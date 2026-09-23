import test from "node:test";
import assert from "node:assert/strict";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parse as parseYaml } from "yaml";

import {
  SUMOLOGIC_CONTROLS,
  SUMOLOGIC_DEPLOYMENTS,
  SumologicApiClient,
  assessSumologicAccessControl,
  assessSumologicContentSharing,
  assessSumologicDataGovernance,
  assessSumologicIdentity,
  checkSumologicAccess,
  collectionOf,
  exportSumologicAuditBundle,
  failedCollection,
  registerSumologicTools,
  resolveSecureOutputPath,
  resolveSumologicBaseUrl,
  resolveSumologicConfiguration,
  scrubErrorText,
} from "../dist/extensions/grc-tools/sumologic.js";
import { getRegisteredToolSummaries } from "../dist/pi/tool-catalog.js";
import { assertSecretsAbsent, readBundleFiles, readZipEntries } from "./helpers/bundle-contents.mjs";

const NOW = new Date("2026-09-21T00:00:00Z");
const FRESH = "2026-09-01T00:00:00Z";
const STALE = "2025-01-01T00:00:00Z";

function createTempBase(prefix) {
  return mkdtempSync(join(tmpdir(), prefix));
}

/** The configured access key: random alphanumerics so every 6 to 24 character window of it is a leak signal. */
const SAMPLE_ACCESS_KEY = "TTmF84rGQ5FKybBUS7CJkEnq";

function sampleConfig(overrides = {}) {
  return {
    accessId: "suABCDEF",
    accessKey: SAMPLE_ACCESS_KEY,
    baseUrl: "https://api.us2.sumologic.com/api",
    deployment: "us2",
    timeoutMs: 30000,
    sourceChain: ["tests"],
    ...overrides,
  };
}

function jsonResponse(value, options = {}) {
  return new Response(JSON.stringify(value), {
    status: options.status ?? 200,
    headers: { "content-type": "application/json", ...(options.headers ?? {}) },
  });
}

function headerValue(headers, name) {
  if (!headers) return undefined;
  if (headers instanceof Headers) return headers.get(name) ?? undefined;
  if (typeof headers.get === "function") return headers.get(name) ?? undefined;
  return headers[name] ?? headers[name.toLowerCase()];
}

function healthyData() {
  return {
    accountStatus: { planType: "Paid", pricingModel: "credits" },
    users: [
      { id: "u1", email: "admin@example.com", isActive: true, isMfaEnabled: true, lastLoginTimestamp: FRESH },
      { id: "u2", email: "analyst@example.com", isActive: true, isMfaEnabled: true, lastLoginTimestamp: FRESH },
    ],
    roles: [
      { id: "r1", name: "Administrator", systemDefined: true, capabilities: ["manageUsersAndRoles"], users: ["u1"], filterPredicate: "" },
      { id: "r2", name: "Analyst", systemDefined: true, capabilities: ["viewCollectors"], users: ["u2"], filterPredicate: "_sourceCategory=prod" },
    ],
    accessKeys: [
      { id: "k1", label: "ci-key", disabled: false, createdAt: FRESH, lastUsed: FRESH, corsHeaders: [] },
    ],
    identityProviders: [
      { id: "idp1", configurationName: "Okta", issuer: "okta", x509cert1: "CERT", signAuthnRequest: true, disableRequestedAuthnContext: false, debugMode: false, spInitiatedLoginEnabled: true },
    ],
    allowlistedUsers: [{ userId: "u1", email: "admin@example.com", isActive: true }],
    passwordPolicy: {
      minLength: 14,
      mustContainLowercase: true,
      mustContainUppercase: true,
      mustContainDigits: true,
      mustContainSpecialChars: true,
      maxPasswordAgeInDays: 60,
      accountLockoutThreshold: 5,
      requireMfa: true,
      disallowWeakPasswords: true,
    },
    allowlistStatus: { loginEnabled: true, contentEnabled: true },
    allowlistAddresses: [{ cidr: "203.0.113.0/24", description: "office" }],
    policies: {
      audit: { enabled: true },
      searchAudit: { enabled: true },
      shareDashboardsOutsideOrganization: { enabled: false },
      dataAccessLevel: { enabled: true },
      userConcurrentSessionsLimit: { enabled: true, maxConcurrentSessions: 2 },
      maxUserSessionTimeout: { maxUserSessionTimeout: "15m" },
      accessKeysLifetime: { accessKeysLifetimeInDays: "90" },
    },
    partitions: [
      { id: "p1", name: "sumologic_default", indexType: "DefaultIndex", isActive: true, retentionPeriod: 400 },
      { id: "p2", name: "sumologic_audit_events", indexType: "AuditIndex", isActive: true, retentionPeriod: 400 },
    ],
    scheduledViews: [{ id: "sv1", indexName: "errors", retentionPeriod: 400 }],
    ingestBudgets: [{ id: "b1", name: "prod-budget", action: "stopCollecting", usageStatus: "Normal" }],
    connections: [],
    collectors: [
      { id: 1, name: "web-1", collectorType: "Installable", alive: true, ephemeral: false, collectorVersion: "19.500-1" },
      { id: 2, name: "hosted", collectorType: "Hosted", alive: true, ephemeral: false },
    ],
    monitors: [
      {
        id: "m1",
        name: "Failed logins",
        isDisabled: false,
        runAs: { runAsId: "u2" },
        notifications: [{ notification: { connectionType: "Email", recipients: ["secops@example.com"] }, runForTriggerTypes: ["Critical"] }],
      },
    ],
    personalFolder: { id: "f1", children: [{ id: "c1", name: "Search A", itemType: "Search", isScheduled: false }] },
    dashboards: [{ id: "d1", title: "SOC", isPublic: false }],
    permissions: { explicitPermissions: [{ permissionName: "View", sourceType: "user", sourceId: "u1", contentId: "c1" }], implicitPermissions: [] },
  };
}

function readerFrom(data, overrides = {}) {
  return {
    getResolvedConfig: () => sampleConfig(),
    getAccountStatus: async () => collectionOf(data.accountStatus),
    listUsers: async () => collectionOf(data.users),
    listRoles: async () => collectionOf(data.roles),
    listAccessKeys: async () => collectionOf(data.accessKeys),
    listSamlIdentityProviders: async () => collectionOf(data.identityProviders),
    listSamlAllowlistedUsers: async () => collectionOf(data.allowlistedUsers),
    getPasswordPolicy: async () => collectionOf(data.passwordPolicy),
    getServiceAllowlistStatus: async () => collectionOf(data.allowlistStatus),
    listServiceAllowlistAddresses: async () => collectionOf(data.allowlistAddresses),
    getPolicy: async (name) => collectionOf(data.policies[name] ?? {}),
    listPartitions: async () => collectionOf(data.partitions),
    listScheduledViews: async () => collectionOf(data.scheduledViews),
    listIngestBudgets: async () => collectionOf(data.ingestBudgets),
    listConnections: async () => collectionOf(data.connections),
    listCollectors: async () => collectionOf(data.collectors),
    listMonitors: async () => collectionOf(data.monitors),
    getPersonalFolder: async () => collectionOf(data.personalFolder),
    listDashboards: async () => collectionOf(data.dashboards),
    getContentPermissions: async () => collectionOf(data.permissions),
    ...overrides,
  };
}

function forbiddenReader() {
  const forbidden = async () => failedCollection("Sumo Logic request failed (403 forbidden)", 403);
  return {
    getResolvedConfig: () => sampleConfig(),
    getAccountStatus: forbidden,
    listUsers: forbidden,
    listRoles: forbidden,
    listAccessKeys: forbidden,
    listSamlIdentityProviders: forbidden,
    listSamlAllowlistedUsers: forbidden,
    getPasswordPolicy: forbidden,
    getServiceAllowlistStatus: forbidden,
    listServiceAllowlistAddresses: forbidden,
    getPolicy: forbidden,
    listPartitions: forbidden,
    listScheduledViews: forbidden,
    listIngestBudgets: forbidden,
    listConnections: forbidden,
    listCollectors: forbidden,
    listMonitors: forbidden,
    getPersonalFolder: forbidden,
    listDashboards: forbidden,
    getContentPermissions: forbidden,
  };
}

function emptyReader() {
  return readerFrom({
    accountStatus: {},
    users: [],
    roles: [],
    accessKeys: [],
    identityProviders: [],
    allowlistedUsers: [],
    passwordPolicy: {},
    allowlistStatus: {},
    allowlistAddresses: [],
    policies: {},
    partitions: [],
    scheduledViews: [],
    ingestBudgets: [],
    connections: [],
    collectors: [],
    monitors: [],
    personalFolder: {},
    dashboards: [],
    permissions: {},
  });
}

function partialReader() {
  const data = healthyData();
  const partial = (items) => collectionOf(items, { complete: false });
  return readerFrom(data, {
    listUsers: async () => partial(data.users),
    listRoles: async () => partial(data.roles),
    listAccessKeys: async () => collectionOf(data.accessKeys, { scope: "personal" }),
    listPartitions: async () => partial(data.partitions),
    listIngestBudgets: async () => partial(data.ingestBudgets),
    listConnections: async () => partial(data.connections),
    listCollectors: async () => partial(data.collectors),
    listMonitors: async () => partial(data.monitors),
    listDashboards: async () => partial(data.dashboards),
  });
}

async function allAssessments(reader) {
  return [
    await assessSumologicIdentity(reader, { now: NOW }),
    await assessSumologicAccessControl(reader, { now: NOW }),
    await assessSumologicDataGovernance(reader, { now: NOW }),
    await assessSumologicContentSharing(reader, { now: NOW }),
  ];
}

function byId(result, id) {
  return result.findings.find((item) => item.id === id);
}

test("resolveSumologicConfiguration prefers args over env over config file and maps deployments", () => {
  const dir = createTempBase("grclanker-sumo-config-");
  const configFile = join(dir, "config.yaml");
  writeFileSync(configFile, "access_id: file-id\naccess_key: file-key\nendpoint: eu\n");

  const fromFile = resolveSumologicConfiguration({}, { SUMOLOGIC_CONFIG_FILE: configFile });
  assert.equal(fromFile.accessId, "file-id");
  assert.equal(fromFile.baseUrl, "https://api.eu.sumologic.com/api");
  assert.equal(fromFile.deployment, "eu");
  assert.ok(fromFile.sourceChain.includes("config-file-access-id"));

  const fromEnv = resolveSumologicConfiguration({}, {
    SUMOLOGIC_CONFIG_FILE: configFile,
    SUMOLOGIC_ACCESS_ID: "env-id",
    SUMOLOGIC_ACCESS_KEY: "env-key",
    SUMOLOGIC_ENDPOINT: "https://api.us2.sumologic.com/api",
  });
  assert.equal(fromEnv.accessId, "env-id");
  assert.equal(fromEnv.baseUrl, "https://api.us2.sumologic.com/api");
  assert.equal(fromEnv.deployment, "us2");

  const fromArgs = resolveSumologicConfiguration(
    { access_id: "arg-id", access_key: "arg-key", endpoint: "fed", timeout_seconds: 9 },
    { SUMOLOGIC_CONFIG_FILE: configFile, SUMOLOGIC_ACCESS_ID: "env-id", SUMOLOGIC_ACCESS_KEY: "env-key", SUMOLOGIC_ENDPOINT: "eu" },
  );
  assert.equal(fromArgs.accessId, "arg-id");
  assert.equal(fromArgs.accessKey, "arg-key");
  assert.equal(fromArgs.baseUrl, "https://api.fed.sumologic.com/api");
  assert.equal(fromArgs.timeoutMs, 9000);
  assert.ok(fromArgs.sourceChain.includes("arguments-access-id"));

  const defaulted = resolveSumologicConfiguration({ access_id: "a", access_key: "b" }, { SUMOLOGIC_CONFIG_FILE: join(dir, "missing.yaml") });
  assert.equal(defaulted.baseUrl, "https://api.sumologic.com/api");
  assert.equal(defaulted.deployment, "us1");

  assert.throws(() => resolveSumologicConfiguration({}, { SUMOLOGIC_CONFIG_FILE: join(dir, "missing.yaml") }), /SUMOLOGIC_ACCESS_ID/);
});

/** Canaries planted on malformed config lines: random alphanumerics, so no 6-character window of one occurs in a legitimate fixture value or in another canary. */
const CONFIG_CANARIES = {
  nestedKey: "Qv7ZkT3mR9pXw2Lc",
  nestedValue: "Hj4NsB8yF6dGa1Ue",
  alias: "Wm2PxK9rT5vLq7Zb",
  unterminated: "Lf9BwD4sN7hVe3Ky",
  indent: "Tn3XcM6zP8gQb5Rw",
  duplicate: "Rk8VqL2tY7jCn4Fs",
  readable: "Zx4HnV7qK2mYt9Pw",
};
const LIBRARY_ERROR_WORDING = [
  "Nested mappings", "is not valid JSON", "Unresolved alias", "illegal operation", "permission denied", "no such file",
  "not a directory", "Unexpected token", "Missing closing", "Map keys must be unique", "must start at the same column",
];

/** Every substring of a planted credential at lengths 6 through 24 (sliding windows), so a partial echo such as a JSON.parse window or a truncated token cannot pass a leak assertion. */
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

function assertConfigErrorText(text, { path, code, line, column, canaries }, label) {
  for (const canary of canaries) assertNoWindowOf(text, canary, `${label} (${canary})`);
  for (const wording of LIBRARY_ERROR_WORDING) assert.ok(!text.includes(wording), `${label} repeats library wording "${wording}": ${text}`);
  assert.ok(text.includes(path), `${label} names the path ${path}: ${text}`);
  assert.ok(text.includes(`(${code})`), `${label} carries the code ${code}: ${text}`);
  if (line) assert.ok(text.includes(` at line ${line}${column ? `, column ${column}` : ""}`), `${label} carries the position line ${line}: ${text}`);
  else assert.doesNotMatch(text, / at line \d+/, `${label} invents no line: ${text}`);
}

function thrownBy(fn) {
  try {
    fn();
  } catch (error) {
    return error;
  }
  assert.fail("expected the call to throw");
}

test("rule 9: Sumo Logic config loader errors carry only the path, position, and code, never a config line or library wording", async () => {
  const dir = createTempBase("grclanker-sumo-config-errors-");
  const registered = [];
  registerSumologicTools({ registerTool: (tool) => registered.push(tool) });
  const checkAccess = registered.find((tool) => tool.name === "sumologic_check_access");
  const exportBundle = registered.find((tool) => tool.name === "sumologic_export_audit_bundle");
  const allCanaries = Object.values(CONFIG_CANARIES);

  const parseCases = [
    { name: "nested mapping", file: "nested.yaml", text: `access_id: suABCDEF\naccess_key: ${CONFIG_CANARIES.nestedKey}: Bearer ${CONFIG_CANARIES.nestedValue}\n`, leaks: [CONFIG_CANARIES.nestedKey, CONFIG_CANARIES.nestedValue], control: /Nested mappings/, code: "BLOCK_AS_IMPLICIT_KEY", line: 2, column: 13 },
    { name: "alias", file: "alias.yaml", text: `access_id: suABCDEF\naccess_key: *${CONFIG_CANARIES.alias}\n`, leaks: [CONFIG_CANARIES.alias], control: /Unresolved alias/, code: "INVALID_YAML" },
    { name: "unterminated quote", file: "quote.yaml", text: `access_id: suABCDEF\naccess_key: "${CONFIG_CANARIES.unterminated}\n`, leaks: [CONFIG_CANARIES.unterminated], control: /Missing closing/, code: "MISSING_CHAR", line: 3, column: 1 },
    { name: "bad indent", file: "indent.yaml", text: `sumo:\n  access_id: suABCDEF\n access_key: ${CONFIG_CANARIES.indent}\n`, leaks: [CONFIG_CANARIES.indent], control: /same column/, code: "BAD_INDENT", line: 3, column: 1 },
    { name: "duplicate key", file: "duplicate.yaml", text: `access_key: one\naccess_key: ${CONFIG_CANARIES.duplicate}\n`, leaks: [CONFIG_CANARIES.duplicate], control: /Map keys must be unique/, code: "DUPLICATE_KEY", line: 2, column: 1 },
  ];
  for (const testCase of parseCases) {
    const configFile = join(dir, testCase.file);
    writeFileSync(configFile, testCase.text);
    const library = thrownBy(() => parseYaml(testCase.text));
    assert.match(library.message, testCase.control, `${testCase.name}: positive control uses the library message`);
    assert.ok(testCase.leaks.some((canary) => windowsOf(canary).some((window) => library.message.includes(window))), `${testCase.name}: positive control, the library message quotes the canary`);
    assertFixtureFreeOfCanaryWindows(testCase.text, allCanaries, `${testCase.name} config fixture`);

    const expected = { path: configFile, code: testCase.code, line: testCase.line, column: testCase.column, canaries: allCanaries };
    const thrown = thrownBy(() => resolveSumologicConfiguration({}, { SUMOLOGIC_CONFIG_FILE: configFile }));
    assert.match(thrown.message, /^Unable to parse Sumo Logic config file: invalid YAML in /, testCase.name);
    assertConfigErrorText(thrown.message, expected, `${testCase.name} resolver error`);
    const fromArgs = thrownBy(() => resolveSumologicConfiguration({ config_file: configFile, access_id: "a", access_key: "b" }, {}));
    assertConfigErrorText(fromArgs.message, expected, `${testCase.name} resolver error with credentials in arguments`);

    const result = await checkAccess.execute("call", checkAccess.prepareArguments({ config_file: configFile }));
    assertConfigErrorText(JSON.stringify(result), expected, `${testCase.name} check_access payload`);
  }

  const outputRoot = join(dir, "export");
  const exported = await exportBundle.execute("call", exportBundle.prepareArguments({ config_file: join(dir, "nested.yaml"), output_dir: outputRoot }));
  assertConfigErrorText(JSON.stringify(exported), { path: join(dir, "nested.yaml"), code: "BLOCK_AS_IMPLICIT_KEY", line: 2, column: 13, canaries: allCanaries }, "export payload");
  assert.equal(existsSync(outputRoot), false, "a config error writes no bundle");

  const readCases = [
    { name: "EISDIR", path: join(dir, "directory.yaml"), setup: (path) => mkdirSync(path), control: /illegal operation/ },
    { name: "ENOTDIR", path: join(dir, "plain-file", "config.yaml"), setup: (path) => writeFileSync(join(dir, "plain-file"), `access_key: ${CONFIG_CANARIES.readable}\n`), control: /not a directory/ },
  ];
  if (process.getuid?.() !== 0) {
    readCases.push({ name: "EACCES", path: join(dir, "locked.yaml"), setup: (path) => { writeFileSync(path, `access_key: ${CONFIG_CANARIES.readable}\n`); chmodSync(path, 0o000); }, control: /permission denied/ });
  }
  for (const testCase of readCases) {
    testCase.setup(testCase.path);
    assert.match(thrownBy(() => readFileSync(testCase.path, "utf8")).message, testCase.control, `${testCase.name}: positive control uses the filesystem message`);
    const expected = { path: testCase.path, code: testCase.name, canaries: allCanaries };
    const thrown = thrownBy(() => resolveSumologicConfiguration({}, { SUMOLOGIC_CONFIG_FILE: testCase.path }));
    assert.equal(thrown.message, `Unable to read Sumo Logic config file ${testCase.path} (${testCase.name})`);
    assertConfigErrorText(thrown.message, expected, `${testCase.name} resolver error`);
    const result = await checkAccess.execute("call", checkAccess.prepareArguments({ config_file: testCase.path }));
    assertConfigErrorText(JSON.stringify(result), expected, `${testCase.name} check_access payload`);
  }

  const missing = join(dir, "missing.yaml");
  const absent = thrownBy(() => resolveSumologicConfiguration({}, { SUMOLOGIC_CONFIG_FILE: missing }));
  assert.match(absent.message, /SUMOLOGIC_ACCESS_ID/, "a missing config file is absent, not a read failure");
  for (const wording of LIBRARY_ERROR_WORDING) assert.ok(!absent.message.includes(wording));
  const absentResult = JSON.stringify(await checkAccess.execute("call", checkAccess.prepareArguments({ config_file: missing })));
  assert.ok(absentResult.includes("SUMOLOGIC_ACCESS_ID"));
  for (const wording of LIBRARY_ERROR_WORDING) assert.ok(!absentResult.includes(wording));
});

test("resolveSumologicBaseUrl maps every documented deployment and normalizes URLs", () => {
  const expected = {
    au: "https://api.au.sumologic.com/api",
    ca: "https://api.ca.sumologic.com/api",
    ch: "https://api.ch.sumologic.com/api",
    de: "https://api.de.sumologic.com/api",
    esc: "https://api.esc.sumologic.com/api",
    eu: "https://api.eu.sumologic.com/api",
    fed: "https://api.fed.sumologic.com/api",
    in: "https://api.in.sumologic.com/api",
    jp: "https://api.jp.sumologic.com/api",
    kr: "https://api.kr.sumologic.com/api",
    us1: "https://api.sumologic.com/api",
    us2: "https://api.us2.sumologic.com/api",
  };
  assert.deepEqual(SUMOLOGIC_DEPLOYMENTS, expected);
  for (const [code, url] of Object.entries(expected)) {
    assert.deepEqual(resolveSumologicBaseUrl(code), { baseUrl: url, deployment: code });
    assert.deepEqual(resolveSumologicBaseUrl(code.toUpperCase()), { baseUrl: url, deployment: code });
  }
  assert.equal(resolveSumologicBaseUrl("https://api.sumologic.com").baseUrl, "https://api.sumologic.com/api");
  assert.equal(resolveSumologicBaseUrl("https://api.jp.sumologic.com/api/v1/").baseUrl, "https://api.jp.sumologic.com/api");
  assert.throws(() => resolveSumologicBaseUrl("mars"), /Unknown Sumo Logic deployment/);
});

test("SumologicApiClient sends basic auth, follows token pagination, retries 429 and 5xx, and redacts the key", async () => {
  const seen = [];
  let usersAttempt = 0;
  const sleeps = [];
  const fetchImpl = async (input, init = {}) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    seen.push({ pathname: url.pathname, search: url.search, auth: headerValue(init.headers, "authorization") });
    if (url.pathname === "/api/v1/users") {
      usersAttempt += 1;
      if (usersAttempt === 1) return jsonResponse({ errors: [{ code: "rate.limit.exceeded" }] }, { status: 429, headers: { "retry-after": "1" } });
      if (usersAttempt === 2) return jsonResponse({ message: "boom" }, { status: 503 });
      if (!url.searchParams.get("token")) return jsonResponse({ data: [{ id: "u1" }], next: "page-2" });
      return jsonResponse({ data: [{ id: "u2" }], next: null });
    }
    if (url.pathname === "/api/v1/roles") {
      return jsonResponse({ errors: [{ code: "forbidden", message: `${SAMPLE_ACCESS_KEY} should not leak` }] }, { status: 403 });
    }
    return jsonResponse({});
  };
  const client = new SumologicApiClient(sampleConfig(), { fetchImpl, sleepImpl: async (ms) => { sleeps.push(ms); } });

  const users = await client.listUsers();
  assert.equal(users.ok, true);
  assert.equal(users.complete, true);
  assert.deepEqual(users.data.map((user) => user.id), ["u1", "u2"]);
  assert.equal(seen[0].auth, `Basic ${Buffer.from(`suABCDEF:${SAMPLE_ACCESS_KEY}`).toString("base64")}`);
  assert.deepEqual(sleeps.slice(0, 2), [1000, 500]);
  assert.ok(seen.some((item) => item.search.includes("token=page-2")));
  assert.ok(seen.every((item) => item.pathname !== "/api/v1/users" || item.search.includes("limit=1000")));

  const roles = await client.listRoles();
  assert.equal(roles.ok, false);
  assert.equal(roles.httpStatus, 403);
  assertNoWindowOf(roles.error, SAMPLE_ACCESS_KEY, "403 error string");
  assert.match(roles.error, /\[REDACTED\]/);
});

test("SumologicApiClient marks capped pagination incomplete, paginates collectors and monitors by offset, and falls back to personal keys", async () => {
  const requests = [];
  const fetchImpl = async (input) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    requests.push(`${url.pathname}${url.search}`);
    if (url.pathname === "/api/v1/partitions") return jsonResponse({ data: [{ id: `p-${url.searchParams.get("token") ?? "0"}` }], next: "more" });
    if (url.pathname === "/api/v1/collectors") {
      const offset = Number(url.searchParams.get("offset"));
      return jsonResponse({ collectors: offset === 0 ? Array.from({ length: 1000 }, (_, index) => ({ id: index })) : [{ id: 1000 }] });
    }
    if (url.pathname === "/api/v1/monitors/search") return jsonResponse([{ item: { id: "m1", name: "Monitor" }, path: "/Monitor/m1" }]);
    if (url.pathname === "/api/v1/accessKeys") return jsonResponse({ errors: [{ code: "forbidden" }] }, { status: 403 });
    if (url.pathname === "/api/v1/accessKeys/personal") return jsonResponse({ data: [{ id: "k1", label: "mine" }] });
    return jsonResponse({});
  };
  const client = new SumologicApiClient(sampleConfig(), { fetchImpl, maxPages: 2, maxRetries: 0 });

  const partitions = await client.listPartitions();
  assert.equal(partitions.ok, true);
  assert.equal(partitions.complete, false);
  assert.equal(partitions.data.length, 2);
  assert.ok(requests[0].includes("viewTypes=DefaultView%2CPartition%2CAuditIndex"));

  const collectors = await client.listCollectors();
  assert.equal(collectors.complete, true);
  assert.equal(collectors.data.length, 1001);
  assert.ok(requests.some((item) => item.includes("/api/v1/collectors?limit=1000&offset=1000")));

  const monitors = await client.listMonitors();
  assert.equal(monitors.data[0].name, "Monitor");
  assert.equal(monitors.data[0].path, "/Monitor/m1");
  assert.ok(requests.some((item) => item.includes("/api/v1/monitors/search?query=type%3Amonitor")));

  const keys = await client.listAccessKeys();
  assert.equal(keys.ok, true);
  assert.equal(keys.scope, "personal");
  assert.deepEqual(keys.data.map((key) => key.label), ["mine"]);
});

test("checkSumologicAccess reports healthy and degraded surfaces with capability hints", async () => {
  const healthy = await checkSumologicAccess(readerFrom(healthyData()));
  assert.equal(healthy.status, "healthy");
  assert.equal(healthy.surfaces.length, 18);
  assert.equal(healthy.missingCapabilities.length, 0);
  assert.match(healthy.recommendedNextStep, /sumologic_assess_identity/);
  const addresses = healthy.surfaces.find((surface) => surface.endpoint === "/v1/serviceAllowlist/addresses");
  assert.equal(addresses.name, "service_allowlist_addresses");
  assert.equal(addresses.status, "readable");
  assert.equal(addresses.count, 1);
  assert.equal(addresses.capabilityHint, "ipAllowlisting");

  const degraded = await checkSumologicAccess(readerFrom(healthyData(), {
    listUsers: async () => failedCollection("forbidden", 403),
    listCollectors: async () => failedCollection("forbidden", 403),
    listServiceAllowlistAddresses: async () => failedCollection("forbidden", 403),
  }));
  assert.equal(degraded.status, "limited");
  assert.ok(degraded.missingCapabilities.includes("manageUsersAndRoles"));
  assert.ok(degraded.missingCapabilities.includes("viewCollectors"));
  assert.ok(degraded.missingCapabilities.includes("ipAllowlisting"));
  assert.equal(degraded.surfaces.find((surface) => surface.name === "service_allowlist_addresses").status, "not_readable");
  assert.match(degraded.recommendedNextStep, /never as passes/);
});

test("all four assessments cover the 20 spec controls with framework mappings", async () => {
  const results = await allAssessments(readerFrom(healthyData()));
  const ids = results.flatMap((result) => result.findings.map((item) => item.id)).sort();
  assert.deepEqual(ids, SUMOLOGIC_CONTROLS.map((item) => item.id).sort());
  assert.equal(new Set(ids).size, 20);
  for (const item of results.flatMap((result) => result.findings)) {
    assert.equal(item.mappings.length, 8, `${item.id} mappings`);
    assert.ok(item.mappings.some((mapping) => mapping.startsWith("FedRAMP ")));
    assert.ok(item.mappings.some((mapping) => mapping.startsWith("ISMAP ")));
  }
  assert.equal(byId(results[0], "SUMO-01").mappings[0], "FedRAMP IA-2");
  assert.equal(byId(results[3], "SUMO-20").mappings[4], "PCI-DSS 10.6.1");
});

test("healthy fixtures pass where evidence is complete and stay manual where the API cannot verify", async () => {
  const [identity, access, data, content] = await allAssessments(readerFrom(healthyData()));
  assert.equal(byId(identity, "SUMO-01").status, "manual");
  assert.match(byId(identity, "SUMO-01").summary, /Require SAML sign-in/);
  assert.equal(byId(identity, "SUMO-02").status, "pass");
  assert.equal(byId(identity, "SUMO-03").status, "pass");
  assert.equal(byId(identity, "SUMO-04").status, "pass");
  assert.equal(byId(identity, "SUMO-05").status, "pass");
  assert.equal(byId(access, "SUMO-06").status, "pass");
  assert.equal(byId(access, "SUMO-07").status, "pass");
  assert.equal(byId(access, "SUMO-08").status, "pass");
  assert.equal(byId(access, "SUMO-13").status, "pass");
  assert.equal(byId(access, "SUMO-14").status, "pass");
  assert.equal(byId(data, "SUMO-09").status, "pass");
  assert.equal(byId(data, "SUMO-10").status, "pass");
  assert.equal(byId(data, "SUMO-12").status, "pass");
  assert.equal(byId(data, "SUMO-16").status, "pass");
  assert.equal(byId(data, "SUMO-17").status, "pass");
  assert.equal(byId(content, "SUMO-11").status, "pass");
  assert.equal(byId(content, "SUMO-15").status, "manual");
  assert.equal(byId(content, "SUMO-18").status, "manual");
  assert.match(byId(content, "SUMO-18").summary, /no lookup table listing endpoint/);
  assert.equal(byId(content, "SUMO-19").status, "pass");
  assert.equal(byId(content, "SUMO-20").status, "pass");
});

test("failing fixtures fail the corresponding controls", async () => {
  const data = healthyData();
  data.identityProviders = [];
  data.passwordPolicy = { ...data.passwordPolicy, minLength: 8, maxPasswordAgeInDays: 0, requireMfa: false };
  data.roles.push({ id: "r3", name: "Power", systemDefined: false, capabilities: ["manageUsersAndRoles"], users: ["u2", "u3", "u4", "u5", "u6", "u7"] });
  data.accessKeys = [{ id: "k2", label: "old", disabled: false, createdAt: STALE, lastUsed: STALE }];
  data.allowlistStatus = { loginEnabled: false, contentEnabled: false };
  data.policies.maxUserSessionTimeout = { maxUserSessionTimeout: "1d" };
  data.policies.audit = { enabled: false };
  data.ingestBudgets = [];
  data.partitions[1].retentionPeriod = 30;
  data.collectors = [{ id: 3, name: "dead", collectorType: "Installable", alive: false, ephemeral: false, lastSeenAlive: Date.parse(STALE), collectorVersion: "19.1" }];
  data.policies.dataAccessLevel = { enabled: false };
  data.policies.shareDashboardsOutsideOrganization = { enabled: true };
  data.monitors[0].notifications = [{ notification: { connectionType: "Email", recipients: ["someone@gmail.com"] }, runForTriggerTypes: ["Critical"] }];
  data.connections = [{ id: "c1", name: "hook", type: "WebhookConnection", url: "https://hooks.evil.example/x" }];

  const [identity, access, governance, content] = await allAssessments(readerFrom(data));
  assert.equal(byId(identity, "SUMO-01").status, "fail");
  assert.equal(byId(identity, "SUMO-02").status, "manual");
  assert.match(byId(identity, "SUMO-02").summary, /Not applicable/);
  assert.equal(byId(identity, "SUMO-03").status, "fail");
  assert.equal(byId(identity, "SUMO-04").status, "fail");
  assert.equal(byId(identity, "SUMO-05").status, "fail");
  assert.equal(byId(access, "SUMO-06").status, "fail");
  assert.equal(byId(access, "SUMO-07").status, "fail");
  assert.equal(byId(access, "SUMO-08").status, "fail");
  assert.equal(byId(access, "SUMO-13").status, "fail");
  assert.equal(byId(access, "SUMO-14").status, "fail");
  assert.equal(byId(governance, "SUMO-09").status, "fail");
  assert.equal(byId(governance, "SUMO-12").status, "fail");
  assert.equal(byId(governance, "SUMO-16").status, "fail");
  assert.equal(byId(governance, "SUMO-17").status, "fail");
  assert.equal(byId(governance, "SUMO-10").status, "manual");
  assert.equal(byId(content, "SUMO-11").status, "fail");
  assert.equal(byId(content, "SUMO-19").status, "fail");
  assert.equal(byId(content, "SUMO-20").status, "fail");

  const approved = await assessSumologicDataGovernance(readerFrom(data), { now: NOW, approvedDestinationDomains: ["example.com"] });
  assert.equal(byId(approved, "SUMO-10").status, "fail");
});

test("self-check (a): every endpoint forbidden yields only manual findings that name the cause", async () => {
  const results = await allAssessments(forbiddenReader());
  const findings = results.flatMap((result) => result.findings);
  assert.equal(findings.length, 20);
  for (const item of findings) {
    assert.notEqual(item.status, "pass", `${item.id} must not pass on 403`);
    assert.equal(item.status, "manual", `${item.id} should be manual on 403`);
    assert.match(item.summary, /403|unreadable|not exposed|Collect manually|unknown error|human/i, `${item.id} summary names the cause`);
  }
  assert.match(byId(results[0], "SUMO-01").summary, /lacks the role capability \(403\)/);
  assert.ok(results.every((result) => result.errors.length > 0));
});

test("self-check (b): empty inventories never pass by default and state whether emptiness fails or needs review", async () => {
  const results = await allAssessments(emptyReader());
  const findings = results.flatMap((result) => result.findings);
  assert.equal(findings.length, 20);
  const passes = findings.filter((item) => item.status === "pass").map((item) => item.id);
  assert.deepEqual(passes, [], `unexpected passes on empty data: ${passes.join(", ")}`);
  const byIdMap = Object.fromEntries(findings.map((item) => [item.id, item]));
  assert.equal(byIdMap["SUMO-01"].status, "fail");
  assert.match(byIdMap["SUMO-01"].summary, /Zero SAML identity providers/);
  assert.equal(byIdMap["SUMO-02"].status, "manual");
  assert.equal(byIdMap["SUMO-06"].status, "manual");
  assert.equal(byIdMap["SUMO-13"].status, "fail");
  assert.equal(byIdMap["SUMO-16"].status, "fail");
  assert.match(byIdMap["SUMO-16"].summary, /Zero ingest budgets/);
  assert.equal(byIdMap["SUMO-17"].status, "manual");
  assert.equal(byIdMap["SUMO-12"].status, "manual");
  assert.equal(byIdMap["SUMO-20"].status, "manual");
  assert.equal(byIdMap["SUMO-09"].status, "fail");
  assert.equal(byIdMap["SUMO-11"].status, "fail");
  assert.equal(byIdMap["SUMO-05"].status, "fail");
  assert.match(byIdMap["SUMO-05"].summary, /requireMfa=absent/);
  assert.equal(byIdMap["SUMO-07"].status, "manual");
  assert.match(byIdMap["SUMO-07"].summary, /did not include accessKeysLifetimeInDays/);
});

test("self-check (b) exception: empty lists pass only where the control intent makes emptiness compliant and the endpoint was readable", async () => {
  const data = healthyData();
  data.allowlistedUsers = [];
  data.connections = [];
  const [identity, , governance] = await allAssessments(readerFrom(data));
  assert.equal(byId(identity, "SUMO-02").status, "pass");
  assert.match(byId(identity, "SUMO-02").summary, /0 SAML allowlisted user\(s\) \(endpoint readable/);
  assert.equal(byId(governance, "SUMO-10").status, "pass");
  assert.match(byId(governance, "SUMO-10").summary, /Zero outbound connections .* \(endpoints readable\)/);
});

test("self-check (c): partial inventories never pass", async () => {
  const results = await allAssessments(partialReader());
  const findings = results.flatMap((result) => result.findings);
  const passes = findings.filter((item) => item.status === "pass").map((item) => item.id);
  const allowedPasses = ["SUMO-02", "SUMO-03", "SUMO-04", "SUMO-13", "SUMO-14", "SUMO-09", "SUMO-11"];
  const unexpected = passes.filter((id) => !allowedPasses.includes(id));
  assert.deepEqual(unexpected, [], `partial inventories must not pass: ${unexpected.join(", ")}`);
  const byIdMap = Object.fromEntries(findings.map((item) => [item.id, item]));
  assert.equal(byIdMap["SUMO-05"].status, "warn");
  assert.match(byIdMap["SUMO-05"].summary, /Pagination stopped before the last page/);
  assert.equal(byIdMap["SUMO-06"].status, "warn");
  assert.equal(byIdMap["SUMO-07"].status, "manual");
  assert.match(byIdMap["SUMO-07"].summary, /Partial view: 1 personal access key/);
  assert.equal(byIdMap["SUMO-08"].status, "manual");
  assert.equal(byIdMap["SUMO-12"].status, "warn");
  assert.equal(byIdMap["SUMO-16"].status, "warn");
  assert.equal(byIdMap["SUMO-17"].status, "warn");
  assert.equal(byIdMap["SUMO-19"].status, "warn");
  assert.equal(byIdMap["SUMO-20"].status, "warn");
});

test("SumologicApiClient caps the dashboards page size at 100 and follows the dashboards cursor", async () => {
  const requests = [];
  const fetchImpl = async (input) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    requests.push({ pathname: url.pathname, limit: url.searchParams.get("limit"), token: url.searchParams.get("token"), mode: url.searchParams.get("mode") });
    if (url.pathname === "/api/v2/dashboards") {
      if (Number(url.searchParams.get("limit")) > 100) return jsonResponse({ errors: [{ code: "invalid.limit", message: "limit must be at most 100" }] }, { status: 400 });
      if (!url.searchParams.get("token")) return jsonResponse({ dashboards: Array.from({ length: 100 }, (_, index) => ({ id: `d${index}`, title: `Dashboard ${index}`, isPublic: false })), next: "page-2" });
      return jsonResponse({ dashboards: [{ id: "d100", title: "Last", isPublic: false }], next: null });
    }
    if (url.pathname === "/api/v1/users") return jsonResponse({ data: [{ id: "u1" }], next: null });
    return jsonResponse({});
  };
  const client = new SumologicApiClient(sampleConfig(), { fetchImpl, maxRetries: 0 });

  const dashboards = await client.listDashboards();
  assert.equal(dashboards.ok, true, dashboards.error);
  assert.equal(dashboards.complete, true);
  assert.equal(dashboards.data.length, 101);
  const dashboardRequests = requests.filter((item) => item.pathname === "/api/v2/dashboards");
  assert.equal(dashboardRequests.length, 2);
  assert.ok(dashboardRequests.every((item) => item.limit === "100" && item.mode === "allViewableByUser"));
  assert.equal(dashboardRequests[1].token, "page-2");

  await client.listUsers();
  assert.equal(requests.find((item) => item.pathname === "/api/v1/users").limit, "1000");

  const access = await checkSumologicAccess(client);
  assert.equal(access.surfaces.find((surface) => surface.name === "dashboards").status, "readable");
});

test("control 11 downgrades when the personal folder holds more items than content_sample", async () => {
  const data = healthyData();
  data.personalFolder = { id: "f1", children: Array.from({ length: 40 }, (_, index) => ({ id: `c${index}`, name: `Search ${index}`, itemType: "Search" })) };
  let permissionLookups = 0;
  const reader = readerFrom(data, { getContentPermissions: async () => { permissionLookups += 1; return collectionOf(data.permissions); } });

  const sampled = await assessSumologicContentSharing(reader, { now: NOW });
  const sharing = byId(sampled, "SUMO-11");
  assert.equal(permissionLookups, 25);
  assert.equal(sharing.status, "warn");
  assert.match(sharing.summary, /Only 25 of 40 personal-folder items were sampled \(content_sample=25\); 15 were not evaluated/);
  assert.equal(sharing.evidence.personal_folder_items_total, 40);
  assert.equal(sharing.evidence.personal_folder_items_sampled, 25);
  assert.equal(sharing.evidence.personal_folder_items_unsampled, 15);
  assert.equal(sampled.summary.personal_folder_items_unsampled, 15);
  assert.equal(byId(sampled, "SUMO-15").evidence.personal_folder_items_total, 40);
  assert.equal(byId(sampled, "SUMO-18").evidence.personal_folder_items_total, 40);

  const full = await assessSumologicContentSharing(readerFrom(data), { now: NOW, contentSample: 40 });
  assert.equal(byId(full, "SUMO-11").status, "pass");
  assert.match(byId(full, "SUMO-11").summary, /all 40 items in the folder were evaluated/);
  assert.equal(byId(full, "SUMO-11").evidence.personal_folder_items_unsampled, 0);
});

test("control 7 treats an access key lifetime policy of 0 or absent as at most warn and always states the policy", async () => {
  const healthy = await assessSumologicAccessControl(readerFrom(healthyData()), { now: NOW });
  assert.equal(byId(healthy, "SUMO-07").status, "pass");
  assert.match(byId(healthy, "SUMO-07").summary, /The access key lifetime policy is 90 days\./);
  assert.equal(byId(healthy, "SUMO-07").evidence.access_keys_lifetime_policy_state, "enforced");

  const neverExpire = healthyData();
  neverExpire.policies.accessKeysLifetime = { accessKeysLifetimeInDays: "0" };
  const zero = await assessSumologicAccessControl(readerFrom(neverExpire), { now: NOW });
  assert.equal(byId(zero, "SUMO-07").status, "warn");
  assert.match(byId(zero, "SUMO-07").summary, /The access key lifetime policy is 0 \(keys never expire\)\./);
  assert.equal(byId(zero, "SUMO-07").evidence.access_keys_lifetime_policy_days, 0);
  assert.equal(byId(zero, "SUMO-07").evidence.access_keys_lifetime_policy_state, "never-expire");
  assert.equal(byId(zero, "SUMO-08").status, "pass");

  const absent = healthyData();
  absent.policies.accessKeysLifetime = {};
  const missing = await assessSumologicAccessControl(readerFrom(absent), { now: NOW });
  assert.equal(byId(missing, "SUMO-07").status, "warn");
  assert.match(byId(missing, "SUMO-07").summary, /did not include accessKeysLifetimeInDays/);
  assert.equal(byId(missing, "SUMO-07").evidence.access_keys_lifetime_policy_state, "absent");

  const unreadable = await assessSumologicAccessControl(readerFrom(healthyData(), {
    getPolicy: async (name) => (name === "accessKeysLifetime" ? failedCollection("forbidden", 403) : collectionOf(healthyData().policies[name] ?? {})),
  }), { now: NOW });
  assert.equal(byId(unreadable, "SUMO-07").status, "warn");
  assert.match(byId(unreadable, "SUMO-07").summary, /lifetime policy was unreadable/);

  const stale = healthyData();
  stale.policies.accessKeysLifetime = { accessKeysLifetimeInDays: "0" };
  stale.accessKeys = [{ id: "k2", label: "old", disabled: false, createdAt: STALE, lastUsed: FRESH }];
  const failed = await assessSumologicAccessControl(readerFrom(stale), { now: NOW });
  assert.equal(byId(failed, "SUMO-07").status, "fail");
  assert.match(byId(failed, "SUMO-07").summary, /have not been rotated\. The access key lifetime policy is 0 \(keys never expire\)\./);

  const personal = await assessSumologicAccessControl(readerFrom(stale, { listAccessKeys: async () => collectionOf(stale.accessKeys, { scope: "personal" }) }), { now: NOW });
  assert.equal(byId(personal, "SUMO-07").status, "manual");
  assert.match(byId(personal, "SUMO-07").summary, /The access key lifetime policy is 0/);
});

test("control 6 warns on custom roles without a filterPredicate and names them", async () => {
  const data = healthyData();
  data.roles.push({ id: "r4", name: "Wide Open", systemDefined: false, capabilities: ["viewCollectors"], users: ["u2"] });
  const unscoped = await assessSumologicAccessControl(readerFrom(data), { now: NOW });
  assert.equal(byId(unscoped, "SUMO-06").status, "warn");
  assert.match(byId(unscoped, "SUMO-06").summary, /1 custom role\(s\) have no filterPredicate and grant unrestricted search scope \(Wide Open\)/);
  assert.deepEqual(byId(unscoped, "SUMO-06").evidence.custom_roles_without_filter_predicate, ["Wide Open"]);

  data.roles[2].filterPredicate = "_sourceCategory=web";
  const scoped = await assessSumologicAccessControl(readerFrom(data), { now: NOW });
  assert.equal(byId(scoped, "SUMO-06").status, "pass");
  assert.match(byId(scoped, "SUMO-06").summary, /every custom role carries a filterPredicate/);

  const systemUnscoped = healthyData();
  systemUnscoped.roles.push({ id: "r5", name: "Analyst (system)", systemDefined: true, capabilities: ["viewCollectors"], users: [] });
  const system = await assessSumologicAccessControl(readerFrom(systemUnscoped), { now: NOW });
  assert.equal(byId(system, "SUMO-06").status, "pass");
});

test("controls 5 and 6 report locked and dormant users and keep undated logins out of the active bucket", async () => {
  const data = healthyData();
  data.users.push(
    { id: "u3", email: "locked@example.com", isActive: true, isMfaEnabled: true, isLocked: true, lastLoginTimestamp: FRESH },
    { id: "u4", email: "dormant@example.com", isActive: true, isMfaEnabled: true, isLocked: false, lastLoginTimestamp: STALE },
    { id: "u5", email: "never@example.com", isActive: true, isMfaEnabled: true, isLocked: false, lastLoginTimestamp: null },
  );
  const [identity, access] = await allAssessments(readerFrom(data));
  const mfa = byId(identity, "SUMO-05");
  assert.equal(mfa.status, "pass");
  assert.deepEqual(mfa.evidence.locked_users, ["locked@example.com"]);
  assert.deepEqual(mfa.evidence.dormant_active_users, ["dormant@example.com"]);
  assert.deepEqual(mfa.evidence.active_users_without_last_login, ["never@example.com"]);
  assert.equal(mfa.evidence.active_users_with_recent_login, 3);
  assert.equal(mfa.evidence.user_inactive_threshold_days, 90);
  assert.equal(identity.summary.locked_users, 1);
  assert.equal(identity.summary.dormant_active_users, 1);
  assert.equal(identity.summary.active_users_without_last_login, 1);

  const rbac = byId(access, "SUMO-06");
  assert.equal(rbac.status, "pass");
  assert.deepEqual(rbac.evidence.locked_users, ["locked@example.com"]);
  assert.deepEqual(rbac.evidence.dormant_active_users, ["dormant@example.com"]);
  assert.deepEqual(rbac.evidence.active_users_without_last_login, ["never@example.com"]);
  assert.deepEqual(rbac.evidence.dormant_admin_members, []);

  data.roles[0].users = ["u1", "u4"];
  const dormantAdmin = await assessSumologicAccessControl(readerFrom(data), { now: NOW });
  assert.equal(byId(dormantAdmin, "SUMO-06").status, "warn");
  assert.match(byId(dormantAdmin, "SUMO-06").summary, /1 admin role member\(s\) have not logged in for over 90 days \(dormant@example.com\)/);
  assert.deepEqual(byId(dormantAdmin, "SUMO-06").evidence.dormant_admin_members, ["dormant@example.com"]);

  data.roles[0].users = ["u1", "u5"];
  const undatedAdmin = await assessSumologicAccessControl(readerFrom(data), { now: NOW });
  assert.equal(byId(undatedAdmin, "SUMO-06").status, "warn");
  assert.match(byId(undatedAdmin, "SUMO-06").summary, /have no lastLoginTimestamp and are not counted as active/);
  assert.deepEqual(byId(undatedAdmin, "SUMO-06").evidence.admin_members_without_last_login, ["never@example.com"]);
  assert.deepEqual(byId(undatedAdmin, "SUMO-06").evidence.dormant_admin_members, []);

  data.roles[0].users = ["u1", "u4"];
  const relaxed = await assessSumologicAccessControl(readerFrom(data), { now: NOW, userInactiveDays: 3650 });
  assert.equal(byId(relaxed, "SUMO-06").status, "pass");
  assert.equal(byId(relaxed, "SUMO-06").evidence.user_inactive_threshold_days, 3650);
  assert.deepEqual(byId(relaxed, "SUMO-06").evidence.dormant_admin_members, []);

  data.roles[0].users = ["u1"];
  const usersUnreadable = await assessSumologicAccessControl(readerFrom(data, { listUsers: async () => failedCollection("forbidden", 403) }), { now: NOW });
  assert.equal(byId(usersUnreadable, "SUMO-06").status, "warn");
  assert.match(byId(usersUnreadable, "SUMO-06").summary, /user list was unreadable/);
});

test("control 5 reports an absent requireMfa flag as absent, not false", async () => {
  const data = healthyData();
  delete data.passwordPolicy.requireMfa;
  const identity = await assessSumologicIdentity(readerFrom(data), { now: NOW });
  assert.equal(byId(identity, "SUMO-05").status, "fail");
  assert.match(byId(identity, "SUMO-05").summary, /requireMfa=absent/);
  assert.doesNotMatch(byId(identity, "SUMO-05").summary, /requireMfa=false/);
  assert.equal(byId(identity, "SUMO-05").evidence.require_mfa_policy, "absent");

  data.passwordPolicy.requireMfa = false;
  const explicit = await assessSumologicIdentity(readerFrom(data), { now: NOW });
  assert.match(byId(explicit, "SUMO-05").summary, /requireMfa=false/);
  assert.equal(byId(explicit, "SUMO-05").evidence.require_mfa_policy, "false");
});

test("control 10 resolves connection hosts from url only and flags connections without a url", async () => {
  const data = healthyData();
  data.connections = [
    { id: "c1", name: "approved-hook", type: "WebhookConnection", url: "https://hooks.example.com/x", defaultPayload: "{\"url\":\"https://hooks.evil.example/decoy\"}" },
    { id: "c2", name: "payload-only", type: "WebhookConnection", defaultPayload: "{\"url\":\"https://hooks.example.com/decoy\"}" },
  ];
  const governance = await assessSumologicDataGovernance(readerFrom(data), { now: NOW, approvedDestinationDomains: ["example.com"] });
  const forwarding = byId(governance, "SUMO-10");
  assert.equal(forwarding.status, "fail");
  assert.deepEqual(forwarding.evidence.destinations.map((item) => item.host), ["hooks.example.com", null]);
  assert.deepEqual(forwarding.evidence.unapproved_destinations, ["payload-only"]);

  data.connections = [data.connections[0]];
  const approved = await assessSumologicDataGovernance(readerFrom(data), { now: NOW, approvedDestinationDomains: ["example.com"] });
  assert.equal(byId(approved, "SUMO-10").status, "pass");
});

test("control 10 never passes the approved-domain check on an empty connection list while forwarding destinations remain", async () => {
  const options = { now: NOW, approvedDestinationDomains: ["example.com"] };

  const forwarding = healthyData();
  forwarding.connections = [];
  forwarding.partitions[0].dataForwardingId = "fwd-1";
  forwarding.scheduledViews[0].dataForwardingId = "fwd-2";
  const remaining = byId(await assessSumologicDataGovernance(readerFrom(forwarding), options), "SUMO-10");
  assert.equal(remaining.status, "manual", remaining.summary);
  assert.match(remaining.summary, /^No outbound connections were found to check against the approved destination domains; 2 data forwarding destination\(s\) on 1 partition\(s\) and 1 scheduled view\(s\) remain unchecked against the approved domains, so a human must confirm each forwarding destination is approved\.$/);
  assert.doesNotMatch(remaining.summary, /All 0 connections/);
  assert.equal(remaining.evidence.connections_seen, 0);
  assert.deepEqual(remaining.evidence.partitions_forwarding, ["sumologic_default"]);
  assert.deepEqual(remaining.evidence.scheduled_views_forwarding, ["errors"]);

  const emptyPartitions = healthyData();
  emptyPartitions.connections = [];
  emptyPartitions.partitions = [];
  emptyPartitions.scheduledViews = [];
  const unconfirmed = byId(await assessSumologicDataGovernance(readerFrom(emptyPartitions), options), "SUMO-10");
  assert.equal(unconfirmed.status, "manual", unconfirmed.summary);
  assert.match(unconfirmed.summary, /no data forwarding destination was seen but the partition inventory is empty, so that absence cannot be confirmed/);

  const nothingConfigured = healthyData();
  nothingConfigured.connections = [];
  const compliantEmptiness = byId(await assessSumologicDataGovernance(readerFrom(nothingConfigured), options), "SUMO-10");
  assert.equal(compliantEmptiness.status, "pass", "zero connections and zero forwarding destinations on readable, non-empty inventories still pass");
  assert.match(compliantEmptiness.summary, /^Zero outbound connections and zero data forwarding destinations/);

  const approvedWithForwarding = healthyData();
  approvedWithForwarding.connections = [{ id: "c1", name: "approved-hook", type: "WebhookConnection", url: "https://hooks.example.com/x" }];
  approvedWithForwarding.partitions[0].dataForwardingId = "fwd-1";
  const checked = byId(await assessSumologicDataGovernance(readerFrom(approvedWithForwarding), options), "SUMO-10");
  assert.equal(checked.status, "pass");
  assert.match(checked.summary, /^All 1 connections resolve to approved destination domains; 1 data forwarding destination\(s\) still require owner review\.$/);
});

test("approved_email_domains drives control 20 when org domains cannot be derived from the user list", async () => {
  const data = healthyData();
  data.monitors[0].notifications = [{ notification: { connectionType: "Email", recipients: ["soc@partner.example.org"] }, runForTriggerTypes: ["Critical"] }];
  const usersUnreadable = { listUsers: async () => failedCollection("forbidden", 403) };

  const noDomains = await assessSumologicContentSharing(readerFrom(data, usersUnreadable), { now: NOW });
  assert.equal(byId(noDomains, "SUMO-20").status, "manual");
  assert.match(byId(noDomains, "SUMO-20").summary, /no org email domains could be derived/);

  // Rule 1 corollary: approved domains let the recipients be judged, but the
  // unreadable user list still caps the verdict at warn and is named.
  const approved = await assessSumologicContentSharing(readerFrom(data, usersUnreadable), { now: NOW, approvedEmailDomains: ["partner.example.org"] });
  assert.equal(byId(approved, "SUMO-20").status, "warn");
  assert.match(byId(approved, "SUMO-20").summary, /Not checked: the user list could not be read because the access key lacks the role capability \(403\)/);
  assert.deepEqual(byId(approved, "SUMO-20").evidence.org_email_domains, ["partner.example.org"]);
  assert.deepEqual(byId(approved, "SUMO-20").evidence.unreadable_inventories, ["user list"]);

  const mismatch = await assessSumologicContentSharing(readerFrom(data, usersUnreadable), { now: NOW, approvedEmailDomains: ["example.com"] });
  assert.equal(byId(mismatch, "SUMO-20").status, "fail");
  assert.deepEqual(byId(mismatch, "SUMO-20").evidence.external_email_recipients, ["soc@partner.example.org"]);

  const combined = await assessSumologicContentSharing(readerFrom(data), { now: NOW, approvedEmailDomains: ["Partner.Example.org"] });
  assert.equal(byId(combined, "SUMO-20").status, "pass");
  assert.ok(byId(combined, "SUMO-20").evidence.org_email_domains.includes("example.com"));
  assert.ok(byId(combined, "SUMO-20").evidence.org_email_domains.includes("partner.example.org"));
});

test("a 401 response is reported as rejected credentials, is not retried, and never falls back to personal keys", async () => {
  const requests = [];
  const fetchImpl = async (input) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    requests.push(url.pathname);
    return jsonResponse({ errors: [{ code: "unauthorized", message: "Full authentication is required" }] }, { status: 401 });
  };
  const client = new SumologicApiClient(sampleConfig(), { fetchImpl, sleepImpl: async () => {} });

  const keys = await client.listAccessKeys();
  assert.equal(keys.ok, false);
  assert.equal(keys.httpStatus, 401);
  assert.match(keys.error, /\(401 unauthorized\)/);
  assert.deepEqual(requests, ["/api/v1/accessKeys"]);

  const access = await checkSumologicAccess(client);
  assert.equal(access.status, "limited");
  assert.equal(access.surfaces.filter((surface) => surface.status === "readable").length, 0);

  const unauthorized = async () => failedCollection("Sumo Logic request failed (401 unauthorized)", 401);
  const reader = { ...forbiddenReader() };
  for (const key of Object.keys(reader)) if (key !== "getResolvedConfig") reader[key] = unauthorized;
  const results = await allAssessments(reader);
  const findings = results.flatMap((result) => result.findings);
  assert.equal(findings.length, 20);
  for (const item of findings) {
    assert.equal(item.status, "manual", `${item.id} must be manual on 401`);
    assert.doesNotMatch(item.summary, /403/, `${item.id} must not describe a 401 as a 403`);
  }
  assert.match(byId(results[0], "SUMO-01").summary, /credentials were rejected \(401\)/);
  assert.equal(byId(results[0], "SUMO-01").evidence.http_status, 401);
  assert.match(byId(results[1], "SUMO-07").summary, /credentials were rejected \(401\)/);
});

test("undated items are never counted as fresh or active", async () => {
  const data = healthyData();
  data.accessKeys = [{ id: "k3", label: "undated", disabled: false, createdAt: null, lastUsed: null }];
  const access = await assessSumologicAccessControl(readerFrom(data), { now: NOW });
  assert.equal(byId(access, "SUMO-07").status, "warn");
  assert.match(byId(access, "SUMO-07").summary, /lack a createdAt timestamp/);
  assert.equal(byId(access, "SUMO-08").status, "warn");
  assert.match(byId(access, "SUMO-08").summary, /no lastUsed timestamp/);

  data.collectors = [{ id: 9, name: "ghost", collectorType: "Installable", alive: false, ephemeral: false, collectorVersion: "19.1" }];
  const governance = await assessSumologicDataGovernance(readerFrom(data), { now: NOW });
  assert.equal(byId(governance, "SUMO-12").status, "fail");
});

test("enabling flags that are false or absent do not support pass", async () => {
  const data = healthyData();
  data.policies.audit = {};
  data.policies.dataAccessLevel = {};
  data.allowlistStatus = { contentEnabled: true };
  data.identityProviders[0].debugMode = true;
  data.partitions = data.partitions.map((partition) => ({ ...partition, retentionPeriod: -1 }));
  const [identity, access, governance, content] = await allAssessments(readerFrom(data));
  assert.equal(byId(identity, "SUMO-01").status, "warn");
  assert.equal(byId(access, "SUMO-13").status, "fail");
  assert.equal(byId(governance, "SUMO-09").status, "fail");
  assert.match(byId(governance, "SUMO-09").summary, /enabled=absent/);
  assert.equal(byId(governance, "SUMO-17").status, "warn");
  assert.match(byId(governance, "SUMO-17").summary, /account default/);
  assert.equal(byId(content, "SUMO-11").status, "fail");
});

test("disabled monitors, org-wide shares, and plan-limited audit index downgrade verdicts", async () => {
  const data = healthyData();
  data.monitors[0].isDisabled = true;
  data.permissions = { explicitPermissions: [{ permissionName: "View", sourceType: "org", sourceId: "org", contentId: "c1" }] };
  data.personalFolder.children.push({ id: "c2", name: "Sensitive lookup", itemType: "Lookups" });
  data.partitions = [data.partitions[0]];
  data.accountStatus = { planType: "Free" };
  const [, , governance, content] = await allAssessments(readerFrom(data));
  assert.equal(byId(content, "SUMO-20").status, "warn");
  assert.equal(byId(content, "SUMO-11").status, "warn");
  assert.equal(byId(content, "SUMO-18").status, "warn");
  assert.equal(byId(governance, "SUMO-09").status, "manual");
  assert.match(byId(governance, "SUMO-09").summary, /plan Free/);
});

test("exportSumologicAuditBundle writes the bundle layout, zip, and error log, and never overwrites a prior bundle", async () => {
  const base = createTempBase("grclanker-sumo-export-");
  const reader = readerFrom(healthyData(), { listCollectors: async () => failedCollection("Sumo Logic request to /v1/collectors failed (403 forbidden)", 403) });

  const first = await exportSumologicAuditBundle(reader, sampleConfig(), base, { now: NOW });
  assert.ok(existsSync(first.outputDir));
  assert.ok(existsSync(first.zipPath));
  assert.equal(first.zipPath, `${first.outputDir}.zip`);
  assert.equal(first.findingCount, 20);
  assert.equal(first.errorCount, 1);
  assert.ok(first.fileCount >= 24);
  for (const relativePath of [
    "QUICK_REFERENCE.md",
    "metadata.json",
    "_errors.log",
    "core_data/access_check.json",
    "core_data/identity.json",
    "core_data/access-control.json",
    "core_data/data-governance.json",
    "core_data/content-sharing.json",
    "analysis/findings.json",
    "analysis/identity.json",
    "compliance/executive_summary.md",
    "compliance/unified_compliance_matrix.md",
    "compliance/fedramp.md",
    "compliance/cmmc.md",
    "compliance/soc-2.md",
    "compliance/cis.md",
    "compliance/pci-dss.md",
    "compliance/stig.md",
    "compliance/irap.md",
    "compliance/ismap.md",
  ]) {
    assert.ok(existsSync(join(first.outputDir, relativePath)), `${relativePath} missing`);
  }
  const metadata = JSON.parse(readFileSync(join(first.outputDir, "metadata.json"), "utf8"));
  assert.equal(metadata.deployment, "us2");
  assert.equal(metadata.access_id_prefix, "suAB");
  const bundleText = readFileSync(join(first.outputDir, "core_data", "access-control.json"), "utf8");
  assertNoWindowOf(bundleText, SAMPLE_ACCESS_KEY, "core_data/access-control.json");
  assert.match(readFileSync(join(first.outputDir, "_errors.log"), "utf8"), /collectors/);
  const findings = JSON.parse(readFileSync(join(first.outputDir, "analysis", "findings.json"), "utf8"));
  assert.equal(findings.find((item) => item.id === "SUMO-12").status, "manual");

  const second = await exportSumologicAuditBundle(readerFrom(healthyData()), sampleConfig(), base, { now: NOW });
  assert.notEqual(second.outputDir, first.outputDir);
  assert.notEqual(second.zipPath, first.zipPath);
  assert.equal(second.zipPath, `${second.outputDir}.zip`);
  assert.equal(second.errorCount, 0);
  assert.ok(!existsSync(join(second.outputDir, "_errors.log")));
  assert.ok(existsSync(first.zipPath));
});

/** Planted secrets for every credential-capable record: random alphanumerics, so no 6-character window of one occurs in a legitimate fixture value. */
const CARRIER = {
  webhookPathToken: "WLfKnscQU649TkVynC",
  webhookQueryToken: "kUkFvcpgZrvBNHV7BL",
  headerSecret: "uG8dhJSjYWYbStMXmJ",
  customHeaderSecret: "GS5CL3ytUXgqZSKXgn",
  routingKey: "FmEP7cQrCjqKDbBCpd",
  resolutionKey: "mLngURgY387cwCdzVN",
  snowUsername: "wwjh6rn7AsBB2VRJ8A",
  payloadOverride: "FRJXxnhkLKwZZhbP9X",
  resolutionOverride: "W4KfHSa7U9UU4AcSza",
  emailBodySecret: "WncUw2Cm8x2LECdwny",
  accessIdTail: "mkG5MhpSyKcnGS6yMw",
  x509Cert: "hX2twH7S4Sxg69PxqJ",
  spCert: "TWZw7cVFdCdgYs3NVg",
  dashboardQuery: "4HALeAXa7dmLqyGBbC",
  collectorField: "YZrCrYKnGMTHpg5bdm",
  folderDescription: "8GqWwDdtBBCjVFfkq6",
  policyLeaf: "LHKdcnVjcv57K5Z5mq",
};

function secretCarrierData() {
  const data = healthyData();
  data.connections = [
    {
      id: "c1",
      name: "pagerduty-hook",
      type: "WebhookConnection",
      webhookType: "PagerDuty",
      url: `https://hooks.example.com/services/${CARRIER.webhookPathToken}?token=${CARRIER.webhookQueryToken}`,
      headers: [{ name: "Authorization", value: `Bearer ${CARRIER.headerSecret}` }],
      customHeaders: [{ name: "X-Api-Key", value: CARRIER.customHeaderSecret }],
      defaultPayload: `{"routing_key":"${CARRIER.routingKey}"}`,
      resolutionPayload: `{"routing_key":"${CARRIER.resolutionKey}"}`,
    },
    { id: "c2", name: "servicenow", type: "ServiceNowConnection", url: "https://example.service-now.com/api", username: CARRIER.snowUsername },
  ];
  data.monitors[0].notifications.push({
    notification: { connectionType: "PagerDuty", connectionId: "c1", payloadOverride: `{"routing_key":"${CARRIER.payloadOverride}"}`, resolutionPayloadOverride: CARRIER.resolutionOverride },
    runForTriggerTypes: ["Critical"],
  });
  data.monitors[0].notifications[0].notification.messageBody = CARRIER.emailBodySecret;
  data.accessKeys = [{ id: `suAK${CARRIER.accessIdTail}`, label: "ci-key", disabled: false, createdAt: FRESH, lastUsed: FRESH, corsHeaders: ["https://app.example.com"] }];
  data.identityProviders[0].x509cert1 = CARRIER.x509Cert;
  data.identityProviders[0].certificate = CARRIER.spCert;
  data.dashboards[0].panels = [{ queryString: CARRIER.dashboardQuery }];
  data.collectors[0].fields = { token: CARRIER.collectorField };
  data.personalFolder.children[0].description = CARRIER.folderDescription;
  data.passwordPolicy.futureSecretSetting = CARRIER.policyLeaf;
  return data;
}

const CARRIER_SECRETS = [...Object.values(CARRIER), SAMPLE_ACCESS_KEY];

test("rule 9: the exported bundle, the zip, and the assess tool payloads never carry connection, monitor, key, or configuration secrets", async () => {
  const base = createTempBase("grclanker-sumo-secrets-");
  const data = secretCarrierData();
  const reader = readerFrom(data);
  assertFixtureFreeOfCanaryWindows(JSON.stringify({ data, config: sampleConfig() }), CARRIER_SECRETS, "secret carrier fixture");
  const secrets = leakWindows(CARRIER_SECRETS);

  const result = await exportSumologicAuditBundle(reader, sampleConfig(), base, { now: NOW, approvedDestinationDomains: ["example.com", "service-now.com"] });
  const files = readBundleFiles(result.outputDir);
  assert.ok(files.has(join("core_data", "data-governance.json")));
  assert.ok(files.has(join("core_data", "content-sharing.json")));
  assertSecretsAbsent(assert, files, secrets, "bundle directory");
  const zipEntries = readZipEntries(result.zipPath);
  assert.equal(zipEntries.size, files.size, "the zip carries exactly the written files");
  assert.ok(zipEntries.has("core_data/data-governance.json"));
  assertSecretsAbsent(assert, zipEntries, secrets, "zip archive");

  // Evidence stays legible: field names survive with markers, hosts survive without paths.
  const governance = JSON.parse(files.get(join("core_data", "data-governance.json")));
  const [hook, snow] = governance.connections.data;
  assert.equal(hook.url_host, "hooks.example.com");
  assert.equal(hook.url, "[REDACTED]");
  assert.deepEqual(hook.headers, [{ name: "Authorization", value: "[REDACTED]" }]);
  assert.deepEqual(hook.customHeaders, [{ name: "X-Api-Key", value: "[REDACTED]" }]);
  assert.equal(hook.defaultPayload, "[REDACTED]");
  assert.equal(hook.resolutionPayload, "[REDACTED]");
  assert.equal(snow.username, "[REDACTED]");
  assert.equal(governance.connections.count, 2);
  const accessControl = JSON.parse(files.get(join("core_data", "access-control.json")));
  assert.deepEqual(accessControl.access_keys.data, [{ label: "ci-key", disabled: false, createdAt: FRESH, lastUsed: FRESH, id_prefix: "suAK", cors_header_count: 1 }]);
  const content = JSON.parse(files.get(join("core_data", "content-sharing.json")));
  const pagerduty = content.monitors.data[0].notifications[1].notification;
  assert.equal(pagerduty.connectionId, "c1");
  assert.equal(pagerduty.payloadOverride, "[REDACTED]");
  assert.equal(pagerduty.resolutionPayloadOverride, "[REDACTED]");
  const identity = JSON.parse(files.get(join("core_data", "identity.json")));
  assert.equal(identity.saml_identity_providers.data[0].x509cert1, "[REDACTED]");
  assert.equal(identity.saml_identity_providers.data[0].configurationName, "Okta");
  assert.equal(identity.password_policy.data.minLength, 14);
  assert.equal(identity.password_policy.data.futureSecretSetting, undefined);

  // The assess tool payloads spread the same rawData, so they must be clean too,
  // while the verdicts still read the in-memory records (SUMO-10 resolves the host).
  const [identityResult, accessResult, governanceResult, contentResult] = [
    await assessSumologicIdentity(reader, { now: NOW }),
    await assessSumologicAccessControl(reader, { now: NOW }),
    await assessSumologicDataGovernance(reader, { now: NOW, approvedDestinationDomains: ["example.com", "service-now.com"] }),
    await assessSumologicContentSharing(reader, { now: NOW }),
  ];
  const payloads = new Map([
    ["identity", JSON.stringify(identityResult)],
    ["access-control", JSON.stringify(accessResult)],
    ["data-governance", JSON.stringify(governanceResult)],
    ["content-sharing", JSON.stringify(contentResult)],
  ]);
  assertSecretsAbsent(assert, payloads, secrets, "assess tool payload");
  assert.equal(byId(governanceResult, "SUMO-10").status, "pass");
  assert.deepEqual(byId(governanceResult, "SUMO-10").evidence.destinations.map((item) => item.host), ["hooks.example.com", "example.service-now.com"]);
  assert.equal(byId(contentResult, "SUMO-20").status, "pass");
});

/** Canaries planted in error bodies, each inside a carrier: random alphanumerics (the JWT keeps its eyJ header prefix and dotted shape). */
const ERROR_BODY = {
  bearerHtml: "tx4FsTaeQaHcbpGqB8",
  sessionHtml: "Ac89VDAd87GTPyz6Kr",
  apiKeyHtml: "hCddmrYzWJjBh9vUZq",
  urlToken: "G9zQNG7PXy37LgyAxr",
  html200: "mhBvKXUqmGBFpj6sAv",
  bearerJson: "PGvs3cKbU67hQtJcQU",
  apiKeyJson: "yc9gR8yHAwPbKEwkuA",
  sessionJson: "WVm4VnFUkDndLbNWGY",
  jwtHeader: "PkX7AwSVwuqDhutSUs",
  jwtPayload: "L9ZwDpETBGnMMZ8CZV",
  jwtSignature: "dN3pEfdd6jrnCd5RRM",
};
const ERROR_BODY_CANARIES = Object.values(ERROR_BODY);
const ERROR_BODY_HTML = `<html><body><h1>502 Bad Gateway</h1><p>Authorization: Bearer ${ERROR_BODY.bearerHtml}</p><p>Set-Cookie: JSESSIONID=${ERROR_BODY.sessionHtml}; Path=/</p><p>api_key=${ERROR_BODY.apiKeyHtml}</p><p>Retry at https://api.example.com/v1/x?token=${ERROR_BODY.urlToken} later.</p></body></html>`;
const ERROR_BODY_JSON = {
  errors: [{
    code: "forbidden",
    message: `Denied while fetching https://api.example.com/v1/x?token=${ERROR_BODY.urlToken} for this key, sent with Authorization: Bearer ${ERROR_BODY.bearerJson}, api_key=${ERROR_BODY.apiKeyJson} (session_id: ${ERROR_BODY.sessionJson}) and eyJ${ERROR_BODY.jwtHeader}.${ERROR_BODY.jwtPayload}.${ERROR_BODY.jwtSignature}`,
  }],
};
const ERROR_BODY_HTML_200 = `<html><body>Sign in. session=${ERROR_BODY.html200}</body></html>`;

function errorBodyFetch() {
  return async (input) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    if (url.pathname === "/api/v1/connections") {
      return new Response(ERROR_BODY_HTML, { status: 502, statusText: "Bad Gateway", headers: { "content-type": "text/html; charset=utf-8" } });
    }
    if (url.pathname === "/api/v1/roles") return jsonResponse(ERROR_BODY_JSON, { status: 403 });
    if (url.pathname === "/api/v1/collectors") {
      return new Response(ERROR_BODY_HTML_200, { status: 200, statusText: "OK", headers: { "content-type": "text/html" } });
    }
    if (url.pathname === "/api/v1/users") return jsonResponse({ data: healthyData().users });
    return jsonResponse({ data: [] });
  };
}

test("rule 9: error bodies and vendor messages are scrubbed at the record point, so a 502 HTML page or a URL with a token never reaches the bundle, the zip, the assess payloads, or the access check", async () => {
  const client = new SumologicApiClient(sampleConfig(), { fetchImpl: errorBodyFetch(), sleepImpl: async () => {}, maxRetries: 1 });
  assertFixtureFreeOfCanaryWindows(
    JSON.stringify({ data: healthyData(), config: sampleConfig(), bodies: [ERROR_BODY_HTML, ERROR_BODY_JSON, ERROR_BODY_HTML_200] }),
    ERROR_BODY_CANARIES,
    "error body fixture",
  );
  const secrets = leakWindows(ERROR_BODY_CANARIES);

  const connections = await client.listConnections();
  assert.equal(connections.ok, false);
  assert.equal(connections.httpStatus, 502);
  assert.match(connections.error, /^Sumo Logic request to \/v1\/connections failed \(502 Bad Gateway\): non-JSON body \(text\/html, \d+ bytes\)$/);
  const roles = await client.listRoles();
  assert.equal(roles.ok, false);
  assert.match(roles.error, /failed \(403 forbidden\): Denied while fetching https:\/\/api\.example\.com\/v1\/x\?\[REDACTED\] for this key, sent with Authorization: Bearer \[REDACTED\], api_key=\[REDACTED\] \(session_id: \[REDACTED\]\) and \[REDACTED\]$/);
  const collectors = await client.listCollectors();
  assert.equal(collectors.ok, false, "a 200 with a non-JSON body is an unreadable surface, not an empty inventory");
  assert.match(collectors.error, /returned an unreadable response \(200 OK\): non-JSON body \(text\/html, \d+ bytes\)$/);

  const access = await checkSumologicAccess(client);
  const connectionSurface = access.surfaces.find((surface) => surface.name === "connections");
  assert.equal(connectionSurface.status, "not_readable");
  assert.match(connectionSurface.error, /502 Bad Gateway\): non-JSON body \(text\/html, \d+ bytes\)/);
  assertSecretsAbsent(assert, new Map([["check_access", JSON.stringify(access)]]), secrets, "access check result");

  const results = await allAssessments(client);
  const payloads = new Map(results.map((result) => [result.area, JSON.stringify(result)]));
  assertSecretsAbsent(assert, payloads, secrets, "assess tool payload");
  const governance = results[2];
  assert.equal(byId(governance, "SUMO-10").status, "manual");
  assert.match(byId(governance, "SUMO-10").summary, /non-JSON body \(text\/html, \d+ bytes\)/, "the finding carries the status-and-length note instead of the body");
  assert.match(byId(results[1], "SUMO-06").evidence.endpoint_error, /https:\/\/api\.example\.com\/v1\/x\?\[REDACTED\] for this key/, "the URL keeps scheme, host, and path so the error stays legible, and its query collapses to a marker");

  const base = createTempBase("grclanker-sumo-error-bodies-");
  const exported = await exportSumologicAuditBundle(client, sampleConfig(), base, { now: NOW });
  const files = readBundleFiles(exported.outputDir);
  assert.ok(files.has("_errors.log"));
  assert.match(files.get("_errors.log"), /connections: Sumo Logic request to \/v1\/connections failed \(502 Bad Gateway\): non-JSON body \(text\/html, \d+ bytes\)/);
  assert.match(files.get("_errors.log"), /collectors: Sumo Logic request to \/v1\/collectors returned an unreadable response \(200 OK\): non-JSON body/);
  assertSecretsAbsent(assert, files, secrets, "bundle directory");
  assertSecretsAbsent(assert, readZipEntries(exported.zipPath), secrets, "zip archive");
});

/** Canaries planted in the failing surface's body, each inside a carrier: random alphanumerics. */
const SURFACE = { bearer: "rK4xXESacBR3fCZe6q", session: "3LJPkrKeAW4cNBHswF", apiKey: "hFUY8WTsSwjWGwETqw", urlToken: "DNEFcZkeyYdm3WhqWS" };
const SURFACE_CANARIES = Object.values(SURFACE);
const SURFACE_HTML_BODY = `<html><body><h1>502 Bad Gateway</h1><p>Authorization: Bearer ${SURFACE.bearer}</p><p>Set-Cookie: JSESSIONID=${SURFACE.session}; Path=/</p><p>api_key=${SURFACE.apiKey}</p><p>Retry at https://api.example.com/v1/x?token=${SURFACE.urlToken} later.</p></body></html>`;
const SURFACE_JSON_BODY = {
  errors: [{
    code: "forbidden",
    message: `Denied while fetching https://api.example.com/v1/x?token=${SURFACE.urlToken} for this key; Authorization: Bearer ${SURFACE.bearer}; api_key=${SURFACE.apiKey}; session_id=${SURFACE.session}`,
  }],
};

// Every path the client reads: the access check probes plus the collectors the
// assessments call outside the access check (the remaining policies and the
// content permission lookup). The access key inventory falls back to the
// personal endpoint on 403, so both endpoints belong to that surface.
const SUMOLOGIC_SURFACES = [
  ["account_status", ["/api/v1/account/status"]],
  ["users", ["/api/v1/users"]],
  ["roles", ["/api/v1/roles"]],
  ["access_keys", ["/api/v1/accessKeys", "/api/v1/accessKeys/personal"]],
  ["saml_identity_providers", ["/api/v1/saml/identityProviders"]],
  ["saml_allowlisted_users", ["/api/v1/saml/allowlistedUsers"]],
  ["password_policy", ["/api/v1/passwordPolicy"]],
  ["service_allowlist_status", ["/api/v1/serviceAllowlist/status"]],
  ["service_allowlist_addresses", ["/api/v1/serviceAllowlist/addresses"]],
  ["audit_policy", ["/api/v1/policies/audit"]],
  ["search_audit_policy", ["/api/v1/policies/searchAudit"]],
  ["share_dashboards_policy", ["/api/v1/policies/shareDashboardsOutsideOrganization"]],
  ["data_access_level_policy", ["/api/v1/policies/dataAccessLevel"]],
  ["concurrent_sessions_policy", ["/api/v1/policies/userConcurrentSessionsLimit"]],
  ["session_timeout_policy", ["/api/v1/policies/maxUserSessionTimeout"]],
  ["access_keys_lifetime_policy", ["/api/v1/policies/accessKeysLifetime"]],
  ["partitions", ["/api/v1/partitions"]],
  ["scheduled_views", ["/api/v1/scheduledViews"]],
  ["ingest_budgets", ["/api/v2/ingestBudgets"]],
  ["connections", ["/api/v1/connections"]],
  ["collectors", ["/api/v1/collectors"]],
  ["monitors", ["/api/v1/monitors/search"]],
  ["personal_folder", ["/api/v2/content/folders/personal"]],
  ["dashboards", ["/api/v2/dashboards"]],
  ["content_permissions", ["/api/v2/content/c1/permissions"]],
];

function healthyRoutes(data = healthyData()) {
  const routes = {
    "/api/v1/account/status": data.accountStatus,
    "/api/v1/users": { data: data.users },
    "/api/v1/roles": { data: data.roles },
    "/api/v1/accessKeys": { data: data.accessKeys },
    "/api/v1/accessKeys/personal": { data: data.accessKeys },
    "/api/v1/saml/identityProviders": data.identityProviders,
    "/api/v1/saml/allowlistedUsers": data.allowlistedUsers,
    "/api/v1/passwordPolicy": data.passwordPolicy,
    "/api/v1/serviceAllowlist/status": data.allowlistStatus,
    "/api/v1/serviceAllowlist/addresses": { data: data.allowlistAddresses },
    "/api/v1/partitions": { data: data.partitions },
    "/api/v1/scheduledViews": { data: data.scheduledViews },
    "/api/v2/ingestBudgets": { data: data.ingestBudgets },
    "/api/v1/connections": { data: data.connections },
    "/api/v1/collectors": { collectors: data.collectors },
    "/api/v1/monitors/search": data.monitors.map((item) => ({ item, path: `/Monitor/${item.name}` })),
    "/api/v2/content/folders/personal": data.personalFolder,
    "/api/v2/dashboards": { dashboards: data.dashboards },
    "/api/v2/content/c1/permissions": data.permissions,
  };
  for (const [name, policy] of Object.entries(data.policies)) routes[`/api/v1/policies/${name}`] = policy;
  return routes;
}

function surfaceCanaryFetch(failingPaths, variant) {
  const routes = healthyRoutes();
  return async (input) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    if (failingPaths.includes(url.pathname)) {
      return variant === "html"
        ? new Response(SURFACE_HTML_BODY, { status: 502, statusText: "Bad Gateway", headers: { "content-type": "text/html; charset=utf-8" } })
        : jsonResponse(SURFACE_JSON_BODY, { status: 403, statusText: "Forbidden" });
    }
    assert.ok(url.pathname in routes, `unexpected request to ${url.pathname}`);
    return jsonResponse(routes[url.pathname]);
  };
}

test("rule 9: every Sumo Logic surface that fails with a 502 HTML page or a JSON error embedding a token URL records only a scrubbed error, on every output", async () => {
  const base = createTempBase("grclanker-sumo-surface-canaries-");
  const healthy = await checkSumologicAccess(new SumologicApiClient(sampleConfig(), { fetchImpl: surfaceCanaryFetch([], "html"), maxRetries: 0 }));
  assert.equal(healthy.surfaces.filter((surface) => surface.status !== "readable").length, 0, "the healthy route table serves every probe");
  assertFixtureFreeOfCanaryWindows(
    JSON.stringify({ routes: healthyRoutes(), config: sampleConfig(), bodies: [SURFACE_HTML_BODY, SURFACE_JSON_BODY] }),
    SURFACE_CANARIES,
    "surface canary fixture",
  );
  const secrets = leakWindows(SURFACE_CANARIES);

  for (const [surface, paths] of SUMOLOGIC_SURFACES) {
    for (const variant of ["html", "json"]) {
      const label = `${surface} (${variant})`;
      const client = new SumologicApiClient(sampleConfig(), { fetchImpl: surfaceCanaryFetch(paths, variant), sleepImpl: async () => {}, maxRetries: 0 });
      const access = await checkSumologicAccess(client);
      const results = await allAssessments(client);
      const exported = await exportSumologicAuditBundle(client, sampleConfig(), join(base, `${surface}-${variant}`), { now: NOW });
      const files = readBundleFiles(exported.outputDir);

      const outputs = new Map([
        [`${label} check_access`, JSON.stringify(access)],
        ...results.map((result) => [`${label} assess ${result.area}`, JSON.stringify(result)]),
        ...[...files].map(([name, content]) => [`${label} bundle ${name}`, content]),
        ...[...readZipEntries(exported.zipPath)].map(([name, content]) => [`${label} zip ${name}`, content]),
      ]);
      assertSecretsAbsent(assert, outputs, secrets, label);

      const errorStrings = [
        ...access.surfaces.filter((item) => item.status === "not_readable").map((item) => item.error),
        ...results.flatMap((result) => result.errors),
        ...results.flatMap((result) => result.findings.map((item) => item.summary)).filter((summary) => /non-JSON body|api\.example\.com/.test(summary)),
      ];
      assert.ok(errorStrings.length >= 1, `${label}: the failing surface is recorded as an error`);
      for (const text of errorStrings) {
        if (variant === "html") {
          assert.match(text, /\(502 Bad Gateway\): non-JSON body \(text\/html, \d+ bytes\)/, `${label}: the error carries the status-and-length note, got ${text}`);
        } else {
          assert.match(text, /https:\/\/api\.example\.com\/v1\/x\?\[REDACTED\] for this key/, `${label}: the URL keeps scheme, host, and path and its query collapses to a marker, got ${text}`);
          assert.match(text, /Authorization: Bearer \[REDACTED\]/, `${label}: the authorization scheme stays and its value is redacted, got ${text}`);
        }
      }
    }
  }
});

// The list datasets the assessments collect, the API path each one reads, and
// the core_data file the collection is written to.
const SUMOLOGIC_LIST_DATASETS = [
  ["users", ["/api/v1/users"], "identity.json"],
  ["saml_identity_providers", ["/api/v1/saml/identityProviders"], "identity.json"],
  ["saml_allowlisted_users", ["/api/v1/saml/allowlistedUsers"], "identity.json"],
  ["roles", ["/api/v1/roles"], "access-control.json"],
  ["access_keys", ["/api/v1/accessKeys", "/api/v1/accessKeys/personal"], "access-control.json"],
  ["service_allowlist_addresses", ["/api/v1/serviceAllowlist/addresses"], "access-control.json"],
  ["partitions", ["/api/v1/partitions"], "data-governance.json"],
  ["scheduled_views", ["/api/v1/scheduledViews"], "data-governance.json"],
  ["connections", ["/api/v1/connections"], "data-governance.json"],
  ["ingest_budgets", ["/api/v2/ingestBudgets"], "data-governance.json"],
  ["collectors", ["/api/v1/collectors"], "data-governance.json"],
  ["monitors", ["/api/v1/monitors/search"], "content-sharing.json"],
  ["dashboards", ["/api/v2/dashboards"], "content-sharing.json"],
];

/**
 * Serves the healthy route table, denies `deniedPaths` with a 403 JSON body,
 * serves `emptyPaths` as readable empty lists, and records every request it
 * answered so the outputs can be checked against what the run observed.
 */
function recordingFetch({ deniedPaths = [], emptyPaths = [] } = {}) {
  const routes = healthyRoutes();
  const requests = [];
  const fetchImpl = async (input, init = {}) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    const method = init.method ?? "GET";
    let response;
    if (deniedPaths.includes(url.pathname)) {
      response = jsonResponse({ errors: [{ code: "forbidden", message: "The access key lacks the capability for this endpoint" }] }, { status: 403, statusText: "Forbidden" });
    } else if (emptyPaths.includes(url.pathname)) {
      response = jsonResponse(url.pathname === "/api/v1/collectors" ? { collectors: [] } : url.pathname === "/api/v2/dashboards" ? { dashboards: [] } : url.pathname === "/api/v1/monitors/search" ? [] : { data: [] });
    } else {
      assert.ok(url.pathname in routes, `unexpected request to ${url.pathname}`);
      response = jsonResponse(routes[url.pathname]);
    }
    requests.push({ method, path: url.pathname, status: response.status });
    return response;
  };
  return { fetchImpl, requests };
}

const MENTIONED_STATUS_PATTERNS = [
  /\((\d{3})(?: [A-Za-z][A-Za-z ]*)?\)/g,
  /"(?:http_status|httpStatus|status)":\s*(\d{3})\b/g,
  /\b(?:HTTP|status|returned)\s+(\d{3})\b/gi,
];
const MENTIONED_ENDPOINT_PATTERN = /\/(?:api\/)?v[123]\/[A-Za-z0-9_./{}-]*[A-Za-z0-9}]/g;

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
      const template = new RegExp(`${mention.replace(/[.*+?^$()|[\]\\]/g, "\\$&").replace(/\\\{[^}]*\\\}|\{[^}]*\}/g, "[^/]+")}$`);
      assert.ok(observedPaths.some((path) => template.test(path)), `${label} ${name}: names endpoint ${mention} but the run requested only ${[...new Set(observedPaths)].join(", ")}`);
    }
  }
}

function sumologicOutputs(access, results, exported) {
  return new Map([
    ["check_access", JSON.stringify(access)],
    ...results.map((result) => [`assess ${result.area}`, JSON.stringify(result)]),
    ...[...readBundleFiles(exported.outputDir)].map(([name, content]) => [`bundle ${name}`, content]),
  ]);
}

test("collection status: a denied list dataset is written to core_data and the assess payload as a not-collected marker with null flags, and every status code and endpoint named in any output was actually observed", async () => {
  const base = createTempBase("grclanker-sumo-denied-markers-");

  for (const [dataset, paths, areaFile] of SUMOLOGIC_LIST_DATASETS) {
    const { fetchImpl, requests } = recordingFetch({ deniedPaths: paths });
    const client = new SumologicApiClient(sampleConfig(), { fetchImpl, sleepImpl: async () => {}, maxRetries: 0 });
    const access = await checkSumologicAccess(client);
    const results = await allAssessments(client);
    const exported = await exportSumologicAuditBundle(client, sampleConfig(), join(base, dataset), { now: NOW });

    const snapshot = JSON.parse(readFileSync(join(exported.outputDir, "core_data", areaFile), "utf8"));
    const entry = snapshot[dataset];
    assert.ok(entry, `${dataset}: written to core_data/${areaFile}`);
    assert.equal(entry.ok, false);
    assert.equal(entry.complete, null, `${dataset}: complete is null, not false, when nothing was read`);
    assert.equal(entry.scope, null, `${dataset}: scope is null, not org, when nothing was read`);
    assert.equal(entry.count, null);
    assert.equal(entry.http_status, 403);
    assert.ok(!Array.isArray(entry.data), `${dataset}: a denied list is never written as an array`);
    assert.deepEqual(entry.data, { collected: false, status: 403, endpoint: entry.endpoint, error: entry.error });
    assert.ok(paths.some((path) => path.endsWith(entry.data.endpoint)), `${dataset}: the marker names the denied endpoint, got ${entry.data.endpoint}`);
    assert.match(entry.data.error, /failed \(403 forbidden\)/);

    const rawEntry = results.find((result) => result.rawData[dataset])?.rawData[dataset];
    assert.deepEqual(rawEntry.data, entry.data, `${dataset}: the assess payload carries the same marker`);

    const surface = access.surfaces.find((item) => item.name === dataset);
    assert.equal(surface.status, "not_readable");
    assert.equal(surface.count, null, `${dataset}: access check count is null when the probe failed`);
    assert.equal(surface.complete, null, `${dataset}: access check complete is null when the probe failed`);
    assert.equal(surface.httpStatus, 403);
    assert.ok(paths.some((path) => path.endsWith(surface.endpoint)), `${dataset}: the surface names the endpoint that failed, got ${surface.endpoint}`);

    assertOutputsNameOnlyObservedRequests(sumologicOutputs(access, results, exported), requests, `${dataset} denied`);
  }

  const { fetchImpl, requests } = recordingFetch({ emptyPaths: ["/api/v1/connections", "/api/v1/scheduledViews", "/api/v1/collectors", "/api/v2/dashboards", "/api/v1/monitors/search"] });
  const client = new SumologicApiClient(sampleConfig(), { fetchImpl, sleepImpl: async () => {}, maxRetries: 0 });
  const access = await checkSumologicAccess(client);
  const results = await allAssessments(client);
  const exported = await exportSumologicAuditBundle(client, sampleConfig(), join(base, "empty"), { now: NOW });
  const governance = JSON.parse(readFileSync(join(exported.outputDir, "core_data", "data-governance.json"), "utf8"));
  const sharing = JSON.parse(readFileSync(join(exported.outputDir, "core_data", "content-sharing.json"), "utf8"));
  for (const entry of [governance.connections, governance.scheduled_views, governance.collectors, sharing.dashboards, sharing.monitors]) {
    assert.deepEqual(entry.data, [], "a readable empty list stays []");
    assert.equal(entry.ok, true);
    assert.equal(entry.complete, true);
    assert.equal(entry.count, 0);
    assert.equal(entry.http_status, null);
  }
  for (const surface of access.surfaces) {
    assert.equal(surface.status, "readable");
    assert.equal(typeof surface.count, "number");
    assert.equal(surface.complete, true);
    assert.equal(surface.httpStatus, null);
  }
  assertOutputsNameOnlyObservedRequests(sumologicOutputs(access, results, exported), requests, "healthy with empty lists");
});

test("rule 10: token pagination stops on a repeated cursor or an empty page with a next token and reports the inventory incomplete", async () => {
  let repeatedRequests = 0;
  let emptyRequests = 0;
  const fetchImpl = async (input) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    if (url.pathname === "/api/v1/roles") {
      repeatedRequests += 1;
      return jsonResponse({ data: [{ id: `r${repeatedRequests}`, name: `Role ${repeatedRequests}` }], next: "stuck-cursor" });
    }
    if (url.pathname === "/api/v2/ingestBudgets") {
      emptyRequests += 1;
      return jsonResponse({ data: emptyRequests === 1 ? [{ id: "b1", name: "budget" }] : [], next: `page-${emptyRequests + 1}` });
    }
    if (url.pathname === "/api/v1/collectors") return jsonResponse({ collectors: Array.from({ length: 1000 }, (_, index) => ({ id: index, name: `c${index}` })) });
    return jsonResponse({});
  };
  const client = new SumologicApiClient(sampleConfig(), { fetchImpl, maxPages: 50, maxRetries: 0 });

  const roles = await client.listRoles();
  assert.equal(roles.ok, true);
  assert.equal(roles.complete, false, "a repeated next token must not report a complete inventory");
  assert.equal(repeatedRequests, 2, "the repeated cursor is detected on the second page, not at the page cap");
  assert.equal(roles.data.length, 2);

  const budgets = await client.listIngestBudgets();
  assert.equal(budgets.complete, false, "an empty page with a next token must not report a complete inventory");
  assert.equal(emptyRequests, 2);
  assert.equal(budgets.data.length, 1);

  const capped = new SumologicApiClient(sampleConfig(), { fetchImpl, maxPages: 2, maxRetries: 0 });
  const collectors = await capped.listCollectors();
  assert.equal(collectors.complete, false, "offset pagination that hits the page cap on a full page is incomplete");
  assert.equal(collectors.data.length, 2000);

  const governance = await assessSumologicDataGovernance(readerFrom(healthyData(), { listRoles: async () => roles, listCollectors: async () => collectors }), { now: NOW });
  assert.equal(byId(governance, "SUMO-12").status, "warn");
  assert.match(byId(governance, "SUMO-12").summary, /Pagination stopped before the last page, so only 2000 items were seen/);
});

test("foreign-origin next link: a URL-shaped next cursor is only ever a token query value on the configured base, so no request leaves for it and the Basic credential stays on the configured origin", async () => {
  const foreignParts = { host: "collector.evil-example.net", path: "/harvest/sumo-basic", query: "sink=basic&page=2" };
  const foreign = `https://${foreignParts.host}${foreignParts.path}?${foreignParts.query}`;
  const requests = [];
  const fetchImpl = async (input, init = {}) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    requests.push({ url, authorization: headerValue(init.headers, "authorization") });
    if (url.pathname !== "/api/v1/roles") return jsonResponse({});
    if (!url.searchParams.get("token")) return jsonResponse({ data: [{ id: "r1", name: "Role 1" }], next: foreign });
    return jsonResponse({ data: [{ id: "r2", name: "Role 2" }], next: null });
  };
  const client = new SumologicApiClient(sampleConfig(), { fetchImpl, maxPages: 50, maxRetries: 0 });

  const roles = await client.listRoles();
  assert.equal(roles.ok, true);
  assert.equal(roles.complete, true);
  assert.equal(roles.data.length, 2);
  assert.equal(requests.length, 2);
  assert.ok(requests.every((request) => request.url.origin === "https://api.us2.sumologic.com"), "every request went to the configured base origin");
  assert.ok(requests.every((request) => request.url.pathname === "/api/v1/roles"), "the walk never left the declared path");
  assert.equal(requests[1].url.searchParams.get("token"), foreign, "the server's next value travels back only as the token query value");
  assert.ok(requests.every((request) => request.authorization.startsWith("Basic ")), "the credential went to the configured origin only");
  for (const part of Object.values(foreignParts)) assert.ok(!JSON.stringify(roles).includes(part), `the collection carries no ${part}`);
});

test("rule 10: control 10 names each capped forwarding inventory and never passes on a truncated partition or scheduled view list", async () => {
  const data = healthyData();
  const partial = (items) => collectionOf(items, { complete: false });

  const viewsCapped = await assessSumologicDataGovernance(readerFrom(data, { listScheduledViews: async () => partial(data.scheduledViews) }), { now: NOW });
  assert.equal(byId(viewsCapped, "SUMO-10").status, "warn");
  assert.match(byId(viewsCapped, "SUMO-10").summary, /Pagination of the scheduled view list stopped before the last page, so only 1 were seen/);
  assert.deepEqual(byId(viewsCapped, "SUMO-10").evidence.incomplete_inventories, ["scheduled view list"]);
  assert.equal(byId(viewsCapped, "SUMO-10").evidence.scheduled_views_complete, false);
  assert.equal(byId(viewsCapped, "SUMO-10").evidence.partitions_complete, true);

  const partitionsCapped = await assessSumologicDataGovernance(readerFrom(data, { listPartitions: async () => partial(data.partitions) }), { now: NOW, approvedDestinationDomains: ["example.com"] });
  assert.equal(byId(partitionsCapped, "SUMO-10").status, "warn");
  assert.match(byId(partitionsCapped, "SUMO-10").summary, /Pagination of the partition list stopped before the last page, so only 2 were seen/);
  assert.equal(byId(partitionsCapped, "SUMO-09").status, "warn", "SUMO-09 never passes on a page-capped partition list");
  assert.match(byId(partitionsCapped, "SUMO-09").summary, /active audit index partition\(s\) exist .* Pagination stopped before the last page, so only 2 items were seen and the population is incomplete\.$/);
  assert.equal(byId(partitionsCapped, "SUMO-09").evidence.partitions_complete, false);
  assert.equal(byId(partitionsCapped, "SUMO-09").evidence.partitions_seen, 2);
  const partitionsComplete = await assessSumologicDataGovernance(readerFrom(data), { now: NOW });
  assert.equal(byId(partitionsComplete, "SUMO-09").status, "pass");
  assert.doesNotMatch(byId(partitionsComplete, "SUMO-09").summary, /Pagination stopped/);

  const allCapped = await assessSumologicDataGovernance(readerFrom(data, {
    listPartitions: async () => partial(data.partitions),
    listScheduledViews: async () => partial(data.scheduledViews),
    listConnections: async () => partial(data.connections),
  }), { now: NOW });
  assert.equal(byId(allCapped, "SUMO-10").status, "warn");
  assert.deepEqual(byId(allCapped, "SUMO-10").evidence.incomplete_inventories, ["connection list", "partition list", "scheduled view list"]);
});

// `unread` names the evidence fields derived from the denied inventory; each
// must render null (never 0 or []) when that inventory returns 403.
const MULTI_INVENTORY_FINDINGS = [
  { id: "SUMO-02", area: "identity", secondary: "listSamlIdentityProviders", names: /the SAML identity provider list could not be read/, unread: ["identity_providers"] },
  { id: "SUMO-05", area: "identity", secondary: "listUsers", names: /user list was unreadable/, unread: ["users_seen", "active_users", "active_users_without_mfa", "locked_users", "dormant_active_users"] },
  { id: "SUMO-06", area: "access", secondary: "listUsers", names: /user list was unreadable/, unread: ["admin_members_seen_in_user_list", "dormant_admin_members", "locked_users"] },
  { id: "SUMO-07", area: "access", secondary: "getPolicy:accessKeysLifetime", names: /lifetime policy was unreadable/, unread: ["access_keys_lifetime_policy_days"] },
  { id: "SUMO-13", area: "access", secondary: "listServiceAllowlistAddresses", names: /CIDR list was unreadable/, unread: ["addresses_seen", "cidrs"] },
  { id: "SUMO-14", area: "access", secondary: "getPolicy:userConcurrentSessionsLimit", names: /the concurrent sessions limit policy could not be read/, unread: ["concurrent_sessions_limit_enabled", "max_concurrent_sessions"] },
  { id: "SUMO-09", area: "governance", secondary: "listPartitions", names: /partition list was unreadable/, unread: ["partitions_seen", "active_audit_index_partitions", "audit_index_partitions"] },
  { id: "SUMO-09", area: "governance", secondary: "getPolicy:searchAudit", names: /the search audit policy could not be read/, unread: ["search_audit_enabled"] },
  { id: "SUMO-10", area: "governance", secondary: "listPartitions", names: /the partition list could not be read/, options: { approvedDestinationDomains: ["example.com"] }, unread: ["partitions_seen", "partitions_forwarding"] },
  { id: "SUMO-10", area: "governance", secondary: "listScheduledViews", names: /the scheduled view list could not be read/, options: { approvedDestinationDomains: ["example.com"] }, unread: ["scheduled_views_seen", "scheduled_views_forwarding"] },
  { id: "SUMO-11", area: "content", secondary: "getPersonalFolder", names: /the personal folder could not be read/, unread: ["personal_folder_items_total", "personal_folder_items_sampled", "org_shared_items"] },
  { id: "SUMO-11", area: "content", secondary: "getContentPermissions", names: /1 content permission lookup\(s\) failed/, recorded: { permission_lookups_failed: 1 } },
  { id: "SUMO-15", area: "content", secondary: "listMonitors", names: /the monitor list could not be read/, baseline: "manual", unread: ["monitors_seen", "monitors_with_run_as"] },
  { id: "SUMO-15", area: "content", secondary: "getPersonalFolder", names: /the personal folder could not be read/, baseline: "manual", unread: ["personal_folder_items_total", "scheduled_searches_in_sampled_folder"] },
  { id: "SUMO-18", area: "content", secondary: "getPersonalFolder", names: /the personal folder could not be read/, baseline: "manual", unread: ["personal_folder_items_total", "lookup_tables_in_sampled_folder"] },
  { id: "SUMO-19", area: "content", secondary: "listDashboards", names: /dashboard list was unreadable/, unread: ["dashboards_seen", "public_dashboards"] },
  { id: "SUMO-20", area: "content", secondary: "listUsers", names: /the user list could not be read/, options: { approvedEmailDomains: ["example.com"] }, unread: ["users_seen"] },
  { id: "SUMO-20", area: "content", secondary: "listConnections", names: /the connection list could not be read/, options: { approvedEmailDomains: ["example.com"] }, unread: ["connections_seen", "notifications_to_unknown_connections"] },
];

async function assessArea(area, reader, options) {
  switch (area) {
    case "identity":
      return assessSumologicIdentity(reader, { now: NOW, ...options });
    case "access":
      return assessSumologicAccessControl(reader, { now: NOW, ...options });
    case "governance":
      return assessSumologicDataGovernance(reader, { now: NOW, ...options });
    default:
      return assessSumologicContentSharing(reader, { now: NOW, ...options });
  }
}

test("rule 1 corollary: every multi-inventory finding drops below pass and names the inventory when one secondary inventory returns 403", async () => {
  const forbidden = () => failedCollection("Sumo Logic request failed (403 forbidden)", 403);
  for (const scenario of MULTI_INVENTORY_FINDINGS) {
    const data = healthyData();
    data.monitors[0].notifications.push({ notification: { connectionType: "Webhook", connectionId: "c1" }, runForTriggerTypes: ["Critical"] });
    data.connections = [{ id: "c1", name: "hook", type: "WebhookConnection", url: "https://hooks.example.com/x" }];
    const label = `${scenario.id} with ${scenario.secondary} forbidden`;

    const healthy = await assessArea(scenario.area, readerFrom(data), scenario.options);
    assert.equal(byId(healthy, scenario.id).status, scenario.baseline ?? "pass", `${label}: baseline must be ${scenario.baseline ?? "pass"} so the demotion is meaningful`);

    const [method, policyName] = scenario.secondary.split(":");
    const override = policyName
      ? { getPolicy: async (name) => (name === policyName ? forbidden() : collectionOf(data.policies[name] ?? {})) }
      : { [method]: async () => forbidden() };
    const result = await assessArea(scenario.area, readerFrom(data, override), scenario.options);
    const item = byId(result, scenario.id);
    assert.notEqual(item.status, "pass", `${label}: must not pass (got ${item.status}: ${item.summary})`);
    assert.match(item.summary, scenario.names, `${label}: summary names the unreadable inventory`);
    assert.match(item.summary, /403|unreadable|could not be read|failed/, `${label}: summary states the cause`);
    for (const field of scenario.unread ?? []) {
      assert.ok(field in item.evidence, `${label}: evidence carries ${field}`);
      assert.equal(item.evidence[field], null, `${label}: ${field} renders null for the unreadable inventory, not ${JSON.stringify(item.evidence[field])}`);
    }
    for (const [field, value] of Object.entries(scenario.recorded ?? {})) {
      assert.equal(item.evidence[field], value, `${label}: ${field} records the failed lookup`);
    }
    assert.doesNotMatch(item.summary, /\b0\/0\b|\b0 (?:monitor|dashboard|user|partition|item)s? (?:seen|were seen|returned)/, `${label}: summary does not render a zero count for the unreadable inventory`);
  }

  // Spot checks on the verdict each fix settles on.
  const data = healthyData();
  data.monitors[0].notifications.push({ notification: { connectionType: "Webhook", connectionId: "c1" }, runForTriggerTypes: ["Critical"] });
  data.connections = [{ id: "c1", name: "hook", type: "WebhookConnection", url: "https://hooks.example.com/x" }];
  const noConnections = await assessSumologicContentSharing(readerFrom(data, { listConnections: async () => forbidden() }), { now: NOW });
  assert.equal(byId(noConnections, "SUMO-20").status, "manual", "webhook notifications cannot be validated without the connection list");
  assert.deepEqual(byId(noConnections, "SUMO-20").evidence.unreadable_inventories, ["connection list"]);
  const emailOnly = healthyData();
  const noConnectionsEmailOnly = await assessSumologicContentSharing(readerFrom(emailOnly, { listConnections: async () => forbidden() }), { now: NOW });
  assert.equal(byId(noConnectionsEmailOnly, "SUMO-20").status, "warn", "email-only routing can still be judged, so the missing connection list caps at warn");
  const noViews = await assessSumologicDataGovernance(readerFrom(healthyData(), { listScheduledViews: async () => forbidden() }), { now: NOW, approvedDestinationDomains: ["example.com"] });
  assert.equal(byId(noViews, "SUMO-10").status, "manual");
  assert.equal(byId(noViews, "SUMO-10").evidence.scheduled_views_readable, false);
  const noSearchAudit = await assessSumologicDataGovernance(readerFrom(healthyData(), { getPolicy: async (name) => (name === "searchAudit" ? forbidden() : collectionOf(healthyData().policies[name] ?? {})) }), { now: NOW });
  assert.equal(byId(noSearchAudit, "SUMO-09").status, "warn");
  assert.doesNotMatch(byId(noSearchAudit, "SUMO-09").summary, /search audit policies are enabled/);
  const noIdps = await assessSumologicIdentity(readerFrom(healthyData(), { listSamlIdentityProviders: async () => forbidden() }), { now: NOW });
  assert.equal(byId(noIdps, "SUMO-02").status, "warn");
  const noConcurrent = await assessSumologicAccessControl(readerFrom(healthyData(), { getPolicy: async (name) => (name === "userConcurrentSessionsLimit" ? forbidden() : collectionOf(healthyData().policies[name] ?? {})) }), { now: NOW });
  assert.equal(byId(noConcurrent, "SUMO-14").status, "warn");
  assert.doesNotMatch(byId(noConcurrent, "SUMO-14").summary, /policy is not enabled/);
  assert.equal(byId(noConcurrent, "SUMO-14").evidence.concurrent_sessions_limit_enabled, null);

  // Uniform null rendering reaches the assessment summaries too.
  const noUsersIdentity = await assessSumologicIdentity(readerFrom(healthyData(), { listUsers: async () => forbidden() }), { now: NOW });
  assert.equal(noUsersIdentity.summary.users_seen, null);
  assert.equal(noUsersIdentity.summary.active_users_without_mfa, null);
  assert.equal(noUsersIdentity.summary.identity_providers, 1);
  const noMfaPolicyUsers = healthyData();
  noMfaPolicyUsers.passwordPolicy.requireMfa = false;
  const failNoUsers = await assessSumologicIdentity(readerFrom(noMfaPolicyUsers, { listUsers: async () => forbidden() }), { now: NOW });
  assert.equal(byId(failNoUsers, "SUMO-05").status, "fail");
  assert.match(byId(failNoUsers, "SUMO-05").summary, /per-user MFA status is unknown because the user list could not be read/);
  assert.doesNotMatch(byId(failNoUsers, "SUMO-05").summary, /0\/0/);
  const noPartitions = await assessSumologicDataGovernance(readerFrom(healthyData(), { listPartitions: async () => forbidden() }), { now: NOW });
  assert.equal(noPartitions.summary.partitions_seen, null);
  assert.equal(noPartitions.summary.active_audit_indexes, null);
  assert.equal(noPartitions.summary.collectors_seen, 2);
  const noFolder = await assessSumologicContentSharing(readerFrom(healthyData(), { getPersonalFolder: async () => forbidden(), listDashboards: async () => forbidden() }), { now: NOW });
  assert.equal(noFolder.summary.personal_folder_items_total, null);
  assert.equal(noFolder.summary.org_shared_items, null);
  assert.equal(noFolder.summary.dashboards_seen, null);
  assert.match(byId(noFolder, "SUMO-15").summary, /the personal folder could not be read so no scheduled searches were sampled/);
  const noKeys = await assessSumologicAccessControl(readerFrom(healthyData(), { listAccessKeys: async () => forbidden() }), { now: NOW });
  assert.equal(noKeys.summary.access_keys_seen, null);
  assert.equal(noKeys.summary.access_key_scope, null);
});

test("content permissions: never requested when the personal folder is unreadable, not collected when every lookup failed, and counted only from the lookups that succeeded", async () => {
  const base = createTempBase("grclanker-sumo-content-permissions-");
  const marker = (entry) => entry.data;

  const folderDenied = recordingFetch({ deniedPaths: ["/api/v2/content/folders/personal"] });
  const folderClient = new SumologicApiClient(sampleConfig(), { fetchImpl: folderDenied.fetchImpl, sleepImpl: async () => {}, maxRetries: 0 });
  const folderAccess = await checkSumologicAccess(folderClient);
  const folderResults = await allAssessments(folderClient);
  const folderExport = await exportSumologicAuditBundle(folderClient, sampleConfig(), join(base, "folder-denied"), { now: NOW });
  assert.ok(folderDenied.requests.every((request) => !/\/permissions$/.test(request.path)), "no permission lookup is issued when the folder listing failed");
  const folderSharing = folderResults.find((result) => result.area === "content-sharing");
  for (const [label, entry] of [
    ["core_data", JSON.parse(readFileSync(join(folderExport.outputDir, "core_data", "content-sharing.json"), "utf8")).content_permissions],
    ["rawData", folderSharing.rawData.content_permissions],
  ]) {
    assert.equal(entry.ok, false, `${label}: content_permissions is not collected`);
    assert.equal(entry.complete, null, label);
    assert.equal(entry.scope, null, label);
    assert.equal(entry.count, null, `${label}: count is null, not 0`);
    assert.equal(entry.http_status, null, `${label}: no status is invented for lookups that were never issued`);
    assert.equal(entry.endpoint, null, `${label}: no endpoint is invented for lookups that were never issued`);
    assert.match(entry.error, /^Not requested: no content permission lookups were issued because the personal folder could not be read \(.*\(403 forbidden\).*\)\.$/, label);
    assert.deepEqual(marker(entry), { collected: false, status: null, endpoint: null, error: entry.error }, `${label}: the marker, not []`);
  }
  assert.ok(folderSharing.errors.some((line) => /^content_permissions: Not requested: /.test(line)));
  assert.equal(byId(folderSharing, "SUMO-11").evidence.org_shared_items, null);
  assertOutputsNameOnlyObservedRequests(sumologicOutputs(folderAccess, folderResults, folderExport), folderDenied.requests, "personal folder denied");

  const lookupsDenied = recordingFetch({ deniedPaths: ["/api/v2/content/c1/permissions"] });
  const lookupClient = new SumologicApiClient(sampleConfig(), { fetchImpl: lookupsDenied.fetchImpl, sleepImpl: async () => {}, maxRetries: 0 });
  const lookupAccess = await checkSumologicAccess(lookupClient);
  const lookupResults = await allAssessments(lookupClient);
  const lookupExport = await exportSumologicAuditBundle(lookupClient, sampleConfig(), join(base, "lookups-denied"), { now: NOW });
  assert.ok(lookupsDenied.requests.some((request) => request.path === "/api/v2/content/c1/permissions" && request.status === 403), "the lookup was issued and denied");
  const lookupSharing = lookupResults.find((result) => result.area === "content-sharing");
  for (const [label, entry] of [
    ["core_data", JSON.parse(readFileSync(join(lookupExport.outputDir, "core_data", "content-sharing.json"), "utf8")).content_permissions],
    ["rawData", lookupSharing.rawData.content_permissions],
  ]) {
    assert.equal(entry.ok, false, `${label}: a set of lookups that all failed is not collected`);
    assert.equal(entry.count, null, `${label}: count is null, not the number of items whose lookups failed`);
    assert.equal(entry.complete, null, label);
    assert.equal(entry.http_status, null, `${label}: no single status stands for the whole set`);
    assert.equal(entry.endpoint, null, label);
    assert.match(entry.error, /^every content permission lookup failed \(1 of 1\): .*\(403 forbidden\)/, label);
    assert.deepEqual(marker(entry), { collected: false, status: null, endpoint: null, error: entry.error }, label);
  }
  assert.equal(lookupSharing.summary.org_shared_items, null, "org-wide shares are unknown when every lookup failed");
  const sharingFinding = byId(lookupSharing, "SUMO-11");
  assert.equal(sharingFinding.status, "manual");
  assert.equal(sharingFinding.evidence.org_shared_items, null, "never [] from lookups that all failed");
  assert.equal(sharingFinding.evidence.permission_lookups_failed, 1);
  assert.equal(sharingFinding.evidence.personal_folder_items_sampled, 1, "the folder itself was read, so its counts are real");
  assert.equal(byId(lookupSharing, "SUMO-18").evidence.lookup_tables_shared_org_wide, null);
  assertOutputsNameOnlyObservedRequests(sumologicOutputs(lookupAccess, lookupResults, lookupExport), lookupsDenied.requests, "permission lookups denied");

  const twoItems = healthyData();
  twoItems.personalFolder.children = [
    { id: "c1", name: "Shared search", itemType: "Search" },
    { id: "c2", name: "Private lookup", itemType: "Lookups" },
  ];
  const partial = await assessSumologicContentSharing(
    readerFrom(twoItems, {
      getContentPermissions: async (id) => (id === "c2" ? failedCollection("Sumo Logic request failed (403 forbidden)", 403, "/v2/content/c2/permissions") : collectionOf(twoItems.permissions)),
    }),
    { now: NOW },
  );
  const partialEntry = partial.rawData.content_permissions;
  assert.equal(partialEntry.ok, true, "one successful lookup makes the set collected");
  assert.equal(partialEntry.complete, false, "a failed lookup makes it incomplete");
  assert.equal(partialEntry.count, 2);
  assert.deepEqual(partialEntry.data.map((row) => [row.id, row.ok]), [["c1", true], ["c2", false]]);
  assert.equal(partial.summary.org_shared_items, byId(partial, "SUMO-11").evidence.org_shared_items.length, "the count covers the lookups that succeeded");
  assert.equal(byId(partial, "SUMO-11").evidence.permission_lookups_failed, 1);
  assert.notEqual(byId(partial, "SUMO-11").status, "pass");
  assert.match(byId(partial, "SUMO-11").summary, /1 content permission lookup\(s\) failed \(Private lookup: /);
});

test("resolveSecureOutputPath rejects traversal and symlink parents", () => {
  const base = createTempBase("grclanker-sumo-path-");
  const outside = createTempBase("grclanker-sumo-outside-");
  const linked = join(base, "linked");
  symlinkSync(outside, linked, "dir");

  assert.throws(() => resolveSecureOutputPath(base, "../escape"), /Refusing to write outside/);
  assert.throws(() => resolveSecureOutputPath(base, "linked/file.txt"), /symlinked parent directory/);
  const safe = resolveSecureOutputPath(base, join("compliance", "safe.md"));
  assert.match(safe, /compliance\/safe\.md$/);
});

test("Sumo Logic tools are registered in the tool catalog under the Sumo Logic group", () => {
  const tools = getRegisteredToolSummaries().filter((tool) => tool.name.startsWith("sumologic_"));
  assert.deepEqual(tools.map((tool) => tool.name).sort(), [
    "sumologic_assess_access_control",
    "sumologic_assess_content_sharing",
    "sumologic_assess_data_governance",
    "sumologic_assess_identity",
    "sumologic_check_access",
    "sumologic_export_audit_bundle",
  ]);
  assert.ok(tools.every((tool) => tool.group === "Sumo Logic"));
  assert.ok(tools.every((tool) => tool.kind === "domain"));
  const exportTool = tools.find((tool) => tool.name === "sumologic_export_audit_bundle");
  assert.ok(exportTool.parameterSummaries.some((parameter) => parameter.name === "output_dir"));
  assert.ok(exportTool.parameterSummaries.some((parameter) => parameter.name === "endpoint"));
});

test("rule 9: scrub boundary: a name-shaped value stays bare in prose and is removed inside every carrier, as a configured secret in every encoding, and whenever it has a real token shape", () => {
  const name = "prod-us-east-2026";
  const bare = `Sumo Logic request failed for tenant ${name} owned by sess-canary-COOKIE-31415926535897`;
  assert.equal(scrubErrorText(bare), bare, "a name-shaped value bare in prose is indistinguishable from a resource name");
  assert.equal(scrubErrorText(bare, [name]), "Sumo Logic request failed for tenant [REDACTED] owned by sess-canary-COOKIE-31415926535897", "the same value registered as a configured secret is removed");
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
    [`Authorization: Basic '${name}' rejected`, "Authorization: Basic '[REDACTED]' rejected"],
    [`Authorization: "Bearer ${name}" rejected`, 'Authorization: "Bearer [REDACTED]" rejected'],
    [`\\"Authorization\\": \\"Bearer ${name}\\"`, '\\"Authorization\\": \\"Bearer [REDACTED]\\"'],
    [`X-Api-Key: \\"Ab3dEf9hIj2k\\", next`, 'X-Api-Key: \\"[REDACTED]\\", next'],
    [`X-Auth-Token: "Ab3dEf9hIj2k"`, 'X-Auth-Token: "[REDACTED]"'],
    [`Bearer "${name}" rejected`, 'Bearer "[REDACTED]" rejected'],
  ];
  for (const [input, expected] of quotedExpectations) assert.equal(scrubErrorText(input), expected, input);
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
  const gatewayBody = (line) => `Sumo Logic request to /api/v1/users failed (502 Bad Gateway): <html><body><h1>502 Bad Gateway</h1><p>upstream headers: ${line}</p></body></html>`;
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
    (value, separator, raw, quote) => `Authorization${separator}${quote}Basic ${raw}${quote}`,
    (value, separator) => `Proxy-Authorization${separator}Bearer ${value}`,
    (value, separator, raw, quote) => `Authorization${separator}${quote}Bearer ${raw}${quote}`,
  ];
  const quotedFrames = [
    (line) => line,
    (line) => `Sumo Logic request to /api/v1/users failed (401 Unauthorized): the request carried ${line} and was rejected`,
    (line) => `{"id":"ABCDE-12345","errors":[{"code":"unauthorized","message":"Invalid header: ${line}"}]}`,
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
  for (const header of SUMOLOGIC_QUOTED_HEADERS_KEPT) {
    assert.equal(scrubErrorText(header), header, `must keep quoted header: ${header}`);
    const sentence = `Sumo Logic request to /api/v1/users failed (400 Bad Request): the response carried ${header}`;
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
    scrubErrorText("failed for /api/v1/users/aB3xZ9qL2mN8pR4tV7wY1/factors from /tmp/run-9b6rz9m4l55zg7/config.yaml and https://hooks.example.com/services/T0/aB3xZ9qL2mN8pR4tV7wY1"),
    "failed for /api/v1/users/aB3xZ9qL2mN8pR4tV7wY1/factors from /tmp/run-9b6rz9m4l55zg7/config.yaml and https://hooks.example.com/services/T0/[REDACTED]",
    "a token-shaped segment of a bare request target or file path is an identifier the run named; inside a URL it is a webhook token",
  );
  assert.equal(
    scrubErrorText("key wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY beside /v2/content/folders/personal/children/000000000ABCDEF1/permissions"),
    "key [REDACTED] beside /v2/content/folders/personal/children/000000000ABCDEF1/permissions",
    "a random 40-character base64 run is an AWS secret access key; a bare path of word segments is a request target",
  );

  // Must-keep table (addendum 7): every identifying string a summary may carry survives alone and inside a realistic sentence.
  for (const value of SUMOLOGIC_MUST_KEEP) {
    assert.equal(scrubErrorText(value), value, `must keep bare: ${value}`);
    for (const sentence of sumologicSummarySentences(value)) assert.equal(scrubErrorText(sentence), sentence, `must keep in a sentence: ${sentence}`);
  }
});

/** Every request target the Sumo Logic client names in an error (the paths the probes and collectors request) plus the same paths as the route table sees them. */
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
    "SUMOLOGIC_ACCESS_KEY", "OKTA_CLIENT_TOKEN", "OKTA_CLIENT_PRIVATEKEY", "SPLUNK_PASSWORD", "SPLUNK_ACS_TOKEN", "VERACODE_API_KEY_SECRET", "SNOWFLAKE_PRIVATE_KEY_PASSPHRASE",
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

const SUMOLOGIC_REQUESTED_PATHS = [
  ...SUMOLOGIC_SURFACES.flatMap(([, paths]) => paths),
  ...SUMOLOGIC_SURFACES.flatMap(([, paths]) => paths.map((path) => path.replace(/^\/api/, ""))),
  "/v1/users?limit=1000",
  "/v1/policies/searchAudit",
  "/v1/policies/shareDashboardsOutsideOrganization",
  "/v1/policies/dataAccessLevel",
  "/v1/policies/userConcurrentSessionsLimit",
  "/v1/policies/maxUserSessionTimeout",
  "/v1/policies/accessKeysLifetime",
  "/v2/dashboards?limit=100",
  "/v2/content/000000000ABCDEF1/permissions",
];
/** Quoted non-credential headers (the Codex P1 must-keep rows): a quote alone never makes a header value a credential. */
const SUMOLOGIC_QUOTED_HEADERS_KEPT = [
  'Content-Type: "application/json"',
  'Content-Type:"application/json; charset=utf-8"',
  "Accept: 'application/json'",
  'Content-Length: "42"',
  'X-Request-Id: "3f2b6a1e-9c4d-4e8f-b1a2-6d7c8e9f0a1b"',
  'X-Rate-Limit-Remaining: "599"',
  'User-Agent: "grclanker-cli/0.4.1"',
  'Cache-Control: "no-store"',
  'Location: "/api/v1/users"',
  '{"Content-Type": "application/json", "Accept": "application/json"}',
  '{\\"Content-Type\\": \\"application/json\\", \\"Accept\\": \\"application/json\\"}',
];

const SUMOLOGIC_MUST_KEEP = [
  ...SUMOLOGIC_REQUESTED_PATHS,
  ...SUMOLOGIC_REQUESTED_PATHS.map((path) => `GET ${path}`),
  "api.us2.sumologic.com",
  "https://api.us2.sumologic.com/api",
  "https://api.fed.sumologic.com/api",
  "acme-prod.us2.sumologic.com",
  "https://acme-prod.us2.sumologic.com/api",
  "prod-us-east-2026",
  "us2",
  "fed",
  "admin@example.com",
  "secops@example.com",
  "jane.doe@acme-prod.example.gov",
  "Administrator",
  "Analyst",
  "manageUsersAndRoles",
  "manageAccessKeys (falls back to createAccessKeys for personal keys)",
  "viewMonitorsV2",
  "suAB...",
  "sumologic_audit_events",
  "_index=sumologic_audit_events",
  "_sourceCategory=prod",
  "200 OK",
  "401 Unauthorized",
  "403 Forbidden",
  "404 Not Found",
  "429 Too Many Requests",
  "500 Internal Server Error",
  "502 Bad Gateway",
  "503 Service Unavailable",
  ...Array.from({ length: 20 }, (_, index) => `SUMO-${String(index + 1).padStart(2, "0")}`),
  "environment-access-id",
  "environment-access-key",
  "config-file-endpoint",
  "default-endpoint",
  "/home/auditor/.sumologic/config.yaml",
  "BLOCK_AS_IMPLICIT_KEY",
  "EACCES",
];

/** Realistic Sumo Logic summary and error sentences with an identifying value in the slot such a value occupies. */
function sumologicSummarySentences(value) {
  return [
    `Sumo Logic request to ${value} failed (403 Forbidden forbidden): the access key lacks the role capability`,
    `Unknown: ${value} could not be read because the endpoint returned an error (Sumo Logic request to ${value} failed (502 Bad Gateway): non-JSON body (text/html, 5120 bytes)). Collect manually: export ${value} with created dates.`,
    `Not requested: no content permission lookups were issued because the personal folder could not be read (Sumo Logic request to ${value} failed (403 forbidden)).`,
    `Access ID suAB... resolved from ${value}, default-endpoint.`,
    `Sumo Logic access check: limited\n\n| Surface | Status | Count | Capability |\n| access_keys | not_readable | - | needs ${value} |\n\nNext: Grant the access key owner a role with: ${value}. Unreadable surfaces render as manual findings, never as passes.`,
  ];
}

/** Every fixed text the Sumo Logic integration emits, with sample paths and names, passes its scrubber unchanged (GWS note 1). */
const SUMOLOGIC_FIXED_TEXTS = [
  "Unable to read Sumo Logic config file /home/auditor/.sumologic/config.yaml (EACCES)",
  "Unable to read Sumo Logic config file /home/auditor/.sumologic/config.yaml (UNREADABLE)",
  "Unable to parse Sumo Logic config file: invalid YAML in /home/auditor/.sumologic/config.yaml at line 2, column 13 (BLOCK_AS_IMPLICIT_KEY)",
  "Unable to parse Sumo Logic config file: invalid YAML in /home/auditor/.sumologic/config.yaml (INVALID_YAML)",
  "SUMOLOGIC_ACCESS_ID and SUMOLOGIC_ACCESS_KEY (or access_id and access_key arguments, or a config file) are required.",
  "Unknown Sumo Logic deployment: mars",
  "Sumo Logic request to /v1/connections failed (502 Bad Gateway): non-JSON body (text/html, 5120 bytes)",
  "Sumo Logic request to /v1/collectors returned an unreadable response (200 OK): non-JSON body (text/html, 5120 bytes)",
  "Sumo Logic request to /v1/collectors returned an unreadable response (200 OK): non-JSON body (unknown content type, 0 bytes)",
  "Sumo Logic request to /v1/roles failed (403 Forbidden forbidden): the access key lacks the role capability",
  "Sumo Logic request to /v1/users failed (401 Unauthorized): credentials were rejected",
  "Sumo Logic request to /v1/users failed: fetch failed",
  "Sumo Logic request to /v1/users failed: The operation was aborted due to timeout",
  "Not requested: no content permission lookups were issued because the personal folder could not be read (Sumo Logic request to /v2/content/folders/personal failed (403 Forbidden forbidden)).",
  "every content permission lookup failed (2 of 2): Search A: Sumo Logic request to /v2/content/c1/permissions failed (403 Forbidden forbidden); Search B: Sumo Logic request to /v2/content/c2/permissions failed (403 Forbidden forbidden)",
  "Unknown: SAML identity providers could not be read because the access key lacks the role capability (403). Collect manually: export Administration > Security > SAML and confirm 'Require SAML sign-in' is enabled.",
  "Unknown: the password policy could not be read because credentials were rejected (401). Collect manually: screenshot Administration > Security > Password Policy showing length, complexity, and lockout settings.",
  "Unknown: the role list could not be read because the endpoint returned an error (Sumo Logic request to /v1/roles failed (502 Bad Gateway): non-JSON body (text/html, 5120 bytes)). Collect manually: export Administration > Users and Roles > Roles with capabilities and member counts.",
  "Unknown: the access key inventory could not be read because the access key lacks the role capability (403). Collect manually: export Administration > Security > Access Keys with created dates.",
  "Unknown: the audit policy could not be read because the access key lacks the role capability (403). Collect manually: screenshot Administration > Security > Policies > Audit and run `_index=sumologic_audit_events` for the last 24 hours.",
  "Unknown: the monitor and content inventories could not be read because the access key lacks the role capability (403). Collect manually: list scheduled searches and monitors with their owners and runAs identities, and confirm none run under shared administrator accounts.",
  "Role least privilege holds for 2 roles. Not checked: the user list could not be read because the access key lacks the role capability (403); collect manually: export the user list with last login dates",
  "The access key lifetime policy was unreadable (Sumo Logic request to /v1/policies/accessKeysLifetime failed (403 Forbidden forbidden)).",
  "Pagination stopped before the last page, so only 100 items were seen and the population is incomplete.",
  "per-user MFA status is unknown because the user list could not be read (the access key lacks the role capability (403))",
  "The password policy was unreadable, so org-wide MFA enforcement is unknown; per-user MFA status is unknown because the user list could not be read (the access key lacks the role capability (403)). Confirm Require MFA in Administration > Security > Password Policy.",
  "Require MFA is enabled, but the user list was unreadable (Sumo Logic request to /v1/users failed (403 Forbidden forbidden)), so per-user coverage cannot be confirmed; export the user list with MFA status.",
  "Require MFA is enabled, but zero users were returned, which indicates a capability-limited key; export the user list with MFA status.",
  "the user list was unreadable, so admin member activity could not be checked",
  "Login allowlisting is enabled but the CIDR list was unreadable (Sumo Logic request to /v1/serviceAllowlist/addresses failed (403 Forbidden forbidden)); export the allowlist entries manually.",
  "The maxUserSessionTimeout policy did not return a parsable value, so session timeout is unknown; confirm it in Administration > Security > Policies.",
  "The audit policy is enabled but the partition list was unreadable (Sumo Logic request to /v1/partitions failed (403 Forbidden forbidden)), so the audit index state is unverified; run `_index=sumologic_audit_events` for the last 24 hours to prove events flow.",
  "the personal folder could not be read, so no items were sampled",
  "The Data Access Level policy is enabled, but content permissions could not be sampled because the personal folder could not be read; review Library sharing for org-wide shares manually.",
  "The Data Access Level policy is enabled, but content permissions could not be sampled (2 lookups failed, 2 items sampled); review Library sharing for org-wide shares manually. 2 content permission lookup(s) failed (Search A: Sumo Logic request to /v2/content/c1/permissions failed (403 Forbidden forbidden); Search B: Sumo Logic request to /v2/content/c2/permissions failed (403 Forbidden forbidden)), so those items were not checked.",
  "the monitor list could not be read",
  "the personal folder could not be read so no scheduled searches were sampled",
  "the personal folder could not be read, so no lookup tables were sampled",
  "the dashboard list could not be read (the access key lacks the role capability (403)), so per-dashboard exposure is unknown",
  "External dashboard sharing is disabled at the policy level, but the dashboard list was unreadable (Sumo Logic request to /v2/dashboards failed (403 Forbidden forbidden)); review dashboard sharing in the Library manually.",
  "External dashboard sharing is disabled at the policy level, but zero dashboards were viewable by the key owner, so per-dashboard sharing could not be sampled; review Library dashboards manually.",
  "3 notification(s) across 1 monitors were seen, but no org email domains could be derived (user list unreadable and no approved_email_domains supplied), so recipient review is manual.",
  "Using Sumo Logic API https://api.us2.sumologic.com/api (deployment us2).",
  "Access ID suAB... resolved from environment-access-id, environment-access-key, config-file-endpoint.",
  "17/24 Sumo Logic audit surfaces are readable.",
  "Run sumologic_assess_identity, sumologic_assess_access_control, sumologic_assess_data_governance, sumologic_assess_content_sharing, or sumologic_export_audit_bundle.",
  "Grant the access key owner a role with: manageUsersAndRoles, manageSaml, manageAccessKeys (falls back to createAccessKeys for personal keys). Unreadable surfaces render as manual findings, never as passes.",
  "needs manageUsersAndRoles",
  "- `_errors.log`: present only when some API surfaces could not be collected",
  "- MANUAL: unreadable endpoint, not applicable, or outside API scope; the summary names the evidence to collect",
];

const SUMOLOGIC_SOURCE_URL = new URL("../extensions/grc-tools/sumologic.ts", import.meta.url);

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
 * The resolver messages rendered live for the no credentials, partial credentials, and config file
 * failure cases (Sumo Logic has a single auth mode, the access ID and key pair), each against a real
 * temp path; the malformed file carries a config canary so the message proves it holds the path,
 * position, and code only.
 */
function liveSumologicResolverMessages() {
  const base = createTempBase("grclanker-sumo-live-resolver-");
  const missingConfig = join(base, "missing.yaml");
  const directoryConfig = join(base, "directory.yaml");
  mkdirSync(directoryConfig);
  const malformedConfig = join(base, "malformed.yaml");
  writeFileSync(malformedConfig, `access_id: suABCDEF\naccess_key: "${CONFIG_CANARIES.unterminated}\n`);
  const resolve = (input, env) => thrownBy(() => resolveSumologicConfiguration({ config_file: missingConfig, ...input }, env)).message;
  return {
    paths: { directoryConfig, malformedConfig },
    messages: {
      "no credentials": resolve({}, {}),
      "partial credentials: access ID without a key": resolve({}, { SUMOLOGIC_ACCESS_ID: "suENVID1" }),
      "partial credentials: access key without an ID": resolve({ access_key: SAMPLE_ACCESS_KEY }, {}),
      "config file failure: directory at the path": resolve({ config_file: directoryConfig }, {}),
      "config file failure: malformed YAML": resolve({ config_file: malformedConfig }, {}),
    },
  };
}

test("rule 9: every fixed text the Sumo Logic integration emits, including the live resolver messages, passes its scrubber unchanged", () => {
  const live = liveSumologicResolverMessages();
  const credentialsRequired = "SUMOLOGIC_ACCESS_ID and SUMOLOGIC_ACCESS_KEY (or access_id and access_key arguments, or a config file) are required.";
  const expected = {
    "no credentials": credentialsRequired,
    "partial credentials: access ID without a key": credentialsRequired,
    "partial credentials: access key without an ID": credentialsRequired,
    "config file failure: directory at the path": `Unable to read Sumo Logic config file ${live.paths.directoryConfig} (EISDIR)`,
    "config file failure: malformed YAML": `Unable to parse Sumo Logic config file: invalid YAML in ${live.paths.malformedConfig} at line 3, column 1 (MISSING_CHAR)`,
  };
  assert.deepEqual(Object.keys(live.messages), Object.keys(expected));
  for (const [label, message] of Object.entries(live.messages)) {
    assert.equal(message, expected[label], label);
    for (const canary of Object.values(CONFIG_CANARIES)) assertNoWindowOf(message, canary, `live resolver message (${label})`);
    for (const wording of LIBRARY_ERROR_WORDING) assert.ok(!message.includes(wording), `${label} repeats library wording "${wording}": ${message}`);
    assert.equal(scrubErrorText(message), message, `live resolver message survives the scrubber (${label})`);
    assert.equal(scrubErrorText(message, [SAMPLE_ACCESS_KEY, "suABCDEF"]), message, `live resolver message survives with the configured credentials registered (${label})`);
  }

  // Every message template the resolver and its loaders can throw is pinned by a fixed text or a live rendering, so a reworded message fails here until the set is updated.
  const corpus = [...SUMOLOGIC_FIXED_TEXTS, ...Object.values(live.messages)];
  const segments = errorTemplateSegments(SUMOLOGIC_SOURCE_URL, ["resolveSumologicConfiguration", "readConfigFileText", "configFileParseError"]);
  assert.ok(segments.length >= 3, `the template scan found the resolver message and the two loader messages (${segments.length})`);
  for (const segment of segments) assert.ok(corpus.some((text) => text.includes(segment)), `resolver template segment is pinned by a fixed text or a live rendering: ${segment}`);

  for (const text of SUMOLOGIC_FIXED_TEXTS) assert.equal(scrubErrorText(text), text, text);
  for (const text of SUMOLOGIC_FIXED_TEXTS) assert.equal(scrubErrorText(text, [SAMPLE_ACCESS_KEY, "suABCDEF"]), text, `${text} (with the configured credentials registered)`);
});

test("resolveSumologicConfiguration keeps environment credentials when an unrelated argument is passed (GWS note 2)", () => {
  const dir = createTempBase("grclanker-sumo-env-args-");
  const configFile = join(dir, "config.yaml");
  writeFileSync(configFile, "endpoint: eu\n");
  const env = { SUMOLOGIC_CONFIG_FILE: configFile, SUMOLOGIC_ACCESS_ID: "suENVID1", SUMOLOGIC_ACCESS_KEY: SAMPLE_ACCESS_KEY };

  const resolved = resolveSumologicConfiguration({ timeout_seconds: 9 }, env);
  assert.equal(resolved.accessId, "suENVID1", "the environment access id survives an argument overlay that names no credential");
  assert.equal(resolved.accessKey, SAMPLE_ACCESS_KEY, "the environment access key survives an argument overlay that names no credential");
  assert.equal(resolved.baseUrl, "https://api.eu.sumologic.com/api", "the config file named through the environment still supplies the endpoint");
  assert.equal(resolved.timeoutMs, 9000);
  assert.deepEqual(resolved.sourceChain, ["environment-access-id", "environment-access-key", "config-file-endpoint"]);

  const withUndefinedArguments = resolveSumologicConfiguration({ access_id: undefined, access_key: undefined, endpoint: undefined }, env);
  assert.equal(withUndefinedArguments.accessId, "suENVID1", "an argument overlay whose credential keys are undefined does not shadow the environment");
  assert.equal(withUndefinedArguments.accessKey, SAMPLE_ACCESS_KEY);
  assert.deepEqual(withUndefinedArguments.sourceChain, ["environment-access-id", "environment-access-key", "config-file-endpoint"]);
});
