import test from "node:test";
import assert from "node:assert/strict";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  SPLUNK_CONTROLS,
  SplunkApiClient,
  assessSplunkAccessControl,
  assessSplunkAuditMonitoring,
  assessSplunkAuthentication,
  assessSplunkDataProtection,
  assessSplunkPlatformHardening,
  checkSplunkAccess,
  exportSplunkAuditBundle,
  registerSplunkTools,
  resolveSecureOutputPath,
  resolveSplunkConfiguration,
  scrubErrorText,
} from "../dist/extensions/grc-tools/splunk.js";
import { getRegisteredToolSummaries } from "../dist/pi/tool-catalog.js";
import { assertSecretsAbsent, readBundleFiles, readZipEntries } from "./helpers/bundle-contents.mjs";

const NOW_SECONDS = Math.floor(Date.now() / 1000);

function createTempBase(prefix) {
  return mkdtempSync(join(tmpdir(), prefix));
}

/** The configured bearer and ACS tokens: random alphanumerics so every 6 to 24 character window of them is a leak signal. */
const SAMPLE_TOKEN = "2xwtSsxGESNew4jyGcRvZHsM";
const SAMPLE_ACS_TOKEN = "BZJaRfcKYwJx5gBWUypXAc4a";

function sampleConfig(overrides = {}) {
  return {
    url: "https://splunk.example.com:8089",
    token: SAMPLE_TOKEN,
    acsBaseUrl: "https://admin.splunk.com",
    verifyTls: true,
    timeoutMs: 30000,
    sourceChain: ["tests"],
    ...overrides,
  };
}

function jsonResponse(value, status = 200) {
  return new Response(JSON.stringify(value), { status, headers: { "content-type": "application/json" } });
}

function entry(name, content = {}, acl = {}) {
  return { name, content, acl };
}

function entryList(entries, totalOverride) {
  return { entry: entries, paging: { total: totalOverride ?? entries.length, perPage: 100, offset: 0 } };
}

const HARDENED = {
  "/services/server/info": [entry("server-info", { version: "9.2.1", product_type: "enterprise", server_roles: ["search_head", "indexer"], serverName: "sh1" })],
  "/services/authentication/current-context": [entry("context", { username: "auditor", capabilities: ["edit_user", "list_tokens_all", "rest_properties_get", "list_settings", "list_inputs", "rest_apps_view", "search"] })],
  "/services/authentication/users": [
    entry("admin", { roles: ["admin"], type: "Splunk" }),
    entry("auditor", { roles: ["auditor"], type: "SAML" }),
  ],
  "/services/authorization/roles": [
    entry("admin", { capabilities: ["admin_all_objects", "edit_user", "edit_roles", "edit_server", "change_authentication"], srchIndexesAllowed: ["*", "_*"] }),
    entry("user", { capabilities: ["search"], srchIndexesAllowed: ["main"], srchIndexesDefault: ["main"] }),
    entry("auditor", { capabilities: ["search", "list_settings"], srchIndexesAllowed: ["main"], srchFilter: "sourcetype=app" }),
    entry("can_delete", { capabilities: ["delete_by_keyword"], srchIndexesAllowed: ["*"] }),
  ],
  "/services/authorization/tokens": [entry("tok1", { claims: { exp: NOW_SECONDS + 86400 * 30, iat: NOW_SECONDS - 86400 * 10, sub: "admin", roles: ["admin"] }, status: "enabled" })],
  "/services/configs/conf-authentication": [
    entry("authentication", { authType: "SAML", authSettings: "okta", externalTwoFactorAuthVendor: "Duo" }),
    entry("okta", { disabled: 0, idpSSOUrl: "https://idp.example.com/sso" }),
    entry("splunk_auth", { minPasswordLength: 14, minPasswordUppercase: 1, minPasswordLowercase: 1, minPasswordDigit: 1, minPasswordSpecial: 1, expirePasswordDays: 90, forceWeakPasswordChange: 1, lockoutUsers: 1 }),
  ],
  "/services/authentication/providers/SAML": [entry("okta", { idpSSOUrl: "https://idp.example.com/sso" })],
  "/services/admin/Duo-MFA": [entry("duo-mfa", { apiHostname: "api-x.duosecurity.com" })],
  "/services/configs/conf-web": [entry("settings", { enableSplunkWebSSL: 1, "tools.sessions.timeout": 30, sslVersions: "tls1.2" })],
  "/services/configs/conf-server": [
    entry("general", { sessionTimeout: "30m" }),
    entry("sslConfig", { enableSplunkdSSL: 1, sslVersions: "tls1.2", requireClientCert: 1, cipherSuite: "ECDHE-RSA-AES256-GCM-SHA384" }),
  ],
  "/services/configs/conf-outputs": [entry("tcpout:primary", { useSSL: "true", clientCert: "/opt/splunk/etc/auth/client.pem" })],
  "/services/configs/conf-inputs": [
    entry("splunktcp-ssl:9997", { disabled: 0 }),
    entry("SSL", { serverCert: "/opt/splunk/etc/auth/server.pem", requireClientCert: 1, sslVersions: "tls1.2" }),
  ],
  "/services/data/inputs/http": [
    entry("http", { disabled: 0, enableSSL: 1, port: 8088 }),
    entry("app-token", { disabled: 0, indexes: "main", sourcetype: "app:json", useACK: 1 }),
  ],
  "/services/data/indexes": [
    entry("_audit", { disabled: 0, totalEventCount: 1200, frozenTimePeriodInSecs: 86400 * 400, homePath: "$SPLUNK_DB/audit/db" }),
    entry("_internal", { disabled: 0, totalEventCount: 5000, frozenTimePeriodInSecs: 86400 * 30 }),
    entry("main", { disabled: 0, totalEventCount: 10, frozenTimePeriodInSecs: 86400 * 365 }),
  ],
  "/servicesNS/-/-/saved/searches": [
    entry("Errors", { is_scheduled: 1, disabled: 0, dispatchAs: "user", search: "index=main error", "dispatch.earliest_time": "-24h" }, { sharing: "app", owner: "auditor", app: "search", perms: { read: ["*"], write: ["admin"] } }),
  ],
  "/servicesNS/-/-/data/lookup-table-files": [entry("assets.csv", {}, { sharing: "app", owner: "admin", app: "search", perms: { read: ["*"], write: ["admin"] } })],
  "/services/apps/local": [
    entry("search", { author: "Splunk", label: "Search", version: "9.2.1" }),
    entry("splunk_monitoring_console", { author: "Splunk", label: "MC", version: "9.2.1" }),
  ],
  "/servicesNS/-/-/storage/collections/config": [entry("assets", {}, { sharing: "app", app: "search", perms: { read: ["admin"], write: ["admin"] } })],
  "/services/data/inputs/tcp/cooked": [entry("9997", { disabled: 0, group: "listenerports" })],
};

const WEAK = {
  ...HARDENED,
  "/services/authentication/users": [
    entry("admin", { roles: ["admin"], type: "Splunk" }),
    entry("a2", { roles: ["admin"], type: "Splunk" }),
    entry("a3", { roles: ["admin"], type: "Splunk" }),
    entry("a4", { roles: ["sc_admin"], type: "Splunk" }),
    entry("analyst1", { roles: ["analyst"], type: "Splunk" }),
  ],
  "/services/authorization/roles": [
    entry("admin", { capabilities: ["admin_all_objects", "edit_user"], srchIndexesAllowed: ["*", "_*"] }),
    entry("analyst", { capabilities: ["search", "admin_all_objects", "edit_server", "delete_by_keyword", "install_apps"], srchIndexesAllowed: ["*"], imported_roles: ["user"] }),
  ],
  "/services/authorization/tokens": [
    entry("tok-forever", { claims: { exp: 0, iat: NOW_SECONDS - 86400 * 200, sub: "ghost" }, status: "enabled" }),
    entry("tok-nodates", { claims: { sub: "admin" }, status: "enabled" }),
  ],
  "/services/configs/conf-authentication": [
    entry("authentication", { authType: "Splunk" }),
    entry("splunk_auth", { minPasswordLength: 6, expirePasswordDays: 0, forceWeakPasswordChange: 0, lockoutUsers: 0 }),
  ],
  "/services/configs/conf-web": [entry("settings", { enableSplunkWebSSL: 0, "tools.sessions.timeout": 480 })],
  "/services/configs/conf-server": [
    entry("general", { sessionTimeout: "3d" }),
    entry("sslConfig", { enableSplunkdSSL: 0, sslVersions: "tls1.0,tls1.2", requireClientCert: 0 }),
  ],
  "/services/configs/conf-outputs": [entry("tcpout:primary", { server: "idx:9997" })],
  "/services/configs/conf-inputs": [entry("splunktcp://9997", { disabled: 0 }), entry("SSL", { requireClientCert: 0 })],
  "/services/data/inputs/http": [
    entry("http", { disabled: 0, enableSSL: 0 }),
    entry("open-token", { disabled: 0, useACK: 0 }),
  ],
  "/services/data/indexes": [
    entry("_audit", { disabled: 1, totalEventCount: 0, frozenTimePeriodInSecs: 86400 * 7 }),
    entry("main", { disabled: 0 }),
  ],
  "/servicesNS/-/-/saved/searches": [
    entry("Everything", { is_scheduled: 1, disabled: 0, dispatchAs: "owner", search: "index=* | stats count", "dispatch.earliest_time": "-0s" }, { sharing: "global", owner: "admin", app: "search", perms: { read: ["*"], write: ["*"] } }),
  ],
  "/services/apps/local": [
    entry("search", { author: "Splunk" }),
    entry("mystery_app", { author: "Unknown Vendor", disabled: 0 }),
  ],
  "/servicesNS/-/-/storage/collections/config": [entry("open", {}, { sharing: "global", app: "search", perms: { read: ["*"], write: ["*"] } })],
  "/services/data/inputs/tcp/cooked": [entry("9997", { disabled: 0, group: "listenerports" })],
};

function createFetch(fixture, options = {}) {
  const seen = [];
  const fetchImpl = async (input, init = {}) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    seen.push({ pathname: url.pathname, search: url.search, method: init.method ?? "GET", auth: new Headers(init.headers ?? {}).get("authorization") ?? undefined, body: init.body });
    if (options.status && options.status !== 200) {
      return jsonResponse({ messages: [{ type: "ERROR", text: "You (user=auditor) do not have permission to perform this operation (requires capability: edit_user)." }] }, options.status);
    }
    if (url.pathname === "/services/auth/login") {
      return jsonResponse({ sessionKey: "session-key-abc" });
    }
    if (url.pathname === "/services/search/jobs") {
      return jsonResponse({ results: options.searchResults ?? [{ action: "login attempt", count: "4" }, { action: "search", count: "9" }, { action: "edit_user", count: "1" }] });
    }
    if (url.hostname === "admin.splunk.com") {
      const acsPath = url.pathname.replace(/^\/[^/]+\/adminconfig\/v2/, "");
      const acsFixture = options.acs?.[acsPath];
      if (acsFixture === undefined) return jsonResponse({ code: "404", message: "not found" }, 404);
      return jsonResponse(acsFixture);
    }
    const entries = fixture[url.pathname];
    if (entries === undefined) return jsonResponse({ messages: [{ type: "ERROR", text: "Not Found" }] }, 404);
    const offset = Number(url.searchParams.get("offset") ?? "0");
    if (options.partial || options.partialPaths?.includes(url.pathname)) {
      return jsonResponse(entryList(offset === 0 ? entries : [], entries.length + 5));
    }
    const count = Number(url.searchParams.get("count") ?? "100");
    return jsonResponse({ entry: entries.slice(offset, offset + count), paging: { total: entries.length, perPage: count, offset } });
  };
  return { fetchImpl, seen };
}

function client(fixture, options = {}, configOverrides = {}) {
  const { fetchImpl, seen } = createFetch(fixture, options);
  return { client: new SplunkApiClient(sampleConfig(configOverrides), { fetchImpl, retryDelayMs: 0, pageSize: options.pageSize ?? 100 }), seen };
}

function byId(result, id) {
  return result.findings.find((item) => item.id === id);
}

async function runAllAssessments(apiClient) {
  return [
    await assessSplunkAuthentication(apiClient),
    await assessSplunkAccessControl(apiClient),
    await assessSplunkDataProtection(apiClient),
    await assessSplunkAuditMonitoring(apiClient),
    await assessSplunkPlatformHardening(apiClient),
  ];
}

test("SPLUNK_CONTROLS covers all 23 spec controls with eight framework mappings each", () => {
  assert.equal(SPLUNK_CONTROLS.length, 23);
  assert.deepEqual(SPLUNK_CONTROLS.map((item) => item.number), Array.from({ length: 23 }, (_, index) => index + 1));
  for (const item of SPLUNK_CONTROLS) {
    assert.equal(Object.keys(item.mappings).length, 8, item.id);
  }
});

test("resolveSplunkConfiguration prefers explicit args over env over config file", () => {
  const base = createTempBase("grclanker-splunk-config-");
  const configFile = join(base, "splunk.json");
  writeFileSync(configFile, JSON.stringify({ url: "https://file.example.com:8089", token: "file-token", stack: "file-stack", verify_ssl: "false" }));

  const fromFile = resolveSplunkConfiguration({ config_file: configFile }, {});
  assert.equal(fromFile.url, "https://file.example.com:8089");
  assert.equal(fromFile.token, "file-token");
  assert.equal(fromFile.stack, "file-stack");
  assert.equal(fromFile.acsToken, "file-token");
  assert.equal(fromFile.verifyTls, false);
  assert.ok(fromFile.sourceChain.includes("config-file-url"));

  const fromEnv = resolveSplunkConfiguration({ config_file: configFile }, { SPLUNK_URL: "https://env.example.com:8089", SPLUNK_USERNAME: "svc", SPLUNK_PASSWORD: "pw", SPLUNK_ACS_TOKEN: "acs-env" });
  assert.equal(fromEnv.url, "https://env.example.com:8089");
  assert.equal(fromEnv.token, "file-token");
  assert.equal(fromEnv.username, "svc");
  assert.equal(fromEnv.acsToken, "acs-env");
  assert.ok(fromEnv.sourceChain.includes("environment-url"));

  const fromArgs = resolveSplunkConfiguration({ config_file: configFile, url: "https://arg.example.com:8089", token: "arg-token", stack: "arg-stack", verify_ssl: "true", timeout_seconds: 9 }, { SPLUNK_URL: "https://env.example.com:8089" });
  assert.equal(fromArgs.url, "https://arg.example.com:8089");
  assert.equal(fromArgs.token, "arg-token");
  assert.equal(fromArgs.stack, "arg-stack");
  assert.equal(fromArgs.verifyTls, true);
  assert.equal(fromArgs.timeoutMs, 9000);
  assert.ok(fromArgs.sourceChain.includes("arguments-url"));

  assert.throws(() => resolveSplunkConfiguration({ config_file: join(base, "missing.json") }, {}), /SPLUNK_URL/);
  assert.throws(() => resolveSplunkConfiguration({ config_file: join(base, "missing.json"), url: "https://x.example.com:8089" }, {}), /SPLUNK_TOKEN or both/);
});

/** Canaries planted on malformed config lines: random alphanumerics, so no 6-character window of one occurs in a legitimate fixture value or in another canary. */
const CONFIG_CANARIES = {
  unquoted: "Yc6RtV3nJ8kMp4Sd",
  short: "Gz5Kq8Wn2Xt",
  trailingComma: "Lf9BwD4sN7hVe3Ky",
  unterminated: "Tn3XcM6zP8gQb5Rw",
  singleQuoted: "Rk8VqL2tY7jCn4Fs",
  readable: "Zx4HnV7qK2mYt9Pw",
};
const LIBRARY_ERROR_WORDING = [
  "Nested mappings", "is not valid JSON", "Unresolved alias", "illegal operation", "permission denied", "no such file",
  "not a directory", "Unexpected token", "Expected double-quoted", "Bad control character", "at position",
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
  if (line) assert.ok(text.includes(` at line ${line}, column ${column}`), `${label} carries the position line ${line}, column ${column}: ${text}`);
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

test("rule 9: Splunk config loader errors carry only the path, position, and code, never the JSON.parse window or filesystem wording", async () => {
  const dir = createTempBase("grclanker-splunk-config-errors-");
  const registered = [];
  registerSplunkTools({ registerTool: (tool) => registered.push(tool) });
  const checkAccess = registered.find((tool) => tool.name === "splunk_check_access");
  const exportBundle = registered.find((tool) => tool.name === "splunk_export_audit_bundle");
  const allCanaries = Object.values(CONFIG_CANARIES);
  const url = "\"url\": \"https://splunk.example.com:8089\"";

  const parseCases = [
    { name: "unquoted value", file: "unquoted.json", text: `{\n  ${url},\n  "token": ${CONFIG_CANARIES.unquoted}\n}\n`, leaks: [CONFIG_CANARIES.unquoted], control: /Unexpected token/ },
    { name: "short file", file: "short.json", text: `{"token":${CONFIG_CANARIES.short}}`, leaks: [CONFIG_CANARIES.short], control: /Unexpected token/, maxLength: 21 },
    { name: "single-quoted value", file: "single.json", text: `{\n  ${url},\n  "token": '${CONFIG_CANARIES.singleQuoted}'\n}\n`, leaks: [CONFIG_CANARIES.singleQuoted], control: /Unexpected token/ },
    { name: "trailing comma", file: "trailing.json", text: `{\n  ${url},\n  "token": "${CONFIG_CANARIES.trailingComma}",\n}\n`, leaks: [], control: /at position 77 \(line 4 column 1\)/, line: 4, column: 1 },
    { name: "unterminated string", file: "unterminated.json", text: `{\n  ${url},\n  "token": "${CONFIG_CANARIES.unterminated}\n}\n`, leaks: [], control: /at position 74 \(line 3 column 29\)/, line: 3, column: 29 },
  ];
  for (const testCase of parseCases) {
    const configFile = join(dir, testCase.file);
    writeFileSync(configFile, testCase.text);
    if (testCase.maxLength) assert.ok(testCase.text.length <= testCase.maxLength, `${testCase.name}: JSON.parse quotes the whole source of a file this short`);
    const library = thrownBy(() => JSON.parse(testCase.text));
    assert.match(library.message, testCase.control, `${testCase.name}: positive control uses the JSON.parse message`);
    for (const canary of testCase.leaks) {
      assert.ok(windowsOf(canary).some((window) => library.message.includes(window)), `${testCase.name}: positive control, JSON.parse quotes a window of the canary`);
    }
    assertFixtureFreeOfCanaryWindows(testCase.text, allCanaries, `${testCase.name} config fixture`);

    const expected = { path: configFile, code: "INVALID_JSON", line: testCase.line, column: testCase.column, canaries: allCanaries };
    const thrown = thrownBy(() => resolveSplunkConfiguration({ config_file: configFile }, {}));
    assert.match(thrown.message, /^Unable to parse Splunk config file: invalid JSON in /, testCase.name);
    assertConfigErrorText(thrown.message, expected, `${testCase.name} resolver error`);
    const fromArgs = thrownBy(() => resolveSplunkConfiguration({ config_file: configFile, url: "https://arg.example.com:8089", token: "arg-token" }, {}));
    assertConfigErrorText(fromArgs.message, expected, `${testCase.name} resolver error with credentials in arguments`);

    const result = await checkAccess.execute("call", checkAccess.prepareArguments({ config_file: configFile }));
    assertConfigErrorText(JSON.stringify(result), expected, `${testCase.name} check_access payload`);
  }

  const outputRoot = join(dir, "export");
  const exported = await exportBundle.execute("call", exportBundle.prepareArguments({ config_file: join(dir, "unquoted.json"), output_dir: outputRoot }));
  assertConfigErrorText(JSON.stringify(exported), { path: join(dir, "unquoted.json"), code: "INVALID_JSON", canaries: allCanaries }, "export payload");
  assert.equal(existsSync(outputRoot), false, "a config error writes no bundle");

  const readCases = [
    { name: "EISDIR", path: join(dir, "directory.json"), setup: (path) => mkdirSync(path), control: /illegal operation/ },
    { name: "ENOTDIR", path: join(dir, "plain-file", "splunk.json"), setup: () => writeFileSync(join(dir, "plain-file"), `{"token":"${CONFIG_CANARIES.readable}"}`), control: /not a directory/ },
  ];
  if (process.getuid?.() !== 0) {
    readCases.push({ name: "EACCES", path: join(dir, "locked.json"), setup: (path) => { writeFileSync(path, `{"token":"${CONFIG_CANARIES.readable}"}`); chmodSync(path, 0o000); }, control: /permission denied/ });
  }
  for (const testCase of readCases) {
    testCase.setup(testCase.path);
    assert.match(thrownBy(() => readFileSync(testCase.path, "utf8")).message, testCase.control, `${testCase.name}: positive control uses the filesystem message`);
    const expected = { path: testCase.path, code: testCase.name, canaries: allCanaries };
    const thrown = thrownBy(() => resolveSplunkConfiguration({ config_file: testCase.path }, {}));
    assert.equal(thrown.message, `Unable to read Splunk config file ${testCase.path} (${testCase.name})`);
    assertConfigErrorText(thrown.message, expected, `${testCase.name} resolver error`);
    const result = await checkAccess.execute("call", checkAccess.prepareArguments({ config_file: testCase.path }));
    assertConfigErrorText(JSON.stringify(result), expected, `${testCase.name} check_access payload`);
  }

  const missing = join(dir, "missing.json");
  const absent = thrownBy(() => resolveSplunkConfiguration({ config_file: missing }, {}));
  assert.match(absent.message, /SPLUNK_URL/, "a missing config file is absent, not a read failure");
  for (const wording of LIBRARY_ERROR_WORDING) assert.ok(!absent.message.includes(wording));
  const absentResult = JSON.stringify(await checkAccess.execute("call", checkAccess.prepareArguments({ config_file: missing })));
  assert.ok(absentResult.includes("SPLUNK_URL"));
  for (const wording of LIBRARY_ERROR_WORDING) assert.ok(!absentResult.includes(wording));
});

test("SplunkApiClient sends bearer tokens, output_mode=json, and pages with count/offset until paging.total", async () => {
  const many = Array.from({ length: 7 }, (_, index) => entry(`role-${index}`, { capabilities: ["search"] }));
  const { client: api, seen } = client({ "/services/authorization/roles": many }, { pageSize: 3 });
  const roles = await api.listRoles();
  assert.equal(roles.entries.length, 7);
  assert.equal(roles.total, 7);
  assert.equal(roles.truncated, false);
  const roleCalls = seen.filter((item) => item.pathname === "/services/authorization/roles");
  assert.equal(roleCalls.length, 3);
  assert.ok(roleCalls.every((item) => item.auth === `Bearer ${SAMPLE_TOKEN}`));
  assert.ok(roleCalls.every((item) => item.search.includes("output_mode=json") && item.search.includes("count=3")));
  assert.ok(roleCalls.some((item) => item.search.includes("offset=6")));
});

test("SplunkApiClient logs in for a session key when only username and password are provided", async () => {
  const { fetchImpl, seen } = createFetch(HARDENED);
  const api = new SplunkApiClient(sampleConfig({ token: undefined, username: "svc", password: "pw-secret" }), { fetchImpl, retryDelayMs: 0 });
  const info = await api.getServerInfo();
  assert.equal(info.content.version, "9.2.1");
  assert.equal(seen[0].pathname, "/services/auth/login");
  assert.equal(seen[0].method, "POST");
  assert.match(String(seen[0].body), /username=svc/);
  assert.equal(seen[1].auth, "Splunk session-key-abc");
  assert.equal(api.redact("Authorization: Splunk session-key-abc password pw-secret"), "Authorization: Splunk [REDACTED] password [REDACTED]");
});

test("SplunkApiClient calls ACS with the ACS bearer token and retries 429 responses", async () => {
  let attempts = 0;
  const fetchImpl = async (input, init = {}) => {
    const url = new URL(input.toString());
    attempts += 1;
    if (attempts === 1) return jsonResponse({ message: "slow down" }, 429);
    assert.equal(url.hostname, "admin.splunk.com");
    assert.equal(url.pathname, "/my-stack/adminconfig/v2/access/hec/ipallowlists");
    assert.equal(new Headers(init.headers).get("authorization"), "Bearer acs-jwt");
    return jsonResponse({ subnets: ["10.0.0.0/8"] });
  };
  const api = new SplunkApiClient(sampleConfig({ stack: "my-stack", acsToken: "acs-jwt" }), { fetchImpl, retryDelayMs: 0 });
  const payload = await api.acsGet("/access/hec/ipallowlists");
  assert.deepEqual(payload.subnets, ["10.0.0.0/8"]);
  assert.equal(attempts, 2);

  const denied = new SplunkApiClient(sampleConfig(), { fetchImpl: async () => jsonResponse({ messages: [{ text: "call not properly authenticated" }] }, 401), retryDelayMs: 0 });
  await assert.rejects(denied.listUsers(), (error) => error.status === 401 && /401/.test(error.message));

  let restAttempts = 0;
  const flaky = new SplunkApiClient(sampleConfig(), {
    retryDelayMs: 0,
    fetchImpl: async () => {
      restAttempts += 1;
      if (restAttempts < 3) return jsonResponse({ messages: [{ text: "temporarily unavailable" }] }, 503);
      return jsonResponse(entryList([entry("admin", { roles: ["admin"] })]));
    },
  });
  const users = await flaky.listUsers();
  assert.equal(users.entries.length, 1);
  assert.equal(restAttempts, 3);
});

test("tokens without iat or exp claims are bucketed separately and cap the verdict at warn", async () => {
  const fixture = {
    ...HARDENED,
    "/services/authorization/tokens": [
      ...HARDENED["/services/authorization/tokens"],
      entry("tok-undated", { claims: { sub: "admin" }, status: "enabled" }),
    ],
  };
  const auth = await assessSplunkAuthentication(client(fixture).client);
  const tokens = byId(auth, "SPLUNK-AUTH-06");
  assert.equal(tokens.status, "warn");
  assert.equal(tokens.evidence.missing_dates.length, 1);
  assert.match(tokens.summary, /1 lack issue or expiry claims/);
});

test("TLS verification opt-out is scoped to the client and never sets NODE_TLS_REJECT_UNAUTHORIZED", () => {
  const before = process.env.NODE_TLS_REJECT_UNAUTHORIZED;
  const config = resolveSplunkConfiguration({ url: "https://splunk.example.com:8089", token: "t" }, { SPLUNK_VERIFY_SSL: "false" });
  assert.equal(config.verifyTls, false);
  const api = new SplunkApiClient(config);
  assert.ok(api);
  assert.equal(process.env.NODE_TLS_REJECT_UNAUTHORIZED, before);
  assert.equal(resolveSplunkConfiguration({ url: "https://splunk.example.com:8089", token: "t" }, {}).verifyTls, true);
});

test("checkSplunkAccess reports healthy access and lists surfaces", async () => {
  const { client: api } = client(HARDENED);
  const result = await checkSplunkAccess(api);
  assert.equal(result.status, "healthy");
  assert.equal(result.authenticatedAs, "auditor");
  assert.deepEqual(result.missingCapabilities, []);
  assert.equal(result.acsConfigured, false);
  assert.equal(result.surfaces.find((item) => item.name === "acs_ip_allowlist").status, "not_configured");
  assert.equal(result.deployment.isCloud, false);
  assert.match(result.recommendedNextStep, /splunk_assess_authentication/);
});

test("checkSplunkAccess reports degraded access and missing capabilities on 403", async () => {
  const { client: api } = client(HARDENED, { status: 403 });
  const result = await checkSplunkAccess(api);
  assert.equal(result.status, "limited");
  assert.ok(result.missingCapabilities.some((item) => item.startsWith("edit_user")));
  assert.ok(result.surfaces.filter((surface) => surface.status !== "not_configured").every((surface) => surface.status === "not_readable"));
  assert.match(result.recommendedNextStep, /missing capabilities/);
});

test("hardened fixture passes the API-verifiable controls and keeps scoped-out controls manual", async () => {
  const { client: api } = client(HARDENED);
  const [auth, access, data, audit, platform] = await runAllAssessments(api);
  assert.equal(byId(auth, "SPLUNK-AUTH-01").status, "pass");
  assert.equal(byId(auth, "SPLUNK-AUTH-02").status, "pass");
  assert.equal(byId(auth, "SPLUNK-AUTH-03").status, "pass");
  assert.equal(byId(auth, "SPLUNK-AUTH-04").status, "pass");
  assert.equal(byId(auth, "SPLUNK-AUTH-05").status, "manual");
  assert.equal(byId(auth, "SPLUNK-AUTH-06").status, "pass");
  for (const id of ["SPLUNK-AC-07", "SPLUNK-AC-08", "SPLUNK-AC-09", "SPLUNK-AC-10", "SPLUNK-AC-11", "SPLUNK-AC-12"]) {
    assert.equal(byId(access, id).status, "pass", id);
  }
  assert.equal(byId(data, "SPLUNK-DP-13").status, "pass");
  assert.equal(byId(data, "SPLUNK-DP-14").status, "manual");
  assert.equal(byId(data, "SPLUNK-DP-15").status, "pass");
  assert.equal(byId(data, "SPLUNK-DP-16").status, "pass");
  assert.equal(byId(audit, "SPLUNK-AUD-17").status, "pass");
  assert.equal(byId(audit, "SPLUNK-AUD-18").status, "pass");
  assert.equal(byId(platform, "SPLUNK-PLAT-19").status, "manual");
  assert.match(byId(platform, "SPLUNK-PLAT-19").summary, /Not applicable/);
  assert.equal(byId(platform, "SPLUNK-PLAT-20").status, "pass");
  assert.equal(byId(platform, "SPLUNK-PLAT-21").status, "pass");
  assert.equal(byId(platform, "SPLUNK-PLAT-22").status, "pass");
  assert.equal(byId(platform, "SPLUNK-PLAT-23").status, "pass");
  const all = [auth, access, data, audit, platform].flatMap((item) => item.findings);
  assert.equal(all.length, 23);
  assert.ok(all.every((item) => item.mappings.length === 8 && item.mappings.some((mapping) => mapping.startsWith("FedRAMP"))));
});

test("weak fixture fails the controls with explicit non-compliant evidence", async () => {
  const { client: api } = client(WEAK);
  const [auth, access, data, audit, platform] = await runAllAssessments(api);
  const expectedFail = {
    "SPLUNK-AUTH-01": auth, "SPLUNK-AUTH-02": auth, "SPLUNK-AUTH-03": auth, "SPLUNK-AUTH-04": auth, "SPLUNK-AUTH-06": auth,
    "SPLUNK-AC-07": access, "SPLUNK-AC-08": access, "SPLUNK-AC-09": access, "SPLUNK-AC-10": access, "SPLUNK-AC-11": access, "SPLUNK-AC-12": access,
    "SPLUNK-DP-13": data, "SPLUNK-DP-15": data, "SPLUNK-DP-16": data,
    "SPLUNK-AUD-17": audit, "SPLUNK-AUD-18": audit,
    "SPLUNK-PLAT-20": platform, "SPLUNK-PLAT-21": platform, "SPLUNK-PLAT-22": platform, "SPLUNK-PLAT-23": platform,
  };
  for (const [id, result] of Object.entries(expectedFail)) {
    assert.equal(byId(result, id).status, "fail", `${id}: ${byId(result, id).summary}`);
  }
  assert.match(byId(auth, "SPLUNK-AUTH-06").summary, /never expire/);
  assert.equal(byId(auth, "SPLUNK-AUTH-06").evidence.missing_dates.length, 1);
  assert.equal(byId(auth, "SPLUNK-AUTH-05").status, "manual");
  assert.equal(byId(data, "SPLUNK-DP-14").status, "manual");
  assert.equal(byId(platform, "SPLUNK-PLAT-19").status, "manual");
});

test("Splunk Cloud with ACS evaluates IP allow lists and HEC through ACS and scopes Enterprise-only controls to manual", async () => {
  const cloud = { ...HARDENED, "/services/server/info": [entry("server-info", { version: "9.3.2411", product_type: "splunk_cloud", instance_type: "cloud" })] };
  const acs = {
    "/access/search-api/ipallowlists": { subnets: ["203.0.113.0/24"] },
    "/access/hec/ipallowlists": { subnets: [] },
    "/access/s2s/ipallowlists": { subnets: ["198.51.100.0/24"] },
    "/access/search-ui/ipallowlists": { subnets: ["0.0.0.0/0"] },
    "/inputs/http-event-collectors": { "http-event-collectors": [{ spec: { name: "firehose", allowedIndexes: ["main"], defaultSourcetype: "aws:firehose", disabled: false, useACK: true }, token: "secret" }] },
  };
  const { client: api } = client(cloud, { acs }, { stack: "acme-stack", acsToken: "acs-jwt" });
  const data = await assessSplunkDataProtection(api);
  const platform = await assessSplunkPlatformHardening(api);
  assert.equal(byId(data, "SPLUNK-DP-15").status, "manual");
  assert.equal(byId(data, "SPLUNK-DP-16").status, "pass");
  assert.equal(byId(data, "SPLUNK-DP-16").evidence.source, "acs:/inputs/http-event-collectors");
  assert.equal(byId(platform, "SPLUNK-PLAT-19").status, "fail");
  assert.match(byId(platform, "SPLUNK-PLAT-19").summary, /hec, search-ui/);
  assert.equal(byId(platform, "SPLUNK-PLAT-23").status, "manual");

  const openApiShape = {
    ...acs,
    "/inputs/http-event-collectors": { http_event_collectors: [{ spec: { name: "firehose", allowedIndexes: ["main"], defaultSourcetype: "aws:firehose", disabled: false, useAck: true }, token: "secret" }] },
  };
  const openApiData = await assessSplunkDataProtection(client(cloud, { acs: openApiShape }, { stack: "acme-stack", acsToken: "acs-jwt" }).client);
  assert.equal(byId(openApiData, "SPLUNK-DP-16").status, "pass");
  assert.equal(byId(openApiData, "SPLUNK-DP-16").evidence.tokens, 1);

  const noAcs = client(cloud).client;
  const platformNoAcs = await assessSplunkPlatformHardening(noAcs);
  assert.equal(byId(platformNoAcs, "SPLUNK-PLAT-19").status, "manual");
  assert.match(byId(platformNoAcs, "SPLUNK-PLAT-19").summary, /ACS is not configured/);
});

test("false-pass self-check (a): every endpoint returning 403 yields only manual findings naming the cause", async () => {
  const { client: api } = client(HARDENED, { status: 403 });
  const findings = (await runAllAssessments(api)).flatMap((item) => item.findings);
  assert.equal(findings.length, 23);
  assert.ok(findings.every((item) => item.status !== "pass"), findings.filter((item) => item.status === "pass").map((item) => item.id).join(","));
  assert.ok(findings.every((item) => item.status === "manual"), findings.filter((item) => item.status !== "manual").map((item) => `${item.id}=${item.status}`).join(","));
  assert.ok(findings.filter((item) => /403/.test(item.summary)).length >= 15);
});

test("false-pass self-check (b): every list empty never passes; emptiness is manual for every control", async () => {
  const empty = Object.fromEntries(Object.keys(HARDENED).map((key) => [key, []]));
  const { client: api } = client(empty, { searchResults: [] });
  const findings = (await runAllAssessments(api)).flatMap((item) => item.findings);
  assert.equal(findings.length, 23);
  assert.ok(findings.every((item) => item.status !== "pass"), findings.filter((item) => item.status === "pass").map((item) => item.id).join(","));
  assert.ok(findings.every((item) => item.status === "manual"), findings.filter((item) => item.status !== "manual").map((item) => `${item.id}=${item.status}`).join(","));
});

test("false-pass self-check (b'): HEC globally disabled with zero tokens is the one explicit empty-inventory pass", async () => {
  const fixture = { ...HARDENED, "/services/data/inputs/http": [entry("http", { disabled: 1, enableSSL: 1 })] };
  const { client: api } = client(fixture);
  const data = await assessSplunkDataProtection(api);
  assert.equal(byId(data, "SPLUNK-DP-16").status, "pass");
  assert.match(byId(data, "SPLUNK-DP-16").summary, /disabled=1 read explicitly/);
});

test("false-pass self-check (c): partial inventories never pass and record seen versus total", async () => {
  const partialFixture = { ...HARDENED, "/services/authorization/roles": [entry("admin", { capabilities: ["admin_all_objects"], srchIndexesAllowed: ["*", "_*"] }), entry("analyst", {})] };
  const { client: api } = client(partialFixture, { partial: true });
  const results = await runAllAssessments(api);
  const findings = results.flatMap((item) => item.findings);
  assert.equal(findings.length, 23);
  assert.ok(findings.every((item) => item.status !== "pass"), findings.filter((item) => item.status === "pass").map((item) => item.id).join(","));
  const rbac = byId(results[1], "SPLUNK-AC-07");
  assert.equal(rbac.status, "warn");
  assert.equal(rbac.evidence.seen, 2);
  assert.equal(rbac.evidence.total, 7);
  assert.equal(byId(results[1], "SPLUNK-AC-09").status, "manual");
  assert.match(byId(results[0], "SPLUNK-AUTH-06").summary, /1 of 6 tokens/);
});

/** Each paginated inventory and the finding ids whose verdict reads it; a truncated list demotes exactly these. */
const INVENTORY_READERS = {
  "/services/configs/conf-authentication": { name: "conf-authentication", readers: ["SPLUNK-AUTH-01", "SPLUNK-AUTH-02", "SPLUNK-AUTH-03"] },
  "/services/authentication/providers/SAML": { name: "saml-providers", readers: ["SPLUNK-AUTH-01"] },
  "/services/admin/Duo-MFA": { name: "mfa-providers", readers: ["SPLUNK-AUTH-03"] },
  "/services/configs/conf-web": { name: "conf-web", readers: ["SPLUNK-AUTH-04", "SPLUNK-DP-13"] },
  "/services/configs/conf-server": { name: "conf-server", readers: ["SPLUNK-AUTH-04", "SPLUNK-DP-13"] },
  "/services/authentication/users": { name: "users", readers: ["SPLUNK-AUTH-01", "SPLUNK-AUTH-06", "SPLUNK-AC-08", "SPLUNK-AUD-18", "SPLUNK-PLAT-22"] },
  "/services/authorization/tokens": { name: "tokens", readers: ["SPLUNK-AUTH-06"] },
  "/services/authorization/roles": { name: "roles", readers: ["SPLUNK-AUTH-05", "SPLUNK-AC-07", "SPLUNK-AC-09", "SPLUNK-AC-10", "SPLUNK-AC-12", "SPLUNK-AUD-18", "SPLUNK-PLAT-20"] },
  "/servicesNS/-/-/saved/searches": { name: "saved-searches", readers: ["SPLUNK-AC-11", "SPLUNK-PLAT-22"] },
  "/servicesNS/-/-/data/lookup-table-files": { name: "lookup-table-files", readers: ["SPLUNK-AC-11"] },
  "/services/configs/conf-outputs": { name: "conf-outputs", readers: ["SPLUNK-DP-15"] },
  "/services/configs/conf-inputs": { name: "conf-inputs", readers: ["SPLUNK-DP-15", "SPLUNK-PLAT-23"] },
  "/services/data/inputs/http": { name: "hec-inputs", readers: ["SPLUNK-DP-16"] },
  "/services/data/indexes": { name: "indexes", readers: ["SPLUNK-DP-14", "SPLUNK-AUD-17", "SPLUNK-AUD-18"] },
  "/services/configs/conf-audit": { name: "conf-audit", readers: ["SPLUNK-AUD-17"] },
  "/services/apps/local": { name: "apps", readers: ["SPLUNK-PLAT-20"] },
  "/servicesNS/-/-/storage/collections/config": { name: "kv-collections", readers: ["SPLUNK-PLAT-21"] },
  "/services/data/inputs/tcp/cooked": { name: "tcp-cooked-inputs", readers: ["SPLUNK-PLAT-23"] },
};

test("rule 10 corollary: a truncated inventory demotes only the findings that read it, and every other pass keeps its verdict and summary", async () => {
  const fixture = { ...HARDENED, "/services/configs/conf-audit": [entry("auditTrail", { queueing: "1", logging_format: "both" })] };
  const baseline = new Map((await runAllAssessments(client(fixture).client)).flatMap((item) => item.findings).map((item) => [item.id, item]));
  assert.equal(baseline.size, 23);
  assert.equal([...baseline.values()].filter((item) => item.status === "pass").length, 20, "the fixture passes every finding that can pass");
  assert.ok(Object.keys(INVENTORY_READERS).every((path) => path in fixture), "every paginated inventory the assessors read is in the fixture");

  for (const [path, { name, readers }] of Object.entries(INVENTORY_READERS)) {
    const { client: api, seen } = client(fixture, { partialPaths: [path] });
    const findings = (await runAllAssessments(api)).flatMap((item) => item.findings);
    assert.ok(seen.some((request) => request.pathname === path), `${name}: the truncated list was requested`);
    for (const item of findings) {
      const before = baseline.get(item.id);
      if (readers.includes(item.id)) {
        assert.notEqual(item.status, "pass", `${name} truncated: reader ${item.id} must not pass: ${item.summary}`);
        if (before.status === "pass") {
          assert.equal(item.status, "warn", `${name} truncated: reader ${item.id} demotes to warn`);
          assert.match(item.summary, /(partially retrieved|before the walk stopped|were retrieved)/, `${name} truncated: ${item.id} states the partial view: ${item.summary}`);
        }
        if (item.evidence.partial_sources !== undefined) {
          assert.deepEqual(item.evidence.partial_sources, [name], `${name} truncated: ${item.id} names only the inventory it read`);
        }
      } else {
        assert.equal(item.status, before.status, `${name} truncated: non-reader ${item.id} keeps its ${before.status} verdict: ${item.summary}`);
        assert.equal(item.summary, before.summary, `${name} truncated: non-reader ${item.id} keeps its summary`);
        assert.equal(item.evidence.partial_sources, undefined, `${name} truncated: non-reader ${item.id} is not attributed to the truncated inventory`);
      }
    }
  }

  const { client: savedSearchesOnly } = client(fixture, { partialPaths: ["/servicesNS/-/-/saved/searches"] });
  const authentication = await assessSplunkAuthentication(savedSearchesOnly);
  assert.equal(byId(authentication, "SPLUNK-AUTH-02").status, "pass", "the password policy verdict never read the saved search list");
  assert.equal(byId(authentication, "SPLUNK-AUTH-04").status, "pass", "the session timeout verdict never read the saved search list");
  const access = await assessSplunkAccessControl(savedSearchesOnly);
  assert.equal(byId(access, "SPLUNK-AC-11").status, "warn");
  assert.match(byId(access, "SPLUNK-AC-11").summary, /Only 1 of 6 saved searches were retrieved/);
  assert.equal(byId(access, "SPLUNK-AC-07").status, "pass", "the role verdicts never read the saved search list");
});

test("unreadable audit search downgrades an enabled _audit index to warn, and a disabled search skips to warn", async () => {
  const { client: api } = client({ ...HARDENED }, { searchResults: [] });
  const noEvents = await assessSplunkAuditMonitoring(api);
  assert.equal(byId(noEvents, "SPLUNK-AUD-17").status, "fail");
  const skipped = await assessSplunkAuditMonitoring(client(HARDENED).client, { runSearches: false });
  assert.equal(byId(skipped, "SPLUNK-AUD-17").status, "warn");
});

test("audit.conf [auditTrail] queueing is read explicitly: absent file assumes the documented default, false caps at warn, forbidden caps at warn", async () => {
  const absent = await assessSplunkAuditMonitoring(client(HARDENED).client);
  assert.equal(byId(absent, "SPLUNK-AUD-17").status, "pass");
  assert.match(byId(absent, "SPLUNK-AUD-17").summary, /documented default true assumed/);
  assert.equal(absent.errors.length, 0);

  const explicit = await assessSplunkAuditMonitoring(client({ ...HARDENED, "/services/configs/conf-audit": [entry("auditTrail", { queueing: "1", logging_format: "both" })] }).client);
  assert.equal(byId(explicit, "SPLUNK-AUD-17").status, "pass");
  assert.match(byId(explicit, "SPLUNK-AUD-17").summary, /queueing=1/);
  assert.doesNotMatch(byId(explicit, "SPLUNK-AUD-17").summary, /assumed/);

  const notQueued = await assessSplunkAuditMonitoring(client({ ...HARDENED, "/services/configs/conf-audit": [entry("auditTrail", { queueing: "0" })] }).client);
  assert.equal(byId(notQueued, "SPLUNK-AUD-17").status, "warn");
  assert.match(byId(notQueued, "SPLUNK-AUD-17").summary, /tailing input/);

  const { fetchImpl } = createFetch(HARDENED);
  const forbiddenFetch = async (input, init) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    if (url.pathname === "/services/configs/conf-audit") return jsonResponse({ messages: [{ type: "ERROR", text: "forbidden" }] }, 403);
    return fetchImpl(input, init);
  };
  const forbidden = await assessSplunkAuditMonitoring(new SplunkApiClient(sampleConfig(), { fetchImpl: forbiddenFetch, retryDelayMs: 0 }));
  assert.equal(byId(forbidden, "SPLUNK-AUD-17").status, "warn");
  assert.match(byId(forbidden, "SPLUNK-AUD-17").summary, /audit\.conf could not be read/);
  assert.equal(forbidden.errors.length, 1);
});

async function dataProtectionWithOutputs(entries) {
  return assessSplunkDataProtection(client({ ...HARDENED, "/services/configs/conf-outputs": entries }).client);
}

test("review fix 1: an explicit useSSL=false fails control 15 even when a clientCert is present", async () => {
  const result = await dataProtectionWithOutputs([entry("tcpout:primary", { useSSL: "false", clientCert: "/opt/splunk/etc/auth/client.pem", sslPassword: "password" })]);
  const forwarding = byId(result, "SPLUNK-DP-15");
  assert.equal(forwarding.status, "fail");
  assert.match(forwarding.summary, /useSSL=false explicitly disables TLS regardless of certificate settings/);
  assert.equal(forwarding.evidence.targets[0].mode, "plaintext");
  assert.equal(forwarding.evidence.targets[0].clientCert, "/opt/splunk/etc/auth/client.pem");

  const explicit = await dataProtectionWithOutputs([entry("tcpout:primary", { useSSL: "true" })]);
  assert.equal(byId(explicit, "SPLUNK-DP-15").status, "pass");
  assert.match(byId(explicit, "SPLUNK-DP-15").summary, /useSSL=true explicitly/);
});

test("review fix 2: sslPassword is never TLS evidence and legacy mode with a clientCert caps at warn", async () => {
  const passwordOnly = await dataProtectionWithOutputs([entry("tcpout:primary", { server: "idx:9997", sslPassword: "password" })]);
  const finding = byId(passwordOnly, "SPLUNK-DP-15");
  assert.equal(finding.status, "fail");
  assert.match(finding.summary, /useSSL unset \(documented default legacy\) with no clientCert/);
  assert.equal(finding.evidence.targets[0].sslPassword_present, true);
  assert.match(finding.evidence.sslPassword_note, /not treated as TLS evidence/);

  const legacyWithCert = await dataProtectionWithOutputs([entry("tcpout:primary", { useSSL: "legacy", clientCert: "/opt/splunk/etc/auth/client.pem" })]);
  assert.equal(byId(legacyWithCert, "SPLUNK-DP-15").status, "warn");
  assert.match(byId(legacyWithCert, "SPLUNK-DP-15").summary, /only infer TLS/);
  assert.equal(byId(legacyWithCert, "SPLUNK-DP-15").evidence.targets[0].mode, "inferred_from_clientCert");

  const unsetWithCert = await dataProtectionWithOutputs([entry("tcpout:primary", { clientCert: "/opt/splunk/etc/auth/client.pem" })]);
  assert.equal(byId(unsetWithCert, "SPLUNK-DP-15").status, "warn");
});

test("review fix 3: useSSL set once in the global [tcpout] stanza applies to every target group and can be overridden per group or server", async () => {
  const inherited = await dataProtectionWithOutputs([
    entry("tcpout", { defaultGroup: "primary", useSSL: "true" }),
    entry("tcpout:primary", { server: "idx1:9997,idx2:9997" }),
    entry("tcpout:secondary", { server: "idx3:9997" }),
  ]);
  const finding = byId(inherited, "SPLUNK-DP-15");
  assert.equal(finding.status, "pass");
  assert.match(finding.summary, /2 inherit it from the global \[tcpout\] stanza/);
  assert.ok(finding.evidence.targets.every((item) => item.useSSL_source === "global [tcpout]"));
  assert.equal(finding.evidence.global_tcpout.useSSL, "true");

  const overridden = await dataProtectionWithOutputs([
    entry("tcpout", { useSSL: "true" }),
    entry("tcpout:primary", { server: "idx1:9997,idx2:9997" }),
    entry("tcpout-server://idx2:9997", { useSSL: "false" }),
  ]);
  const overriddenFinding = byId(overridden, "SPLUNK-DP-15");
  assert.equal(overriddenFinding.status, "fail");
  assert.match(overriddenFinding.summary, /tcpout-server:\/\/idx2:9997/);
  assert.equal(overriddenFinding.evidence.targets.find((item) => item.target === "tcpout:primary").mode, "explicit_tls");

  const groupOverride = await dataProtectionWithOutputs([entry("tcpout", { useSSL: "true" }), entry("tcpout:primary", { useSSL: "false" })]);
  assert.equal(byId(groupOverride, "SPLUNK-DP-15").status, "fail");
});

async function platformWithReceivers(cooked, inputs) {
  const fixture = { ...HARDENED, "/services/data/inputs/tcp/cooked": cooked };
  if (inputs === undefined) delete fixture["/services/configs/conf-inputs"];
  else fixture["/services/configs/conf-inputs"] = inputs;
  return assessSplunkPlatformHardening(client(fixture).client);
}

const HARDENED_SSL_STANZA = entry("SSL", { serverCert: "/opt/splunk/etc/auth/server.pem", requireClientCert: 1 });

test("review fix 4: a listener name containing ssl never upgrades an explicit plaintext receiver", async () => {
  const named = await platformWithReceivers(
    [entry("ssl9997", { disabled: 0, SSL: 0 }), entry("sslhost.example.com:9998", { disabled: 0 })],
    [entry("splunktcp://ssl9997", { disabled: 0 }), entry("splunktcp://sslhost.example.com:9998", { disabled: 0 }), HARDENED_SSL_STANZA],
  );
  const finding = byId(named, "SPLUNK-PLAT-23");
  assert.equal(finding.status, "fail");
  assert.match(finding.summary, /2 of 2 enabled S2S listeners are plaintext/);
  assert.deepEqual(finding.evidence.listeners.map((item) => item.port).sort(), ["9997", "9998"]);

  const mixed = await platformWithReceivers(
    [entry("9997", { disabled: 0 }), entry("9998", { disabled: 0 })],
    [entry("splunktcp-ssl:9997", { disabled: 0 }), entry("splunktcp://9998", { disabled: 0 }), HARDENED_SSL_STANZA],
  );
  assert.equal(byId(mixed, "SPLUNK-PLAT-23").status, "fail");
  assert.match(byId(mixed, "SPLUNK-PLAT-23").summary, /ports 9998/);
});

test("review fix 5: control 23 decides TLS from inputs.conf [splunktcp-ssl:*] and [SSL], never from the cooked REST view alone", async () => {
  const cookedOnly = await platformWithReceivers([entry("9997", { disabled: 0, SSL: 1 })], undefined);
  const unknown = byId(cookedOnly, "SPLUNK-PLAT-23");
  assert.equal(unknown.status, "manual");
  assert.match(unknown.summary, /conf-inputs could not be read/);
  assert.match(unknown.summary, /does not report TLS/);

  const noStanza = await platformWithReceivers([entry("9997", { disabled: 0, SSL: 1 })], [HARDENED_SSL_STANZA]);
  assert.equal(byId(noStanza, "SPLUNK-PLAT-23").status, "manual");
  assert.match(byId(noStanza, "SPLUNK-PLAT-23").summary, /no \[splunktcp-ssl:<port>\] stanza/);

  const noRequire = await platformWithReceivers([entry("9997", { disabled: 0 })], [entry("splunktcp-ssl:9997", { disabled: 0 }), entry("SSL", { serverCert: "/opt/splunk/etc/auth/server.pem" })]);
  assert.equal(byId(noRequire, "SPLUNK-PLAT-23").status, "warn");
  assert.match(byId(noRequire, "SPLUNK-PLAT-23").summary, /requireClientCert absent from both \[splunktcp-ssl:9997\] and \[SSL\]/);

  const noCert = await platformWithReceivers([entry("9997", { disabled: 0 })], [entry("splunktcp-ssl:9997", { disabled: 0 }), entry("SSL", { requireClientCert: 1 })]);
  assert.equal(byId(noCert, "SPLUNK-PLAT-23").status, "warn");
  assert.match(byId(noCert, "SPLUNK-PLAT-23").summary, /serverCert is absent/);

  const missingSsl = await platformWithReceivers([entry("9997", { disabled: 0 })], [entry("splunktcp-ssl:9997", { disabled: 0 })]);
  assert.equal(byId(missingSsl, "SPLUNK-PLAT-23").status, "warn");
  assert.match(byId(missingSsl, "SPLUNK-PLAT-23").summary, /absent from both \[splunktcp-ssl:9997\] and \[SSL\]/);
  assert.equal(byId(missingSsl, "SPLUNK-PLAT-23").evidence.ssl_stanza_present, false);

  const hardened = await platformWithReceivers([entry("9997", { disabled: 0 })], [entry("splunktcp-ssl:9997", { disabled: 0 }), HARDENED_SSL_STANZA]);
  assert.equal(byId(hardened, "SPLUNK-PLAT-23").status, "pass");
  assert.match(byId(hardened, "SPLUNK-PLAT-23").summary, /\[splunktcp-ssl:\*\] receivers \(ports 9997\) with serverCert set and requireClientCert=true/);

  const confOnly = await platformWithReceivers([], [entry("splunktcp-ssl:9997", { disabled: 0 }), entry("splunktcp://9996", { disabled: 1 }), HARDENED_SSL_STANZA]);
  assert.equal(byId(confOnly, "SPLUNK-PLAT-23").status, "pass");
  assert.equal(byId(confOnly, "SPLUNK-PLAT-23").evidence.listeners.length, 1);
});

test("review fix 8: control 23 resolves serverCert and requireClientCert per port from [splunktcp-ssl:<port>] before [SSL]", async () => {
  const portOverridesGlobal = await platformWithReceivers(
    [entry("9997", { disabled: 0 })],
    [entry("splunktcp-ssl:9997", { disabled: 0, requireClientCert: 0 }), HARDENED_SSL_STANZA],
  );
  const overridden = byId(portOverridesGlobal, "SPLUNK-PLAT-23");
  assert.equal(overridden.status, "warn");
  assert.match(overridden.summary, /port 9997 requireClientCert=0 from \[splunktcp-ssl:9997\], overriding \[SSL\] requireClientCert=1/);
  assert.doesNotMatch(overridden.summary, /requireClientCert=true/);
  const overriddenListener = overridden.evidence.listeners.find((item) => item.port === "9997");
  assert.equal(overriddenListener.tls.requireClientCert, "0");
  assert.equal(overriddenListener.tls.requireClientCert_source, "[splunktcp-ssl:9997]");
  assert.equal(overriddenListener.tls.serverCert_source, "[SSL]");

  const perPortOnly = await platformWithReceivers(
    [entry("9997", { disabled: 0 })],
    [entry("splunktcp-ssl:9997", { disabled: 0, serverCert: "/opt/splunk/etc/auth/port9997.pem", requireClientCert: "true", sslVersions: "tls1.2" })],
  );
  const perPort = byId(perPortOnly, "SPLUNK-PLAT-23");
  assert.equal(perPort.status, "pass");
  assert.match(perPort.summary, /resolved per port from \[splunktcp-ssl:<port>\] first and \[SSL\] second/);
  assert.equal(perPort.evidence.ssl_stanza_present, false);
  const perPortListener = perPort.evidence.listeners[0];
  assert.equal(perPortListener.tls.serverCert, "/opt/splunk/etc/auth/port9997.pem");
  assert.equal(perPortListener.tls.serverCert_source, "[splunktcp-ssl:9997]");
  assert.equal(perPortListener.tls.requireClientCert_source, "[splunktcp-ssl:9997]");

  const mixed = await platformWithReceivers(
    [entry("9997", { disabled: 0 }), entry("9998", { disabled: 0 })],
    [entry("splunktcp-ssl:9997", { disabled: 0 }), entry("splunktcp-ssl:9998", { disabled: 0, requireClientCert: "false" }), HARDENED_SSL_STANZA],
  );
  const mixedFinding = byId(mixed, "SPLUNK-PLAT-23");
  assert.equal(mixedFinding.status, "warn");
  assert.match(mixedFinding.summary, /not true for 1 of them: port 9998 requireClientCert=false from \[splunktcp-ssl:9998\], overriding \[SSL\] requireClientCert=1/);
  assert.doesNotMatch(mixedFinding.summary, /port 9997/);

  const perPortCertOnly = await platformWithReceivers(
    [entry("9997", { disabled: 0 })],
    [entry("splunktcp-ssl:9997", { disabled: 0, serverCert: "/opt/splunk/etc/auth/port9997.pem" }), entry("SSL", { requireClientCert: 1 })],
  );
  assert.equal(byId(perPortCertOnly, "SPLUNK-PLAT-23").status, "pass");
});

test("review fix 9: an absent requireClientCert quotes the documented defaults and stays unknown at warn", async () => {
  const absent = await platformWithReceivers([entry("9997", { disabled: 0 })], [entry("splunktcp-ssl:9997", { disabled: 0 }), entry("SSL", { serverCert: "/opt/splunk/etc/auth/server.pem" })]);
  const finding = byId(absent, "SPLUNK-PLAT-23");
  assert.equal(finding.status, "warn");
  assert.match(finding.summary, /documented default: "false" if using self-signed and third-party certificates, "true" if using the default certificates, and the REST view cannot tell which certificates are in use/);
  assert.doesNotMatch(finding.summary, /varies with the certificate in use/);
  assert.equal(finding.evidence.listeners[0].tls.requireClientCert, null);
  assert.equal(finding.evidence.listeners[0].tls.requireClientCert_source, "unset");

  const explicitFalse = await platformWithReceivers([entry("9997", { disabled: 0 })], [entry("splunktcp-ssl:9997", { disabled: 0 }), entry("SSL", { serverCert: "/opt/splunk/etc/auth/server.pem", requireClientCert: 0 })]);
  assert.equal(byId(explicitFalse, "SPLUNK-PLAT-23").status, "warn");
  assert.match(byId(explicitFalse, "SPLUNK-PLAT-23").summary, /port 9997 requireClientCert=0 from \[SSL\]/);
  assert.doesNotMatch(byId(explicitFalse, "SPLUNK-PLAT-23").summary, /documented default/);
});

test("review fix 10: data/inputs/tcp/ssl is no longer exposed or requested", async () => {
  assert.equal(typeof SplunkApiClient.prototype.listSslTcpInputs, "undefined");
  const { client: api, seen } = client(HARDENED);
  await runAllAssessments(api);
  await checkSplunkAccess(api);
  const base = createTempBase("grclanker-splunk-no-tcp-ssl-");
  await exportSplunkAuditBundle(api, sampleConfig(), base);
  assert.ok(seen.length > 0);
  assert.ok(seen.every((request) => request.pathname !== "/services/data/inputs/tcp/ssl"), "data/inputs/tcp/ssl was requested");
  assert.ok(seen.some((request) => request.pathname === "/services/configs/conf-inputs"));
});

test("review fix 6: an absent sslVersions is an unknown default and caps control 13 at warn", async () => {
  const fixture = { ...HARDENED, "/services/configs/conf-server": [entry("general", { sessionTimeout: "30m" }), entry("sslConfig", { enableSplunkdSSL: 1, requireClientCert: 1 })] };
  const result = await assessSplunkDataProtection(client(fixture).client);
  const tls = byId(result, "SPLUNK-DP-13");
  assert.equal(tls.status, "warn");
  assert.match(tls.summary, /sslVersions absent and its documented default varies by release/);
  assert.doesNotMatch(tls.summary, /tls1\.2 \(default\)|default tls1\.2 assumed/);
  assert.equal(tls.evidence.unknown_defaults.length, 1);
  assert.equal(byId(await assessSplunkDataProtection(client(HARDENED).client), "SPLUNK-DP-13").status, "pass");
});

test("review fix 7: non-admin roles without srchIndexesAllowed are never counted as lacking _audit or _internal access", async () => {
  const someMissing = {
    ...HARDENED,
    "/services/authorization/roles": [
      entry("admin", { capabilities: ["admin_all_objects"], srchIndexesAllowed: ["*", "_*"] }),
      entry("user", { capabilities: ["search"], srchIndexesAllowed: ["main"] }),
      entry("opaque", { capabilities: ["search"] }),
    ],
  };
  const partial = await assessSplunkAccessControl(client(someMissing).client);
  const indexAccess = byId(partial, "SPLUNK-AC-10");
  assert.equal(indexAccess.status, "warn");
  assert.match(indexAccess.summary, /1 of 2 non-admin roles did not expose srchIndexesAllowed \(opaque\)/);
  assert.match(indexAccess.summary, /not counted as granted/);
  assert.deepEqual(indexAccess.evidence.roles_without_srchIndexesAllowed_field, ["opaque"]);
  const searchScope = byId(partial, "SPLUNK-AC-09");
  assert.equal(searchScope.status, "warn");
  assert.match(searchScope.summary, /not counted as unrestricted/);

  const allMissing = { ...HARDENED, "/services/authorization/roles": [entry("admin", { capabilities: ["admin_all_objects"], srchIndexesAllowed: ["*", "_*"] }), entry("opaque", { capabilities: ["search"] })] };
  const unknown = await assessSplunkAccessControl(client(allMissing).client);
  assert.equal(byId(unknown, "SPLUNK-AC-10").status, "manual");
  assert.match(byId(unknown, "SPLUNK-AC-10").summary, /Unknown: no non-admin role exposed the srchIndexesAllowed field/);

  const explicit = await assessSplunkAccessControl(client({ ...someMissing, "/services/authorization/roles": [...someMissing["/services/authorization/roles"], entry("leaky", { capabilities: ["search"], imported_srchIndexesAllowed: ["_*"] })] }).client);
  assert.equal(byId(explicit, "SPLUNK-AC-10").status, "fail");
});

test("exportSplunkAuditBundle writes core_data, analysis, compliance reports, quick reference, errors log, and a paired zip", async () => {
  const base = createTempBase("grclanker-splunk-export-");
  const partialFailure = { ...HARDENED };
  delete partialFailure["/services/authorization/tokens"];
  const { client: api } = client(partialFailure);
  const result = await exportSplunkAuditBundle(api, sampleConfig(), base);
  assert.ok(existsSync(result.outputDir));
  assert.ok(existsSync(result.zipPath));
  assert.equal(result.zipPath, `${result.outputDir}.zip`);
  assert.equal(result.findingCount, 23);
  assert.ok(result.errorCount >= 1);
  for (const file of [
    "QUICK_REFERENCE.md", "_errors.log", "metadata.json", "analysis/findings.json", "analysis/authentication.json", "analysis/platform_hardening.json",
    "core_data/server_info.json", "core_data/roles.json", "core_data/access_check.json", "core_data/conf_outputs.json", "core_data/conf_inputs.json",
    "compliance/executive_summary.md", "compliance/unified_compliance_matrix.md", "compliance/fedramp.md", "compliance/cmmc.md", "compliance/soc2.md", "compliance/cis.md", "compliance/pci.md", "compliance/stig.md", "compliance/irap.md", "compliance/ismap.md",
  ]) {
    assert.ok(existsSync(join(result.outputDir, file)), file);
  }
  assert.match(readFileSync(join(result.outputDir, "_errors.log"), "utf8"), /tokens/);
  const findings = JSON.parse(readFileSync(join(result.outputDir, "analysis/findings.json"), "utf8"));
  assert.equal(findings.find((item) => item.id === "SPLUNK-AUTH-06").status, "manual");
  const metadata = JSON.parse(readFileSync(join(result.outputDir, "metadata.json"), "utf8"));
  assert.equal(metadata.url, "https://splunk.example.com:8089");
  assertNoWindowOf(readFileSync(join(result.outputDir, "core_data/hec_inputs.json"), "utf8"), SAMPLE_TOKEN, "core_data/hec_inputs.json");

  const rerun = await exportSplunkAuditBundle(client(partialFailure).client, sampleConfig(), base);
  assert.notEqual(rerun.outputDir, result.outputDir);
  assert.notEqual(rerun.zipPath, result.zipPath);
  assert.ok(existsSync(result.zipPath) && existsSync(rerun.zipPath));
});

/** Planted secrets: random alphanumerics (the Splunk ciphertexts keep their $7$ and $1$ prefixes), so no 6-character window of one occurs in a legitimate fixture value. */
const FAKE_SECRETS = {
  pass4SymmKey: "8Kw9ExUHb7Y3CbFJdr",
  clusteringKey: "$7$gkWJcf98TvLBnPKkHJ",
  sslKeysfilePassword: "4975Q3dY7v42SawGus",
  proxyPassword: "9UuF9u63aYHpsFUmeu",
  httpEventCollectorToken: "e3PWkuJSQgQbcjKyRz",
  discoveryKey: "gR7Efd8kk72J87EFaW",
  outputsSslPassword: "axJE3DCPasdNvvp9Tt",
  soapPassword: "A4w2XUNjYgBBfCXhsp",
  rsaAccessKey: "SZWRrhMsc6XjB5LURB",
  bindPassword: "5ZAR84KxJV5mqCKQej",
  duoSecret: "Bfk7B9GfWxkLEgkV7C",
  hashedValue: "$1$RbDk5JPFPuQHvDnKvd",
  hecToken: "9XWrk2ZvMFkvKRxUd9",
  inputsSslPassword: "pMRkZj27UYBXajtvFySbdSbQ",
  s2sPassword: "Heb5VKCAf2VT5MSKXbdBZ46c",
  webSslPassword: "78MufNpWDNdJmpjX9tMhHjW3",
  hecInputToken: "tsaMTrUYqUkYNN8aZKTjmmLR",
  webhookToken: "ZFEs9XDcfwfCFxxfyVD9FqcU",
  slackToken: "8bsWKgqWCQn7fRJgD6eKk4jr",
  pagerdutyKey: "C9sKx6YMZee52aA9hKavCtjB",
  customToken: "nXH5v29gTgy6CsrHAQahPfRn",
  splText: "6tNNaNeeqP4vcQX6UjQh2zpM",
  queryToken: "ShWLCDwUTEn9pFsdCc38ZLD7",
  acsHecToken: "Vh27ecdg7ce6eqg3eZ3Y3FyN",
  errorBody: "b4cmZJu28ZhHvQfDrMff734X",
};

const SECRET_FIXTURE = {
  ...HARDENED,
  "/services/configs/conf-server": [
    entry("general", { sessionTimeout: "30m", pass4SymmKey: FAKE_SECRETS.pass4SymmKey }),
    entry("clustering", { mode: "manager", pass4SymmKey: FAKE_SECRETS.clusteringKey }),
    entry("sslConfig", { enableSplunkdSSL: 1, sslVersions: "tls1.2", requireClientCert: 1, cipherSuite: "ECDHE-RSA-AES256-GCM-SHA384", sslKeysfilePassword: FAKE_SECRETS.sslKeysfilePassword }),
    entry("proxyConfig", { http_proxy: `http://proxyuser:${FAKE_SECRETS.proxyPassword}@proxy.example.com:8080`, https_proxy: `https://proxyuser:${FAKE_SECRETS.proxyPassword}@proxy.example.com:8443` }),
  ],
  "/services/configs/conf-outputs": [
    entry("tcpout:primary", { useSSL: "true", clientCert: "/opt/splunk/etc/auth/client.pem", sslPassword: FAKE_SECRETS.outputsSslPassword }),
    entry("httpout", { uri: `https://hec.example.com:8088?token=${FAKE_SECRETS.queryToken}`, httpEventCollectorToken: FAKE_SECRETS.httpEventCollectorToken }),
    entry("indexer_discovery:idx", { pass4SymmKey: FAKE_SECRETS.discoveryKey, manager_uri: "https://cm.example.com:8089" }),
  ],
  "/services/configs/conf-authentication": [
    entry("authentication", { authType: "SAML", authSettings: "okta", externalTwoFactorAuthVendor: "Duo" }),
    entry("okta", { disabled: 0, idpSSOUrl: "https://idp.example.com/sso", attributeQuerySoapPassword: FAKE_SECRETS.soapPassword }),
    entry("rsa", { accessKey: FAKE_SECRETS.rsaAccessKey, replayCache: FAKE_SECRETS.hashedValue }),
    entry("corp-ldap", { bindDNpassword: FAKE_SECRETS.bindPassword }),
    entry("duo", { appSecretKey: FAKE_SECRETS.duoSecret, secretKey: FAKE_SECRETS.duoSecret }),
    entry("splunk_auth", { minPasswordLength: 14, minPasswordUppercase: 1, minPasswordLowercase: 1, minPasswordDigit: 1, minPasswordSpecial: 1, expirePasswordDays: 90, forceWeakPasswordChange: 1, lockoutUsers: 1, passwordHistoryCount: 24 }),
  ],
  "/services/configs/conf-inputs": [
    entry("splunktcp-ssl:9997", { disabled: 0, sslPassword: FAKE_SECRETS.s2sPassword, password: FAKE_SECRETS.s2sPassword }),
    entry("SSL", { serverCert: "/opt/splunk/etc/auth/server.pem", requireClientCert: 1, sslVersions: "tls1.2", sslPassword: FAKE_SECRETS.inputsSslPassword }),
    entry("http://app-token", { token: FAKE_SECRETS.hecToken, index: "main" }),
  ],
  "/services/configs/conf-web": [entry("settings", { enableSplunkWebSSL: 1, "tools.sessions.timeout": 30, sslVersions: "tls1.2", sslPassword: FAKE_SECRETS.webSslPassword })],
  "/services/data/inputs/http": [
    entry("http", { disabled: 0, enableSSL: 1, port: 8088 }),
    entry("app-token", { disabled: 0, indexes: "main", sourcetype: "app:json", useACK: 1, token: FAKE_SECRETS.hecInputToken }),
  ],
  "/servicesNS/-/-/saved/searches": [
    entry("Errors", {
      is_scheduled: 1,
      disabled: 0,
      dispatchAs: "user",
      search: `index=main error ${FAKE_SECRETS.splText}`,
      "dispatch.earliest_time": "-24h",
      "action.webhook": 1,
      "action.webhook.param.url": `https://hooks.example.com/services/${FAKE_SECRETS.webhookToken}`,
      "action.slack": 1,
      "action.slack.param.webhook_url": `https://hooks.slack.com/services/${FAKE_SECRETS.slackToken}`,
      "action.pagerduty": 1,
      "action.pagerduty.param.integration_key": FAKE_SECRETS.pagerdutyKey,
      "action.custom.param.api_token": FAKE_SECRETS.customToken,
    }, { sharing: "app", owner: "auditor", app: "search", perms: { read: ["*"], write: ["admin"] } }),
  ],
};

test("rule 9: the exported bundle, the zip, the assess payloads, and the access check never carry conf secrets, HEC tokens, alert action parameters, or the raw splunktcp-ssl stanza", async () => {
  const { fetchImpl } = createFetch(SECRET_FIXTURE);
  const withErrorBody = async (input, init) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    if (url.pathname === "/servicesNS/-/-/storage/collections/config") return new Response(`<html>${FAKE_SECRETS.errorBody}</html>`, { status: 400, headers: { "content-type": "text/html" } });
    return fetchImpl(input, init);
  };
  const api = new SplunkApiClient(sampleConfig(), { fetchImpl: withErrorBody, retryDelayMs: 0 });
  const planted = [...Object.values(FAKE_SECRETS), SAMPLE_TOKEN, SAMPLE_ACS_TOKEN];
  assertFixtureFreeOfCanaryWindows(JSON.stringify({ fixture: SECRET_FIXTURE, config: sampleConfig(), errorBody: `<html>${FAKE_SECRETS.errorBody}</html>` }), planted, "secret fixture");
  const secrets = leakWindows(planted);

  const base = createTempBase("grclanker-splunk-rule9-");
  const result = await exportSplunkAuditBundle(api, sampleConfig(), base);
  const files = readBundleFiles(result.outputDir);
  for (const file of ["core_data/conf_server.json", "core_data/conf_outputs.json", "core_data/conf_authentication.json", "core_data/conf_inputs.json", "core_data/conf_web.json", "core_data/hec_inputs.json", "core_data/saved_searches.json", "analysis/platform_hardening.json", "_errors.log"]) {
    assert.ok(files.has(file), file);
  }
  assertSecretsAbsent(assert, files, secrets, "bundle directory");
  assertSecretsAbsent(assert, readZipEntries(result.zipPath), secrets, "zip archive");

  const server = JSON.parse(files.get("core_data/conf_server.json"));
  const stanzaOf = (snapshot, name) => snapshot.entries.find((item) => item.name === name).content;
  assert.equal(stanzaOf(server, "general").pass4SymmKey, "[REDACTED]");
  assert.equal(stanzaOf(server, "clustering").pass4SymmKey, "[REDACTED]");
  assert.equal(stanzaOf(server, "sslConfig").sslKeysfilePassword, "[REDACTED]");
  assert.equal(stanzaOf(server, "sslConfig").sslVersions, "tls1.2");
  assert.equal(stanzaOf(server, "proxyConfig").http_proxy, "http://[REDACTED]@proxy.example.com:8080/");
  const outputs = JSON.parse(files.get("core_data/conf_outputs.json"));
  assert.equal(stanzaOf(outputs, "httpout").httpEventCollectorToken, "[REDACTED]");
  assert.equal(stanzaOf(outputs, "httpout").uri, "https://hec.example.com:8088/?[REDACTED]");
  assert.equal(stanzaOf(outputs, "indexer_discovery:idx").pass4SymmKey, "[REDACTED]");
  assert.equal(stanzaOf(outputs, "indexer_discovery:idx").manager_uri, "https://cm.example.com:8089", "URLs without userinfo or a query stay verbatim");
  const authentication = JSON.parse(files.get("core_data/conf_authentication.json"));
  assert.equal(stanzaOf(authentication, "okta").attributeQuerySoapPassword, "[REDACTED]");
  assert.equal(stanzaOf(authentication, "okta").idpSSOUrl, "https://idp.example.com/sso");
  assert.equal(stanzaOf(authentication, "rsa").accessKey, "[REDACTED]");
  assert.equal(stanzaOf(authentication, "rsa").replayCache, "[REDACTED]", "$1$ ciphertext is redacted by value even under a non-credential key");
  assert.equal(stanzaOf(authentication, "corp-ldap").bindDNpassword, "[REDACTED]");
  assert.equal(stanzaOf(authentication, "duo").appSecretKey, "[REDACTED]");
  assert.equal(stanzaOf(authentication, "splunk_auth").minPasswordLength, 14, "password policy keys stay legible");
  assert.equal(stanzaOf(authentication, "splunk_auth").passwordHistoryCount, 24);
  const inputs = JSON.parse(files.get("core_data/conf_inputs.json"));
  assert.equal(stanzaOf(inputs, "http://app-token").token, "[REDACTED]", "URL-shaped stanza names stay verbatim and their token is redacted");
  assert.equal(stanzaOf(inputs, "splunktcp-ssl:9997").sslPassword, "[REDACTED]");
  assert.equal(stanzaOf(inputs, "SSL").serverCert, "/opt/splunk/etc/auth/server.pem");
  assert.equal(stanzaOf(JSON.parse(files.get("core_data/hec_inputs.json")), "app-token").token, "[REDACTED]");
  const savedSearches = JSON.parse(files.get("core_data/saved_searches.json"));
  const errorsSearch = savedSearches.entries.find((item) => item.name === "Errors");
  assert.equal(errorsSearch.content.search, "[REDACTED]");
  assert.equal(errorsSearch.content.search_index_scope, "index_bound");
  assert.deepEqual(errorsSearch.content.action_names, ["webhook", "slack", "pagerduty"]);
  assert.equal(errorsSearch.content.action_params_dropped, 4);
  assert.deepEqual(errorsSearch.acl.perms.write, ["admin"]);
  assert.ok(Object.keys(errorsSearch.content).every((key) => !key.includes(".param.")), "no action parameter survives the projection");
  const platform = JSON.parse(files.get("analysis/platform_hardening.json"));
  const s2s = platform.findings.find((item) => item.id === "SPLUNK-PLAT-23");
  assert.equal(s2s.status, "pass");
  assert.ok(s2s.evidence.listeners.every((listener) => listener.tlsStanza === undefined), "raw [splunktcp-ssl:<port>] stanza is not evidence");
  assert.equal(s2s.evidence.listeners[0].tls.requireClientCert, "1");
  assert.match(files.get("_errors.log"), /failed \(400\): non-JSON body \(text\/html, \d+ bytes\)/);

  const payloads = JSON.stringify([...(await runAllAssessments(api)), await checkSplunkAccess(api)]);
  assertSecretsAbsent(assert, new Map([["assess results and access check", payloads]]), secrets, "tool payloads");

  const cloud = { ...SECRET_FIXTURE, "/services/server/info": [entry("server-info", { version: "9.3.2411", product_type: "splunk_cloud", instance_type: "cloud" })] };
  const acs = { "/inputs/http-event-collectors": { "http-event-collectors": [{ spec: { name: "firehose", allowedIndexes: ["main"], defaultSourcetype: "aws:firehose", disabled: false, useACK: true }, token: FAKE_SECRETS.acsHecToken }] } };
  assertFixtureFreeOfCanaryWindows(JSON.stringify({ cloud, acs }), planted, "cloud secret fixture");
  const cloudData = JSON.stringify(await assessSplunkDataProtection(client(cloud, { acs }, { stack: "acme-stack", acsToken: SAMPLE_ACS_TOKEN }).client));
  assertNoWindowOf(cloudData, FAKE_SECRETS.acsHecToken, "ACS data protection payload");
  assertNoWindowOf(cloudData, SAMPLE_ACS_TOKEN, "ACS data protection payload");
});

function pagedFetch(fixture, path, page) {
  const { fetchImpl } = createFetch(fixture);
  return async (input, init) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    if (url.pathname !== path) return fetchImpl(input, init);
    return jsonResponse(page(Number(url.searchParams.get("offset") ?? "0"), Number(url.searchParams.get("count") ?? "100")));
  };
}

test("rule 10: list() reports a full last page without paging.total, the item cap, and a repeating page as truncated, and the dependent findings state seen versus total", async () => {
  const rolesPath = "/services/authorization/roles";
  const roleEntry = (index) => entry(`role-${index}`, { capabilities: ["search"], srchIndexesAllowed: ["main"] });

  const noTotal = new SplunkApiClient(sampleConfig(), { fetchImpl: pagedFetch(HARDENED, rolesPath, (offset, count) => ({ entry: Array.from({ length: count }, (_, index) => roleEntry(offset + index)) })), retryDelayMs: 0, pageSize: 3, maxEntries: 9 });
  const capped = await noTotal.listRoles();
  assert.equal(capped.truncated, true);
  assert.equal(capped.totalKnown, false);
  assert.equal(capped.entries.length, 9);
  const cappedAccess = await assessSplunkAccessControl(noTotal);
  for (const id of ["SPLUNK-AC-07", "SPLUNK-AC-09", "SPLUNK-AC-10", "SPLUNK-AC-12"]) {
    assert.notEqual(byId(cappedAccess, id).status, "pass", `${id}: ${byId(cappedAccess, id).summary}`);
  }
  assert.equal(byId(cappedAccess, "SPLUNK-AC-08").status, "pass", "the admin count reads the user list, not the capped role list, so it keeps its verdict");
  assert.equal(byId(cappedAccess, "SPLUNK-AC-11").status, "pass", "knowledge object permissions never read the capped role list");
  assert.match(byId(cappedAccess, "SPLUNK-AC-07").summary, /9 roles \(total unknown\)/);
  assert.equal(byId(cappedAccess, "SPLUNK-AC-07").evidence.total, null);
  assert.equal(byId(cappedAccess, "SPLUNK-AC-07").evidence.total_known, false);

  const shortLastPage = new SplunkApiClient(sampleConfig(), { fetchImpl: pagedFetch(HARDENED, rolesPath, (offset, count) => ({ entry: offset >= 6 ? [roleEntry(6)] : Array.from({ length: count }, (_, index) => roleEntry(offset + index)) })), retryDelayMs: 0, pageSize: 3 });
  const complete = await shortLastPage.listRoles();
  assert.equal(complete.truncated, false, "a short page without paging.total ends the walk as complete");
  assert.equal(complete.totalKnown, false);
  assert.equal(complete.entries.length, 7);

  const knownTotal = new SplunkApiClient(sampleConfig(), { fetchImpl: pagedFetch(HARDENED, rolesPath, (offset, count) => ({ entry: Array.from({ length: count }, (_, index) => roleEntry(offset + index)), paging: { total: 50, offset } })), retryDelayMs: 0, pageSize: 3, maxEntries: 6 });
  const itemCapped = await knownTotal.listRoles();
  assert.equal(itemCapped.truncated, true);
  assert.equal(itemCapped.totalKnown, true);
  assert.equal(itemCapped.total, 50);
  assert.match(byId(await assessSplunkAccessControl(knownTotal), "SPLUNK-AC-07").summary, /6 of 50 roles/);

  const repeating = new SplunkApiClient(sampleConfig(), { fetchImpl: pagedFetch(HARDENED, rolesPath, () => ({ entry: [roleEntry(0), roleEntry(1), roleEntry(2)], paging: { total: 50, offset: 0 } })), retryDelayMs: 0, pageSize: 3 });
  const stuck = await repeating.listRoles();
  assert.equal(stuck.truncated, true, "a server that ignores offset repeats the page and must not loop or report complete");
  assert.equal(stuck.entries.length, 3);
  const stuckAccess = await assessSplunkAccessControl(repeating);
  assert.notEqual(byId(stuckAccess, "SPLUNK-AC-07").status, "pass");
  assert.match(byId(stuckAccess, "SPLUNK-AC-07").summary, /3 of 50 roles/);
});

test("rule 10: the repeated-page check fingerprints entries by id or by name within acl.app and acl.owner, so same-named namespaced objects across a page boundary are not a repeated page", async () => {
  const savedSearchesPath = "/servicesNS/-/-/saved/searches";
  const search = (app, owner, id) => ({ name: "Errors", content: { is_scheduled: 0, disabled: 0, search: "index=main error" }, acl: { app, owner, sharing: "app", perms: { read: ["*"], write: ["admin"] } }, ...(id ? { id } : {}) });
  const page = (entries, total) => ({ entry: entries, paging: { total, perPage: 1, offset: 0 } });

  const namespaced = new SplunkApiClient(sampleConfig(), { fetchImpl: pagedFetch(HARDENED, savedSearchesPath, (offset) => page(offset === 0 ? [search("search", "admin")] : [search("itsi", "svc_itsi")], 2)), retryDelayMs: 0, pageSize: 1 });
  const twoNamespaces = await namespaced.listSavedSearches();
  assert.equal(twoNamespaces.truncated, false, "a same-named saved search in another app and owner is a different object, not a repeated page");
  assert.equal(twoNamespaces.totalKnown, true);
  assert.equal(twoNamespaces.entries.length, 2);
  assert.deepEqual(twoNamespaces.entries.map((item) => item.acl.app), ["search", "itsi"]);
  const access = await assessSplunkAccessControl(namespaced);
  assert.equal(byId(access, "SPLUNK-AC-11").status, "pass", byId(access, "SPLUNK-AC-11").summary);
  assert.doesNotMatch(byId(access, "SPLUNK-AC-11").summary, /before the walk stopped|partially retrieved/);
  const platform = await assessSplunkPlatformHardening(namespaced);
  assert.equal(byId(platform, "SPLUNK-PLAT-22").status, "pass", byId(platform, "SPLUNK-PLAT-22").summary);

  const byOwner = new SplunkApiClient(sampleConfig(), { fetchImpl: pagedFetch(HARDENED, savedSearchesPath, (offset) => page(offset === 0 ? [search("search", "admin")] : [search("search", "analyst")], 2)), retryDelayMs: 0, pageSize: 1 });
  const twoOwners = await byOwner.listSavedSearches();
  assert.equal(twoOwners.truncated, false, "the same name and app under another owner is a different object");
  assert.equal(twoOwners.entries.length, 2);

  const byId_ = new SplunkApiClient(sampleConfig(), { fetchImpl: pagedFetch(HARDENED, savedSearchesPath, (offset) => page(offset === 0 ? [search("search", "admin", "https://splunk.example.com:8089/servicesNS/admin/search/saved/searches/Errors")] : [search("search", "admin", "https://splunk.example.com:8089/servicesNS/nobody/search/saved/searches/Errors")], 2)), retryDelayMs: 0, pageSize: 1 });
  const twoIds = await byId_.listSavedSearches();
  assert.equal(twoIds.truncated, false, "distinct entry ids are distinct objects even with the same name, app, and owner");
  assert.equal(twoIds.entries.length, 2);
  assert.ok(twoIds.entries.every((item) => item.id === undefined), "the entry id is used for the fingerprint only and is not kept");

  const repeatingByName = new SplunkApiClient(sampleConfig(), { fetchImpl: pagedFetch(HARDENED, savedSearchesPath, () => page([search("search", "admin")], 50)), retryDelayMs: 0, pageSize: 1 });
  const stuckByName = await repeatingByName.listSavedSearches();
  assert.equal(stuckByName.truncated, true, "the same name, app, and owner on two consecutive pages is a repeated page");
  assert.equal(stuckByName.entries.length, 1);

  const repeatingById = new SplunkApiClient(sampleConfig(), { fetchImpl: pagedFetch(HARDENED, savedSearchesPath, () => page([search("search", "admin", "https://splunk.example.com:8089/servicesNS/admin/search/saved/searches/Errors")], 50)), retryDelayMs: 0, pageSize: 1 });
  const stuckById = await repeatingById.listSavedSearches();
  assert.equal(stuckById.truncated, true, "the same entry id on two consecutive pages is a repeated page");
  assert.equal(stuckById.entries.length, 1);
  const stuckAccess = await assessSplunkAccessControl(repeatingById);
  assert.equal(byId(stuckAccess, "SPLUNK-AC-11").status, "warn");
  assert.match(byId(stuckAccess, "SPLUNK-AC-11").summary, /1 of 50 saved searches/);
});

test("foreign-origin next link: splunkd pages by count and offset, so a planted next link or entry id on another origin is never requested and never persisted", async () => {
  const foreignParts = { host: "collector.evil-example.net", path: "/harvest/splunk-token", query: "sink=bearer&offset=100" };
  const foreign = `https://${foreignParts.host}${foreignParts.path}?${foreignParts.query}`;
  const requests = [];
  const fetchImpl = async (input, init = {}) => {
    const url = new URL(typeof input === "string" ? input : input.url);
    requests.push({ url, authorization: new Headers(init.headers ?? {}).get("authorization") });
    if (url.pathname !== "/services/authorization/roles") return jsonResponse({ messages: [{ type: "ERROR", text: "Not Found" }] }, 404);
    const offset = Number(url.searchParams.get("offset") ?? "0");
    const name = offset === 0 ? "admin" : "user";
    const page = [{ name, id: `${foreign}#${name}`, links: { alternate: foreign, next: foreign }, content: { capabilities: ["search"] }, acl: { app: "system", owner: "nobody", sharing: "system" } }];
    return jsonResponse({ links: { next: foreign, alternate: foreign }, entry: page, paging: { total: 2, perPage: 1, offset } });
  };
  const client = new SplunkApiClient(sampleConfig(), { fetchImpl, retryDelayMs: 0, pageSize: 1 });

  const roles = await client.listRoles();
  assert.equal(roles.truncated, false);
  assert.equal(roles.entries.length, 2);
  assert.deepEqual(roles.entries.map((item) => item.name), ["admin", "user"]);
  assert.equal(requests.length, 2);
  assert.ok(requests.every((request) => request.url.origin === "https://splunk.example.com:8089"), "every request went to the configured origin");
  assert.ok(requests.every((request) => request.url.pathname === "/services/authorization/roles"), "the walk never left the declared path");
  assert.deepEqual(requests.map((request) => request.url.searchParams.get("offset")), ["0", "1"], "the walk advances by offset, never by the server-supplied link");
  assert.ok(requests.every((request) => request.authorization === `Bearer ${SAMPLE_TOKEN}`), "the token went to the configured origin only");
  for (const part of Object.values(foreignParts)) assert.ok(!JSON.stringify(roles).includes(part), `the persisted entries carry no ${part}`);
});

test("rule 10: acsListAll reports a repeated ACS page as truncated and an unrecognized payload as unreadable, and control 16 never passes on either", async () => {
  const cloud = { ...HARDENED, "/services/server/info": [entry("server-info", { version: "9.3.2411", product_type: "splunk_cloud", instance_type: "cloud" })] };
  const config = { stack: "acme-stack", acsToken: "acs-jwt" };
  const tokenSpec = (name) => ({ spec: { name, allowedIndexes: ["main"], defaultSourcetype: "aws:firehose", disabled: false, useACK: true } });

  const repeating = { "/inputs/http-event-collectors": { "http-event-collectors": [tokenSpec("a"), tokenSpec("b")] } };
  const repeatingClient = client(cloud, { acs: repeating, pageSize: 2 }, config).client;
  const walk = await repeatingClient.acsListAll("/inputs/http-event-collectors", "http-event-collectors");
  assert.equal(walk.truncated, true);
  assert.equal(walk.items.length, 2);
  const repeated = byId(await assessSplunkDataProtection(repeatingClient), "SPLUNK-DP-16");
  assert.equal(repeated.status, "warn");
  assert.match(repeated.summary, /2 seen, total unknown/);

  const unrecognized = { "/inputs/http-event-collectors": { collectors: [tokenSpec("a")] } };
  const unrecognizedClient = client(cloud, { acs: unrecognized }, config).client;
  await assert.rejects(() => unrecognizedClient.acsListAll("/inputs/http-event-collectors", "http-event-collectors"), /did not include a http-event-collectors list/);
  const unreadableResult = await assessSplunkDataProtection(unrecognizedClient);
  const unreadable = byId(unreadableResult, "SPLUNK-DP-16");
  assert.equal(unreadable.status, "warn", "the readable local HEC view is capped at warn, never pass, when ACS could not be read");
  assert.match(unreadable.summary, /ACS HEC token inventory \(acs:\/inputs\/http-event-collectors\) could not be read/);
  assert.ok(unreadableResult.errors.some((item) => /did not include a http-event-collectors list/.test(item)), unreadableResult.errors.join("\n"));

  const nothingLocal = { ...cloud, "/services/data/inputs/http": undefined };
  delete nothingLocal["/services/data/inputs/http"];
  const bothUnreadable = byId(await assessSplunkDataProtection(client(nothingLocal, { acs: unrecognized }, config).client), "SPLUNK-DP-16");
  assert.equal(bothUnreadable.status, "manual");
  assert.match(bothUnreadable.summary, /acs:\/inputs\/http-event-collectors/);
});

function forbidding(fixture, forbiddenEndpoints, options = {}, configOverrides = {}) {
  const { fetchImpl } = createFetch(fixture, options);
  const forbidden = new Set(forbiddenEndpoints);
  const wrapped = async (input, init) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    const endpoint = url.hostname === "admin.splunk.com" ? `acs:${url.pathname.replace(/^\/[^/]+\/adminconfig\/v2/, "")}` : url.pathname;
    if (forbidden.has(endpoint)) return jsonResponse({ messages: [{ type: "ERROR", text: "You (user=auditor) do not have permission to perform this operation." }] }, 403);
    return fetchImpl(input, init);
  };
  return new SplunkApiClient(sampleConfig(configOverrides), { fetchImpl: wrapped, retryDelayMs: 0 });
}

test("rule 1 corollary: each multi-inventory finding drops below pass and names the secondary inventory when that inventory alone returns 403", async () => {
  const cloud = { ...HARDENED, "/services/server/info": [entry("server-info", { version: "9.3.2411", product_type: "splunk_cloud", instance_type: "cloud" })] };
  const unscheduled = { ...HARDENED, "/servicesNS/-/-/saved/searches": [entry("Errors", { is_scheduled: 0, disabled: 0, search: "index=main error" }, { sharing: "app", owner: "auditor", app: "search", perms: { read: ["*"], write: ["admin"] } })] };
  const acsHealthy = { "/inputs/http-event-collectors": { "http-event-collectors": [{ spec: { name: "firehose", allowedIndexes: ["main"], defaultSourcetype: "aws:firehose", disabled: false, useACK: true } }] } };
  const scenarios = [
    { id: "SPLUNK-AUTH-06", area: assessSplunkAuthentication, fixture: HARDENED, secondary: "/services/authentication/users", expected: "warn", names: /subject-to-user check was skipped because the user list could not be read/ },
    { id: "SPLUNK-DP-15", area: assessSplunkDataProtection, fixture: HARDENED, secondary: "/services/configs/conf-inputs", expected: "warn", names: /inputs\.conf \[SSL\] could not be read/ },
    { id: "SPLUNK-DP-16", area: assessSplunkDataProtection, fixture: cloud, options: { acs: acsHealthy }, config: { stack: "acme-stack", acsToken: "acs-jwt" }, secondary: "acs:/inputs/http-event-collectors", expected: "warn", names: /ACS HEC token inventory \(acs:\/inputs\/http-event-collectors\) could not be read/ },
    { id: "SPLUNK-AUD-18", area: assessSplunkAuditMonitoring, fixture: HARDENED, secondary: "/services/authentication/users", expected: "warn", names: /role assignments could not be enumerated because the user list could not be read/, evidence: (item) => item.users_readable === false },
    { id: "SPLUNK-PLAT-22", area: assessSplunkPlatformHardening, fixture: unscheduled, secondary: "/services/authentication/users", expected: "warn", names: /user list could not be read/ },
    { id: "SPLUNK-PLAT-23", area: assessSplunkPlatformHardening, fixture: HARDENED, secondary: "/services/server/info", expected: "warn", names: /classified as Splunk Enterprise from the URL heuristic/ },
    { id: "SPLUNK-DP-15", area: assessSplunkDataProtection, fixture: HARDENED, secondary: "/services/server/info", expected: "warn", names: /classified as Splunk Enterprise from the URL heuristic/ },
    { id: "SPLUNK-DP-16", area: assessSplunkDataProtection, fixture: HARDENED, secondary: "/services/server/info", expected: "warn", names: /classified as Splunk Enterprise from the URL heuristic/ },
  ];
  for (const scenario of scenarios) {
    const label = `${scenario.id} with ${scenario.secondary} forbidden`;
    const healthy = await scenario.area(forbidding(scenario.fixture, [], scenario.options, scenario.config));
    assert.equal(byId(healthy, scenario.id).status, "pass", `${label}: baseline must be pass so the demotion is meaningful`);
    const result = await scenario.area(forbidding(scenario.fixture, [scenario.secondary], scenario.options, scenario.config));
    const item = byId(result, scenario.id);
    assert.equal(item.status, scenario.expected, `${label}: ${item.summary}`);
    assert.match(item.summary, scenario.names, `${label}: summary names the unreadable inventory`);
    assert.match(item.summary, /403/, `${label}: summary states the cause`);
    const evidenceHolds = scenario.evidence ?? ((evidence) => Array.isArray(evidence.caveats) && evidence.caveats.length >= 1);
    assert.ok(evidenceHolds(item.evidence), `${label}: evidence records the unreadable inventory`);
  }

  const noUsers = await assessSplunkAuthentication(forbidding(HARDENED, ["/services/authentication/users"]));
  assert.equal(byId(noUsers, "SPLUNK-AUTH-06").evidence.users_readable, false);
  assert.match(byId(noUsers, "SPLUNK-AUTH-06").summary, /whether every subject maps to a known user was not checked/);
  const noUsersAudit = await assessSplunkAuditMonitoring(forbidding(HARDENED, ["/services/authentication/users"]));
  assert.equal(byId(noUsersAudit, "SPLUNK-AUD-18").evidence.users_with_delete_roles, null);
  assert.doesNotMatch(byId(noUsersAudit, "SPLUNK-AUD-18").summary, /unassigned admin-like roles/);

  const noServerInfo = forbidding(HARDENED, ["/services/server/info"]);
  const data = await assessSplunkDataProtection(noServerInfo);
  const platform = await assessSplunkPlatformHardening(noServerInfo);
  for (const [result, id] of [[data, "SPLUNK-DP-14"], [platform, "SPLUNK-PLAT-19"]]) {
    assert.equal(byId(result, id).status, "manual", id);
    assert.match(byId(result, id).summary, /URL heuristic .*403/, `${id}: manual verdict names the deployment guess`);
  }
  const cloudNoServerInfo = forbidding(cloud, ["/services/server/info"], { acs: acsHealthy }, { url: "https://acme.splunkcloud.com:8089", stack: "acme-stack", acsToken: "acs-jwt" });
  const cloudData = await assessSplunkDataProtection(cloudNoServerInfo);
  assert.equal(byId(cloudData, "SPLUNK-DP-16").status, "warn");
  assert.match(byId(cloudData, "SPLUNK-DP-16").summary, /classified as Splunk Cloud from the URL heuristic \(the URL matches \*\.splunkcloud\.com\)/);
  assert.equal(byId(cloudData, "SPLUNK-DP-16").evidence.source, "acs:/inputs/http-event-collectors");
});

/** Canaries planted in the failing surface's body, each inside a carrier: random alphanumerics. */
const SURFACE = { bearer: "uWQ2n4KZw5xqJTLmL8aPbeVM", session: "8unXXkWgbbr7qQW5V2Hwk6TxNVmsW85e", apiKey: "kpQxJQTYthwEcws2ZMA2rZKS4MGBhLvK", urlToken: "8fyNDV2sTJnfNYZdjFVkhDGCDd4gg4ML" };
const SURFACE_CANARIES = Object.values(SURFACE);
const SURFACE_HTML_BODY = `<html><body><h1>502 Bad Gateway</h1><p>Authorization: Bearer ${SURFACE.bearer}</p><p>Set-Cookie: JSESSIONID=${SURFACE.session}; Path=/</p><p>api_key=${SURFACE.apiKey}</p><p>Retry at https://api.example.com/v1/x?token=${SURFACE.urlToken} later.</p></body></html>`;
const SURFACE_JSON_BODY = {
  messages: [{ type: "ERROR", text: `Denied while fetching https://api.example.com/v1/x?token=${SURFACE.urlToken} for this key; Authorization: Bearer ${SURFACE.bearer}; api_key=${SURFACE.apiKey}; session_id=${SURFACE.session}` }],
};

function endpointOf(url) {
  return url.hostname === "admin.splunk.com" ? `acs:${url.pathname.replace(/^\/[^/]+\/adminconfig\/v2/, "")}` : url.pathname;
}

/** Like forbidding(), but the failing endpoint answers with a 502 HTML page or a 403 JSON body that both carry the canaries; records every endpoint requested. */
function failingWith(fixture, endpoint, variant, options = {}, configOverrides = {}) {
  const { fetchImpl } = createFetch(fixture, options);
  const seen = [];
  const wrapped = async (input, init) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    const target = endpointOf(url);
    seen.push(target);
    if (endpoint !== undefined && target === endpoint) {
      return variant === "html"
        ? new Response(SURFACE_HTML_BODY, { status: 502, statusText: "Bad Gateway", headers: { "content-type": "text/html; charset=utf-8" } })
        : new Response(JSON.stringify(SURFACE_JSON_BODY), { status: 403, statusText: "Forbidden", headers: { "content-type": "application/json" } });
    }
    return fetchImpl(input, init);
  };
  return { client: new SplunkApiClient(sampleConfig(configOverrides), { fetchImpl: wrapped, retryDelayMs: 0, retryAttempts: 1 }), seen };
}

test("rule 9: every Splunk surface that fails with a 502 HTML page or a JSON error embedding a token URL records only a scrubbed error, on every output", async () => {
  const cloud = { ...HARDENED, "/services/server/info": [entry("server-info", { version: "9.3.2411", product_type: "splunk_cloud", instance_type: "cloud" })] };
  const acs = {
    "/inputs/http-event-collectors": { "http-event-collectors": [{ spec: { name: "firehose", allowedIndexes: ["main"], defaultSourcetype: "aws:firehose", disabled: false, useACK: true } }] },
    "/access/search-api/ipallowlists": { subnets: ["10.0.0.0/8"] },
    "/access/hec/ipallowlists": { subnets: ["10.0.0.0/8"] },
    "/access/s2s/ipallowlists": { subnets: ["10.0.0.0/8"] },
    "/access/search-ui/ipallowlists": { subnets: ["10.0.0.0/8"] },
  };
  const acsConfig = { url: "https://acme.splunkcloud.com:8089", stack: "acme-stack", acsToken: "acs-jwt-token-value" };
  const base = createTempBase("grclanker-splunk-surface-canaries-");

  const discovery = failingWith(cloud, undefined, "html", { acs }, acsConfig);
  const healthyAccess = await checkSplunkAccess(discovery.client);
  assert.equal(healthyAccess.surfaces.filter((surface) => surface.status === "not_readable").length, 0, "the healthy fixture serves every probe");
  await runAllAssessments(discovery.client);
  const endpoints = [...new Set(discovery.seen)].filter((endpoint) => endpoint !== "/services/auth/login");
  assert.ok(endpoints.length >= 18, `every access check probe, collector, ACS path, and the audit search are discovered (${endpoints.length})`);
  assertFixtureFreeOfCanaryWindows(
    JSON.stringify({ cloud, acs, config: sampleConfig(acsConfig), bodies: [SURFACE_HTML_BODY, SURFACE_JSON_BODY] }),
    SURFACE_CANARIES,
    "surface canary fixture",
  );
  const secrets = leakWindows(SURFACE_CANARIES);

  for (const endpoint of endpoints) {
    for (const variant of ["html", "json"]) {
      const label = `${endpoint} (${variant})`;
      const access = await checkSplunkAccess(failingWith(cloud, endpoint, variant, { acs }, acsConfig).client);
      const results = await runAllAssessments(failingWith(cloud, endpoint, variant, { acs }, acsConfig).client);
      const exported = await exportSplunkAuditBundle(failingWith(cloud, endpoint, variant, { acs }, acsConfig).client, sampleConfig(acsConfig), base);
      const files = readBundleFiles(exported.outputDir);

      const outputs = new Map([
        [`${label} check_access`, JSON.stringify(access)],
        ...results.map((result) => [`${label} assess ${result.title}`, JSON.stringify(result)]),
        ...[...files].map(([name, content]) => [`${label} bundle ${name}`, content]),
        ...[...readZipEntries(exported.zipPath)].map(([name, content]) => [`${label} zip ${name}`, content]),
      ]);
      assertSecretsAbsent(assert, outputs, secrets, label);

      // Wherever the error lands (access surface, errors array, a finding
      // summary quoting the cause, _errors.log), every string derived from
      // the 502 carries the status-and-length note and every string derived
      // from the JSON message keeps only scheme, host, and path of the URL.
      // The markdown tables truncate columns by design, so the note count is
      // taken over the structured outputs and the error log.
      const serialized = [...outputs.values()].join("\n");
      const structured = [...outputs].filter(([name]) => !name.endsWith(".md")).map(([, content]) => content).join("\n");
      if (variant === "html") {
        const statusMentions = structured.match(/502 Bad Gateway\)/g) ?? [];
        const noted = structured.match(/502 Bad Gateway\): non-JSON body \(text\/html, \d+ bytes\)/g) ?? [];
        assert.ok(noted.length >= 1, `${label}: the failing surface is recorded with the status-and-length note`);
        assert.equal(statusMentions.length, noted.length, `${label}: every error string derived from the 502 carries the note`);
      } else {
        assert.match(serialized, /\(403/, `${label}: the failing surface is recorded as denied`);
        for (const mention of serialized.match(/https:\/\/api\.example\.com[^\s"\\)]*/g) ?? []) {
          assert.equal(mention, "https://api.example.com/v1/x?[REDACTED]", `${label}: the URL keeps scheme, host, and path, and its query collapses to a marker`);
        }
        assert.doesNotMatch(serialized, /Authorization: Bearer (?!\[REDACTED\])/, `${label}: no authorization value survives`);
      }
    }
  }

  const noContext = await checkSplunkAccess(failingWith(cloud, "/services/authentication/current-context", "json", { acs }, acsConfig).client);
  assert.equal(noContext.capabilities, null, "an unread capability list renders null, not []");
  assert.match(noContext.notes[1], /an unread capability list/);
});

/** Like forbidding(), but records method, endpoint, and status for every request the fixture answered. */
function recording(fixture, deniedEndpoints, options = {}, configOverrides = {}) {
  const { fetchImpl } = createFetch(fixture, options);
  const denied = new Set(deniedEndpoints);
  const requests = [];
  const wrapped = async (input, init = {}) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    const endpoint = endpointOf(url);
    const response = denied.has(endpoint)
      ? jsonResponse({ messages: [{ type: "ERROR", text: "You (user=auditor) do not have permission to perform this operation." }] }, 403)
      : await fetchImpl(input, init);
    requests.push({ method: init.method ?? "GET", endpoint, status: response.status });
    return response;
  };
  return { client: new SplunkApiClient(sampleConfig(configOverrides), { fetchImpl: wrapped, retryDelayMs: 0, retryAttempts: 1 }), requests };
}

const MENTIONED_STATUS_PATTERNS = [
  /\((\d{3})(?: [A-Za-z][A-Za-z ]*)?\)/g,
  /"(?:http_status|httpStatus|status)":\s*(\d{3})\b/g,
  /\b(?:HTTP|status|returned)\s+(\d{3})\b/gi,
];
const MENTIONED_ENDPOINT_PATTERN = /(?:acs:)?\/services(?:NS)?\/[A-Za-z0-9_./:{}*-]*[A-Za-z0-9*}]/g;

/**
 * Every 4xx or 5xx status code and every REST or ACS path named anywhere in
 * the outputs must belong to a request the fixture actually served; a code or
 * endpoint absent from the request log is a claim the run did not observe.
 */
function assertOutputsNameOnlyObservedRequests(outputs, requests, label) {
  const observedStatuses = new Set(requests.map((request) => request.status));
  const observedEndpoints = [...new Set(requests.map((request) => request.endpoint))];
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
      const template = new RegExp(`^${mention.replace(/[.+?^$()|[\]\\]/g, "\\$&").replace(/\{[^}]*\}|\*/g, "[^/]*")}$`);
      assert.ok(observedEndpoints.some((endpoint) => template.test(endpoint)), `${label} ${name}: names endpoint ${mention} but the run requested only ${observedEndpoints.join(", ")}`);
    }
  }
}

function splunkOutputs(access, results, exported) {
  return new Map([
    ["check_access", JSON.stringify(access)],
    ...results.map((result) => [`assess ${result.title}`, JSON.stringify(result)]),
    ...[...readBundleFiles(exported.outputDir)].map(([name, content]) => [`bundle ${name}`, content]),
  ]);
}

// Every core_data snapshot the export writes and the endpoint it reads.
const SPLUNK_SNAPSHOTS = [
  ["server_info", "/services/server/info"],
  ["current_context", "/services/authentication/current-context"],
  ["users", "/services/authentication/users"],
  ["roles", "/services/authorization/roles"],
  ["tokens", "/services/authorization/tokens"],
  ["conf_authentication", "/services/configs/conf-authentication"],
  ["conf_server", "/services/configs/conf-server"],
  ["conf_web", "/services/configs/conf-web"],
  ["conf_outputs", "/services/configs/conf-outputs"],
  ["conf_inputs", "/services/configs/conf-inputs"],
  ["indexes", "/services/data/indexes"],
  ["hec_inputs", "/services/data/inputs/http"],
  ["saved_searches", "/servicesNS/-/-/saved/searches"],
  ["apps", "/services/apps/local"],
  ["kv_collections", "/servicesNS/-/-/storage/collections/config"],
  ["tcp_cooked_inputs", "/services/data/inputs/tcp/cooked"],
];

test("collection status: a denied snapshot is written to core_data as a not-collected marker naming the real endpoint and status, access surfaces render null counts for failed probes, a readable empty list stays [], and every status code and endpoint named in any output was actually requested", async () => {
  const cloud = { ...HARDENED, "/services/server/info": [entry("server-info", { version: "9.3.2411", product_type: "splunk_cloud", instance_type: "cloud" })] };
  const acs = {
    "/inputs/http-event-collectors": { "http-event-collectors": [{ spec: { name: "firehose", allowedIndexes: ["main"], defaultSourcetype: "aws:firehose", disabled: false, useACK: true } }] },
    "/access/search-api/ipallowlists": { subnets: ["10.0.0.0/8"] },
    "/access/hec/ipallowlists": { subnets: ["10.0.0.0/8"] },
    "/access/s2s/ipallowlists": { subnets: ["10.0.0.0/8"] },
    "/access/search-ui/ipallowlists": { subnets: ["10.0.0.0/8"] },
  };
  const acsConfig = { url: "https://acme.splunkcloud.com:8089", stack: "acme-stack", acsToken: "acs-jwt-token-value" };
  const base = createTempBase("grclanker-splunk-denied-markers-");

  for (const [name, endpoint] of SPLUNK_SNAPSHOTS) {
    const { client: api, requests } = recording(cloud, [endpoint], { acs }, acsConfig);
    const access = await checkSplunkAccess(api);
    const results = await runAllAssessments(api);
    const exported = await exportSplunkAuditBundle(api, sampleConfig(acsConfig), join(base, name));

    const file = JSON.parse(readFileSync(join(exported.outputDir, "core_data", `${name}.json`), "utf8"));
    assert.ok(!Array.isArray(file) && !Array.isArray(file.entries), `${name}: a denied snapshot is never written as an array`);
    assert.deepEqual(file, { collected: false, status: 403, endpoint, error: file.error }, `${name}: core_data carries the not-collected marker`);
    assert.match(file.error, /failed \(403\)/, `${name}: the marker error names the observed status`);
    assert.match(readFileSync(join(exported.outputDir, "_errors.log"), "utf8"), new RegExp(`^\\[core_data/${name}\\] Splunk request to `, "m"), `${name}: the _errors.log line is bracket-prefixed, so the dataset name never forms a carrier with the Splunk scheme word`);

    const surface = access.surfaces.find((item) => item.name === name);
    if (surface) {
      assert.equal(surface.status, "not_readable");
      assert.equal(surface.endpoint, endpoint);
      assert.equal(surface.count, null, `${name}: count is null, not 0, when the probe failed`);
      assert.equal(surface.total, null, `${name}: total is null when the probe failed`);
      assert.equal(surface.truncated, null, `${name}: truncated is null, not false, when the probe failed`);
      assert.equal(surface.httpStatus, 403);
    }
    for (const item of results.flatMap((result) => result.findings).filter((finding) => finding.evidence.endpoint !== undefined && finding.evidence.http_status === 403)) {
      assert.ok(requests.some((request) => request.endpoint === item.evidence.endpoint && request.status === 403), `${name}: ${item.id} names ${item.evidence.endpoint} as denied but no such request was observed`);
    }

    assertOutputsNameOnlyObservedRequests(splunkOutputs(access, results, exported), requests, `${name} denied`);
  }

  const emptyTokens = { ...cloud, "/services/authorization/tokens": [] };
  const { client: api, requests } = recording(emptyTokens, [], { acs }, acsConfig);
  const access = await checkSplunkAccess(api);
  const results = await runAllAssessments(api);
  const exported = await exportSplunkAuditBundle(api, sampleConfig(acsConfig), join(base, "empty"));
  const tokens = JSON.parse(readFileSync(join(exported.outputDir, "core_data", "tokens.json"), "utf8"));
  assert.deepEqual(tokens.entries, [], "a readable empty list stays []");
  assert.equal(tokens.total, 0);
  assert.equal(tokens.truncated, false);
  assert.equal(tokens.totalKnown, true);
  assert.equal(tokens.collected, undefined);
  const tokenSurface = access.surfaces.find((item) => item.name === "tokens");
  assert.deepEqual({ count: tokenSurface.count, total: tokenSurface.total, truncated: tokenSurface.truncated, httpStatus: tokenSurface.httpStatus }, { count: 0, total: 0, truncated: false, httpStatus: null });
  for (const surface of access.surfaces) {
    assert.equal(surface.status, "readable", `${surface.name} is readable on the healthy fixture`);
    assert.equal(typeof surface.count, "number");
    assert.equal(surface.httpStatus, null);
  }
  assertOutputsNameOnlyObservedRequests(splunkOutputs(access, results, exported), requests, "healthy with an empty token list");
});

test("collection status: leaves derived from a denied snapshot render null, never [] or 0 (DP-13 web_sslVersions, PLAT-23 ssl_stanza, PLAT-22 admin-owner counts, deployment serverRoles)", async () => {
  const base = createTempBase("grclanker-splunk-null-leaves-");
  const unscheduled = { ...HARDENED, "/servicesNS/-/-/saved/searches": [entry("Errors", { is_scheduled: 1, disabled: 0, search: "index=main error", dispatchAs: "owner", "dispatch.earliest_time": "-24h" }, { sharing: "app", owner: "auditor", app: "search", perms: { read: ["*"], write: ["admin"] } })] };

  const webDenied = await assessSplunkDataProtection(forbidding(HARDENED, ["/services/configs/conf-web"]));
  const tls = byId(webDenied, "SPLUNK-DP-13");
  assert.equal(tls.evidence.web_sslVersions, null, "web.conf sslVersions is unknown when conf-web was denied");
  assert.equal(tls.evidence.enableSplunkWebSSL, null);
  assert.ok(Array.isArray(tls.evidence.sslVersions) && tls.evidence.sslVersions.length > 0, "server.conf sslVersions were read and stay a real list");
  assert.match(tls.summary, /web\.conf unreadable \(.*403/);
  const webReadable = byId(await assessSplunkDataProtection(forbidding(HARDENED, [])), "SPLUNK-DP-13");
  assert.deepEqual(webReadable.evidence.web_sslVersions, ["tls1.2"], "a readable web.conf keeps the list");

  const inputsDenied = await assessSplunkPlatformHardening(forbidding(HARDENED, ["/services/configs/conf-inputs"]));
  const s2s = byId(inputsDenied, "SPLUNK-PLAT-23");
  assert.equal(s2s.evidence.inputs_conf_readable, false);
  assert.equal(s2s.evidence.ssl_stanza, null, "the [SSL] stanza is unknown, not an empty stanza, when inputs.conf was denied");
  assert.equal(s2s.evidence.ssl_stanza_present, null);
  assert.equal(s2s.status, "manual");
  const inputsReadable = byId(await assessSplunkPlatformHardening(forbidding(HARDENED, [])), "SPLUNK-PLAT-23");
  assert.equal(typeof inputsReadable.evidence.ssl_stanza_present, "boolean");
  assert.ok(Array.isArray(inputsReadable.evidence.ssl_stanza.sslVersions));

  const usersDenied = await assessSplunkPlatformHardening(forbidding(unscheduled, ["/services/authentication/users"]));
  const dispatch = byId(usersDenied, "SPLUNK-PLAT-22");
  assert.equal(dispatch.status, "warn");
  assert.equal(dispatch.evidence.owner_dispatched_by_admins, null, "admin ownership is unknown without the user list");
  assert.equal(dispatch.evidence.risky_scheduled_searches, null);
  assert.equal(dispatch.evidence.scheduled, 1, "the schedule flag was read from the saved search itself");
  assert.match(dispatch.evidence.owner_roles_note, /^owner roles were not verified because the user list could not be read \(.*403/);
  assert.deepEqual(dispatch.evidence.unverified_owner_searches, [], "the bounded search is not listed as unverified-risky");
  assert.match(dispatch.summary, /^Owner roles of the 1 scheduled searches could not be verified because the user list could not be read \(.*403.*\); none combine all indexes with an unbounded time range\.$/);
  assert.doesNotMatch(dispatch.summary, /\b0 of 1\b/);
  const usersReadable = byId(await assessSplunkPlatformHardening(forbidding(unscheduled, [])), "SPLUNK-PLAT-22");
  assert.equal(usersReadable.evidence.owner_dispatched_by_admins, 0);
  assert.deepEqual(usersReadable.evidence.risky_scheduled_searches, []);
  assert.equal(usersReadable.evidence.owner_roles_note, undefined);
  const riskyUnverified = { ...unscheduled, "/servicesNS/-/-/saved/searches": [entry("Everything", { is_scheduled: 1, disabled: 0, search: "error", dispatchAs: "owner", "dispatch.earliest_time": "0" }, { sharing: "app", owner: "auditor", app: "search", perms: { read: ["*"], write: ["admin"] } })] };
  const unverifiedFail = byId(await assessSplunkPlatformHardening(forbidding(riskyUnverified, ["/services/authentication/users"])), "SPLUNK-PLAT-22");
  assert.equal(unverifiedFail.status, "fail");
  assert.match(unverifiedFail.summary, /run as their \(unverified\) owner across all indexes with no time bound\. Owner roles were not verified because the user list could not be read/);
  assert.equal(unverifiedFail.evidence.risky_scheduled_searches, null);
  assert.deepEqual(unverifiedFail.evidence.unverified_owner_searches.map((item) => item.name), ["Everything"], "the fail stays grounded in the searches that were read");

  const { client: api, requests } = recording(HARDENED, ["/services/server/info"]);
  const access = await checkSplunkAccess(api);
  assert.equal(access.deployment.serverRoles, null, "server roles are unknown, not [], when server/info was denied");
  assert.equal(access.deployment.source, "unknown", "a non-splunkcloud.com URL gives no deployment source when server/info was denied");
  const exported = await exportSplunkAuditBundle(api, sampleConfig(), join(base, "server-info-denied"));
  const accessFile = JSON.parse(readFileSync(join(exported.outputDir, "core_data", "access_check.json"), "utf8"));
  assert.equal(accessFile.deployment.serverRoles, null);
  assert.ok(requests.some((request) => request.endpoint === "/services/server/info" && request.status === 403));
  const healthyAccess = await checkSplunkAccess(recording(HARDENED, []).client);
  assert.ok(Array.isArray(healthyAccess.deployment.serverRoles), "a readable server/info keeps the role list");
});

test("resolveSecureOutputPath rejects traversal and symlink parents", () => {
  const base = createTempBase("grclanker-splunk-path-");
  const outside = createTempBase("grclanker-splunk-outside-");
  symlinkSync(outside, join(base, "linked"), "dir");
  assert.throws(() => resolveSecureOutputPath(base, "../escape"), /Refusing to write outside/);
  assert.throws(() => resolveSecureOutputPath(base, "linked/file.txt"), /symlinked parent directory/);
  assert.match(resolveSecureOutputPath(base, join("compliance", "safe.md")), /compliance\/safe\.md$/);
});

test("Splunk tools are registered under the Splunk group", () => {
  const tools = getRegisteredToolSummaries().filter((tool) => tool.name.startsWith("splunk_"));
  assert.deepEqual(tools.map((tool) => tool.name).sort(), [
    "splunk_assess_access_control",
    "splunk_assess_audit_monitoring",
    "splunk_assess_authentication",
    "splunk_assess_data_protection",
    "splunk_assess_platform_hardening",
    "splunk_check_access",
    "splunk_export_audit_bundle",
  ]);
  assert.ok(tools.every((tool) => tool.group === "Splunk" && tool.kind === "domain"));
  assert.ok(tools.every((tool) => tool.parameterSummaries.some((parameter) => parameter.name === "url")));
});

test("rule 9: scrub boundary: a name-shaped value stays bare in prose and is removed inside every carrier, as a configured secret in every encoding, and whenever it has a real token shape", () => {
  const name = "prod-us-east-2026";
  const bare = `Splunk request failed for tenant ${name} owned by sess-canary-COOKIE-31415926535897`;
  assert.equal(scrubErrorText(bare), bare, "a name-shaped value bare in prose is indistinguishable from a resource name");
  assert.equal(scrubErrorText(bare, [name]), "Splunk request failed for tenant [REDACTED] owned by sess-canary-COOKIE-31415926535897", "the same value registered as a configured secret is removed");
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
    [`Authorization: Splunk '${name}' rejected`, "Authorization: Splunk '[REDACTED]' rejected"],
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
  const gatewayBody = (line) => `Splunk request to /services/authentication/users failed (502 Bad Gateway): <html><body><h1>502 Bad Gateway</h1><p>upstream headers: ${line}</p></body></html>`;
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
    (value, separator) => `Authorization${separator}Splunk ${value}`,
    (value, separator) => `Proxy-Authorization${separator}Bearer ${value}`,
    (value, separator, raw, quote) => `Authorization${separator}${quote}Bearer ${raw}${quote}`,
  ];
  const quotedFrames = [
    (line) => line,
    (line) => `Splunk request to /services/authentication/users failed (401 Unauthorized): the request carried ${line} and was rejected`,
    (line) => `{"messages":[{"type":"ERROR","text":"Invalid header: ${line}"}]}`,
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
  for (const header of SPLUNK_QUOTED_HEADERS_KEPT) {
    assert.equal(scrubErrorText(header), header, `must keep quoted header: ${header}`);
    const sentence = `Splunk request to /services/authentication/users failed (400 Bad Request): the response carried ${header}`;
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
    scrubErrorText("failed for /api/v1/users/aB3xZ9qL2mN8pR4tV7wY1/factors from /tmp/run-9b6rz9m4l55zg7/config.json and https://hooks.example.com/services/T0/aB3xZ9qL2mN8pR4tV7wY1"),
    "failed for /api/v1/users/aB3xZ9qL2mN8pR4tV7wY1/factors from /tmp/run-9b6rz9m4l55zg7/config.json and https://hooks.example.com/services/T0/[REDACTED]",
    "a token-shaped segment of a bare request target or file path is an identifier the run named; inside a URL it is a webhook token",
  );
  assert.equal(
    scrubErrorText("key wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY beside /servicesNS/nobody/search/saved/searches/Errors/acl"),
    "key [REDACTED] beside /servicesNS/nobody/search/saved/searches/Errors/acl",
    "a random 40-character base64 run is an AWS secret access key; a bare path of word segments is a request target",
  );
  assert.equal(
    scrubErrorText("casing frozenTimePeriodInSecs maxTotalDataSizeMB externalTwoFactorAuthVendor QaZwSxEdCrFvTgByHn aBcDeFgHiJkLmNoPqRs ABcdEFghIJklMNopQR"),
    "casing frozenTimePeriodInSecs maxTotalDataSizeMB externalTwoFactorAuthVendor [REDACTED] [REDACTED] [REDACTED]",
    "camelCase identifiers whose words average three or more letters stay; alternating capitalized fragments and doubled-case runs are tokens",
  );
  assert.equal(
    scrubErrorText("stanza [http://hec] httpEventCollectorToken=4f9c2b7e1d3a4c5b8e6f7a9b0c1d2e3f and sslPassword=hunter2x9 rejected"),
    "stanza [http://hec] httpEventCollectorToken=[REDACTED] and sslPassword=[REDACTED] rejected",
    "a credential-named key keeps its name once its value is replaced; the trailing = is not read as base64 padding",
  );

  // Must-keep table (addendum 7): every identifying string a summary may carry survives alone and inside a realistic sentence.
  for (const value of SPLUNK_MUST_KEEP) {
    assert.equal(scrubErrorText(value), value, `must keep bare: ${value}`);
    for (const sentence of splunkSummarySentences(value)) assert.equal(scrubErrorText(sentence), sentence, `must keep in a sentence: ${sentence}`);
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
    "SPLUNK_PASSWORD", "SPLUNK_TOKEN", "SPLUNK_ACS_TOKEN", "OKTA_CLIENT_TOKEN", "SUMOLOGIC_ACCESS_KEY", "VERACODE_API_KEY_SECRET", "SNOWFLAKE_PRIVATE_KEY_PASSPHRASE",
  ];
  for (const key of credentialKeys) {
    for (const value of PAIR_VALUE_SHAPES) {
      for (const form of PAIR_FORMS) {
        const pair = form(key, value);
        for (const [frameName, frame] of PAIR_FRAMES) {
          // The JSON forms inside the double-escaped raw member sit at quote depth 2; the quote-aware reader (item F) covers them.
          if (frameName === "502-json-raw" && pair.startsWith("{")) continue;
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

/** Every endpoint the Splunk client requests (splunkd REST, ACS, and the login and search job paths). */
const SPLUNK_REQUESTED_PATHS = [
  "/services/server/info",
  "/services/authentication/current-context",
  "/services/authentication/users",
  "/services/authentication/providers/LDAP",
  "/services/authentication/providers/SAML",
  "/services/authorization/roles",
  "/services/authorization/tokens",
  "/services/auth/login",
  "/services/admin/Duo-MFA",
  "/services/admin/Rsa-MFA",
  "/services/apps/local",
  "/services/configs/conf-authentication",
  "/services/configs/conf-audit",
  "/services/configs/conf-inputs",
  "/services/configs/conf-outputs",
  "/services/configs/conf-server",
  "/services/configs/conf-web",
  "/services/data/indexes",
  "/services/data/inputs/http",
  "/services/data/inputs/tcp/cooked",
  "/services/search/jobs",
  "/servicesNS/-/-/data/lookup-table-files",
  "/servicesNS/-/-/saved/searches",
  "/servicesNS/-/-/storage/collections/config",
  "/services/authorization/roles?output_mode=json&count=100&offset=200",
  "acs:/inputs/http-event-collectors",
  "acs:/access/search-api/ipallowlists",
  "acs:/access/hec/ipallowlists",
  "acs:/access/s2s/ipallowlists",
  "acs:/access/search-ui/ipallowlists",
  "/acme-stack/adminconfig/v2/inputs/http-event-collectors",
];
/** Quoted non-credential headers (the Codex P1 must-keep rows): a quote alone never makes a header value a credential. */
const SPLUNK_QUOTED_HEADERS_KEPT = [
  'Content-Type: "application/json"',
  'Content-Type:"application/json; charset=utf-8"',
  "Accept: 'application/json'",
  'Content-Length: "42"',
  'X-Request-Id: "3f2b6a1e-9c4d-4e8f-b1a2-6d7c8e9f0a1b"',
  'X-Rate-Limit-Remaining: "599"',
  'User-Agent: "grclanker-cli/0.4.1"',
  'Cache-Control: "no-store"',
  'Location: "/services/authentication/users"',
  '{"Content-Type": "application/json", "Accept": "application/json"}',
  '{\\"Content-Type\\": \\"application/json\\", \\"Accept\\": \\"application/json\\"}',
];

const SPLUNK_MUST_KEEP = [
  ...SPLUNK_REQUESTED_PATHS,
  ...SPLUNK_REQUESTED_PATHS.map((path) => `GET ${path}`),
  "https://splunk.example.com:8089",
  "https://acme.splunkcloud.com:8089",
  "acme.splunkcloud.com",
  "https://admin.splunk.com",
  "acme-stack",
  "prod-us-east-2026",
  "splunk-prod-idx-01.example.gov:8089",
  "tokens",
  "core_data/tokens",
  "[tokens]",
  "[core_data/tokens]",
  "hec-inputs",
  "acs-hec",
  "conf-authentication",
  "saved-searches",
  "lookup-table-files",
  "kv-collections",
  "tcp-cooked-inputs",
  "server/info",
  "authType",
  "SAML",
  "LDAP",
  "Scripted",
  "ProxySSO",
  "externalTwoFactorAuthVendor",
  "frozenTimePeriodInSecs",
  "httpEventCollectorToken",
  "maxTotalDataSizeMB",
  "sslVerifyServerCert",
  "enableSplunkdSSL",
  "allowRemoteLogin",
  "minPasswordLength",
  "InvalidAuthenticationToken",
  "Duo",
  "RSA",
  "admin",
  "sc_admin",
  "auditor",
  "svc-audit-reader",
  "jane.doe@acme-prod.example.gov",
  "nobody",
  "splunk-system-user",
  "power",
  "can_delete",
  "delete_by_keyword",
  "admin_all_objects",
  "srchIndexesAllowed",
  "index=main error",
  "_audit",
  "_internal",
  "[splunktcp-ssl:9997]",
  "[SSL]",
  "[tcpout]",
  "[auditTrail]",
  "requireClientCert=1",
  "sslVersions=tls1.2",
  "useSSL=false",
  "200 OK",
  "400 Bad Request",
  "401 Unauthorized",
  "403 Forbidden",
  "404 Not Found",
  "429 Too Many Requests",
  "500 Internal Server Error",
  "502 Bad Gateway",
  "503 Service Unavailable",
  ...SPLUNK_CONTROLS.map((control) => control.id),
  "environment-url",
  "environment-token",
  "config-file-url",
  "arguments-url",
  "/home/auditor/.splunk/grclanker.json",
  "INVALID_JSON",
  "EACCES",
  "ENOTDIR",
  "EISDIR",
];

/** Realistic Splunk summary and error sentences with an identifying value in the slot such a value occupies. */
function splunkSummarySentences(value) {
  return [
    `Splunk request to ${value} failed (403 Forbidden): the credential lacks the required capability`,
    `Unknown: ${value} could not be evaluated because the credential lacks the required capability (403). Collect manually: ${value} from each indexer.`,
    `Not collected: ${value} was not requested because ${value} could not be read (Splunk request to ${value} failed (403 Forbidden)).`,
    `Splunk Cloud Platform 9.3.2411 at ${value} (bearer token auth, TLS verification on).`,
    `Authenticated as ${value} with 42 capabilities.`,
    `[${value}] Splunk request to ${value} failed (502 Bad Gateway): non-JSON body (text/html, 5120 bytes)`,
    `[core_data/${value}] Splunk request to ${value} failed (403 Forbidden): the credential lacks the required capability`,
    `authType is ${value} with provider stanza ${value} present, but the provider endpoint could not be read (the credential lacks the required capability (403)); verify the provider is active.`,
  ];
}

/** Every fixed text the Splunk integration emits, with sample paths and names, passes its scrubber unchanged (GWS note 1). */
const SPLUNK_FIXED_TEXTS = [
  "Unable to read Splunk config file /home/auditor/.splunk/grclanker.json (EACCES)",
  "Unable to read Splunk config file /home/auditor/.splunk/grclanker.json (UNREADABLE)",
  "Unable to parse Splunk config file: invalid JSON in /home/auditor/.splunk/grclanker.json at line 4, column 1 (INVALID_JSON)",
  "Unable to parse Splunk config file: invalid JSON in /home/auditor/.splunk/grclanker.json (INVALID_JSON)",
  "SPLUNK_URL, a url argument, or a config file url is required (for example https://splunk.example.com:8089).",
  "Provide SPLUNK_TOKEN or both SPLUNK_USERNAME and SPLUNK_PASSWORD (arguments or config file also work).",
  "Splunk session login requires SPLUNK_USERNAME and SPLUNK_PASSWORD.",
  "Splunk login response did not include a sessionKey.",
  "Splunk request to /services/authorization/roles failed (403 Forbidden): the credential lacks the required capability",
  "Splunk request to /services/authorization/roles failed (401 Unauthorized): call not properly authenticated",
  "[tokens] Splunk request to /services/authorization/tokens failed (403 Forbidden): the credential lacks the required capability",
  "[core_data/tokens] Splunk request to /services/authorization/tokens failed (403 Forbidden): the credential lacks the required capability",
  "[core_data/current_context] Splunk request to /services/authentication/current-context failed (401 Unauthorized): call not properly authenticated",
  "[acs-hec] Splunk request to acs:/inputs/http-event-collectors failed (403 Forbidden): the credential lacks the required capability",
  "authType is Splunk: local Splunk authentication is the primary method; SAML or LDAP is not enforced.",
  "authType is Scripted: enforcement depends on the external proxy or script; collect the upstream identity provider configuration manually.",
  "authType is SAML but no SAML provider stanza was readable in authentication.conf or the provider endpoint, so enforcement cannot be confirmed.",
  "authType is LDAP but 1 referenced provider stanza(s) are disabled.",
  "externalTwoFactorAuthVendor is Duo and the Duo-MFA configuration is present.",
  "externalTwoFactorAuthVendor is RSA but no Rsa-MFA configuration stanza exists.",
  "authType is SAML with active provider okta; 2 local Splunk-type accounts remain.",
  "authType is SAML with no Splunk-native MFA vendor: MFA is enforced by the identity provider. Collect the IdP MFA policy for the Splunk application manually.",
  "No externalTwoFactorAuthVendor (Duo or RSA) is configured and authType Splunk does not delegate MFA to an identity provider.",
  "Splunk request to /servicesNS/-/-/storage/collections/config failed (400 Bad Request): non-JSON body (text/html, 5120 bytes)",
  "Splunk request to /services/server/info returned an unreadable response (200 OK): non-JSON body (unknown content type, 0 bytes)",
  "ACS response for /inputs/http-event-collectors did not include a http-event-collectors list (top-level fields: items, paging), so the inventory could not be read.",
  "The deployment was classified as Splunk Cloud from the URL heuristic (the URL matches *.splunkcloud.com) because /services/server/info could not be read (the credential lacks the required capability (403)); confirm the product type before relying on this verdict.",
  "the endpoint could not be read (Splunk request to /services/server/info failed (502 Bad Gateway): non-JSON body (text/html, 5120 bytes))",
  "the endpoint was not found on this deployment (404)",
  "the credential was rejected (401)",
  "Unknown: /services/authentication/providers/SAML could not be evaluated because the credential lacks the required capability (403). Collect manually: the SAML provider stanza and its active state.",
  "authType is SAML with provider stanza okta present, but the provider endpoint could not be read (the credential lacks the required capability (403)); verify the provider is active.",
  "authType is SAML with an active provider, but the user list could not be read so local break-glass accounts could not be enumerated.",
  "externalTwoFactorAuthVendor is Duo but /services/admin/Duo-MFA could not be read (the credential lacks the required capability (403)); verify the MFA stanza manually.",
  "The subject-to-user check was skipped because the user list could not be read (the credential lacks the required capability (403)); confirm each token subject is a current user.",
  "Unknown: no non-admin role exposed the srchIndexesAllowed field, so search restrictions could not be read.",
  "Unknown: no non-admin role exposed the srchIndexesAllowed field, so _audit and _internal access could not be read.",
  "None of the 3 non-admin roles hold high-risk capabilities. Only 3 of 50 roles were retrieved before the walk stopped, so the verdict is downgraded.",
  "None of the 3 visible users hold admin or sc_admin; at least one administrator must exist, so the credential sees a partial view. Only 3 users (total unknown) were retrieved before the walk stopped, so the verdict is downgraded.",
  "inputs.conf [SSL] could not be read (the credential lacks the required capability (403)), so the receiving-side serverCert and requireClientCert were not checked.",
  "The ACS HEC token inventory (acs:/inputs/http-event-collectors) could not be read (the credential lacks the required capability (403)), so this verdict rests on the local /services/data/inputs/http view alone and the Splunk Cloud token settings were not checked.",
  "audit.conf could not be read (the credential lacks the required capability (403))",
  "No roles were visible, so audit deletion rights could not be evaluated; collect the roles holding delete_by_keyword manually.",
  "role assignments could not be enumerated because the user list could not be read (the credential lacks the required capability (403)), so whether anyone holds a delete-capable role is unknown",
  "_audit frozenTimePeriodInSecs was not readable because the index list could not be read (the credential lacks the required capability (403))",
  "Splunk Cloud ACS is not configured (SPLUNK_STACK and SPLUNK_ACS_TOKEN), so IP allow lists could not be read. Collect GET /access/{feature}/ipallowlists for search-api, hec, s2s, and search-ui manually.",
  "Unknown: 2 enabled apps lack Splunk or Splunkbase provenance and role capabilities could not be read to confirm installation is admin-only.",
  "owner roles were not verified because the user list could not be read (the credential lacks the required capability (403))",
  "Owner roles of the 4 scheduled searches could not be verified because the user list could not be read (the credential lacks the required capability (403)); none combine all indexes with an unbounded time range.",
  "Unknown: 2 enabled splunktcp listeners exist (ports 9997, 9998) but /services/configs/conf-inputs could not be read because the credential lacks the required capability (403), and the data/inputs/tcp/cooked REST view does not report TLS. Collect inputs.conf [splunktcp-ssl:*] and [SSL] from each indexer manually.",
  "Splunk Cloud Platform 9.3.2411 at https://acme.splunkcloud.com:8089 (bearer token auth, TLS verification on).",
  "Splunk Enterprise 9.2.1 at https://splunk.example.com:8089 (session key auth, TLS verification OFF).",
  "Authenticated as admin with 42 capabilities.",
  "Authenticated as unknown (current-context unreadable) with an unread capability list.",
  "17/21 audit surfaces are readable; ACS configured.",
  "Run splunk_assess_authentication, splunk_assess_access_control, splunk_assess_data_protection, splunk_assess_audit_monitoring, splunk_assess_platform_hardening, or splunk_export_audit_bundle.",
  "Grant the audit role the missing capabilities (list_users; edit_roles; list_tokens_all; rest_properties_get) or use an admin-scoped token; unreadable surfaces will render as manual findings.",
];

const SPLUNK_SOURCE_URL = new URL("../extensions/grc-tools/splunk.ts", import.meta.url);

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
 * The resolver messages rendered live for the no credentials, partial credentials, bad URL, and
 * config file failure cases, each against a real temp path; the malformed file carries a config
 * canary so the message proves it holds the path, position, and code only.
 */
function liveSplunkResolverMessages() {
  const base = createTempBase("grclanker-splunk-live-resolver-");
  const missingConfig = join(base, "missing.json");
  const directoryConfig = join(base, "directory.json");
  mkdirSync(directoryConfig);
  const malformedConfig = join(base, "malformed.json");
  writeFileSync(malformedConfig, `{\n  "url": "https://splunk.example.com:8089",\n  "token": "${CONFIG_CANARIES.unterminated}\n}\n`);
  const url = { SPLUNK_URL: "https://splunk.example.com:8089" };
  const resolve = (input, env) => thrownBy(() => resolveSplunkConfiguration({ config_file: missingConfig, ...input }, env)).message;
  return {
    paths: { directoryConfig, malformedConfig },
    messages: {
      "no credentials": resolve({}, {}),
      "partial credentials: URL without a token or password": resolve({}, url),
      "partial credentials: username without a password": resolve({}, { ...url, SPLUNK_USERNAME: "svc-audit" }),
      "bad URL: a scheme the REST API does not serve": resolve({}, { SPLUNK_URL: "ftp://splunk.example.com:8089", SPLUNK_TOKEN: SAMPLE_TOKEN }),
      "config file failure: directory at the path": resolve({ config_file: directoryConfig }, {}),
      "config file failure: malformed JSON": resolve({ config_file: malformedConfig }, {}),
    },
  };
}

test("rule 9: every fixed text the Splunk integration emits, including the live resolver messages, passes its scrubber unchanged", () => {
  const live = liveSplunkResolverMessages();
  const credentialsRequired = "Provide SPLUNK_TOKEN or both SPLUNK_USERNAME and SPLUNK_PASSWORD (arguments or config file also work).";
  const expected = {
    "no credentials": "SPLUNK_URL, a url argument, or a config file url is required (for example https://splunk.example.com:8089).",
    "partial credentials: URL without a token or password": credentialsRequired,
    "partial credentials: username without a password": credentialsRequired,
    "bad URL: a scheme the REST API does not serve": "SPLUNK_URL must be an http(s) URL such as https://splunk.example.com:8089.",
    "config file failure: directory at the path": `Unable to read Splunk config file ${live.paths.directoryConfig} (EISDIR)`,
    "config file failure: malformed JSON": `Unable to parse Splunk config file: invalid JSON in ${live.paths.malformedConfig} at line 3, column 29 (INVALID_JSON)`,
  };
  assert.deepEqual(Object.keys(live.messages), Object.keys(expected));
  for (const [label, message] of Object.entries(live.messages)) {
    assert.equal(message, expected[label], label);
    for (const canary of Object.values(CONFIG_CANARIES)) assertNoWindowOf(message, canary, `live resolver message (${label})`);
    for (const wording of LIBRARY_ERROR_WORDING) assert.ok(!message.includes(wording), `${label} repeats library wording "${wording}": ${message}`);
    assert.equal(scrubErrorText(message), message, `live resolver message survives the scrubber (${label})`);
    assert.equal(scrubErrorText(message, [SAMPLE_TOKEN, SAMPLE_ACS_TOKEN]), message, `live resolver message survives with the configured tokens registered (${label})`);
  }

  // Every message template the resolver and its loaders can throw is pinned by a fixed text or a live rendering, so a reworded message fails here until the set is updated.
  const corpus = [...SPLUNK_FIXED_TEXTS, ...Object.values(live.messages)];
  const segments = errorTemplateSegments(SPLUNK_SOURCE_URL, ["resolveSplunkConfiguration", "readConfigFileText", "configFileParseError", "normalizeBaseUrl"]);
  assert.ok(segments.length >= 6, `the template scan found the two resolver messages, the URL message, and the loader messages (${segments.length})`);
  for (const segment of segments) assert.ok(corpus.some((text) => text.includes(segment)), `resolver template segment is pinned by a fixed text or a live rendering: ${segment}`);

  for (const text of SPLUNK_FIXED_TEXTS) assert.equal(scrubErrorText(text), text, text);
  for (const text of SPLUNK_FIXED_TEXTS) assert.equal(scrubErrorText(text, [SAMPLE_TOKEN, SAMPLE_ACS_TOKEN]), text, `${text} (with the configured tokens registered)`);
});

test("resolveSplunkConfiguration keeps environment credentials when an unrelated argument is passed (GWS note 2)", () => {
  const dir = createTempBase("grclanker-splunk-env-args-");
  const configFile = join(dir, "grclanker.json");
  writeFileSync(configFile, JSON.stringify({ stack: "file-stack" }));
  const env = { SPLUNK_CONFIG_FILE: configFile, SPLUNK_URL: "https://env.example.com:8089", SPLUNK_TOKEN: SAMPLE_TOKEN, SPLUNK_ACS_TOKEN: SAMPLE_ACS_TOKEN };

  const resolved = resolveSplunkConfiguration({ timeout_seconds: 9 }, env);
  assert.equal(resolved.token, SAMPLE_TOKEN, "the environment token survives an argument overlay that names no credential");
  assert.equal(resolved.url, "https://env.example.com:8089");
  assert.equal(resolved.stack, "file-stack", "the config file named through the environment still supplies the stack");
  assert.equal(resolved.acsToken, SAMPLE_ACS_TOKEN);
  assert.equal(resolved.timeoutMs, 9000);
  assert.deepEqual(resolved.sourceChain, ["environment-url", "environment-token", "config-file-stack", "environment-acs-token"]);

  const withUndefinedArguments = resolveSplunkConfiguration({ url: undefined, token: undefined, username: undefined, password: undefined }, env);
  assert.equal(withUndefinedArguments.token, SAMPLE_TOKEN, "an argument overlay whose credential keys are undefined does not shadow the environment");
  assert.deepEqual(withUndefinedArguments.sourceChain, ["environment-url", "environment-token", "config-file-stack", "environment-acs-token"]);

  const session = resolveSplunkConfiguration({ verify_ssl: "true" }, { SPLUNK_URL: "https://env.example.com:8089", SPLUNK_USERNAME: "svc-audit-reader", SPLUNK_PASSWORD: SAMPLE_ACS_TOKEN });
  assert.equal(session.username, "svc-audit-reader");
  assert.equal(session.password, SAMPLE_ACS_TOKEN, "the environment password survives an unrelated verify_ssl argument");
  assert.deepEqual(session.sourceChain, ["environment-url", "environment-username", "environment-password", "arguments-verify-ssl"]);
});
