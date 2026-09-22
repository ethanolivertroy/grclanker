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
} from "../dist/extensions/grc-tools/splunk.js";
import { getRegisteredToolSummaries } from "../dist/pi/tool-catalog.js";
import { assertSecretsAbsent, readBundleFiles, readZipEntries } from "./helpers/bundle-contents.mjs";

const NOW_SECONDS = Math.floor(Date.now() / 1000);

function createTempBase(prefix) {
  return mkdtempSync(join(tmpdir(), prefix));
}

function sampleConfig(overrides = {}) {
  return {
    url: "https://splunk.example.com:8089",
    token: "test-bearer-token",
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
    if (options.partial) {
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

/** Canaries planted on malformed config lines; every 8-character window of each is distinct so a partial quote is caught too. */
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

function fragmentsOf(value, size = 8) {
  const fragments = [];
  for (let index = 0; index + size <= value.length; index += 1) fragments.push(value.slice(index, index + size));
  return fragments;
}

function assertConfigErrorText(text, { path, code, line, column, canaries }, label) {
  for (const canary of canaries) {
    for (const fragment of fragmentsOf(canary)) assert.ok(!text.includes(fragment), `${label} carries a fragment (${fragment}) of ${canary}: ${text}`);
  }
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
      assert.ok(fragmentsOf(canary).some((fragment) => library.message.includes(fragment)), `${testCase.name}: positive control, JSON.parse quotes a window of the canary`);
    }

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
  assert.ok(roleCalls.every((item) => item.auth === "Bearer test-bearer-token"));
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
  assert.equal(api.redact("Authorization: Splunk session-key-abc password pw-secret"), "Authorization: [REDACTED] [REDACTED] password [REDACTED]");
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
  assert.ok(!readFileSync(join(result.outputDir, "core_data/hec_inputs.json"), "utf8").includes("test-bearer-token"));

  const rerun = await exportSplunkAuditBundle(client(partialFailure).client, sampleConfig(), base);
  assert.notEqual(rerun.outputDir, result.outputDir);
  assert.notEqual(rerun.zipPath, result.zipPath);
  assert.ok(existsSync(result.zipPath) && existsSync(rerun.zipPath));
});

const FAKE_SECRETS = {
  pass4SymmKey: "FAKE_PASS4SYMMKEY_1",
  clusteringKey: "$7$FAKE_CIPHERTEXT_1",
  sslKeysfilePassword: "FAKE_SSLKEYSFILE_PASSWORD_1",
  proxyPassword: "FAKE_PROXY_PASSWORD_1",
  httpEventCollectorToken: "FAKE_HEC_OUT_TOKEN_1",
  discoveryKey: "FAKE_PASS4SYMMKEY_2",
  outputsSslPassword: "FAKE_SSL_PASSWORD_1",
  soapPassword: "FAKE_SOAP_PASSWORD_1",
  rsaAccessKey: "FAKE_RSA_ACCESS_KEY_1",
  bindPassword: "FAKE_BIND_PASSWORD_1",
  duoSecret: "FAKE_DUO_SECRET_1",
  hashedValue: "$1$FAKE_HASH_1",
  hecToken: "FAKE_HEC_TOKEN_1",
  inputsSslPassword: "FAKE_SSL_PASSWORD_2",
  s2sPassword: "FAKE_S2S_PASSWORD_1",
  webSslPassword: "FAKE_WEB_SSL_PASSWORD_1",
  hecInputToken: "FAKE_HEC_TOKEN_2",
  webhookToken: "FAKE_WEBHOOK_TOKEN_1",
  slackToken: "FAKE_SLACK_TOKEN_1",
  pagerdutyKey: "FAKE_PD_KEY_1",
  customToken: "FAKE_CUSTOM_TOKEN_1",
  splText: "FAKE_SPL_SECRET_1",
  queryToken: "FAKE_QUERY_TOKEN_1",
  acsHecToken: "FAKE_ACS_HEC_TOKEN_1",
  errorBody: "FAKE_BODY_SECRET_1",
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
  const secrets = [...Object.values(FAKE_SECRETS), "test-bearer-token"];

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
  for (const secret of secrets) {
    assert.ok(!payloads.includes(secret), `${secret} appears in an assess or access check payload`);
  }

  const cloud = { ...SECRET_FIXTURE, "/services/server/info": [entry("server-info", { version: "9.3.2411", product_type: "splunk_cloud", instance_type: "cloud" })] };
  const acs = { "/inputs/http-event-collectors": { "http-event-collectors": [{ spec: { name: "firehose", allowedIndexes: ["main"], defaultSourcetype: "aws:firehose", disabled: false, useACK: true }, token: FAKE_SECRETS.acsHecToken }] } };
  const cloudData = JSON.stringify(await assessSplunkDataProtection(client(cloud, { acs }, { stack: "acme-stack", acsToken: "acs-jwt" }).client));
  assert.ok(!cloudData.includes(FAKE_SECRETS.acsHecToken));
  assert.ok(!cloudData.includes("acs-jwt"));
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
  for (const id of ["SPLUNK-AC-07", "SPLUNK-AC-08", "SPLUNK-AC-09", "SPLUNK-AC-10", "SPLUNK-AC-12"]) {
    assert.notEqual(byId(cappedAccess, id).status, "pass", `${id}: ${byId(cappedAccess, id).summary}`);
  }
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

const SURFACE_CANARIES = ["CANARY_BEARER_S1", "CANARY_SESSION_S1", "CANARY_APIKEY_S1", "CANARY_URL_TOKEN_S1"];
const SURFACE_HTML_BODY = "<html><body><h1>502 Bad Gateway</h1><p>Authorization: Bearer CANARY_BEARER_S1</p><p>Set-Cookie: JSESSIONID=CANARY_SESSION_S1; Path=/</p><p>api_key=CANARY_APIKEY_S1</p><p>Retry at https://api.example.com/v1/x?token=CANARY_URL_TOKEN_S1 later.</p></body></html>";
const SURFACE_JSON_BODY = {
  messages: [{ type: "ERROR", text: "Denied while fetching https://api.example.com/v1/x?token=CANARY_URL_TOKEN_S1 for this key; Authorization: Bearer CANARY_BEARER_S1; api_key=CANARY_APIKEY_S1; session_id=CANARY_SESSION_S1" }],
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
      assertSecretsAbsent(assert, outputs, SURFACE_CANARIES, label);

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
          assert.equal(mention, "https://api.example.com/v1/x", `${label}: the URL keeps scheme, host, and path only`);
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
    assert.match(readFileSync(join(exported.outputDir, "_errors.log"), "utf8"), new RegExp(`core_data/${name}: `));

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
