import test from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
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
  resolveSecureOutputPath,
  resolveSplunkConfiguration,
} from "../dist/extensions/grc-tools/splunk.js";
import { getRegisteredToolSummaries } from "../dist/pi/tool-catalog.js";

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
  "/services/data/inputs/tcp/ssl": [entry("SSL", { serverCert: "/opt/splunk/etc/auth/server.pem", requireClientCert: 1, sslVersions: "tls1.2" })],
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
  "/services/data/inputs/tcp/cooked": [entry("9997", { disabled: 0, SSL: 1 })],
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
  "/services/data/inputs/tcp/cooked": [entry("9997", { disabled: 0, SSL: 0 })],
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
    "core_data/server_info.json", "core_data/roles.json", "core_data/access_check.json",
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
