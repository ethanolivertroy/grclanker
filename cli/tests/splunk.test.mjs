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
