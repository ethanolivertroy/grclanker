import test from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  ZiaApiClient,
  ZpaApiClient,
  assessZiaAccessControl,
  assessZiaAccessControlData,
  checkZscalerAccess,
  listZscalerControls,
  mappingsForControl,
  obfuscateZiaApiKey,
  redactSecrets,
  resolveSecureOutputPath,
  resolveZiaBaseUrl,
  resolveZpaBaseUrl,
  resolveZscalerConfiguration,
} from "../dist/extensions/grc-tools/zscaler.js";
import { getRegisteredToolSummaries } from "../dist/pi/tool-catalog.js";

const NOW = new Date("2026-09-21T12:00:00Z");

function createTempBase(prefix) {
  return mkdtempSync(join(tmpdir(), prefix));
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

function ziaConfig() {
  return { cloud: "zscalerthree", baseUrl: "https://zsapi.zscalerthree.net/api/v1", apiKey: "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123", username: "auditor@example.com", password: "s3cret-pass" };
}

function zpaConfig() {
  return { cloud: "PRODUCTION", baseUrl: "https://config.private.zscaler.com", clientId: "zpa-client", clientSecret: "zpa-secret-value", customerId: "216196257331281920" };
}

function findingById(result, id) {
  return result.findings.find((item) => item.id === id);
}

function readable(data) {
  return { data };
}

function forbidden(fallback) {
  return { data: fallback, error: "ZIA GET failed (403): forbidden", statusCode: 403 };
}

function accessControlFixture(overrides = {}) {
  return {
    adminUsers: readable([
      { id: 1, loginName: "sso-admin@example.com", disabled: false, isPasswordLoginAllowed: false, adminScopeType: "ORGANIZATION", role: { id: 10, name: "Super Admin" } },
      { id: 2, loginName: "scoped-admin@example.com", disabled: false, isPasswordLoginAllowed: false, adminScopeType: "DEPARTMENT", role: { id: 11, name: "Policy Admin" } },
      { id: 3, loginName: "old-admin@example.com", disabled: true, isPasswordLoginAllowed: true, adminScopeType: "ORGANIZATION", role: { id: 10, name: "Super Admin" } },
    ]),
    adminRoles: readable([
      { id: 10, name: "Super Admin", roleType: "ORG_ADMIN" },
      { id: 11, name: "Policy Admin", roleType: "ORG_ADMIN" },
    ]),
    authSettings: readable({ samlEnabled: true, orgAuthType: "SAML" }),
    passwordExpiry: readable({ passwordExpirationEnabled: true, passwordExpiryDays: 90 }),
    auditLogReport: readable({ status: "COMPLETE" }),
    nssFeeds: readable([{ id: 1, name: "SIEM admin audit", feedStatus: "ENABLED", nssLogType: "ADMIN_AUDIT" }]),
    ...overrides,
  };
}

test("resolveZscalerConfiguration prefers args over env over config file and maps clouds to hosts", () => {
  const base = createTempBase("grclanker-zscaler-config-");
  const configFile = join(base, "zscaler.yaml");
  writeFileSync(configFile, [
    "zia:",
    "  client:",
    "    cloud: zscalerone",
    "    apiKey: file-api-key-000",
    "    username: file-user",
    "    password: file-pass",
    "zpa:",
    "  client:",
    "    clientId: file-client",
    "    clientSecret: file-secret",
    "    customerId: file-customer",
    "    cloud: BETA",
  ].join("\n"));

  const fromFile = resolveZscalerConfiguration({ config_file: configFile }, {});
  assert.equal(fromFile.zia.cloud, "zscalerone");
  assert.equal(fromFile.zia.baseUrl, "https://zsapi.zscalerone.net/api/v1");
  assert.equal(fromFile.zpa.baseUrl, "https://config.zpabeta.net");
  assert.equal(fromFile.configFile, configFile);

  const fromEnv = resolveZscalerConfiguration({ config_file: configFile }, {
    ZIA_CLOUD: "zscalergov",
    ZIA_API_KEY: "env-api-key-0000",
    ZIA_USERNAME: "env-user",
    ZIA_PASSWORD: "env-pass",
    ZPA_CLIENT_ID: "env-client",
    ZPA_CLIENT_SECRET: "env-secret",
    ZPA_CUSTOMER_ID: "env-customer",
    ZPA_CLOUD: "GOV",
    ZSCALER_CLIENT_ID: "oneapi-id",
    ZSCALER_CLIENT_SECRET: "oneapi-secret",
  });
  assert.equal(fromEnv.zia.baseUrl, "https://zsapi.zscalergov.net/api/v1");
  assert.equal(fromEnv.zia.username, "env-user");
  assert.equal(fromEnv.zpa.baseUrl, "https://config.zpagov.net");
  assert.equal(fromEnv.oneApiDetected, true);

  const fromArgs = resolveZscalerConfiguration({
    config_file: configFile,
    zia_cloud: "zscalerten",
    zia_api_key: "arg-api-key-00000",
    zia_username: "arg-user",
    zia_password: "arg-pass",
    zpa_client_id: "arg-client",
    zpa_client_secret: "arg-secret",
    zpa_customer_id: "arg-customer",
    zpa_cloud: "GOVUS",
    timeout_seconds: 9,
  }, { ZIA_CLOUD: "zscalergov", ZIA_API_KEY: "env", ZIA_USERNAME: "env", ZIA_PASSWORD: "env" });
  assert.equal(fromArgs.zia.baseUrl, "https://zsapi.zscalerten.net/api/v1");
  assert.equal(fromArgs.zia.username, "arg-user");
  assert.equal(fromArgs.zpa.baseUrl, "https://config.zpagov.us");
  assert.equal(fromArgs.timeoutMs, 9000);
  assert.ok(fromArgs.sourceChain.includes("arguments-ziaCloud"));

  for (const [cloud, host] of [
    ["zscaler", "https://zsapi.zscaler.net/api/v1"],
    ["zscalertwo", "https://zsapi.zscalertwo.net/api/v1"],
    ["zscalerthree", "https://zsapi.zscalerthree.net/api/v1"],
    ["zscloud", "https://zsapi.zscloud.net/api/v1"],
    ["zscalerbeta", "https://zsapi.zscalerbeta.net/api/v1"],
  ]) {
    assert.equal(resolveZiaBaseUrl(cloud), host);
  }
  assert.equal(resolveZpaBaseUrl("PRODUCTION"), "https://config.private.zscaler.com");
  assert.equal(resolveZpaBaseUrl("zpatwo"), "https://config.zpatwo.net");
  assert.throws(() => resolveZiaBaseUrl("nonsense"), /Unknown ZIA cloud/);
  assert.throws(() => resolveZscalerConfiguration({}, {}), /No Zscaler credentials/);
  assert.throws(() => resolveZscalerConfiguration({ zia_cloud: "zscaler", zia_api_key: "only-key" }, {}), /ZIA requires/);
  const zpaOnly = resolveZscalerConfiguration({}, { ZPA_CLIENT_ID: "c", ZPA_CLIENT_SECRET: "s", ZPA_CUSTOMER_ID: "1" });
  assert.equal(zpaOnly.zia, undefined);
  assert.equal(zpaOnly.zpa.cloud, "PRODUCTION");
});

test("obfuscateZiaApiKey follows the documented timestamp algorithm", () => {
  assert.equal(obfuscateZiaApiKey("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123", "1700000000123"), "AAABCDCCCCID");
  assert.throws(() => obfuscateZiaApiKey("short", "1700000000123"), /12\+ character/);
  assert.equal(redactSecrets("key s3cret-pass JSESSIONID=abc; ok", ["s3cret-pass"]), "key [REDACTED] JSESSIONID=[REDACTED]; ok");
});

test("ZiaApiClient logs in with an obfuscated key, reuses the session cookie, retries 429, and logs out", async () => {
  const seen = [];
  let adminCalls = 0;
  const fetchImpl = async (input, init = {}) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    seen.push({ pathname: url.pathname, search: url.search, method: init.method ?? "GET", cookie: headerValue(init.headers, "cookie"), body: init.body });
    if (url.pathname === "/api/v1/authenticatedSession" && init.method === "POST") {
      return jsonResponse({ authType: "ADMIN_LOGIN" }, { headers: { "set-cookie": "JSESSIONID=SESSION123; Path=/; Secure; HttpOnly" } });
    }
    if (url.pathname === "/api/v1/authenticatedSession" && init.method === "DELETE") {
      return jsonResponse({});
    }
    if (url.pathname === "/api/v1/adminUsers") {
      adminCalls += 1;
      if (adminCalls === 1) return jsonResponse({ message: "Rate limit exceeded" }, { status: 429, headers: { "retry-after": "0" } });
      return jsonResponse([{ id: 1, loginName: "admin@example.com" }]);
    }
    return jsonResponse({ message: "not found" }, { status: 404 });
  };

  const client = new ZiaApiClient(ziaConfig(), { fetchImpl, now: () => new Date(1700000000123) });
  const admins = await client.listAdminUsers();
  assert.deepEqual(admins.items.map((item) => item.loginName), ["admin@example.com"]);
  assert.equal(admins.truncated, false);
  const login = JSON.parse(seen[0].body);
  assert.equal(seen[0].method, "POST");
  assert.equal(login.apiKey, "AAABCDCCCCID");
  assert.equal(login.username, "auditor@example.com");
  assert.equal(login.timestamp, "1700000000123");
  assert.equal(seen[1].cookie, "JSESSIONID=SESSION123");
  assert.ok(seen[1].search.includes("pageSize=1000"));
  assert.equal(seen.filter((item) => item.pathname === "/api/v1/adminUsers").length, 2);

  await assert.rejects(() => client.getAuthSettings(), (error) => error.status === 404 && !error.message.includes("SESSION123"));
  await client.logout();
  assert.equal(seen.at(-1).method, "DELETE");
  assert.equal(seen.at(-1).pathname, "/api/v1/authenticatedSession");
});

test("ZiaApiClient surfaces login failures with redacted secrets", async () => {
  const fetchImpl = async () => jsonResponse({ message: "Invalid credentials for s3cret-pass" }, { status: 401 });
  const client = new ZiaApiClient(ziaConfig(), { fetchImpl });
  await assert.rejects(() => client.listAdminRoles(), (error) => {
    assert.equal(error.status, 401);
    assert.match(error.message, /ZIA login failed \(401\)/);
    assert.ok(!error.message.includes("s3cret-pass"));
    return true;
  });
});

test("ZpaApiClient signs in with client credentials and pages until totalPages", async () => {
  const seen = [];
  const fetchImpl = async (input, init = {}) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    seen.push({ pathname: url.pathname, page: url.searchParams.get("page"), pagesize: url.searchParams.get("pagesize"), method: init.method ?? "GET", auth: headerValue(init.headers, "authorization"), contentType: headerValue(init.headers, "content-type"), body: init.body });
    if (url.pathname === "/signin") {
      return jsonResponse({ token_type: "Bearer", access_token: "zpa-token", expires_in: "3600" });
    }
    if (url.pathname.endsWith("/application")) {
      const page = Number(url.searchParams.get("page"));
      return jsonResponse({ totalPages: "3", list: [{ id: `app-${page}`, name: `App ${page}` }] });
    }
    return jsonResponse({ id: "x" }, { status: 404 });
  };
  const client = new ZpaApiClient(zpaConfig(), { fetchImpl });
  const segments = await client.listApplicationSegments();
  assert.deepEqual(segments.items.map((item) => item.id), ["app-1", "app-2", "app-3"]);
  assert.equal(segments.truncated, false);
  assert.equal(segments.totalPages, 3);
  assert.equal(seen[0].pathname, "/signin");
  assert.equal(seen[0].contentType, "application/x-www-form-urlencoded");
  assert.match(seen[0].body, /client_id=zpa-client&client_secret=zpa-secret-value/);
  assert.equal(seen[1].pathname, "/mgmtconfig/v1/admin/customers/216196257331281920/application");
  assert.equal(seen[1].auth, "Bearer zpa-token");
  assert.equal(seen[1].pagesize, "500");
  assert.deepEqual(seen.slice(1).map((item) => item.page), ["1", "2", "3"]);
  assert.equal(seen.filter((item) => item.pathname === "/signin").length, 1);
});

test("checkZscalerAccess reports healthy, limited, and single-product states", async () => {
  const zia = {
    getResolvedConfig: () => ziaConfig(),
    getNow: () => NOW,
    listAdminUsers: async () => ({ items: [{ id: 1 }], truncated: false, pagesFetched: 1 }),
    listAdminRoles: async () => [{ id: 1 }],
    getAuthSettings: async () => ({ samlEnabled: true }),
    getAuditLogReportStatus: async () => ({ status: "COMPLETE" }),
    listUrlFilteringRules: async () => [{ id: 1 }],
    listFirewallFilteringRules: async () => [{ id: 1 }],
    listDlpEngines: async () => [{ id: 1 }],
    listSslInspectionRules: async () => [{ id: 1 }],
    getAdvancedThreatSettings: async () => ({ malwareSitesBlocked: true }),
    listLocations: async () => ({ items: [{ id: 1 }], truncated: false, pagesFetched: 1 }),
  };
  const zpa = {
    getResolvedConfig: () => zpaConfig(),
    getNow: () => NOW,
    listApplicationSegments: async () => ({ items: [{ id: "1" }], truncated: false, pagesFetched: 1, totalPages: 1 }),
    listSegmentGroups: async () => ({ items: [{ id: "1" }], truncated: false, pagesFetched: 1, totalPages: 1 }),
    listPolicyRules: async () => ({ items: [{ id: "1" }], truncated: false, pagesFetched: 1, totalPages: 1 }),
    listAppConnectors: async () => ({ items: [{ id: "1" }], truncated: false, pagesFetched: 1, totalPages: 1 }),
    listIdpControllers: async () => ({ items: [{ id: "1" }], truncated: false, pagesFetched: 1, totalPages: 1 }),
    listPostureProfiles: async () => ({ items: [{ id: "1" }], truncated: false, pagesFetched: 1, totalPages: 1 }),
    listAdministrators: async () => ({ items: [{ id: "1" }], truncated: false, pagesFetched: 1, totalPages: 1 }),
  };
  const config = { zia: ziaConfig(), zpa: zpaConfig(), oneApiDetected: false, zdxDetected: false, timeoutMs: 30000, maxRetries: 3, sourceChain: [] };

  const healthy = await checkZscalerAccess({ config, zia, zpa });
  assert.equal(healthy.status, "healthy");
  assert.equal(healthy.surfaces.length, 17);
  assert.equal(healthy.products.zpa, "configured");

  const degraded = await checkZscalerAccess({
    config: { ...config, zpa: undefined },
    zia: { ...zia, listFirewallFilteringRules: async () => { throw new Error("ZIA GET /firewallFilteringRules failed (403)"); } },
  });
  assert.equal(degraded.status, "limited");
  assert.equal(degraded.products.zpa, "not_configured");
  assert.ok(degraded.notes.some((note) => /ZPA is not configured/.test(note)));
  assert.equal(degraded.surfaces.find((surface) => surface.name === "firewall_filtering_rules").status, "not_readable");
});

test("assessZiaAccessControl: compliant tenant passes automatable controls and keeps MFA manual", () => {
  const result = assessZiaAccessControlData(accessControlFixture(), { maxSuperAdmins: 5 });
  assert.equal(findingById(result, "ZS-06").status, "manual");
  assert.match(findingById(result, "ZS-06").summary, /password login disabled/);
  assert.equal(findingById(result, "ZS-07").status, "pass");
  assert.equal(findingById(result, "ZS-14").status, "pass");
  assert.equal(result.errors.length, 0);
  for (const item of result.findings) {
    assert.equal(item.mappings.length, 8);
    assert.ok(item.mappings[0].startsWith("FedRAMP "));
  }
});

test("assessZiaAccessControl: password-login admins, super admin sprawl, and missing audit export fail or warn", () => {
  const result = assessZiaAccessControlData(accessControlFixture({
    adminUsers: readable([
      { id: 1, loginName: "a@example.com", disabled: false, isPasswordLoginAllowed: true, role: { id: 10, name: "Super Admin" } },
      { id: 2, loginName: "b@example.com", disabled: false, isPasswordLoginAllowed: true, role: { id: 10, name: "Super Admin" } },
    ]),
    nssFeeds: readable([{ id: 1, name: "web feed", feedStatus: "ENABLED", nssLogType: "WEBLOG" }]),
  }), { maxSuperAdmins: 1 });
  assert.equal(findingById(result, "ZS-06").status, "warn");
  assert.match(findingById(result, "ZS-06").summary, /2 of 2 enabled administrators allow password login/);
  assert.equal(findingById(result, "ZS-07").status, "fail");
  assert.equal(findingById(result, "ZS-14").status, "fail");

  const noFeeds = assessZiaAccessControlData(accessControlFixture({ nssFeeds: readable([]) }));
  assert.equal(findingById(noFeeds, "ZS-14").status, "warn");
});

test("assessZiaAccessControl: 403 on every surface yields manual verdicts that name the cause", () => {
  const result = assessZiaAccessControlData({
    adminUsers: forbidden([]),
    adminRoles: forbidden([]),
    authSettings: forbidden({}),
    passwordExpiry: forbidden({}),
    auditLogReport: forbidden({}),
    nssFeeds: forbidden([]),
  });
  assert.equal(result.findings.length, 3);
  for (const item of result.findings) {
    assert.equal(item.status, "manual");
    assert.match(item.summary, /403/);
    assert.ok(item.manualEvidence);
  }
  assert.ok(result.errors.length >= 3);
});

test("assessZiaAccessControl: empty inventories never pass", () => {
  const result = assessZiaAccessControlData(accessControlFixture({ adminUsers: readable([]), adminRoles: readable([]), nssFeeds: readable([]) }));
  assert.equal(findingById(result, "ZS-06").status, "manual");
  assert.match(findingById(result, "ZS-06").summary, /Empty inventory/);
  assert.equal(findingById(result, "ZS-07").status, "manual");
  assert.equal(findingById(result, "ZS-14").status, "warn");
  assert.ok(result.findings.every((item) => item.status !== "pass"));
});

test("assessZiaAccessControl: a partial admin inventory caps the verdict at warn", () => {
  const fixture = accessControlFixture();
  fixture.adminUsers = { ...fixture.adminUsers, truncated: true, seen: 50 };
  const result = assessZiaAccessControlData(fixture);
  assert.equal(findingById(result, "ZS-07").status, "warn");
  assert.match(findingById(result, "ZS-07").summary, /inventory is partial/);
  assert.equal(result.truncated.length, 1);
});

test("assessZiaAccessControl renders not-configured manual findings without ZIA credentials", async () => {
  const result = await assessZiaAccessControl(undefined);
  assert.deepEqual(result.findings.map((item) => item.id), ["ZS-06", "ZS-07", "ZS-14"]);
  for (const item of result.findings) {
    assert.equal(item.status, "manual");
    assert.match(item.summary, /Not configured: ZIA credentials were not provided \(ZIA_CLOUD, ZIA_API_KEY/);
  }
});

test("control catalog covers all 25 spec controls with eight framework mappings each", () => {
  const controls = listZscalerControls();
  assert.equal(controls.length, 25);
  assert.deepEqual(controls.map((item) => item.control), Array.from({ length: 25 }, (_, index) => index + 1));
  assert.deepEqual(mappingsForControl(1), ["FedRAMP SC-7, SI-4", "CMMC 2.0 C.3.13, C.5.3", "SOC 2 CC6.1, CC6.8", "CIS CIS CSC 9", "PCI-DSS 4.0 1.2, 6.2", "DISA STIG V-XXXXX", "IRAP ISM-0261", "ISMAP 7.3.1"]);
});

test("zscaler tools are registered in the tool catalog under the Zscaler group", () => {
  const tools = getRegisteredToolSummaries().filter((tool) => tool.name.startsWith("zscaler_"));
  const names = tools.map((tool) => tool.name);
  assert.ok(names.includes("zscaler_check_access"));
  assert.ok(names.includes("zscaler_assess_zia_access_control"));
  for (const tool of tools) {
    assert.equal(tool.group, "Zscaler");
    assert.equal(tool.kind, "domain");
  }
});

test("resolveSecureOutputPath rejects traversal and symlink parents", () => {
  const base = createTempBase("grclanker-zscaler-path-");
  const outside = createTempBase("grclanker-zscaler-outside-");
  const linked = join(base, "linked");
  symlinkSync(outside, linked, "dir");

  assert.throws(() => resolveSecureOutputPath(base, "../escape"), /Refusing to write outside/);
  assert.throws(() => resolveSecureOutputPath(base, "linked/file.txt"), /symlinked parent directory/);
  const safe = resolveSecureOutputPath(base, join("reports", "safe.txt"));
  assert.match(safe, /reports\/safe\.txt$/);
  assert.ok(!existsSync(safe));
  assert.equal(typeof readFileSync, "function");
});
