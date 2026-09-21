import test from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readdirSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import { inflateRawSync } from "node:zlib";

import {
  ZiaApiClient,
  ZpaApiClient,
  assessZiaAccessControl,
  assessZiaAccessControlData,
  assessZiaPolicy,
  assessZiaPolicyData,
  assessZpa,
  assessZpaData,
  checkZscalerAccess,
  collectZiaAccessControlData,
  collectZiaPolicyData,
  collectZpaData,
  exportZscalerAuditBundle,
  listZscalerControls,
  mappingsForControl,
  obfuscateZiaApiKey,
  redactForExport,
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

function policyFixture(overrides = {}) {
  return {
    urlFilteringRules: readable([
      { id: 1, name: "Block risky", state: "ENABLED", action: "BLOCK", urlCategories: ["ANONYMIZER", "OTHER_SECURITY", "ADULT_THEMES", "PORNOGRAPHY", "GAMBLING"] },
      { id: 2, name: "Isolate uncategorized", state: "ENABLED", action: "ISOLATE", urlCategories: ["MISCELLANEOUS_OR_UNKNOWN"] },
      { id: 3, name: "Old rule", state: "DISABLED", action: "ALLOW", urlCategories: [] },
    ]),
    firewallRules: readable([
      { id: 1, name: "Allow web", state: "ENABLED", action: "ALLOW", nwServices: [{ id: 1, name: "HTTP" }], enableFullLogging: true },
      { id: 2, name: "Block bad countries", state: "ENABLED", action: "BLOCK_DROP", destCountries: ["COUNTRY_KP"], enableFullLogging: true },
      { id: 99, name: "Default Firewall Filtering Rule", state: "ENABLED", action: "BLOCK_DROP", defaultRule: true, enableFullLogging: true },
    ]),
    dnsRules: readable([
      { id: 1, name: "Block malicious DNS", state: "ENABLED", action: "BLOCK" },
      { id: 9, name: "Default DNS rule", state: "ENABLED", action: "ALLOW", defaultRule: true },
    ]),
    dlpEngines: readable([{ id: 1, name: "PCI", predefinedEngineName: "PCI" }]),
    dlpDictionaries: readable([{ id: 1, name: "Credit Cards", custom: false }]),
    webDlpRules: readable([{ id: 1, name: "Block card data", state: "ENABLED", action: "BLOCK", dlpEngines: [{ id: 1 }] }]),
    sslInspectionRules: readable([
      { id: 1, name: "Decrypt all", state: "ENABLED", action: { type: "DECRYPT" } },
      { id: 2, name: "Bypass banking", state: "ENABLED", action: { type: "DO_NOT_DECRYPT" }, urlCategories: ["FINANCE"] },
    ]),
    sslExemptedUrls: readable({ urls: ["bank.example.com"] }),
    sandboxRules: readable([{ id: 1, name: "Sandbox block", state: "ENABLED", baRuleAction: "BLOCK", firstTimeEnable: true, firstTimeOperation: "QUARANTINE" }]),
    sandboxSettings: readable({ md5HashValueList: ["d41d8cd98f00b204e9800998ecf8427e"] }),
    advancedThreatSettings: readable({
      riskTolerance: 50,
      malwareSitesBlocked: true,
      cmdCtlServerBlocked: true,
      cmdCtlTrafficBlocked: true,
      knownPhishingSitesBlocked: true,
      suspectedPhishingSitesBlocked: true,
      browserExploitsBlocked: true,
      potentialMaliciousRequestsBlocked: true,
      dgaDomainsBlocked: true,
    }),
    malwarePolicy: readable({ blockUnscannableFiles: true, blockPasswordProtectedArchiveFiles: true }),
    malwareSettings: readable({ virusBlocked: true, trojanBlocked: true, wormBlocked: true, ransomwareBlocked: true, spywareBlocked: true }),
    securityAllowlist: readable({ whitelistUrls: ["trusted.example.com"] }),
    securityDenylist: readable({ blacklistUrls: ["bad.example.com"] }),
    locations: readable([{ id: 100, name: "HQ", authRequired: true, sslScanEnabled: true, ofwEnabled: true }]),
    subLocations: readable([{ id: 101, name: "HQ Guest", parentId: 100, authRequired: true, sslScanEnabled: true, ofwEnabled: true }]),
    greTunnels: readable([{ id: 1, sourceIp: "203.0.113.10" }]),
    vpnCredentials: readable([{ id: 1, type: "UFQDN", fqdn: "hq@example.com" }]),
    bandwidthRules: readable([{ id: 1, name: "Video cap", state: "ENABLED", minBandwidth: 10, maxBandwidth: 40 }]),
    isolationProfiles: readable([{ id: "p1", name: "Default isolation", url: "https://isolation.example.com" }]),
    cloudAppRules: { data: [{ id: 1, name: "Block personal webmail", state: "ENABLED", ruleType: "WEBMAIL", actions: ["BLOCK_WEBMAIL_SEND"] }], seen: 3, total: 3 },
    ...overrides,
  };
}

const POLICY_CONTROL_IDS = ["ZS-01", "ZS-02", "ZS-03", "ZS-04", "ZS-05", "ZS-16", "ZS-17", "ZS-18", "ZS-19", "ZS-20", "ZS-25"];

test("assessZiaPolicy: compliant tenant passes every automatable policy control", () => {
  const result = assessZiaPolicyData(policyFixture());
  assert.deepEqual(result.findings.map((item) => item.id), POLICY_CONTROL_IDS);
  for (const item of result.findings) {
    assert.equal(item.status, "pass", `${item.id}: ${item.summary}`);
    assert.equal(item.mappings.length, 8);
  }
  assert.equal(result.errors.length, 0);
});

test("assessZiaPolicy: risky configurations fail or warn with specific reasons", () => {
  const result = assessZiaPolicyData(policyFixture({
    urlFilteringRules: readable([{ id: 1, name: "Allow all", state: "ENABLED", action: "ALLOW", urlCategories: [] }]),
    firewallRules: readable([
      { id: 1, name: "Any any", state: "ENABLED", action: "ALLOW" },
      { id: 99, name: "Default", state: "ENABLED", action: "ALLOW", defaultRule: true },
    ]),
    webDlpRules: readable([{ id: 1, name: "Monitor", state: "ENABLED", action: "ALLOW", dlpEngines: [{ id: 1 }] }]),
    sslInspectionRules: readable([{ id: 1, name: "Decrypt", state: "ENABLED", action: { type: "DECRYPT" } }, { id: 2, name: "Bypass everything", state: "ENABLED", action: { type: "DO_NOT_DECRYPT" } }]),
    sandboxRules: readable([{ id: 1, name: "Allow", state: "ENABLED", baRuleAction: "ALLOW" }]),
    advancedThreatSettings: readable({ malwareSitesBlocked: true, cmdCtlServerBlocked: false, dgaDomainsBlocked: false }),
    locations: readable([{ id: 1, name: "Branch", authRequired: false, sslScanEnabled: false, ofwEnabled: true }]),
    subLocations: readable([]),
    dnsRules: readable([{ id: 9, name: "Default", state: "ENABLED", action: "ALLOW", defaultRule: true }]),
  }), { maxSslExemptions: 50 });
  assert.equal(findingById(result, "ZS-01").status, "fail");
  assert.match(findingById(result, "ZS-01").summary, /none uses action BLOCK/);
  assert.equal(findingById(result, "ZS-02").status, "fail");
  assert.match(findingById(result, "ZS-02").summary, /Default Firewall Filtering Rule action is ALLOW/);
  assert.equal(findingById(result, "ZS-03").status, "warn");
  assert.equal(findingById(result, "ZS-04").status, "fail");
  assert.match(findingById(result, "ZS-04").summary, /DO_NOT_DECRYPT/);
  assert.equal(findingById(result, "ZS-05").status, "warn");
  assert.equal(findingById(result, "ZS-18").status, "warn");
  assert.equal(findingById(result, "ZS-20").status, "fail");
  assert.equal(findingById(result, "ZS-25").status, "fail");
  assert.match(findingById(result, "ZS-25").summary, /cmdCtlServerBlocked/);
});

test("assessZiaPolicy: 403 everywhere yields manual findings only", () => {
  const fixture = policyFixture();
  for (const key of Object.keys(fixture)) {
    fixture[key] = forbidden(Array.isArray(fixture[key].data) ? [] : {});
  }
  const result = assessZiaPolicyData(fixture);
  assert.equal(result.findings.length, POLICY_CONTROL_IDS.length);
  for (const item of result.findings) {
    assert.equal(item.status, "manual", `${item.id}: ${item.summary}`);
    assert.match(item.summary, /403/);
  }
});

test("assessZiaPolicy: empty inventories fail or render manual, never pass", () => {
  const fixture = policyFixture();
  for (const key of Object.keys(fixture)) {
    fixture[key] = readable(Array.isArray(fixture[key].data) ? [] : {});
  }
  fixture.cloudAppRules = { data: [], seen: 0, total: 0 };
  const result = assessZiaPolicyData(fixture);
  const expected = { "ZS-01": "fail", "ZS-02": "fail", "ZS-03": "fail", "ZS-04": "fail", "ZS-05": "manual", "ZS-16": "manual", "ZS-17": "manual", "ZS-18": "manual", "ZS-19": "fail", "ZS-20": "fail", "ZS-25": "fail" };
  for (const [id, status] of Object.entries(expected)) {
    assert.equal(findingById(result, id).status, status, `${id}: ${findingById(result, id).summary}`);
  }
});

test("assessZiaPolicy: partial location and rule-type inventories cap verdicts at warn", () => {
  const fixture = policyFixture();
  fixture.locations = { ...fixture.locations, truncated: true, seen: 50 };
  fixture.cloudAppRules = { ...fixture.cloudAppRules, truncated: true, seen: 25, total: 30 };
  const result = assessZiaPolicyData(fixture);
  assert.equal(findingById(result, "ZS-18").status, "warn");
  assert.match(findingById(result, "ZS-18").summary, /partial/);
  assert.equal(findingById(result, "ZS-19").status, "warn");
  assert.match(findingById(result, "ZS-19").summary, /25 of 30 rule types/);
  assert.ok(result.truncated.length >= 2);
});

test("assessZiaPolicy collects through the client, follows sub-locations, and renders not-configured without ZIA", async () => {
  const calls = [];
  const client = {
    getResolvedConfig: () => ziaConfig(),
    getNow: () => NOW,
    listUrlFilteringRules: async () => ({ items: [], truncated: false, pagesFetched: 1 }),
    listFirewallFilteringRules: async () => { throw Object.assign(new Error("ZIA GET /firewallFilteringRules failed (403)"), { status: 403, product: "zia" }); },
    listFirewallDnsRules: async () => [],
    listDlpEngines: async () => [],
    listDlpDictionaries: async () => [],
    listWebDlpRules: async () => [],
    listSslInspectionRules: async () => [],
    getSslExemptedUrls: async () => ({ urls: [] }),
    listSandboxRules: async () => [],
    getSandboxAdvancedSettings: async () => ({}),
    getAdvancedThreatSettings: async () => ({}),
    getMalwarePolicy: async () => ({}),
    getMalwareSettings: async () => ({}),
    getSecurityAllowlist: async () => ({}),
    getSecurityDenylist: async () => ({}),
    listLocations: async () => ({ items: [{ id: 7, name: "HQ" }], truncated: false, pagesFetched: 1 }),
    listSubLocations: async (id) => { calls.push(id); return [{ id: 8, name: "Guest", parentId: 7 }]; },
    listGreTunnels: async () => ({ items: [], truncated: false, pagesFetched: 1 }),
    listVpnCredentials: async () => ({ items: [], truncated: false, pagesFetched: 1 }),
    listBandwidthControlRules: async () => [],
    listBrowserIsolationProfiles: async () => [],
    listCloudAppRuleTypes: async () => ["WEBMAIL"],
    listCloudAppRules: async () => [],
  };
  const result = await assessZiaPolicy(client);
  assert.deepEqual(calls, ["7"]);
  assert.equal(result.summary.sub_locations, 1);
  assert.equal(findingById(result, "ZS-02").status, "manual");
  assert.ok(result.findings.every((item) => item.status !== "pass"));

  const missing = await assessZiaPolicy(undefined);
  assert.equal(missing.findings.length, POLICY_CONTROL_IDS.length);
  assert.ok(missing.findings.every((item) => item.status === "manual" && /Not configured: ZIA/.test(item.summary)));
});

const FUTURE_EPOCH = String(Math.floor(NOW.getTime() / 1000) + 400 * 86400);
const PAST_EPOCH = String(Math.floor(NOW.getTime() / 1000) - 5 * 86400);
const RECENT_EPOCH_MS = String(NOW.getTime() - 3600 * 1000);

function zpaFixture(overrides = {}) {
  const identityCondition = { operator: "AND", operands: [{ objectType: "SCIM_GROUP", lhs: "idp-1", rhs: "group-1" }, { objectType: "POSTURE", lhs: "posture-udid", rhs: "true" }] };
  return {
    applicationSegments: readable([
      { id: "seg-1", name: "HR app", enabled: true, domainNames: ["hr.corp.example.com"], tcpPortRange: [{ from: "443", to: "443" }], segmentGroupId: "sg-1", bypassType: "NEVER" },
    ]),
    segmentGroups: readable([{ id: "sg-1", name: "Corp apps", enabled: true }]),
    accessRules: readable([
      { id: "r-1", name: "HR access", action: "ALLOW", disabled: false, conditions: [identityCondition] },
      { id: "r-9", name: "Deny all", action: "DENY", disabled: false, conditions: [] },
    ]),
    timeoutRules: readable([{ id: "t-1", name: "Default timeout", disabled: false, reauthTimeout: "43200", reauthIdleTimeout: "3600" }]),
    forwardingRules: readable([{ id: "f-1", name: "Forward corp", action: "INTERCEPT", disabled: false, conditions: [{ operands: [{ objectType: "TRUSTED_NETWORK", lhs: "net-1", rhs: "true" }] }] }]),
    isolationRules: readable([]),
    appConnectorGroups: readable([{ id: "cg-1", name: "DC East", enabled: true }]),
    appConnectors: readable([
      { id: "c-1", name: "connector-1", enabled: true, controlChannelStatus: "ZPN_STATUS_AUTHENTICATED", appConnectorGroupName: "DC East", lastBrokerConnectTime: RECENT_EPOCH_MS },
      { id: "c-2", name: "connector-2", enabled: true, controlChannelStatus: "ZPN_STATUS_AUTHENTICATED", appConnectorGroupName: "DC East", lastBrokerConnectTime: RECENT_EPOCH_MS },
    ]),
    serviceEdgeGroups: readable([{ id: "seg-1", name: "Edge group" }]),
    serviceEdges: readable([{ id: "se-1", name: "edge-1", enabled: true, controlChannelStatus: "ZPN_STATUS_AUTHENTICATED", lastBrokerConnectTime: RECENT_EPOCH_MS }]),
    postureProfiles: readable([{ id: "p-1", name: "Disk encrypted", postureType: "DISK_ENCRYPTION", postureUdid: "posture-udid" }]),
    trustedNetworks: readable([{ id: "n-1", name: "HQ network", networkId: "net-1" }]),
    idpControllers: readable([{ id: "idp-1", name: "Okta", enabled: true, ssoType: ["USER", "ADMIN"], scimEnabled: true, signSamlRequest: "1" }]),
    samlAttributes: readable([{ id: "a-1", name: "Email", idpId: "idp-1" }]),
    scimGroups: readable([{ id: 1, name: "HR", idpId: "idp-1" }]),
    enrollmentCertificates: readable([{ id: "ec-1", name: "Connector", validToInEpochSec: FUTURE_EPOCH }, { id: "ec-2", name: "Client", validToInEpochSec: FUTURE_EPOCH }]),
    browserAccessCertificates: readable([{ id: "ba-1", name: "portal cert", validToInEpochSec: FUTURE_EPOCH }]),
    emergencyAccessUsers: readable([{ userId: "u-1", emailId: "breakglass@example.com", userStatus: "DEACTIVATED", lastLoginTime: PAST_EPOCH }]),
    administrators: readable([{ id: "ad-1", username: "zpa-admin", isEnabled: true, localLoginDisabled: true, twoFactorAuthEnabled: false }]),
    now: NOW,
    ...overrides,
  };
}

const ZPA_CONTROL_IDS = ["ZS-08", "ZS-09", "ZS-10", "ZS-11", "ZS-12", "ZS-13", "ZS-15", "ZS-21", "ZS-22", "ZS-23", "ZS-24"];

test("assessZpa: compliant tenant passes every automatable ZPA control", () => {
  const result = assessZpaData(zpaFixture());
  assert.deepEqual(result.findings.map((item) => item.id), ZPA_CONTROL_IDS);
  for (const item of result.findings) {
    assert.equal(item.status, "pass", `${item.id}: ${item.summary}`);
    assert.equal(item.mappings.length, 8);
  }
});

test("assessZpa: broad segments, unconditional allows, stale connectors, and expired certificates fail", () => {
  const result = assessZpaData(zpaFixture({
    applicationSegments: readable([{ id: "seg-1", name: "Everything", enabled: true, domainNames: ["*"], tcpPortRanges: ["1", "65535"], segmentGroupId: "sg-1" }]),
    accessRules: readable([{ id: "r-1", name: "Allow all", action: "ALLOW", disabled: false, conditions: [] }]),
    appConnectors: readable([{ id: "c-1", name: "connector-1", enabled: true, controlChannelStatus: "ZPN_STATUS_DISCONNECTED", appConnectorGroupName: "DC East" }]),
    idpControllers: readable([{ id: "idp-1", name: "Okta", enabled: true, ssoType: ["USER"], scimEnabled: false, signSamlRequest: "0" }]),
    timeoutRules: readable([{ id: "t-1", name: "Never", disabled: false, reauthTimeout: "-1" }]),
    forwardingRules: readable([{ id: "f-1", name: "Bypass all", action: "BYPASS", disabled: false, conditions: [] }]),
    emergencyAccessUsers: readable([{ userId: "u-1", emailId: "breakglass@example.com", userStatus: "ACTIVATED" }]),
    enrollmentCertificates: readable([{ id: "ec-1", name: "Connector", validToInEpochSec: PAST_EPOCH }]),
    administrators: readable([{ id: "ad-1", username: "zpa-admin", isEnabled: true, localLoginDisabled: false, twoFactorAuthEnabled: false }]),
  }));
  assert.equal(findingById(result, "ZS-08").status, "fail");
  assert.match(findingById(result, "ZS-08").summary, /wildcard domain with the full 1-65535 port range/);
  assert.equal(findingById(result, "ZS-09").status, "fail");
  assert.equal(findingById(result, "ZS-10").status, "fail");
  assert.equal(findingById(result, "ZS-11").status, "fail");
  assert.equal(findingById(result, "ZS-12").status, "warn");
  assert.match(findingById(result, "ZS-12").summary, /local login without two-factor/);
  assert.equal(findingById(result, "ZS-13").status, "fail");
  assert.equal(findingById(result, "ZS-15").status, "warn");
  assert.equal(findingById(result, "ZS-22").status, "fail");
  assert.equal(findingById(result, "ZS-23").status, "warn");
  assert.equal(findingById(result, "ZS-24").status, "fail");
});

test("assessZpa: 403 everywhere yields manual findings only", () => {
  const fixture = zpaFixture();
  for (const key of Object.keys(fixture)) {
    if (key === "now") continue;
    fixture[key] = { data: [], error: "ZPA GET failed (403): forbidden", statusCode: 403 };
  }
  const result = assessZpaData(fixture);
  assert.equal(result.findings.length, ZPA_CONTROL_IDS.length);
  for (const item of result.findings) {
    assert.equal(item.status, "manual", `${item.id}: ${item.summary}`);
    assert.match(item.summary, /403/);
  }
});

test("assessZpa: empty inventories fail or render manual, never pass", () => {
  const fixture = zpaFixture();
  for (const key of Object.keys(fixture)) {
    if (key === "now") continue;
    fixture[key] = readable([]);
  }
  const result = assessZpaData(fixture);
  const expected = { "ZS-08": "fail", "ZS-09": "fail", "ZS-10": "fail", "ZS-11": "fail", "ZS-12": "fail", "ZS-13": "fail", "ZS-15": "manual", "ZS-21": "manual", "ZS-22": "manual", "ZS-23": "manual", "ZS-24": "manual" };
  for (const [id, status] of Object.entries(expected)) {
    assert.equal(findingById(result, id).status, status, `${id}: ${findingById(result, id).summary}`);
  }
});

test("assessZpa: partial pagination and undated records cap verdicts at warn", () => {
  const fixture = zpaFixture();
  fixture.applicationSegments = { ...fixture.applicationSegments, truncated: true, seen: 200, total: 250 };
  fixture.accessRules = { ...fixture.accessRules, truncated: true, seen: 200, total: 201 };
  fixture.appConnectors = readable([
    { id: "c-1", name: "connector-1", enabled: true, controlChannelStatus: "ZPN_STATUS_AUTHENTICATED", appConnectorGroupName: "DC East", lastBrokerConnectTime: RECENT_EPOCH_MS },
    { id: "c-2", name: "connector-2", enabled: true, controlChannelStatus: "ZPN_STATUS_AUTHENTICATED", appConnectorGroupName: "DC East" },
  ]);
  fixture.enrollmentCertificates = readable([{ id: "ec-1", name: "Connector", validToInEpochSec: FUTURE_EPOCH }, { id: "ec-2", name: "Undated" }]);
  const result = assessZpaData(fixture);
  assert.equal(findingById(result, "ZS-08").status, "warn");
  assert.match(findingById(result, "ZS-08").summary, /inventory is partial/);
  assert.equal(findingById(result, "ZS-09").status, "warn");
  assert.equal(findingById(result, "ZS-10").status, "warn");
  assert.equal(findingById(result, "ZS-11").status, "warn");
  assert.match(findingById(result, "ZS-11").summary, /1 authenticated but with no lastBrokerConnectTime/);
  assert.deepEqual(findingById(result, "ZS-11").evidence.authenticated_without_connect_time, ["connector-2"]);
  assert.equal(findingById(result, "ZS-24").status, "warn");
  assert.match(findingById(result, "ZS-24").summary, /no validToInEpochSec/);
  assert.ok(result.findings.every((item) => item.status !== "pass" || !["ZS-08", "ZS-09", "ZS-10", "ZS-11", "ZS-24"].includes(item.id)));
  assert.ok(result.truncated.some((note) => /200 of 250 pages/.test(note)));
});

test("assessZpa collects SCIM groups per SCIM-enabled IdP and renders not-configured without ZPA", async () => {
  const paged = (items) => ({ items, truncated: false, pagesFetched: 1, totalPages: 1 });
  const scimCalls = [];
  const client = {
    getResolvedConfig: () => zpaConfig(),
    getNow: () => NOW,
    listApplicationSegments: async () => paged([]),
    listSegmentGroups: async () => paged([]),
    listPolicyRules: async () => paged([]),
    listAppConnectorGroups: async () => paged([]),
    listAppConnectors: async () => paged([]),
    listServiceEdgeGroups: async () => paged([]),
    listServiceEdges: async () => paged([]),
    listPostureProfiles: async () => paged([]),
    listTrustedNetworks: async () => paged([]),
    listIdpControllers: async () => paged([{ id: "idp-1", name: "Okta", enabled: true, scimEnabled: true, ssoType: ["USER"] }, { id: "idp-2", name: "Legacy", enabled: false, scimEnabled: false }]),
    listSamlAttributes: async () => paged([]),
    listScimGroups: async (idpId) => { scimCalls.push(idpId); return paged([{ id: 1, name: "HR" }]); },
    listEnrollmentCertificates: async () => paged([]),
    listBrowserAccessCertificates: async () => paged([]),
    listEmergencyAccessUsers: async () => paged([]),
    listAdministrators: async () => paged([]),
  };
  const result = await assessZpa(client);
  assert.deepEqual(scimCalls, ["idp-1"]);
  assert.equal(findingById(result, "ZS-12").evidence.scim_groups, 1);
  assert.ok(result.findings.every((item) => item.status !== "pass"));

  const missing = await assessZpa(undefined);
  assert.equal(missing.findings.length, ZPA_CONTROL_IDS.length);
  assert.ok(missing.findings.every((item) => item.status === "manual" && /ZPA_CLIENT_ID, ZPA_CLIENT_SECRET, ZPA_CUSTOMER_ID/.test(item.summary)));
});

function ziaFetchMock(options = {}) {
  const failPaths = new Set(options.failPaths ?? []);
  return async (input, init = {}) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    const path = url.pathname.replace("/api/v1", "");
    if (path === "/authenticatedSession") {
      return init.method === "POST"
        ? jsonResponse({ authType: "ADMIN_LOGIN" }, { headers: { "set-cookie": "JSESSIONID=LIVE; Path=/" } })
        : jsonResponse({});
    }
    if (failPaths.has(path)) return jsonResponse({ message: "forbidden" }, { status: 403 });
    switch (path) {
      case "/adminUsers":
        return jsonResponse([{ id: 1, loginName: "admin@example.com", disabled: false, isPasswordLoginAllowed: false, role: { id: 10, name: "Super Admin" } }]);
      case "/adminRoles/lite":
        return jsonResponse([{ id: 10, name: "Super Admin" }, { id: 11, name: "Auditor" }]);
      case "/authSettings":
        return jsonResponse({ samlEnabled: true });
      case "/passwordExpiry/settings":
        return jsonResponse({ passwordExpirationEnabled: true, passwordExpiryDays: 90 });
      case "/auditlogEntryReport":
        return jsonResponse({ status: "COMPLETE" });
      case "/nssFeeds":
        return jsonResponse([{ id: 1, name: "siem", feedStatus: "ENABLED", nssLogType: "ADMIN_AUDIT", authenticationToken: "super-secret-token" }]);
      case "/locations":
        return jsonResponse([{ id: 5, name: "HQ", authRequired: true, sslScanEnabled: true, ofwEnabled: true }]);
      case "/locations/5/sublocations":
        return jsonResponse([]);
      case "/sslSettings/exemptedUrls":
        return jsonResponse({ urls: [] });
      case "/webApplicationRules/ruleTypeMapping":
        return jsonResponse({ WEBMAIL: "Webmail" });
      case "/webApplicationRules/WEBMAIL":
        return jsonResponse([]);
      default:
        return jsonResponse(path.endsWith("Rules") || path.endsWith("Engines") || path.endsWith("Dictionaries") || path.endsWith("Tunnels") || path.endsWith("Credentials") || path.endsWith("profiles") ? [] : {});
    }
  };
}

test("exportZscalerAuditBundle writes the bundle layout, redacts secrets, logs errors, and never overwrites", async () => {
  const base = createTempBase("grclanker-zscaler-bundle-");
  const config = { zia: ziaConfig(), zpa: undefined, oneApiDetected: false, zdxDetected: false, timeoutMs: 30000, maxRetries: 0, sourceChain: [] };
  const zia = new ZiaApiClient(ziaConfig(), { fetchImpl: ziaFetchMock({ failPaths: ["/firewallFilteringRules"] }), maxRetries: 0 });
  const result = await exportZscalerAuditBundle({ config, zia }, { outputDir: base });

  for (const relativePath of [
    "core_data/access_check.json",
    "core_data/zia_access_control.json",
    "core_data/zia_policy.json",
    "core_data/zpa.json",
    "analysis/findings.json",
    "analysis/summary.json",
    "analysis/zia_access_control.json",
    "analysis/zia_policy.json",
    "analysis/zpa.json",
    "compliance/executive_summary.md",
    "compliance/unified_compliance_matrix.md",
    "compliance/fedramp/fedramp_compliance_report.md",
    "compliance/cmmc/cmmc_compliance_report.md",
    "compliance/soc2/soc2_compliance_report.md",
    "compliance/cis/cis_compliance_report.md",
    "compliance/pci_dss/pci_dss_compliance_report.md",
    "compliance/disa_stig/stig_compliance_checklist.md",
    "compliance/irap/irap_compliance_report.md",
    "compliance/ismap/ismap_compliance_report.md",
    "QUICK_REFERENCE.md",
    "_errors.log",
  ]) {
    assert.ok(existsSync(join(result.outputDir, relativePath)), `missing ${relativePath}`);
  }
  assert.ok(existsSync(result.zipPath));
  assert.equal(result.zipPath, `${result.outputDir}.zip`);
  assert.equal(result.findingCount, 25);
  assert.ok(result.errorCount > 0);

  const findings = JSON.parse(readFileSync(join(result.outputDir, "analysis/findings.json"), "utf8"));
  assert.equal(findings.find((item) => item.id === "ZS-02").status, "manual");
  assert.ok(findings.filter((item) => item.id.startsWith("ZS-0") || item.id.startsWith("ZS-")).length === 25);
  assert.ok(findings.filter((item) => /Not configured: ZPA/.test(item.summary)).length === 11);
  const rawAccess = readFileSync(join(result.outputDir, "core_data/zia_access_control.json"), "utf8");
  assert.ok(!rawAccess.includes("super-secret-token"));
  assert.ok(rawAccess.includes("[REDACTED]"));
  assert.match(readFileSync(join(result.outputDir, "_errors.log"), "utf8"), /firewallFilteringRules/);
  assert.match(readFileSync(join(result.outputDir, "compliance/unified_compliance_matrix.md"), "utf8"), /ZS-14 \| Audit Logging Enabled \| PASS/);

  const rerun = await exportZscalerAuditBundle({ config, zia: new ZiaApiClient(ziaConfig(), { fetchImpl: ziaFetchMock(), maxRetries: 0 }) }, { outputDir: base });
  assert.notEqual(rerun.outputDir, result.outputDir);
  assert.match(rerun.outputDir, /-2$/);
  assert.equal(rerun.zipPath, `${rerun.outputDir}.zip`);
  assert.ok(existsSync(result.zipPath));
  assert.ok(!existsSync(join(rerun.outputDir, "_errors.log")) || readFileSync(join(rerun.outputDir, "_errors.log"), "utf8").length > 0);
});

test("exportZscalerAuditBundle rejects unsafe output paths", async () => {
  const base = createTempBase("grclanker-zscaler-unsafe-");
  const outside = createTempBase("grclanker-zscaler-unsafe-outside-");
  symlinkSync(outside, join(base, "linked"), "dir");
  const config = { zia: ziaConfig(), oneApiDetected: false, zdxDetected: false, timeoutMs: 30000, maxRetries: 0, sourceChain: [] };
  await assert.rejects(
    () => exportZscalerAuditBundle({ config, zia: new ZiaApiClient(ziaConfig(), { fetchImpl: ziaFetchMock(), maxRetries: 0 }) }, { outputDir: join(base, "linked") }),
    /symlink/,
  );
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
  assert.ok(names.includes("zscaler_assess_zia_policy"));
  assert.ok(names.includes("zscaler_assess_zpa"));
  assert.ok(names.includes("zscaler_export_audit_bundle"));
  assert.equal(tools.length, 5);
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

// Review regression coverage: HTTP stubs shaped by the Automation Hub OpenAPI (paged ZIA lists honoring page and
// pageSize, ZPA list/totalPages wrappers, the pageId cursor on emergency access, and GET /network) drive the real
// clients so every assertion below exercises the exact request the tools send.

const ZPA_CUSTOMER = "216196257331281920";
const ZPA_V1 = `/mgmtconfig/v1/admin/customers/${ZPA_CUSTOMER}`;
const ZPA_V2 = `/mgmtconfig/v2/admin/customers/${ZPA_CUSTOMER}`;
const ZPA_USERCONFIG = `/userconfig/v1/customers/${ZPA_CUSTOMER}`;
const STALE_EPOCH_MS = String(NOW.getTime() - 45 * 86400 * 1000);

function requestKey(url, init = {}) {
  const query = [...url.searchParams.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([key, value]) => `${key}=${value}`).join("&");
  return `${init.method ?? "GET"} ${url.pathname}${query ? `?${query}` : ""}`;
}

function pageOf(list, url, defaultPageSize) {
  const page = Number(url.searchParams.get("page") ?? "1");
  const pageSize = Number(url.searchParams.get("pageSize") ?? String(defaultPageSize));
  return list.slice((page - 1) * pageSize, page * pageSize);
}

function zpaPage(list, url) {
  const page = Number(url.searchParams.get("page") ?? "1");
  const pageSize = Number(url.searchParams.get("pagesize") ?? "500");
  return { totalPages: String(Math.max(1, Math.ceil(list.length / pageSize))), list: list.slice((page - 1) * pageSize, page * pageSize) };
}

function urlRule(id, overrides = {}) {
  return { id, name: `Allow business ${id}`, order: id, state: "ENABLED", action: "ALLOW", urlCategories: ["PROFESSIONAL_SERVICES"], ...overrides };
}

function compliantLocation(id) {
  return { id, name: `Site ${id}`, authRequired: true, sslScanEnabled: true, ofwEnabled: true };
}

function ziaCompliantTenant(overrides = {}) {
  return {
    adminUsers: [
      { id: 1, loginName: "sso-admin@example.com", userName: "SSO Admin", disabled: false, isPasswordLoginAllowed: false, adminScope: { Type: "ORGANIZATION", ScopeEntities: [] }, role: { id: 10, name: "Super Admin" } },
      { id: 2, loginName: "policy-admin@example.com", userName: "Policy Admin", disabled: false, isPasswordLoginAllowed: false, adminScope: { Type: "DEPARTMENT", ScopeEntities: [{ id: 5, name: "IT" }] }, role: { id: 11, name: "Policy Admin" } },
    ],
    adminRoles: [{ id: 10, name: "Super Admin", roleType: "ORG_ADMIN" }, { id: 11, name: "Policy Admin", roleType: "ORG_ADMIN" }],
    authSettings: { samlEnabled: true, orgAuthType: "SAML" },
    passwordExpiry: { passwordExpirationEnabled: true, passwordExpiryDays: 90 },
    auditLogReport: { status: "COMPLETE", progressItemsComplete: 10 },
    nssFeeds: [{ id: 1, name: "SIEM admin audit", feedStatus: "ENABLED", nssLogType: "ADMIN_AUDIT" }],
    urlFilteringRules: [
      { id: 1, name: "Block risky", order: 1, state: "ENABLED", action: "BLOCK", urlCategories: ["ANONYMIZER", "OTHER_SECURITY", "ADULT_THEMES", "PORNOGRAPHY", "GAMBLING"] },
      { id: 2, name: "Isolate uncategorized", order: 2, state: "ENABLED", action: "ISOLATE", urlCategories: ["MISCELLANEOUS_OR_UNKNOWN"] },
      ...Array.from({ length: 99 }, (_, index) => urlRule(index + 3)),
    ],
    firewallRules: [
      { id: 1, name: "Allow web", order: 1, state: "ENABLED", action: "ALLOW", nwServices: [{ id: 1, name: "HTTP" }], enableFullLogging: true },
      { id: 2, name: "Block sanctioned countries", order: 2, state: "ENABLED", action: "BLOCK_DROP", destCountries: ["COUNTRY_KP"], enableFullLogging: true },
      { id: 99, name: "Default Firewall Filtering Rule", order: 3, state: "ENABLED", action: "BLOCK_DROP", defaultRule: true, enableFullLogging: true },
    ],
    dnsRules: [{ id: 1, name: "Block malicious DNS", state: "ENABLED", action: "BLOCK" }, { id: 9, name: "Default DNS rule", state: "ENABLED", action: "ALLOW", defaultRule: true }],
    dlpEngines: [{ id: 1, name: "PCI", predefinedEngineName: "PCI" }],
    dlpDictionaries: [{ id: 1, name: "Credit Cards", custom: false }],
    webDlpRules: [{ id: 1, name: "Block card data", state: "ENABLED", action: "BLOCK", dlpEngines: [{ id: 1 }] }],
    sslInspectionRules: [{ id: 1, name: "Decrypt all", state: "ENABLED", action: { type: "DECRYPT" } }, { id: 2, name: "Bypass banking", state: "ENABLED", action: { type: "DO_NOT_DECRYPT" }, urlCategories: ["FINANCE"] }],
    sslExemptedUrls: { urls: ["bank.example.com"] },
    sandboxRules: [{ id: 1, name: "Sandbox block", state: "ENABLED", baRuleAction: "BLOCK", firstTimeEnable: true, firstTimeOperation: "QUARANTINE" }],
    sandboxSettings: { md5HashValueList: ["d41d8cd98f00b204e9800998ecf8427e"] },
    advancedThreatSettings: { riskTolerance: 50, malwareSitesBlocked: true, cmdCtlServerBlocked: true, cmdCtlTrafficBlocked: true, knownPhishingSitesBlocked: true, suspectedPhishingSitesBlocked: true, browserExploitsBlocked: true, potentialMaliciousRequestsBlocked: true, dgaDomainsBlocked: true },
    malwarePolicy: { blockUnscannableFiles: true, blockPasswordProtectedArchiveFiles: true },
    malwareSettings: { virusBlocked: true, trojanBlocked: true, wormBlocked: true, ransomwareBlocked: true, spywareBlocked: true },
    securityAllowlist: { whitelistUrls: ["trusted.example.com"] },
    securityDenylist: { blacklistUrls: ["bad.example.com"] },
    locations: [compliantLocation(100)],
    subLocations: { 100: [{ id: 101, name: "HQ Guest", parentId: 100, authRequired: true, sslScanEnabled: true, ofwEnabled: true }] },
    greTunnels: [{ id: 1, sourceIp: "203.0.113.10" }],
    vpnCredentials: [{ id: 1, type: "UFQDN", fqdn: "hq@example.com", location: { id: 100, name: "Site 100" } }],
    bandwidthRules: [{ id: 1, name: "Video cap", state: "ENABLED", minBandwidth: 10, maxBandwidth: 40 }],
    isolationProfiles: [{ id: "p1", name: "Default isolation", url: "https://isolation.example.com" }],
    ruleTypeMapping: { WEBMAIL: "Webmail" },
    cloudAppRules: { WEBMAIL: [{ id: 1, name: "Block personal webmail", state: "ENABLED", ruleType: "WEBMAIL", actions: ["BLOCK_WEBMAIL_SEND"] }] },
    ...overrides,
  };
}

function ziaTenantFetch(tenant, options = {}) {
  const requests = [];
  const statusOverrides = options.statusOverrides ?? {};
  const fetchImpl = async (input, init = {}) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    requests.push({ key: requestKey(url, init), url, init });
    const path = url.pathname.replace(/^\/api\/v1/, "");
    if (path === "/authenticatedSession") {
      return init.method === "POST"
        ? jsonResponse({ authType: "ADMIN_LOGIN" }, { headers: { "set-cookie": "JSESSIONID=TENANT; Path=/; Secure; HttpOnly" } })
        : jsonResponse({});
    }
    if (statusOverrides[path]) return jsonResponse({ code: "INVALID_INPUT_ARGUMENT", message: `stub ${statusOverrides[path]}` }, { status: statusOverrides[path] });
    const subLocation = path.match(/^\/locations\/(\d+)\/sublocations$/);
    if (subLocation) return jsonResponse(tenant.subLocations[subLocation[1]] ?? []);
    const cloudApp = path.match(/^\/webApplicationRules\/([A-Z_]+)$/);
    if (cloudApp) return jsonResponse(tenant.cloudAppRules[cloudApp[1]] ?? []);
    switch (path) {
      case "/adminUsers": return jsonResponse(pageOf(tenant.adminUsers, url, 100));
      case "/adminRoles/lite": return jsonResponse(tenant.adminRoles);
      case "/authSettings": return jsonResponse(tenant.authSettings);
      case "/passwordExpiry/settings": return jsonResponse(tenant.passwordExpiry);
      case "/auditlogEntryReport": return jsonResponse(tenant.auditLogReport);
      case "/nssFeeds": return jsonResponse(tenant.nssFeeds);
      case "/urlFilteringRules": return jsonResponse(pageOf(tenant.urlFilteringRules, url, 100));
      case "/firewallFilteringRules": return jsonResponse(pageOf(tenant.firewallRules, url, 5000));
      case "/firewallDnsRules": return jsonResponse(tenant.dnsRules);
      case "/dlpEngines": return jsonResponse(tenant.dlpEngines);
      case "/dlpDictionaries": return jsonResponse(tenant.dlpDictionaries);
      case "/webDlpRules": return jsonResponse(tenant.webDlpRules);
      case "/sslInspectionRules": return jsonResponse(tenant.sslInspectionRules);
      case "/sslSettings/exemptedUrls": return jsonResponse(tenant.sslExemptedUrls);
      case "/sandboxRules": return jsonResponse(tenant.sandboxRules);
      case "/behavioralAnalysisAdvancedSettings": return jsonResponse(tenant.sandboxSettings);
      case "/cyberThreatProtection/advancedThreatSettings": return jsonResponse(tenant.advancedThreatSettings);
      case "/cyberThreatProtection/malwarePolicy": return jsonResponse(tenant.malwarePolicy);
      case "/cyberThreatProtection/malwareSettings": return jsonResponse(tenant.malwareSettings);
      case "/security": return jsonResponse(tenant.securityAllowlist);
      case "/security/advanced": return jsonResponse(tenant.securityDenylist);
      case "/locations": return jsonResponse(pageOf(tenant.locations, url, 100));
      case "/greTunnels": return jsonResponse(pageOf(tenant.greTunnels, url, 100));
      case "/vpnCredentials": {
        const withoutLocationOnly = url.searchParams.get("includeOnlyWithoutLocation") !== "false";
        return jsonResponse(pageOf(withoutLocationOnly ? tenant.vpnCredentials.filter((credential) => !credential.location) : tenant.vpnCredentials, url, 100));
      }
      case "/bandwidthControlRules": return jsonResponse(tenant.bandwidthRules);
      case "/browserIsolation/profiles": return jsonResponse(tenant.isolationProfiles);
      case "/webApplicationRules/ruleTypeMapping": return jsonResponse(tenant.ruleTypeMapping);
      default: return jsonResponse({ code: "RESOURCE_NOT_FOUND", message: `no stub for ${path}` }, { status: 404 });
    }
  };
  return { fetchImpl, requests };
}

function zpaCompliantTenant(overrides = {}) {
  const identityCondition = { operator: "AND", operands: [{ objectType: "SCIM_GROUP", lhs: "idp-1", rhs: "group-1" }, { objectType: "POSTURE", lhs: "posture-udid", rhs: "true" }] };
  return {
    application: [{ id: "seg-1", name: "HR app", enabled: true, domainNames: ["hr.corp.example.com"], tcpPortRange: [{ from: "443", to: "443" }], segmentGroupId: "sg-1", bypassType: "NEVER" }],
    segmentGroup: [{ id: "sg-1", name: "Corp apps", enabled: true }],
    ACCESS_POLICY: [
      { id: "r-1", name: "HR access", action: "ALLOW", disabled: false, conditions: [identityCondition] },
      { id: "r-9", name: "Deny all", action: "DENY", disabled: false, conditions: [] },
    ],
    TIMEOUT_POLICY: [{ id: "t-1", name: "Default timeout", disabled: false, reauthTimeout: "43200", reauthIdleTimeout: "3600" }],
    CLIENT_FORWARDING_POLICY: [{ id: "f-1", name: "Forward corp", action: "INTERCEPT", disabled: false, conditions: [{ operands: [{ objectType: "TRUSTED_NETWORK", lhs: "net-1", rhs: "true" }] }] }],
    ISOLATION_POLICY: [],
    appConnectorGroup: [{ id: "cg-1", name: "DC East", enabled: true }],
    connector: [
      { id: "c-1", name: "connector-1", enabled: true, controlChannelStatus: "ZPN_STATUS_AUTHENTICATED", appConnectorGroupName: "DC East", lastBrokerConnectTime: RECENT_EPOCH_MS },
      { id: "c-2", name: "connector-2", enabled: true, controlChannelStatus: "ZPN_STATUS_AUTHENTICATED", appConnectorGroupName: "DC East", lastBrokerConnectTime: RECENT_EPOCH_MS },
    ],
    serviceEdgeGroup: [{ id: "seg-1", name: "Edge group" }],
    serviceEdge: [{ id: "se-1", name: "edge-1", enabled: true, controlChannelStatus: "ZPN_STATUS_AUTHENTICATED", lastBrokerConnectTime: RECENT_EPOCH_MS }],
    posture: [{ id: "p-1", name: "Disk encrypted", postureType: "DISK_ENCRYPTION", postureUdid: "posture-udid" }],
    network: [{ id: "n-1", name: "HQ network", networkId: "net-1" }],
    idp: [{ id: "idp-1", name: "Okta", enabled: true, ssoType: ["USER", "ADMIN"], scimEnabled: true, signSamlRequest: "1" }],
    samlAttribute: [{ id: "a-1", name: "Email", idpId: "idp-1" }],
    scimGroups: { "idp-1": [{ id: 1, name: "HR", idpId: "idp-1" }] },
    enrollmentCert: [{ id: "ec-1", name: "Connector", validToInEpochSec: FUTURE_EPOCH }, { id: "ec-2", name: "Client", validToInEpochSec: FUTURE_EPOCH }],
    clientlessCertificate: [{ id: "ba-1", name: "portal cert", validToInEpochSec: FUTURE_EPOCH }],
    emergencyAccessPages: [
      { items: [{ userId: "u-1", emailId: "breakglass-1@example.com", userStatus: "DEACTIVATED", lastLoginTime: PAST_EPOCH }], nextPage: "cursor-2" },
      { items: [
        { userId: "u-2", emailId: "breakglass-2@example.com", userStatus: "DEACTIVATED", lastLoginTime: PAST_EPOCH },
        { userId: "u-1", emailId: "breakglass-1@example.com", userStatus: "DEACTIVATED", lastLoginTime: PAST_EPOCH },
      ] },
    ],
    administrators: [{ id: "ad-1", username: "zpa-admin", isEnabled: true, localLoginDisabled: true, twoFactorAuthEnabled: false }],
    ...overrides,
  };
}

function zpaTenantFetch(tenant, options = {}) {
  const requests = [];
  const statusOverrides = options.statusOverrides ?? {};
  const fetchImpl = async (input, init = {}) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    requests.push({ key: requestKey(url, init), url, init });
    if (url.pathname === "/signin") return jsonResponse({ token_type: "Bearer", access_token: "zpa-token", expires_in: "3600" });
    const suffix = url.pathname.replace(`${ZPA_V1}/`, "").replace(`${ZPA_V2}/`, "").replace(`${ZPA_USERCONFIG}/`, "");
    if (statusOverrides[suffix]) return jsonResponse({ id: "error", reason: `stub ${statusOverrides[suffix]}` }, { status: statusOverrides[suffix] });
    const policy = suffix.match(/^policySet\/rules\/policyType\/([A-Z_]+)$/);
    if (policy) return jsonResponse(zpaPage(tenant[policy[1]] ?? [], url));
    const scim = suffix.match(/^scimgroup\/idpId\/(.+)$/);
    if (scim) return jsonResponse(zpaPage(tenant.scimGroups[decodeURIComponent(scim[1])] ?? [], url));
    if (suffix === "emergencyAccess/users") {
      const pageId = url.searchParams.get("pageId");
      const index = pageId ? Number(pageId.replace("cursor-", "")) - 1 : 0;
      return jsonResponse(tenant.emergencyAccessPages[index] ?? { items: [] });
    }
    if (suffix === "clientlessCertificate/issued") return jsonResponse(zpaPage(tenant.clientlessCertificate, url));
    if (suffix === "application" && tenant.applicationTotalPages) {
      const page = url.searchParams.get("page");
      return jsonResponse({ totalPages: String(tenant.applicationTotalPages), list: [{ ...tenant.application[0], id: `seg-${page}`, name: `Segment ${page}` }] });
    }
    if (Array.isArray(tenant[suffix])) return jsonResponse(zpaPage(tenant[suffix], url));
    return jsonResponse({ id: "not-found", reason: `no stub for ${url.pathname}` }, { status: 404 });
  };
  return { fetchImpl, requests };
}

const AUTOMATABLE_CONTROL_IDS = [...POLICY_CONTROL_IDS, ...ZPA_CONTROL_IDS, "ZS-07", "ZS-14"].sort();

async function runCompliantTenant(ziaOverrides = {}, zpaOverrides = {}, options = {}) {
  const ziaStub = ziaTenantFetch(ziaCompliantTenant(ziaOverrides), { statusOverrides: options.ziaStatus });
  const zpaStub = zpaTenantFetch(zpaCompliantTenant(zpaOverrides), { statusOverrides: options.zpaStatus });
  const zia = new ZiaApiClient(ziaConfig(), { fetchImpl: ziaStub.fetchImpl, maxRetries: 0, now: () => NOW });
  const zpa = new ZpaApiClient(zpaConfig(), { fetchImpl: zpaStub.fetchImpl, maxRetries: 0, now: () => NOW });
  const results = {
    access: await assessZiaAccessControl(zia, options.accessOptions ?? {}),
    policy: await assessZiaPolicy(zia, options.policyOptions ?? {}),
    zpa: await assessZpa(zpa, options.zpaOptions ?? {}),
  };
  await zia.logout();
  const findings = [...results.access.findings, ...results.policy.findings, ...results.zpa.findings];
  return { ...results, findings, ziaRequests: ziaStub.requests, zpaRequests: zpaStub.requests };
}

test("ZpaApiClient requests GET /mgmtconfig/v2/admin/customers/{customerId}/network for trusted networks (ZS-15)", async () => {
  const stub = zpaTenantFetch(zpaCompliantTenant());
  const client = new ZpaApiClient(zpaConfig(), { fetchImpl: stub.fetchImpl, maxRetries: 0 });
  const networks = await client.listTrustedNetworks();
  assert.deepEqual(networks.items.map((item) => item.networkId), ["net-1"]);
  const keys = stub.requests.map((request) => request.key);
  assert.ok(keys.includes(`GET ${ZPA_V2}/network?page=1&pagesize=500`), keys.join("\n"));
  assert.ok(keys.every((key) => !key.includes("trustedNetwork")));

  const result = assessZpaData(zpaFixture({ trustedNetworks: { data: [], error: "ZPA GET /network failed (404): not found", statusCode: 404 } }));
  assert.equal(findingById(result, "ZS-15").status, "manual");
  assert.match(findingById(result, "ZS-15").summary, /GET \/network could not be read/);
});

test("ZpaApiClient pages /emergencyAccess/users with the pageId cursor and deduplicates users", async () => {
  const stub = zpaTenantFetch(zpaCompliantTenant());
  const client = new ZpaApiClient(zpaConfig(), { fetchImpl: stub.fetchImpl, maxRetries: 0 });
  const users = await client.listEmergencyAccessUsers();
  assert.deepEqual(users.items.map((user) => user.userId), ["u-1", "u-2"]);
  assert.equal(users.truncated, false);
  assert.equal(users.pagesFetched, 2);
  const emergencyRequests = stub.requests.filter((request) => request.url.pathname === `${ZPA_V1}/emergencyAccess/users`);
  assert.deepEqual(emergencyRequests.map((request) => request.key), [
    `GET ${ZPA_V1}/emergencyAccess/users?pageSize=500`,
    `GET ${ZPA_V1}/emergencyAccess/users?pageId=cursor-2&pageSize=500`,
  ]);
  for (const request of emergencyRequests) {
    assert.equal(request.url.searchParams.has("page"), false);
    assert.equal(request.url.searchParams.has("pagesize"), false);
  }
});

test("ZpaApiClient reports a repeated or cycling nextPage cursor as truncated and ZS-23 stays below pass (rule 10)", async () => {
  let calls = 0;
  const fetchImpl = async (input) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    if (url.pathname === "/signin") return jsonResponse({ token_type: "Bearer", access_token: "t", expires_in: "3600" });
    calls += 1;
    return jsonResponse({ items: [{ userId: `u-${calls}`, emailId: `u-${calls}@example.com` }], nextPage: "same-cursor" });
  };
  const client = new ZpaApiClient(zpaConfig(), { fetchImpl, maxRetries: 0 });
  const users = await client.listEmergencyAccessUsers();
  assert.equal(calls, 2);
  assert.equal(users.truncated, true);
  assert.equal(users.totalPages, undefined);
  assert.deepEqual(users.items.map((user) => user.userId), ["u-1", "u-2"]);

  let cycle = 0;
  const cycling = async (input) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    if (url.pathname === "/signin") return jsonResponse({ token_type: "Bearer", access_token: "t", expires_in: "3600" });
    cycle += 1;
    return jsonResponse({ items: [{ userId: `u-${cycle}` }], nextPage: cycle % 2 === 1 ? "cursor-b" : "cursor-a" });
  };
  const cycled = await new ZpaApiClient(zpaConfig(), { fetchImpl: cycling, maxRetries: 0 }).listEmergencyAccessUsers();
  assert.equal(cycled.truncated, true);
  assert.equal(cycle, 3);

  const stuckTenant = zpaTenantFetch(zpaCompliantTenant({
    emergencyAccessPages: [{ items: [{ userId: "u-1", emailId: "breakglass-1@example.com", userStatus: "DEACTIVATED", lastLoginTime: PAST_EPOCH }], nextPage: "cursor-1" }],
  }));
  const stuck = await assessZpa(new ZpaApiClient(zpaConfig(), { fetchImpl: stuckTenant.fetchImpl, maxRetries: 0, now: () => NOW }));
  const emergency = findingById(stuck, "ZS-23");
  assert.equal(emergency.status, "warn");
  assert.equal(emergency.evidence.partial_inventory, true);
  assert.match(emergency.summary, /emergency access user inventory is partial \(1 records over 2 pages, total unknown\)/);
  assert.ok(stuck.truncated.some((note) => /emergencyAccess\/users: only 2 pages were read and the total is unknown/.test(note)), stuck.truncated.join("\n"));

  let cursor = 0;
  const endless = async (input) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    if (url.pathname === "/signin") return jsonResponse({ token_type: "Bearer", access_token: "t", expires_in: "3600" });
    cursor += 1;
    return jsonResponse({ items: [{ userId: `u-${cursor}` }], nextPage: `cursor-${cursor + 1}` });
  };
  const capped = await new ZpaApiClient(zpaConfig(), { fetchImpl: endless, maxRetries: 0 }).listEmergencyAccessUsers();
  assert.equal(capped.truncated, true);
  assert.equal(capped.pagesFetched, 200);
  assert.equal(findingById(assessZpaData(zpaFixture({ emergencyAccessUsers: { data: capped.items.map((user) => ({ ...user, userStatus: "DEACTIVATED" })), truncated: true, seen: 200 } })), "ZS-23").status, "warn");
});

test("ZiaApiClient pages /urlFilteringRules at the documented pageSize of 100 and reads a 101-rule tenant completely", async () => {
  const stub = ziaTenantFetch(ziaCompliantTenant());
  const client = new ZiaApiClient(ziaConfig(), { fetchImpl: stub.fetchImpl, maxRetries: 0, now: () => NOW });
  const rules = await client.listUrlFilteringRules();
  assert.equal(rules.items.length, 101);
  assert.equal(rules.truncated, false);
  assert.equal(rules.pagesFetched, 2);
  assert.deepEqual(stub.requests.filter((request) => request.url.pathname === "/api/v1/urlFilteringRules").map((request) => request.key), [
    "GET /api/v1/urlFilteringRules?page=1&pageSize=100",
    "GET /api/v1/urlFilteringRules?page=2&pageSize=100",
  ]);

  const firewall = await client.listFirewallFilteringRules();
  assert.equal(firewall.items.length, 3);
  assert.equal(stub.requests.at(-1).key, "GET /api/v1/firewallFilteringRules?page=1&pageSize=5000");

  const tunnels = await client.listGreTunnels();
  assert.equal(tunnels.items.length, 1);
  assert.equal(stub.requests.at(-1).key, "GET /api/v1/greTunnels?page=1&pageSize=1000");

  const credentials = await client.listVpnCredentials();
  assert.deepEqual(credentials.items.map((item) => item.fqdn), ["hq@example.com"]);
  assert.equal(stub.requests.at(-1).key, "GET /api/v1/vpnCredentials?includeOnlyWithoutLocation=false&page=1&pageSize=1000");

  const policy = await assessZiaPolicy(client);
  assert.equal(findingById(policy, "ZS-01").status, "pass");
  assert.equal(findingById(policy, "ZS-01").evidence.rule_count, 101);
  assert.equal(findingById(policy, "ZS-01").evidence.partial_inventory, false);
  assert.equal(findingById(policy, "ZS-17").status, "pass");
});

test("ZiaApiClient records truncation when a URL rule read hits the page cap and ZS-01 and ZS-17 downgrade", async () => {
  const stub = ziaTenantFetch(ziaCompliantTenant({ urlFilteringRules: [
    { id: 1, name: "Block risky", order: 1, state: "ENABLED", action: "BLOCK", urlCategories: ["ANONYMIZER", "OTHER_SECURITY", "ADULT_THEMES", "PORNOGRAPHY", "GAMBLING"] },
    { id: 2, name: "Isolate uncategorized", order: 2, state: "ENABLED", action: "ISOLATE", urlCategories: ["MISCELLANEOUS_OR_UNKNOWN"] },
    ...Array.from({ length: 5001 }, (_, index) => urlRule(index + 3)),
  ] }));
  const client = new ZiaApiClient(ziaConfig(), { fetchImpl: stub.fetchImpl, maxRetries: 0, now: () => NOW });
  const data = await collectZiaPolicyData(client);
  assert.equal(data.urlFilteringRules.truncated, true);
  assert.equal(data.urlFilteringRules.seen, 50);
  assert.equal(data.urlFilteringRules.data.length, 5000);
  assert.equal(stub.requests.filter((request) => request.url.pathname === "/api/v1/urlFilteringRules").length, 50);

  const result = assessZiaPolicyData(data);
  assert.equal(findingById(result, "ZS-01").status, "warn");
  assert.match(findingById(result, "ZS-01").summary, /URL filtering rule inventory is partial \(5000 records over 50 pages, total unknown\)/);
  assert.equal(findingById(result, "ZS-17").status, "warn");
  assert.match(findingById(result, "ZS-17").summary, /inventory is partial/);
  assert.ok(result.truncated.some((note) => /urlFilteringRules: only 50 pages were read/.test(note)));

  const firewall = assessZiaPolicyData(policyFixture({ firewallRules: { ...policyFixture().firewallRules, truncated: true, seen: 50 } }));
  assert.equal(findingById(firewall, "ZS-02").status, "warn");
  assert.match(findingById(firewall, "ZS-02").summary, /firewall rule inventory is partial/);
});

test("assessZpa: authenticated connectors and service edges with a deleted lastBrokerConnectTime cap ZS-11 and ZS-21 at warn", () => {
  const undated = ({ lastBrokerConnectTime, ...rest }) => rest;
  const fixture = zpaFixture();
  fixture.appConnectors = readable(fixture.appConnectors.data.map(undated));
  fixture.serviceEdges = readable(fixture.serviceEdges.data.map(undated));
  const result = assessZpaData(fixture);
  assert.equal(findingById(result, "ZS-11").status, "warn");
  assert.match(findingById(result, "ZS-11").summary, /0 of 2 enabled connectors are authenticated with a broker connect time within 30 days; 2 authenticated but with no lastBrokerConnectTime/);
  assert.deepEqual(findingById(result, "ZS-11").evidence.authenticated_without_connect_time, ["connector-1", "connector-2"]);
  assert.equal(findingById(result, "ZS-21").status, "warn");
  assert.match(findingById(result, "ZS-21").summary, /1 authenticated but with no lastBrokerConnectTime/);
  assert.deepEqual(findingById(result, "ZS-21").evidence.authenticated_without_connect_time, ["edge-1"]);
});

test("assessZpa: stale_connector_days changes the ZS-11 and ZS-21 verdicts for over-threshold connect times", () => {
  const stale = (item) => ({ ...item, lastBrokerConnectTime: STALE_EPOCH_MS });
  const fixture = zpaFixture();
  fixture.appConnectors = readable(fixture.appConnectors.data.map(stale));
  fixture.serviceEdges = readable(fixture.serviceEdges.data.map(stale));

  const defaults = assessZpaData(fixture);
  assert.equal(findingById(defaults, "ZS-11").status, "warn");
  assert.match(findingById(defaults, "ZS-11").summary, /2 authenticated but with lastBrokerConnectTime older than 30 days/);
  assert.deepEqual(findingById(defaults, "ZS-11").evidence.stale, ["connector-1", "connector-2"]);
  assert.equal(findingById(defaults, "ZS-11").evidence.stale_connector_days, 30);
  assert.equal(findingById(defaults, "ZS-21").status, "warn");
  assert.match(findingById(defaults, "ZS-21").summary, /older than 30 days/);

  const strict = assessZpaData(fixture, { staleConnectorDays: 7 });
  assert.equal(findingById(strict, "ZS-11").status, "warn");
  assert.match(findingById(strict, "ZS-11").summary, /older than 7 days/);

  const relaxed = assessZpaData(fixture, { staleConnectorDays: 60 });
  assert.equal(findingById(relaxed, "ZS-11").status, "pass");
  assert.equal(findingById(relaxed, "ZS-11").evidence.stale_connector_days, 60);
  assert.deepEqual(findingById(relaxed, "ZS-11").evidence.stale, []);
  assert.equal(findingById(relaxed, "ZS-21").status, "pass");

  const disconnected = assessZpaData(zpaFixture({ serviceEdges: readable([{ id: "se-1", name: "edge-1", enabled: true, controlChannelStatus: "ZPN_STATUS_DISCONNECTED", lastBrokerConnectTime: RECENT_EPOCH_MS }]) }));
  assert.equal(findingById(disconnected, "ZS-21").status, "fail");
});

test("assessZiaPolicy: sub-location truncation caps ZS-18 at warn with parents read versus total", async () => {
  const locations = Array.from({ length: 150 }, (_, index) => compliantLocation(index + 1));
  const subLocations = locations.slice(0, 100).map((location) => ({ id: location.id + 1000, name: `${location.name} guest`, parentId: location.id, authRequired: true, sslScanEnabled: true, ofwEnabled: true }));
  const result = assessZiaPolicyData(policyFixture({ locations: readable(locations), subLocations: { data: subLocations, truncated: true, seen: 100, total: 150 } }));
  assert.equal(findingById(result, "ZS-18").status, "warn");
  assert.match(findingById(result, "ZS-18").summary, /Sub-locations were read for only 100 of 150 parent locations/);
  assert.equal(findingById(result, "ZS-18").evidence.sub_location_parents_read, 100);
  assert.equal(findingById(result, "ZS-18").evidence.sub_location_parents_total, 150);
  assert.equal(findingById(result, "ZS-18").evidence.partial_inventory, true);
  assert.ok(result.truncated.some((note) => /sublocations: only 100 of 150 parent locations were read/.test(note)));

  const calls = [];
  const client = {
    getResolvedConfig: () => ziaConfig(),
    getNow: () => NOW,
    listUrlFilteringRules: async () => ({ items: policyFixture().urlFilteringRules.data, truncated: false, pagesFetched: 1 }),
    listFirewallFilteringRules: async () => ({ items: policyFixture().firewallRules.data, truncated: false, pagesFetched: 1 }),
    listFirewallDnsRules: async () => policyFixture().dnsRules.data,
    listDlpEngines: async () => policyFixture().dlpEngines.data,
    listDlpDictionaries: async () => policyFixture().dlpDictionaries.data,
    listWebDlpRules: async () => policyFixture().webDlpRules.data,
    listSslInspectionRules: async () => policyFixture().sslInspectionRules.data,
    getSslExemptedUrls: async () => policyFixture().sslExemptedUrls.data,
    listSandboxRules: async () => policyFixture().sandboxRules.data,
    getSandboxAdvancedSettings: async () => policyFixture().sandboxSettings.data,
    getAdvancedThreatSettings: async () => policyFixture().advancedThreatSettings.data,
    getMalwarePolicy: async () => policyFixture().malwarePolicy.data,
    getMalwareSettings: async () => policyFixture().malwareSettings.data,
    getSecurityAllowlist: async () => policyFixture().securityAllowlist.data,
    getSecurityDenylist: async () => policyFixture().securityDenylist.data,
    listLocations: async () => ({ items: locations, truncated: false, pagesFetched: 1 }),
    listSubLocations: async (id) => { calls.push(id); return [{ id: Number(id) + 1000, name: `Site ${id} guest`, parentId: Number(id), authRequired: true, sslScanEnabled: true, ofwEnabled: true }]; },
    listGreTunnels: async () => ({ items: policyFixture().greTunnels.data, truncated: false, pagesFetched: 1 }),
    listVpnCredentials: async () => ({ items: policyFixture().vpnCredentials.data, truncated: false, pagesFetched: 1 }),
    listBandwidthControlRules: async () => policyFixture().bandwidthRules.data,
    listBrowserIsolationProfiles: async () => policyFixture().isolationProfiles.data,
    listCloudAppRuleTypes: async () => ["WEBMAIL"],
    listCloudAppRules: async () => policyFixture().cloudAppRules.data,
  };
  const collected = await assessZiaPolicy(client);
  assert.equal(calls.length, 100);
  assert.equal(findingById(collected, "ZS-18").status, "warn");
  assert.match(findingById(collected, "ZS-18").summary, /only 100 of 150 parent locations/);
  assert.equal(collected.summary.locations, 150);
  for (const item of collected.findings.filter((entry) => entry.id !== "ZS-18")) {
    assert.equal(item.status, "pass", `${item.id}: ${item.summary}`);
  }
});

test("assessZiaPolicy: sandbox evidence reads md5HashValueList and records fileHashesToBeBlocked only as legacy evidence", () => {
  const documented = assessZiaPolicyData(policyFixture());
  assert.equal(findingById(documented, "ZS-05").status, "pass");
  assert.equal(findingById(documented, "ZS-05").evidence.blocked_file_hashes, 1);
  assert.equal(findingById(documented, "ZS-05").evidence.legacy_file_hashes_to_be_blocked, null);

  const legacy = assessZiaPolicyData(policyFixture({ sandboxSettings: readable({ fileHashesToBeBlocked: ["abc", "def"] }) }));
  assert.equal(findingById(legacy, "ZS-05").evidence.blocked_file_hashes, 0);
  assert.equal(findingById(legacy, "ZS-05").evidence.legacy_file_hashes_to_be_blocked, 2);
});

test("assessZiaPolicy: firewall block rules without enableFullLogging in the response never count toward logging", () => {
  const withoutField = policyFixture().firewallRules.data.map(({ enableFullLogging, ...rule }) => rule);
  const absent = assessZiaPolicyData(policyFixture({ firewallRules: readable(withoutField) }));
  assert.equal(findingById(absent, "ZS-02").status, "pass");
  assert.match(findingById(absent, "ZS-02").summary, /block-rule logging was not evaluated for 2 rule\(s\) because enableFullLogging is absent/);
  assert.equal(findingById(absent, "ZS-02").evidence.block_rules_with_unknown_logging, 2);
  assert.equal(findingById(absent, "ZS-02").evidence.block_rules_without_full_logging, 0);
  assert.match(findingById(absent, "ZS-02").evidence.full_logging_field_source, /zscaler-sdk-go only/);

  const disabled = assessZiaPolicyData(policyFixture({ firewallRules: readable(policyFixture().firewallRules.data.map((rule) => ({ ...rule, enableFullLogging: false }))) }));
  assert.equal(findingById(disabled, "ZS-02").status, "warn");
  assert.match(findingById(disabled, "ZS-02").summary, /2 block rule\(s\) have full logging disabled/);
});

test("assessZiaAccessControl: adminScope.Type is read per the reference and adminScopeType only as legacy evidence", () => {
  const result = assessZiaAccessControlData(accessControlFixture({
    adminUsers: readable([
      { id: 1, loginName: "org@example.com", disabled: false, isPasswordLoginAllowed: false, adminScope: { Type: "ORGANIZATION", ScopeEntities: [] }, role: { id: 10, name: "Super Admin" } },
      { id: 2, loginName: "dept@example.com", disabled: false, isPasswordLoginAllowed: false, adminScope: { Type: "DEPARTMENT", ScopeEntities: [{ id: 5, name: "IT" }] }, role: { id: 11, name: "Policy Admin" } },
      { id: 3, loginName: "legacy@example.com", disabled: false, isPasswordLoginAllowed: false, adminScopeType: "ORGANIZATION", role: { id: 11, name: "Policy Admin" } },
      { id: 4, loginName: "unscoped@example.com", disabled: false, isPasswordLoginAllowed: false, role: { id: 11, name: "Policy Admin" } },
    ]),
  }), { maxSuperAdmins: 5 });
  const rbac = findingById(result, "ZS-07");
  assert.equal(rbac.status, "pass");
  assert.equal(rbac.evidence.organization_scoped_admins, 2);
  assert.equal(rbac.evidence.admins_scoped_via_legacy_field, 1);
  assert.equal(rbac.evidence.admins_without_scope, 1);
  assert.match(rbac.evidence.admin_scope_field_source, /adminScope\.Type per the published reference/);
  assert.match(rbac.summary, /2 are organization-scoped \(1 returned no adminScope and are not counted as scoped\)/);
});

test("assessZiaAccessControl: a 400 from GET /auditlogEntryReport renders ZS-14 manual naming the statusId requirement", async () => {
  const stub = ziaTenantFetch(ziaCompliantTenant(), { statusOverrides: { "/auditlogEntryReport": 400 } });
  const client = new ZiaApiClient(ziaConfig(), { fetchImpl: stub.fetchImpl, maxRetries: 0, now: () => NOW });
  const data = await collectZiaAccessControlData(client);
  assert.equal(data.auditLogReport.statusCode, 400);
  assert.equal(stub.requests.find((request) => request.url.pathname === "/api/v1/auditlogEntryReport").key, "GET /api/v1/auditlogEntryReport");

  const result = assessZiaAccessControlData(data);
  const audit = findingById(result, "ZS-14");
  assert.equal(audit.status, "manual");
  assert.match(audit.summary, /returned 400/);
  assert.match(audit.summary, /statusId as a required query parameter/);
  assert.match(audit.summary, /zscaler-sdk-go and zscaler-sdk-python send the same bare GET/);
  assert.equal(audit.evidence.documented_request_shape, "GET /auditlogEntryReport?statusId={export task id}");
  assert.equal(audit.evidence.nss_feeds, 1);
  assert.equal(findingById(result, "ZS-07").status, "pass");
  assert.ok(result.errors.some((error) => /auditlogEntryReport/.test(error)));
});

test("assessZpa: ZS-12 states that GET /administrators is documented only by zscaler-sdk-go", () => {
  const compliant = assessZpaData(zpaFixture());
  assert.equal(findingById(compliant, "ZS-12").status, "pass");
  assert.match(findingById(compliant, "ZS-12").summary, /documented only by zscaler-sdk-go, not by the published ZPA API reference/);
  assert.match(findingById(compliant, "ZS-12").evidence.zpa_administrators_surface, /never the sole basis for pass/);

  const unreadable = assessZpaData(zpaFixture({ administrators: { data: [], error: "ZPA GET /administrators failed (404): not found", statusCode: 404 } }));
  assert.equal(findingById(unreadable, "ZS-12").status, "warn");
  assert.match(findingById(unreadable, "ZS-12").summary, /GET \/administrators .*documented only by zscaler-sdk-go/);
});

test("schema: the real clients send exactly the documented path and query for every ZIA and ZPA endpoint the tools call", async () => {
  const ziaStub = ziaTenantFetch(ziaCompliantTenant());
  const zpaStub = zpaTenantFetch(zpaCompliantTenant());
  const zia = new ZiaApiClient(ziaConfig(), { fetchImpl: ziaStub.fetchImpl, maxRetries: 0, now: () => NOW });
  const zpa = new ZpaApiClient(zpaConfig(), { fetchImpl: zpaStub.fetchImpl, maxRetries: 0 });

  const access = await collectZiaAccessControlData(zia);
  const policy = await collectZiaPolicyData(zia);
  const zpaData = await collectZpaData(zpa);
  await zia.logout();
  for (const dataset of [...Object.values(access), ...Object.values(policy), ...Object.values(zpaData).filter((value) => value instanceof Date === false)]) {
    assert.equal(dataset.error, undefined, dataset.error);
  }

  const expectedZia = [
    "POST /api/v1/authenticatedSession",
    "GET /api/v1/adminUsers?includeAdminUsers=true&includeAuditorUsers=true&page=1&pageSize=1000",
    "GET /api/v1/adminRoles/lite?includeApiRole=true&includeAuditorRole=true&includePartnerRole=true",
    "GET /api/v1/authSettings",
    "GET /api/v1/passwordExpiry/settings",
    "GET /api/v1/auditlogEntryReport",
    "GET /api/v1/nssFeeds",
    "GET /api/v1/urlFilteringRules?page=1&pageSize=100",
    "GET /api/v1/urlFilteringRules?page=2&pageSize=100",
    "GET /api/v1/firewallFilteringRules?page=1&pageSize=5000",
    "GET /api/v1/firewallDnsRules",
    "GET /api/v1/dlpEngines",
    "GET /api/v1/dlpDictionaries",
    "GET /api/v1/webDlpRules",
    "GET /api/v1/sslInspectionRules",
    "GET /api/v1/sslSettings/exemptedUrls",
    "GET /api/v1/sandboxRules",
    "GET /api/v1/behavioralAnalysisAdvancedSettings",
    "GET /api/v1/cyberThreatProtection/advancedThreatSettings",
    "GET /api/v1/cyberThreatProtection/malwarePolicy",
    "GET /api/v1/cyberThreatProtection/malwareSettings",
    "GET /api/v1/security",
    "GET /api/v1/security/advanced",
    "GET /api/v1/locations?page=1&pageSize=1000",
    "GET /api/v1/locations/100/sublocations",
    "GET /api/v1/greTunnels?page=1&pageSize=1000",
    "GET /api/v1/vpnCredentials?includeOnlyWithoutLocation=false&page=1&pageSize=1000",
    "GET /api/v1/bandwidthControlRules",
    "GET /api/v1/browserIsolation/profiles",
    "GET /api/v1/webApplicationRules/ruleTypeMapping",
    "GET /api/v1/webApplicationRules/WEBMAIL",
    "DELETE /api/v1/authenticatedSession",
  ];
  assert.deepEqual([...new Set(ziaStub.requests.map((request) => request.key))].sort(), [...expectedZia].sort());
  assert.equal(ziaStub.requests.filter((request) => request.init.method === "POST").length, 1);

  const expectedZpa = [
    "POST /signin",
    `GET ${ZPA_V1}/application?page=1&pagesize=500`,
    `GET ${ZPA_V1}/segmentGroup?page=1&pagesize=500`,
    `GET ${ZPA_V1}/policySet/rules/policyType/ACCESS_POLICY?page=1&pagesize=500`,
    `GET ${ZPA_V1}/policySet/rules/policyType/TIMEOUT_POLICY?page=1&pagesize=500`,
    `GET ${ZPA_V1}/policySet/rules/policyType/CLIENT_FORWARDING_POLICY?page=1&pagesize=500`,
    `GET ${ZPA_V1}/policySet/rules/policyType/ISOLATION_POLICY?page=1&pagesize=500`,
    `GET ${ZPA_V1}/appConnectorGroup?page=1&pagesize=500`,
    `GET ${ZPA_V1}/connector?page=1&pagesize=500`,
    `GET ${ZPA_V1}/serviceEdgeGroup?page=1&pagesize=500`,
    `GET ${ZPA_V1}/serviceEdge?page=1&pagesize=500`,
    `GET ${ZPA_V2}/posture?page=1&pagesize=500`,
    `GET ${ZPA_V2}/network?page=1&pagesize=500`,
    `GET ${ZPA_V2}/idp?page=1&pagesize=500`,
    `GET ${ZPA_V2}/samlAttribute?page=1&pagesize=500`,
    `GET ${ZPA_USERCONFIG}/scimgroup/idpId/idp-1?page=1&pagesize=500`,
    `GET ${ZPA_V2}/enrollmentCert?page=1&pagesize=500`,
    `GET ${ZPA_V2}/clientlessCertificate/issued?page=1&pagesize=500`,
    `GET ${ZPA_V1}/emergencyAccess/users?pageSize=500`,
    `GET ${ZPA_V1}/emergencyAccess/users?pageId=cursor-2&pageSize=500`,
    `GET ${ZPA_V1}/administrators?page=1&pagesize=500`,
  ];
  assert.deepEqual([...new Set(zpaStub.requests.map((request) => request.key))].sort(), [...expectedZpa].sort());
  assert.ok(zpaStub.requests.every((request) => !request.url.pathname.includes("trustedNetwork") && !request.url.pathname.endsWith("/roles")));

  const accessCheck = await checkZscalerAccess({
    config: { zia: ziaConfig(), zpa: zpaConfig(), oneApiDetected: false, zdxDetected: false, timeoutMs: 30000, maxRetries: 0, sourceChain: [] },
    zia: new ZiaApiClient(ziaConfig(), { fetchImpl: ziaStub.fetchImpl, maxRetries: 0, now: () => NOW }),
    zpa: new ZpaApiClient(zpaConfig(), { fetchImpl: zpaStub.fetchImpl, maxRetries: 0 }),
  });
  assert.equal(accessCheck.status, "healthy");
  const known = new Set([...expectedZia, ...expectedZpa]);
  for (const request of [...ziaStub.requests, ...zpaStub.requests]) {
    assert.ok(known.has(request.key), `unexpected request ${request.key}`);
  }
});

test("self-check (a): every endpoint returning 403 through the real clients yields no pass", async () => {
  const ziaStub = ziaTenantFetch(ziaCompliantTenant(), { statusOverrides: Object.fromEntries([
    "/adminUsers", "/adminRoles/lite", "/authSettings", "/passwordExpiry/settings", "/auditlogEntryReport", "/nssFeeds", "/urlFilteringRules", "/firewallFilteringRules",
    "/firewallDnsRules", "/dlpEngines", "/dlpDictionaries", "/webDlpRules", "/sslInspectionRules", "/sslSettings/exemptedUrls", "/sandboxRules", "/behavioralAnalysisAdvancedSettings",
    "/cyberThreatProtection/advancedThreatSettings", "/cyberThreatProtection/malwarePolicy", "/cyberThreatProtection/malwareSettings", "/security", "/security/advanced", "/locations",
    "/greTunnels", "/vpnCredentials", "/bandwidthControlRules", "/browserIsolation/profiles", "/webApplicationRules/ruleTypeMapping",
  ].map((path) => [path, 403])) });
  const zpaStub = zpaTenantFetch(zpaCompliantTenant(), { statusOverrides: Object.fromEntries([
    "application", "segmentGroup", "policySet/rules/policyType/ACCESS_POLICY", "policySet/rules/policyType/TIMEOUT_POLICY", "policySet/rules/policyType/CLIENT_FORWARDING_POLICY",
    "policySet/rules/policyType/ISOLATION_POLICY", "appConnectorGroup", "connector", "serviceEdgeGroup", "serviceEdge", "posture", "network", "idp", "samlAttribute",
    "enrollmentCert", "clientlessCertificate/issued", "emergencyAccess/users", "administrators",
  ].map((path) => [path, 403])) });
  const zia = new ZiaApiClient(ziaConfig(), { fetchImpl: ziaStub.fetchImpl, maxRetries: 0, now: () => NOW });
  const zpa = new ZpaApiClient(zpaConfig(), { fetchImpl: zpaStub.fetchImpl, maxRetries: 0 });
  const findings = [
    ...(await assessZiaAccessControl(zia)).findings,
    ...(await assessZiaPolicy(zia)).findings,
    ...(await assessZpa(zpa)).findings,
  ];
  assert.equal(findings.length, 25);
  for (const item of findings) {
    assert.equal(item.status, "manual", `${item.id}: ${item.summary}`);
    assert.match(item.summary, /403/);
  }
});

test("self-check (b): empty inventories through the real clients pass only where emptiness is compliant", async () => {
  const emptyZia = ziaCompliantTenant();
  for (const key of Object.keys(emptyZia)) {
    if (Array.isArray(emptyZia[key])) emptyZia[key] = [];
  }
  emptyZia.subLocations = {};
  emptyZia.cloudAppRules = {};
  emptyZia.sslExemptedUrls = { urls: [] };
  emptyZia.sandboxSettings = {};
  emptyZia.securityAllowlist = {};
  emptyZia.securityDenylist = {};
  emptyZia.advancedThreatSettings = {};
  emptyZia.malwarePolicy = {};
  emptyZia.malwareSettings = {};
  emptyZia.authSettings = {};
  emptyZia.passwordExpiry = {};
  emptyZia.auditLogReport = {};
  emptyZia.ruleTypeMapping = {};
  const emptyZpa = zpaCompliantTenant();
  for (const key of Object.keys(emptyZpa)) {
    if (Array.isArray(emptyZpa[key])) emptyZpa[key] = [];
  }
  emptyZpa.scimGroups = {};
  emptyZpa.emergencyAccessPages = [{ items: [] }];

  const zia = new ZiaApiClient(ziaConfig(), { fetchImpl: ziaTenantFetch(emptyZia).fetchImpl, maxRetries: 0, now: () => NOW });
  const zpa = new ZpaApiClient(zpaConfig(), { fetchImpl: zpaTenantFetch(emptyZpa).fetchImpl, maxRetries: 0 });
  const findings = [
    ...(await assessZiaAccessControl(zia)).findings,
    ...(await assessZiaPolicy(zia)).findings,
    ...(await assessZpa(zpa)).findings,
  ];
  assert.equal(findings.length, 25);
  assert.deepEqual(findings.filter((item) => item.status === "pass").map((item) => item.id), []);
  const expected = {
    "ZS-01": "fail", "ZS-02": "fail", "ZS-03": "fail", "ZS-04": "fail", "ZS-05": "manual", "ZS-06": "manual", "ZS-07": "manual",
    "ZS-08": "fail", "ZS-09": "fail", "ZS-10": "fail", "ZS-11": "fail", "ZS-12": "fail", "ZS-13": "fail", "ZS-14": "warn", "ZS-15": "manual",
    "ZS-16": "manual", "ZS-17": "manual", "ZS-18": "manual", "ZS-19": "fail", "ZS-20": "fail", "ZS-21": "manual", "ZS-22": "manual",
    "ZS-23": "manual", "ZS-24": "manual", "ZS-25": "fail",
  };
  for (const item of findings) {
    assert.equal(item.status, expected[item.id], `${item.id}: ${item.summary}`);
  }
});

test("self-check (c): stale connectors, truncated sub-locations, capped rule reads, and unread ZPA pages never pass", async () => {
  const locations = Array.from({ length: 150 }, (_, index) => compliantLocation(index + 1));
  const stale = (item) => ({ ...item, lastBrokerConnectTime: STALE_EPOCH_MS });
  const ziaTenant = ziaCompliantTenant({
    locations,
    subLocations: Object.fromEntries(locations.map((location) => [location.id, [{ id: location.id + 1000, name: `${location.name} guest`, parentId: location.id, authRequired: true, sslScanEnabled: true, ofwEnabled: true }]])),
    urlFilteringRules: [
      { id: 1, name: "Block risky", order: 1, state: "ENABLED", action: "BLOCK", urlCategories: ["ANONYMIZER", "OTHER_SECURITY", "ADULT_THEMES", "PORNOGRAPHY", "GAMBLING"] },
      { id: 2, name: "Isolate uncategorized", order: 2, state: "ENABLED", action: "ISOLATE", urlCategories: ["MISCELLANEOUS_OR_UNKNOWN"] },
      ...Array.from({ length: 5001 }, (_, index) => urlRule(index + 3)),
    ],
  });
  const zpaBase = zpaCompliantTenant();
  const zpaTenant = zpaCompliantTenant({
    applicationTotalPages: 400,
    connector: zpaBase.connector.map(stale),
    serviceEdge: zpaBase.serviceEdge.map(stale),
  });
  const ziaStub = ziaTenantFetch(ziaTenant);
  const zpaStub = zpaTenantFetch(zpaTenant);
  const zia = new ZiaApiClient(ziaConfig(), { fetchImpl: ziaStub.fetchImpl, maxRetries: 0, now: () => NOW });
  const zpa = new ZpaApiClient(zpaConfig(), { fetchImpl: zpaStub.fetchImpl, maxRetries: 0, now: () => NOW });
  const policy = await assessZiaPolicy(zia);
  const zpaResult = await assessZpa(zpa);

  assert.equal(ziaStub.requests.filter((request) => request.url.pathname.endsWith("/sublocations")).length, 100);
  assert.equal(ziaStub.requests.filter((request) => request.url.pathname === "/api/v1/urlFilteringRules").length, 50);
  assert.equal(zpaStub.requests.filter((request) => request.url.pathname === `${ZPA_V1}/application`).length, 200);

  const affected = {
    "ZS-01": [policy, /URL filtering rule inventory is partial/],
    "ZS-17": [policy, /URL filtering rule inventory is partial/],
    "ZS-18": [policy, /Sub-locations were read for only 100 of 150 parent locations/],
    "ZS-08": [zpaResult, /inventory is partial \(200 records over 200 of 400 pages\)/],
    "ZS-11": [zpaResult, /2 authenticated but with lastBrokerConnectTime older than 30 days/],
    "ZS-21": [zpaResult, /1 authenticated but with lastBrokerConnectTime older than 30 days/],
  };
  for (const [id, [result, pattern]] of Object.entries(affected)) {
    const item = findingById(result, id);
    assert.equal(item.status, "warn", `${id}: ${item.summary}`);
    assert.match(item.summary, pattern);
  }
  assert.ok(policy.truncated.some((note) => /sublocations: only 100 of 150 parent locations were read/.test(note)));
  assert.ok(zpaResult.truncated.some((note) => /application: only 200 of 400 pages were read/.test(note)));
  const stillPassing = [...policy.findings, ...zpaResult.findings].filter((item) => item.status === "pass").map((item) => item.id).sort();
  assert.deepEqual(stillPassing, ["ZS-02", "ZS-03", "ZS-04", "ZS-05", "ZS-09", "ZS-10", "ZS-12", "ZS-13", "ZS-15", "ZS-16", "ZS-19", "ZS-20", "ZS-22", "ZS-23", "ZS-24", "ZS-25"]);
});

test("self-check (c): every paged dataset marked partial caps its dependent controls at warn or below", () => {
  const partial = (dataset) => ({ ...dataset, truncated: true, seen: 200, total: 201 });
  const access = accessControlFixture();
  access.adminUsers = partial(access.adminUsers);
  const policy = policyFixture();
  for (const key of ["urlFilteringRules", "firewallRules", "locations", "subLocations", "greTunnels", "vpnCredentials", "cloudAppRules"]) {
    policy[key] = partial(policy[key]);
  }
  const zpa = zpaFixture();
  for (const key of Object.keys(zpa)) {
    if (key !== "now") zpa[key] = partial(zpa[key]);
  }
  const findings = [
    ...assessZiaAccessControlData(access).findings,
    ...assessZiaPolicyData(policy).findings,
    ...assessZpaData(zpa).findings,
  ];
  const pagedControls = new Set(["ZS-01", "ZS-02", "ZS-04", "ZS-06", "ZS-07", "ZS-17", "ZS-18", "ZS-19", ...ZPA_CONTROL_IDS]);
  for (const item of findings) {
    if (pagedControls.has(item.id)) {
      assert.notEqual(item.status, "pass", `${item.id}: ${item.summary}`);
    }
  }
  const byId = (id) => findings.find((item) => item.id === id);
  assert.equal(byId("ZS-04").status, "warn");
  assert.match(byId("ZS-04").summary, /SSL scanning enabled on every location that was read\. The location inventory is partial/);
  assert.equal(byId("ZS-12").status, "warn");
  assert.match(byId("ZS-12").summary, /IdP inventory is partial/);
  assert.match(byId("ZS-12").summary, /ZPA administrator inventory is partial/);
  assert.equal(byId("ZS-15").status, "warn");
  assert.match(byId("ZS-15").summary, /trusted network inventory is partial/);
  assert.deepEqual(findings.filter((item) => item.status === "pass").map((item) => item.id).sort(), ["ZS-03", "ZS-05", "ZS-14", "ZS-16", "ZS-20", "ZS-25"]);
});

const PARTIAL_DATASET_DEPENDENTS = {
  access: {
    adminUsers: ["ZS-06", "ZS-07"],
  },
  policy: {
    urlFilteringRules: ["ZS-01", "ZS-17"],
    firewallRules: ["ZS-02"],
    locations: ["ZS-04", "ZS-18"],
    subLocations: ["ZS-18"],
    greTunnels: ["ZS-18"],
    vpnCredentials: ["ZS-18"],
    cloudAppRules: ["ZS-19"],
  },
  zpa: {
    applicationSegments: ["ZS-08"],
    segmentGroups: ["ZS-08"],
    accessRules: ["ZS-09", "ZS-10", "ZS-15"],
    timeoutRules: ["ZS-13"],
    forwardingRules: ["ZS-15", "ZS-22"],
    appConnectorGroups: ["ZS-11"],
    appConnectors: ["ZS-11"],
    serviceEdgeGroups: ["ZS-21"],
    serviceEdges: ["ZS-21"],
    postureProfiles: ["ZS-10"],
    trustedNetworks: ["ZS-15"],
    idpControllers: ["ZS-12"],
    samlAttributes: ["ZS-12"],
    scimGroups: ["ZS-12"],
    enrollmentCertificates: ["ZS-24"],
    browserAccessCertificates: ["ZS-24"],
    emergencyAccessUsers: ["ZS-23"],
    administrators: ["ZS-12"],
  },
};

test("self-check (c): a single partial dataset caps exactly the controls that read it, including secondary inventories", () => {
  const partial = (dataset) => ({ ...dataset, truncated: true, seen: 200, total: 201 });
  const suites = {
    access: [accessControlFixture, assessZiaAccessControlData],
    policy: [policyFixture, assessZiaPolicyData],
    zpa: [zpaFixture, assessZpaData],
  };
  for (const [suite, [build, assess]] of Object.entries(suites)) {
    const baselinePass = new Set(assess(build()).findings.filter((item) => item.status === "pass").map((item) => item.id));
    for (const [key, dependents] of Object.entries(PARTIAL_DATASET_DEPENDENTS[suite])) {
      const data = build();
      data[key] = partial(data[key]);
      const findings = assess(data).findings;
      for (const item of findings) {
        if (dependents.includes(item.id)) {
          assert.notEqual(item.status, "pass", `${suite}.${key} partial left ${item.id} at pass: ${item.summary}`);
          assert.equal(item.evidence.partial_inventory ?? item.evidence.location_inventory_partial, true, `${suite}.${key} partial not recorded on ${item.id}`);
          assert.match(item.summary, /is partial/, `${suite}.${key}: ${item.id} summary does not name the partial inventory`);
        } else if (baselinePass.has(item.id)) {
          assert.equal(item.status, "pass", `${suite}.${key} partial should not affect ${item.id}: ${item.summary}`);
        }
      }
    }
  }
  const zpa = zpaFixture();
  zpa.browserAccessCertificates = partial(zpa.browserAccessCertificates);
  const certificates = assessZpaData(zpa).findings.find((item) => item.id === "ZS-24");
  assert.equal(certificates.status, "warn");
  assert.match(certificates.summary, /browser access certificate inventory is partial \(\d+ records over 200 of 201 pages\)/);
  const idp = zpaFixture();
  idp.samlAttributes = partial(idp.samlAttributes);
  assert.match(assessZpaData(idp).findings.find((item) => item.id === "ZS-12").summary, /SAML attribute inventory is partial/);
  const connectors = zpaFixture();
  connectors.appConnectorGroups = partial(connectors.appConnectorGroups);
  assert.match(assessZpaData(connectors).findings.find((item) => item.id === "ZS-11").summary, /every enabled connector group that was read has at least two connected connectors\. The connector group inventory is partial/);
});

test("self-check (d): a compliant tenant served in Automation Hub shapes passes every automatable control, including ZS-15", async () => {
  const run = await runCompliantTenant();
  assert.equal(run.findings.length, 25);
  const passing = run.findings.filter((item) => item.status === "pass").map((item) => item.id).sort();
  assert.deepEqual(passing, AUTOMATABLE_CONTROL_IDS);
  assert.equal(passing.length, 24);
  assert.equal(findingById(run.access, "ZS-06").status, "manual");
  assert.match(findingById(run.access, "ZS-06").summary, /Per-admin MFA is not exposed by the API/);
  assert.equal(findingById(run.zpa, "ZS-15").status, "pass");
  assert.equal(findingById(run.zpa, "ZS-15").evidence.trusted_network_count, 1);
  assert.deepEqual(findingById(run.zpa, "ZS-15").evidence.rules_referencing_trusted_networks, ["Forward corp"]);
  assert.equal(findingById(run.zpa, "ZS-23").evidence.emergency_user_count, 2);
  assert.equal(findingById(run.policy, "ZS-01").evidence.rule_count, 101);
  assert.equal(findingById(run.policy, "ZS-18").evidence.sub_location_parents_read, 1);
  assert.equal(findingById(run.access, "ZS-07").evidence.organization_scoped_admins, 1);
  assert.equal(run.access.errors.length + run.policy.errors.length + run.zpa.errors.length, 0);
  assert.equal(run.policy.truncated.length + run.zpa.truncated.length, 0);
  assert.ok(run.zpaRequests.some((request) => request.key === `GET ${ZPA_V2}/network?page=1&pagesize=500`));
  assert.ok(run.zpaRequests.some((request) => request.key === `GET ${ZPA_V1}/emergencyAccess/users?pageId=cursor-2&pageSize=500`));
  assert.ok(run.ziaRequests.some((request) => request.key === "GET /api/v1/urlFilteringRules?page=2&pageSize=100"));
  assert.equal(run.ziaRequests.at(-1).key, "DELETE /api/v1/authenticatedSession");
});

// Rule 9 (bundle secret hygiene) and rule 10 (truncation on every cap exit) regression coverage.

test("redactForExport redacts documented and credential-shaped keys and keeps the benign fields the verdicts read", () => {
  const redacted = redactForExport({
    kerberosPwd: "bind-pw",
    scimSharedSecret: "scim",
    snmpCommunity: "public",
    provisioningKey: "prov",
    passwordHash: "hash",
    tunnelKey: "tunnel",
    bind_password: "bind",
    "api-key": "api",
    sharedSecret: "shared",
    accessToken: "token",
    passphrase: "phrase",
    credentialBlob: "blob",
    privateCertificate: "pem",
    comments: "psk is hunter2",
    comment: "psk is hunter2",
    numericPin: 1234,
    apiToken: 9876,
    isPasswordLoginAllowed: false,
    passwordExpiryDays: 90,
    passwordExpirationEnabled: true,
    publicKey: "ssh-rsa AAAA",
    privateIp: "10.0.0.5",
    tokenType: "Bearer",
    scimSharedSecretExists: true,
    privateKeyPresent: true,
    password_login_admins: ["a@example.com"],
    vpn_credentials: 3,
    vpnCredentials: { data: [{ id: 1, preSharedKey: "psk", fqdn: "hq@example.com" }] },
    nested: [{ password: "n", name: "keep" }],
    md5HashValueList: ["d41d8cd98f00b204e9800998ecf8427e"],
    emptyToken: "",
  });
  for (const key of ["kerberosPwd", "scimSharedSecret", "snmpCommunity", "provisioningKey", "passwordHash", "tunnelKey", "bind_password", "api-key", "sharedSecret", "accessToken", "passphrase", "credentialBlob", "privateCertificate", "comments", "comment", "apiToken"]) {
    assert.equal(redacted[key], "[REDACTED]", key);
  }
  assert.equal(redacted.numericPin, 1234);
  assert.equal(redacted.emptyToken, "[REDACTED]");
  assert.equal(redacted.isPasswordLoginAllowed, false);
  assert.equal(redacted.passwordExpiryDays, 90);
  assert.equal(redacted.passwordExpirationEnabled, true);
  assert.equal(redacted.publicKey, "ssh-rsa AAAA");
  assert.equal(redacted.privateIp, "10.0.0.5");
  assert.equal(redacted.tokenType, "Bearer");
  assert.equal(redacted.scimSharedSecretExists, true);
  assert.equal(redacted.privateKeyPresent, true);
  assert.deepEqual(redacted.password_login_admins, ["a@example.com"]);
  assert.equal(redacted.vpn_credentials, 3);
  assert.deepEqual(redacted.vpnCredentials, { data: [{ id: 1, preSharedKey: "[REDACTED]", fqdn: "hq@example.com" }] });
  assert.deepEqual(redacted.nested, [{ password: "[REDACTED]", name: "keep" }]);
  assert.deepEqual(redacted.md5HashValueList, ["d41d8cd98f00b204e9800998ecf8427e"]);
});

test("ZIA and ZPA clients never echo raw response bodies and scrub credential-shaped tokens from documented error fields", async () => {
  const longMessage = Array.from({ length: 60 }, (_, index) => `word${index % 10}`).join(" ");
  const ziaFetch = async (input, init = {}) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    const path = url.pathname.replace(/^\/api\/v1/, "");
    if (path === "/authenticatedSession") {
      return init.method === "POST" ? jsonResponse({ authType: "ADMIN_LOGIN" }, { headers: { "set-cookie": "JSESSIONID=SESSION; Path=/" } }) : jsonResponse({});
    }
    if (path === "/adminUsers") return new Response("<html>CANARYrawBody0001</html>", { status: 500, headers: { "content-type": "text/html" } });
    if (path === "/adminRoles/lite") {
      return jsonResponse({ code: "AUTHENTICATION_FAILED", message: `apiKey=CANARYkeyValue0002 rejected for CANARYlongToken0003 "password": "CANARYquoted0004" by INVALID_INPUT_ARGUMENT` }, { status: 401 });
    }
    if (path === "/authSettings") return jsonResponse({ message: longMessage }, { status: 403 });
    return jsonResponse({});
  };
  const zia = new ZiaApiClient(ziaConfig(), { fetchImpl: ziaFetch, maxRetries: 0 });
  await assert.rejects(() => zia.listAdminUsers(), (error) => {
    assert.match(error.message, /^ZIA GET \/adminUsers failed \(500\): non-JSON response body of \d+ bytes omitted$/);
    return true;
  });
  await assert.rejects(() => zia.listAdminRoles(), (error) => {
    assert.match(error.message, /^ZIA GET \/adminRoles\/lite failed \(401\): /);
    assert.match(error.message, /apiKey=\[REDACTED\]/);
    assert.match(error.message, /"password": "\[REDACTED\]"/);
    assert.match(error.message, /INVALID_INPUT_ARGUMENT/);
    assert.match(error.message, /AUTHENTICATION_FAILED/);
    assert.ok(!error.message.includes("CANARY"), error.message);
    return true;
  });
  await assert.rejects(() => zia.getAuthSettings(), (error) => {
    assert.ok(error.message.length <= "ZIA GET /authSettings failed (403): ".length + 160, error.message);
    return true;
  });

  const zpaFetch = async (input) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    if (url.pathname === "/signin") return jsonResponse({ id: "err", reason: "client_secret=CANARYsecret0005 invalid for CANARYcustomer0006" }, { status: 401 });
    return jsonResponse({});
  };
  await assert.rejects(() => new ZpaApiClient(zpaConfig(), { fetchImpl: zpaFetch, maxRetries: 0 }).listApplicationSegments(), (error) => {
    assert.match(error.message, /^ZPA signin failed \(401\): client_secret=\[REDACTED\] invalid for \[REDACTED\]$/);
    return true;
  });
});

function walkFiles(dir) {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => (entry.isDirectory() ? walkFiles(join(dir, entry.name)) : [join(dir, entry.name)]));
}

function zipEntries(zipPath) {
  const buffer = readFileSync(zipPath);
  let eocd = buffer.length - 22;
  while (eocd >= 0 && buffer.readUInt32LE(eocd) !== 0x06054b50) eocd -= 1;
  assert.ok(eocd >= 0, "zip end of central directory record not found");
  const entryCount = buffer.readUInt16LE(eocd + 10);
  let offset = buffer.readUInt32LE(eocd + 16);
  const entries = [];
  for (let index = 0; index < entryCount; index += 1) {
    assert.equal(buffer.readUInt32LE(offset), 0x02014b50, "central directory header expected");
    const method = buffer.readUInt16LE(offset + 10);
    const compressedSize = buffer.readUInt32LE(offset + 20);
    const nameLength = buffer.readUInt16LE(offset + 28);
    const extraLength = buffer.readUInt16LE(offset + 30);
    const commentLength = buffer.readUInt16LE(offset + 32);
    const localOffset = buffer.readUInt32LE(offset + 42);
    const name = buffer.subarray(offset + 46, offset + 46 + nameLength).toString("utf8");
    assert.equal(buffer.readUInt32LE(localOffset), 0x04034b50, "local file header expected");
    const dataStart = localOffset + 30 + buffer.readUInt16LE(localOffset + 26) + buffer.readUInt16LE(localOffset + 28);
    const compressed = buffer.subarray(dataStart, dataStart + compressedSize);
    entries.push({ name, content: (method === 8 ? inflateRawSync(compressed) : compressed).toString("utf8") });
    offset += 46 + nameLength + extraLength + commentLength;
  }
  return entries;
}

const CANARIES = {
  ziaApiKey: "CANARYziaApiKey0001ABCDEFGHIJKLMNOP",
  ziaPassword: "CANARYziaPassword0002",
  zpaClientSecret: "CANARYzpaClientSecret0003",
  sessionCookie: "CANARYsessionCookie0004",
  accessToken: "CANARYaccessToken0005",
  adminPassword: "CANARYadminPassword0006",
  adminTmpPassword: "CANARYadminTmpPassword0007",
  kerberosPwd: "CANARYkerberosPwd0008",
  nssToken: "CANARYnssToken0009",
  preSharedKey: "CANARYpreSharedKey0010",
  vpnComments: "CANARYvpnComments0011",
  greComment: "CANARYgreComment0012",
  snmpCommunity: "CANARYsnmpCommunity0013",
  provisioningKey: "CANARYprovisioningKey0014",
  passwordHash: "CANARYpasswordHash0015",
  tunnelKey: "CANARYtunnelKey0016",
  sandboxToken: "CANARYsandboxApiToken0017",
  sharedSecret: "CANARYsharedSecret0018",
  passphrase: "CANARYpassphrase0019",
  credentialBlob: "CANARYcredentialBlob0020",
  ziaErrorEcho: "CANARYerrorBodyEcho0021",
  ziaRawBody: "CANARYrawBody0022",
  scimSharedSecret: "CANARYscimSharedSecret0023",
  zrsaPrivateKey: "CANARYzrsaPrivateKey0024",
  zrsaSessionKey: "CANARYzrsaSessionKey0025",
  enrollmentPrivateKey: "CANARYenrollmentPrivateKey0026",
  browserAccessPrivateKey: "CANARYbaPrivateKey0027",
  zpaAdminPassword: "CANARYzpaAdminPassword0028",
  zpaAdminTmpPassword: "CANARYzpaAdminTmpPassword0029",
  zpaAdminSessionToken: "CANARYzpaAdminSessionToken0030",
  connectorProvisioningKey: "CANARYconnectorProvisioningKey0031",
  zpaErrorEcho: "CANARYzpaErrorEcho0032",
};

function canaryZiaTenant() {
  const tenant = ziaCompliantTenant();
  tenant.adminUsers[0].password = CANARIES.adminPassword;
  tenant.adminUsers[0].tmpPassword = CANARIES.adminTmpPassword;
  tenant.adminUsers[1].passwordHash = CANARIES.passwordHash;
  tenant.authSettings.kerberosPwd = CANARIES.kerberosPwd;
  tenant.nssFeeds[0].authenticationToken = CANARIES.nssToken;
  tenant.vpnCredentials[0].preSharedKey = CANARIES.preSharedKey;
  tenant.vpnCredentials[0].comments = CANARIES.vpnComments;
  tenant.greTunnels[0].comment = CANARIES.greComment;
  tenant.greTunnels[0].tunnelKey = CANARIES.tunnelKey;
  tenant.locations[0].snmpCommunity = CANARIES.snmpCommunity;
  tenant.locations[0].passphrase = CANARIES.passphrase;
  tenant.isolationProfiles[0].provisioningKey = CANARIES.provisioningKey;
  tenant.sandboxSettings.sandboxApiToken = CANARIES.sandboxToken;
  tenant.dlpDictionaries[0].sharedSecret = CANARIES.sharedSecret;
  tenant.urlFilteringRules[0].credentialBlob = CANARIES.credentialBlob;
  return tenant;
}

function canaryZpaTenant() {
  const tenant = zpaCompliantTenant();
  tenant.idp[0].scimSharedSecret = CANARIES.scimSharedSecret;
  tenant.enrollmentCert[0].zrsaencryptedprivatekey = CANARIES.zrsaPrivateKey;
  tenant.enrollmentCert[0].zrsaencryptedsessionkey = CANARIES.zrsaSessionKey;
  tenant.enrollmentCert[1].privateKey = CANARIES.enrollmentPrivateKey;
  tenant.clientlessCertificate[0].privateKey = CANARIES.browserAccessPrivateKey;
  tenant.administrators[0].password = CANARIES.zpaAdminPassword;
  tenant.administrators[0].tmpPassword = CANARIES.zpaAdminTmpPassword;
  tenant.administrators[0].sessionToken = CANARIES.zpaAdminSessionToken;
  tenant.appConnectorGroup[0].provisioningKey = CANARIES.connectorProvisioningKey;
  tenant.connector[0].privateIp = "10.0.0.5";
  tenant.connector[0].publicKey = "PUBLIC-KEY-MATERIAL-STAYS";
  return tenant;
}

test("exportZscalerAuditBundle leaks no canary from any credential carrier into any bundle file or zip entry (rule 9)", async () => {
  const base = createTempBase("grclanker-zscaler-canary-");
  const ziaStub = ziaTenantFetch(canaryZiaTenant());
  const zpaStub = zpaTenantFetch(canaryZpaTenant());
  const ziaFetch = async (input, init = {}) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    const path = url.pathname.replace(/^\/api\/v1/, "");
    if (path === "/authenticatedSession" && init.method === "POST") {
      return jsonResponse({ authType: "ADMIN_LOGIN" }, { headers: { "set-cookie": `JSESSIONID=${CANARIES.sessionCookie}; Path=/; Secure; HttpOnly` } });
    }
    if (path === "/auditlogEntryReport") return jsonResponse({ code: "AUTHENTICATION_FAILED", message: `session ${CANARIES.ziaErrorEcho} rejected` }, { status: 401 });
    if (path === "/bandwidthControlRules") return new Response(`<html>${CANARIES.ziaRawBody}</html>`, { status: 500, headers: { "content-type": "text/html" } });
    return ziaStub.fetchImpl(input, init);
  };
  const zpaFetch = async (input, init = {}) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    if (url.pathname === "/signin") return jsonResponse({ token_type: "Bearer", access_token: CANARIES.accessToken, expires_in: "3600" });
    if (url.pathname === `${ZPA_V2}/posture`) return jsonResponse({ id: "err", reason: `${CANARIES.zpaErrorEcho} forbidden` }, { status: 403 });
    return zpaStub.fetchImpl(input, init);
  };
  const ziaCanaryConfig = { ...ziaConfig(), apiKey: CANARIES.ziaApiKey, password: CANARIES.ziaPassword };
  const zpaCanaryConfig = { ...zpaConfig(), clientSecret: CANARIES.zpaClientSecret };
  const config = { zia: ziaCanaryConfig, zpa: zpaCanaryConfig, oneApiDetected: false, zdxDetected: false, timeoutMs: 30000, maxRetries: 0, sourceChain: [] };
  const zia = new ZiaApiClient(ziaCanaryConfig, { fetchImpl: ziaFetch, maxRetries: 0, now: () => NOW });
  const zpa = new ZpaApiClient(zpaCanaryConfig, { fetchImpl: zpaFetch, maxRetries: 0, now: () => NOW });
  const result = await exportZscalerAuditBundle({ config, zia, zpa }, { outputDir: base });

  const files = walkFiles(result.outputDir);
  assert.ok(files.length >= 20, `only ${files.length} files written`);
  assert.equal(files.length, result.fileCount);
  const leaks = [];
  for (const file of files) {
    const content = readFileSync(file, "utf8");
    for (const [carrier, canary] of Object.entries(CANARIES)) {
      if (content.includes(canary)) leaks.push(`${relative(result.outputDir, file)}: ${carrier}`);
    }
    assert.ok(!/JSESSIONID=(?!\[REDACTED\])/.test(content), `${file} carries a session cookie`);
  }
  assert.deepEqual(leaks, []);

  const entries = zipEntries(result.zipPath).filter((entry) => !entry.name.endsWith("/"));
  assert.equal(entries.length, files.length);
  const zipLeaks = [];
  for (const entry of entries) {
    for (const [carrier, canary] of Object.entries(CANARIES)) {
      if (entry.content.includes(canary)) zipLeaks.push(`${entry.name}: ${carrier}`);
    }
  }
  assert.deepEqual(zipLeaks, []);

  const ziaAccess = JSON.parse(readFileSync(join(result.outputDir, "core_data/zia_access_control.json"), "utf8"));
  assert.equal(ziaAccess.authSettings.data.kerberosPwd, "[REDACTED]");
  assert.equal(ziaAccess.authSettings.data.samlEnabled, true);
  assert.equal(ziaAccess.adminUsers.data[0].isPasswordLoginAllowed, false);
  assert.equal(ziaAccess.passwordExpiry.data.passwordExpiryDays, 90);
  assert.match(ziaAccess.auditLogReport.error, /failed \(401\): session \[REDACTED\] rejected; AUTHENTICATION_FAILED$/);
  const ziaPolicy = JSON.parse(readFileSync(join(result.outputDir, "core_data/zia_policy.json"), "utf8"));
  assert.equal(ziaPolicy.vpnCredentials.data[0].preSharedKey, "[REDACTED]");
  assert.equal(ziaPolicy.vpnCredentials.data[0].comments, "[REDACTED]");
  assert.equal(ziaPolicy.vpnCredentials.data[0].fqdn, "hq@example.com");
  assert.equal(ziaPolicy.greTunnels.data[0].comment, "[REDACTED]");
  assert.equal(ziaPolicy.greTunnels.data[0].sourceIp, "203.0.113.10");
  assert.match(ziaPolicy.bandwidthRules.error, /failed \(500\): non-JSON response body of \d+ bytes omitted/);
  const zpaData = JSON.parse(readFileSync(join(result.outputDir, "core_data/zpa.json"), "utf8"));
  assert.equal(zpaData.idpControllers.data[0].scimSharedSecret, "[REDACTED]");
  assert.equal(zpaData.idpControllers.data[0].scimEnabled, true);
  assert.equal(zpaData.appConnectors.data[0].privateIp, "10.0.0.5");
  assert.equal(zpaData.appConnectors.data[0].publicKey, "PUBLIC-KEY-MATERIAL-STAYS");
  assert.match(zpaData.postureProfiles.error, /failed \(403\): \[REDACTED\] forbidden$/);
  const findings = JSON.parse(readFileSync(join(result.outputDir, "analysis/findings.json"), "utf8"));
  assert.equal(findings.length, 25);
  assert.deepEqual(findings.find((item) => item.id === "ZS-06").evidence.password_login_admins, []);
  const auditFinding = findings.find((item) => item.id === "ZS-14");
  assert.equal(auditFinding.status, "manual");
  assert.match(auditFinding.summary, /returned 401/);
  assert.match(auditFinding.evidence.error, /session \[REDACTED\] rejected/);
  assert.equal(findings.find((item) => item.id === "ZS-10").status, "manual");
  const errorLog = readFileSync(join(result.outputDir, "_errors.log"), "utf8");
  assert.match(errorLog, /auditlogEntryReport/);
  assert.match(errorLog, /posture/);
  assert.match(errorLog, /bandwidthControlRules/);
  const accessCheck = readFileSync(join(result.outputDir, "core_data/access_check.json"), "utf8");
  assert.match(accessCheck, /\[REDACTED\] forbidden/);
  assert.match(accessCheck, /session \[REDACTED\] rejected/);
  assert.equal(result.errorCount, errorLog.trimEnd().split("\n").length);
});

function zpaFetchIntercepting(tenant, interceptor) {
  const stub = zpaTenantFetch(tenant);
  const requests = [];
  const fetchImpl = async (input, init = {}) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    const suffix = url.pathname.replace(`${ZPA_V1}/`, "").replace(`${ZPA_V2}/`, "");
    const intercepted = url.pathname === "/signin" ? undefined : interceptor(suffix, url);
    if (!intercepted) return stub.fetchImpl(input, init);
    requests.push({ key: requestKey(url, init), url, init });
    return intercepted;
  };
  return { fetchImpl, requests };
}

function segment(id) {
  return { id: `seg-${id}`, name: `Segment ${id}`, enabled: true, domainNames: [`app-${id}.corp.example.com`], tcpPortRange: [{ from: "443", to: "443" }], segmentGroupId: "sg-1", bypassType: "NEVER" };
}

test("ZpaApiClient treats a missing totalPages as an unknown total: full pages keep paging, a repeated page is truncated, and ZS-08 stays below pass (rule 10)", async () => {
  const segments = Array.from({ length: 1200 }, (_, index) => segment(index + 1));
  const untotaled = zpaFetchIntercepting(zpaCompliantTenant(), (suffix, url) => {
    if (suffix !== "application") return undefined;
    const page = Number(url.searchParams.get("page") ?? "1");
    return jsonResponse({ list: segments.slice((page - 1) * 500, page * 500) });
  });
  const complete = await assessZpa(new ZpaApiClient(zpaConfig(), { fetchImpl: untotaled.fetchImpl, maxRetries: 0, now: () => NOW }));
  assert.equal(untotaled.requests.filter((request) => request.url.pathname === `${ZPA_V1}/application`).length, 3);
  assert.equal(findingById(complete, "ZS-08").status, "pass");
  assert.equal(findingById(complete, "ZS-08").evidence.segment_count ?? findingById(complete, "ZS-08").evidence.enabled_segments ?? 1200, 1200);
  assert.equal(complete.truncated.length, 0);

  const stuck = zpaFetchIntercepting(zpaCompliantTenant(), (suffix) => (suffix === "application" ? jsonResponse({ list: segments.slice(0, 500) }) : undefined));
  const client = new ZpaApiClient(zpaConfig(), { fetchImpl: stuck.fetchImpl, maxRetries: 0, now: () => NOW });
  const paged = await client.listApplicationSegments();
  assert.equal(paged.items.length, 500);
  assert.equal(paged.truncated, true);
  assert.equal(paged.totalPages, undefined);
  assert.equal(paged.pagesFetched, 2);
  const partial = await assessZpa(client);
  const finding = findingById(partial, "ZS-08");
  assert.equal(finding.status, "warn");
  assert.equal(finding.evidence.partial_inventory, true);
  assert.match(finding.summary, /application segment inventory is partial \(500 records over 2 pages, total unknown\)/);
  assert.ok(partial.truncated.some((note) => /^application: only 2 pages were read and the total is unknown/.test(note)), partial.truncated.join("\n"));

  let served = 0;
  const endless = zpaFetchIntercepting(zpaCompliantTenant(), (suffix, url) => {
    if (suffix !== "application") return undefined;
    served += 1;
    const page = Number(url.searchParams.get("page") ?? "1");
    return jsonResponse({ list: Array.from({ length: 500 }, (_, index) => segment(page * 1000 + index)) });
  });
  const capped = await new ZpaApiClient(zpaConfig(), { fetchImpl: endless.fetchImpl, maxRetries: 0, now: () => NOW }).listApplicationSegments();
  assert.equal(served, 200);
  assert.equal(capped.truncated, true);
  assert.equal(capped.totalPages, undefined);
  assert.equal(capped.items.length, 100000);
});

test("ZpaApiClient pages a bare array until a short page and reports a repeating full array as truncated, capping ZS-08 and ZS-12 (rule 10)", async () => {
  const groups = Array.from({ length: 500 }, (_, index) => ({ id: `sg-${index + 1}`, name: `Group ${index + 1}`, enabled: true }));
  const bare = zpaFetchIntercepting(zpaCompliantTenant(), (suffix, url) => {
    if (suffix !== "segmentGroup") return undefined;
    return jsonResponse(Number(url.searchParams.get("page") ?? "1") === 1 ? groups : []);
  });
  const client = new ZpaApiClient(zpaConfig(), { fetchImpl: bare.fetchImpl, maxRetries: 0, now: () => NOW });
  const paged = await client.listSegmentGroups();
  assert.equal(paged.items.length, 500);
  assert.equal(paged.truncated, false);
  assert.equal(paged.pagesFetched, 2);
  assert.deepEqual(bare.requests.filter((request) => request.url.pathname === `${ZPA_V1}/segmentGroup`).map((request) => request.key), [
    `GET ${ZPA_V1}/segmentGroup?page=1&pagesize=500`,
    `GET ${ZPA_V1}/segmentGroup?page=2&pagesize=500`,
  ]);
  const short = await client.listTrustedNetworks();
  assert.equal(short.truncated, false);
  assert.equal(short.pagesFetched, 1);

  const repeating = zpaFetchIntercepting(zpaCompliantTenant(), (suffix) => {
    if (suffix === "segmentGroup") return jsonResponse(groups);
    if (suffix === "idp") return jsonResponse(Array.from({ length: 500 }, (_, index) => ({ id: `idp-${index + 1}`, name: `IdP ${index + 1}`, enabled: true, ssoType: ["USER"], scimEnabled: true, signSamlRequest: "1" })));
    return undefined;
  });
  const result = await assessZpa(new ZpaApiClient(zpaConfig(), { fetchImpl: repeating.fetchImpl, maxRetries: 0, now: () => NOW }));
  for (const id of ["ZS-08", "ZS-12"]) {
    const item = findingById(result, id);
    assert.notEqual(item.status, "pass", id);
    assert.equal(item.evidence.partial_inventory, true, id);
  }
  assert.ok(result.truncated.some((note) => /^segmentGroup: only 2 pages were read and the total is unknown/.test(note)), result.truncated.join("\n"));
  assert.ok(result.truncated.some((note) => /^idp: only 2 pages were read and the total is unknown/.test(note)), result.truncated.join("\n"));
});
