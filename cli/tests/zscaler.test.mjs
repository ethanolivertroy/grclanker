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
  assessZiaPolicy,
  assessZiaPolicyData,
  assessZpa,
  assessZpaData,
  checkZscalerAccess,
  exportZscalerAuditBundle,
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
    sandboxSettings: readable({ fileHashesToBeBlocked: ["abc"] }),
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
    listUrlFilteringRules: async () => [],
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
    listGreTunnels: async () => [],
    listVpnCredentials: async () => [],
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
    { id: "c-2", name: "connector-2", enabled: true, controlChannelStatus: "ZPN_STATUS_UNKNOWN", appConnectorGroupName: "DC East" },
  ]);
  fixture.enrollmentCertificates = readable([{ id: "ec-1", name: "Connector", validToInEpochSec: FUTURE_EPOCH }, { id: "ec-2", name: "Undated" }]);
  const result = assessZpaData(fixture);
  assert.equal(findingById(result, "ZS-08").status, "warn");
  assert.match(findingById(result, "ZS-08").summary, /inventory is partial/);
  assert.equal(findingById(result, "ZS-09").status, "warn");
  assert.equal(findingById(result, "ZS-10").status, "warn");
  assert.equal(findingById(result, "ZS-11").status, "warn");
  assert.match(findingById(result, "ZS-11").summary, /no lastBrokerConnectTime/);
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
