import test from "node:test";
import assert from "node:assert/strict";
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  symlinkSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  CLOUDFLARE_RULESET_PHASES,
  CLOUDFLARE_ZONE_SETTING_IDS,
  CloudflareApiClient,
  CloudflareApiError,
  assessCloudflareIdentity,
  assessCloudflareTrafficControls,
  assessCloudflareZoneSecurity,
  checkCloudflareAccess,
  cloudflareFixedTexts,
  displayPath,
  exportCloudflareAuditBundle,
  labelIdentifier,
  redactCarrierText,
  redactErrorText,
  resolveCloudflareConfiguration,
  resolveSecureOutputPath,
  scrubSnapshotValue,
} from "../dist/extensions/grc-tools/cloudflare.js";
import { readBundleFiles, readZipEntries } from "./helpers/bundle-contents.mjs";
import {
  CANARY_VALUES,
  ENCODED_FORM_SECRET,
  HTML_BODY_NOTE,
  PARSER_SNIPPET_CANARY,
  PARSER_WORDING,
  REDACTED_CANARY_URL,
  SHORT_BODY_CANARY,
  SHORT_BODY_CONTENT_TYPE,
  assertCanaryFixture,
  assertNoCanaryWindows,
  assertNoCanaryWindowsInFiles,
  assertNoShortBodyFragments,
  assertRedactionCases,
  assertScrubBoundary,
  assertShortBodyRecordedAsNote,
  htmlCanaryBody,
  jsonCanaryMessage,
  parserMessageFor,
  parserSnippetBody,
  shortBodyResponse,
} from "./helpers/error-canaries.mjs";
import {
  BEARER_ID_CARRIER_CONTROL_ROWS,
  BEARER_ID_VALUES,
  DEPTH_CONTROL,
  ESCAPED_HEADER_LINES,
  JSON_ESCAPES,
  MASKED_HEX_ID_GROUP,
  QUOTED_NON_CREDENTIAL_GROUP,
  SERVER_ASSIGNED_HEX_IDS,
  assertBearerIdKeyRows,
  assertBearerIdSnapshotKeys,
  assertCarrierTextScrub,
  assertCredentialPairValuesRemoved,
  assertDepthControl,
  assertDepthControlOutputs,
  assertEscapedHeaderCarriers,
  assertFixedTextsSurvive,
  assertHexIdentifierPolicy,
  assertIdentifierKeyRows,
  assertFlagAndPathPairRows,
  assertUrlUserinfoBoundaryRows,
  assertMustKeepRows,
  assertMustRedactRowsBesideMustKeep,
  withPlantedRoutes,
} from "./helpers/redaction-table.mjs";

function createTempBase(prefix) {
  return mkdtempSync(join(tmpdir(), prefix));
}

function sampleConfig(overrides = {}) {
  return {
    apiToken: "token-123",
    accountId: "acc-123",
    baseUrl: "https://api.cloudflare.com/client/v4",
    timeoutMs: 30000,
    authMethod: "token",
    sourceChain: ["tests"],
    ...overrides,
  };
}

function forbidden(path) {
  const error = new Error(`Cloudflare request failed for ${path} (403 Forbidden): Authentication error`);
  error.status = 403;
  return error;
}

const FUTURE = "2027-12-31T00:00:00Z";
const RECENT = new Date(Date.now() - 2 * 86_400_000).toISOString();

function compliantSettings() {
  return [
    { id: "ssl", value: "strict" },
    { id: "min_tls_version", value: "1.2" },
    { id: "always_use_https", value: "on" },
    { id: "automatic_https_rewrites", value: "on" },
    { id: "security_header", value: { strict_transport_security: { enabled: true, max_age: 31536000, include_subdomains: true, preload: true, nosniff: true } } },
    { id: "browser_check", value: "on" },
    { id: "email_obfuscation", value: "on" },
    { id: "tls_client_auth", value: "on" },
  ];
}

function compliantEntrypoint(phase) {
  switch (phase) {
    case CLOUDFLARE_RULESET_PHASES.firewallManaged:
      return { id: "rs-managed", phase, kind: "zone", rules: [{ id: "r1", action: "execute", enabled: true, expression: "true", action_parameters: { id: "efb7b8c949ac4650a09736fc376e9aee", overrides: { enabled: true } } }] };
    case CLOUDFLARE_RULESET_PHASES.firewallCustom:
      return { id: "rs-custom", phase, kind: "zone", rules: [{ id: "r2", action: "block", enabled: true, expression: "(cf.threat_score gt 50)" }] };
    case CLOUDFLARE_RULESET_PHASES.ddosL7:
      return { id: "rs-ddos", phase, kind: "zone", rules: [{ id: "r3", action: "execute", enabled: true, expression: "true", action_parameters: { id: "4d21379b4f9f4bb088e0729962c8b3cf", overrides: { sensitivity_level: "default" } } }] };
    case CLOUDFLARE_RULESET_PHASES.responseHeadersTransform:
      return {
        id: "rs-headers",
        phase,
        kind: "zone",
        rules: [{
          id: "r4",
          action: "rewrite",
          enabled: true,
          expression: "true",
          action_parameters: {
            headers: {
              "Content-Security-Policy": { operation: "set", value: "default-src 'self'" },
              "X-Frame-Options": { operation: "set", value: "DENY" },
              "X-Content-Type-Options": { operation: "set", value: "nosniff" },
              "Referrer-Policy": { operation: "set", value: "strict-origin-when-cross-origin" },
            },
          },
        }],
      };
    case CLOUDFLARE_RULESET_PHASES.rateLimit:
      return { id: "rs-rl", phase, kind: "zone", rules: [{ id: "r5", action: "block", enabled: true, expression: "http.request.uri.path contains \"/login\"", ratelimit: { characteristics: ["ip.src"], period: 60, requests_per_period: 20, mitigation_timeout: 600 } }] };
    default:
      return null;
  }
}

/**
 * Fixture modes: "compliant" (d), "forbidden" (a), "empty" (b), "partial" (c).
 */
function fixtureClient(mode, overrides = {}) {
  const zones = mode === "empty"
    ? []
    : mode === "partial"
      ? [{ id: "zone-1", name: "one.example" }, { id: "zone-2", name: "two.example" }]
      : [{ id: "zone-1", name: "one.example" }];
  const forbiddenZone = mode === "partial" ? "zone-2" : undefined;
  const list = (path, items, total) => {
    if (mode === "forbidden") throw forbidden(path);
    if (mode === "empty") return { items: [], truncated: false, totalCount: 0 };
    if (mode === "partial") return { items, truncated: true, totalCount: total ?? items.length + 5 };
    return { items, truncated: false, totalCount: items.length };
  };
  const single = (path, zoneId, value) => {
    if (mode === "forbidden" || zoneId === forbiddenZone) throw forbidden(path);
    return value;
  };

  const client = {
    getResolvedConfig: () => sampleConfig(),
    async verifyCurrentToken() {
      if (mode === "forbidden") throw forbidden("/user/tokens/verify");
      return { id: "tok-current", status: "active", expires_on: FUTURE, not_before: "2026-01-01T00:00:00Z" };
    },
    async getUserToken(tokenId) {
      if (mode === "forbidden") throw forbidden(`/user/tokens/${tokenId}`);
      return { id: tokenId, status: "active", expires_on: FUTURE, policies: [{ id: "p1", effect: "allow", permission_groups: [{ id: "pg1", name: "Zone Read" }], resources: { "com.cloudflare.api.account.zone.zone-1": "*" } }] };
    },
    async listAccounts() {
      if (mode === "forbidden") throw forbidden("/accounts");
      return { items: [{ id: "acc-123", name: "Example", type: "standard", settings: { enforce_twofactor: true } }], truncated: false, totalCount: 1 };
    },
    async listZones() {
      if (mode === "forbidden") throw forbidden("/zones");
      if (mode === "partial") return { items: zones, truncated: true, totalCount: 7 };
      return { items: zones, truncated: false, totalCount: zones.length };
    },
    async listUserTokens() {
      return list("/user/tokens", [
        { id: "tok-1", name: "audit", status: "active", expires_on: FUTURE, last_used_on: RECENT, issued_on: "2026-01-01T00:00:00Z", policies: [] },
        { id: "tok-2", name: "old", status: "expired", expires_on: "2025-01-01T00:00:00Z", policies: [] },
      ]);
    },
    async listAccountTokens() {
      return list("/accounts/acc-123/tokens", [{ id: "atok-1", name: "ci", status: "active", expires_on: FUTURE, last_used_on: RECENT, policies: [] }]);
    },
    async getZoneSettings(zoneId) {
      if (mode === "forbidden" || zoneId === forbiddenZone) {
        return CLOUDFLARE_ZONE_SETTING_IDS.map((id) => ({ id, error: forbidden(`/zones/${zoneId}/settings/${id}`).message, status: 403 }));
      }
      return compliantSettings();
    },
    async listFirewallRules(zoneId) {
      return list(`/zones/${zoneId}/firewall/rules`, []);
    },
    async listZoneRulesets(zoneId) {
      if (zoneId === forbiddenZone) throw forbidden(`/zones/${zoneId}/rulesets`);
      return list(`/zones/${zoneId}/rulesets`, [
        { id: "rs-managed", kind: "zone", phase: CLOUDFLARE_RULESET_PHASES.firewallManaged, name: "zone", version: "1" },
        { id: "rs-ddos", kind: "managed", phase: CLOUDFLARE_RULESET_PHASES.ddosL7, name: "DDoS L7 ruleset", version: "1" },
      ]);
    },
    async getZoneEntrypointRuleset(zoneId, phase) {
      return single(`/zones/${zoneId}/rulesets/phases/${phase}/entrypoint`, zoneId, compliantEntrypoint(phase));
    },
    async listDnsRecords(zoneId) {
      if (zoneId === forbiddenZone) throw forbidden(`/zones/${zoneId}/dns_records`);
      return list(`/zones/${zoneId}/dns_records`, [
        { id: "rec-1", type: "A", name: "one.example", content: "203.0.113.10", proxied: true, proxiable: true, ttl: 1 },
        { id: "rec-2", type: "TXT", name: "one.example", content: "v=spf1 -all", proxied: false, proxiable: false, ttl: 300 },
      ]);
    },
    async getDnssec(zoneId) {
      return single(`/zones/${zoneId}/dnssec`, zoneId, { status: "active", algorithm: "13" });
    },
    async listCertificatePacks(zoneId) {
      if (zoneId === forbiddenZone) throw forbidden(`/zones/${zoneId}/ssl/certificate_packs`);
      return list(`/zones/${zoneId}/ssl/certificate_packs`, [
        { id: "pack-1", type: "universal", status: "active", hosts: ["one.example"], certificates: [{ id: "cert-1", status: "active", expires_on: FUTURE, hosts: ["one.example"] }] },
      ]);
    },
    async getUniversalSslSettings(zoneId) {
      return single(`/zones/${zoneId}/ssl/universal/settings`, zoneId, { enabled: true });
    },
    async getOriginTlsClientAuthSettings(zoneId) {
      return single(`/zones/${zoneId}/origin_tls_client_auth/settings`, zoneId, { enabled: true });
    },
    async listOriginTlsClientAuthHostnames(zoneId) {
      if (zoneId === forbiddenZone) throw forbidden(`/zones/${zoneId}/origin_tls_client_auth/hostnames`);
      return list(`/zones/${zoneId}/origin_tls_client_auth/hostnames`, [
        { cert_id: "cert-aop-1", created_at: "2026-01-01T00:00:00Z", enabled: true, hostname: "app.one.example", status: "active", updated_at: RECENT },
      ]);
    },
    async getZoneSubscription(zoneId) {
      return single(`/zones/${zoneId}/subscription`, zoneId, { id: "sub-1", state: "Paid", rate_plan: { id: "cf_pro", public_name: "Pro Website", currency: "USD" } });
    },
    async getZeroTrustAccount() {
      if (mode === "forbidden") throw forbidden("/accounts/acc-123/gateway");
      if (mode === "empty") return null;
      return { id: "acc-123", gateway_tag: "gw-tag-1", provider_name: "Cloudflare" };
    },
    async listRateLimits(zoneId) {
      return list(`/zones/${zoneId}/rate_limits`, []);
    },
    async listPageRules(zoneId) {
      if (zoneId === forbiddenZone) throw forbidden(`/zones/${zoneId}/pagerules`);
      return list(`/zones/${zoneId}/pagerules`, [{ id: "pr-1", status: "active", priority: 1, targets: [{ target: "url", constraint: { operator: "matches", value: "one.example/static/*" } }], actions: [{ id: "browser_cache_ttl", value: 14400 }] }]);
    },
    async getBotManagement(zoneId) {
      return single(`/zones/${zoneId}/bot_management`, zoneId, { fight_mode: true });
    },
    async listAccessApplications() {
      return list("/accounts/acc-123/access/apps", [{ id: "app-1", name: "Admin", type: "self_hosted", domain: "admin.one.example", policies: [{ id: "pol-1", decision: "allow", include: [{ email_domain: { domain: "example.com" } }] }] }]);
    },
    async listAccessPolicies() {
      return list("/accounts/acc-123/access/policies", [{ id: "pol-2", name: "Staff", decision: "allow", reusable: true, include: [] }]);
    },
    async listIdentityProviders() {
      return list("/accounts/acc-123/access/identity_providers", [{ id: "idp-1", name: "Okta", type: "okta" }]);
    },
    async listGatewayRules() {
      return list("/accounts/acc-123/gateway/rules", [{ id: "gw-1", name: "Block malware", action: "block", enabled: true, filters: ["dns"] }, { id: "gw-2", name: "Isolate", action: "isolate", enabled: true, filters: ["http"] }]);
    },
    async listAuditLogs() {
      return list("/accounts/acc-123/audit_logs", [{ id: "evt-1", when: RECENT, action: { type: "change_setting", result: true }, actor: { email: "admin@example.com" } }]);
    },
    async listMembers() {
      return list("/accounts/acc-123/members", [
        { id: "m1", status: "accepted", user: { email: "owner@example.com", two_factor_authentication_enabled: true }, roles: [{ id: "r1", name: "Super Administrator - All Privileges" }] },
        { id: "m2", status: "accepted", user: { email: "auditor@example.com", two_factor_authentication_enabled: true }, roles: [{ id: "r2", name: "Administrator Read Only" }] },
      ]);
    },
    async listIpAccessRules() {
      return list("/accounts/acc-123/firewall/access_rules/rules", [{ id: "ip-1", mode: "block", notes: "Known scanner", modified_on: RECENT, configuration: { target: "ip", value: "198.51.100.1" } }]);
    },
  };
  return { ...client, ...overrides };
}

function byId(result, id) {
  const item = result.findings.find((finding) => finding.id === id);
  assert.ok(item, `missing finding ${id}`);
  return item;
}

async function runAllAssessments(client) {
  return {
    identity: await assessCloudflareIdentity(client),
    zone: await assessCloudflareZoneSecurity(client),
    traffic: await assessCloudflareTrafficControls(client),
  };
}

test("resolveCloudflareConfiguration prefers explicit arguments over environment defaults", () => {
  const resolved = resolveCloudflareConfiguration(
    {
      api_token: "arg-token",
      account_id: "arg-account",
      base_url: "https://example.com/client/v4",
      timeout_seconds: 10,
    },
    {
      CLOUDFLARE_API_TOKEN: "env-token",
      CLOUDFLARE_ACCOUNT_ID: "env-account",
      CLOUDFLARE_API_BASE_URL: "https://env.example/client/v4",
    },
  );

  assert.equal(resolved.apiToken, "arg-token");
  assert.equal(resolved.accountId, "arg-account");
  assert.equal(resolved.baseUrl, "https://example.com/client/v4");
  assert.equal(resolved.timeoutMs, 10000);
  assert.equal(resolved.authMethod, "token");
  assert.ok(resolved.sourceChain.includes("arguments-api-token"));
});

test("config resolution: credentials set through the environment survive an argument overlay that carries every credential key as undefined and names only an unrelated argument, and the source chain names the environment", () => {
  const env = { CLOUDFLARE_API_TOKEN: "vN8kQ3xT7mWp2Zr9Lc4Hd6Fs", CLOUDFLARE_ACCOUNT_ID: "acc-env-123", CLOUDFLARE_API_KEY: "Xr4Tq9Vw2Kp7Mz3Nb8Lc5Hd1", CLOUDFLARE_EMAIL: "auditor@example.com" };
  // Every documented credential key present as undefined (the shape an argument overlay emits), one unrelated argument set.
  const overlay = { api_token: undefined, token: undefined, api_key: undefined, email: undefined, account_id: undefined, base_url: undefined, timeout_seconds: 12 };

  const token = resolveCloudflareConfiguration(overlay, { CLOUDFLARE_API_TOKEN: env.CLOUDFLARE_API_TOKEN, CLOUDFLARE_ACCOUNT_ID: env.CLOUDFLARE_ACCOUNT_ID });
  assert.equal(token.apiToken, env.CLOUDFLARE_API_TOKEN, "the environment token resolves");
  assert.equal(token.accountId, env.CLOUDFLARE_ACCOUNT_ID, "the environment account id resolves");
  assert.equal(token.authMethod, "token");
  assert.equal(token.timeoutMs, 12_000, "the unrelated argument is applied");
  assert.deepEqual(token.sourceChain, ["environment-api-token", "environment-account-id", "default-base-url"], "the source chain names the environment");

  const pair = resolveCloudflareConfiguration(overlay, { CLOUDFLARE_API_KEY: env.CLOUDFLARE_API_KEY, CLOUDFLARE_EMAIL: env.CLOUDFLARE_EMAIL });
  assert.equal(pair.apiKey, env.CLOUDFLARE_API_KEY, "the environment global key resolves");
  assert.equal(pair.email, env.CLOUDFLARE_EMAIL, "the environment email resolves");
  assert.equal(pair.authMethod, "global_key");
  assert.deepEqual(pair.sourceChain, ["environment-api-key", "environment-email", "default-base-url"], "the source chain names the environment for the pair");

  // A blank string argument is "not provided" as well: it never shadows the environment value.
  const blank = resolveCloudflareConfiguration({ ...overlay, api_token: "", token: "  " }, { CLOUDFLARE_API_TOKEN: env.CLOUDFLARE_API_TOKEN });
  assert.equal(blank.apiToken, env.CLOUDFLARE_API_TOKEN, "a blank token argument does not erase the environment token");
  assert.deepEqual(blank.sourceChain, ["environment-api-token", "default-base-url"]);
});

test("checkCloudflareAccess reports readable Cloudflare surfaces", async () => {
  const result = await checkCloudflareAccess(fixtureClient("compliant"));
  assert.equal(result.status, "healthy");
  assert.equal(result.surfaces.filter((surface) => surface.status === "readable").length, 9);
  assert.match(result.recommendedNextStep, /cloudflare_assess_identity/);
});

test("assessCloudflareIdentity flags global keys, super admins, bypass policies, and weak identity providers", async () => {
  const client = fixtureClient("compliant", {
    getResolvedConfig: () => sampleConfig({ authMethod: "global_key", apiToken: undefined, apiKey: "legacy", email: "user@example.com" }),
    async verifyCurrentToken() {
      return null;
    },
    async listMembers() {
      return [
        { id: "m1", roles: [{ name: "Super Administrator - All Privileges" }] },
        { id: "m2", roles: [{ name: "Super Administrator - All Privileges" }] },
        { id: "m3", roles: [{ name: "Super Administrator - All Privileges" }] },
      ];
    },
    async listAccessApplications() {
      return [{ id: "app-1", name: "Open", type: "self_hosted", policies: [{ id: "p", decision: "bypass" }] }];
    },
    async listIdentityProviders() {
      return [{ id: "idp-1", type: "onetimepin" }];
    },
  });

  const result = await assessCloudflareIdentity(client, { maxSuperAdmins: 2 });
  assert.equal(byId(result, "CF-IAM-01").status, "fail");
  assert.equal(byId(result, "CF-IAM-02").status, "manual");
  assert.equal(byId(result, "CF-IAM-03").status, "fail");
  assert.equal(byId(result, "CF-IAM-04").status, "fail");
  assert.equal(byId(result, "CF-IAM-05").status, "fail");
});

test("assessCloudflareZoneSecurity classifies TLS, DNSSEC, WAF, DDoS, and header controls per zone", async () => {
  const client = fixtureClient("compliant", {
    async listZones() {
      return [{ id: "zone-1", name: "good.example" }, { id: "zone-2", name: "bad.example" }];
    },
    async getZoneSettings(zoneId) {
      if (zoneId === "zone-1") return compliantSettings();
      return [
        { id: "ssl", value: "flexible" },
        { id: "min_tls_version", value: "1.0" },
        { id: "always_use_https", value: "off" },
        { id: "automatic_https_rewrites", value: "off" },
        { id: "security_header", value: { strict_transport_security: { enabled: false } } },
        { id: "browser_check", value: "off" },
        { id: "email_obfuscation", value: "off" },
        { id: "tls_client_auth", value: "off" },
      ];
    },
    async getZoneEntrypointRuleset(zoneId, phase) {
      if (zoneId === "zone-1") return compliantEntrypoint(phase);
      if (phase === CLOUDFLARE_RULESET_PHASES.ddosL7) {
        return { id: "rs", phase, rules: [{ id: "r", action: "execute", enabled: true, action_parameters: { id: "4d21379b4f9f4bb088e0729962c8b3cf", overrides: { sensitivity_level: "eoff" } } }] };
      }
      return null;
    },
    async getDnssec(zoneId) {
      return zoneId === "zone-1" ? { status: "active" } : { status: "disabled" };
    },
    async getUniversalSslSettings(zoneId) {
      return { enabled: zoneId === "zone-1" };
    },
    async getOriginTlsClientAuthSettings(zoneId) {
      return { enabled: zoneId === "zone-1" };
    },
    async listOriginTlsClientAuthHostnames(zoneId) {
      return zoneId === "zone-1"
        ? { items: [{ cert_id: "cert-aop-1", created_at: "2026-01-01T00:00:00Z", enabled: true, hostname: "app.good.example", status: "active", updated_at: RECENT }], truncated: false, totalCount: 1 }
        : { items: [], truncated: false, totalCount: 0 };
    },
  });

  const result = await assessCloudflareZoneSecurity(client, { zoneLimit: 20 });
  for (const id of ["CF-ZONE-01", "CF-ZONE-02", "CF-ZONE-03", "CF-ZONE-04", "CF-ZONE-05", "CF-ZONE-06", "CF-ZONE-07", "CF-ZONE-08", "CF-ZONE-09", "CF-ZONE-10", "CF-ZONE-11", "CF-ZONE-12", "CF-ZONE-13", "CF-ZONE-14"]) {
    assert.equal(byId(result, id).status, "fail", `${id} should fail when one zone violates the control`);
    assert.equal(byId(result, id).evidence.counts.pass, 1, `${id} should record the compliant zone`);
  }
  assert.equal(byId(result, "CF-ZONE-15").status, "pass");
  assert.equal(result.findings.length, 15);
});

test("assessCloudflareTrafficControls flags missing rate limits, risky page rules, and disabled bot controls", async () => {
  const client = fixtureClient("compliant", {
    async listZones() {
      return [{ id: "zone-1", name: "good.example" }, { id: "zone-2", name: "bad.example" }];
    },
    async getZoneEntrypointRuleset(zoneId, phase) {
      return zoneId === "zone-1" ? compliantEntrypoint(phase) : null;
    },
    async listPageRules(zoneId) {
      return zoneId === "zone-2"
        ? [{ id: "pr-1", status: "active", targets: [{ target: "url", constraint: { operator: "matches", value: "bad.example/admin/*" } }], actions: [{ id: "disable_security" }] }]
        : [];
    },
    async getBotManagement(zoneId) {
      return zoneId === "zone-1" ? { fight_mode: true } : { fight_mode: false };
    },
    async listGatewayRules() {
      return [{ id: "gw-1", action: "allow", enabled: true, filters: ["dns"] }];
    },
  });

  const result = await assessCloudflareTrafficControls(client, { zoneLimit: 20, auditLimit: 50 });
  assert.equal(byId(result, "CF-TRF-01").status, "fail");
  assert.equal(byId(result, "CF-TRF-02").status, "fail");
  assert.equal(byId(result, "CF-TRF-03").status, "fail");
  assert.equal(byId(result, "CF-TRF-04").status, "pass");
  assert.equal(byId(result, "CF-TRF-05").status, "pass");
  assert.equal(byId(result, "CF-TRF-06").status, "fail");
});

test("exportCloudflareAuditBundle writes the shared bundle layout and never overwrites a prior bundle", async () => {
  const base = createTempBase("grclanker-cloudflare-export-");
  const client = fixtureClient("compliant", {
    async listGatewayRules() {
      throw forbidden("/accounts/acc-123/gateway/rules");
    },
  });

  const result = await exportCloudflareAuditBundle(client, sampleConfig(), base);
  assert.ok(existsSync(result.outputDir));
  assert.ok(existsSync(result.zipPath));
  assert.equal(result.zipPath, `${result.outputDir}.zip`);
  assert.equal(result.findingCount, 27);
  assert.ok(result.errorCount >= 1);

  for (const relativePath of [
    "QUICK_REFERENCE.md",
    "README.md",
    "summary.md",
    "metadata.json",
    "_errors.log",
    "compliance/executive_summary.md",
    "compliance/unified_compliance_matrix.md",
    "compliance/fedramp/fedramp_compliance_report.md",
    "compliance/cmmc/cmmc_compliance_report.md",
    "compliance/soc2/soc2_compliance_report.md",
    "compliance/cis/cis_compliance_report.md",
    "compliance/pci_dss/pci_dss_compliance_report.md",
    "compliance/disa_stig/disa_stig_compliance_report.md",
    "compliance/irap/irap_compliance_report.md",
    "compliance/ismap/ismap_compliance_report.md",
    "analysis/findings.json",
    "core_data/access.json",
    "core_data/zones.json",
  ]) {
    assert.ok(existsSync(join(result.outputDir, relativePath)), `missing ${relativePath}`);
  }
  const metadata = JSON.parse(readFileSync(join(result.outputDir, "metadata.json"), "utf8"));
  assert.equal(metadata.auth_method, "token");
  assert.equal(metadata.account_id, "acc-123");
  assert.match(readFileSync(join(result.outputDir, "_errors.log"), "utf8"), /gateway\/rules/);

  const rerun = await exportCloudflareAuditBundle(client, sampleConfig(), base);
  assert.notEqual(rerun.outputDir, result.outputDir);
  assert.notEqual(rerun.zipPath, result.zipPath);
  assert.ok(existsSync(result.zipPath));
  assert.ok(existsSync(rerun.zipPath));
});

test("compliant export has no _errors.log", async () => {
  const base = createTempBase("grclanker-cloudflare-clean-");
  const result = await exportCloudflareAuditBundle(fixtureClient("compliant"), sampleConfig(), base);
  assert.equal(result.errorCount, 0);
  assert.ok(!existsSync(join(result.outputDir, "_errors.log")));
});

test("resolveSecureOutputPath rejects traversal and symlink parents", () => {
  const base = createTempBase("grclanker-cloudflare-path-");
  const outside = createTempBase("grclanker-cloudflare-outside-");
  const linked = join(base, "linked");
  symlinkSync(outside, linked, "dir");

  assert.throws(() => resolveSecureOutputPath(base, "../escape"), /Refusing to write outside/);
  assert.throws(() => resolveSecureOutputPath(base, "linked/file.txt"), /symlinked parent directory/);

  const safe = resolveSecureOutputPath(base, join("reports", "safe.txt"));
  assert.match(safe, /reports\/safe\.txt$/);
});

test("verdict rule 1: 403 reads yield manual naming endpoint, permission, and evidence, never pass", async () => {
  const client = fixtureClient("compliant", {
    async getBotManagement(zoneId) {
      throw forbidden(`/zones/${zoneId}/bot_management`);
    },
    async listMembers() {
      throw forbidden("/accounts/acc-123/members");
    },
  });
  const traffic = await assessCloudflareTrafficControls(client);
  const bot = byId(traffic, "CF-TRF-03");
  assert.equal(bot.status, "manual");
  assert.match(bot.summary, /bot_management/);
  assert.match(bot.summary, /Bot Management: Read/);
  assert.match(bot.summary, /manually/);

  const identity = await assessCloudflareIdentity(client);
  const members = byId(identity, "CF-IAM-03");
  assert.equal(members.status, "manual");
  assert.match(members.summary, /Account Settings: Read/);
});

test("verdict rule 2: empty inventories never pass by default and state the chosen status", async () => {
  const client = fixtureClient("compliant", {
    async listZones() {
      return [];
    },
    async listUserTokens() {
      return [];
    },
    async listAccountTokens() {
      return [];
    },
    async listAccessApplications() {
      return [];
    },
    async listIdentityProviders() {
      return [];
    },
    async listIpAccessRules() {
      return [];
    },
  });
  const zone = await assessCloudflareZoneSecurity(client);
  for (const item of zone.findings) {
    assert.equal(item.status, "manual", `${item.id} with zero zones`);
    assert.match(item.summary, /No zones were visible/);
  }
  const identity = await assessCloudflareIdentity(client);
  assert.equal(byId(identity, "CF-IAM-06").status, "manual");
  assert.equal(byId(identity, "CF-IAM-04").status, "manual");
  assert.equal(byId(identity, "CF-IAM-05").status, "fail");
  const traffic = await assessCloudflareTrafficControls(client);
  const ipRules = byId(traffic, "CF-TRF-05");
  assert.equal(ipRules.status, "pass");
  assert.match(ipRules.summary, /emptiness is compliant/);
});

test("verdict rule 3: plan-gated products render manual naming the plan", async () => {
  const client = fixtureClient("compliant", {
    async getBotManagement() {
      return { auto_update_model: true, suppress_session_score: false };
    },
    async getZoneEntrypointRuleset(zoneId, phase) {
      return phase === CLOUDFLARE_RULESET_PHASES.ddosL7 ? null : compliantEntrypoint(phase);
    },
    async listZoneRulesets(zoneId) {
      throw forbidden(`/zones/${zoneId}/rulesets`);
    },
    async listGatewayRules() {
      return [];
    },
    async getZeroTrustAccount() {
      return null;
    },
  });
  const traffic = await assessCloudflareTrafficControls(client);
  assert.equal(byId(traffic, "CF-TRF-03").status, "manual");
  assert.match(byId(traffic, "CF-TRF-03").summary, /Enterprise Bot Management/);
  assert.match(byId(traffic, "CF-TRF-03").summary, /Current zone plan: Pro Website \(subscription Paid\)/);
  assert.equal(byId(traffic, "CF-TRF-06").status, "manual");
  assert.match(byId(traffic, "CF-TRF-06").summary, /Zero Trust subscription/);
  assert.match(byId(traffic, "CF-TRF-06").summary, /returned no gateway_tag/);
  const zone = await assessCloudflareZoneSecurity(client);
  assert.equal(byId(zone, "CF-ZONE-07").status, "manual");
  assert.match(byId(zone, "CF-ZONE-07").summary, /Enterprise plan with Advanced DDoS Protection/);
});

test("review fix 4: documented licensing signals upgrade manual verdicts (gateway_tag, managed ddos_l7 ruleset, subscription plan name)", async () => {
  const licensed = fixtureClient("compliant", {
    async listGatewayRules() {
      return [];
    },
  });
  const traffic = await assessCloudflareTrafficControls(licensed);
  assert.equal(byId(traffic, "CF-TRF-06").status, "fail");
  assert.match(byId(traffic, "CF-TRF-06").summary, /gateway_tag gw-tag-1/);
  assert.equal(byId(traffic, "CF-TRF-06").evidence.gateway_tag, "gw-tag-1");

  const defaults = fixtureClient("compliant", {
    async getZoneEntrypointRuleset(zoneId, phase) {
      return phase === CLOUDFLARE_RULESET_PHASES.ddosL7 ? null : compliantEntrypoint(phase);
    },
  });
  const zone = await assessCloudflareZoneSecurity(defaults);
  assert.equal(byId(zone, "CF-ZONE-07").status, "pass");
  assert.match(byId(zone, "CF-ZONE-07").evidence.zones[0].detail, /managed ddos_l7 ruleset is listed/);

  const unlisted = fixtureClient("compliant", {
    async getZoneEntrypointRuleset(zoneId, phase) {
      return phase === CLOUDFLARE_RULESET_PHASES.ddosL7 ? null : compliantEntrypoint(phase);
    },
    async listZoneRulesets() {
      return [{ id: "rs-managed", kind: "zone", phase: CLOUDFLARE_RULESET_PHASES.firewallManaged, name: "zone", version: "1" }];
    },
  });
  const unlistedZone = await assessCloudflareZoneSecurity(unlisted);
  assert.equal(byId(unlistedZone, "CF-ZONE-07").status, "manual");
  assert.match(byId(unlistedZone, "CF-ZONE-07").summary, /does not show a managed ddos_l7 ruleset/);

  const unpriced = fixtureClient("compliant", {
    async getBotManagement() {
      return { auto_update_model: true };
    },
    async getZoneSubscription(zoneId) {
      throw forbidden(`/zones/${zoneId}/subscription`);
    },
  });
  const unpricedTraffic = await assessCloudflareTrafficControls(unpriced);
  assert.equal(byId(unpricedTraffic, "CF-TRF-03").status, "manual");
  assert.match(byId(unpricedTraffic, "CF-TRF-03").summary, /zones\[\]\.plan is deprecated and is not read/);
});

test("verdict rule 4: items without dates are never counted valid and cap at warn", async () => {
  const client = fixtureClient("compliant", {
    async listUserTokens() {
      return [{ id: "tok-1", name: "no-expiry", status: "active", expires_on: null, policies: [] }];
    },
    async listAccountTokens() {
      return [];
    },
    async listCertificatePacks() {
      return [{ id: "pack-1", type: "universal", status: "active", certificates: [{ id: "c1", status: "active", expires_on: null }] }];
    },
    async listIpAccessRules() {
      return [{ id: "ip-1", mode: "whitelist", notes: "office", modified_on: null, configuration: { target: "ip", value: "192.0.2.1" } }];
    },
  });
  const identity = await assessCloudflareIdentity(client);
  assert.equal(byId(identity, "CF-IAM-06").status, "fail");
  const zone = await assessCloudflareZoneSecurity(client);
  assert.equal(byId(zone, "CF-ZONE-10").status, "warn");
  const traffic = await assessCloudflareTrafficControls(client);
  assert.equal(byId(traffic, "CF-TRF-05").status, "warn");
});

test("verdict rule 5: partial inventories are capped at warn with seen and total counts", async () => {
  const client = fixtureClient("compliant", {
    async listZones() {
      return { items: [{ id: "zone-1", name: "one.example" }], truncated: true, totalCount: 40 };
    },
    async listMembers() {
      return { items: [{ id: "m1", roles: [{ name: "Administrator" }], user: { two_factor_authentication_enabled: true } }], truncated: true, totalCount: 120 };
    },
  });
  const zone = await assessCloudflareZoneSecurity(client);
  for (const item of zone.findings) {
    assert.notEqual(item.status, "pass", `${item.id} must not pass on a partial zone inventory`);
    assert.match(item.summary, /1 seen of 40 total/);
  }
  const identity = await assessCloudflareIdentity(client);
  assert.equal(byId(identity, "CF-IAM-03").status, "warn");
  assert.match(byId(identity, "CF-IAM-03").summary, /1 seen of 120 total/);
});

test("verdict rule 6: documented flags drive verdicts (disabled rules, inactive tokens, inactive DNSSEC, bypass decisions)", async () => {
  const client = fixtureClient("compliant", {
    async getZoneEntrypointRuleset(zoneId, phase) {
      const ruleset = compliantEntrypoint(phase);
      if (ruleset && phase === CLOUDFLARE_RULESET_PHASES.firewallManaged) ruleset.rules[0].enabled = false;
      if (ruleset && phase === CLOUDFLARE_RULESET_PHASES.responseHeadersTransform) ruleset.rules[0].enabled = false;
      return ruleset;
    },
    async verifyCurrentToken() {
      return { id: "tok-current", status: "disabled", expires_on: FUTURE };
    },
    async getDnssec() {
      return { status: "pending" };
    },
    async listCertificatePacks() {
      return [{ id: "pack-1", type: "universal", status: "pending_validation", certificates: [{ id: "c1", status: "active", expires_on: FUTURE }] }];
    },
  });
  const zone = await assessCloudflareZoneSecurity(client);
  assert.equal(byId(zone, "CF-ZONE-01").status, "fail");
  assert.equal(byId(zone, "CF-ZONE-14").status, "fail");
  assert.equal(byId(zone, "CF-ZONE-05").status, "warn");
  assert.equal(byId(zone, "CF-ZONE-10").status, "fail");
  const identity = await assessCloudflareIdentity(client);
  assert.equal(byId(identity, "CF-IAM-02").status, "fail");
});

function fakeFetch(handler) {
  const calls = [];
  const fetchImpl = async (url) => {
    const parsed = new URL(url);
    calls.push(parsed);
    const body = handler(parsed);
    return {
      ok: body.status === undefined || body.status < 400,
      status: body.status ?? 200,
      statusText: body.status && body.status >= 400 ? "Error" : "OK",
      async text() {
        return JSON.stringify(body.payload ?? {});
      },
    };
  };
  return { calls, fetchImpl };
}

test("verdict rule 7: pagination follows result_info to completion and flags truncation at the cap", async () => {
  const { calls, fetchImpl } = fakeFetch((url) => {
    const page = Number(url.searchParams.get("page"));
    if (url.pathname.endsWith("/accounts/acc-123/members")) {
      const items = page === 1
        ? Array.from({ length: 50 }, (_, index) => ({ id: `m-${index}` }))
        : [{ id: "m-50" }];
      return { payload: { success: true, result: items, result_info: { page, per_page: 50, total_pages: 2, total_count: 51, count: items.length } } };
    }
    if (url.pathname.endsWith("/zones")) {
      return { payload: { success: true, result: Array.from({ length: 50 }, (_, index) => ({ id: `z-${index}` })), result_info: { page, per_page: 50, total_pages: 3, total_count: 150, count: 50 } } };
    }
    if (url.pathname.endsWith("/rulesets")) {
      const cursor = url.searchParams.get("cursor");
      return cursor
        ? { payload: { success: true, result: [{ id: "rs-2", phase: "http_ratelimit", kind: "zone" }], result_info: { cursors: {} } } }
        : { payload: { success: true, result: [{ id: "rs-1", phase: "http_request_firewall_managed", kind: "zone" }], result_info: { cursors: { after: "next-cursor" } } } };
    }
    return { payload: { success: true, result: [] } };
  });
  const client = new CloudflareApiClient(sampleConfig(), { fetchImpl });

  const members = await client.listMembers("acc-123", 500);
  assert.equal(members.items.length, 51);
  assert.equal(members.truncated, false);
  assert.equal(calls.filter((url) => url.pathname.endsWith("/members")).length, 2);
  assert.equal(calls[0].searchParams.get("per_page"), "50");

  const zones = await client.listZones(60);
  assert.equal(zones.items.length, 60);
  assert.equal(zones.truncated, true);
  assert.equal(zones.totalCount, 150);

  const rulesets = await client.listZoneRulesets("zone-1");
  assert.equal(rulesets.items.length, 2);
  const rulesetCalls = calls.filter((url) => url.pathname.endsWith("/rulesets"));
  assert.equal(rulesetCalls.length, 2);
  assert.equal(rulesetCalls[1].searchParams.get("cursor"), "next-cursor");
  assert.equal(rulesetCalls[0].searchParams.get("page"), null);
});

test("verdict rule 8: re-running the export allocates a new directory and zip", async () => {
  const base = createTempBase("grclanker-cloudflare-rerun-");
  const first = await exportCloudflareAuditBundle(fixtureClient("compliant"), sampleConfig(), base);
  const second = await exportCloudflareAuditBundle(fixtureClient("compliant"), sampleConfig(), base);
  const third = await exportCloudflareAuditBundle(fixtureClient("compliant"), sampleConfig(), base);
  assert.equal(new Set([first.outputDir, second.outputDir, third.outputDir]).size, 3);
  assert.equal(new Set([first.zipPath, second.zipPath, third.zipPath]).size, 3);
  assert.match(second.zipPath, /-audit-bundle-2\.zip$/);
});

test("schema fidelity: client requests documented paths, phases, setting ids, and query parameters", async () => {
  const { calls, fetchImpl } = fakeFetch((url) => {
    if (url.pathname.includes("/settings/")) return { payload: { success: true, result: { id: url.pathname.split("/").pop(), value: "on" } } };
    if (url.pathname.endsWith("/entrypoint")) return { payload: { success: true, result: { id: "rs", rules: [] } } };
    return { payload: { success: true, result: [] } };
  });
  const client = new CloudflareApiClient(sampleConfig(), { fetchImpl, now: () => new Date("2026-09-21T00:00:00Z") });
  const zone = "zone-1";
  const account = "acc-123";

  await client.getZoneEntrypointRuleset(zone, CLOUDFLARE_RULESET_PHASES.ddosL7);
  await client.getZoneEntrypointRuleset(zone, CLOUDFLARE_RULESET_PHASES.firewallManaged);
  await client.getZoneEntrypointRuleset(zone, CLOUDFLARE_RULESET_PHASES.firewallCustom);
  await client.getZoneEntrypointRuleset(zone, CLOUDFLARE_RULESET_PHASES.responseHeadersTransform);
  await client.getZoneEntrypointRuleset(zone, CLOUDFLARE_RULESET_PHASES.rateLimit);
  await client.getZoneSettings(zone);
  await client.listDnsRecords(zone);
  await client.listCertificatePacks(zone);
  await client.getOriginTlsClientAuthSettings(zone);
  await client.listOriginTlsClientAuthHostnames(zone);
  await client.getZoneSubscription(zone);
  await client.getZeroTrustAccount(account);
  await client.listUserTokens();
  await client.listAccountTokens(account);
  await client.getUserToken("tok-1");
  await client.verifyCurrentToken();
  await client.listPageRules(zone);
  await client.listGatewayRules(account);
  await client.listAuditLogs(account, 10);
  await client.getBotManagement(zone);
  await client.getDnssec(zone);
  await client.getUniversalSslSettings(zone);

  const paths = calls.map((url) => url.pathname.replace("/client/v4", ""));
  for (const expected of [
    "/zones/zone-1/rulesets/phases/ddos_l7/entrypoint",
    "/zones/zone-1/rulesets/phases/http_request_firewall_managed/entrypoint",
    "/zones/zone-1/rulesets/phases/http_request_firewall_custom/entrypoint",
    "/zones/zone-1/rulesets/phases/http_response_headers_transform/entrypoint",
    "/zones/zone-1/rulesets/phases/http_ratelimit/entrypoint",
    "/zones/zone-1/settings/ssl",
    "/zones/zone-1/settings/min_tls_version",
    "/zones/zone-1/settings/always_use_https",
    "/zones/zone-1/settings/automatic_https_rewrites",
    "/zones/zone-1/settings/security_header",
    "/zones/zone-1/settings/browser_check",
    "/zones/zone-1/settings/email_obfuscation",
    "/zones/zone-1/settings/tls_client_auth",
    "/zones/zone-1/dns_records",
    "/zones/zone-1/ssl/certificate_packs",
    "/zones/zone-1/origin_tls_client_auth/settings",
    "/zones/zone-1/origin_tls_client_auth/hostnames",
    "/zones/zone-1/subscription",
    "/accounts/acc-123/gateway",
    "/user/tokens",
    "/accounts/acc-123/tokens",
    "/user/tokens/tok-1",
    "/user/tokens/verify",
    "/zones/zone-1/pagerules",
    "/accounts/acc-123/gateway/rules",
    "/accounts/acc-123/audit_logs",
    "/zones/zone-1/bot_management",
    "/zones/zone-1/dnssec",
    "/zones/zone-1/ssl/universal/settings",
  ]) {
    assert.ok(paths.includes(expected), `expected request to ${expected}`);
  }
  assert.ok(!paths.includes("/zones/zone-1/settings"), "deprecated get-all settings endpoint must not be called");

  const byPath = (suffix) => calls.find((url) => url.pathname.endsWith(suffix));
  assert.equal(byPath("/ssl/certificate_packs").searchParams.get("status"), "all");
  assert.equal(byPath("/ssl/certificate_packs").searchParams.get("per_page"), "50");
  assert.equal(byPath("/user/tokens").searchParams.get("include_expired"), "true");
  assert.equal(byPath("/user/tokens").searchParams.get("per_page"), "50");
  assert.equal(byPath("/pagerules").searchParams.get("page"), null);
  assert.equal(byPath("/pagerules").searchParams.get("status"), "active");
  assert.equal(byPath("/origin_tls_client_auth/hostnames").searchParams.get("per_page"), "1000");
  assert.equal(byPath("/origin_tls_client_auth/hostnames").searchParams.get("status"), "all");
  assert.equal(byPath("/origin_tls_client_auth/hostnames").searchParams.get("page"), "1");
  assert.equal(byPath("/zone-1/subscription").search, "");
  assert.equal(byPath("/acc-123/gateway").search, "");
  assert.equal(byPath("/gateway/rules").searchParams.get("page"), null);
  assert.equal(byPath("/audit_logs").searchParams.get("since"), "2026-08-22T00:00:00.000Z");
  assert.equal(byPath("/dnssec").search, "");
  assert.equal(byPath("/bot_management").search, "");
});

test("review fix 1: per-hostname Authenticated Origin Pulls associations are read and judged in CF-ZONE-11", async () => {
  const disabledAssociation = fixtureClient("compliant", {
    async listOriginTlsClientAuthHostnames() {
      return {
        items: [
          { cert_id: "cert-aop-1", created_at: "2026-01-01T00:00:00Z", enabled: true, hostname: "app.one.example", status: "active", updated_at: RECENT },
          { cert_id: "cert-aop-2", created_at: "2026-01-01T00:00:00Z", enabled: false, hostname: "api.one.example", status: "active", updated_at: RECENT },
        ],
        truncated: false,
        totalCount: 2,
      };
    },
  });
  const disabledZone = await assessCloudflareZoneSecurity(disabledAssociation);
  assert.equal(byId(disabledZone, "CF-ZONE-11").status, "warn");
  assert.match(byId(disabledZone, "CF-ZONE-11").summary, /api\.one\.example: enabled false, status active/);

  const undatedAssociation = fixtureClient("compliant", {
    async listOriginTlsClientAuthHostnames() {
      return { items: [{ cert_id: "cert-aop-1", created_at: null, enabled: true, hostname: "app.one.example", status: "active", updated_at: null }], truncated: false, totalCount: 1 };
    },
  });
  assert.equal(byId(await assessCloudflareZoneSecurity(undatedAssociation), "CF-ZONE-11").status, "warn");

  const pendingAssociation = fixtureClient("compliant", {
    async listOriginTlsClientAuthHostnames() {
      return { items: [{ cert_id: "cert-aop-1", created_at: "2026-01-01T00:00:00Z", enabled: true, hostname: "app.one.example", status: "pending_deployment", updated_at: RECENT }], truncated: false, totalCount: 1 };
    },
  });
  assert.equal(byId(await assessCloudflareZoneSecurity(pendingAssociation), "CF-ZONE-11").status, "warn");

  const truncatedAssociations = fixtureClient("compliant", {
    async listOriginTlsClientAuthHostnames() {
      return { items: [{ cert_id: "cert-aop-1", created_at: "2026-01-01T00:00:00Z", enabled: true, hostname: "app.one.example", status: "active", updated_at: RECENT }], truncated: true, totalCount: 40 };
    },
  });
  const truncatedZone = await assessCloudflareZoneSecurity(truncatedAssociations);
  assert.equal(byId(truncatedZone, "CF-ZONE-11").status, "warn");
  assert.match(byId(truncatedZone, "CF-ZONE-11").summary, /1 seen of 40 total/);

  const zoneLevelOff = fixtureClient("compliant", {
    async getOriginTlsClientAuthSettings() {
      return { enabled: false };
    },
    async getZoneSettings() {
      return compliantSettings().map((setting) => (setting.id === "tls_client_auth" ? { id: "tls_client_auth", value: "off" } : setting));
    },
  });
  const zoneLevelOffResult = await assessCloudflareZoneSecurity(zoneLevelOff);
  assert.equal(byId(zoneLevelOffResult, "CF-ZONE-11").status, "warn");
  assert.match(byId(zoneLevelOffResult, "CF-ZONE-11").summary, /only 1 of 1 per-hostname associations/);

  const hostnamesForbidden = fixtureClient("compliant", {
    async listOriginTlsClientAuthHostnames(zoneId) {
      throw forbidden(`/zones/${zoneId}/origin_tls_client_auth/hostnames`);
    },
  });
  const forbiddenZone = await assessCloudflareZoneSecurity(hostnamesForbidden);
  assert.equal(byId(forbiddenZone, "CF-ZONE-11").status, "manual");
  assert.match(byId(forbiddenZone, "CF-ZONE-11").summary, /origin_tls_client_auth\/hostnames could not be read/);
  assert.match(byId(forbiddenZone, "CF-ZONE-11").evidence.per_hostname_source, /per-hostname-authenticated-origin-pull-list-hostname-associations/);
});

test("review fix 2: the deprecated /rate_limits API is evidence only, read only when http_ratelimit is unreadable, and never passes", async () => {
  const legacyReads = [];
  const legacyOnly = fixtureClient("compliant", {
    async getZoneEntrypointRuleset(zoneId, phase) {
      if (phase === CLOUDFLARE_RULESET_PHASES.rateLimit) throw forbidden(`/zones/${zoneId}/rulesets/phases/${phase}/entrypoint`);
      return compliantEntrypoint(phase);
    },
    async listRateLimits(zoneId) {
      legacyReads.push(zoneId);
      return { items: [{ id: "rl-1", disabled: false, threshold: 100, period: 60 }], truncated: false, totalCount: 1 };
    },
  });
  const legacyResult = await assessCloudflareTrafficControls(legacyOnly);
  assert.equal(byId(legacyResult, "CF-TRF-01").status, "warn");
  assert.match(byId(legacyResult, "CF-TRF-01").summary, /deprecated \/rate_limits API shows 1 enabled legacy rate limits as evidence only/);
  assert.deepEqual(legacyReads, ["zone-1"]);

  const rulesetReadable = fixtureClient("compliant", {
    async getZoneEntrypointRuleset(zoneId, phase) {
      return phase === CLOUDFLARE_RULESET_PHASES.rateLimit ? { id: "rs-rl", phase, rules: [] } : compliantEntrypoint(phase);
    },
    async listRateLimits() {
      throw new Error("legacy /rate_limits must not be read when http_ratelimit is readable");
    },
  });
  const rulesetResult = await assessCloudflareTrafficControls(rulesetReadable);
  assert.equal(byId(rulesetResult, "CF-TRF-01").status, "fail");
  assert.match(byId(rulesetResult, "CF-TRF-01").summary, /http_ratelimit entry point has no enabled rules/);

  const nothingReadable = fixtureClient("compliant", {
    async getZoneEntrypointRuleset(zoneId, phase) {
      if (phase === CLOUDFLARE_RULESET_PHASES.rateLimit) throw forbidden(`/zones/${zoneId}/rulesets/phases/${phase}/entrypoint`);
      return compliantEntrypoint(phase);
    },
    async listRateLimits() {
      return { items: [], truncated: false, totalCount: 0 };
    },
  });
  const nothingResult = await assessCloudflareTrafficControls(nothingReadable);
  assert.equal(byId(nothingResult, "CF-TRF-01").status, "manual");
  assert.match(byId(nothingResult, "CF-TRF-01").summary, /returned no enabled legacy rate limits/);
});

test("review fix 3: page rules are requested with status=active so disabled rules cannot satisfy CF-TRF-02", async () => {
  const { calls, fetchImpl } = fakeFetch((url) => {
    if (url.pathname.endsWith("/pagerules")) {
      return { payload: { success: true, result: [{ id: "pr-1", status: "active", priority: 1, targets: [{ target: "url", constraint: { operator: "matches", value: "one.example/*" } }], actions: [{ id: "disable_security" }] }] } };
    }
    return { payload: { success: true, result: [] } };
  });
  const client = new CloudflareApiClient(sampleConfig(), { fetchImpl });
  const rules = await client.listPageRules("zone-1");
  assert.equal(rules.items.length, 1);
  assert.equal(calls[0].searchParams.get("status"), "active");
});

test("self-check (a): every call 403 yields no pass in any assessment", async () => {
  const results = await runAllAssessments(fixtureClient("forbidden"));
  for (const result of Object.values(results)) {
    for (const item of result.findings) {
      if (item.id === "CF-IAM-01") continue;
      assert.notEqual(item.status, "pass", `${item.id} passed under blanket 403`);
    }
    assert.ok(result.errors.length > 0);
  }
  assert.equal(byId(results.identity, "CF-IAM-01").status, "pass", "credential type is judged from the configured auth method, not an API read");
});

test("self-check (b): every list empty passes only where emptiness is compliant by intent", async () => {
  const results = await runAllAssessments(fixtureClient("empty"));
  const passing = Object.values(results).flatMap((result) => result.findings.filter((item) => item.status === "pass").map((item) => item.id));
  assert.deepEqual(passing.sort(), ["CF-IAM-01", "CF-IAM-02", "CF-TRF-05"]);
  assert.match(byId(results.traffic, "CF-TRF-05").summary, /emptiness is compliant/);
  for (const item of results.zone.findings) assert.equal(item.status, "manual");
});

test("self-check (c): partial inventory with a forbidden zone never passes", async () => {
  const results = await runAllAssessments(fixtureClient("partial"));
  for (const result of Object.values(results)) {
    for (const item of result.findings) {
      if (item.id === "CF-IAM-01" || item.id === "CF-IAM-02") continue;
      assert.notEqual(item.status, "pass", `${item.id} passed on a partial inventory`);
    }
  }
  assert.match(byId(results.zone, "CF-ZONE-02").summary, /2 seen of 7 total/);
  assert.equal(byId(results.zone, "CF-ZONE-02").evidence.counts.manual, 1);
});

test("self-check (d): a fully compliant account built from documented fields passes every automatable control", async () => {
  const results = await runAllAssessments(fixtureClient("compliant"));
  for (const result of Object.values(results)) {
    for (const item of result.findings) {
      assert.equal(item.status, "pass", `${item.id}: ${item.summary}`);
    }
    assert.deepEqual(result.errors, []);
  }
  assert.equal(results.identity.findings.length + results.zone.findings.length + results.traffic.findings.length, 27);
});

test("verdict rule 10: listCursorPaginated reports an empty page with a cursor, a repeated cursor, the page budget, and a mid-listing 404 as truncated", async () => {
  const cursorClient = (handler) => new CloudflareApiClient(sampleConfig(), { fetchImpl: fakeFetch(handler).fetchImpl });

  const emptyPageWithCursor = await cursorClient((url) => {
    const cursor = url.searchParams.get("cursor");
    return cursor
      ? { payload: { success: true, result: [], result_info: { cursors: { after: "still-more" } } } }
      : { payload: { success: true, result: [{ id: "rs-1" }], result_info: { cursors: { after: "c-1" } } } };
  }).listZoneRulesets("zone-1");
  assert.equal(emptyPageWithCursor.items.length, 1);
  assert.equal(emptyPageWithCursor.truncated, true);
  assert.equal(emptyPageWithCursor.totalCount, undefined);

  const repeatedCursor = await cursorClient(() => ({ payload: { success: true, result: [{ id: "rs-x" }], result_info: { cursors: { after: "same" } } } })).listZoneRulesets("zone-1");
  assert.equal(repeatedCursor.truncated, true, "a cursor that repeats the one just used is reported as truncated instead of following it forever");
  assert.equal(repeatedCursor.items.length, 2);

  let page = 0;
  const budget = await cursorClient(() => {
    page += 1;
    return { payload: { success: true, result: [{ id: `rs-${page}` }], result_info: { cursors: { after: `c-${page}` } } } };
  }).listZoneRulesets("zone-1");
  assert.equal(page, 100, "the cursor loop stops at its page budget");
  assert.equal(budget.items.length, 100);
  assert.equal(budget.truncated, true);
  assert.equal(budget.totalCount, undefined);

  const cursorNotFound = await cursorClient((url) => (url.searchParams.get("cursor")
    ? { status: 404, payload: { success: false, errors: [{ code: 10000, message: "not found" }] } }
    : { payload: { success: true, result: [{ id: "rs-1" }], result_info: { cursors: { after: "c-1" } } } })).listZoneRulesets("zone-1");
  assert.equal(cursorNotFound.items.length, 1);
  assert.equal(cursorNotFound.truncated, true, "a 404 after items were collected keeps them and reports the listing incomplete");

  const pageNotFound = await cursorClient((url) => (Number(url.searchParams.get("page")) > 1
    ? { status: 404, payload: { success: false, errors: [{ code: 10000, message: "not found" }] } }
    : { payload: { success: true, result: Array.from({ length: 50 }, (_, index) => ({ id: `ip-${index}` })), result_info: { page: 1, per_page: 50, total_pages: 3, total_count: 150 } } })).listIpAccessRules("acc-123");
  assert.equal(pageNotFound.items.length, 50);
  assert.equal(pageNotFound.truncated, true);
  assert.equal(pageNotFound.totalCount, undefined);

  const firstPageNotFound = await cursorClient(() => ({ status: 404, payload: { success: false, errors: [{ code: 10000, message: "not found" }] } })).listIpAccessRules("acc-123");
  assert.deepEqual(firstPageNotFound, { items: [], truncated: false, totalCount: 0 }, "a 404 on the first page still means the product is not provisioned");
});

test("verdict rule 10: CF-IAM-04 caps at warn when the reusable Access policy list is truncated and names seen versus total", async () => {
  const client = fixtureClient("compliant", {
    async listAccessPolicies() {
      return { items: [{ id: "pol-2", name: "Staff", decision: "allow", reusable: true, include: [] }], truncated: true, totalCount: 1200 };
    },
  });
  const identity = await assessCloudflareIdentity(client);
  const access = byId(identity, "CF-IAM-04");
  assert.equal(access.status, "warn");
  assert.match(access.summary, /Partial reusable Access policy inventory: 1 seen of 1200 total/);
  assert.equal(access.evidence.reusable_policies_truncated, true);
  assert.equal(access.evidence.reusable_policies_total, 1200);
  assert.equal(access.evidence.reusable_policies_readable, true);
});

test("rule 1 corollary: multi-inventory findings never pass when only a secondary read returns 403 and name the unreadable endpoint", async () => {
  const policiesForbidden = await assessCloudflareIdentity(fixtureClient("compliant", {
    async listAccessPolicies() {
      throw forbidden("/accounts/acc-123/access/policies");
    },
  }));
  const access = byId(policiesForbidden, "CF-IAM-04");
  assert.equal(access.status, "manual", access.summary);
  assert.match(access.summary, /reusable policy list could not be checked/);
  assert.match(access.summary, /\/accounts\/acc-123\/access\/policies could not be read \(.*403/);
  assert.match(access.summary, /Access: Apps and Policies: Read/);
  assert.equal(access.evidence.reusable_policies_readable, false);
  // The denied inventory renders null with the observed status, never the zero of an empty fallback.
  assert.equal(access.evidence.reusable_policies, null);
  assert.equal(access.evidence.reusable_policies_total, null);
  assert.equal(access.evidence.reusable_policies_truncated, null);
  assert.equal(access.evidence.reusable_policies_http_status, 403);
  assert.equal(access.evidence.inline_policies, 1);
  assert.ok(policiesForbidden.errors.some((error) => error.includes("/accounts/acc-123/access/policies")));
  for (const item of policiesForbidden.findings) {
    if (item.id !== "CF-IAM-04") assert.equal(item.status, "pass", `${item.id} should be unaffected by the policies read: ${item.summary}`);
  }

  const accountTokensForbidden = await assessCloudflareIdentity(fixtureClient("compliant", {
    async listAccountTokens() {
      throw forbidden("/accounts/acc-123/tokens");
    },
  }));
  const tokenExpiry = byId(accountTokensForbidden, "CF-IAM-06");
  assert.equal(tokenExpiry.status, "warn", tokenExpiry.summary);
  assert.match(tokenExpiry.summary, /\/accounts\/acc-123\/tokens could not be read/);
  assert.deepEqual(tokenExpiry.evidence.sources.map((source) => source.readable), [true, false]);
  const deniedSource = tokenExpiry.evidence.sources[1];
  assert.deepEqual(
    { seen: deniedSource.seen, total: deniedSource.total, truncated: deniedSource.truncated, http_status: deniedSource.http_status, attempted: deniedSource.attempted },
    { seen: null, total: null, truncated: null, http_status: 403, attempted: true },
    "the denied token list carries no count or truncation flag, only the observed status",
  );

  const gatewayForbidden = await assessCloudflareTrafficControls(fixtureClient("compliant", {
    async listGatewayRules() {
      return { items: [], truncated: false, totalCount: 0 };
    },
    async getZeroTrustAccount() {
      throw forbidden("/accounts/acc-123/gateway");
    },
  }));
  const gateway = byId(gatewayForbidden, "CF-TRF-06");
  assert.equal(gateway.status, "manual", gateway.summary);
  assert.match(gateway.summary, /\/accounts\/\{account_id\}\/gateway could not be read \(.*403/);
});

/**
 * Planted values that must never reach the bundle, alphanumeric and random-looking so no 6-character window of
 * them occurs in the fixture's legitimate values (see the fixture self-check). A contact email's canary is its
 * local part; the domain is legitimate text.
 */
const FAKE_CLOUDFLARE_SECRETS = {
  tokenValue: "YYSQRQdqSqf9TtSkHKPxfKXQ",
  abuseContactEmail: "d4gLMFRxxvB3@example.test",
  zoneOwnerEmail: "d39crtHdJgRw@example.test",
  memberEmail: "WPHygAMNBYa8@example.test",
  accountFreeformSetting: "GhCYt6r7rzqWqPKCzb9k",
};
const FAKE_CLOUDFLARE_CANARIES = Object.values(FAKE_CLOUDFLARE_SECRETS).map((value) => value.split("@")[0]);

/** Other planted credentials: the header echoed by a proxy page, a configured token, and the canary run's token. */
const CLOUDFLARE_HEADER_ECHO_CANARY = "aJagv77Dvu2evcFMM4NP";
const CLOUDFLARE_CONFIGURED_TOKEN_CANARY = "dcgqmL3afrWE64EJTmzpzEjb";
const CLOUDFLARE_RUN_TOKEN_CANARY = "BhK5xQdrtGjV39mFJaKvKeRV";

/** Every planted canary a Cloudflare output is swept for, window by window. */
const CLOUDFLARE_PLANTED_CANARIES = Object.freeze([
  ...CANARY_VALUES,
  SHORT_BODY_CANARY,
  PARSER_SNIPPET_CANARY,
  ...FAKE_CLOUDFLARE_CANARIES,
  CLOUDFLARE_HEADER_ECHO_CANARY,
  CLOUDFLARE_CONFIGURED_TOKEN_CANARY,
  CLOUDFLARE_RUN_TOKEN_CANARY,
]);

test("verdict rule 9: exportCloudflareAuditBundle never writes token values, contact emails, or unprojected account settings into the bundle or its zip", async () => {
  const base = createTempBase("grclanker-cloudflare-secrets-");
  const client = fixtureClient("compliant", {
    async listAccounts() {
      return {
        items: [{
          id: "acc-123",
          name: "Example",
          type: "standard",
          settings: { enforce_twofactor: true, abuse_contact_email: FAKE_CLOUDFLARE_SECRETS.abuseContactEmail, default_nameservers: FAKE_CLOUDFLARE_SECRETS.accountFreeformSetting },
          legacy_flags: { secret_hint: FAKE_CLOUDFLARE_SECRETS.accountFreeformSetting },
        }],
        truncated: false,
        totalCount: 1,
      };
    },
    async listZones() {
      return {
        items: [{ id: "zone-1", name: "one.example", status: "active", plan: { id: "cf_pro", name: "Pro Website" }, owner: { id: "own-1", type: "user", email: FAKE_CLOUDFLARE_SECRETS.zoneOwnerEmail }, account: { id: "acc-123", name: "Example" } }],
        truncated: false,
        totalCount: 1,
      };
    },
    async listUserTokens() {
      return {
        items: [{ id: "tok-1", name: "audit", status: "active", expires_on: FUTURE, last_used_on: RECENT, issued_on: "2026-01-01T00:00:00Z", value: FAKE_CLOUDFLARE_SECRETS.tokenValue, policies: [] }],
        truncated: false,
        totalCount: 1,
      };
    },
    async listMembers() {
      return {
        items: [{ id: "m1", status: "accepted", user: { email: FAKE_CLOUDFLARE_SECRETS.memberEmail, two_factor_authentication_enabled: true }, roles: [{ id: "r1", name: "Super Administrator - All Privileges" }] }],
        truncated: false,
        totalCount: 1,
      };
    },
  });

  const result = await exportCloudflareAuditBundle(client, sampleConfig(), base);
  const files = readBundleFiles(result.outputDir);
  const entries = readZipEntries(result.zipPath);
  assert.ok(files.size > 10);
  assert.equal(entries.size, files.size, "every written file is in the zip");
  assertNoCanaryWindowsInFiles(assert, files, FAKE_CLOUDFLARE_CANARIES, "bundle files");
  assertNoCanaryWindowsInFiles(assert, entries, FAKE_CLOUDFLARE_CANARIES, "zip entries");

  const accounts = JSON.parse(files.get("core_data/accounts.json"));
  assert.deepEqual(Object.keys(accounts.items[0]).sort(), ["id", "name", "settings", "type"]);
  assert.deepEqual(accounts.items[0].settings, { enforce_twofactor: true, abuse_contact_email_configured: true });
  const zones = JSON.parse(files.get("core_data/zones.json"));
  assert.deepEqual(zones.items[0].owner, { id: "own-1", type: "user" });
  assert.deepEqual(zones.items[0].account, { id: "acc-123", name: "Example" });
  assert.equal(zones.items[0].plan.name, "Pro Website");
});

test("verdict rule 9: non-JSON error bodies are described, never echoed, in CloudflareApiError messages", async () => {
  const leaked = CLOUDFLARE_HEADER_ECHO_CANARY;
  const fetchImpl = async () => ({
    ok: false,
    status: 502,
    statusText: "Bad Gateway",
    headers: { get: (name) => (name.toLowerCase() === "content-type" ? "text/html; charset=utf-8" : null) },
    async text() {
      return `<html><body>Proxy error: Authorization: Bearer ${leaked}</body></html>`;
    },
  });
  const client = new CloudflareApiClient(sampleConfig(), { fetchImpl });
  await assert.rejects(client.listMembers("acc-123"), (error) => {
    assert.equal(error.status, 502);
    assert.equal(error.path, "/accounts/acc-123/members");
    assertNoCanaryWindows(assert, error.message, [leaked], "CloudflareApiError message");
    assert.match(error.message, /\(502 Bad Gateway\): non-JSON body \(text\/html, \d+ bytes\)/);
    return true;
  });

  // A 2xx answer that is not JSON (a proxy login page) is a failed read, not an empty inventory.
  const okHtml = new CloudflareApiClient(sampleConfig(), {
    fetchImpl: async () => new Response(`<html>Sign in with Bearer ${leaked}</html>`, { status: 200, statusText: "OK", headers: { "content-type": "text/html" } }),
  });
  await assert.rejects(okHtml.listMembers("acc-123"), (error) => {
    assert.equal(error.status, 200);
    assertNoCanaryWindows(assert, error.message, [leaked], "CloudflareApiError message");
    assert.match(error.message, /non-JSON payload for \/accounts\/acc-123\/members \(200 OK\): non-JSON body \(text\/html, \d+ bytes\)/);
    return true;
  });

  // Transport failures carry the path and the failure class, never a status they did not observe.
  const timedOut = new CloudflareApiClient(sampleConfig({ timeoutMs: 5 }), {
    fetchImpl: (_url, init) => new Promise((_resolve, reject) => {
      init.signal.addEventListener("abort", () => reject(new Error(`aborted while holding Bearer ${leaked}`)));
    }),
  });
  await assert.rejects(timedOut.verifyCurrentToken(), (error) => {
    assert.equal(error.status, undefined);
    assert.equal(error.path, "/user/tokens/verify");
    assert.match(error.message, /timed out after 5 ms/);
    assertNoCanaryWindows(assert, error.message, [leaked], "CloudflareApiError message");
    return true;
  });
});

test("rule 9: redactErrorText scrubs every credential shape anywhere in an error string and leaves prose alone", () => {
  assertRedactionCases(assert, redactErrorText);
  // The configured token is scrubbed wherever an upstream error echoes it.
  new CloudflareApiClient(sampleConfig({ apiToken: CLOUDFLARE_CONFIGURED_TOKEN_CANARY }), { fetchImpl: async () => new Response("{}") });
  assert.equal(redactErrorText(`proxy replayed ${CLOUDFLARE_CONFIGURED_TOKEN_CANARY} upstream`), "proxy replayed [REDACTED] upstream");
});

test("rule 9 scrub boundary: name-shaped values stay bare, any value in a carrier is removed, token-shaped values are removed bare, the configured secret is removed in every encoded form, and the integration's fixed texts survive", () => {
  new CloudflareApiClient(sampleConfig({ apiToken: ENCODED_FORM_SECRET }), { fetchImpl: async () => new Response("{}") });
  assertScrubBoundary(assert, redactErrorText, {
    configuredSecret: ENCODED_FORM_SECRET,
    mustKeep: [
      "GET /accounts/acc-123/access/policies (403 Forbidden): Authentication error (code 10000)",
      "GET /zones/zone-1/settings/always_use_https (502 Bad Gateway): non-JSON body (text/html, 5120 bytes)",
      "SyntaxError: response could not be parsed as JSON; the parser's message is not recorded because it quotes the body",
      "Cloudflare API token verification failed for tok-current: token status is expired",
      "reusable policies not readable (GET /accounts/acc-123/access/policies: 403 Forbidden)",
      ...cloudflareFixedTexts(),
    ],
  });
});

test("rule 9 escapes (reviewer D round 5 escapes): a header carrier after a two-character or six-character JSON escape is removed exactly as at a line start, for the nineteen header lines the integrations send, the six escapes, and five forms, at 6-to-24 windows, direct and through the client's JSON error path", async () => {
  const judged = assertEscapedHeaderCarriers(assert, redactErrorText);
  assert.equal(judged, ESCAPED_HEADER_LINES.length * JSON_ESCAPES.length * 5);
  assert.equal(ESCAPED_HEADER_LINES.length, 19);

  // The two classes reviewer D found leaking, carried by a JSON error message on a probed surface: a later cookie
  // pair whose name has no credential word, and X-Auth-Key with an alphabetic value, each after a two-character
  // and a six-character escape.
  const tracker = "Rk7mVq2Zt9Xw4Ly6Pn8Hc3Jb";
  const globalKey = "prodkeyQz8Nv3Tm5Rk2Wy7";
  const message = `request failed\\nCookie: theme=dark; my.tracker=${tracker}\\u000aX-Auth-Key: ${globalKey}`;
  assert.ok(message.includes("\\n") && message.includes("\\u000a"), "the message carries the escapes as backslash text");
  const routes = healthyCloudflareRoutes();
  routes[`/accounts/${ACCOUNT}/members`] = () => new Response(JSON.stringify({ success: false, errors: [{ code: 10000, message }], messages: [], result: null }), { status: 403, statusText: "Forbidden", headers: CLOUDFLARE_JSON_HEADERS });
  const client = new CloudflareApiClient(sampleConfig(), { fetchImpl: cloudflareRoutedFetch(routes) });
  const access = await checkCloudflareAccess(client);
  const members = access.surfaces.find((entry) => entry.name === "members");
  assert.equal(members.status, "not_readable");
  assert.ok(members.error.includes("\\nCookie: [REDACTED]\\u000aX-Auth-Key: [REDACTED]"), `both carriers are removed whole after their escapes: ${members.error}`);
  assertNoCanaryWindows(assert, access, [tracker, globalKey], "check_access after escaped headers");
});

test("rule 9 depth control (reviewer D round 5 depth control): every string a snapshot keeps passes the data-side carrier scrub at every depth in place, a credential-keyed value is the marker in place with its benign sibling kept, and a container nested past the cap of 32 is the marker, on scrubSnapshotValue and end to end through every healthy route into the bundle, the zip, and every tool payload", async () => {
  assert.equal(DEPTH_CONTROL.cap, 32);
  // The exported walker: level k of the tree handed to it sits at depth k, so levels 1 to 32 are in place and level 33 is the marker.
  assertDepthControl(assert, scrubSnapshotValue, { label: "cloudflare.scrubSnapshotValue" });
  assertDepthControl(assert, (tree) => scrubSnapshotValue([tree])[0], { label: "cloudflare.scrubSnapshotValue on a record list", rootDepth: 2 });
  assertDepthControl(assert, (tree) => scrubSnapshotValue({ result: [{ settings: tree }] }).result[0].settings, { label: "cloudflare.scrubSnapshotValue under an envelope", rootDepth: 4 });
  // The string half on its own: carriers go, identifiers stay (a 32-hex account id among them), the configured token goes in every form.
  const config = sampleConfig({ apiToken: CLOUDFLARE_RUN_TOKEN_CANARY });
  new CloudflareApiClient(config, { fetchImpl: cloudflareRoutedFetch(healthyCloudflareRoutes()) });
  assertCarrierTextScrub(assert, redactCarrierText, { label: "cloudflare.redactCarrierText", configuredSecret: CLOUDFLARE_RUN_TOKEN_CANARY });
  for (const { label, id } of SERVER_ASSIGNED_HEX_IDS) {
    assert.equal(redactCarrierText(`/accounts/${id}/members read`), `/accounts/${id}/members read`, `a snapshot keeps a ${label} whole`);
  }

  // End to end: the tree planted on every envelope and in every record and nested record of every healthy route.
  // Every Cloudflare writer projects documented fields, so no bundle file, zip entry, or tool payload carries a trace of it.
  const planted = { count: 0 };
  const log = [];
  const run = await runEveryCloudflareTool(
    new CloudflareApiClient(config, { fetchImpl: cloudflareRoutedFetch(withPlantedRoutes(healthyCloudflareRoutes(), { planted }), log) }),
    createTempBase("grclanker-cloudflare-depth-"),
  );
  assert.ok(planted.count >= Object.keys(healthyCloudflareRoutes()).length, `the fixture planted the tree into ${planted.count} objects`);
  assert.equal(run.exported.errorCount, 0, "the planted tree causes no read to fail");
  assert.ok(run.access.surfaces.every((surface) => surface.status === "readable"), "every surface reads the planted fixture");
  assertDepthControlOutputs(
    assert,
    { files: readBundleFiles(run.exported.outputDir), zipEntries: readZipEntries(run.exported.zipPath), outputs: [run.access, ...run.assessments] },
    { label: "cloudflare", treeExpected: false },
  );
});

test("rule 9 fixed texts (GWS note 1): every fixed-text message the integration emits survives redactErrorText unchanged, from the SyntaxError and non-JSON notes through the not attempted and Not attempted wordings to the manual-review, partial-inventory, and zone-plan prose", () => {
  const texts = cloudflareFixedTexts();
  assertFixedTextsSurvive(assert, redactErrorText, texts, { minimum: 25 });
  for (const required of [
    "SyntaxError: response could not be parsed as JSON; the parser's message is not recorded because it quotes the body",
    "not attempted: this client does not expose listAccessPolicies, so no request was made",
    "Not attempted: /zones could not be read (Cloudflare request failed for /zones (403 Forbidden): Authentication error)",
    "3 zone-scoped surfaces were not attempted because /zones could not be read (403).",
    "Cloudflare request failed for /zones (timed out after 30000 ms)",
    "Cloudflare request failed for /zones (network error: fetch failed)",
    "Cloudflare API reported failure for /zones.",
    "The active API token reported status expired instead of active.",
    "Global API Key auth has no token to verify; create a scoped read-only API token and record its permission groups manually.",
  ]) {
    assert.ok(texts.includes(required), `the fixed-text list carries: ${required}`);
  }
  assert.ok(texts.some((text) => HTML_BODY_NOTE.test(text)), "the fixed-text list carries the non-JSON body note");
  assert.ok(texts.some((text) => /^Manual review required: \/accounts\/acc-123\/access\/policies could not be read \(Cloudflare request failed for .* Grant Access: Apps and Policies: Read to the audit token/.test(text)), "the manual-review reason is in the list");
  assert.ok(texts.some((text) => /^Partial Access application inventory: 1 seen of 40 total; unseen items were not assessed\.$/.test(text)), "the partial-inventory note is in the list");
  assert.ok(texts.some((text) => text.startsWith("The zone plan could not be named because /zones/{zone_id}/subscription was not readable (")), "the zone-plan note is in the list");

  // The renderings the client throws, built the way requestJson builds them, survive too.
  const thrown = [
    "Cloudflare request failed for /accounts/acc-123/access/policies (403 Forbidden): Authentication error",
    "Cloudflare request failed for /zones/zone-1/settings/always_use_https (502 Bad Gateway): non-JSON body (text/html, 5120 bytes)",
    "Cloudflare request returned a non-JSON payload for /zones (200 OK): non-JSON body (text/plain, 21 bytes)",
    "Cloudflare request failed for /user/tokens/verify (timed out after 30000 ms)",
  ];
  for (const message of thrown) {
    assert.equal(redactErrorText(message), message, `the thrown rendering survives the scrub: ${message}`);
  }
});

test("rule 9 must-keep and must-redact table (addendum 7): every endpoint path, name, principal, status text, finding id, and fixed text the summaries, markers, probes, and evidence rely on survives redactErrorText alone and inside a realistic summary sentence, and every canary planted in every carrier beside one of them is removed while the row survives (extends the rule 9 scrub boundary fixed texts)", () => {
  const groups = [
    {
      label: "endpoint paths",
      values: [
        "/zones",
        "/zones/zone-1/dnssec",
        "/zones/{zone_id}/dnssec",
        "/zones/zone-1/settings/always_use_https",
        "/zones/zone-1/settings/min_tls_version",
        "/zones/zone-1/rulesets/phases/http_request_firewall_custom/entrypoint",
        "/zones/zone-1/ssl/universal/settings",
        "/zones/zone-1/origin_tls_client_auth/settings",
        "/zones/zone-1/subscription",
        "/zones/{zone_id}/firewall/rules",
        "/accounts/acc-123/access/policies",
        "/accounts/acc-123/access/apps",
        "/accounts/acc-123/access/identity_providers",
        "/accounts/acc-123/members",
        "/accounts/acc-123/tokens",
        "/accounts/acc-123/audit_logs",
        "/accounts/acc-123/gateway/rules",
        "/user/tokens/verify",
        "/user/tokens/tok-current",
        "GET /accounts/acc-123/access/policies",
        "https://api.cloudflare.com/client/v4/zones/zone-1/dnssec",
      ],
      sentence: (value) => `Cloudflare request failed for ${value} (403 Forbidden): Authentication error`,
    },
    {
      label: "names",
      values: [
        "zone-1",
        "acc-123",
        "one.example",
        "prod-us-east-2026",
        "tok-current",
        "http_request_firewall_custom",
        "always_use_https",
        "min_tls_version",
        "strict_transport_security",
        "Zone Read",
        "Access: Apps and Policies: Read",
      ],
      sentence: (value) => `${value} was not readable (403 Forbidden); its count is null, the surface is listed as not_readable, and the verdict is manual.`,
    },
    {
      label: "principals",
      values: ["tok-current", "svc-deploy", "auditor@example.com", "owner@example.com", "Super Administrator - All Privileges", "Administrator Read Only"],
      sentence: (value) => `Account member ${value} could not be checked because /accounts/acc-123/members returned 403 Forbidden; the member count is null.`,
    },
    {
      label: "status text",
      values: [
        "403 Forbidden",
        "404 Not Found",
        "502 Bad Gateway",
        "200 OK",
        "timed out after 30000 ms",
        "network error: fetch failed",
        "Authentication error",
        "token status is expired",
        "non-JSON body (text/html, 5120 bytes)",
      ],
      sentence: (value) => `GET /accounts/acc-123/access/policies returned ${value}, so the reusable Access policy list must be collected manually.`,
    },
    {
      label: "finding ids",
      values: ["CF-IAM-01", "CF-IAM-04", "CF-IAM-06", "CF-ZONE-07", "CF-ZONE-11", "CF-TRF-03", "CF-TRF-06"],
      sentence: (value) => `${value} is manual because /zones/zone-1/dnssec was not readable (403 Forbidden).`,
    },
    {
      label: "fixed texts",
      values: cloudflareFixedTexts(),
      sentence: (value) => `CF-IAM-04: ${value}`,
    },
    QUOTED_NON_CREDENTIAL_GROUP,
    MASKED_HEX_ID_GROUP,
  ];
  assertMustKeepRows(assert, redactErrorText, groups);
  assertMustRedactRowsBesideMustKeep(assert, redactErrorText, groups);
});

test("rule 9 credential-named pairs (reviewer D round 5 baseline): a value under a credential-named key is removed whatever its shape and length, unquoted as well as quoted, in every form the pair takes, while identifier-named keys keep their values unless the value's own shape removes it", () => {
  assertCredentialPairValuesRemoved(assert, redactErrorText);
  assertIdentifierKeyRows(assert, redactErrorText);
  assertFlagAndPathPairRows(assert, redactErrorText);
  // The retired value-shape test would have kept every one of these; the pair rule no longer asks.
  for (const [text, expected] of [
    ["password=letmein", "password=[REDACTED]"],
    ["DB_PASSWORD=Sunshine", "DB_PASSWORD=[REDACTED]"],
    ["AZURE_CLIENT_SECRET: abc12", "AZURE_CLIENT_SECRET: [REDACTED]"],
    ["DUO_SKEY=p@ss", "DUO_SKEY=[REDACTED]"],
    ["DUO_IKEY=DIXXXXXXXXXXXXXXXXXX", "DUO_IKEY=[REDACTED]"],
    ["DUO_IKEY=letmein", "DUO_IKEY=[REDACTED]"],
    ["ikey: monkey", "ikey: [REDACTED]"],
    ['{"DUO_IKEY":"Sunshine"}', '{"DUO_IKEY":"[REDACTED]"}'],
    ['"ikey": "abc12"', '"ikey": "[REDACTED]"'],
    ["Authorization: Basic letmein", "Authorization: Basic [REDACTED]"],
    ["token: value shape", "token: [REDACTED] shape"],
  ]) {
    assert.equal(redactErrorText(text), expected, `credential-named pair: ${text}`);
  }
  // A PascalCase error code that ends in a credential word is prose, and a bare scheme word is not a pair; a path segment
  // ending in a credential word is one (assertFlagAndPathPairRows).
  for (const text of [
    "InvalidAuthenticationToken: Access token has expired. Basic authentication is disabled for this tenant.",
    "ExpiredToken: The security token included in the request is expired",
    "sent as Authorization: Bearer) or as X-Auth-Key",
    "oauth: invalid_grant was returned",
  ]) {
    assert.equal(redactErrorText(text), text, `prose beside a credential word survives: ${text}`);
  }
});

test("rule 9 URL userinfo boundary (CodeRabbit on #76 at b0ef16f): an `@` inside a query or a fragment is not a userinfo boundary, so the real host stays, a query becomes the marker whole, and a fragment is kept, on the error sink, the data-string sink, and a snapshot string", () => {
  assertUrlUserinfoBoundaryRows(assert, redactErrorText, { label: "cloudflare.redactErrorText" });
  assertUrlUserinfoBoundaryRows(assert, redactCarrierText, { label: "cloudflare.redactCarrierText" });
  assertUrlUserinfoBoundaryRows(assert, (text) => scrubSnapshotValue(text), { label: "cloudflare.scrubSnapshotValue" });
});
test("rule 9 bearer-id override (CodeRabbit r4077259415 on #78): a key ending in secret_id or naming a session id is a credential key despite its id suffix, so a Vault AppRole secret id goes whatever its shape, a UUID included, through the error sink, the data-string sink, the snapshot walker, and the thrown error, while AZURE_TENANT_ID=<uuid> and the other identifier keys keep their values", async () => {
  assertBearerIdKeyRows(assert, redactErrorText);
  assertBearerIdKeyRows(assert, redactCarrierText, { controls: BEARER_ID_CARRIER_CONTROL_ROWS });
  assertBearerIdSnapshotKeys(assert, scrubSnapshotValue);
  const [uuid, random] = BEARER_ID_VALUES;
  const tenant = "3f2504e0-4f89-11d3-9a0c-0305e82c3301";
  const echoed = `VAULT_SECRET_ID=${uuid} and role_secret_id: ${random} were rejected; AZURE_TENANT_ID=${tenant} was accepted`;
  const expected = `VAULT_SECRET_ID=[REDACTED] and role_secret_id: [REDACTED] were rejected; AZURE_TENANT_ID=${tenant} was accepted`;
  const thrown = new CloudflareApiError(`Cloudflare request failed for /accounts/acc-123/members (403 Forbidden): ${echoed}`, 403, "/accounts/acc-123/members");
  assert.equal(thrown.message, `Cloudflare request failed for /accounts/acc-123/members (403 Forbidden): ${expected}`);
  assertNoCanaryWindows(assert, thrown.message, [uuid, random], "CloudflareApiError message");
});

const CLOUDFLARE_JSON_HEADERS = { "content-type": "application/json" };

function cloudflareOk(result) {
  return () => new Response(JSON.stringify({ success: true, errors: [], messages: [], result }), { status: 200, statusText: "OK", headers: CLOUDFLARE_JSON_HEADERS });
}

function cloudflareForbidden() {
  return new Response(JSON.stringify({ success: false, errors: [{ code: 10000, message: "Authentication error" }], messages: [], result: null }), { status: 403, statusText: "Forbidden", headers: CLOUDFLARE_JSON_HEADERS });
}

function cloudflareNotFound() {
  return new Response(JSON.stringify({ success: false, errors: [{ code: 10000, message: "not found" }], messages: [], result: null }), { status: 404, statusText: "Not Found", headers: CLOUDFLARE_JSON_HEADERS });
}

function cloudflareCanaryHtml() {
  return new Response(htmlCanaryBody(), { status: 502, statusText: "Bad Gateway", headers: { "content-type": "text/html; charset=utf-8" } });
}

function cloudflareCanaryJson() {
  return new Response(JSON.stringify({ success: false, errors: [{ code: 10000, message: jsonCanaryMessage() }], messages: [], result: null }), { status: 403, statusText: "Forbidden", headers: CLOUDFLARE_JSON_HEADERS });
}

const ZONE = "zone-1";
const ACCOUNT = "acc-123";

/**
 * Every documented path the access check, the three assessments, and the export request for one
 * account with one zone, each answering with the compliant fixture. Keys are request paths without
 * the /client/v4 prefix; the fallback routes (/firewall/rules, /rate_limits, /subscription) are
 * included so a run that reaches them is still served.
 */
function healthyCloudflareRoutes(account = ACCOUNT, zone = ZONE) {
  const routes = {
    "/user/tokens/verify": cloudflareOk({ id: "tok-current", status: "active", expires_on: FUTURE, not_before: "2026-01-01T00:00:00Z" }),
    "/user/tokens/tok-current": cloudflareOk({ id: "tok-current", status: "active", expires_on: FUTURE, policies: [{ id: "p1", effect: "allow", permission_groups: [{ id: "pg1", name: "Zone Read" }], resources: { [`com.cloudflare.api.account.zone.${zone}`]: "*" } }] }),
    "/user/tokens": cloudflareOk([
      { id: "tok-1", name: "audit", status: "active", expires_on: FUTURE, last_used_on: RECENT, issued_on: "2026-01-01T00:00:00Z", policies: [] },
      { id: "tok-2", name: "old", status: "expired", expires_on: "2025-01-01T00:00:00Z", policies: [] },
    ]),
    "/accounts": cloudflareOk([{ id: account, name: "Example", type: "standard", settings: { enforce_twofactor: true } }]),
    "/zones": cloudflareOk([{ id: zone, name: "one.example", status: "active" }]),
    [`/accounts/${account}/tokens`]: cloudflareOk([{ id: "atok-1", name: "ci", status: "active", expires_on: FUTURE, last_used_on: RECENT, policies: [] }]),
    [`/accounts/${account}/members`]: cloudflareOk([
      { id: "m1", status: "accepted", user: { email: "owner@example.com", two_factor_authentication_enabled: true }, roles: [{ id: "r1", name: "Super Administrator - All Privileges" }] },
      { id: "m2", status: "accepted", user: { email: "auditor@example.com", two_factor_authentication_enabled: true }, roles: [{ id: "r2", name: "Administrator Read Only" }] },
    ]),
    [`/accounts/${account}/access/apps`]: cloudflareOk([{ id: "app-1", name: "Admin", type: "self_hosted", domain: "admin.one.example", policies: [{ id: "pol-1", decision: "allow", include: [{ email_domain: { domain: "example.com" } }] }] }]),
    [`/accounts/${account}/access/policies`]: cloudflareOk([{ id: "pol-2", name: "Staff", decision: "allow", reusable: true, include: [] }]),
    [`/accounts/${account}/access/identity_providers`]: cloudflareOk([{ id: "idp-1", name: "Okta", type: "okta" }]),
    [`/accounts/${account}/audit_logs`]: cloudflareOk([{ id: "evt-1", when: RECENT, action: { type: "change_setting", result: true }, actor: { email: "admin@example.com" } }]),
    [`/accounts/${account}/gateway/rules`]: cloudflareOk([{ id: "gw-1", name: "Block malware", action: "block", enabled: true, filters: ["dns"] }, { id: "gw-2", name: "Isolate", action: "isolate", enabled: true, filters: ["http"] }]),
    [`/accounts/${account}/gateway`]: cloudflareOk({ id: account, gateway_tag: "gw-tag-1", provider_name: "Cloudflare" }),
    [`/accounts/${account}/firewall/access_rules/rules`]: cloudflareOk([{ id: "ip-1", mode: "block", notes: "Known scanner", modified_on: RECENT, configuration: { target: "ip", value: "198.51.100.1" } }]),
    [`/zones/${zone}/dnssec`]: cloudflareOk({ status: "active", algorithm: "13" }),
    [`/zones/${zone}/rulesets`]: cloudflareOk([
      { id: "rs-managed", kind: "zone", phase: CLOUDFLARE_RULESET_PHASES.firewallManaged, name: "zone", version: "1" },
      { id: "rs-ddos", kind: "managed", phase: CLOUDFLARE_RULESET_PHASES.ddosL7, name: "DDoS L7 ruleset", version: "1" },
    ]),
    [`/zones/${zone}/ssl/universal/settings`]: cloudflareOk({ enabled: true }),
    [`/zones/${zone}/origin_tls_client_auth/settings`]: cloudflareOk({ enabled: true }),
    [`/zones/${zone}/origin_tls_client_auth/hostnames`]: cloudflareOk([{ cert_id: "cert-aop-1", created_at: "2026-01-01T00:00:00Z", enabled: true, hostname: "app.one.example", status: "active", updated_at: RECENT }]),
    [`/zones/${zone}/ssl/certificate_packs`]: cloudflareOk([{ id: "pack-1", type: "universal", status: "active", hosts: ["one.example"], certificates: [{ id: "cert-1", status: "active", expires_on: FUTURE, hosts: ["one.example"] }] }]),
    [`/zones/${zone}/dns_records`]: cloudflareOk([
      { id: "rec-1", type: "A", name: "one.example", content: "203.0.113.10", proxied: true, proxiable: true, ttl: 1 },
      { id: "rec-2", type: "TXT", name: "one.example", content: "v=spf1 -all", proxied: false, proxiable: false, ttl: 300 },
    ]),
    [`/zones/${zone}/pagerules`]: cloudflareOk([{ id: "pr-1", status: "active", priority: 1, targets: [{ target: "url", constraint: { operator: "matches", value: "one.example/static/*" } }], actions: [{ id: "browser_cache_ttl", value: 14400 }] }]),
    [`/zones/${zone}/bot_management`]: cloudflareOk({ fight_mode: true }),
    [`/zones/${zone}/subscription`]: cloudflareOk({ id: "sub-1", state: "Paid", rate_plan: { id: "cf_pro", public_name: "Pro Website", currency: "USD" } }),
    [`/zones/${zone}/firewall/rules`]: cloudflareOk([]),
    [`/zones/${zone}/rate_limits`]: cloudflareOk([]),
  };
  for (const setting of compliantSettings()) routes[`/zones/${zone}/settings/${setting.id}`] = cloudflareOk(setting);
  for (const phase of [CLOUDFLARE_RULESET_PHASES.firewallManaged, CLOUDFLARE_RULESET_PHASES.firewallCustom, CLOUDFLARE_RULESET_PHASES.ddosL7, CLOUDFLARE_RULESET_PHASES.responseHeadersTransform, CLOUDFLARE_RULESET_PHASES.rateLimit]) {
    routes[`/zones/${zone}/rulesets/phases/${phase}/entrypoint`] = cloudflareOk(compliantEntrypoint(phase));
  }
  return routes;
}

/** Fallback paths a compliant run never reaches; they are served so any run that does reach them is still healthy. */
const CLOUDFLARE_FALLBACK_ROUTES = new Set([`/zones/${ZONE}/firewall/rules`, `/zones/${ZONE}/rate_limits`, `/zones/${ZONE}/subscription`]);

/**
 * Serves the route table over the real client and records every request (method, path, status).
 * An unrouted path answers 500 with a distinctive message so the healthy baseline (errorCount 0)
 * proves the table is complete.
 */
function cloudflareRoutedFetch(routes, log = []) {
  return async (url, init) => {
    const parsed = new URL(url);
    const path = parsed.pathname.replace("/client/v4", "");
    const route = routes[path];
    const response = route
      ? await route(parsed)
      : new Response(JSON.stringify({ success: false, errors: [{ code: 1, message: `unrouted test path ${path}` }] }), { status: 500, statusText: "Internal Server Error", headers: CLOUDFLARE_JSON_HEADERS });
    log.push({ method: init?.method ?? "GET", path, status: response.status });
    return response;
  };
}

async function runEveryCloudflareTool(client, outputRoot) {
  const access = await checkCloudflareAccess(client);
  const identity = await assessCloudflareIdentity(client);
  const zone = await assessCloudflareZoneSecurity(client);
  const traffic = await assessCloudflareTrafficControls(client);
  const exported = await exportCloudflareAuditBundle(client, client.getResolvedConfig(), outputRoot);
  return { access, assessments: [identity, zone, traffic], exported };
}

/** Every string an assessment records about a failed read: the errors array plus evidence error fields. */
function recordedCloudflareErrors(assessments) {
  const recorded = [];
  for (const assessment of assessments) {
    recorded.push(...assessment.errors);
    for (const item of assessment.findings) {
      for (const [key, value] of Object.entries(item.evidence ?? {})) {
        if (typeof value === "string" && /(^|_)error$/.test(key)) recorded.push(value);
      }
      for (const source of item.evidence?.sources ?? []) {
        if (typeof source.error === "string") recorded.push(source.error);
      }
    }
  }
  return recorded;
}

test("fixture self-check: every planted canary is alphanumeric and random-looking, and no 6-to-24-character window of any canary occurs in the healthy fixture's legitimate values, so a windowed leak assertion can fail only on a real echo", async () => {
  const legitimate = new Map();
  for (const [path, route] of Object.entries(healthyCloudflareRoutes())) {
    legitimate.set(`route ${path}`, await route(new URL(`https://api.cloudflare.com/client/v4${path}`)).text());
  }
  const run = await runEveryCloudflareTool(
    new CloudflareApiClient(sampleConfig(), { fetchImpl: cloudflareRoutedFetch(healthyCloudflareRoutes()) }),
    createTempBase("grclanker-cloudflare-self-check-"),
  );
  legitimate.set("check_access", run.access);
  for (const assessment of run.assessments) legitimate.set(assessment.title, assessment);
  for (const [name, text] of readBundleFiles(run.exported.outputDir)) legitimate.set(`bundle ${name}`, text);
  for (const [name, text] of readZipEntries(run.exported.zipPath)) legitimate.set(`zip ${name}`, text);
  legitimate.set("sample config", sampleConfig());
  assertCanaryFixture(assert, CLOUDFLARE_PLANTED_CANARIES, legitimate, "cloudflare fixture");
});

test("rule 9: a 502 HTML page or a JSON error message carrying credentials on any surface never reaches a probe, finding, summary, or bundle file", async () => {
  const config = sampleConfig({ apiToken: CLOUDFLARE_RUN_TOKEN_CANARY });
  const outputRoot = createTempBase("grclanker-cloudflare-canary-");

  // The healthy run proves the route table is the surface list: every route is requested and nothing else is.
  const healthyLog = [];
  const healthy = new CloudflareApiClient(config, { fetchImpl: cloudflareRoutedFetch(healthyCloudflareRoutes(), healthyLog) });
  const healthyRun = await runEveryCloudflareTool(healthy, outputRoot);
  assert.equal(healthyRun.exported.errorCount, 0, "the healthy fixture records no errors");
  for (const assessment of healthyRun.assessments) {
    for (const item of assessment.findings) assert.equal(item.status, "pass", `${item.id}: ${item.summary}`);
  }
  const requested = new Set(healthyLog.map((entry) => entry.path));
  const surfaces = Object.keys(healthyCloudflareRoutes()).filter((path) => !CLOUDFLARE_FALLBACK_ROUTES.has(path));
  assert.deepEqual([...requested].sort(), [...surfaces].sort(), "every documented surface is exercised by the access check, the assessments, or the export");
  const accessLog = [];
  await checkCloudflareAccess(new CloudflareApiClient(config, { fetchImpl: cloudflareRoutedFetch(healthyCloudflareRoutes(), accessLog) }));
  const probed = new Set(accessLog.map((entry) => entry.path));

  for (const surface of surfaces) {
    for (const [variant, response, expectedNote] of [
      ["html", cloudflareCanaryHtml, HTML_BODY_NOTE],
      ["json", cloudflareCanaryJson, REDACTED_CANARY_URL],
    ]) {
      const label = `${surface} (${variant})`;
      const client = new CloudflareApiClient(config, { fetchImpl: cloudflareRoutedFetch({ ...healthyCloudflareRoutes(), [surface]: response }) });
      const { access, assessments, exported } = await runEveryCloudflareTool(client, createTempBase("grclanker-cloudflare-canary-"));

      assertNoCanaryWindows(assert, access, CLOUDFLARE_PLANTED_CANARIES, `${label} check_access`);
      if (probed.has(surface)) {
        const failed = access.surfaces.filter((entry) => entry.status === "not_readable");
        assert.ok(failed.length > 0, `${label}: the access check records the failing surface`);
        for (const entry of failed) {
          assert.match(entry.error, expectedNote, `${label}: probe ${entry.name} carries the expected note`);
          assert.equal(entry.count, null, `${label}: probe ${entry.name} renders no count`);
          assert.equal(entry.http_status, variant === "html" ? 502 : 403, `${label}: probe ${entry.name} records the observed status`);
        }
      }

      const recorded = recordedCloudflareErrors(assessments);
      for (const assessment of assessments) assertNoCanaryWindows(assert, assessment, CLOUDFLARE_PLANTED_CANARIES, `${label} ${assessment.title}`);
      assert.ok(recorded.length > 0, `${label}: the failing surface is recorded by an assessment`);
      if (variant === "html") {
        for (const error of recorded) assert.match(error, HTML_BODY_NOTE, `${label}: "${error}" carries the status-and-length note`);
        assert.ok(recorded.some((error) => /\(502 Bad Gateway\): non-JSON body \(text\/html, \d+ bytes\)/.test(error)), `${label}: the note names the observed status`);
      } else {
        for (const error of recorded) assert.match(error, REDACTED_CANARY_URL, `${label}: "${error}" keeps the URL host and path with its query redacted`);
      }

      const files = readBundleFiles(exported.outputDir);
      assertNoCanaryWindowsInFiles(assert, files, CLOUDFLARE_PLANTED_CANARIES, `${label} bundle`);
      assertNoCanaryWindowsInFiles(assert, readZipEntries(exported.zipPath), CLOUDFLARE_PLANTED_CANARIES, `${label} zip`);
      assert.ok(exported.errorCount > 0, `${label}: the export logs the failed read`);
      if (variant === "html") assert.match(files.get("_errors.log"), /502 Bad Gateway\): non-JSON body \(text\/html, \d+ bytes\)/);
    }
  }
});

/**
 * Single-surface denials with the evidence a consumer reads for the denied inventory. Every field
 * listed must render null (or false for readable flags), never the zero or empty list of a fallback.
 */
const CLOUDFLARE_DENIAL_TABLE = [
  { surface: "/accounts", finding: null, summaryFields: { identity: ["visible_accounts"] }, coreData: "core_data/accounts.json" },
  { surface: "/zones", finding: null, summaryFields: { zone: ["sampled_zones", "zones_total", "zone_inventory_truncated"], traffic: ["sampled_zones", "zones_total", "zone_inventory_truncated"], identity: ["sampled_zones"] }, coreData: "core_data/zones.json" },
  { surface: "/user/tokens", finding: "CF-IAM-06", nullFields: [], sourceIndex: 0 },
  { surface: `/accounts/${ACCOUNT}/tokens`, finding: "CF-IAM-06", nullFields: [], sourceIndex: 1 },
  { surface: `/accounts/${ACCOUNT}/members`, finding: "CF-IAM-03", nullFields: ["super_admins", "members_seen", "members_total", "members_truncated", "members_without_2fa"], statusField: "members_http_status", summaryFields: { identity: ["super_admins"] } },
  { surface: `/accounts/${ACCOUNT}/access/apps`, finding: "CF-IAM-04", nullFields: ["access_apps", "access_apps_total", "access_apps_truncated", "inline_policies", "bypass_policies", "apps_without_policies"], statusField: "access_apps_http_status", summaryFields: { identity: ["access_apps", "access_policies"] } },
  { surface: `/accounts/${ACCOUNT}/access/policies`, finding: "CF-IAM-04", nullFields: ["reusable_policies", "reusable_policies_total", "reusable_policies_truncated"], statusField: "reusable_policies_http_status", summaryFields: { identity: ["access_policies"] } },
  { surface: `/accounts/${ACCOUNT}/access/identity_providers`, finding: "CF-IAM-05", nullFields: ["identity_providers", "identity_provider_types", "identity_providers_truncated"], statusField: "identity_providers_http_status", summaryFields: { identity: ["identity_providers"] } },
  { surface: `/accounts/${ACCOUNT}/audit_logs`, finding: "CF-TRF-04", nullFields: ["audit_events"], statusField: "http_status", summaryFields: { traffic: ["audit_events"] } },
  { surface: `/accounts/${ACCOUNT}/firewall/access_rules/rules`, finding: "CF-TRF-05", nullFields: ["ip_access_rules"], statusField: "http_status", summaryFields: { traffic: ["ip_access_rules"] } },
  { surface: `/accounts/${ACCOUNT}/gateway/rules`, finding: "CF-TRF-06", nullFields: ["gateway_rules"], statusField: "http_status", summaryFields: { traffic: ["gateway_rules"] } },
];

const ASSESSMENT_KEYS = { identity: "Cloudflare identity posture", zone: "Cloudflare zone security posture", traffic: "Cloudflare traffic controls posture" };

test("denied-list markers: a denied list writes a not-collected marker in core_data with the observed status and path, a readable-but-empty list stays [], and every count for the denied inventory renders null", async () => {
  const config = sampleConfig();
  const outputRoot = createTempBase("grclanker-cloudflare-denied-");

  // Readable-but-empty lists keep an empty items array with real, observed flags.
  const emptyRoutes = { ...healthyCloudflareRoutes(), "/zones": cloudflareOk([]) };
  const emptyRun = await runEveryCloudflareTool(new CloudflareApiClient(config, { fetchImpl: cloudflareRoutedFetch(emptyRoutes) }), outputRoot);
  const emptyZones = JSON.parse(readBundleFiles(emptyRun.exported.outputDir).get("core_data/zones.json"));
  assert.deepEqual(emptyZones, { items: [], truncated: false, totalCount: 0 }, "a readable-but-empty zone list is written as an empty items array with observed flags");
  assert.equal(emptyRun.access.surfaces.find((entry) => entry.name === "zones").count, 0, "a readable-but-empty probe reports the real zero");
  for (const name of ["zone_settings", "dnssec", "rulesets"]) {
    const probe = emptyRun.access.surfaces.find((entry) => entry.name === name);
    assert.equal(probe.status, "not_configured", `${name}: a readable-but-empty zone list leaves the zone-scoped probe not_configured`);
    assert.equal(probe.error, "No visible zones were available.");
  }
  assert.equal(emptyRun.access.status, "healthy", "a readable-but-empty zone list is not a failure");
  for (const item of emptyRun.assessments[1].findings) {
    assert.equal(item.status, "manual", `${item.id} with zero zones`);
    assert.equal(item.evidence.zones_seen, 0, `${item.id}: a readable-but-empty zone list counts zero`);
    assert.equal(item.evidence.zone_inventory_truncated, false);
  }

  for (const entry of CLOUDFLARE_DENIAL_TABLE) {
    const log = [];
    const client = new CloudflareApiClient(config, { fetchImpl: cloudflareRoutedFetch({ ...healthyCloudflareRoutes(), [entry.surface]: cloudflareForbidden }, log) });
    const { access, assessments, exported } = await runEveryCloudflareTool(client, outputRoot);
    const label = entry.surface;
    const files = readBundleFiles(exported.outputDir);
    const accessFile = JSON.parse(files.get("core_data/access.json"));
    assert.ok(log.some((request) => request.path === entry.surface && request.status === 403), `${label}: the fixture served the 403`);

    for (const probe of accessFile.surfaces.filter((candidate) => candidate.status === "not_readable")) {
      assert.deepEqual(
        { count: probe.count, http_status: probe.http_status, endpoint: probe.endpoint },
        { count: null, http_status: 403, endpoint: entry.surface },
        `${label}: the denied probe ${probe.name} keeps count null and records the observed status and path`,
      );
      assert.match(probe.error, /\(403 Forbidden\)/, `${label}: the probe error names the observed status`);
    }
    for (const probe of access.surfaces.filter((candidate) => candidate.status === "readable")) {
      assert.equal(typeof probe.count, "number", `${label}: a readable probe still reports its count`);
    }
    const probeFailed = access.surfaces.some((candidate) => candidate.status === "not_readable" || candidate.status === "not_attempted");
    assert.equal(access.status, probeFailed ? "limited" : "healthy", `${label}: a failed or unattempted probe never leaves the access check healthy`);
    const readableTally = access.notes.find((line) => /Cloudflare audit surfaces are readable/.test(line));
    assert.equal(readableTally, `${access.surfaces.filter((candidate) => candidate.status === "readable").length}/${access.surfaces.length} Cloudflare audit surfaces are readable.`, `${label}: the tally counts only readable probes`);

    if (entry.surface === "/zones") {
      // The zone-scoped probes were never sent: each names the parent read and its status, never the
      // not_configured rendering a readable-but-empty zone list earns, and none counts as readable.
      const dependent = ["zone_settings", "dnssec", "rulesets"].map((name) => access.surfaces.find((candidate) => candidate.name === name));
      assert.equal(dependent.filter(Boolean).length, 3, `${label}: zone_settings, dnssec, and rulesets rows are all present`);
      for (const probe of dependent) {
        assert.deepEqual(
          { status: probe.status, count: probe.count, http_status: probe.http_status },
          { status: "not_attempted", count: null, http_status: 403 },
          `${label}: ${probe.name} is not attempted with the /zones status`,
        );
        assert.match(probe.error, /^Not attempted: \/zones could not be read \(.*\(403 Forbidden\)/, `${label}: ${probe.name} names the parent read and its status`);
        assert.doesNotMatch(probe.error, /No visible zones/, `${label}: ${probe.name} is not mistaken for an empty zone list`);
      }
      assert.equal(access.surfaces.filter((candidate) => candidate.status === "not_configured").length, 0, `${label}: no probe renders not_configured for a denied zone list`);
      assert.ok(access.notes.some((line) => /3 zone-scoped surfaces were not attempted because \/zones could not be read \(403\)/.test(line)), `${label}: the notes name the parent read`);
      assert.equal(access.surfaces.length, 9, `${label}: the denied zone list drops no row`);
    }

    if (entry.coreData) {
      const marker = JSON.parse(files.get(entry.coreData));
      assert.deepEqual(
        { collected: marker.collected, status: marker.status, endpoint: marker.endpoint },
        { collected: false, status: 403, endpoint: entry.surface },
        `${label}: ${entry.coreData} is a not-collected marker, never an empty list`,
      );
      assert.match(marker.error, /403 Forbidden/, `${label}: the marker carries the scrubbed error`);
      assert.ok(!("items" in marker), `${label}: the marker has no items array to mistake for an inventory`);
    }

    for (const [key, fields] of Object.entries(entry.summaryFields ?? {})) {
      const assessment = assessments.find((candidate) => candidate.title === ASSESSMENT_KEYS[key]);
      for (const field of fields) assert.equal(assessment.summary[field], null, `${label}: ${key} summary ${field} renders null for the denied inventory`);
    }

    if (entry.finding) {
      const item = assessments.flatMap((assessment) => assessment.findings).find((candidate) => candidate.id === entry.finding);
      assert.notEqual(item.status, "pass", `${label}: ${entry.finding} must not pass (${item.summary})`);
      for (const field of entry.nullFields) assert.equal(item.evidence[field], null, `${label}: ${entry.finding} evidence ${field} renders null, not a fallback count`);
      if (entry.statusField) assert.equal(item.evidence[entry.statusField], 403, `${label}: ${entry.finding} records the observed status`);
      if (entry.sourceIndex !== undefined) {
        const source = item.evidence.sources[entry.sourceIndex];
        assert.deepEqual({ readable: source.readable, seen: source.seen, total: source.total, truncated: source.truncated, http_status: source.http_status, endpoint: source.endpoint }, { readable: false, seen: null, total: null, truncated: null, http_status: 403, endpoint: entry.surface }, `${label}: the denied token source carries no count`);
      }
      assert.match(item.summary, new RegExp(entry.surface.replace(/[/]/g, "\\/")), `${label}: ${entry.finding} names the denied endpoint`);
    } else if (entry.surface === "/zones") {
      // Every zone-scoped finding (the account-scoped CF-TRF-04..06 do not read the zone list).
      const zoneScoped = [...assessments[1].findings, ...assessments[2].findings.filter((item) => /^CF-TRF-0[1-3]$/.test(item.id))];
      assert.equal(zoneScoped.length, 18, `${label}: every zone-scoped finding is checked`);
      {
        for (const item of zoneScoped) {
          assert.equal(item.status, "manual", `${label}: ${item.id} renders manual for the denied zone list`);
          assert.deepEqual(
            { zones_seen: item.evidence.zones_seen, zones_total: item.evidence.zones_total, zone_inventory_truncated: item.evidence.zone_inventory_truncated, zones_http_status: item.evidence.zones_http_status },
            { zones_seen: null, zones_total: null, zone_inventory_truncated: null, zones_http_status: 403 },
            `${label}: ${item.id} carries no zone count, total, or truncation flag`,
          );
          assert.ok(!("per_hostname_source" in item.evidence) && !("legacy_fallback" in item.evidence), `${label}: ${item.id} names no endpoint the run never requested`);
        }
      }
    }
  }
});

/** Endpoint mentions: absolute paths, `{zone_id}`-style templates, and per-zone suffix labels such as "/dnssec". */
function namedCloudflareEndpoints(text) {
  const mentions = new Set();
  for (const match of text.matchAll(/(?<![\w.:/])(\/(?:user|accounts|zones|rulesets|dnssec|settings|ssl|origin_tls_client_auth|dns_records|pagerules|bot_management|rate_limits|firewall|subscription|access|gateway|audit_logs|members|tokens)(?:\/[A-Za-z0-9_{}.*-]+)*)/g)) {
    mentions.add(match[1].replace(/[.,;:)]+$/, ""));
  }
  return mentions;
}

function namedCloudflareStatusCodes(text) {
  const codes = new Set();
  for (const match of text.matchAll(/\((\d{3}) (?:Forbidden|Unauthorized|Not Found|Bad Gateway|Bad Request|Internal Server Error|Service Unavailable|Too Many Requests|OK)\)/g)) codes.add(Number(match[1]));
  for (const match of text.matchAll(/"[a-z_]*(?:http_)?status": ?(\d{3})\b/g)) codes.add(Number(match[1]));
  return codes;
}

function cloudflareEndpointWasRequested(mention, log) {
  const pattern = new RegExp(`${mention.replace(/[.*]/g, "\\$&").replace(/\{[^}]+\}/g, "[^/]+")}$`);
  return log.some((request) => pattern.test(request.path));
}

test("request matching: every endpoint path and HTTP status named in any output corresponds to a request the run made and observed", async () => {
  const config = sampleConfig();
  const outputRoot = createTempBase("grclanker-cloudflare-request-log-");
  const log = [];
  const routes = {
    ...healthyCloudflareRoutes(),
    [`/accounts/${ACCOUNT}/access/policies`]: cloudflareForbidden,
    [`/accounts/${ACCOUNT}/members`]: cloudflareCanaryHtml,
    [`/zones/${ZONE}/rulesets/phases/${CLOUDFLARE_RULESET_PHASES.firewallManaged}/entrypoint`]: cloudflareForbidden,
    [`/zones/${ZONE}/dnssec`]: cloudflareNotFound,
    // Enterprise-shaped bot management renders manual, which is the only path that requests the zone subscription.
    [`/zones/${ZONE}/bot_management`]: cloudflareOk({ auto_update_model: true, suppress_session_score: false }),
    [`/zones/${ZONE}/subscription`]: cloudflareForbidden,
    [`/accounts/${ACCOUNT}/gateway`]: cloudflareForbidden,
  };
  const client = new CloudflareApiClient(config, { fetchImpl: cloudflareRoutedFetch(routes, log) });
  const { access, assessments, exported } = await runEveryCloudflareTool(client, outputRoot);

  const outputs = [JSON.stringify(access), ...assessments.map((assessment) => JSON.stringify(assessment)), ...readBundleFiles(exported.outputDir).values()];
  const text = outputs.join("\n");
  const observedStatuses = new Set(log.map((request) => request.status));
  assert.ok(observedStatuses.has(403) && observedStatuses.has(502) && observedStatuses.has(404), "the fixture served every failure status under test");
  assert.ok(log.some((request) => request.path === `/zones/${ZONE}/firewall/rules`), "the deprecated firewall rules fallback was requested because the managed ruleset read failed");
  assert.ok(log.some((request) => request.path === `/zones/${ZONE}/subscription`), "the zone subscription was requested because the bot management verdict is manual");

  const endpoints = namedCloudflareEndpoints(text);
  assert.ok(endpoints.size >= 8, `the outputs name the failing endpoints (${[...endpoints].join(", ")})`);
  for (const mention of endpoints) {
    assert.ok(cloudflareEndpointWasRequested(mention, log), `endpoint "${mention}" is named in output but the run never requested it`);
  }
  const statuses = namedCloudflareStatusCodes(text);
  assert.ok(statuses.has(403) && statuses.has(502), `the outputs name the observed failure statuses (${[...statuses].join(", ")})`);
  for (const status of statuses) {
    assert.ok(observedStatuses.has(status), `status ${status} is named in output but no request observed it`);
  }
  // The legacy fallback is documented only because the run requested it.
  const managedWaf = assessments[1].findings.find((item) => item.id === "CF-ZONE-01");
  assert.equal(managedWaf.evidence.legacy_firewall_rules_seen, 0);
  assert.match(managedWaf.evidence.legacy_fallback, /was consulted for evidence only because the rulesets API was unreadable/);
});

test("config loader errors: a SyntaxError raised by the transport is recorded by name only, never by the parser's message that quotes the body", async () => {
  const snippet = parserSnippetBody();
  const fetchImpl = async () => {
    throw new SyntaxError(`Unexpected token '<', "${snippet}"... is not valid JSON`);
  };
  const note = "SyntaxError: response could not be parsed as JSON; the parser's message is not recorded because it quotes the body";
  const client = new CloudflareApiClient(sampleConfig(), { fetchImpl });

  await assert.rejects(() => client.listAccounts(), (error) => {
    assert.equal(error.name, "CloudflareApiError");
    assertNoCanaryWindows(assert, error.message, [PARSER_SNIPPET_CANARY], "thrown client error");
    assert.doesNotMatch(error.message, PARSER_WORDING, `the parser's message was interpolated: ${error.message}`);
    assert.equal(error.message, `Cloudflare request failed for /accounts (network error: ${note})`);
    return true;
  });

  const outputs = [
    await checkCloudflareAccess(client).then((result) => JSON.stringify(result), (error) => error.message),
    JSON.stringify(await assessCloudflareIdentity(client)),
  ];
  for (const text of outputs) {
    assertNoCanaryWindows(assert, text, [PARSER_SNIPPET_CANARY], "tool output");
    assert.doesNotMatch(text, PARSER_WORDING, `a slice of the parser's message reached an output: ${text.slice(0, 400)}`);
    assert.ok(text.includes(note), `the output records the parse failure by name: ${text.slice(0, 400)}`);
  }
});

test("config loader errors: a 200 answer whose body is short non-JSON text is recorded as the non-JSON note only; no 6-to-24-character window of the body and no parser wording reaches the thrown client error, the access check, an assessment, or the bundle", async () => {
  // Positive control for the class: V8 quotes the whole source when it is 21 characters or shorter.
  assert.ok(SHORT_BODY_CANARY.length <= 21 && parserMessageFor(SHORT_BODY_CANARY).includes(SHORT_BODY_CANARY), "the parser's message carries the whole short body");

  const surface = "/accounts";
  const log = [];
  const client = new CloudflareApiClient(sampleConfig(), { fetchImpl: cloudflareRoutedFetch({ ...healthyCloudflareRoutes(), [surface]: () => shortBodyResponse() }, log) });

  // The thrown client error is fixed text: a scrub at the tool boundary would not protect a caller that logs it.
  await assert.rejects(() => client.listAccounts(), (error) => {
    assert.equal(error.name, "CloudflareApiError");
    assert.equal(error.status, 200);
    assertShortBodyRecordedAsNote(assert, error.message, "thrown client error");
    assert.equal(error.message, `Cloudflare request returned a non-JSON payload for ${surface} (200 OK): non-JSON body (${SHORT_BODY_CONTENT_TYPE}, 18 bytes)`);
    return true;
  });

  const { access, assessments, exported } = await runEveryCloudflareTool(client, createTempBase("grclanker-cloudflare-short-body-"));
  assertShortBodyRecordedAsNote(assert, access, "check_access");
  const probe = access.surfaces.find((entry) => entry.name === "accounts");
  assert.ok(probe && probe.status === "not_readable", "the accounts probe is not readable");
  assert.equal(probe.http_status, 200, "the probe records the observed status");
  assertShortBodyRecordedAsNote(assert, assessments[0], `${assessments[0].title} assessment`);
  for (const assessment of assessments) assertNoShortBodyFragments(assert, assessment, `${assessment.title} assessment`);

  const files = readBundleFiles(exported.outputDir);
  for (const [name, text] of files) assertNoShortBodyFragments(assert, text, `bundle ${name}`);
  for (const [name, text] of readZipEntries(exported.zipPath)) assertNoShortBodyFragments(assert, text, `zip ${name}`);
  assertShortBodyRecordedAsNote(assert, files.get("_errors.log"), "_errors.log");
  assert.ok(log.some((entry) => entry.path === surface && entry.status === 200), "the 200 answer named in the note was observed");
});

test("rule 9 server-assigned 32-hex ids (round 4 open ruling): a real Cloudflare account or zone id is removed from error text bare, named by its masked form in every sentence that names its endpoint or account, and kept whole in every structured field", async () => {
  const account = SERVER_ASSIGNED_HEX_IDS.find((entry) => entry.label === "Cloudflare account id");
  const zone = SERVER_ASSIGNED_HEX_IDS.find((entry) => entry.label === "Cloudflare zone id");
  assertHexIdentifierPolicy(assert, redactErrorText, { mask: labelIdentifier });
  assert.equal(displayPath(`/accounts/${account.id}/members`), `/accounts/${account.masked}/members`);
  assert.equal(displayPath(`/zones/${zone.id}/rulesets/phases/http_request_firewall_custom/entrypoint`), `/zones/${zone.masked}/rulesets/phases/http_request_firewall_custom/entrypoint`);
  assert.equal(displayPath("/accounts/acc-123/access/policies"), "/accounts/acc-123/access/policies", "a name-shaped placeholder path is unchanged");
  assert.equal(displayPath("/zones/{zone_id}/settings/{setting_id}"), "/zones/{zone_id}/settings/{setting_id}", "a documented path template is unchanged");
  assert.equal(redactErrorText(`Cloudflare request failed for /accounts/${account.id}/members (403 Forbidden)`), "Cloudflare request failed for /accounts/[REDACTED]/members (403 Forbidden)", "negative control: the raw id in error text is a hex digest to the scrub");

  // The real client under a real-shaped account and zone, with the members list and the DNSSEC read denied.
  const routes = healthyCloudflareRoutes(account.id, zone.id);
  routes[`/accounts/${account.id}/members`] = () => cloudflareForbidden();
  routes[`/zones/${zone.id}/dnssec`] = () => cloudflareForbidden();
  const log = [];
  const client = new CloudflareApiClient(sampleConfig({ accountId: account.id }), { fetchImpl: cloudflareRoutedFetch(routes, log) });
  const { access, assessments, exported } = await runEveryCloudflareTool(client, createTempBase("grclanker-cloudflare-hex-ids-"));
  assert.ok(log.some((entry) => entry.path === `/accounts/${account.id}/members` && entry.status === 403), "the denied members request went to the real account path");
  assert.ok(log.some((entry) => entry.path === `/zones/${zone.id}/dnssec` && entry.status === 403), "the denied DNSSEC request went to the real zone path");

  // Structured fields keep the ids whole.
  assert.equal(access.accountId, account.id);
  const members = access.surfaces.find((entry) => entry.name === "members");
  const dnssec = access.surfaces.find((entry) => entry.name === "dnssec");
  assert.deepEqual(
    { status: members.status, endpoint: members.endpoint, http_status: members.http_status, count: members.count },
    { status: "not_readable", endpoint: `/accounts/${account.id}/members`, http_status: 403, count: null },
  );
  assert.deepEqual(
    { status: dnssec.status, endpoint: dnssec.endpoint, http_status: dnssec.http_status },
    { status: "not_readable", endpoint: `/zones/${zone.id}/dnssec`, http_status: 403 },
  );
  for (const surface of access.surfaces.filter((entry) => entry.scope === "account" && entry.endpoint !== "/accounts")) {
    assert.ok(surface.endpoint.startsWith(`/accounts/${account.id}/`), `structured endpoint carries the real account id: ${surface.endpoint}`);
  }
  const [identity, zoneSecurity, traffic] = assessments;
  assert.equal(identity.summary.account_id, account.id);
  assert.equal(traffic.summary.account_id, account.id);
  for (const item of traffic.findings) {
    if (item.evidence && "account_id" in item.evidence) assert.equal(item.evidence.account_id, account.id, `${item.id} evidence names the real account id`);
  }

  // Sentences name the resource by its masked id and never carry a window of the raw one.
  assert.equal(members.error, `Cloudflare request failed for /accounts/${account.masked}/members (403 Forbidden): Authentication error`);
  assert.equal(dnssec.error, `Cloudflare request failed for /zones/${zone.masked}/dnssec (403 Forbidden): Authentication error`);
  assert.ok(access.notes.includes(`Using configured account ${account.masked}.`), `the account note names the masked id: ${JSON.stringify(access.notes)}`);
  const memberFinding = byId(identity, "CF-IAM-03");
  assert.equal(memberFinding.status, "manual", memberFinding.summary);
  assert.equal(
    memberFinding.summary,
    `Manual review required: /accounts/${account.masked}/members could not be read (Cloudflare request failed for /accounts/${account.masked}/members (403 Forbidden): Authentication error). Grant Account Settings: Read to the audit token, or collect the account member and role list manually.`,
  );
  assert.ok(identity.errors.includes(`/accounts/${account.masked}/members: Cloudflare request failed for /accounts/${account.masked}/members (403 Forbidden): Authentication error`), `the errors line names the masked account: ${JSON.stringify(identity.errors)}`);
  const dnssecFinding = zoneSecurity.findings.find((item) => item.status === "manual" && /dnssec/i.test(item.summary));
  assert.ok(dnssecFinding, `a zone finding went manual on the denied DNSSEC read: ${JSON.stringify(zoneSecurity.findings.map((item) => [item.id, item.status]))}`);
  assert.match(dnssecFinding.summary, new RegExp(`/zones/${zone.masked.replace(/\*/g, "\\*")}/dnssec`), dnssecFinding.summary);
  const sentences = [
    ...access.surfaces.map((entry) => entry.error).filter(Boolean),
    ...access.notes,
    access.recommendedNextStep,
    ...assessments.flatMap((assessment) => [...assessment.errors, ...assessment.findings.map((item) => item.summary)]),
    ...recordedCloudflareErrors(assessments),
  ];
  assertNoCanaryWindows(assert, sentences.join("\n"), [account.id, zone.id], "sentences about requests and accounts");
  assert.ok(sentences.some((text) => text.includes(account.masked)) && sentences.some((text) => text.includes(zone.masked)), "the sentences still name both resources by their masked ids");

  // The bundle: structured files keep the ids, _errors.log lines mask them, and the ids are absent from no structured field.
  const files = readBundleFiles(exported.outputDir);
  const metadata = JSON.parse(files.get("metadata.json"));
  assert.equal(metadata.account_id, account.id);
  assert.equal(JSON.parse(files.get("core_data/accounts.json")).items[0].id, account.id);
  assert.equal(JSON.parse(files.get("core_data/zones.json")).items[0].id, zone.id);
  assert.equal(JSON.parse(files.get("core_data/access.json")).accountId, account.id);
  const errorsLog = files.get("_errors.log");
  assert.match(errorsLog, new RegExp(`/accounts/${account.masked.replace(/\*/g, "\\*")}/members: Cloudflare request failed`));
  assertNoCanaryWindows(assert, errorsLog, [account.id, zone.id], "_errors.log");
  for (const [name, text] of files) {
    if (name.endsWith(".json")) continue;
    // Markdown reports render the field lines (Account: <id>, Bundle: <dir>, - account_id: <id>) as they are and every sentence masked.
    for (const line of text.split("\n")) {
      if (/^(Account: |Bundle: |- account_id: )/.test(line)) continue;
      assertNoCanaryWindows(assert, line, [account.id, zone.id], `${name}: ${line}`);
    }
  }
  assert.ok(files.get("compliance/executive_summary.md").includes(`Account: ${account.id}`), "the executive summary's account line is a field rendering and keeps the id whole");
});
