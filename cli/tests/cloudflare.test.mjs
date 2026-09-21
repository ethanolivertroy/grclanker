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
  assessCloudflareIdentity,
  assessCloudflareTrafficControls,
  assessCloudflareZoneSecurity,
  checkCloudflareAccess,
  exportCloudflareAuditBundle,
  resolveCloudflareConfiguration,
  resolveSecureOutputPath,
} from "../dist/extensions/grc-tools/cloudflare.js";

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
