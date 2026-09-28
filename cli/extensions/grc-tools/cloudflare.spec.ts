import {
  buildBatchIntegrationSpec,
  buildBatchOutputContract,
  type BatchCompletenessSourceDefinition,
} from "./batch-spec-builder.js";
import {
  batch2All,
  batch2Any,
  batch2Checks,
  batch2Completeness,
  batch2ComparePaths,
  batch2Eq,
  batch2GenericDecisionInputs,
  batch2Gt,
  batch2Ne,
  batch2Rule,
  restSurface,
  type Batch2CheckRow,
} from "./batch2-spec-helpers.js";
import { CLOUDFLARE_AUTH_RESOLVER } from "./auth-resolver-contracts.js";

const DOCS = "https://developers.cloudflare.com/api/resources/";
export const CLOUDFLARE_DEFAULT_MAX_SUPER_ADMINS = 2;
export const CLOUDFLARE_HSTS_MIN_MAX_AGE_SECONDS = 15_552_000;
export const CLOUDFLARE_STALE_IP_RULE_DAYS = 365;
export const CLOUDFLARE_CERTIFICATE_EXPIRY_WARNING_DAYS = 30;
export const CLOUDFLARE_AUDIT_LOG_LOOKBACK_DAYS = 30;
export const CLOUDFLARE_REQUIRED_SECURITY_HEADERS = ["content-security-policy", "x-frame-options", "x-content-type-options", "referrer-policy"] as const;
export const CLOUDFLARE_WEAK_IDENTITY_PROVIDER_TYPES = ["onetimepin"] as const;
const cfSurface = (id: string, path: string, fields: readonly string[]) =>
  restSurface(id, path, "Cloudflare API v4", DOCS, fields);
const surfaces = [
  cfSurface("credential-method", "resolved API credential configuration", ["authMethod"]),
  cfSurface("token-verification", "/user/tokens/verify", ["id", "status", "expires_on"]),
  cfSurface("current-token-detail", "/user/tokens/{token_id}", ["policies", "permission_groups", "resources"]),
  cfSurface("account-members", "/accounts/{account_id}/members", ["id", "roles", "user.two_factor_authentication_enabled"]),
  cfSurface("user-token-inventory", "/user/tokens", ["id", "status", "expires_on", "last_used_on"]),
  cfSurface("account-token-inventory", "/accounts/{account_id}/tokens", ["id", "status", "expires_on", "last_used_on"]),
  cfSurface("access-applications", "/accounts/{account_id}/access/apps", ["id", "name", "type", "policies"]),
  cfSurface("access-reusable-policies", "/accounts/{account_id}/access/policies", ["id", "name", "decision", "include", "exclude", "require"]),
  cfSurface("access-identity-providers", "/accounts/{account_id}/access/identity_providers", ["id", "name", "type"]),
  cfSurface("zone-inventory", "/zones", ["id", "name", "status", "plan"]),
  cfSurface("zone-security-datasets", "/zones/{zone_id}/{settings|rulesets|dnssec|ssl|origin_tls_client_auth|dns_records|pagerules|rate_limits|bot_management}", ["phase", "kind", "rules", "status", "enabled", "expires_on", "content", "proxied", "value"]),
  cfSurface("account-audit-logs", "/accounts/{account_id}/audit_logs", ["action", "when"]),
  cfSurface("account-ip-access-rules", "/accounts/{account_id}/firewall/access_rules/rules", ["mode", "notes", "modified_on"]),
  cfSurface("gateway-rules", "/accounts/{account_id}/gateway/rules", ["action", "enabled", "filters"]),
  cfSurface("gateway-account", "/accounts/{account_id}/gateway", ["gateway_tag"]),
] as const;

type Row = readonly [string, number, string, Batch2CheckRow["severity"], readonly string[]];
const zoneRows: readonly Row[] = [
  ["CF-ZONE-01", 1, "WAF managed rulesets deployed", "high", ["zone-inventory", "zone-security-datasets"]],
  ["CF-ZONE-02", 5, "SSL mode Full (Strict)", "high", ["zone-inventory", "zone-security-datasets"]],
  ["CF-ZONE-03", 6, "Minimum TLS version", "medium", ["zone-inventory", "zone-security-datasets"]],
  ["CF-ZONE-04", 7, "HSTS enforcement", "medium", ["zone-inventory", "zone-security-datasets"]],
  ["CF-ZONE-05", 8, "DNSSEC enabled", "medium", ["zone-inventory", "zone-security-datasets"]],
  ["CF-ZONE-06", 2, "WAF custom rules with blocking actions", "medium", ["zone-inventory", "zone-security-datasets"]],
  ["CF-ZONE-07", 3, "HTTP DDoS protection sensitivity", "high", ["zone-inventory", "zone-security-datasets"]],
  ["CF-ZONE-08", 21, "Always Use HTTPS", "medium", ["zone-inventory", "zone-security-datasets"]],
  ["CF-ZONE-09", 22, "Automatic HTTPS Rewrites", "low", ["zone-inventory", "zone-security-datasets"]],
  ["CF-ZONE-10", 25, "Universal SSL and certificate validity", "medium", ["zone-inventory", "zone-security-datasets"]],
  ["CF-ZONE-11", 18, "Authenticated Origin Pulls", "medium", ["zone-inventory", "zone-security-datasets"]],
  ["CF-ZONE-12", 19, "Browser Integrity Check", "low", ["zone-inventory", "zone-security-datasets"]],
  ["CF-ZONE-13", 20, "Email Address Obfuscation", "low", ["zone-inventory", "zone-security-datasets"]],
  ["CF-ZONE-14", 23, "Security headers via transform rules", "medium", ["zone-inventory", "zone-security-datasets"]],
  ["CF-ZONE-15", 27, "DNS record origin exposure", "low", ["zone-inventory", "zone-security-datasets"]],
];
const rows: readonly Row[] = [
  ["CF-IAM-01", 12, "Authentication method hygiene", "high", ["credential-method"]],
  ["CF-IAM-02", 13, "Current token verification and scoping", "high", ["token-verification", "current-token-detail"]],
  ["CF-IAM-03", 14, "Account member privilege concentration", "medium", ["account-members"]],
  ["CF-IAM-04", 9, "Zero Trust Access app and policy coverage", "high", ["access-applications", "access-reusable-policies"]],
  ["CF-IAM-05", 10, "Zero Trust identity provider coverage", "medium", ["access-identity-providers"]],
  ["CF-IAM-06", 13, "API token expiration", "medium", ["user-token-inventory", "account-token-inventory"]],
  ...zoneRows,
  ["CF-TRF-01", 16, "Rate limiting coverage", "medium", ["zone-inventory", "zone-security-datasets"]],
  ["CF-TRF-02", 15, "Page rule security regressions", "medium", ["zone-inventory", "zone-security-datasets"]],
  ["CF-TRF-03", 4, "Bot and automated traffic controls", "medium", ["zone-inventory", "zone-security-datasets"]],
  ["CF-TRF-04", 11, "Account audit log visibility", "high", ["account-audit-logs"]],
  ["CF-TRF-05", 17, "IP access rules", "medium", ["account-ip-access-rules"]],
  ["CF-TRF-06", 24, "Gateway SWG policies", "medium", ["gateway-rules", "gateway-account"]],
] as const;

const CT = ["truncated"] as const;
const CTF = ["truncated", "error", "denied", "not-collected"] as const;
const CN = [] as const;
const cfSource = (surfaceId: string, falseWhen: BatchCompletenessSourceDefinition["falseWhen"]): BatchCompletenessSourceDefinition => ({ surfaceId, falseWhen });
const zoneCompleteness = () => [
  cfSource("zone-inventory", CTF),
  cfSource("zone-security-datasets", CN),
] as const;
export const CLOUDFLARE_COMPLETENESS_SOURCES: Readonly<Record<string, readonly BatchCompletenessSourceDefinition[]>> = {
  "CF-IAM-01": [cfSource("credential-method", CN)],
  "CF-IAM-02": [cfSource("token-verification", CN), cfSource("current-token-detail", CN)],
  "CF-IAM-03": [cfSource("account-members", CT)],
  "CF-IAM-04": [cfSource("access-applications", CT), cfSource("access-reusable-policies", CT)],
  "CF-IAM-05": [cfSource("access-identity-providers", CT)],
  "CF-IAM-06": [cfSource("user-token-inventory", CTF), cfSource("account-token-inventory", CTF)],
  ...Object.fromEntries(zoneRows.map(([id]) => [id, zoneCompleteness()])),
  "CF-TRF-01": zoneCompleteness(),
  "CF-TRF-02": zoneCompleteness(),
  "CF-TRF-03": zoneCompleteness(),
  "CF-TRF-04": [cfSource("account-audit-logs", CT)],
  "CF-TRF-05": [cfSource("account-ip-access-rules", CT)],
  "CF-TRF-06": [cfSource("gateway-rules", CT), cfSource("gateway-account", CN)],
};

function owner(id: string): string {
  if (id.startsWith("CF-IAM-")) return "cloudflare_assess_identity";
  if (id.startsWith("CF-ZONE-")) return "cloudflare_assess_zone_security";
  return "cloudflare_assess_traffic_controls";
}

const decisionConstants = (id: string): Batch2CheckRow["constants"] => ({
  "CF-IAM-03": { default_maximum_super_administrators: CLOUDFLARE_DEFAULT_MAX_SUPER_ADMINS },
  "CF-IAM-05": { weak_identity_provider_types: CLOUDFLARE_WEAK_IDENTITY_PROVIDER_TYPES },
  "CF-ZONE-04": { minimum_hsts_max_age_seconds: CLOUDFLARE_HSTS_MIN_MAX_AGE_SECONDS },
  "CF-ZONE-10": { certificate_expiry_warning_days: CLOUDFLARE_CERTIFICATE_EXPIRY_WARNING_DAYS },
  "CF-ZONE-14": { required_security_headers: CLOUDFLARE_REQUIRED_SECURITY_HEADERS },
  "CF-TRF-04": { audit_log_lookback_days: CLOUDFLARE_AUDIT_LOG_LOOKBACK_DAYS },
  "CF-TRF-05": { stale_ip_access_rule_days: CLOUDFLARE_STALE_IP_RULE_DAYS },
} as const)[id as "CF-IAM-03" | "CF-IAM-05" | "CF-ZONE-04" | "CF-ZONE-10" | "CF-ZONE-14" | "CF-TRF-04" | "CF-TRF-05"];

const decisionPredicate: Readonly<Record<string, string>> = {
  "CF-IAM-01": "Fail when authMethod is the legacy Global API Key; pass only when the resolved raw authentication method is token.",
  "CF-IAM-02": "Use the explicit token-verification, policy, permission-group, and resource-scope rules rendered below.",
  "CF-IAM-03": `Fail when the complete active-member inventory contains more Super Administrator roles than max_super_admins. The operator option defaults to ${CLOUDFLARE_DEFAULT_MAX_SUPER_ADMINS} and is clamped to the inclusive range 0 through 100; warn for members whose two-factor authentication field is not true.`,
  "CF-IAM-04": "Fail when an Access application has no attached or reusable policy or any policy decision is bypass; pass only after both complete application and policy inventories establish coverage without bypass.",
  "CF-IAM-05": `Fail when the complete identity-provider inventory is empty or every lowercased provider type is ${CLOUDFLARE_WEAK_IDENTITY_PROVIDER_TYPES.join(" or ")}; warn when one of those weak types coexists with any other provider type.`,
  "CF-IAM-06": "Fail for active API tokens with no expires_on or an expires_on in the past; warn for undocumented token status or active tokens with no last_used_on.",
  "CF-ZONE-01": "For every zone, fail when the managed-firewall entry point is absent, has no enabled execute rule, or an execute rule has overrides.enabled=false.",
  "CF-ZONE-02": "For every zone, pass only for ssl=strict, warn for full or origin_pull, fail for flexible or off, and treat every other or absent value as unreadable.",
  "CF-ZONE-03": "For every zone, pass only for min_tls_version 1.2 or 1.3, fail for 1.0 or 1.1, and treat every other or absent value as unreadable.",
  "CF-ZONE-04": `For every zone, fail unless HSTS is enabled with max_age at least ${CLOUDFLARE_HSTS_MIN_MAX_AGE_SECONDS}; warn when include_subdomains or preload is not true.`,
  "CF-ZONE-05": "For every zone, pass for DNSSEC status active, warn for pending or pending-disabled, fail for disabled or error, and treat any other value as unreadable.",
  "CF-ZONE-06": "For every zone, fail when no custom-firewall entry point or enabled custom rule exists; warn when enabled rules exist but none uses block, managed_challenge, js_challenge, or challenge.",
  "CF-ZONE-07": "For every zone, fail when every DDoS execute override is disabled or sensitivity is eoff; warn for low; pass for default or medium, including a listed managed ddos_l7 ruleset with no override.",
  "CF-ZONE-08": "For every zone, fail unless always_use_https is exactly on; undocumented or absent values are unreadable.",
  "CF-ZONE-09": "For every zone, fail unless automatic_https_rewrites is exactly on; undocumented or absent values are unreadable.",
  "CF-ZONE-10": `For every zone, fail when Universal SSL is disabled, no active certificate pack exists, or an active certificate is expired; warn for missing expiry, expiry within ${CLOUDFLARE_CERTIFICATE_EXPIRY_WARNING_DAYS} days, or truncated certificate packs.`,
  "CF-ZONE-11": "For every zone, fail when Authenticated Origin Pulls is disabled and has no active enabled hostname association; warn for only hostname-level coverage, inactive or undated associations, or a partial association inventory.",
  "CF-ZONE-12": "For every zone, fail unless browser_check is exactly on; undocumented or absent values are unreadable.",
  "CF-ZONE-13": "For every zone, fail unless email_obfuscation is exactly on; undocumented or absent values are unreadable.",
  "CF-ZONE-14": `For every zone, fail when no enabled response-header rewrite sets any of ${CLOUDFLARE_REQUIRED_SECURITY_HEADERS.join(", ")}; warn when only a proper subset is set.`,
  "CF-ZONE-15": "For every zone, warn when any proxiable A, AAAA, or CNAME record has proxied=false or when the DNS-record inventory is partial; an empty DNS inventory remains manual.",
  "CF-TRF-01": "For every zone, fail when the http_ratelimit entry point has no enabled rule with a ratelimit block; a readable legacy /rate_limits result is evidence-only and warns, never passes.",
  "CF-TRF-02": "For every zone, fail when an active page rule disables security, sets security_level essentially_off, turns SSL off or flexible, disables browser or email protection, or cache-everything matches a sensitive path.",
  "CF-TRF-03": "For every zone, pass when fight_mode=true or definitely automated traffic is blocked or challenged; fail when definitely automated traffic is allowed or fight_mode=false without an SBFM action.",
  "CF-TRF-04": `Warn when no audit event is visible in the ${CLOUDFLARE_AUDIT_LOG_LOOKBACK_DAYS}-day window, any action failed, or pagination is partial; pass requires at least one complete readable event.`,
  "CF-TRF-05": `Warn for allow-mode IP rules, rules with no notes, or rules with no modified_on or older than ${CLOUDFLARE_STALE_IP_RULE_DAYS} days; a complete empty inventory passes.`,
  "CF-TRF-06": "Use the explicit Gateway provisioning, rule-action, filter, and completeness rules rendered below.",
};

const checks = batch2Checks(rows.map(([id, control, title, severity, sourceSurfaces]) => {
  const custom: Partial<Batch2CheckRow> = id === "CF-IAM-02"
    ? {
        decisionInputs: {
          evidence_readable: "Boolean. True only when token verification and the current-token detail response were readable; Global API Key authentication has no token and is false.",
          evidence_complete: "Boolean. True because token verification and current-token detail are single-object reads; false means either read was incomplete.",
          verified_status: "String from /user/tokens/verify result.status; null means absent or unreadable. The only compliant value is active.",
          token_policy_count: "Complete count of current-token policy objects before presentation slicing.",
          write_capable_permission_group_count: "Complete count of permission groups whose name does not end in Read.",
          broad_resource_policy_count: "Complete count of policies whose resources object is empty or contains wildcard resource selectors.",
        },
        decisionRules: [
          batch2Rule("manual", batch2Ne("evidence_readable", true)),
          batch2Rule("fail", batch2Any(
            batch2Ne("verified_status", "active"),
            batch2Eq("token_policy_count", 0),
          )),
          batch2Rule("warn", batch2Any(
            batch2Ne("evidence_complete", true),
            batch2Gt("write_capable_permission_group_count", 0),
            batch2Gt("broad_resource_policy_count", 0),
          )),
          batch2Rule("pass", { op: "always" }),
        ],
      }
    : id === "CF-IAM-03"
      ? {
          decisionInputs: {
            evidence_readable: "Boolean. True only when account context and the complete account-member response were readable.",
            evidence_complete: "Boolean. True only when member pagination exhausted without reaching a configured item cap.",
            member_count: "Non-negative integer count of every account member returned before evidence-display slicing.",
            super_administrator_count: "Non-negative integer count of members with at least one role name containing both `super` and `admin`, using case-insensitive substring matching.",
            member_without_two_factor_count: "Non-negative integer count of members whose raw two_factor_authentication_enabled field is not true.",
            maximum_super_administrator_count: `Non-negative integer max_super_admins operator option after clamping to 0 through 100; omitted or non-finite input uses ${CLOUDFLARE_DEFAULT_MAX_SUPER_ADMINS}.`,
          },
          decisionRules: [
            batch2Rule("manual", batch2Ne("evidence_readable", true)),
            batch2Rule("manual", batch2Eq("member_count", 0)),
            batch2Rule("fail", batch2ComparePaths("gt", "super_administrator_count", "maximum_super_administrator_count")),
            batch2Rule("warn", batch2Any(
              batch2Ne("evidence_complete", true),
              batch2Gt("member_without_two_factor_count", 0),
            )),
            batch2Rule("pass", { op: "always" }),
          ],
        }
    : id === "CF-TRF-06"
      ? {
          decisionInputs: {
            evidence_readable: "Boolean. True only when Gateway rules and, for an empty rule list, the Gateway account provisioning object were readable.",
            evidence_complete: "Boolean. True only when Gateway rule pagination proved exhaustion.",
            gateway_provisioned: "Boolean. True when /accounts/{account_id}/gateway returns a non-empty gateway_tag.",
            gateway_rule_count: "Complete count of Gateway rules before presentation slicing.",
            blocking_or_isolating_rule_count: "Count of enabled rules whose action is block, isolate, or override.",
            dns_or_http_filter_present: "Boolean. True when at least one enabled rule names a DNS or HTTP filter.",
          },
          decisionRules: [
            batch2Rule("manual", batch2Ne("evidence_readable", true)),
            batch2Rule("fail", batch2Any(
              batch2All(batch2Eq("gateway_rule_count", 0), batch2Eq("gateway_provisioned", true)),
              batch2All(batch2Gt("gateway_rule_count", 0), batch2Any(
                batch2Eq("blocking_or_isolating_rule_count", 0),
                batch2Eq("dns_or_http_filter_present", false),
              )),
            )),
            batch2Rule("manual", batch2All(batch2Eq("gateway_rule_count", 0), batch2Eq("gateway_provisioned", false))),
            batch2Rule("warn", batch2Ne("evidence_complete", true)),
            batch2Rule("pass", { op: "always" }),
          ],
        }
      : {};
  const decisionInputs = custom.decisionInputs ?? batch2GenericDecisionInputs(decisionPredicate[id]);
  const aggregationSemantics = sourceSurfaces.some((surface) => surface.includes("zone"))
    ? "Across zones, evaluator counts come from the named raw predicates rather than rendered per-zone statuses."
    : "Evaluator counts come directly from the named account-level raw predicates and complete source inventories.";
  return {
    id,
    control,
    title,
    severity,
    owner: owner(id),
    surfaces: sourceSurfaces,
    emptyOutcome: id === "CF-IAM-05" ? "fail" : id === "CF-TRF-05" ? "pass" : "manual",
    constants: decisionConstants(id),
    decisionInputs,
    ...custom,
    completeness: batch2Completeness(
      decisionInputs,
      CLOUDFLARE_COMPLETENESS_SOURCES[id],
      id.startsWith("CF-ZONE-") || ["CF-TRF-01", "CF-TRF-02", "CF-TRF-03"].includes(id)
        ? `For ${id}, the zone inventory governs evidence_complete: truncation, error, denial, or absence makes it false. Per-zone endpoint failures instead increase manual or review counts and leave evidence_complete unchanged.`
        : id === "CF-IAM-06"
          ? "For CF-IAM-06, each token inventory participates only when attempted. Any attempted list that truncates or fails makes evidence_complete false; an account-token read omitted because no account context exists is not a failed source."
          : `For ${id}, each named source changes evidence_complete only for its declared source-state failures. A primary single-object error instead makes the finding manual and omits the primitive; a source with no failure modes does not lower it.`,
    ),
    decision: `${decisionPredicate[id]} ${aggregationSemantics} A proved violation has first-match precedence and incomplete or unreadable evidence cannot pass.`,
  };
}));
const idsFor = (tool: string): string[] => checks.filter((check) => check.owner === tool).map((check) => check.id);

export const CLOUDFLARE_RUNTIME_BEHAVIOR = [
  "Account context is explicit or discovered only when exactly one readable account is visible; ambiguous or unreadable account context keeps account checks manual.",
  "Zone findings aggregate per-zone judgments, and a proved failing zone has precedence over warnings while any unreadable sampled zone prevents pass.",
  "Every paged result retains seen, reported total, page count, and truncation; finding evidence arrays are presentation samples only.",
] as const;

export const CLOUDFLARE_SPEC = buildBatchIntegrationSpec({
  slug: "cloudflare-sec-inspector",
  displayName: "Cloudflare Security Inspector",
  vendor: "Cloudflare",
  category: "edge-security",
  summary: "Portable contract for the shipped Cloudflare identity, zone-security, and traffic-control assessments.",
  sourceModule: "cli/extensions/grc-tools/cloudflare.ts",
  baseServices: ["Cloudflare API v4"],
  authentication: CLOUDFLARE_AUTH_RESOLVER,
  permissions: [
    { id: "cloudflare-read-scopes", kind: "oauth-scope", value: "Token, Account, Zone, DNS, SSL, WAF, Zero Trust, audit-log, and firewall read permissions required by each declared surface", unlocks: surfaces.map((surface) => surface.id) },
    { id: "cloudflare-plan-features", kind: "plan", value: "The account or zone plan must expose the assessed WAF, bot, Access, Gateway, audit-log, and certificate features", unlocks: surfaces.slice(2).map((surface) => surface.id) },
  ],
  surfaces,
  checks,
  tools: {
    cloudflare_check_access: [],
    cloudflare_assess_identity: idsFor("cloudflare_assess_identity"),
    cloudflare_assess_zone_security: idsFor("cloudflare_assess_zone_security"),
    cloudflare_assess_traffic_controls: idsFor("cloudflare_assess_traffic_controls"),
    cloudflare_export_audit_bundle: checks.map((check) => check.id),
  },
  pagination: [{
    surfaceIds: surfaces.map((surface) => surface.id),
    cursorFields: ["result_info.page", "result_info.total_pages", "result_info.total_count"],
    pageSize: null,
    itemCap: null,
    pageCap: null,
    totalSemantics: "Completion requires reaching result_info.total_pages or total_count without a repeated or empty advancing page and remaining below every configured zone, member, token, or audit cap.",
    stopConditions: ["Reported final page", "Reported total reached", "Repeated page", "Empty advancing page", "Configured item cap"],
  }],
  rateLimit: {
    documentedLimit: "Endpoint and account-plan specific",
    retryHeaders: ["Retry-After", "Ratelimit", "Ratelimit-Policy"],
    retryableStatuses: [429, 500, 502, 503, 504],
    backoffPolicy: "Honor bounded Retry-After and use bounded retries for transient responses; exhausted reads remain unreadable.",
  },
  runtimeBehavior: CLOUDFLARE_RUNTIME_BEHAVIOR,
  knownGaps: [
    "Feature and plan ambiguity is preserved as manual evidence where the API cannot distinguish an unlicensed feature from an empty configuration.",
    "The shipped runtime has no framework mapping for CF-ZONE-15 (DNS record origin exposure); this migration preserves that gap rather than inventing a control mapping.",
  ],
  sensitiveFields: ["api_token", "api_key", "authorization", "x-auth-key", "x-auth-email", "cookie"],
  credentialFormats: ["Cloudflare API tokens", "Cloudflare Global API keys", "session cookies"],
  output: buildBatchOutputContract({
    files: [
      "README.md", "QUICK_REFERENCE.md", "metadata.json", "core_data/access.json",
      "core_data/accounts.json", "core_data/zones.json",
      "analysis/identity.json", "analysis/zone-security.json", "analysis/traffic-controls.json",
      "analysis/findings.json", "compliance/executive_summary.md",
      "compliance/unified_compliance_matrix.md",
      "compliance/fedramp/fedramp_compliance_report.md",
      "compliance/cmmc/cmmc_compliance_report.md",
      "compliance/soc2/soc2_compliance_report.md",
      "compliance/cis/cis_compliance_report.md",
      "compliance/pci_dss/pci_dss_compliance_report.md",
      "compliance/disa_stig/disa_stig_compliance_report.md",
      "compliance/irap/irap_compliance_report.md",
      "compliance/ismap/ismap_compliance_report.md",
    ],
    conditionalFiles: ["_errors.log"],
    overwritePolicy: "Allocate a new Cloudflare audit directory and numeric suffix without overwriting an existing directory or paired archive.",
    archivePairing: "Create <allocated-directory>.zip beside the allocated Cloudflare audit directory.",
  }),
});
