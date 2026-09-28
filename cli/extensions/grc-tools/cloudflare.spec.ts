import {
  buildBatchIntegrationSpec,
  buildBatchOutputContract,
} from "./batch-spec-builder.js";
import {
  batch2Checks,
  restSurface,
  type Batch2CheckRow,
} from "./batch2-spec-helpers.js";
import { CLOUDFLARE_AUTH_RESOLVER } from "./auth-resolver-contracts.js";

const DOCS = "https://developers.cloudflare.com/api/resources/";
const surfaces = [
  restSurface("token-and-account", "/user/tokens/verify and /accounts/{account_id}", "Cloudflare API v4", DOCS, ["status", "expires_on", "id", "name", "settings"]),
  restSurface("members-and-tokens", "/accounts/{account_id}/{members|tokens}", "Cloudflare API v4", DOCS, ["id", "status", "roles", "policies", "expires_on", "modified_on"]),
  restSurface("zero-trust-identity", "/accounts/{account_id}/access/{apps|policies|identity_providers}", "Cloudflare API v4", DOCS, ["id", "name", "type", "decision", "include", "exclude", "require"]),
  restSurface("zones-and-settings", "/zones and /zones/{zone_id}/settings", "Cloudflare API v4", DOCS, ["id", "name", "status", "plan", "value"]),
  restSurface("zone-rules-and-certificates", "/zones/{zone_id}/{rulesets|dnssec|ssl|origin_tls_client_auth|dns_records}", "Cloudflare API v4", DOCS, ["phase", "kind", "rules", "status", "enabled", "expires_on", "content", "proxied"]),
  restSurface("traffic-and-account-controls", "/accounts/{account_id}/{audit_logs|firewall/access_rules/rules|gateway/rules}", "Cloudflare API v4", DOCS, ["action", "when", "mode", "notes", "modified_on", "enabled", "filters"]),
] as const;

type Row = readonly [string, number, string, Batch2CheckRow["severity"], readonly string[]];
const rows: readonly Row[] = [
  ["CF-IAM-01", 12, "Authentication method hygiene", "high", ["token-and-account"]],
  ["CF-IAM-02", 13, "Current token verification and scoping", "high", ["token-and-account"]],
  ["CF-IAM-03", 14, "Account member privilege concentration", "medium", ["members-and-tokens"]],
  ["CF-IAM-04", 9, "Zero Trust Access app and policy coverage", "high", ["zero-trust-identity"]],
  ["CF-IAM-05", 10, "Zero Trust identity provider coverage", "medium", ["zero-trust-identity"]],
  ["CF-IAM-06", 13, "API token expiration", "medium", ["members-and-tokens"]],
  ["CF-ZONE-01", 1, "WAF managed rulesets deployed", "high", ["zones-and-settings", "zone-rules-and-certificates"]],
  ["CF-ZONE-02", 5, "SSL mode Full (Strict)", "high", ["zones-and-settings"]],
  ["CF-ZONE-03", 6, "Minimum TLS version", "medium", ["zones-and-settings"]],
  ["CF-ZONE-04", 7, "HSTS enforcement", "medium", ["zones-and-settings"]],
  ["CF-ZONE-05", 8, "DNSSEC enabled", "medium", ["zone-rules-and-certificates"]],
  ["CF-ZONE-06", 2, "WAF custom rules with blocking actions", "medium", ["zone-rules-and-certificates"]],
  ["CF-ZONE-07", 3, "HTTP DDoS protection sensitivity", "high", ["zone-rules-and-certificates"]],
  ["CF-ZONE-08", 21, "Always Use HTTPS", "medium", ["zones-and-settings"]],
  ["CF-ZONE-09", 22, "Automatic HTTPS Rewrites", "low", ["zones-and-settings"]],
  ["CF-ZONE-10", 25, "Universal SSL and certificate validity", "medium", ["zone-rules-and-certificates"]],
  ["CF-ZONE-11", 18, "Authenticated Origin Pulls", "medium", ["zone-rules-and-certificates"]],
  ["CF-ZONE-12", 19, "Browser Integrity Check", "low", ["zones-and-settings"]],
  ["CF-ZONE-13", 20, "Email Address Obfuscation", "low", ["zones-and-settings"]],
  ["CF-ZONE-14", 23, "Security headers via transform rules", "medium", ["zone-rules-and-certificates"]],
  ["CF-ZONE-15", 27, "DNS record origin exposure", "low", ["zone-rules-and-certificates"]],
  ["CF-TRF-01", 16, "Rate limiting coverage", "medium", ["zone-rules-and-certificates"]],
  ["CF-TRF-02", 15, "Page rule security regressions", "medium", ["zone-rules-and-certificates"]],
  ["CF-TRF-03", 4, "Bot and automated traffic controls", "medium", ["zones-and-settings"]],
  ["CF-TRF-04", 11, "Account audit log visibility", "high", ["traffic-and-account-controls"]],
  ["CF-TRF-05", 17, "IP access rules", "medium", ["traffic-and-account-controls"]],
  ["CF-TRF-06", 24, "Gateway SWG policies", "medium", ["traffic-and-account-controls"]],
] as const;

function owner(id: string): string {
  if (id.startsWith("CF-IAM-")) return "cloudflare_assess_identity";
  if (id.startsWith("CF-ZONE-")) return "cloudflare_assess_zone_security";
  return "cloudflare_assess_traffic_controls";
}

const checks = batch2Checks(rows.map(([id, control, title, severity, sourceSurfaces]) => ({
  id,
  control,
  title,
  severity,
  owner: owner(id),
  surfaces: sourceSurfaces,
  emptyOutcome: "manual",
  decision: `Evaluate ${title} from the complete Cloudflare account or zone inventories: unreadable dependencies and ambiguous feature availability remain manual, a proved insecure record takes precedence, partial lists or review records warn, and pass requires complete readable evidence with no violating zone or account.`,
})));
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
    surfaceIds: surfaces,
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
  knownGaps: ["Feature and plan ambiguity is preserved as manual evidence where the API cannot distinguish an unlicensed feature from an empty configuration."],
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
