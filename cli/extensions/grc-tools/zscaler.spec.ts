import {
  buildBatchIntegrationSpec,
  buildBatchOutputContract,
} from "./batch-spec-builder.js";
import {
  batch2All,
  batch2Any,
  batch2Checks,
  batch2Eq,
  batch2Gt,
  batch2Ne,
  batch2Rule,
  restSurface,
  type Batch2CheckRow,
} from "./batch2-spec-helpers.js";
import { ZSCALER_AUTH_RESOLVER } from "./auth-resolver-contracts.js";

const ZIA_DOCS = "https://help.zscaler.com/zia/api";
const ZPA_DOCS = "https://help.zscaler.com/zpa/api-reference";
export const ZSCALER_DEFAULT_MAX_SUPER_ADMINS = 5;
export const ZSCALER_DEFAULT_CERT_EXPIRY_WARN_DAYS = 30;
export const ZSCALER_DEFAULT_STALE_CONNECTOR_DAYS = 30;
export const ZSCALER_DEFAULT_MAX_TIMEOUT_HOURS = 24;
export const ZSCALER_REQUIRED_URL_BLOCK_CATEGORIES = ["ANONYMIZER", "OTHER_SECURITY", "ADULT_THEMES", "PORNOGRAPHY", "GAMBLING"] as const;
export const ZSCALER_REQUIRED_ATP_FLAGS = [
  "malwareSitesBlocked", "cmdCtlServerBlocked", "cmdCtlTrafficBlocked", "knownPhishingSitesBlocked",
  "suspectedPhishingSitesBlocked", "browserExploitsBlocked", "potentialMaliciousRequestsBlocked",
] as const;
export const ZSCALER_REQUIRED_MALWARE_FLAGS = ["virusBlocked", "trojanBlocked", "wormBlocked", "ransomwareBlocked", "spywareBlocked"] as const;
const surfaces = [
  restSurface("zia-administration", "/api/v1/{adminUsers|adminRoles|authSettings|auditLogFeeds}", "ZIA API", ZIA_DOCS, ["id", "loginName", "role", "adminScope", "mfa", "status"]),
  restSurface("zia-policy", "/api/v1/{urlFilteringRules|firewallFilteringRules|dlpEngines|sslInspectionRules|sandboxRules|locations}", "ZIA API", ZIA_DOCS, ["id", "name", "state", "action", "rank", "order", "destinations", "locations"]),
  restSurface("zpa-policy", "/mgmtconfig/v1/admin/customers/{customerId}/{application|policy|posture|connector|idp|admin|certificate} resources", "ZPA API", ZPA_DOCS, ["id", "name", "enabled", "operator", "action", "health", "modifiedTime", "expirationDate"]),
] as const;

const rows: ReadonlyArray<readonly [string, Batch2CheckRow["severity"], "zia_policy" | "zia_access_control" | "zpa"]> = [
  ["URL Filtering Policy Audit", "high", "zia_policy"],
  ["Firewall Rule Audit", "high", "zia_policy"],
  ["DLP Engine Configuration", "high", "zia_policy"],
  ["SSL Inspection Coverage", "high", "zia_policy"],
  ["Cloud Sandbox Analysis", "medium", "zia_policy"],
  ["Admin MFA Enforcement", "critical", "zia_access_control"],
  ["RBAC & Admin Role Audit", "high", "zia_access_control"],
  ["Application Segmentation", "high", "zpa"],
  ["Zero Trust Access Policies", "critical", "zpa"],
  ["Posture Profile Enforcement", "high", "zpa"],
  ["App Connector Health & Coverage", "medium", "zpa"],
  ["IdP Integration & SAML Config", "critical", "zpa"],
  ["Session Timeout Configuration", "medium", "zpa"],
  ["Audit Logging Enabled", "high", "zia_access_control"],
  ["Trusted Network Detection", "medium", "zpa"],
  ["Bandwidth Control Policies", "low", "zia_policy"],
  ["Browser Isolation Policies", "medium", "zia_policy"],
  ["Location & GRE/VPN Configuration", "medium", "zia_policy"],
  ["Cloud Application Control", "medium", "zia_policy"],
  ["DNS Security Configuration", "high", "zia_policy"],
  ["Service Edge Deployment", "low", "zpa"],
  ["Forwarding Policy Audit", "medium", "zpa"],
  ["Emergency Access Configuration", "medium", "zpa"],
  ["Certificate Management", "high", "zpa"],
  ["Security Policy Baseline", "high", "zia_policy"],
] as const;

function owner(area: "zia_policy" | "zia_access_control" | "zpa"): string {
  switch (area) {
    case "zia_policy":
      return "zscaler_assess_zia_policy";
    case "zia_access_control":
      return "zscaler_assess_zia_access_control";
    case "zpa":
      return "zscaler_assess_zpa";
    default: {
      const exhaustive: never = area;
      return exhaustive;
    }
  }
}

const decisionConstants = (control: number): Batch2CheckRow["constants"] => ({
  1: { required_url_block_categories: ZSCALER_REQUIRED_URL_BLOCK_CATEGORIES },
  7: { default_maximum_super_administrators: ZSCALER_DEFAULT_MAX_SUPER_ADMINS },
  11: { default_stale_connector_days: ZSCALER_DEFAULT_STALE_CONNECTOR_DAYS },
  13: { default_maximum_timeout_hours: ZSCALER_DEFAULT_MAX_TIMEOUT_HOURS },
  24: { default_certificate_expiry_warning_days: ZSCALER_DEFAULT_CERT_EXPIRY_WARN_DAYS },
  25: {
    required_advanced_threat_protection_flags: ZSCALER_REQUIRED_ATP_FLAGS,
    required_malware_protection_flags: ZSCALER_REQUIRED_MALWARE_FLAGS,
  },
} as const)[control as 1 | 7 | 11 | 13 | 24 | 25];

const checks = batch2Checks(rows.map(([title, severity, area], index) => {
  const control = index + 1;
  const custom: Partial<Batch2CheckRow> = control === 1
    ? {
        decisionInputs: {
          evidence_readable: "Boolean. True only when GET /urlFilteringRules returned a readable inventory.",
          evidence_complete: "Boolean. True only when URL-rule pagination proved exhaustion; false means the rule counts are lower bounds.",
          rule_count: "Complete number of URL filtering rules before presentation slicing; zero is a readable empty inventory.",
          enabled_rule_count: "Count of rules whose state is exactly ENABLED.",
          blocking_rule_count: "Count of enabled rules whose action is exactly BLOCK.",
          missing_required_category_count: "Count of required categories absent from enabled BLOCK rules. Required categories are ANONYMIZER, OTHER_SECURITY, ADULT_THEMES, PORNOGRAPHY, and GAMBLING.",
        },
        decisionRules: [
          batch2Rule("manual", batch2Ne("evidence_readable", true)),
          batch2Rule("fail", batch2Any(batch2Eq("rule_count", 0), batch2Eq("enabled_rule_count", 0), batch2Eq("blocking_rule_count", 0))),
          batch2Rule("warn", batch2Any(batch2Ne("evidence_complete", true), batch2Gt("missing_required_category_count", 0))),
          batch2Rule("pass", batch2All(
            batch2Eq("evidence_readable", true),
            batch2Eq("evidence_complete", true),
            batch2Gt("rule_count", 0),
            batch2Gt("enabled_rule_count", 0),
            batch2Gt("blocking_rule_count", 0),
            batch2Eq("missing_required_category_count", 0),
          )),
          batch2Rule("manual", { op: "always" }),
        ],
      }
    : control === 2
      ? {
          decisionInputs: {
            evidence_readable: "Boolean. True only when GET /firewallFilteringRules returned a readable inventory.",
            evidence_complete: "Boolean. True only when firewall-rule pagination proved exhaustion; false means the rule counts are lower bounds.",
            rule_count: "Complete number of firewall filtering rules before presentation slicing; zero is a readable empty inventory and fails.",
            enabled_rule_count: "Count of rules whose state is exactly ENABLED.",
            default_rule_present: "Boolean. True when a returned rule has defaultRule=true.",
            default_rule_allows: "Boolean. True when the default rule action is exactly ALLOW.",
            unbounded_allow_rule_count: "Count of enabled ALLOW rules with no destination or service restriction.",
            blocking_rule_without_full_logging_count: "Count of enabled BLOCK rules whose documented enableFullLogging field is not true.",
            enabled_non_default_rule_count: "Count of enabled rules that are not the default rule.",
          },
          decisionRules: [
            batch2Rule("manual", batch2Ne("evidence_readable", true)),
            batch2Rule("fail", batch2Any(
              batch2Eq("rule_count", 0),
              batch2Eq("default_rule_allows", true),
              batch2Gt("unbounded_allow_rule_count", 0),
            )),
            batch2Rule("warn", batch2Any(
              batch2Ne("evidence_complete", true),
              batch2Eq("default_rule_present", false),
              batch2Eq("enabled_non_default_rule_count", 0),
              batch2Gt("blocking_rule_without_full_logging_count", 0),
            )),
            batch2Rule("pass", { op: "always" }),
          ],
        }
      : {};
  return {
    id: `ZS-${String(control).padStart(2, "0")}`,
    control,
    title,
    severity,
    owner: owner(area),
    surfaces: [area === "zpa" ? "zpa-policy" : area === "zia_policy" ? "zia-policy" : "zia-administration"],
    emptyOutcome: "manual" as const,
    constants: decisionConstants(control),
    ...custom,
    decision: `Evaluate ${title} from the complete ${area === "zpa" ? "ZPA" : "ZIA"} inventory: missing product credentials and unreadable or ambiguous feature responses remain manual, a proved insecure record takes precedence, partial or review records warn, and pass requires complete readable evidence with no violation.`,
  };
}));
const idsFor = (tool: string): string[] => checks.filter((check) => check.owner === tool).map((check) => check.id);

export const ZSCALER_RUNTIME_BEHAVIOR = [
  "ZIA and ZPA authenticate independently; absent credentials produce explicit not-configured manual findings for that product.",
  "The ZIA client logs out in a finally path, and ZIA API-key obfuscation plus session cookies are never written to findings or bundles.",
  "List pagination and configured retry exhaustion remain partial or unreadable; presentation samples never establish compliance.",
] as const;

export const ZSCALER_SPEC = buildBatchIntegrationSpec({
  slug: "zscaler-sec-inspector",
  displayName: "Zscaler Security Inspector",
  vendor: "Zscaler",
  category: "zero-trust-and-secure-web-gateway",
  summary: "Portable contract for the shipped ZIA administrative and policy assessments and ZPA zero-trust access assessment.",
  sourceModule: "cli/extensions/grc-tools/zscaler.ts",
  baseServices: ["ZIA API", "ZPA API"],
  authentication: ZSCALER_AUTH_RESOLVER,
  permissions: [
    { id: "zia-read-admin", kind: "role", value: "ZIA administrator API read access to the declared administrative and policy surfaces", unlocks: ["zia-administration", "zia-policy"] },
    { id: "zpa-read-client", kind: "oauth-scope", value: "ZPA API client read access for the configured customer", unlocks: ["zpa-policy"] },
  ],
  surfaces,
  checks,
  tools: {
    zscaler_check_access: [],
    zscaler_assess_zia_access_control: idsFor("zscaler_assess_zia_access_control"),
    zscaler_assess_zia_policy: idsFor("zscaler_assess_zia_policy"),
    zscaler_assess_zpa: idsFor("zscaler_assess_zpa"),
    zscaler_export_audit_bundle: checks.map((check) => check.id),
  },
  pagination: [{
    surfaceIds: surfaces.map((surface) => surface.id),
    cursorFields: ["page", "pageSize", "totalPages", "totalElements", "next"],
    pageSize: null,
    itemCap: null,
    pageCap: null,
    totalSemantics: "Completion requires reaching the documented final page or total without a repeated cursor, empty advancing page, or configured item cap.",
    stopConditions: ["Reported final page", "Reported total reached", "Short or empty final page", "Repeated cursor", "Configured cap"],
  }],
  rateLimit: {
    documentedLimit: "Cloud, product, and endpoint specific",
    retryHeaders: ["Retry-After"],
    retryableStatuses: [429, 500, 502, 503, 504],
    backoffPolicy: "Honor bounded Retry-After and retry transient responses up to the configured retry count; exhausted reads remain unreadable.",
  },
  runtimeBehavior: ZSCALER_RUNTIME_BEHAVIOR,
  knownGaps: [
    "Current-runtime limitation preserved for parity: secondary ZIA and ZPA inventories processed by capForUnreadableAll cap pass when unreadable, but truncation alone is not completeness-gating. Some single-dataset truncations therefore remain pass until the runtime is corrected.",
    "ZDX and OneAPI credentials are recognized by configuration but the shipped assessment tools cover ZIA and ZPA only.",
  ],
  sensitiveFields: ["apiKey", "password", "clientSecret", "authorization", "cookie", "token"],
  credentialFormats: ["ZIA API keys", "ZIA administrator passwords", "ZIA session cookies", "ZPA OAuth client secrets and bearer tokens"],
  output: buildBatchOutputContract({
    files: [
      "QUICK_REFERENCE.md", "core_data/access_check.json", "core_data/zia_access_control.json",
      "core_data/zia_policy.json", "core_data/zpa.json", "analysis/findings.json",
      "analysis/summary.json", "analysis/zia_access_control.json",
      "analysis/zia_policy.json", "analysis/zpa.json", "compliance/executive_summary.md",
      "compliance/unified_compliance_matrix.md",
      "compliance/fedramp/fedramp_compliance_report.md",
      "compliance/cmmc/cmmc_compliance_report.md",
      "compliance/soc2/soc2_compliance_report.md",
      "compliance/cis/cis_compliance_report.md",
      "compliance/pci_dss/pci_dss_compliance_report.md",
      "compliance/disa_stig/stig_compliance_checklist.md",
      "compliance/irap/irap_compliance_report.md",
      "compliance/ismap/ismap_compliance_report.md",
    ],
    conditionalFiles: ["_errors.log"],
    overwritePolicy: "Allocate a new Zscaler audit directory and numeric suffix without overwriting an existing directory or paired archive.",
    archivePairing: "Create <allocated-directory>.zip beside the allocated Zscaler audit directory.",
  }),
});
