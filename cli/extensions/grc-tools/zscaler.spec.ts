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
import { ZSCALER_AUTH_RESOLVER } from "./auth-resolver-contracts.js";

const ZIA_DOCS = "https://help.zscaler.com/zia/api";
const ZPA_DOCS = "https://help.zscaler.com/zpa/api-reference";
export const ZSCALER_DEFAULT_MAX_SUPER_ADMINS = 5;
export const ZSCALER_DEFAULT_CERT_EXPIRY_WARN_DAYS = 30;
export const ZSCALER_DEFAULT_STALE_CONNECTOR_DAYS = 30;
export const ZSCALER_DEFAULT_MAX_TIMEOUT_HOURS = 24;
export const ZSCALER_DEFAULT_MAX_SSL_EXEMPTIONS = 50;
export const ZSCALER_MAX_SECURITY_ALLOWLIST_URLS = 100;
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

const ZSCALER_TRUNCATION_ONLY = ["truncated"] as const;
const zscalerCompletenessSources = (
  surfaceId: string,
): readonly BatchCompletenessSourceDefinition[] => [{
  surfaceId,
  falseWhen: ZSCALER_TRUNCATION_ONLY,
}];

function zscalerCompletenessSemantics(control: number, title: string): string {
  if (control === 4) {
    return "true unless the location inventory is truncated; SSL-rule truncation is disclosed but does not change this primitive in the preserved current behavior.";
  }
  if (control === 25) {
    return "true unless a companion inventory that the current capForUnreadableAll path recognizes is incomplete; the documented single-dataset truncation exceptions do not change this primitive.";
  }
  return `true for ${title} only when every dataset currently designated as completeness-gating for this finding reaches its final page; the documented truncation exceptions remain excluded.`;
}

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
  4: { default_maximum_ssl_exemptions: ZSCALER_DEFAULT_MAX_SSL_EXEMPTIONS },
  7: { default_maximum_super_administrators: ZSCALER_DEFAULT_MAX_SUPER_ADMINS },
  11: { default_stale_connector_days: ZSCALER_DEFAULT_STALE_CONNECTOR_DAYS },
  13: { default_maximum_timeout_hours: ZSCALER_DEFAULT_MAX_TIMEOUT_HOURS },
  21: { default_stale_service_edge_days: ZSCALER_DEFAULT_STALE_CONNECTOR_DAYS },
  24: { default_certificate_expiry_warning_days: ZSCALER_DEFAULT_CERT_EXPIRY_WARN_DAYS },
  25: {
    required_advanced_threat_protection_flags: ZSCALER_REQUIRED_ATP_FLAGS,
    required_malware_protection_flags: ZSCALER_REQUIRED_MALWARE_FLAGS,
    maximum_security_allowlist_urls: ZSCALER_MAX_SECURITY_ALLOWLIST_URLS,
  },
} as const)[control as 1 | 4 | 7 | 11 | 13 | 24 | 25];

const decisionPredicate: readonly string[] = [
  `Use the explicit enabled BLOCK-rule and required-category rules rendered below; required categories are ${ZSCALER_REQUIRED_URL_BLOCK_CATEGORIES.join(", ")}.`,
  "Use the explicit default-rule, unbounded-ALLOW, full-logging, and enabled non-default rule predicates rendered below.",
  "Fail when web DLP rules or engines are empty or all rules are disabled; warn when no enabled blocking rule references a DLP engine or withoutContentInspection.",
  `Fail when no enabled DECRYPT rule exists or an unscoped DO_NOT_DECRYPT rule exists. Warn when the exemption list is unreadable, its count exceeds max_ssl_exemptions (default ${ZSCALER_DEFAULT_MAX_SSL_EXEMPTIONS}, clamped to 0 through 100000), or a location has sslScanEnabled=false.`,
  "Remain manual when no sandbox rule exists; fail when all rules are disabled; warn when enabled rules do not use BLOCK.",
  "Fail when any enabled ZIA administrator permits password login without readable SAML authentication evidence; warn for incomplete administrators.",
  `Fail when enabled administrator coverage is absent or enabled Super Admin membership exceeds max_super_admins. That option defaults to ${ZSCALER_DEFAULT_MAX_SUPER_ADMINS} and is clamped to 0 through 500; warn for missing role resolution, local-password access, or unreadable password-expiry settings.`,
  "Fail when no enabled application segment exists or a segment is wildcard-domain plus full-port-range or bypassType=ALWAYS; warn for wildcard domains, full ranges, bypass, ungrouped segments, or partial segment/group data.",
  "Fail when no enabled access ALLOW rule exists or an unconditional ALLOW rule exists; warn for ALLOW rules without identity criteria.",
  "Fail when no posture profile exists or no ALLOW access rule uses posture; warn when only a subset of ALLOW rules uses posture.",
  `Fail when no authenticated App Connector exists; warn for disconnected, undated, or older-than-stale_connector_days connectors and connector groups with fewer than two connectors. stale_connector_days defaults to ${ZSCALER_DEFAULT_STALE_CONNECTOR_DAYS} and is clamped to 1 through 3650.`,
  "Fail when no user IdP is enabled; warn for absent SCIM, unsigned SAML requests, weak ZPA administrators, absent admin IdP coverage, or partial IdP companion inventories.",
  `Fail when no enabled timeout rule exists or reauthentication exceeds max_timeout_hours; warn for missing timeout values. max_timeout_hours defaults to ${ZSCALER_DEFAULT_MAX_TIMEOUT_HOURS} and is clamped to 1 through 8760.`,
  "Fail when the audit report is not COMPLETE and NSS feeds exist but none is an enabled ADMIN_AUDIT feed; warn when no NSS feed exists.",
  "Remain manual when no trusted network exists; warn when no enabled access or forwarding rule references a TRUSTED_NETWORK condition.",
  "Remain manual when no bandwidth-control rule exists; warn when every returned rule is disabled.",
  "Remain manual when no isolation profile exists; warn when no enabled URL filtering rule uses ISOLATE.",
  "Fail when any location or sub-location lacks authentication, SSL scanning, or firewall enablement; warn when tunnel/VPN coverage or child-location collection is partial.",
  "Remain manual when no cloud-application control rule exists; warn when no enabled restrictive action covers an assessed cloud-app rule type.",
  "Fail when no non-default enabled DNS rule blocks or redirects; warn when dgaDomainsBlocked is not true.",
  `Warn for disconnected, undated, or older-than-stale_connector_days private Service Edges; the option defaults to ${ZSCALER_DEFAULT_STALE_CONNECTOR_DAYS} and is clamped to 1 through 3650. A complete empty inventory documents reliance on public edges.`,
  "Remain manual when no forwarding rule exists; fail for an unconditional BYPASS and warn for scoped BYPASS rules.",
  "Remain manual when no emergency-access user exists; warn when any returned emergency user is active.",
  `Fail for expired enrollment or browser-access certificates; warn for missing expiry or expiry within cert_expiry_warn_days. That option defaults to ${ZSCALER_DEFAULT_CERT_EXPIRY_WARN_DAYS} and is clamped to 1 through 3650 days.`,
  `Fail when any required ATP flag (${ZSCALER_REQUIRED_ATP_FLAGS.join(", ")}) or malware flag (${ZSCALER_REQUIRED_MALWARE_FLAGS.join(", ")}) is not true; warn when blockUnscannableFiles is not true or the security whitelistUrls count exceeds ${ZSCALER_MAX_SECURITY_ALLOWLIST_URLS}.`,
] as const;

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
      : control === 4
        ? {
            decisionInputs: {
              evidence_readable: "Boolean. True only when GET /sslInspectionRules returned a readable array; unreadable companion datasets are represented separately.",
              evidence_complete: "Boolean. For parent parity, true unless the location inventory is truncated; SSL-rule truncation is disclosed but currently does not cap pass.",
              rule_count: "Non-negative integer count of every returned SSL inspection rule before display slicing.",
              decrypt_rule_count: "Non-negative integer count of enabled rules whose action type is exactly `DECRYPT`.",
              blanket_bypass_rule_count: "Non-negative integer count of enabled `DO_NOT_DECRYPT` rules with empty URL-category, cloud-application, destination-IP-group, location, user, group, and department scopes.",
              exemptions_readable: "Boolean. True when GET /sslSettings/exemptedUrls returned a readable urls array.",
              exemption_count: "Non-negative integer count of entries in the raw exempted URL array; null means that companion surface was unreadable.",
              maximum_exemption_count: `Non-negative integer max_ssl_exemptions option after clamping to 0 through 100000; omitted or non-finite input uses ${ZSCALER_DEFAULT_MAX_SSL_EXEMPTIONS}.`,
              location_without_ssl_scan_count: "Non-negative integer count of returned locations whose raw sslScanEnabled field is false; null means the location companion surface was unreadable.",
            },
            decisionRules: [
              batch2Rule("manual", batch2Ne("evidence_readable", true)),
              batch2Rule("fail", batch2Any(
                batch2Eq("rule_count", 0),
                batch2Eq("decrypt_rule_count", 0),
                batch2Gt("blanket_bypass_rule_count", 0),
              )),
              batch2Rule("warn", batch2Any(
                batch2Ne("exemptions_readable", true),
                batch2ComparePaths("gt", "exemption_count", "maximum_exemption_count"),
                batch2Gt("location_without_ssl_scan_count", 0),
                batch2Ne("evidence_complete", true),
              )),
              batch2Rule("pass", { op: "always" }),
            ],
          }
        : control === 25
          ? {
              decisionInputs: {
                evidence_readable: "Boolean. True only when both Advanced Threat Protection and malware settings objects were readable.",
                evidence_complete: "Boolean collector state disclosed by unreadable or truncated companion inventories. For parent parity, this value is not a direct ZS-25 decision gate; the documented capForUnreadableAll limitation remains.",
                atp_setting_count: "Non-negative integer count of raw fields in the Advanced Threat Protection settings object.",
                malware_setting_count: "Non-negative integer count of raw fields in the malware settings object.",
                missing_atp_flag_count: `Count of these required fields whose raw value is not true: ${ZSCALER_REQUIRED_ATP_FLAGS.join(", ")}.`,
                missing_malware_flag_count: `Count of these required fields whose raw value is not true: ${ZSCALER_REQUIRED_MALWARE_FLAGS.join(", ")}.`,
                block_unscannable_files: "Boolean from malwarePolicy.blockUnscannableFiles; false or missing triggers warning when primary protection flags pass.",
                allowlist_url_count: "Non-negative integer count of security whitelistUrls; null means the companion allowlist surface was unreadable.",
              },
              decisionRules: [
                batch2Rule("manual", batch2Ne("evidence_readable", true)),
                batch2Rule("fail", batch2Any(
                  batch2Eq("atp_setting_count", 0),
                  batch2Eq("malware_setting_count", 0),
                  batch2Gt("missing_atp_flag_count", 0),
                  batch2Gt("missing_malware_flag_count", 0),
                )),
                batch2Rule("warn", batch2Any(
                  batch2Ne("evidence_complete", true),
                  batch2Ne("block_unscannable_files", true),
                  batch2Gt("allowlist_url_count", ZSCALER_MAX_SECURITY_ALLOWLIST_URLS),
                )),
                batch2Rule("pass", { op: "always" }),
              ],
            }
          : {};
  const id = `ZS-${String(control).padStart(2, "0")}`;
  const surfaceId = area === "zpa" ? "zpa-policy" : area === "zia_policy" ? "zia-policy" : "zia-administration";
  const decisionInputs = custom.decisionInputs ?? batch2GenericDecisionInputs(decisionPredicate[index]);
  return {
    id,
    control,
    title,
    severity,
    owner: owner(area),
    surfaces: [surfaceId],
    emptyOutcome: "manual" as const,
    constants: decisionConstants(control),
    decisionInputs,
    ...custom,
    completeness: batch2Completeness(
      decisionInputs,
      zscalerCompletenessSources(surfaceId),
      zscalerCompletenessSemantics(control, title),
    ),
    decision: `${decisionPredicate[index]} Missing product credentials and unreadable or ambiguous feature responses remain manual; a proved violation has first-match precedence. The known truncation exceptions are listed as runtime gaps rather than silently hardened.`,
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
    "Current-runtime limitation preserved for parity: across the 41 ZIA-policy and ZPA single-dataset truncation replays, 16 affected finding cases remain pass for ZS-03, ZS-04, ZS-05, ZS-16, ZS-17, ZS-20, and ZS-25. Secondary inventories cap pass when unreadable, but those truncations and several primary ZIA truncations are not completeness-gating.",
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
