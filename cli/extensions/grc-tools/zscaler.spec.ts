import {
  buildBatchIntegrationSpec,
  buildBatchOutputContract,
} from "./batch-spec-builder.js";
import {
  batch2Checks,
  restSurface,
  type Batch2CheckRow,
} from "./batch2-spec-helpers.js";
import { ZSCALER_AUTH_RESOLVER } from "./auth-resolver-contracts.js";

const ZIA_DOCS = "https://help.zscaler.com/zia/api";
const ZPA_DOCS = "https://help.zscaler.com/zpa/api-reference";
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

const checks = batch2Checks(rows.map(([title, severity, area], index) => {
  const control = index + 1;
  return {
    id: `ZS-${String(control).padStart(2, "0")}`,
    control,
    title,
    severity,
    owner: owner(area),
    surfaces: [area === "zpa" ? "zpa-policy" : area === "zia_policy" ? "zia-policy" : "zia-administration"],
    emptyOutcome: "manual" as const,
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
    surfaceIds: surfaces,
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
  knownGaps: ["ZDX and OneAPI credentials are recognized by configuration but the shipped assessment tools cover ZIA and ZPA only."],
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
