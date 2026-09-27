import { buildBatchIntegrationSpec, type BatchCheckDefinition } from "./batch-spec-builder.js";

const titles = [
  "Instance security properties", "ACL rule completeness", "Role hierarchy audit", "User access review",
  "Session timeout configuration", "Password policy enforcement", "MFA enforcement", "LDAP and SSO integration",
  "Encryption at rest", "Audit logging configuration", "Table-level access controls", "Script execution restrictions",
  "Instance hardening", "Integration user permissions", "Update set management", "Debug mode verification",
  "IP access restrictions", "Email security", "MID Server security", "Plugin inventory and licensing",
] as const;
const identity = new Set([3, 4, 6, 7, 8, 14]);
const hardening = new Set([1, 5, 12, 13, 16, 17, 18]);
const access = new Set([2, 11]);
const ownerFor = (control: number): string => identity.has(control)
  ? "servicenow_assess_identity_access"
  : hardening.has(control)
    ? "servicenow_assess_platform_hardening"
    : access.has(control)
      ? "servicenow_assess_access_control"
      : "servicenow_assess_operations_governance";
const decisions = [
  "return pass when the complete security-property set enables the documented secure defaults, fail when any required property is explicitly insecure, and warn when optional hardening is absent or evidence is partial.",
  "return fail when any active ACL lacks both a role and a condition or script, warn when questionable ACLs remain or ACL and role joins are partial, and pass when every active ACL has an explicit restriction.",
  "return fail when administrator-equivalent roles exceed the configured population threshold, warn for broad inheritance, stale assignments, or partial role data, and pass when complete role and assignment evidence stays within the threshold.",
  "return fail when active privileged users exceed the configured maximum or include stale accounts beyond the configured age, warn for undated users or partial evidence, and pass when the complete population is bounded and recent.",
  "return pass when the inactivity timeout is positive and at or below the configured threshold, warn when it exceeds the threshold, fail when disabled, and manual when the property is absent or unreadable.",
  "return pass when the password policy meets minimum and maximum length, character-class, and strength requirements, warn when only some fields miss the baseline, fail for a weak preset or multiple gaps, and manual when decisive fields are absent.",
  "return pass when an active multi-factor criterion covers every required privileged role, fail when no active criterion exists, warn for incomplete role coverage, and manual when criteria or role evidence is unavailable.",
  "return pass when an active SSO or LDAP integration is visible and privileged local-account exceptions are bounded, warn for disabled or partial integration evidence, and manual when integration policy cannot be read.",
  "return pass when an active customer encryption module or encrypted field evidence is visible, warn when only platform-default encryption is evident, fail when readable evidence explicitly disables encryption, and manual when the licensed encryption surface is unavailable.",
  "return pass when system auditing is enabled and the complete lookback contains records, warn when the readable window is empty or partial, fail when auditing is explicitly disabled, and manual when properties or audit rows are unavailable.",
  "return fail when any sensitive table has an active permissive ACL without role, condition, or script restrictions, warn for incomplete table or ACL evidence, and pass when every inspected sensitive table is explicitly protected.",
  "return fail when unrestricted server-side script execution is enabled, pass when the documented script restrictions are enabled, warn for mixed settings, and manual when the required properties are absent.",
  "return pass when all documented baseline hardening properties are secure, fail when any critical property is explicitly insecure, and warn when noncritical settings are weak or evidence is partial.",
  "return fail when an active integration user has administrator-equivalent roles, warn for broad non-admin roles, stale users, or partial assignments, and pass when complete evidence shows least-privileged integration identities.",
  "return pass when complete update-set evidence shows recent completed sets with no unresolved preview or commit errors, warn for in-progress, stale, failed, or partial sets, and manual when update-set tables are unavailable.",
  "return pass when debug and diagnostic properties are disabled, fail when any is enabled, and manual when no decisive debug property is readable.",
  "return pass when the complete IP access-control inventory contains active restrictive ranges, fail when an explicit allow-all rule exists, warn when no rule exists or coverage is partial, and manual when the table is unavailable.",
  "return pass when documented outbound email TLS and security properties are enabled, fail when TLS is explicitly disabled, warn for weaker optional settings, and manual when decisive properties are absent.",
  "return pass when every active MID Server is validated, recent, and uses a non-administrator service identity, fail for administrator identities or failed validation, warn for stale, down, or partial records, and manual when the MID inventory is unavailable.",
  "return pass when the complete plugin inventory contains only active licensed plugins required by the instance, warn for inactive, unlicensed, or partial plugin evidence, and manual when licensing or intended-use evidence cannot be inferred from the API.",
] as const;
const checks: BatchCheckDefinition[] = titles.map((title, index) => {
  const control = index + 1;
  return {
    id: `SNOW-${String(control).padStart(2, "0")}`,
    control,
    title,
    severity: control === 7 ? "critical" : [1, 2, 3, 4, 6, 8, 10, 11, 12, 13, 14].includes(control) ? "high" : "medium",
    owner: ownerFor(control),
    decision: decisions[index],
  };
});
const idsFor = (owner: string): string[] => checks.filter((check) => check.owner === owner).map((check) => check.id);

export const SERVICENOW_RUNTIME_BEHAVIOR = [
  "Table API rows and Aggregate API counts are cross-checked; missing totals, ACL-filtered visibility, truncation, denied reads, and skipped child requests prevent pass.",
  "Encoded-query pagination uses sysparm_offset plus X-Total-Count, rejects foreign next links, and preserves exact seen, total, page, and stop-reason evidence.",
  "MFA, encryption, script, IP, email, and outbound TLS controls use documented properties and tables available to the runtime; unavailable Instance Security Center and product-specific proofs remain manual.",
] as const;

export const SERVICENOW_SPEC = buildBatchIntegrationSpec({
  slug: "servicenow-sec-inspector",
  displayName: "ServiceNow Security Inspector",
  vendor: "ServiceNow",
  category: "it-service-management",
  summary: "Portable contract for the shipped ServiceNow identity, hardening, access-control, and operations-governance assessments.",
  sourceModule: "cli/extensions/grc-tools/servicenow.ts",
  baseServices: ["ServiceNow Table API", "ServiceNow Aggregate API", "ServiceNow OAuth token endpoint"],
  authentication: {
    modes: ["Basic username and password", "OAuth client credentials or refresh token", "Explicit OAuth access token", "mTLS configuration metadata"],
    precedence: ["Explicit access token", "Explicit OAuth client credentials or refresh token", "Explicit Basic credentials", "Config file", "SERVICENOW_* environment variables"],
    environment: ["SERVICENOW_INSTANCE", "SERVICENOW_USERNAME", "SERVICENOW_PASSWORD", "SERVICENOW_CLIENT_ID", "SERVICENOW_CLIENT_SECRET", "SERVICENOW_ACCESS_TOKEN", "SERVICENOW_REFRESH_TOKEN"],
    configLocations: ["~/.servicenow-sec-inspector/config.yaml"],
    variants: ["Instance name or explicit HTTPS instance URL"],
    configFields: ["instanceUrl", "instanceName", "authMode", "username", "password", "clientId", "clientSecret", "accessToken", "refreshToken", "pageSize"],
    refreshRequest: "POST /oauth_token.do with client_credentials or refresh_token form fields.",
  },
  permissions: ["Read access to sys_user, role, ACL, property, audit, update-set, dictionary, plugin, and MID Server tables", "Aggregate API count visibility matching Table API row visibility"],
  surfaces: [
    { id: "table-api", path: "/api/now/table/{table}", service: "ServiceNow Table API", documentationUrl: "https://www.servicenow.com/docs/bundle/zurich-api-reference/page/integrate/inbound-rest/concept/c_TableAPI.html", fields: ["result", "sys_id", "sys_updated_on", "active", "name", "value"] },
    { id: "aggregate-api", path: "/api/now/stats/{table}", service: "ServiceNow Aggregate API", documentationUrl: "https://www.servicenow.com/docs/bundle/zurich-api-reference/page/integrate/inbound-rest/concept/c_AggregateAPI.html", fields: ["result.stats.count"] },
    { id: "system-properties", path: "/api/now/table/sys_properties", service: "ServiceNow Table API", documentationUrl: "https://www.servicenow.com/docs/bundle/zurich-platform-security/page/administer/security/reference/security-properties.html", fields: ["name", "value", "description", "sys_updated_on"] },
    { id: "access-controls", path: "/api/now/table/sys_security_acl", service: "ServiceNow Table API", documentationUrl: "https://www.servicenow.com/docs/bundle/zurich-platform-security/page/administer/contextual-security/concept/access-control-rules.html", fields: ["sys_id", "name", "operation", "active", "admin_overrides", "requires_role", "script"] },
    { id: "audit", path: "/api/now/table/sys_audit", service: "ServiceNow Table API", documentationUrl: "https://www.servicenow.com/docs/bundle/zurich-platform-administration/page/administer/security/concept/c_SystemAuditLog.html", fields: ["documentkey", "tablename", "fieldname", "oldvalue", "newvalue", "sys_created_on"] },
  ],
  checks,
  tools: {
    servicenow_check_access: [],
    servicenow_assess_identity_access: idsFor("servicenow_assess_identity_access"),
    servicenow_assess_platform_hardening: idsFor("servicenow_assess_platform_hardening"),
    servicenow_assess_access_control: idsFor("servicenow_assess_access_control"),
    servicenow_assess_operations_governance: idsFor("servicenow_assess_operations_governance"),
    servicenow_export_audit_bundle: checks.map((check) => check.id),
  },
  pagination: {
    cursorFields: ["sysparm_offset", "sysparm_limit", "X-Total-Count", "Link rel=next"],
    pageSize: 500,
    itemCap: 10000,
    pageCap: null,
    totalSemantics: "X-Total-Count or Aggregate count is authoritative; absent or mismatched totals prevent proven exhaustion.",
    stopConditions: ["Seen count reaches authoritative total", "Short page with authoritative completion", "Configured item cap", "Empty page before total", "Repeated offset", "Missing total", "Rejected next link"],
  },
  rateLimit: {
    documentedLimit: "Instance and node configuration determine ServiceNow inbound REST limits",
    retryHeaders: ["Retry-After", "X-RateLimit-Limit", "X-RateLimit-Remaining"],
    retryableStatuses: [429, 500, 502, 503, 504],
    backoffPolicy: "Honor bounded Retry-After and retry transient reads three times; exhausted reads remain unavailable.",
  },
  runtimeBehavior: SERVICENOW_RUNTIME_BEHAVIOR,
  knownGaps: ["mTLS transport and several Instance Security Center, Scan, DKIM, adaptive MFA, MID, and retention proofs remain manual."],
  sensitiveFields: ["password", "client_secret", "access_token", "refresh_token", "authorization", "cookie", "sysparm_query"],
  credentialFormats: ["ServiceNow passwords", "OAuth bearer and refresh tokens", "client secrets", "JSESSIONID cookies"],
  outputPrefix: "servicenow-audit",
});
