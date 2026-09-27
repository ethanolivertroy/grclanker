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
const checks: BatchCheckDefinition[] = titles.map((title, index) => {
  const control = index + 1;
  return {
    id: `SNOW-${String(control).padStart(2, "0")}`,
    control,
    title,
    severity: control === 7 ? "critical" : [1, 2, 3, 4, 6, 8, 10, 11, 12, 13, 14].includes(control) ? "high" : "medium",
    owner: ownerFor(control),
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
