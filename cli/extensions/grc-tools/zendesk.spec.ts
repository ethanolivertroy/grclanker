import { buildBatchIntegrationSpec, type BatchCheckDefinition } from "./batch-spec-builder.js";

const titles = [
  "SSO enforcement enabled", "Two-factor authentication required for agents", "Password policy meets complexity requirements",
  "IP restrictions configured for agent access", "Session timeout configured and reasonable", "Agent roles follow least privilege",
  "No excessive admin accounts", "Group-based access controls configured", "Audit logging enabled and accessible",
  "Audit log retention meets compliance requirements", "HIPAA compliance mode enabled when applicable",
  "Data deletion and redaction policies configured", "API tokens are minimal and reviewed",
  "OAuth application permissions are scoped", "Marketplace apps reviewed for permissions",
  "Private and custom apps have appropriate scope", "Sandbox environment used for testing",
  "Authenticated attachment downloads configured", "File attachment restrictions configured",
  "Suspended ticket handling automated", "End-user authentication required", "Brand security settings consistent",
  "External sharing agreements reviewed", "External notification targets use HTTPS",
  "Triggers and automations do not send data to external URLs",
] as const;
const ownerFor = (control: number): string => [1, 2, 3, 4, 5, 21].includes(control)
  ? "zendesk_assess_authentication"
  : [6, 7, 8, 13, 14].includes(control)
    ? "zendesk_assess_access_control"
    : [9, 10, 11, 12, 18, 19, 20].includes(control)
      ? "zendesk_assess_data_protection"
      : "zendesk_assess_integrations";
const checks: BatchCheckDefinition[] = titles.map((title, index) => {
  const control = index + 1;
  return {
    id: `ZD-${String(control).padStart(2, "0")}`,
    control,
    title,
    severity: [1, 2, 6, 11].includes(control) ? "critical" : [3, 4, 7, 9, 12, 13, 14, 21, 24, 25].includes(control) ? "high" : "medium",
    owner: ownerFor(control),
  };
});
const idsFor = (owner: string): string[] => checks.filter((check) => check.owner === owner).map((check) => check.id);

export const ZENDESK_RUNTIME_BEHAVIOR = [
  "Cursor pagination is preferred and offset pagination is retained defensively; both deduplicate stable record IDs and mark cap, repeated-link, and inconsistent-total exits partial.",
  "Admin-only, Enterprise-only, and plan-gated reads produce explicit manual findings with endpoint and evidence instructions; forbidden evidence never becomes an empty pass.",
  "HIPAA mode, allowed attachment types, and anonymous-ticket posture have no decisive published read field and remain manual.",
] as const;

export const ZENDESK_SPEC = buildBatchIntegrationSpec({
  slug: "zendesk-sec-inspector",
  displayName: "Zendesk Security Inspector",
  vendor: "Zendesk",
  category: "customer-support",
  summary: "Portable contract for the shipped Zendesk authentication, access-control, data-protection, and integration assessments.",
  sourceModule: "cli/extensions/grc-tools/zendesk.ts",
  baseServices: ["Zendesk Support API"],
  authentication: {
    modes: ["API token with email Basic authentication", "OAuth bearer token"],
    precedence: ["Explicit OAuth token", "Explicit API token and email", "Explicit config file", "ZENDESK_* environment variables"],
    environment: ["ZENDESK_SUBDOMAIN", "ZENDESK_EMAIL", "ZENDESK_API_TOKEN", "ZENDESK_OAUTH_TOKEN", "ZENDESK_CONFIG_FILE"],
    configLocations: ["~/.zendesk/config.json"],
    variants: ["Zendesk subdomain or explicit same-origin API base URL"],
    configFields: ["subdomain", "email", "apiToken", "oauthToken", "baseUrl", "timeoutMs"],
  },
  permissions: ["Zendesk administrator API access", "Enterprise audit-log and custom-role entitlements", "OAuth read scope"],
  surfaces: [
    { id: "security-settings", path: "/api/v2/security_settings", service: "Zendesk Support API", documentationUrl: "https://developer.zendesk.com/api-reference/ticketing/account-configuration/security_settings/", fields: ["sso", "two_factor_authentication", "password_policy", "ip_restrictions", "session_expiration"] },
    { id: "users", path: "/api/v2/users", service: "Zendesk Support API", documentationUrl: "https://developer.zendesk.com/api-reference/ticketing/users/users/", fields: ["id", "email", "role", "custom_role_id", "active", "suspended", "last_login_at"] },
    { id: "audit-logs", path: "/api/v2/audit_logs", service: "Zendesk Support API", documentationUrl: "https://developer.zendesk.com/api-reference/ticketing/account-configuration/audit_logs/", fields: ["id", "created_at", "action", "source_type", "source_id", "actor_id"] },
    { id: "deletion-schedules", path: "/api/v2/deletion_schedules", service: "Zendesk Support API", documentationUrl: "https://developer.zendesk.com/api-reference/ticketing/account-configuration/data-deletion-schedules/", fields: ["id", "title", "status", "object_type", "retention_period"] },
    { id: "apps-and-webhooks", path: "/api/v2/apps/installations", service: "Zendesk Support API", documentationUrl: "https://developer.zendesk.com/api-reference/ticketing/apps/apps/", fields: ["id", "app_id", "enabled", "settings", "url"] },
  ],
  checks,
  tools: {
    zendesk_check_access: [],
    zendesk_assess_authentication: idsFor("zendesk_assess_authentication"),
    zendesk_assess_access_control: idsFor("zendesk_assess_access_control"),
    zendesk_assess_data_protection: idsFor("zendesk_assess_data_protection"),
    zendesk_assess_integrations: idsFor("zendesk_assess_integrations"),
    zendesk_export_audit_bundle: checks.map((check) => check.id),
  },
  pagination: {
    cursorFields: ["meta.has_more", "links.next", "next_page", "count"],
    pageSize: 100,
    itemCap: 2000,
    pageCap: null,
    totalSemantics: "Cursor exhaustion or offset count equality proves completeness; missing or larger totals keep the dataset partial.",
    stopConditions: ["has_more false or no next page", "Declared total reached", "Configured item cap", "Repeated next link", "Empty page with continuation", "Rejected cross-origin next link"],
  },
  rateLimit: {
    documentedLimit: "400 requests/minute on Team and 700 requests/minute on Professional or Enterprise by default",
    retryHeaders: ["Retry-After", "X-Rate-Limit", "X-Rate-Limit-Remaining"],
    retryableStatuses: [429, 500, 502, 503, 504],
    backoffPolicy: "Honor bounded Retry-After and retry transient failures; expose exhausted reads without copying response bodies.",
  },
  runtimeBehavior: ZENDESK_RUNTIME_BEHAVIOR,
  knownGaps: ["Guide, Talk, Chat, Sell, and real-tenant validation remain outside the shipped scope."],
  sensitiveFields: ["api_token", "oauth_token", "authorization", "cookie", "email", "webhook_url"],
  credentialFormats: ["Zendesk API tokens", "OAuth bearer tokens", "Basic authorization values", "webhook path secrets"],
  outputPrefix: "zendesk-audit",
});
