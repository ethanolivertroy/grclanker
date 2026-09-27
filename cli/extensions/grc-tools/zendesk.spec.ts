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

const decisions = [
  "return pass when team-member SSO is enforced, Zendesk password login is disabled, and at least one SSO method is enabled; warn when SSO is enforced without a method or while password login remains enabled; and fail when SSO is not enforced.",
  "return fail when any active team member explicitly lacks 2FA or account enforcement is disabled without enforced SSO, pass when enforcement is enabled and every member in a complete inventory reports 2FA enabled, warn for missing enrollment flags or partial coverage, and manual when MFA depends on the identity provider.",
  "return pass for the Recommended preset or a Custom policy with length at least 12, complexity at least two, mixed case, at most ten failed attempts, email-local-part rejection, and history at least five or unlimited; warn for High or a deficient Custom policy, and fail for every lower preset.",
  "return pass when IP restriction is enabled with at least one range, warn when enabled with no range, and fail when disabled.",
  "return pass when positive agent and applicable mobile inactivity timeouts are at or below the configured threshold, fail when the agent timeout is zero or above three times the threshold, and warn for every other threshold violation.",
  "return fail when any populated custom role grants administrator-equivalent permissions, warn for partial inventories, unassigned administrator-equivalent roles, or an all-unrestricted agent population, and pass when complete role and team inventories show none.",
  "return fail when active administrators exceed the configured threshold, warn when any administrator is stale, undated, or the inventory is partial, and pass when the non-empty complete inventory is within the threshold and all administrators are recent.",
  "return pass when complete inventories contain more than one group and at least one membership, and warn when only one group exists, no membership exists, or either inventory is truncated.",
  "return pass when the recent audit-log endpoint returns at least one entry and fills or cleanly completes its 25-entry sample, warn when paging cuts that sample short, and manual when the endpoint is unavailable or a completed sample is unexpectedly empty.",
  "return pass when the dated oldest audit entry is at least the configured retention age and warn when it is younger; an absent or undated oldest entry is manual.",
  "always return manual because the published Account Settings and Security Settings APIs expose no HIPAA or Advanced Data Privacy and Protection field.",
  "return fail when a complete deletion-schedule inventory is empty or has no active schedule, pass when it has a conditioned active ticket schedule and all companion evidence is complete, and warn for truncation, no active ticket schedule, or any active schedule without conditions.",
  "return pass when API-token authentication is disabled and audit evidence is complete, warn when it is enabled but the event history shows no outstanding token, and manual when enabled tokens remain or account settings or token history are unavailable.",
  "return fail when any OAuth client is unscoped or has a non-local HTTP redirect, pass when complete client and token inventories are empty or all clients are scoped with HTTPS redirects and every token is expiring and recently used, and warn for public, privileged, non-expiring, stale, undated, hidden, partial, or unreadable token evidence.",
  "return pass when complete installation and owned-app inventories prove no installed apps, warn when the installation inventory truncates before its first app, and manual when any installation exists because the API does not prove that marketplace permissions were reviewed.",
  "return pass when the complete owned-app inventory is empty, warn when any owned app is deprecated or obsolete or the inventory truncates before its first app, and manual for other non-empty inventories because manifest scope review is not automated.",
  "return pass when account settings report the sandbox feature enabled, warn when disabled, and manual when the flag is absent.",
  "return pass when authenticated attachment downloads are enabled and every listed CDN host uses HTTPS, warn when authentication is enabled but any CDN host is insecure, and fail when authenticated downloads are disabled.",
  "always return manual because the API exposes attachment size and email-attachment posture but not allowed file types or malicious-attachment detection.",
  "return pass when the complete suspended-ticket queue is empty or every queued ticket is dated and newer than the configured age, and warn for stale, undated, or partial queue evidence.",
  "return pass when end users have enforced SSO with a method, password login under Recommended or High, or SSO-only login; warn for enforced SSO without a method or a weaker password preset, fail when no login method exists, and keep anonymous-ticket submission as a named manual limitation.",
  "return pass when an administrator reads every active brand and all have one known help-center state, warn for a non-admin view, truncation, or mixed or unknown states, and manual when no brand is visible.",
  "return pass when the complete sharing-agreement inventory is empty, warn when any agreement is failed, ssl_error, or configuration_error or the inventory truncates before its first record, and manual when accepted or pending external agreements require business review.",
  "return fail when any active target or webhook uses a non-HTTPS endpoint, pass when complete readable inventories contain no active destination or every destination is HTTPS and every webhook has authentication, and warn for missing, partial, or unauthenticated destination evidence.",
  "return fail when any active trigger or automation sends ticket data to an HTTP destination, pass when the complete non-empty rule inventory has no external notification action and destination lookups are complete, warn for external actions or partial evidence, and manual when no active rule is visible or either rule inventory is unavailable.",
] as const;

const checks: BatchCheckDefinition[] = titles.map((title, index) => {
  const control = index + 1;
  return {
    id: `ZD-${String(control).padStart(2, "0")}`,
    control,
    title,
    severity: [1, 2, 6, 11].includes(control) ? "critical" : [3, 4, 7, 9, 12, 13, 14, 21, 24, 25].includes(control) ? "high" : "medium",
    owner: ownerFor(control),
    decision: decisions[index],
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
