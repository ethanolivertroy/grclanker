import { buildBatchIntegrationSpec, type BatchCheckDefinition } from "./batch-spec-builder.js";

const groups = {
  ID: [
    "Privileged users enforce 2-step verification",
    "Broad 2-step verification coverage for active users",
    "Dormant active accounts stay limited",
    "Super admins stay strongly protected",
    "2-step verification is enforced by organization policy",
  ],
  ADMIN: [
    "Super admin population stays constrained",
    "Suspended or archived privileged accounts are removed",
    "Delegated roles reduce Super Admin dependence",
    "Privileged activity stays observable",
    "Group-based admin grants get explicit review",
  ],
  INTEG: [
    "Third-party token inventory is readable",
    "Privileged users avoid excessive third-party token exposure",
    "High-scope third-party apps stay limited",
    "Token activity telemetry stays available",
  ],
  MON: [
    "Alert Center is available for the tenant",
    "Suspicious login backlog stays low",
    "Admin audit telemetry stays available",
    "Token audit telemetry stays available",
    "Open alert backlog is manageable",
  ],
} as const;

const owners: Record<keyof typeof groups, string> = {
  ID: "gws_assess_identity",
  ADMIN: "gws_assess_admin_access",
  INTEG: "gws_assess_integrations",
  MON: "gws_assess_monitoring",
};

let control = 0;
const checks: BatchCheckDefinition[] = Object.entries(groups).flatMap(([key, titles]) => {
  const group = key as keyof typeof groups;
  return titles.map((title, index) => ({
    id: `GWS-${group}-${String(index + 1).padStart(3, "0")}`,
    control: ++control,
    title,
    severity: /Privileged|Super admin|2-step|Suspicious|Alert Center/i.test(title) ? "high" : "medium",
    owner: owners[group],
  }));
});

const idsFor = (owner: string): string[] => checks.filter((check) => check.owner === owner).map((check) => check.id);

export const GWS_RUNTIME_BEHAVIOR = [
  "A separate Cloud Identity policy token is optional; when absent or denied, policy-dependent findings remain manual and user or audit evidence cannot substitute for policy evidence.",
  "Per-user token-list failures are retained as partial markers and demote every dependent finding; named application lists are withheld unless every required user token read completed.",
  "The shipped collector does not read Chrome Policy, device controls, installed-app OAuth grants, or expanded group membership; those claims remain outside automated coverage.",
] as const;

export const GWS_SPEC = buildBatchIntegrationSpec({
  slug: "gws-inspector-go",
  displayName: "Google Workspace Inspector",
  vendor: "Google",
  category: "identity-and-collaboration",
  summary: "Portable contract for the shipped Google Workspace tenant inspector, distinct from the gws operator bridge.",
  sourceModule: "cli/extensions/grc-tools/gws.ts",
  baseServices: ["Admin SDK Directory API", "Admin SDK Reports API", "Alert Center API", "Cloud Identity API"],
  authentication: {
    modes: ["Service-account JWT assertion with domain-wide delegation", "Explicit access tokens for directory/reporting and Cloud Identity policy reads"],
    precedence: ["Explicit tool arguments and tokens", "Explicit service-account JSON", "GOOGLE_* and GWS_* environment variables"],
    environment: ["GOOGLE_APPLICATION_CREDENTIALS", "GWS_SERVICE_ACCOUNT_FILE", "GWS_ADMIN_EMAIL", "GWS_CUSTOMER_ID", "GWS_ACCESS_TOKEN", "GWS_POLICY_ACCESS_TOKEN"],
    configLocations: ["Service-account JSON supplied by path"],
    variants: ["my_customer alias or explicit customer ID", "Separate delegated subject and Cloud Identity policy token"],
    configFields: ["client_email", "private_key", "private_key_id", "adminEmail", "customerId", "accessToken", "policyAccessToken"],
    refreshRequest: "POST https://oauth2.googleapis.com/token with a signed JWT bearer grant and delegated administrator subject.",
  },
  permissions: [
    "admin.directory.user.readonly",
    "admin.directory.rolemanagement.readonly",
    "admin.directory.user.security",
    "admin.reports.audit.readonly",
    "apps.alerts",
    "cloud-identity.policies.readonly",
  ],
  surfaces: [
    { id: "directory-users", path: "/admin/directory/v1/users", service: "Admin SDK Directory API", documentationUrl: "https://developers.google.com/admin-sdk/directory/reference/rest/v1/users/list", fields: ["id", "primaryEmail", "suspended", "archived", "isAdmin", "isEnforcedIn2Sv", "lastLoginTime"] },
    { id: "role-assignments", path: "/admin/directory/v1/customer/{customer}/roleassignments", service: "Admin SDK Directory API", documentationUrl: "https://developers.google.com/admin-sdk/directory/reference/rest/v1/roleAssignments/list", fields: ["roleAssignmentId", "roleId", "assignedTo", "scopeType"] },
    { id: "user-tokens", path: "/admin/directory/v1/users/{userKey}/tokens", service: "Admin SDK Directory API", documentationUrl: "https://developers.google.com/admin-sdk/directory/reference/rest/v1/tokens/list", fields: ["clientId", "displayText", "scopes", "anonymous"] },
    { id: "activities", path: "/admin/reports/v1/activity/users/all/applications/{applicationName}", service: "Admin SDK Reports API", documentationUrl: "https://developers.google.com/admin-sdk/reports/reference/rest/v1/activities/list", fields: ["id", "actor", "events", "ipAddress"] },
    { id: "alerts", path: "/v1beta1/alerts", service: "Alert Center API", documentationUrl: "https://developers.google.com/admin-sdk/alertcenter/reference/rest/v1beta1/alerts/list", fields: ["alertId", "type", "source", "createTime", "endTime"] },
    { id: "policies", path: "/v1/policies", service: "Cloud Identity API", documentationUrl: "https://cloud.google.com/identity/docs/reference/rest/v1/policies/list", fields: ["name", "setting", "policyQuery", "customer"] },
  ],
  checks,
  tools: {
    gws_check_access: [],
    gws_assess_identity: idsFor("gws_assess_identity"),
    gws_assess_admin_access: idsFor("gws_assess_admin_access"),
    gws_assess_integrations: idsFor("gws_assess_integrations"),
    gws_assess_monitoring: idsFor("gws_assess_monitoring"),
    gws_export_audit_bundle: checks.map((check) => check.id),
  },
  pagination: {
    cursorFields: ["nextPageToken", "pageToken"],
    pageSize: null,
    itemCap: null,
    pageCap: 1000,
    totalSemantics: "Google list APIs generally omit authoritative totals; completion requires a missing nextPageToken.",
    stopConditions: ["No nextPageToken", "Configured item cap", "Page cap", "Repeated page token", "Empty page with token", "Per-user child request denied or errored"],
  },
  rateLimit: {
    documentedLimit: "Per-project and per-customer Google API quotas",
    retryHeaders: ["Retry-After"],
    retryableStatuses: [429, 500, 502, 503, 504],
    backoffPolicy: "Use bounded exponential backoff with jitter and honor Retry-After; exhausted requests become unreadable evidence.",
  },
  runtimeBehavior: GWS_RUNTIME_BEHAVIOR,
  knownGaps: ["Installed-app OAuth, Chrome Policy, endpoint device controls, and group-membership expansion are not shipped."],
  sensitiveFields: ["private_key", "access_token", "refresh_token", "authorization", "cookie"],
  credentialFormats: ["Google service-account private keys", "OAuth bearer tokens", "signed JWT assertions"],
  outputPrefix: "gws-audit",
});
