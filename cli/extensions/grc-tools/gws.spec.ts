import { buildBatchIntegrationSpec, buildBatchOutputContract, type BatchCheckDefinition } from "./batch-spec-builder.js";

const GWS_CHECK_SURFACES: Readonly<Record<string, readonly string[]>> = {
  "GWS-ID-001": ["directory-users"], "GWS-ID-002": ["directory-users"], "GWS-ID-003": ["directory-users"],
  "GWS-ID-004": ["directory-users", "login-activities"], "GWS-ID-005": ["two-step-policies"],
  "GWS-ADMIN-001": ["directory-users", "roles", "role-assignments"],
  "GWS-ADMIN-002": ["directory-users", "roles", "role-assignments"],
  "GWS-ADMIN-003": ["roles", "role-assignments"], "GWS-ADMIN-004": ["admin-activities"],
  "GWS-ADMIN-005": ["role-assignments"],
  "GWS-INTEG-001": ["directory-users", "user-tokens"], "GWS-INTEG-002": ["directory-users", "roles", "role-assignments", "user-tokens"],
  "GWS-INTEG-003": ["user-tokens"], "GWS-INTEG-004": ["token-activities"],
  "GWS-MON-001": ["alerts"], "GWS-MON-002": ["alerts"], "GWS-MON-003": ["admin-activities"],
  "GWS-MON-004": ["token-activities"], "GWS-MON-005": ["alerts"],
};

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

const decisions = {
  ID: [
    "for a non-empty privileged-user population, return pass when 100 percent enforce 2-step verification, warn from 80 percent through below 100 percent, and fail below 80 percent.",
    "for a non-empty active-user population, return pass when at least 98 percent enforce 2-step verification, warn from 85 percent through below 98 percent, and fail below 85 percent.",
    "return fail when more than 10 percent of active users have no login within the configured stale period, warn when one through 10 percent are dormant or login dates are missing, and pass when none are dormant or undated.",
    "return pass when every super admin enforces 2-step verification and has recent activity, fail when any super admin lacks enforced 2-step verification, and warn for stale, undated, or partial evidence.",
    "return pass when every returned enforcement policy has a past enforcedFrom date and enrollment is allowed, warn when only some scopes satisfy that state, fail when none do, and manual when the policy token or enforcement setting is unavailable.",
  ],
  ADMIN: [
    "return pass when the complete privileged inventory has at most two super admins, warn with three through five, and fail above five.",
    "return fail when any privileged user is suspended or archived and pass when none is, with partial evidence demoting pass to warn.",
    "return pass when at least one active delegated role assignment exists outside the Super Admin role, warn when none exists or role evidence is partial, and manual when role definitions or assignments are unavailable.",
    "return pass when the complete admin-audit lookback contains activity, warn when it is empty or truncated, and manual when the audit read is denied or unreadable.",
    "always return manual when group-based role assignments exist because expanded group membership is not collected; return pass only when complete role-assignment evidence proves no group-based grant.",
  ],
  INTEG: [
    "return pass when every required per-user token read completes and at least one token is inventoried, warn when the complete inventory is empty, and manual when any token read is denied, failed, unattributed, or skipped.",
    "return fail when any privileged user has more than the configured token threshold, warn when any has a smaller non-zero exposure or reads are partial, and pass when complete reads show no excessive privileged exposure.",
    "return fail when any visible application grant contains a high-risk scope, warn when high-scope applications remain below the configured count or token evidence is partial, and pass when complete token evidence contains none.",
    "return pass when the complete token audit lookback contains at least one event, warn when it is empty or truncated, and manual when token audit telemetry is unreadable.",
  ],
  MON: [
    "return pass when the Alert Center endpoint is readable, including a complete empty alert inventory, warn when its inventory is truncated, and manual when access is denied or unreadable.",
    "return fail when open suspicious-login alerts exceed the configured threshold, warn when one through the threshold remain or alert evidence is partial, and pass when the complete inventory contains none.",
    "return pass when the complete admin-audit lookback contains events, warn when the window is empty or truncated, and manual when the Reports read is unavailable.",
    "return pass when the complete token-audit lookback contains events, warn when the window is empty or truncated, and manual when the Reports read is unavailable.",
    "return fail when open alerts exceed the configured backlog threshold, warn when a non-zero backlog is within the threshold or the inventory is partial, and pass when a complete inventory has no open alerts.",
  ],
} as const;

let control = 0;
const checks: BatchCheckDefinition[] = Object.entries(groups).flatMap(([key, titles]) => {
  const group = key as keyof typeof groups;
  return titles.map((title, index) => ({
    id: `GWS-${group}-${String(index + 1).padStart(3, "0")}`,
    control: ++control,
    title,
    severity: /Privileged|Super admin|2-step|Suspicious|Alert Center/i.test(title) ? "high" : "medium",
    owner: owners[group],
    surfaces: GWS_CHECK_SURFACES[`GWS-${group}-${String(index + 1).padStart(3, "0")}`],
    evidenceFields: [...GWS_CHECK_SURFACES[`GWS-${group}-${String(index + 1).padStart(3, "0")}`], "complete_source_counts"],
    decision: decisions[group][index],
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
    { id: "directory-users-read", kind: "oauth-scope", value: "https://www.googleapis.com/auth/admin.directory.user.readonly", unlocks: ["directory-users"] },
    { id: "directory-roles-read", kind: "oauth-scope", value: "https://www.googleapis.com/auth/admin.directory.rolemanagement.readonly", unlocks: ["roles", "role-assignments"] },
    { id: "directory-user-security", kind: "oauth-scope", value: "https://www.googleapis.com/auth/admin.directory.user.security", unlocks: ["user-tokens"] },
    { id: "reports-audit-read", kind: "oauth-scope", value: "https://www.googleapis.com/auth/admin.reports.audit.readonly", unlocks: ["login-activities", "admin-activities", "token-activities"] },
    { id: "alerts-read", kind: "oauth-scope", value: "https://www.googleapis.com/auth/apps.alerts", unlocks: ["alerts"] },
    { id: "policies-read", kind: "oauth-scope", value: "https://www.googleapis.com/auth/cloud-identity.policies.readonly", unlocks: ["two-step-policies"], notes: "Requested with the separate policy token; absence affects only policy-dependent findings." },
  ],
  surfaces: [
    { id: "directory-users", path: "/admin/directory/v1/users", service: "Admin SDK Directory API", documentationUrl: "https://developers.google.com/admin-sdk/directory/reference/rest/v1/users/list", fields: ["id", "primaryEmail", "suspended", "archived", "isAdmin", "isEnforcedIn2Sv", "lastLoginTime"] },
    { id: "roles", path: "/admin/directory/v1/customer/{customer}/roles", service: "Admin SDK Directory API", documentationUrl: "https://developers.google.com/admin-sdk/directory/reference/rest/v1/roles/list", fields: ["roleId", "roleName", "isSystemRole", "isSuperAdminRole", "rolePrivileges"] },
    { id: "role-assignments", path: "/admin/directory/v1/customer/{customer}/roleassignments", service: "Admin SDK Directory API", documentationUrl: "https://developers.google.com/admin-sdk/directory/reference/rest/v1/roleAssignments/list", fields: ["roleAssignmentId", "roleId", "assignedTo", "scopeType"] },
    { id: "user-tokens", path: "/admin/directory/v1/users/{userKey}/tokens", service: "Admin SDK Directory API", documentationUrl: "https://developers.google.com/admin-sdk/directory/reference/rest/v1/tokens/list", fields: ["clientId", "displayText", "scopes", "anonymous"] },
    { id: "login-activities", path: "/admin/reports/v1/activity/users/all/applications/login", service: "Admin SDK Reports API", documentationUrl: "https://developers.google.com/admin-sdk/reports/reference/rest/v1/activities/list", fields: ["id", "actor", "events", "ipAddress"] },
    { id: "admin-activities", path: "/admin/reports/v1/activity/users/all/applications/admin", service: "Admin SDK Reports API", documentationUrl: "https://developers.google.com/admin-sdk/reports/reference/rest/v1/activities/list", fields: ["id", "actor", "events", "ipAddress"] },
    { id: "token-activities", path: "/admin/reports/v1/activity/users/all/applications/token", service: "Admin SDK Reports API", documentationUrl: "https://developers.google.com/admin-sdk/reports/reference/rest/v1/activities/list", fields: ["id", "actor", "events", "ipAddress"] },
    { id: "alerts", path: "/v1beta1/alerts", service: "Alert Center API", documentationUrl: "https://developers.google.com/admin-sdk/alertcenter/reference/rest/v1beta1/alerts/list", fields: ["alertId", "type", "source", "createTime", "endTime", "metadata.status", "metadata.severity"] },
    { id: "two-step-policies", path: "/v1/policies", service: "Cloud Identity API", documentationUrl: "https://cloud.google.com/identity/docs/reference/rest/v1/policies/list", fields: ["name", "customer", "type", "policyQuery", "setting.value.enforcedFrom", "setting.value.allowEnrollment", "setting.value.allowedSignInFactorSet"] },
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
  pagination: [
    {
      surfaceIds: ["directory-users"], cursorFields: ["nextPageToken", "pageToken"], pageSize: 500, itemCap: 5000, pageCap: 1000,
      totalSemantics: "No total is returned; a missing nextPageToken before the 5,000-user cap proves exhaustion.",
      stopConditions: ["No nextPageToken", "5,000-user cap", "1,000-page cap", "Repeated token", "Empty page with token"],
    },
    {
      surfaceIds: ["roles"], cursorFields: ["nextPageToken", "pageToken"], pageSize: 100, itemCap: 1000, pageCap: 1000,
      totalSemantics: "No total is returned; completion requires a missing nextPageToken.", stopConditions: ["No nextPageToken", "1,000-role cap", "Page cap", "Repeated token", "Empty page with token"],
    },
    {
      surfaceIds: ["role-assignments"], cursorFields: ["nextPageToken", "pageToken"], pageSize: 200, itemCap: 10000, pageCap: 1000,
      totalSemantics: "No total is returned; completion requires a missing nextPageToken.", stopConditions: ["No nextPageToken", "10,000-assignment cap", "Page cap", "Repeated token", "Empty page with token"],
    },
    {
      surfaceIds: ["login-activities", "admin-activities", "token-activities"], cursorFields: ["nextPageToken", "pageToken"], pageSize: 1000, itemCap: 5000, pageCap: 1000,
      totalSemantics: "Reports omit a total; completion requires token exhaustion.", stopConditions: ["No nextPageToken", "5,000-record cap", "Page cap", "Repeated token", "Empty page with token"],
    },
    {
      surfaceIds: ["alerts", "two-step-policies"], cursorFields: ["nextPageToken", "pageToken"], pageSize: 100, itemCap: 1000, pageCap: 1000,
      totalSemantics: "No authoritative total is used; completion requires token exhaustion.", stopConditions: ["No nextPageToken", "1,000-item cap", "Page cap", "Repeated token", "Empty page with token"],
    },
    {
      surfaceIds: ["user-tokens"], cursorFields: [], pageSize: null, itemCap: 50, pageCap: null,
      totalSemantics: "tokens.list is a single request per user; only the first 50 users are queried and any skipped or failed user makes the aggregate inventory incomplete.",
      stopConditions: ["Single response", "50-user sampling cap", "Per-user denial or error"],
    },
  ],
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
  output: buildBatchOutputContract({
    files: [
      "core_data/users.json", "core_data/roles.json", "core_data/role_assignments.json", "core_data/login_activities.json",
      "core_data/admin_activities.json", "core_data/token_activities.json", "core_data/token_inventory.json", "core_data/alerts.json",
      "core_data/two_step_verification_policies.json", "analysis/findings.json", "analysis/identity.json", "analysis/identity.md",
      "analysis/admin_access.json", "analysis/admin_access.md", "analysis/integrations.json", "analysis/integrations.md",
      "analysis/monitoring.json", "analysis/monitoring.md", "compliance/executive_summary.md", "compliance/unified_compliance_matrix.md",
      "QUICK_REFERENCE.md",
    ],
    conditionalFiles: [
      "compliance/fedramp/fedramp_compliance_report.md", "compliance/cmmc/cmmc_compliance_report.md",
      "compliance/soc2/soc2_compliance_report.md", "compliance/cis/cis_compliance_report.md",
      "compliance/pci_dss/pci_dss_compliance_report.md", "compliance/disa_stig/stig_compliance_checklist.md",
      "compliance/irap/irap_compliance_report.md", "compliance/ismap/ismap_compliance_report.md", "_errors.log",
    ],
    conditionalFileConditions: {
      "compliance/fedramp/fedramp_compliance_report.md": "When the effective framework selection includes fedramp.",
      "compliance/cmmc/cmmc_compliance_report.md": "When the effective framework selection includes cmmc.",
      "compliance/soc2/soc2_compliance_report.md": "When the effective framework selection includes soc2.",
      "compliance/cis/cis_compliance_report.md": "When the effective framework selection includes cis.",
      "compliance/pci_dss/pci_dss_compliance_report.md": "When the effective framework selection includes pci_dss.",
      "compliance/disa_stig/stig_compliance_checklist.md": "When the effective framework selection includes disa_stig.",
      "compliance/irap/irap_compliance_report.md": "When the effective framework selection includes irap.",
      "compliance/ismap/ismap_compliance_report.md": "When the effective framework selection includes ismap.",
      "_errors.log": "When at least one collection error or truncation warning exists.",
    },
    overwritePolicy: "Allocate a new <organization>-gws-audit directory with a numeric suffix; never overwrite an existing directory or paired archive.",
    archivePairing: "Create <allocated-directory>.zip beside the allocated audit directory.",
  }),
});
