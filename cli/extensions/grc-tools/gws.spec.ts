import {
  buildBatchIntegrationSpec,
  buildBatchOutputContract,
  deriveDecisionRules,
  type BatchCheckDefinition,
} from "./batch-spec-builder.js";
import { GWS_AUTH_RESOLVER } from "./auth-resolver-contracts.js";
import type { PortableValue, VerdictCondition, VerdictRule } from "./spec-model.js";

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
    "return fail when dormant active users exceed the greater of two or five percent of active users, warn for a smaller non-zero dormant set, missing login dates, or partial evidence, and pass when complete evidence has neither.",
    "return pass when every super admin enforces 2-step verification, fail when any super admin does not, and demote pass to warn when directory or assignment evidence is partial.",
    "return pass when every returned enforcement policy has a past enforcedFrom date and enrollment is allowed, warn when only some scopes satisfy that state, fail when none do, and manual when the policy token or enforcement setting is unavailable.",
  ],
  ADMIN: [
    "return pass when the complete privileged inventory has at most four super admins, warn with five or six, and fail above six.",
    "return fail when any privileged user is suspended or archived and pass when none is, with partial evidence demoting pass to warn.",
    "return pass when at least one active delegated role assignment exists outside the Super Admin role, manual when none exists or role evidence is unavailable, and demote pass to warn when role evidence is partial.",
    "return pass when the complete admin-audit lookback contains activity, manual when it is empty, denied, or unreadable, and demote pass to warn when the read is truncated.",
    "always return manual when group-based role assignments exist because expanded group membership is not collected; return pass only when complete role-assignment evidence proves no group-based grant.",
  ],
  INTEG: [
    "return pass when every required per-user token read completes and at least one token is inventoried, warn when only some per-user reads succeed, and manual when the sample is absent, every read fails, or the readable inventory is empty.",
    "return fail when any privileged user has more than the configured token threshold, warn when any has a smaller non-zero exposure or reads are partial, and pass when complete reads show no excessive privileged exposure.",
    "return fail when any visible application grant contains a high-risk scope, warn when high-scope applications remain below the configured count or token evidence is partial, and pass when complete token evidence contains none.",
    "return pass when the complete token audit lookback contains at least one event, manual when it is empty or unreadable, and demote pass to warn when the read is truncated.",
  ],
  MON: [
    "return pass when Alert Center is readable and returns at least one alert, manual when the list is empty or unreadable, and demote pass to warn when the inventory is truncated.",
    "for a non-empty readable login-audit window, return fail above five suspicious-login signals, warn for one through five or partial evidence, and pass when complete evidence contains none.",
    "return pass when the admin-audit lookback contains events, manual when the window is empty or unreadable, and demote pass to warn when the read is truncated.",
    "return pass when the token-audit lookback contains events, manual when the window is empty or unreadable, and demote pass to warn when the read is truncated.",
    "for a non-empty readable alert inventory, return fail above ten open alerts, warn for four through ten, unknown statuses, or partial evidence, and pass with at most three open alerts.",
  ],
} as const;

interface GwsExecutableDecision {
  inputs: Readonly<Record<string, string>>;
  constants?: Readonly<Record<string, PortableValue>>;
  rules: readonly VerdictRule[];
}

const value = (entry: PortableValue) => ({ kind: "value" as const, value: entry });
const path = (name: string) => ({ kind: "path" as const, path: name });
const compare = (
  op: "eq" | "ne" | "gt" | "gte" | "lt" | "lte",
  name: string,
  entry: PortableValue,
): VerdictCondition => ({ op, left: path(name), right: value(entry) });
const eq = (name: string, entry: PortableValue): VerdictCondition => compare("eq", name, entry);
const ne = (name: string, entry: PortableValue): VerdictCondition => compare("ne", name, entry);
const gt = (name: string, entry: PortableValue): VerdictCondition => compare("gt", name, entry);
const lte = (name: string, entry: PortableValue): VerdictCondition => compare("lte", name, entry);
const ratio = (
  comparator: "gt" | "gte" | "lt" | "lte",
  numerator: string,
  denominator: string,
  threshold: number,
): VerdictCondition => ({
  op: "ratio",
  numerator: path(numerator),
  denominator: path(denominator),
  comparator,
  threshold: value(threshold),
});
const all = (...conditions: VerdictCondition[]): VerdictCondition => ({ op: "and", conditions });
const any = (...conditions: VerdictCondition[]): VerdictCondition => ({ op: "or", conditions });
const rule = (status: VerdictRule["status"], condition: VerdictCondition, note?: string): VerdictRule => ({
  status,
  condition,
  ...(note ? { note } : {}),
});
const ordered = (branches: {
  fail?: VerdictCondition;
  manual?: VerdictCondition;
  warn?: VerdictCondition;
  pass?: VerdictCondition;
}): readonly VerdictRule[] => [
  ...(branches.manual ? [rule("manual", branches.manual)] : []),
  ...(branches.fail ? [rule("fail", branches.fail)] : []),
  ...(branches.warn ? [rule("warn", branches.warn)] : []),
  ...(branches.pass ? [rule("pass", branches.pass)] : []),
  rule("manual", { op: "always" }, "Unknown or contradictory evidence requires manual review."),
];
const input = (...names: string[]): Readonly<Record<string, string>> => Object.fromEntries(
  names.map((name) => [name, `Runtime-owned ${name.replaceAll("_", " ")} computed from the complete declared source inventories.`]),
);
const unreadable = ne("readable", true);
const incomplete = ne("complete", true);

const GWS_EXECUTABLE_DECISIONS: Readonly<Record<string, GwsExecutableDecision>> = {
  "GWS-ID-001": {
    inputs: input("readable", "complete", "privileged_user_count", "two_step_required_user_count"),
    constants: { warning_minimum: 0.8, pass_minimum: 1 },
    rules: ordered({
      manual: any(unreadable, eq("privileged_user_count", 0)),
      fail: ratio("lt", "two_step_required_user_count", "privileged_user_count", 0.8),
      warn: any(incomplete, ratio("lt", "two_step_required_user_count", "privileged_user_count", 1)),
      pass: ratio("gte", "two_step_required_user_count", "privileged_user_count", 1),
    }),
  },
  "GWS-ID-002": {
    inputs: input("readable", "complete", "active_user_count", "two_step_required_user_count"),
    constants: { warning_minimum: 0.85, pass_minimum: 0.98 },
    rules: ordered({
      manual: any(unreadable, eq("active_user_count", 0)),
      fail: ratio("lt", "two_step_required_user_count", "active_user_count", 0.85),
      warn: any(incomplete, ratio("lt", "two_step_required_user_count", "active_user_count", 0.98)),
      pass: ratio("gte", "two_step_required_user_count", "active_user_count", 0.98),
    }),
  },
  "GWS-ID-003": {
    inputs: input("readable", "complete", "active_user_count", "dormant_user_count", "unknown_login_count"),
    constants: { dormant_days: 90, absolute_warning_maximum: 2, proportional_warning_maximum: 0.05 },
    rules: ordered({
      manual: any(unreadable, eq("active_user_count", 0)),
      fail: all(
        gt("dormant_user_count", 2),
        ratio("gt", "dormant_user_count", "active_user_count", 0.05),
      ),
      warn: any(incomplete, gt("dormant_user_count", 0), gt("unknown_login_count", 0)),
      pass: all(eq("dormant_user_count", 0), eq("unknown_login_count", 0)),
    }),
  },
  "GWS-ID-004": {
    inputs: input("readable", "complete", "super_admin_count", "super_admin_without_two_step_count"),
    rules: ordered({
      manual: any(unreadable, eq("super_admin_count", 0)),
      fail: gt("super_admin_without_two_step_count", 0),
      warn: incomplete,
      pass: eq("super_admin_without_two_step_count", 0),
    }),
  },
  "GWS-ID-005": {
    inputs: input("readable", "complete", "policy_count", "two_step_policy_count", "effective_policy_count", "policy_disallowing_enrollment_count"),
    rules: ordered({
      manual: any(unreadable, eq("two_step_policy_count", 0)),
      fail: eq("effective_policy_count", 0),
      warn: any(
        incomplete,
        { op: "lt", left: path("effective_policy_count"), right: path("two_step_policy_count") },
        gt("policy_disallowing_enrollment_count", 0),
      ),
      pass: all(
        { op: "eq", left: path("effective_policy_count"), right: path("two_step_policy_count") },
        eq("policy_disallowing_enrollment_count", 0),
      ),
    }),
  },
  "GWS-ADMIN-001": {
    inputs: input("readable", "complete", "super_admin_count"),
    constants: { pass_maximum: 4, warning_maximum: 6 },
    rules: ordered({
      manual: any(unreadable, eq("super_admin_count", 0)),
      fail: gt("super_admin_count", 6),
      warn: any(incomplete, gt("super_admin_count", 4)),
      pass: lte("super_admin_count", 4),
    }),
  },
  "GWS-ADMIN-002": {
    inputs: input("readable", "complete", "privileged_user_count", "suspended_privileged_count"),
    rules: ordered({
      manual: any(unreadable, eq("privileged_user_count", 0)),
      fail: gt("suspended_privileged_count", 0),
      warn: incomplete,
      pass: eq("suspended_privileged_count", 0),
    }),
  },
  "GWS-ADMIN-003": {
    inputs: input("readable", "complete", "delegated_admin_count"),
    rules: ordered({
      manual: any(unreadable, eq("delegated_admin_count", 0)),
      warn: incomplete,
      pass: gt("delegated_admin_count", 0),
    }),
  },
  "GWS-ADMIN-004": {
    inputs: input("readable", "complete", "event_count"),
    rules: ordered({
      manual: any(unreadable, eq("event_count", 0)),
      warn: incomplete,
      pass: gt("event_count", 0),
    }),
  },
  "GWS-ADMIN-005": {
    inputs: input("readable", "complete", "assignment_count", "group_assignment_count"),
    rules: ordered({
      manual: any(unreadable, eq("assignment_count", 0), gt("group_assignment_count", 0)),
      warn: incomplete,
      pass: eq("group_assignment_count", 0),
    }),
  },
  "GWS-INTEG-001": {
    inputs: input("users_readable", "complete", "sampled_user_count", "failed_read_count", "token_count"),
    rules: ordered({
      manual: any(
        ne("users_readable", true),
        eq("sampled_user_count", 0),
        { op: "eq", left: path("failed_read_count"), right: path("sampled_user_count") },
        eq("token_count", 0),
      ),
      warn: any(incomplete, gt("failed_read_count", 0)),
      pass: gt("token_count", 0),
    }),
  },
  "GWS-INTEG-002": {
    inputs: input("directory_readable", "complete", "privileged_user_count", "token_count", "failed_read_count", "privileged_token_count"),
    constants: { warning_maximum: 3 },
    rules: ordered({
      manual: any(
        ne("directory_readable", true),
        eq("privileged_user_count", 0),
        eq("token_count", 0),
        all(gt("failed_read_count", 0), eq("privileged_token_count", 0)),
      ),
      fail: gt("privileged_token_count", 3),
      warn: any(incomplete, gt("privileged_token_count", 0)),
      pass: eq("privileged_token_count", 0),
    }),
  },
  "GWS-INTEG-003": {
    inputs: input("users_readable", "complete", "token_count", "high_risk_token_count"),
    constants: { warning_maximum: 5 },
    rules: ordered({
      manual: any(ne("users_readable", true), eq("token_count", 0)),
      fail: gt("high_risk_token_count", 5),
      warn: any(incomplete, gt("high_risk_token_count", 0)),
      pass: eq("high_risk_token_count", 0),
    }),
  },
  "GWS-INTEG-004": {
    inputs: input("readable", "complete", "event_count"),
    rules: ordered({
      manual: any(unreadable, eq("event_count", 0)),
      warn: incomplete,
      pass: gt("event_count", 0),
    }),
  },
  "GWS-MON-001": {
    inputs: input("readable", "complete", "alert_count"),
    rules: ordered({
      manual: any(unreadable, eq("alert_count", 0)),
      warn: incomplete,
      pass: gt("alert_count", 0),
    }),
  },
  "GWS-MON-002": {
    inputs: input("readable", "complete", "event_count", "suspicious_login_count"),
    constants: { warning_maximum: 5 },
    rules: ordered({
      manual: any(unreadable, eq("event_count", 0)),
      fail: gt("suspicious_login_count", 5),
      warn: any(incomplete, gt("suspicious_login_count", 0)),
      pass: eq("suspicious_login_count", 0),
    }),
  },
  "GWS-MON-003": {
    inputs: input("readable", "complete", "event_count"),
    rules: ordered({
      manual: any(unreadable, eq("event_count", 0)),
      warn: incomplete,
      pass: gt("event_count", 0),
    }),
  },
  "GWS-MON-004": {
    inputs: input("readable", "complete", "event_count"),
    rules: ordered({
      manual: any(unreadable, eq("event_count", 0)),
      warn: incomplete,
      pass: gt("event_count", 0),
    }),
  },
  "GWS-MON-005": {
    inputs: input("readable", "complete", "alert_count", "open_alert_count", "alert_without_known_state_count"),
    constants: { pass_maximum: 3, warning_maximum: 10 },
    rules: ordered({
      manual: any(unreadable, eq("alert_count", 0)),
      fail: gt("open_alert_count", 10),
      warn: any(incomplete, gt("open_alert_count", 3), gt("alert_without_known_state_count", 0)),
      pass: lte("open_alert_count", 3),
    }),
  },
};

let control = 0;
const checks: BatchCheckDefinition[] = Object.entries(groups).flatMap(([key, titles]) => {
  const group = key as keyof typeof groups;
  return titles.map((title, index) => {
    const id = `GWS-${group}-${String(index + 1).padStart(3, "0")}`;
    const decision = GWS_EXECUTABLE_DECISIONS[id];
    const executable = deriveDecisionRules(id, decision.rules);
    return {
      id,
      control: ++control,
      title,
      severity: /Privileged|Super admin|2-step|Suspicious|Alert Center/i.test(title) ? "high" : "medium",
      owner: owners[group],
      surfaces: GWS_CHECK_SURFACES[id],
      evidenceFields: [...GWS_CHECK_SURFACES[id], "complete_source_counts"],
      decisionInputs: decision.inputs,
      decisionConstants: decision.constants,
      decisionRules: executable.rules,
      derivedFactRules: executable.derivedFactRules,
      decision: decisions[group][index],
    };
  });
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
  authentication: GWS_AUTH_RESOLVER,
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
