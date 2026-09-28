import {
  buildBatchIntegrationSpec,
  buildBatchOutputContract,
  deriveDecisionRules,
  type BatchCheckDefinition,
  type BatchCompletenessDefinition,
} from "./batch-spec-builder.js";
import { SALESFORCE_AUTH_RESOLVER } from "./auth-resolver-contracts.js";
import type { PortableValue, VerdictCondition, VerdictRule } from "./spec-model.js";

const SALESFORCE_SURFACES = [
  ["limits", "GET", "/services/data/v{version}/limits"], ["organization", "GET", "/services/data/v{version}/query?q=Organization"],
  ["health-check", "GET", "/services/data/v{version}/tooling/query?q=SecurityHealthCheck"],
  ["health-check-risks", "GET", "/services/data/v{version}/tooling/query?q=SecurityHealthCheckRisks"],
  ["security-settings", "POST", "/services/Soap/m/{version} readMetadata(SecuritySettings)"],
  ["my-domain-settings", "POST", "/services/Soap/m/{version} readMetadata(MyDomainSettings)"],
  ["users", "GET", "/services/data/v{version}/query?q=User"], ["profiles", "GET", "/services/data/v{version}/query?q=Profile"],
  ["profile-metadata", "POST", "/services/Soap/m/{version} listMetadata(Profile)+readMetadata(Profile)"],
  ["permission-sets", "GET", "/services/data/v{version}/query?q=PermissionSet"],
  ["permission-set-assignments", "GET", "/services/data/v{version}/query?q=PermissionSetAssignment"],
  ["two-factor-methods", "GET", "/services/data/v{version}/query?q=TwoFactorMethodsInfo"],
  ["field-permissions", "GET", "/services/data/v{version}/query?q=FieldPermissions"],
  ["tenant-secrets", "GET", "/services/data/v{version}/query?q=TenantSecret"],
  ["certificates", "GET", "/services/data/v{version}/tooling/query?q=Certificate"],
  ["connected-applications", "GET", "/services/data/v{version}/query?q=ConnectedApplication"],
  ["oauth-tokens", "GET", "/services/data/v{version}/query?q=OauthToken"],
  ["caller-permissions", "GET", "/services/data/v{version}/query?q=UserPermissionAccess"],
  ["login-history", "GET", "/services/data/v{version}/query?q=LoginHistory"],
  ["setup-audit-trail", "GET", "/services/data/v{version}/query?q=SetupAuditTrail"],
  ["event-log-files", "GET", "/services/data/v{version}/query?q=EventLogFile"],
].map(([id, method, path]) => ({ id, method: method as "GET" | "POST", path, service: path.includes("Soap") ? "Salesforce Metadata API" : path.includes("tooling") ? "Salesforce Tooling API" : "Salesforce REST API", documentationUrl: "https://developer.salesforce.com/docs/platform/", fields: ["selected fields named in the runtime SOQL or Metadata API request"] }));

const SALESFORCE_CHECK_SURFACES: Readonly<Record<number, readonly string[]>> = {
  1: ["health-check", "health-check-risks"], 2: ["security-settings"], 3: ["security-settings"], 4: ["security-settings", "health-check-risks", "users", "profiles", "two-factor-methods"],
  5: ["security-settings", "profiles", "profile-metadata"], 6: ["profiles", "profile-metadata"], 7: ["users", "profiles"],
  8: ["field-permissions"], 9: ["users", "profiles", "permission-sets", "permission-set-assignments"], 10: ["users", "profiles"],
  11: ["connected-applications", "oauth-tokens"], 12: ["organization"], 13: ["users", "profiles"],
  14: ["login-history"], 15: ["setup-audit-trail", "event-log-files"], 16: ["tenant-secrets"],
  17: ["certificates"], 18: ["my-domain-settings"], 19: ["security-settings"], 20: ["security-settings"],
};

const ALL_FAILURE_MODES = ["truncated", "error", "denied", "not-collected"] as const;
const TRUNCATION_ONLY = ["truncated"] as const;
const completeFrom = (
  sourceIds: readonly string[],
  semantics: string,
  falseWhen: readonly ("truncated" | "error" | "denied" | "not-collected")[] = ALL_FAILURE_MODES,
): BatchCompletenessDefinition => ({
  sources: sourceIds.map((surfaceId) => ({ surfaceId, falseWhen })),
  semantics,
});
const SALESFORCE_COMPLETENESS: Readonly<Record<string, Readonly<Record<string, BatchCompletenessDefinition>>>> = {
  "SF-01": { risks_complete: completeFrom(["health-check-risks"], "true only when the Health Check risk query is readable and completely paged; the summary score query does not contribute.") },
  "SF-04": { enrollment_complete: completeFrom(["users", "two-factor-methods"], "true only when both users and TwoFactorMethodsInfo are readable and completely paged; profiles, SecuritySettings, and Health Check risk reads do not contribute.") },
  "SF-05": { profile_complete: completeFrom(["profile-metadata"], "true only when at least one sensitive profile metadata record resolves, none remains unresolved, and the metadata listing is untruncated; profile-query truncation and SecuritySettings state do not contribute.") },
  "SF-06": { complete: completeFrom(["profile-metadata"], "true only when at least one sensitive profile metadata record resolves, none remains unresolved, and the metadata listing is untruncated; profile-query truncation, error, or denial does not itself change this fact.") },
  "SF-07": { complete: completeFrom(["users", "profiles"], "true when both user and profile inventories are untruncated; errors, denials, and not-collected states are handled by separate population-readability facts and do not themselves change this fact.", TRUNCATION_ONLY) },
  "SF-08": { complete: completeFrom(["field-permissions"], "true only when FieldPermissions is readable and completely paged.") },
  "SF-09": {
    complete: {
      sources: [
        { surfaceId: "permission-sets", falseWhen: TRUNCATION_ONLY },
        { surfaceId: "permission-set-assignments", falseWhen: ALL_FAILURE_MODES },
      ],
      semantics: "true when the PermissionSet inventory is untruncated and, only if at least one elevated set exists, PermissionSetAssignment is readable and untruncated; assignment failure modes do not change this fact when no elevated set exists, and users and profiles never contribute.",
    },
  },
  "SF-10": { complete: completeFrom(["users", "profiles"], "true when both user and profile inventories are untruncated; errors, denials, and not-collected states are handled by separate population-readability facts and do not themselves change this fact.", TRUNCATION_ONLY) },
  "SF-13": { users_complete: completeFrom(["users"], "true when the user inventory is untruncated; errors, denials, and not-collected states are handled by `users_readable` and do not themselves change this fact.", TRUNCATION_ONLY) },
  "SF-14": { complete: completeFrom(["login-history"], "true only when LoginHistory is readable and completely paged.") },
  "SF-15": { audit_complete: completeFrom(["setup-audit-trail"], "true only when SetupAuditTrail is readable and completely paged; EventLogFile readability is a separate fact and does not contribute.") },
  "SF-16": { complete: completeFrom(["tenant-secrets"], "true only when TenantSecret is readable and completely paged.") },
  "SF-17": { complete: completeFrom(["certificates"], "true only when the certificate inventory is readable and completely paged.") },
};

const titles = [
  "Health Check score", "Session timeout", "Password policy", "MFA enforcement", "IP range restrictions",
  "Login hour restrictions", "API access controls", "Field-level security", "Permission set review",
  "Profile permissions", "Connected app OAuth policies", "Sharing settings", "Guest user access",
  "Login forensics", "Setup change tracking", "Data encryption status", "Certificate management",
  "My Domain enforcement", "Clickjack protection", "CSRF protection",
] as const;
const platform = new Set([1, 2, 3, 5, 18, 19, 20]);
const identity = new Set([4, 6, 7, 9, 10, 13]);
const protection = new Set([8, 12, 16, 17]);
const ownerFor = (control: number): string => platform.has(control)
  ? "salesforce_assess_platform_security"
  : identity.has(control)
    ? "salesforce_assess_identity_access"
    : protection.has(control)
      ? "salesforce_assess_data_protection"
      : "salesforce_assess_monitoring_integrations";
const decisions = [
  "return pass for a Health Check score of at least 90, warn from 70 through 89, fail below 70, and manual when SecurityHealthCheck exposes no score.",
  "return pass when session timeout is at most 120 minutes, forced logout is enabled, and sessions are locked to the originating IP; warn when only the IP lock is missing, fail for an excessive timeout or disabled forced logout, and manual for absent values.",
  "evaluate minimum length 12, strongest complexity, expiration at most 90 days, and history at least five; return pass with no gap, warn with one gap, fail with two or more gaps, and manual when a required field is absent.",
  "return fail when direct-UI MFA is not required or more than 25 percent of visible active standard users lack a registered method, warn for a smaller unenrolled population or partial reads, and pass when complete evidence shows MFA required and every user enrolled.",
  "return pass when every sensitive profile has login IP ranges, per-request enforcement is enabled, and an org-wide trusted range exists; fail when none exists at either level, and warn or manual for mixed, unresolved, or unreadable coverage.",
  "return pass when every sensitive profile restricts login hours every day, fail when none does, and warn when only some do or profile resolution is incomplete.",
  "return pass when no visible active user is assigned a profile with API Enabled, warn when such users are below the configured ratio or evidence is partial, and fail when the configured excessive-access threshold is crossed.",
  "return fail when any sensitive-name field is broadly readable by more than five profile or permission-set grants, warn for narrower grants or partial rows, pass when complete evidence finds classified fields with no readable grants, and manual when no field matches the classification patterns.",
  "return pass when no permission set grants elevated permissions, warn when elevated sets are assigned within the configured administrator threshold or evidence is partial, fail above the threshold, and manual when the standard inventory is implausibly empty.",
  "return fail when active administrator-profile users exceed the configured maximum, warn for stale, undated, or partial administrator evidence, and pass when the complete recent population is within the maximum.",
  "return fail when more than half of connected apps allow user self-authorization, warn for a smaller open set or when visible policies require pre-approval because scopes remain unreadable, and manual when no app or no policy flag is visible.",
  "return fail when at least three standard objects have public organization-wide defaults, warn for one or two public defaults or for private defaults whose custom objects and sharing rules remain manual, and manual when no default-access field is exposed.",
  "return fail when any active guest user has API Enabled or elevated data permissions, warn when other active guests exist or coverage is partial, and pass when a complete user inventory has no active guest.",
  "return fail for severe login forensics such as a failure ratio above the configured threshold, repeated-source failures, or legacy TLS, warn for lesser anomalies, undated rows, or partial reads, and pass when the complete non-empty window has none.",
  "return pass when complete setup-audit and Event Monitoring evidence is readable and no collection gap exists, warn for high-risk changes or partial or absent EventLogFile evidence, and manual when the active-org audit window is unreadable or implausibly empty.",
  "return fail when a readable complete TenantSecret inventory has no active key, warn when active keys are undated, older than 365 days, or partial, pass for complete recent active keys, and manual when Shield encryption is unavailable or scoped out.",
  "return fail when any certificate is expired or has a key under 2048 bits, warn for near expiry, missing dates, exportable private keys, pending chains, or partial evidence, pass when all certificates are valid and managed, and manual when none is returned.",
  "return fail when My Domain is absent or still permits login.salesforce.com, pass when it is enforced for UI and API login, warn when API login is not restricted, and manual when the enforcement flag is absent.",
  "return pass when all four setup, non-setup, Visualforce-with-header, and Visualforce-without-header clickjack flags are enabled, fail when at least two are disabled, warn when one is disabled, and manual when flags are absent.",
  "return pass when CSRF protection is enabled for both GET and POST, fail when either is disabled, and manual when either flag is absent.",
] as const;

interface SalesforceExecutableDecision { inputs: Readonly<Record<string, string>>; rules: readonly VerdictRule[] }
const value = (entry: PortableValue) => ({ kind: "value" as const, value: entry });
const path = (name: string) => ({ kind: "path" as const, path: name });
const cmp = (op: "eq" | "ne" | "gt" | "gte" | "lt" | "lte", name: string, entry: PortableValue): VerdictCondition => ({ op, left: path(name), right: value(entry) });
const eq = (name: string, entry: PortableValue) => cmp("eq", name, entry);
const ne = (name: string, entry: PortableValue) => cmp("ne", name, entry);
const gt = (name: string, entry: PortableValue) => cmp("gt", name, entry);
const gte = (name: string, entry: PortableValue) => cmp("gte", name, entry);
const lte = (name: string, entry: PortableValue) => cmp("lte", name, entry);
const defined = (name: string): VerdictCondition => ({ op: "defined", operand: path(name) });
const not = (condition: VerdictCondition): VerdictCondition => ({ op: "not", condition });
const all = (...conditions: VerdictCondition[]): VerdictCondition => ({ op: "and", conditions });
const any = (...conditions: VerdictCondition[]): VerdictCondition => ({ op: "or", conditions });
const rule = (status: VerdictRule["status"], condition: VerdictCondition): VerdictRule => ({ status, condition });
const input = (...names: string[]) => Object.fromEntries(names.map((name) => {
  const counts: Readonly<Record<string, string>> = {
    high_risk_count: "high-risk records", gap_count: "required settings missing the secure value", user_count: "users", profile_count: "profiles",
    admin_profile_count: "administrator-equivalent profiles", admin_count: "active administrator-equivalent users", active_standard_user_count: "active standard users",
    unenrolled_count: "active standard users without two-factor enrollment", resolved_profile_count: "profiles with resolved metadata",
    profiles_with_ranges_count: "profiles with login IP ranges", org_range_count: "organization trusted IP ranges", fully_restricted_count: "admin profiles restricted every day",
    partially_restricted_count: "partially restricted admin profiles", api_profile_count: "admin-equivalent profiles granting API access",
    sensitive_field_count: "fields classified sensitive", broad_field_count: "sensitive fields readable broadly", set_count: "permission sets",
    elevated_set_count: "administrator-equivalent permission sets", assignee_count: "active users assigned elevated sets", stale_admin_count: "stale administrators",
    undated_admin_count: "administrators without last login", app_count: "connected applications", unknown_policy_count: "apps with unknown OAuth policy",
    open_app_count: "apps allowing unrestricted self-authorization", default_field_count: "sharing defaults", open_default_count: "public or read/write sharing defaults",
    active_guest_count: "active guest users", risky_guest_count: "privileged or stale guest users", login_count: "login-history records",
    failed_count: "failed logins", brute_force_source_count: "source IPs meeting repeated-failure threshold", legacy_tls_count: "legacy-TLS logins",
    country_count: "distinct login countries", undated_count: "records without timestamps", audit_count: "setup audit records", secret_count: "secret-bearing principals",
    active_count: "active records", undated_active_count: "active secret records without dates", certificate_count: "certificates", failure_count: "certificates in failure window",
    warning_count: "certificates in warning window",
  };
  const booleans: Readonly<Record<string, string>> = {
    readable: "the required query or metadata response was returned", complete: "defined by this check's structured completeness contract",
    health_readable: "Security Health Check summary was returned", score_present: "Health Check contains a numeric score", risks_readable: "Health Check risks were returned",
    risks_complete: "all risk pages completed", settings_readable: "required organization settings were returned", required_fields_present: "every required settings field exists",
    force_logout: "sessions force logout on timeout", lock_to_ip: "sessions are locked to originating IP", security_settings_readable: "security settings were returned",
    mfa_required: "organization settings require MFA", mfa_risk_present: "Health Check contains an MFA risk", two_factor_methods_readable: "two-factor enrollment was returned",
    users_readable: "users were returned", profiles_readable: "profiles were returned", enrollment_complete: "enrollment was established for every active standard user",
    health_check_risks_readable: "MFA fallback risk evidence was readable", profile_metadata_readable: "profile metadata was returned", profile_complete: "all required profile metadata resolved",
    enforce_every_request: "IP ranges are enforced on every request", sets_readable: "permission sets were returned", assignments_readable: "permission-set assignments were returned",
    users_complete: "all user pages completed", audit_readable: "setup audit trail was returned", audit_complete: "audit trail covered the lookback",
    event_log_readable: "event-log files were returned", has_my_domain: "My Domain is configured",
    can_only_login_with_my_domain_url_present: "exclusive My Domain login field exists", prevent_legacy_login: "legacy login hosts are disabled",
    require_domain_for_api: "API logins require My Domain", get_enabled: "GET CSRF protection is enabled", post_enabled: "POST CSRF protection is enabled",
  };
  const raw: Readonly<Record<string, string>> = {
    score: "Numeric Security Health Check score.", timeout_minutes: "Configured session timeout in minutes.", mfa_risk_type: "Raw normalized MFA risk type.",
    max_admins: "Maximum accepted administrator population.", oldest_active_age_days: "Age in whole days of the oldest active secret.",
  };
  const definition = counts[name] ? `Non-negative cardinality of ${counts[name]} in the complete Salesforce inventory at the verdict point.`
    : booleans[name] ? `Boolean true exactly when ${booleans[name]}.` : raw[name];
  if (!definition) throw new Error(`Salesforce primitive ${name} lacks an explicit portable definition`);
  return [name, definition];
}));
const inputWith = (
  overrides: Readonly<Record<string, string>>,
  ...names: string[]
): Readonly<Record<string, string>> => Object.fromEntries(
  names.map((name) => [name, overrides[name] ?? input(name)[name]]),
);
const populationUnavailable = any(
  ne("users_readable", true),
  ne("profiles_readable", true),
  eq("user_count", 0),
  eq("profile_count", 0),
  eq("admin_profile_count", 0),
  eq("admin_count", 0),
);

const SALESFORCE_EXECUTABLE_DECISIONS: Readonly<Record<string, SalesforceExecutableDecision>> = {
  "SF-01": {
    inputs: input("health_readable", "score_present", "risks_readable", "risks_complete", "score", "high_risk_count"),
    rules: [
      rule("manual", any(ne("health_readable", true), ne("score_present", true), ne("risks_readable", true))),
      rule("pass", all(gte("score", 90), eq("high_risk_count", 0), eq("risks_complete", true))),
      rule("warn", gte("score", 70)),
      rule("fail", { op: "always" }),
    ],
  },
  "SF-02": {
    inputs: input("settings_readable", "required_fields_present", "timeout_minutes", "force_logout", "lock_to_ip"),
    rules: [
      rule("manual", any(ne("settings_readable", true), ne("required_fields_present", true))),
      rule("pass", all(lte("timeout_minutes", 120), eq("force_logout", true), eq("lock_to_ip", true))),
      rule("warn", all(lte("timeout_minutes", 120), eq("force_logout", true))),
      rule("fail", { op: "always" }),
    ],
  },
  "SF-03": {
    inputs: input("settings_readable", "required_fields_present", "gap_count"),
    rules: [rule("manual", any(ne("settings_readable", true), ne("required_fields_present", true))), rule("pass", eq("gap_count", 0)), rule("warn", eq("gap_count", 1)), rule("fail", { op: "always" })],
  },
  "SF-04": {
    inputs: input("security_settings_readable", "mfa_required", "mfa_risk_present", "mfa_risk_type", "two_factor_methods_readable", "users_readable", "profiles_readable", "user_count", "profile_count", "admin_profile_count", "admin_count", "active_standard_user_count", "unenrolled_count", "enrollment_complete", "health_check_risks_readable"),
    rules: [
      rule("manual", all(ne("security_settings_readable", true), ne("mfa_risk_present", true))),
      rule("fail", any(eq("mfa_required", false), all(eq("mfa_risk_present", true), ne("mfa_risk_type", "MEETS_STANDARD")))),
      rule("manual", all(ne("mfa_required", true), ne("mfa_risk_type", "MEETS_STANDARD"))),
      rule("manual", any(ne("two_factor_methods_readable", true), populationUnavailable, eq("active_standard_user_count", 0))),
      rule("fail", all(eq("enrollment_complete", true), {
        op: "ratio",
        numerator: path("unenrolled_count"),
        denominator: path("active_standard_user_count"),
        comparator: "gt",
        threshold: value(0.25),
      })),
      rule("warn", any(gt("unenrolled_count", 0), ne("enrollment_complete", true), ne("security_settings_readable", true), ne("health_check_risks_readable", true))),
      rule("pass", { op: "always" }),
    ],
  },
  "SF-05": {
    inputs: input("settings_readable", "profiles_readable", "profile_count", "admin_profile_count", "profile_metadata_readable", "resolved_profile_count", "profiles_with_ranges_count", "org_range_count", "profile_complete", "enforce_every_request"),
    rules: [
      rule("manual", any(ne("settings_readable", true), ne("profiles_readable", true), eq("profile_count", 0), eq("admin_profile_count", 0), ne("profile_metadata_readable", true), eq("resolved_profile_count", 0))),
      rule("fail", all(eq("profiles_with_ranges_count", 0), eq("org_range_count", 0))),
      rule("pass", all({ op: "eq", left: path("profiles_with_ranges_count"), right: path("resolved_profile_count") }, eq("profile_complete", true), eq("enforce_every_request", true))),
      rule("warn", { op: "always" }),
    ],
  },
  "SF-06": {
    inputs: input("profiles_readable", "profile_count", "admin_profile_count", "profile_metadata_readable", "resolved_profile_count", "fully_restricted_count", "partially_restricted_count", "complete"),
    rules: [
      rule("manual", any(ne("profiles_readable", true), eq("profile_count", 0), eq("admin_profile_count", 0), ne("profile_metadata_readable", true), eq("resolved_profile_count", 0))),
      rule("pass", all({ op: "eq", left: path("fully_restricted_count"), right: path("resolved_profile_count") }, eq("complete", true))),
      rule("fail", all(eq("fully_restricted_count", 0), eq("partially_restricted_count", 0))),
      rule("warn", { op: "always" }),
    ],
  },
  "SF-07": {
    inputs: input("users_readable", "profiles_readable", "user_count", "profile_count", "admin_profile_count", "admin_count", "complete", "api_profile_count"),
    rules: [
      rule("manual", populationUnavailable),
      rule("warn", ne("complete", true)),
      rule("fail", { op: "ratio", numerator: path("api_profile_count"), denominator: path("profile_count"), comparator: "gt", threshold: value(0.5) }),
      rule("warn", { op: "ratio", numerator: path("api_profile_count"), denominator: path("profile_count"), comparator: "gt", threshold: value(0.25) }),
      rule("pass", { op: "always" }),
    ],
  },
  "SF-08": {
    inputs: input("readable", "complete", "sensitive_field_count", "broad_field_count"),
    rules: [rule("manual", any(ne("readable", true), eq("sensitive_field_count", 0))), rule("warn", gt("broad_field_count", 0)), rule("warn", ne("complete", true)), rule("pass", { op: "always" })],
  },
  "SF-09": {
    inputs: input("sets_readable", "users_readable", "profiles_readable", "user_count", "profile_count", "admin_profile_count", "admin_count", "set_count", "elevated_set_count", "assignments_readable", "complete", "assignee_count", "max_admins"),
    rules: [
      rule("manual", any(ne("sets_readable", true), populationUnavailable, eq("set_count", 0))),
      rule("warn", all(eq("elevated_set_count", 0), ne("assignments_readable", true))),
      rule("warn", all(eq("elevated_set_count", 0), ne("complete", true))),
      rule("pass", eq("elevated_set_count", 0)),
      rule("manual", ne("assignments_readable", true)),
      rule("fail", { op: "gt", left: path("assignee_count"), right: path("max_admins") }),
      rule("warn", gt("assignee_count", 0)),
      rule("warn", ne("complete", true)),
      rule("pass", { op: "always" }),
    ],
  },
  "SF-10": {
    inputs: input("users_readable", "profiles_readable", "user_count", "profile_count", "admin_profile_count", "admin_count", "complete", "max_admins", "stale_admin_count", "undated_admin_count"),
    rules: [rule("manual", populationUnavailable), rule("fail", any({ op: "gt", left: path("admin_count"), right: path("max_admins") }, gt("stale_admin_count", 0))), rule("warn", any(gt("undated_admin_count", 0), ne("complete", true))), rule("pass", { op: "always" })],
  },
  "SF-11": {
    inputs: input("readable", "app_count", "unknown_policy_count", "open_app_count"),
    rules: [
      rule("manual", any(ne("readable", true), eq("app_count", 0), { op: "eq", left: path("unknown_policy_count"), right: path("app_count") })),
      rule("fail", { op: "ratio", numerator: path("open_app_count"), denominator: path("app_count"), comparator: "gt", threshold: value(0.5) }),
      rule("warn", { op: "always" }),
    ],
  },
  "SF-12": {
    inputs: input("readable", "default_field_count", "open_default_count"),
    rules: [rule("manual", any(ne("readable", true), eq("default_field_count", 0))), rule("fail", gte("open_default_count", 3)), rule("warn", { op: "always" })],
  },
  "SF-13": {
    inputs: input("users_readable", "profiles_readable", "user_count", "profile_count", "admin_profile_count", "admin_count", "users_complete", "active_guest_count", "risky_guest_count"),
    rules: [rule("manual", populationUnavailable), rule("warn", ne("users_complete", true)), rule("pass", eq("active_guest_count", 0)), rule("fail", gt("risky_guest_count", 0)), rule("warn", { op: "always" })],
  },
  "SF-14": {
    inputs: input("readable", "login_count", "complete", "failed_count", "brute_force_source_count", "legacy_tls_count", "country_count", "undated_count"),
    rules: [
      rule("manual", any(ne("readable", true), eq("login_count", 0))),
      rule("warn", ne("complete", true)),
      rule("fail", any(
        gt("brute_force_source_count", 0),
        gt("legacy_tls_count", 0),
        { op: "ratio", numerator: path("failed_count"), denominator: path("login_count"), comparator: "gt", threshold: value(0.25) },
      )),
      rule("warn", any(
        { op: "ratio", numerator: path("failed_count"), denominator: path("login_count"), comparator: "gt", threshold: value(0.1) },
        gt("country_count", 5),
        gt("undated_count", 0),
      )),
      rule("pass", { op: "always" }),
    ],
  },
  "SF-15": {
    inputs: input("audit_readable", "audit_count", "audit_complete", "high_risk_count", "undated_count", "event_log_readable"),
    rules: [rule("manual", any(ne("audit_readable", true), eq("audit_count", 0))), rule("warn", any(ne("audit_complete", true), gt("high_risk_count", 0), gt("undated_count", 0), ne("event_log_readable", true))), rule("pass", { op: "always" })],
  },
  "SF-16": {
    inputs: input("readable", "complete", "secret_count", "active_count", "undated_active_count", "oldest_active_age_days"),
    rules: [
      rule("manual", ne("readable", true)),
      rule("manual", all(eq("secret_count", 0), ne("complete", true))),
      rule("fail", any(eq("secret_count", 0), eq("active_count", 0))),
      rule("warn", any(gt("undated_active_count", 0), gt("oldest_active_age_days", 365), ne("complete", true))),
      rule("pass", { op: "always" }),
    ],
  },
  "SF-17": {
    inputs: input("readable", "complete", "certificate_count", "failure_count", "warning_count"),
    rules: [rule("manual", any(ne("readable", true), eq("certificate_count", 0))), rule("fail", gt("failure_count", 0)), rule("warn", any(gt("warning_count", 0), ne("complete", true))), rule("pass", { op: "always" })],
  },
  "SF-18": {
    inputs: input("readable", "has_my_domain", "can_only_login_with_my_domain_url_present", "prevent_legacy_login", "require_domain_for_api"),
    rules: [rule("manual", ne("readable", true)), rule("fail", ne("has_my_domain", true)), rule("manual", ne("can_only_login_with_my_domain_url_present", true)), rule("pass", all(eq("prevent_legacy_login", true), eq("require_domain_for_api", true))), rule("warn", eq("prevent_legacy_login", true)), rule("fail", { op: "always" })],
  },
  "SF-19": {
    inputs: inputWith({
      setup_flag: "Raw nullable boolean from SecuritySettings `sessionSettings.enableClickjackSetup`, which controls clickjack protection for setup pages.",
      nonsetup_sfdc_flag: "Raw nullable boolean from SecuritySettings `sessionSettings.enableClickjackNonsetupSFDC`, which controls clickjack protection for non-setup Salesforce pages.",
      nonsetup_user_flag: "Raw nullable boolean from SecuritySettings `sessionSettings.enableClickjackNonsetupUser`, which controls clickjack protection for Visualforce pages with standard headers.",
      nonsetup_user_headerless_flag: "Raw nullable boolean from SecuritySettings `sessionSettings.enableClickjackNonsetupUserHeaderless`, which controls clickjack protection for Visualforce pages without standard headers.",
      disabled_count: "Non-negative cardinality of the four SF-19 clickjack-protection flags whose raw normalized value is explicitly false; absent or unparseable flags are not counted as disabled.",
    }, "settings_readable", "setup_flag", "nonsetup_sfdc_flag", "nonsetup_user_flag", "nonsetup_user_headerless_flag", "disabled_count"),
    rules: [
      rule("manual", ne("settings_readable", true)),
      rule("pass", all(eq("setup_flag", true), eq("nonsetup_sfdc_flag", true), eq("nonsetup_user_flag", true), eq("nonsetup_user_headerless_flag", true))),
      rule("fail", gte("disabled_count", 2)),
      rule("warn", eq("disabled_count", 1)),
      rule("manual", any(not(defined("setup_flag")), not(defined("nonsetup_sfdc_flag")), not(defined("nonsetup_user_flag")), not(defined("nonsetup_user_headerless_flag")))),
      rule("manual", { op: "always" }),
    ],
  },
  "SF-20": {
    inputs: input("settings_readable", "get_enabled", "post_enabled"),
    rules: [
      rule("manual", ne("settings_readable", true)),
      rule("pass", all(eq("get_enabled", true), eq("post_enabled", true))),
      rule("fail", any(eq("get_enabled", false), eq("post_enabled", false))),
      rule("manual", { op: "always" }),
    ],
  },
};

const checks: BatchCheckDefinition[] = titles.map((title, index) => {
  const control = index + 1;
  const id = `SF-${String(control).padStart(2, "0")}`;
  const decision = SALESFORCE_EXECUTABLE_DECISIONS[id];
  const executable = deriveDecisionRules(id, decision.rules);
  return {
    id,
    control,
    title,
    severity: [4].includes(control) ? "critical" : [3, 5, 6, 9, 10, 11, 12, 16, 17].includes(control) ? "high" : "medium",
    owner: ownerFor(control),
    surfaces: SALESFORCE_CHECK_SURFACES[control],
    evidenceFields: [...SALESFORCE_CHECK_SURFACES[control], "complete_source_counts"],
    decisionInputs: decision.inputs,
    decisionRules: executable.rules,
    derivedFactRules: executable.derivedFactRules,
    completeness: SALESFORCE_COMPLETENESS[id],
    decision: decisions[index],
  };
});
const idsFor = (owner: string): string[] => checks.filter((check) => check.owner === owner).map((check) => check.id);

export const SALESFORCE_RUNTIME_BEHAVIOR = [
  "REST, Tooling SOQL, and synchronous Metadata API reads retain separate permission and pagination states; one readable surface does not substitute for another denied dependency.",
  "Profile and user verdicts require population sanity gates: zero standard users, unresolved sensitive profiles, row caps, or partial profile metadata cannot pass.",
  "SOQL nextRecordsUrl values are followed only on the configured Salesforce instance origin without user information; rejected links stop truncated.",
] as const;

export const SALESFORCE_SPEC = buildBatchIntegrationSpec({
  slug: "salesforce-sec-inspector",
  displayName: "Salesforce Security Inspector",
  vendor: "Salesforce",
  category: "crm-and-business-applications",
  summary: "Portable contract for the shipped Salesforce platform, identity, data-protection, and monitoring assessments.",
  sourceModule: "cli/extensions/grc-tools/salesforce.ts",
  baseServices: ["Salesforce REST API", "Salesforce Tooling API", "Salesforce Metadata API"],
  authentication: SALESFORCE_AUTH_RESOLVER,
  permissions: [
    { id: "api-enabled", kind: "role", value: "API Enabled", unlocks: SALESFORCE_SURFACES.filter((surface) => surface.service !== "Salesforce Metadata API").map((surface) => surface.id) },
    { id: "view-setup", kind: "role", value: "View Setup and Configuration", unlocks: ["organization", "users", "profiles", "permission-sets", "permission-set-assignments", "field-permissions", "tenant-secrets", "certificates", "connected-applications", "oauth-tokens", "caller-permissions", "setup-audit-trail"] },
    { id: "view-health-check", kind: "role", value: "View Health Check", unlocks: ["health-check", "health-check-risks"] },
    { id: "manage-mfa-api", kind: "role", value: "Manage Multi-Factor Authentication in API", unlocks: ["two-factor-methods"] },
    { id: "metadata-api-read", kind: "role", value: "Modify Metadata Through Metadata API Functions", unlocks: ["security-settings", "my-domain-settings", "profile-metadata"], notes: "The runtime performs only readMetadata and listMetadata calls." },
    { id: "event-monitoring", kind: "license", value: "Event Monitoring plus View Event Log Files", unlocks: ["event-log-files"] },
  ],
  surfaces: SALESFORCE_SURFACES,
  checks,
  tools: {
    salesforce_check_access: [],
    salesforce_assess_platform_security: idsFor("salesforce_assess_platform_security"),
    salesforce_assess_identity_access: idsFor("salesforce_assess_identity_access"),
    salesforce_assess_data_protection: idsFor("salesforce_assess_data_protection"),
    salesforce_assess_monitoring_integrations: idsFor("salesforce_assess_monitoring_integrations"),
    salesforce_export_audit_bundle: checks.map((check) => check.id),
  },
  pagination: [{
    surfaceIds: SALESFORCE_SURFACES.filter((surface) => surface.path.includes("query?q=")).map((surface) => surface.id),
    cursorFields: ["nextRecordsUrl", "done", "totalSize"],
    pageSize: null,
    itemCap: 2000,
    pageCap: null,
    totalSemantics: "totalSize is authoritative when present; done=true and seen equal total prove completion.",
    stopConditions: ["done true with matching total", "Configured row cap", "Repeated nextRecordsUrl", "Empty page with continuation", "Missing or larger total", "Rejected cross-origin or user-information cursor"],
  }],
  rateLimit: {
    documentedLimit: "Organization edition and license determine daily and concurrent API limits",
    retryHeaders: ["Sforce-Limit-Info", "Retry-After"],
    retryableStatuses: [429, 500, 502, 503, 504],
    backoffPolicy: "Use bounded Retry-After and exponential retry; preserve REQUEST_LIMIT_EXCEEDED as unreadable evidence.",
  },
  runtimeBehavior: SALESFORCE_RUNTIME_BEHAVIOR,
  knownGaps: ["Interactive authorization code flow, geolocation baselines, and several policy surfaces are not read."],
  sensitiveFields: ["password", "securityToken", "consumerSecret", "privateKey", "refreshToken", "accessToken", "authorization", "sessionId"],
  credentialFormats: ["Salesforce OAuth access and refresh tokens", "security tokens", "private keys", "signed JWT assertions", "SOAP session IDs"],
  output: buildBatchOutputContract({
    files: [
      "metadata.json",
      "QUICK_REFERENCE.md",
      "core_data/access_check.json",
      "core_data/organization.json",
      "core_data/security_health_check.json",
      "core_data/security_health_check_risks.json",
      "core_data/security_settings.json",
      "core_data/my_domain_settings.json",
      "core_data/users.json",
      "core_data/profiles.json",
      "core_data/profile_metadata.json",
      "core_data/permission_sets.json",
      "core_data/permission_set_assignments.json",
      "core_data/two_factor_methods_info.json",
      "core_data/field_permissions_sensitive.json",
      "core_data/tenant_secrets.json",
      "core_data/certificates.json",
      "core_data/connected_applications.json",
      "core_data/oauth_tokens.json",
      "core_data/caller_permissions.json",
      "core_data/login_history.json",
      "core_data/setup_audit_trail.json",
      "core_data/event_log_files.json",
      "analysis/platform_security.json",
      "analysis/identity_access.json",
      "analysis/data_protection.json",
      "analysis/monitoring_integrations.json",
      "analysis/findings.json",
      "analysis/summary.json",
      "compliance/executive_summary.md",
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
    overwritePolicy: "Allocate a new {organization}-audit-bundle directory with a numeric suffix when needed; never overwrite a prior directory.",
    archivePairing: "Write a sibling zip named from the exact allocated bundle-directory basename plus .zip.",
  }),
});
