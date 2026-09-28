import { buildBatchIntegrationSpec, buildBatchOutputContract, type BatchCheckDefinition } from "./batch-spec-builder.js";
import type { PortableValue, VerdictCondition, VerdictRule } from "./spec-model.js";

const tableSurface = (id: string, table: string, fields: readonly string[]) => ({
  id,
  path: `/api/now/table/${table}`,
  service: "ServiceNow Table API",
  documentationUrl: "https://www.servicenow.com/docs/bundle/zurich-api-reference/page/integrate/inbound-rest/concept/c_TableAPI.html",
  fields,
});
const countSurface = (id: string, table: string) => ({
  id,
  path: `/api/now/stats/${table}`,
  service: "ServiceNow Aggregate API",
  documentationUrl: "https://www.servicenow.com/docs/bundle/zurich-api-reference/page/integrate/inbound-rest/concept/c_AggregateAPI.html",
  fields: ["result.stats.count"],
});
const SERVICENOW_SURFACES = [
  tableSurface("users", "sys_user", ["sys_id", "user_name", "active", "last_login_time", "web_service_access_only", "internal_integration_user", "enable_multifactor_authn", "sys_updated_on"]),
  tableSurface("privileged-assignments", "sys_user_has_role", ["sys_id", "user", "user.user_name", "user.active", "user.web_service_access_only", "user.internal_integration_user", "role", "role.name"]),
  tableSurface("role-inheritance", "sys_user_role_contains", ["sys_id", "role", "role.name", "contains", "contains.name"]),
  countSurface("role-inheritance-count", "sys_user_role_contains"),
  tableSurface("identity-properties", "sys_properties", ["sys_id", "name", "value", "description", "sys_updated_on"]),
  tableSurface("password-policies", "password_policy", ["sys_id", "name", "active", "minimum_password_length", "maximum_password_length", "strength", "sys_updated_on"]),
  tableSurface("sso-providers", "sso_properties", ["sys_id", "name", "active", "default", "auto_redirect_idp", "sys_updated_on"]),
  tableSurface("ldap-servers", "ldap_server_config", ["sys_id", "name", "active", "sys_updated_on"]),
  tableSurface("certificates", "sys_certificate", ["sys_id", "name", "active", "valid_from", "expires", "sys_updated_on"]),
  tableSurface("oauth-entities", "oauth_entity", ["sys_id", "name", "type", "active", "client_id", "sys_updated_on"]),
  tableSurface("mfa-criteria", "multi_factor_criteria", ["sys_id", "name", "active", "order", "roles", "multi_factor_roles", "sys_updated_on"]),
  tableSurface("hardening-properties", "sys_properties", ["sys_id", "name", "value", "description", "sys_updated_on"]),
  tableSurface("debug-properties", "sys_properties", ["sys_id", "name", "value", "description", "sys_updated_on"]),
  tableSurface("eval-scripts", "sys_script", ["sys_id", "name", "collection", "sys_updated_on"]),
  tableSurface("ip-access", "ip_access", ["sys_id", "type", "direction", "active", "range_start", "range_end", "description", "sys_updated_on"]),
  tableSurface("ip-authenticator-plugin", "sys_plugins", ["sys_id", "name", "source", "active", "state", "version", "sys_updated_on"]),
  tableSurface("email-accounts", "sys_email_account", ["sys_id", "name", "type", "active", "connection_security", "enable_ssl", "enable_tls", "authentication", "server", "port", "sys_updated_on"]),
  tableSurface("acls", "sys_security_acl", ["sys_id", "name", "operation", "type", "active", "admin_overrides", "condition-present", "script-present", "sys_updated_on"]),
  tableSurface("acl-roles", "sys_security_acl_role", ["sys_id", "sys_security_acl", "sys_user_role", "sys_user_role.name"]),
  countSurface("acl-count", "sys_security_acl"),
  tableSurface("public-pages", "sys_public", ["sys_id", "page", "active", "sys_updated_on"]),
  tableSurface("encryption-contexts", "sys_encryption_context", ["sys_id", "name", "type", "sys_updated_on"]),
  tableSurface("crypto-modules", "sys_kmf_crypto_module", ["sys_id", "name", "module_name", "state", "sys_scope", "sys_updated_on"]),
  tableSurface("encrypted-fields", "sys_dictionary", ["sys_id", "name", "element", "internal_type"]),
  tableSurface("audit-dictionary", "sys_dictionary", ["sys_id", "name", "audit", "attributes"]),
  countSurface("recent-audit-count", "sys_audit"),
  countSurface("recent-transaction-count", "syslog_transaction"),
  tableSurface("update-sets", "sys_update_set", ["sys_id", "name", "state", "application", "sys_created_by", "sys_updated_on"]),
  countSurface("update-set-count", "sys_update_set"),
  tableSurface("sensitive-update-xml", "sys_update_xml", ["sys_id", "name", "type", "target_name", "action", "update_set", "update_set.name", "sys_updated_on"]),
  tableSurface("mid-servers", "ecc_agent", ["sys_id", "name", "status", "validated", "version", "host_name", "sys_updated_on"]),
  tableSurface("mid-properties", "sys_properties", ["sys_id", "name", "value", "description", "sys_updated_on"]),
  tableSurface("plugins", "sys_plugins", ["sys_id", "name", "source", "active", "state", "version", "sys_updated_on"]),
] as const;

const SERVICENOW_CHECK_SURFACES: Readonly<Record<number, readonly string[]>> = {
  1: ["hardening-properties"],
  2: ["acls", "acl-roles", "acl-count", "public-pages"],
  3: ["role-inheritance", "role-inheritance-count"],
  4: ["users", "privileged-assignments"],
  5: ["hardening-properties"],
  6: ["identity-properties", "password-policies"],
  7: ["identity-properties", "users", "privileged-assignments", "mfa-criteria"],
  8: ["sso-providers", "ldap-servers", "identity-properties", "certificates"],
  9: ["encryption-contexts", "crypto-modules", "encrypted-fields"],
  10: ["audit-dictionary", "recent-audit-count", "recent-transaction-count"],
  11: ["acls", "acl-roles", "acl-count"],
  12: ["hardening-properties", "eval-scripts"],
  13: ["hardening-properties"],
  14: ["users", "privileged-assignments", "oauth-entities"],
  15: ["update-sets", "update-set-count", "sensitive-update-xml"],
  16: ["hardening-properties", "debug-properties"],
  17: ["hardening-properties", "ip-access", "ip-authenticator-plugin"],
  18: ["hardening-properties", "email-accounts"],
  19: ["mid-servers", "mid-properties"],
  20: ["plugins"],
};

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
  "return pass when an active SSO or LDAP integration is visible with enabled redirect policy and valid dated certificates, fail when complete evidence has no active external identity provider or an active certificate is expired, warn for weak redirect policy or near-expiry and undated certificates, and manual when integration evidence is unreadable or partial.",
  "return pass when an active customer encryption module or encrypted field evidence is visible, warn when only platform-default encryption is evident, fail when readable evidence explicitly disables encryption, and manual when the licensed encryption surface is unavailable.",
  "return pass when system auditing is enabled and the complete lookback contains records, warn when the readable window is empty or partial, fail when auditing is explicitly disabled, and manual when properties or audit rows are unavailable.",
  "return fail when any sensitive table has an active permissive ACL without role, condition, or script restrictions, warn for incomplete table or ACL evidence, and pass when every inspected sensitive table is explicitly protected.",
  "return fail when unrestricted server-side script execution is enabled, pass when the documented script restrictions are enabled, warn for mixed settings, and manual when the required properties are absent.",
  "return pass when all documented baseline hardening properties are secure, fail when any critical property is explicitly insecure, and warn when noncritical settings are weak or evidence is partial.",
  "return fail when an active integration user has administrator-equivalent roles, warn for broad non-admin roles, stale users, or partial assignments, and pass when complete evidence shows least-privileged integration identities.",
  "return pass when complete update-set evidence shows recent completed sets with no unresolved preview or commit errors, warn for in-progress, stale, failed, or partial sets, and manual when update-set tables are unavailable.",
  "return pass when debug and diagnostic properties are disabled, fail when any is enabled, warn when the property inventory is partial, and manual when no decisive debug property is readable.",
  "return pass when the complete IP access-control inventory contains active restrictive ranges, fail when an explicit allow-all rule exists, warn when no rule exists or coverage is partial, and manual when the table is unavailable.",
  "return pass when documented outbound email TLS and security properties are enabled, fail when TLS is explicitly disabled, warn for weaker optional settings, and manual when decisive properties are absent.",
  "return pass when every active MID Server is validated, recent, and uses a non-administrator service identity, fail for administrator identities or failed validation, warn for stale, down, or partial records, and manual when the MID inventory is unavailable.",
  "return fail when a complete plugin inventory is missing a required baseline security plugin or a visible required plugin is inactive, and manual when the inventory is empty, partial around a missing baseline plugin, or all required plugins are active because licensing and intended use cannot be inferred from the API.",
] as const;

interface ServicenowExecutableDecision { inputs: Readonly<Record<string, string>>; rules: readonly VerdictRule[] }
const value = (entry: PortableValue) => ({ kind: "value" as const, value: entry });
const path = (name: string) => ({ kind: "path" as const, path: name });
const cmp = (op: "eq" | "ne" | "gt" | "gte" | "lt" | "lte", name: string, entry: PortableValue): VerdictCondition => ({ op, left: path(name), right: value(entry) });
const eq = (name: string, entry: PortableValue) => cmp("eq", name, entry);
const ne = (name: string, entry: PortableValue) => cmp("ne", name, entry);
const gt = (name: string, entry: PortableValue) => cmp("gt", name, entry);
const all = (...conditions: VerdictCondition[]): VerdictCondition => ({ op: "and", conditions });
const any = (...conditions: VerdictCondition[]): VerdictCondition => ({ op: "or", conditions });
const rule = (status: VerdictRule["status"], condition: VerdictCondition): VerdictRule => ({ status, condition });
const input = (...names: string[]) => Object.fromEntries(names.map((name) => [name, `Runtime-owned ${name.replaceAll("_", " ")} derived from complete ServiceNow table and aggregate collector state before rendered evidence arrays are capped.`]));
const propertyDecision = (): ServicenowExecutableDecision => ({
  inputs: input("readable", "complete", "noncompliant_count", "absent_count"),
  rules: [rule("manual", ne("readable", true)), rule("fail", gt("noncompliant_count", 0)), rule("warn", any(gt("absent_count", 0), ne("complete", true))), rule("pass", { op: "always" })],
});
const manualDecision = (): ServicenowExecutableDecision => ({ inputs: {}, rules: [rule("manual", { op: "always" })] });

const SERVICENOW_EXECUTABLE_DECISIONS: Readonly<Record<string, ServicenowExecutableDecision>> = {
  "SNOW-01": propertyDecision(),
  "SNOW-02": {
    inputs: input("readable", "complete", "inventory_proven", "visible_acl_count", "unrestricted_count", "wildcard_count", "public_page_count"),
    rules: [rule("manual", any(ne("readable", true), ne("inventory_proven", true), eq("visible_acl_count", 0))), rule("fail", gt("unrestricted_count", 0)), rule("warn", any(gt("wildcard_count", 0), gt("public_page_count", 0), ne("complete", true))), rule("pass", { op: "always" })],
  },
  "SNOW-03": {
    inputs: input("readable", "complete", "inventory_proven", "inheriting_count"),
    rules: [rule("manual", any(ne("readable", true), ne("inventory_proven", true))), rule("warn", gt("inheriting_count", 0)), rule("warn", ne("complete", true)), rule("pass", { op: "always" })],
  },
  "SNOW-04": {
    inputs: input("readable", "complete", "user_count", "admin_assignment_count", "admin_count", "max_admins", "stale_admin_count", "warning_count"),
    rules: [rule("manual", any(ne("readable", true), eq("user_count", 0), eq("admin_assignment_count", 0))), rule("fail", any({ op: "gt", left: path("admin_count"), right: path("max_admins") }, gt("stale_admin_count", 0))), rule("warn", any(gt("warning_count", 0), ne("complete", true))), rule("pass", { op: "always" })],
  },
  "SNOW-05": {
    inputs: input("readable", "complete", "timeout_present", "timeout_valid", "rotate_disabled"),
    rules: [rule("manual", ne("readable", true)), rule("fail", all(eq("timeout_present", true), ne("timeout_valid", true))), rule("warn", any(ne("timeout_present", true), eq("rotate_disabled", true), ne("complete", true))), rule("pass", { op: "always" })],
  },
  "SNOW-06": {
    inputs: input("readable", "complete", "policy_enabled", "policy_count", "minimum_fields_readable", "weak_policy_count", "enablement_present"),
    rules: [
      rule("manual", ne("readable", true)),
      rule("fail", eq("policy_enabled", false)),
      rule("manual", all(eq("policy_count", 0), ne("complete", true))),
      rule("fail", eq("policy_count", 0)),
      rule("manual", ne("minimum_fields_readable", true)),
      rule("fail", gt("weak_policy_count", 0)),
      rule("warn", any(ne("enablement_present", true), ne("complete", true))),
      rule("pass", { op: "always" }),
    ],
  },
  "SNOW-07": {
    inputs: input("readable", "complete", "properties_complete", "platform_property_present", "platform_enabled", "criteria_count", "admin_count", "active_role_criteria_count", "role_enforced", "user_enforced", "email_otp_enabled"),
    rules: [
      rule("manual", ne("readable", true)),
      rule("manual", all(ne("platform_property_present", true), ne("properties_complete", true))),
      rule("fail", ne("platform_enabled", true)),
      rule("manual", any(eq("criteria_count", 0), eq("admin_count", 0))),
      rule("fail", all(eq("active_role_criteria_count", 0), ne("user_enforced", true))),
      rule("warn", any(eq("active_role_criteria_count", 0), all(ne("role_enforced", true), ne("user_enforced", true)), eq("email_otp_enabled", true), ne("complete", true))),
      rule("pass", { op: "always" }),
    ],
  },
  "SNOW-08": {
    inputs: input("readable", "complete", "providers_complete", "provider_count", "expired_certificate_count", "concern_count"),
    rules: [rule("manual", ne("readable", true)), rule("manual", all(eq("provider_count", 0), ne("providers_complete", true))), rule("fail", eq("provider_count", 0)), rule("fail", gt("expired_certificate_count", 0)), rule("warn", any(gt("concern_count", 0), ne("complete", true))), rule("pass", { op: "always" })],
  },
  "SNOW-09": manualDecision(),
  "SNOW-10": {
    inputs: input("readable", "unaudited_count", "missing_dictionary_count", "recent_audit_count_known", "recent_audit_count"),
    rules: [rule("manual", ne("readable", true)), rule("fail", gt("unaudited_count", 0)), rule("manual", gt("missing_dictionary_count", 0)), rule("fail", all(eq("recent_audit_count_known", true), eq("recent_audit_count", 0))), rule("manual", { op: "always" })],
  },
  "SNOW-11": {
    inputs: input("readable", "complete", "inventory_proven", "uncovered_table_count", "operation_gap_count"),
    rules: [rule("manual", any(ne("readable", true), ne("inventory_proven", true))), rule("manual", all(ne("complete", true), any(gt("uncovered_table_count", 0), gt("operation_gap_count", 0)))), rule("fail", gt("uncovered_table_count", 0)), rule("warn", gt("operation_gap_count", 0)), rule("warn", ne("complete", true)), rule("pass", { op: "always" })],
  },
  "SNOW-12": {
    inputs: input("readable", "complete", "noncompliant_count", "absent_count", "eval_rule_count"),
    rules: [rule("manual", ne("readable", true)), rule("fail", any(gt("eval_rule_count", 0), gt("noncompliant_count", 0))), rule("warn", any(gt("absent_count", 0), ne("complete", true))), rule("pass", { op: "always" })],
  },
  "SNOW-13": propertyDecision(),
  "SNOW-14": {
    inputs: input("readable", "complete", "integration_user_count", "admin_integration_count", "privileged_assignment_count"),
    rules: [rule("manual", ne("readable", true)), rule("fail", gt("admin_integration_count", 0)), rule("manual", eq("integration_user_count", 0)), rule("warn", any(gt("privileged_assignment_count", 0), ne("complete", true))), rule("pass", { op: "always" })],
  },
  "SNOW-15": {
    inputs: input("readable", "complete", "inventory_proven", "visibility_proven", "in_progress_count", "sensitive_change_count"),
    rules: [rule("manual", any(ne("readable", true), ne("inventory_proven", true), ne("visibility_proven", true))), rule("warn", any(gt("in_progress_count", 0), gt("sensitive_change_count", 0), ne("complete", true))), rule("pass", { op: "always" })],
  },
  "SNOW-16": {
    inputs: input("readable", "complete", "enabled_debug_count", "hardening_property_count"),
    rules: [rule("manual", ne("readable", true)), rule("fail", gt("enabled_debug_count", 0)), rule("manual", eq("hardening_property_count", 0)), rule("warn", ne("complete", true)), rule("pass", { op: "always" })],
  },
  "SNOW-17": {
    inputs: input("readable", "complete", "plugin_present", "plugin_inventory_complete", "plugin_active", "active_rule_count", "rule_inventory_complete", "table_available", "strict_enabled"),
    rules: [
      rule("manual", ne("readable", true)),
      rule("warn", all(ne("plugin_present", true), gt("active_rule_count", 0))),
      rule("manual", all(ne("plugin_present", true), ne("plugin_inventory_complete", true))),
      rule("fail", ne("plugin_active", true)),
      rule("manual", ne("table_available", true)),
      rule("manual", all(eq("active_rule_count", 0), ne("rule_inventory_complete", true))),
      rule("fail", eq("active_rule_count", 0)),
      rule("warn", any(ne("strict_enabled", true), ne("complete", true))),
      rule("pass", { op: "always" }),
    ],
  },
  "SNOW-18": {
    inputs: input("readable", "smtp_account_count", "insecure_count", "smtp_auth_disabled", "unverified_count", "starttls_count"),
    rules: [rule("manual", ne("readable", true)), rule("fail", any(gt("insecure_count", 0), eq("smtp_auth_disabled", true))), rule("manual", eq("smtp_account_count", 0)), rule("manual", gt("unverified_count", 0)), rule("warn", gt("starttls_count", 0)), rule("manual", { op: "always" })],
  },
  "SNOW-19": {
    inputs: input("readable", "server_count", "not_validated_count", "version_override_present"),
    rules: [rule("manual", any(ne("readable", true), eq("server_count", 0))), rule("fail", gt("not_validated_count", 0)), rule("warn", eq("version_override_present", true)), rule("manual", { op: "always" })],
  },
  "SNOW-20": {
    inputs: input("readable", "complete", "plugin_count", "observed_inactive_required_count", "missing_required_count"),
    rules: [rule("manual", any(ne("readable", true), eq("plugin_count", 0))), rule("fail", gt("observed_inactive_required_count", 0)), rule("manual", all(gt("missing_required_count", 0), ne("complete", true))), rule("fail", gt("missing_required_count", 0)), rule("manual", { op: "always" })],
  },
};

const checks: BatchCheckDefinition[] = titles.map((title, index) => {
  const control = index + 1;
  const id = `SNOW-${String(control).padStart(2, "0")}`;
  return {
    id,
    control,
    title,
    severity: control === 7 ? "critical" : [1, 2, 3, 4, 6, 8, 10, 11, 12, 13, 14].includes(control) ? "high" : "medium",
    owner: ownerFor(control),
    surfaces: SERVICENOW_CHECK_SURFACES[control],
    evidenceFields: [...SERVICENOW_CHECK_SURFACES[control], "complete_source_counts"],
    decisionInputs: SERVICENOW_EXECUTABLE_DECISIONS[id].inputs,
    decisionRules: SERVICENOW_EXECUTABLE_DECISIONS[id].rules,
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
    modes: ["Basic username and password", "OAuth client credentials or refresh token", "Explicit OAuth access token"],
    precedence: ["Explicit access token", "Explicit OAuth client credentials or refresh token", "Explicit Basic credentials", "Config file", "SERVICENOW_* environment variables"],
    environment: ["SERVICENOW_INSTANCE", "SERVICENOW_USERNAME", "SERVICENOW_PASSWORD", "SERVICENOW_CLIENT_ID", "SERVICENOW_CLIENT_SECRET", "SERVICENOW_ACCESS_TOKEN", "SERVICENOW_REFRESH_TOKEN"],
    configLocations: ["~/.servicenow-sec-inspector/config.yaml"],
    variants: ["Instance name or explicit HTTPS instance URL"],
    configFields: ["instanceUrl", "instanceName", "authMode", "username", "password", "clientId", "clientSecret", "accessToken", "refreshToken", "pageSize"],
    refreshRequest: "POST /oauth_token.do with client_credentials or refresh_token form fields.",
  },
  permissions: [
    { id: "table-read", kind: "role", value: "Table API read ACLs for every listed table", unlocks: SERVICENOW_SURFACES.filter((surface) => surface.service === "ServiceNow Table API").map((surface) => surface.id), notes: "The exact ServiceNow roles are instance-specific because table and field ACLs can be customized." },
    { id: "aggregate-read", kind: "role", value: "Aggregate API count ACLs matching the Table API population", unlocks: SERVICENOW_SURFACES.filter((surface) => surface.service === "ServiceNow Aggregate API").map((surface) => surface.id) },
    { id: "security-admin", kind: "role", value: "security_admin where protected security tables require elevation", unlocks: ["acls", "acl-roles", "acl-count"], notes: "Elevation does not replace each table's read ACL." },
  ],
  surfaces: SERVICENOW_SURFACES,
  checks,
  tools: {
    servicenow_check_access: [],
    servicenow_assess_identity_access: idsFor("servicenow_assess_identity_access"),
    servicenow_assess_platform_hardening: idsFor("servicenow_assess_platform_hardening"),
    servicenow_assess_access_control: idsFor("servicenow_assess_access_control"),
    servicenow_assess_operations_governance: idsFor("servicenow_assess_operations_governance"),
    servicenow_export_audit_bundle: checks.map((check) => check.id),
  },
  pagination: [{
    surfaceIds: SERVICENOW_SURFACES.filter((surface) => surface.service === "ServiceNow Table API").map((surface) => surface.id),
    cursorFields: ["sysparm_offset", "sysparm_limit", "X-Total-Count", "Link rel=next"],
    pageSize: 500,
    itemCap: 10000,
    pageCap: null,
    totalSemantics: "X-Total-Count or Aggregate count is authoritative; absent or mismatched totals prevent proven exhaustion.",
    stopConditions: ["Seen count reaches authoritative total", "Short page with authoritative completion", "Configured item cap", "Empty page before total", "Repeated offset", "Missing total", "Rejected next link"],
  }],
  rateLimit: {
    documentedLimit: "Instance and node configuration determine ServiceNow inbound REST limits",
    retryHeaders: ["Retry-After", "X-RateLimit-Limit", "X-RateLimit-Remaining"],
    retryableStatuses: [429, 500, 502, 503, 504],
    backoffPolicy: "Honor bounded Retry-After and retry transient reads three times; exhausted reads remain unavailable.",
  },
  runtimeBehavior: SERVICENOW_RUNTIME_BEHAVIOR,
  knownGaps: ["The configuration parser recognizes the legacy mtls selector only to reject it with an explicit unsupported-mode error; no mTLS transport is implemented.", "Several Instance Security Center, Scan, DKIM, adaptive MFA, MID mutual-authentication, and retention proofs remain manual."],
  sensitiveFields: ["password", "client_secret", "access_token", "refresh_token", "authorization", "cookie", "sysparm_query"],
  credentialFormats: ["ServiceNow passwords", "OAuth bearer and refresh tokens", "client secrets", "JSESSIONID cookies"],
  output: buildBatchOutputContract({
    files: [
      "metadata.json",
      "QUICK_REFERENCE.md",
      "core_data/access_check.json",
      "core_data/sys_user.json",
      "core_data/sys_user_has_role_privileged.json",
      "core_data/sys_user_role_contains.json",
      "core_data/sys_user_role_contains_count.json",
      "core_data/sys_properties_identity.json",
      "core_data/password_policy.json",
      "core_data/sso_properties.json",
      "core_data/ldap_server_config.json",
      "core_data/sys_certificate.json",
      "core_data/oauth_entity.json",
      "core_data/multi_factor_criteria.json",
      "core_data/sys_properties_hardening.json",
      "core_data/sys_properties_debug.json",
      "core_data/sys_script_eval.json",
      "core_data/ip_access.json",
      "core_data/sys_plugins_ip_authenticator.json",
      "core_data/sys_email_account.json",
      "core_data/sys_security_acl.json",
      "core_data/sys_security_acl_role.json",
      "core_data/sys_security_acl_count.json",
      "core_data/sys_public.json",
      "core_data/sys_encryption_context.json",
      "core_data/sys_kmf_crypto_module.json",
      "core_data/sys_dictionary_encrypted.json",
      "core_data/sys_dictionary_audit.json",
      "core_data/sys_audit_count.json",
      "core_data/syslog_transaction_count.json",
      "core_data/sys_update_set_in_progress.json",
      "core_data/sys_update_set_count.json",
      "core_data/sys_update_xml_sensitive.json",
      "core_data/ecc_agent.json",
      "core_data/sys_properties_mid.json",
      "core_data/sys_plugins.json",
      "analysis/identity_access.json",
      "analysis/platform_hardening.json",
      "analysis/access_control.json",
      "analysis/operations_governance.json",
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
    overwritePolicy: "Allocate a new {instance}-audit-bundle directory with a numeric suffix when needed; never overwrite a prior directory.",
    archivePairing: "Write a sibling zip named from the exact allocated bundle-directory basename plus .zip.",
  }),
});
