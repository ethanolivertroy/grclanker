import {
  buildBatchIntegrationSpec,
  buildBatchOutputContract,
  deriveDecisionRules,
  type BatchCheckDefinition,
  type BatchSurfaceDefinition,
} from "./batch-spec-builder.js";
import { OKTA_AUTH_RESOLVER } from "./auth-resolver-contracts.js";
import type { PortableValue, VerdictCondition, VerdictRule } from "./spec-model.js";

const OKTA_SURFACES: readonly BatchSurfaceDefinition[] = [
  { id: "sign-on-policies", path: "/api/v1/policies?type=OKTA_SIGN_ON", service: "Okta Management API", documentationUrl: "https://developer.okta.com/docs/api/openapi/okta-management/management/tag/Policy/", fields: ["id", "name", "type", "status", "conditions", "settings"] },
  { id: "sign-on-policy-rules", path: "/api/v1/policies/{policyId}/rules", service: "Okta Management API", documentationUrl: "https://developer.okta.com/docs/api/openapi/okta-management/management/tag/Policy/", fields: ["id", "name", "status", "conditions", "actions"] },
  { id: "password-policies", path: "/api/v1/policies?type=PASSWORD", service: "Okta Management API", documentationUrl: "https://developer.okta.com/docs/api/openapi/okta-management/management/tag/Policy/", fields: ["id", "name", "status", "settings.password"] },
  { id: "mfa-policies", path: "/api/v1/policies?type=MFA_ENROLL", service: "Okta Management API", documentationUrl: "https://developer.okta.com/docs/api/openapi/okta-management/management/tag/Policy/", fields: ["id", "name", "status", "settings", "conditions"] },
  { id: "access-policies", path: "/api/v1/policies?type=ACCESS_POLICY", service: "Okta Management API", documentationUrl: "https://developer.okta.com/docs/api/openapi/okta-management/management/tag/Policy/", fields: ["id", "name", "status", "conditions", "settings"] },
  { id: "access-policy-rules", path: "/api/v1/policies/{policyId}/rules", service: "Okta Management API", documentationUrl: "https://developer.okta.com/docs/api/openapi/okta-management/management/tag/Policy/", fields: ["id", "name", "status", "conditions", "actions"] },
  { id: "authenticators", path: "/api/v1/authenticators", service: "Okta Management API", documentationUrl: "https://developer.okta.com/docs/api/openapi/okta-management/management/tag/Authenticator/", fields: ["id", "key", "name", "type", "status", "settings"] },
  { id: "idps", path: "/api/v1/idps", service: "Okta Management API", documentationUrl: "https://developer.okta.com/docs/api/openapi/okta-management/management/tag/IdentityProvider/", fields: ["id", "name", "type", "status", "protocol"] },
  { id: "authorization-servers", path: "/api/v1/authorizationServers", service: "Okta Management API", documentationUrl: "https://developer.okta.com/docs/api/openapi/okta-management/management/tag/AuthorizationServer/", fields: ["id", "name", "issuer", "status", "audiences"] },
  { id: "default-authorization-server", path: "/api/v1/authorizationServers/default", service: "Okta Management API", documentationUrl: "https://developer.okta.com/docs/api/openapi/okta-management/management/tag/AuthorizationServer/", fields: ["id", "issuer", "audiences"] },
  { id: "org-factors", path: "/api/v1/org/factors", service: "Okta Management API", documentationUrl: "https://developer.okta.com/docs/reference/api/factors/", fields: ["id", "factorType", "provider", "status"] },
  { id: "users", path: "/api/v1/users", service: "Okta Management API", documentationUrl: "https://developer.okta.com/docs/api/openapi/okta-management/management/tag/User/", fields: ["id", "status", "created", "lastLogin", "profile.login", "profile.email"] },
  { id: "role-assignees", path: "/api/v1/iam/assignees/users", service: "Okta Management API", documentationUrl: "https://developer.okta.com/docs/api/openapi/okta-management/management/tag/RoleAssignmentAUser/", fields: ["id", "status", "profile.login", "lastLogin"] },
  { id: "user-roles", path: "/api/v1/users/{userId}/roles", service: "Okta Management API", documentationUrl: "https://developer.okta.com/docs/api/openapi/okta-management/management/tag/RoleAssignmentAUser/", fields: ["id", "type", "label", "status"] },
  { id: "user-factors", path: "/api/v1/users/{userId}/factors", service: "Okta Management API", documentationUrl: "https://developer.okta.com/docs/reference/api/factors/", fields: ["id", "factorType", "provider", "status"] },
  { id: "groups", path: "/api/v1/groups", service: "Okta Management API", documentationUrl: "https://developer.okta.com/docs/api/openapi/okta-management/management/tag/Group/", fields: ["id", "type", "profile.name"] },
  { id: "group-roles", path: "/api/v1/groups/{groupId}/roles", service: "Okta Management API", documentationUrl: "https://developer.okta.com/docs/api/openapi/okta-management/management/tag/RoleAssignmentAGroup/", fields: ["id", "type", "label"] },
  { id: "group-members", path: "/api/v1/groups/{groupId}/users", service: "Okta Management API", documentationUrl: "https://developer.okta.com/docs/api/openapi/okta-management/management/tag/Group/", fields: ["id", "status", "profile.login"] },
  { id: "okta-support", path: "/api/v1/org/privacy/oktaSupport", service: "Okta Management API", documentationUrl: "https://developer.okta.com/docs/api/openapi/okta-management/management/tag/OrgSetting/", fields: ["support", "expiration"] },
  { id: "third-party-admin", path: "/api/v1/org/orgSettings/thirdPartyAdminSetting", service: "Okta Management API", documentationUrl: "https://developer.okta.com/docs/api/openapi/okta-management/management/tag/OrgSetting/", fields: ["thirdPartyAdmin"] },
  { id: "apps", path: "/api/v1/apps", service: "Okta Management API", documentationUrl: "https://developer.okta.com/docs/api/openapi/okta-management/management/tag/Application/", fields: ["id", "name", "label", "status", "settings", "credentials", "features"] },
  { id: "trusted-origins", path: "/api/v1/trustedOrigins", service: "Okta Management API", documentationUrl: "https://developer.okta.com/docs/api/openapi/okta-management/management/tag/TrustedOrigin/", fields: ["id", "name", "origin", "status", "scopes"] },
  { id: "network-zones", path: "/api/v1/zones", service: "Okta Management API", documentationUrl: "https://developer.okta.com/docs/api/openapi/okta-management/management/tag/NetworkZone/", fields: ["id", "name", "type", "status", "system"] },
  { id: "group-rules", path: "/api/v1/groups/rules", service: "Okta Management API", documentationUrl: "https://developer.okta.com/docs/api/openapi/okta-management/management/tag/GroupRule/", fields: ["id", "name", "status", "conditions", "actions"] },
  { id: "event-hooks", path: "/api/v1/eventHooks", service: "Okta Management API", documentationUrl: "https://developer.okta.com/docs/api/openapi/okta-management/management/tag/EventHook/", fields: ["id", "name", "status", "events"] },
  { id: "log-streams", path: "/api/v1/logStreams", service: "Okta Management API", documentationUrl: "https://developer.okta.com/docs/api/openapi/okta-management/management/tag/LogStream/", fields: ["id", "name", "type", "status"] },
  { id: "system-log", path: "/api/v1/logs", service: "Okta Management API", documentationUrl: "https://developer.okta.com/docs/api/openapi/okta-management/management/tag/SystemLog/", fields: ["uuid", "published", "eventType", "severity", "outcome"] },
  { id: "behaviors", path: "/api/v1/behaviors", service: "Okta Management API", documentationUrl: "https://developer.okta.com/docs/api/openapi/okta-management/management/tag/BehaviorRule/", fields: ["id", "name", "type", "status", "settings"] },
  { id: "threat-insight", path: "/api/v1/threats/configuration", service: "Okta Management API", documentationUrl: "https://developer.okta.com/docs/api/openapi/okta-management/management/tag/ThreatInsight/", fields: ["action", "mode", "settings", "excludeZones"] },
  { id: "api-tokens", path: "/api/v1/api-tokens", service: "Okta Management API", documentationUrl: "https://developer.okta.com/docs/api/openapi/okta-management/management/tag/ApiToken/", fields: ["id", "name", "created", "lastUpdated", "expiresAt", "network", "userId"] },
  { id: "device-assurance", path: "/api/v1/device-assurances", service: "Okta Management API", documentationUrl: "https://developer.okta.com/docs/api/openapi/okta-management/management/tag/DeviceAssurance/", fields: ["id", "name", "platform", "status"] },
  { id: "org-contacts", path: "/api/v1/org/contacts", service: "Okta Management API", documentationUrl: "https://developer.okta.com/docs/api/openapi/okta-management/management/tag/OrgSetting/", fields: ["contactType", "userId"] },
] as const;

const OKTA_CHECK_SURFACES: Readonly<Record<string, readonly string[]>> = {
  "OKTA-AUTH-001": ["authenticators", "org-factors"],
  "OKTA-AUTH-002": ["sign-on-policies", "sign-on-policy-rules", "access-policies", "access-policy-rules", "authenticators", "mfa-policies"],
  "OKTA-AUTH-003": ["password-policies"],
  "OKTA-AUTH-004": ["password-policies"],
  "OKTA-AUTH-005": ["password-policies"],
  "OKTA-AUTH-006": ["sign-on-policies", "sign-on-policy-rules"],
  "OKTA-AUTH-007": ["sign-on-policies", "sign-on-policy-rules"],
  "OKTA-AUTH-008": ["idps", "authenticators"],
  "OKTA-AUTH-009": ["authenticators", "org-factors"],
  "OKTA-ADMIN-001": ["role-assignees", "user-roles"],
  "OKTA-ADMIN-002": ["role-assignees", "user-roles"],
  "OKTA-ADMIN-003": ["groups", "group-roles", "group-members"],
  "OKTA-ADMIN-004": ["role-assignees", "user-factors"],
  "OKTA-ADMIN-005": ["users"],
  "OKTA-ADMIN-006": ["okta-support", "third-party-admin"],
  "OKTA-INTEG-001": ["trusted-origins"],
  "OKTA-INTEG-002": ["network-zones"],
  "OKTA-INTEG-003": ["apps"],
  "OKTA-INTEG-004": ["sign-on-policies", "sign-on-policy-rules", "access-policies", "access-policy-rules", "network-zones"],
  "OKTA-INTEG-005": ["apps"],
  "OKTA-INTEG-006": ["apps", "group-rules"],
  "OKTA-MON-001": ["event-hooks", "log-streams"],
  "OKTA-MON-002": ["system-log"],
  "OKTA-MON-003": ["threat-insight"],
  "OKTA-MON-004": ["behaviors"],
  "OKTA-MON-005": ["api-tokens"],
  "OKTA-MON-006": ["device-assurance"],
  "OKTA-MON-007": ["api-tokens"],
  "OKTA-MON-008": ["org-contacts", "users"],
  "OKTA-MON-009": [],
};

const titles: Readonly<Record<string, string>> = {
  "OKTA-AUTH-001": "Phishing-resistant authenticators",
  "OKTA-AUTH-002": "Administrator MFA enforcement",
  "OKTA-AUTH-003": "Password complexity",
  "OKTA-AUTH-004": "Password aging and history",
  "OKTA-AUTH-005": "Password lockout threshold",
  "OKTA-AUTH-006": "Session idle timeout",
  "OKTA-AUTH-007": "Session lifetime and persistent cookie controls",
  "OKTA-AUTH-008": "Certificate or PIV/CAC authentication",
  "OKTA-AUTH-009": "FIPS and restricted authenticator posture",
  "OKTA-ADMIN-001": "Super admin assignments are constrained",
  "OKTA-ADMIN-002": "Inactive privileged accounts",
  "OKTA-ADMIN-003": "Privileged group assignments are bounded",
  "OKTA-ADMIN-004": "Privileged user MFA enrollment",
  "OKTA-ADMIN-005": "Workforce account lifecycle hygiene",
  "OKTA-ADMIN-006": "Okta Support access and third-party admin governance",
  "OKTA-INTEG-001": "Trusted origins hygiene",
  "OKTA-INTEG-002": "Network zones are configured",
  "OKTA-INTEG-003": "OIDC application grant hygiene",
  "OKTA-INTEG-004": "Risk-based and contextual access controls",
  "OKTA-INTEG-005": "Application inventory hygiene",
  "OKTA-INTEG-006": "Provisioning and deprovisioning automation",
  "OKTA-MON-001": "Log offloading and external monitoring",
  "OKTA-MON-002": "System log visibility",
  "OKTA-MON-003": "ThreatInsight posture",
  "OKTA-MON-004": "Behavior detection coverage",
  "OKTA-MON-005": "API token hygiene",
  "OKTA-MON-006": "Device assurance policy coverage",
  "OKTA-MON-007": "API token expiry and network restrictions",
  "OKTA-MON-008": "Security contact routing",
  "OKTA-MON-009": "Administrator security notification emails",
};

const decisions: Readonly<Record<string, string>> = {
  "OKTA-AUTH-001": "return pass when any ACTIVE authenticator is WebAuthn, FIDO2, smart card, certificate, PIV, or CAC, warn when another strong authenticator exists, and fail when a complete non-Classic inventory has none.",
  "OKTA-AUTH-002": "return pass when an ACTIVE Admin Console or Dashboard policy has an ACTIVE MFA rule, a strong authenticator exists, and all policy reads completed; warn for partial evidence or MFA controls without an explicit admin rule; fail when complete evidence shows none.",
  "OKTA-AUTH-003": "across ACTIVE password policies, return pass when every policy has minimum length 12 and requires upper, lower, number, and symbol, warn when only some do, and fail when none do or no policy is ACTIVE.",
  "OKTA-AUTH-004": "across ACTIVE password policies, return pass when every policy has maximum age from 1 through 90 days and history at least five, warn when only some do, and fail when none do or no policy is ACTIVE.",
  "OKTA-AUTH-005": "across ACTIVE password policies, return pass when every policy locks after one through six attempts, warn when only some do, and fail when none do or no policy is ACTIVE.",
  "OKTA-AUTH-006": "return pass when every ACTIVE sign-on rule with an idle value is at most 15 minutes, fail when any exceeds 15, manual when none exposes the value, and warn instead of pass when rule reads are partial.",
  "OKTA-AUTH-007": "return pass when every ACTIVE sign-on rule lifetime is at most 1080 minutes and no rule enables persistent cookies, fail when either condition is violated, manual when neither value is exposed, and warn instead of pass when rule reads are partial.",
  "OKTA-AUTH-008": "return pass when any ACTIVE certificate-oriented IdP or authenticator exists and both inventories are readable, warn when one exists but the other inventory is unreadable, fail when none exists on a federal-domain tenant, and manual when none exists commercially.",
  "OKTA-AUTH-009": "for federal domains, return pass only when ACTIVE Okta Verify requires FIPS and no restricted authenticator is active, fail for a restricted authenticator or non-required FIPS, and warn when Okta Verify is absent; commercially, warn for restricted authenticators and pass otherwise.",
  "OKTA-ADMIN-001": "for a non-empty privileged-user inventory, return pass with at most two SUPER_ADMIN users, warn with three through five, and fail above five.",
  "OKTA-ADMIN-002": "return fail when any privileged account is non-ACTIVE or last signed in over 90 days ago, warn when any lacks a last-login date, and pass otherwise.",
  "OKTA-ADMIN-003": "for detected admin-like groups, return pass when every expanded privileged group has at most 25 members, warn when any exceeds 25 or expansion is partial, and manual when no group matches the discovery pattern.",
  "OKTA-ADMIN-004": "return fail when any inspected privileged user has no ACTIVE factor, warn when every inspected user has a factor but any lacks a phishing-resistant one, and pass when every privileged user has an ACTIVE phishing-resistant factor.",
  "OKTA-ADMIN-005": "return fail when any ACTIVE user has not signed in for over 90 days or any STAGED or PROVISIONED user is older than 30 days, warn for missing last-login or suspended, locked, expired, recovery, or partial users, and pass otherwise.",
  "OKTA-ADMIN-006": "return pass only when Okta Support access is DISABLED, thirdPartyAdmin is false, and both reads complete; return warn for every other readable state and manual when support access is unavailable.",
  "OKTA-INTEG-001": "return fail when any ACTIVE trusted origin uses HTTP or a wildcard, pass when at least one ACTIVE origin exists and none is insecure, info when the complete inventory has no ACTIVE origin because origins are optional, and manual when the inventory is unreadable.",
  "OKTA-INTEG-002": "return pass when at least one ACTIVE non-system, non-LegacyIpZone custom zone exists, warn when a non-empty complete zone inventory has none, and manual when the zone inventory is empty or unreadable.",
  "OKTA-INTEG-003": "return fail when any ACTIVE OIDC app uses password or implicit grants, warn when only inactive apps retain those grants, and pass when no app does.",
  "OKTA-INTEG-004": "return pass when any ACTIVE sign-on or access rule uses risk, device, behavior, or network context, warn when custom zones exist without such a rule or reads are partial, and fail when complete evidence has neither.",
  "OKTA-INTEG-005": "return pass when every application is ACTIVE, warn when any application is inactive or restricted, and manual when the app inventory is empty or unreadable.",
  "OKTA-INTEG-006": "return pass when any ACTIVE provisioning app has PUSH_USER_DEACTIVATION, fail when provisioning exists but none pushes deactivation, warn when no provisioning feature is visible or group rules are partial, and manual when apps are unavailable.",
  "OKTA-MON-001": "return pass when any ACTIVE log stream exists, warn when only ACTIVE event hooks exist or a pass has partial companion evidence, and fail when complete evidence has neither.",
  "OKTA-MON-002": "return pass when the complete lookback contains at least one System Log event, warn when the window is empty or truncated, and manual when the log read fails.",
  "OKTA-MON-003": "return pass for ThreatInsight block mode, warn for audit or log_only, fail for another readable mode, and manual when the feature object is unavailable.",
  "OKTA-MON-004": "return pass when any behavior rule is ACTIVE and warn when a complete behavior inventory has no active rule.",
  "OKTA-MON-005": "return pass when every listed SSWS token has a usable reference date no older than 90 days, warn for stale or undated tokens, manual for an empty SSWS-authenticated inventory, and pass for an empty OAuth-authenticated inventory.",
  "OKTA-MON-006": "return pass when at least one device assurance policy exists and warn when the complete readable inventory is empty.",
  "OKTA-MON-007": "return fail when any listed token is expired, warn when any is not zone-restricted, lacks a valid expiry, or has an inactivity window over 30 days, and pass otherwise, including an empty OAuth-authenticated inventory.",
  "OKTA-MON-008": "return pass when TECHNICAL contact resolves to an ACTIVE user, fail when missing, unassigned, or non-ACTIVE, warn when status or lookup is unknown, and manual when the contact inventory itself is empty or unreadable.",
  "OKTA-MON-009": "always return manual because administrator security-notification email preferences have no Management API read surface.",
};

interface OktaExecutableDecision {
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
const comparePaths = (op: "eq" | "ne" | "gt" | "gte" | "lt" | "lte", left: string, right: string): VerdictCondition => ({
  op,
  left: path(left),
  right: path(right),
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
  info?: VerdictCondition;
  manual?: VerdictCondition;
  warn?: VerdictCondition;
  pass?: VerdictCondition;
  failFirst?: boolean;
}): readonly VerdictRule[] => [
  ...(branches.failFirst && branches.fail ? [rule("fail", branches.fail, "A proven violation retains precedence over incomplete companion evidence.")] : []),
  ...(branches.manual ? [rule("manual", branches.manual)] : []),
  ...(!branches.failFirst && branches.fail ? [rule("fail", branches.fail)] : []),
  ...(branches.warn ? [rule("warn", branches.warn)] : []),
  ...(branches.info ? [rule("info", branches.info)] : []),
  ...(branches.pass ? [rule("pass", branches.pass)] : []),
  rule("manual", { op: "always" }, "Unknown or contradictory evidence requires manual review."),
];
const input = (...names: string[]): Readonly<Record<string, string>> => Object.fromEntries(
  names.map((name) => [name, `Runtime-owned ${name.replaceAll("_", " ")} computed from the complete declared source inventories.`]),
);
const unavailable = any(ne("readable", true), { op: "not", condition: { op: "defined", operand: path("readable") } });
const incomplete = ne("complete", true);

const OKTA_EXECUTABLE_DECISIONS: Readonly<Record<string, OktaExecutableDecision>> = {
  "OKTA-AUTH-001": {
    inputs: input("readable", "complete", "classic_engine", "authenticator_count", "phishing_resistant_count", "strong_count"),
    rules: ordered({
      manual: any(unavailable, eq("classic_engine", true)),
      fail: any(eq("authenticator_count", 0), all(eq("phishing_resistant_count", 0), eq("strong_count", 0))),
      warn: any(incomplete, all(eq("phishing_resistant_count", 0), gt("strong_count", 0))),
      pass: gt("phishing_resistant_count", 0),
    }),
  },
  "OKTA-AUTH-002": {
    inputs: input("policy_inventory_readable", "complete", "admin_policy_count", "admin_mfa_rule_count", "strong_authenticator_count", "mfa_control_count"),
    rules: ordered({
      manual: ne("policy_inventory_readable", true),
      fail: all(eq("admin_policy_count", 0), eq("mfa_control_count", 0), eq("strong_authenticator_count", 0)),
      warn: any(incomplete, eq("admin_mfa_rule_count", 0), eq("strong_authenticator_count", 0)),
      pass: all(gt("admin_policy_count", 0), gt("admin_mfa_rule_count", 0), gt("strong_authenticator_count", 0)),
    }),
  },
  "OKTA-AUTH-003": {
    inputs: input("readable", "complete", "inventory_count", "policy_count", "gap_count"),
    rules: ordered({
      manual: any(unavailable, eq("inventory_count", 0)),
      fail: comparePaths("eq", "gap_count", "policy_count"),
      warn: any(incomplete, gt("gap_count", 0)),
      pass: eq("gap_count", 0),
    }),
  },
  "OKTA-AUTH-004": {
    inputs: input("readable", "complete", "inventory_count", "policy_count", "gap_count"),
    rules: ordered({
      manual: any(unavailable, eq("inventory_count", 0)),
      fail: comparePaths("eq", "gap_count", "policy_count"),
      warn: any(incomplete, gt("gap_count", 0)),
      pass: eq("gap_count", 0),
    }),
  },
  "OKTA-AUTH-005": {
    inputs: input("readable", "complete", "inventory_count", "policy_count", "gap_count"),
    rules: ordered({
      manual: any(unavailable, eq("inventory_count", 0)),
      fail: comparePaths("eq", "gap_count", "policy_count"),
      warn: any(incomplete, gt("gap_count", 0)),
      pass: eq("gap_count", 0),
    }),
  },
  "OKTA-AUTH-006": {
    inputs: input("readable", "complete", "exposed_value_count", "over_limit_count"),
    constants: { max_idle_minutes: 15 },
    rules: ordered({
      manual: any(unavailable, eq("exposed_value_count", 0)),
      fail: gt("over_limit_count", 0),
      warn: incomplete,
      pass: eq("over_limit_count", 0),
      failFirst: true,
    }),
  },
  "OKTA-AUTH-007": {
    inputs: input("readable", "complete", "exposed_value_count", "over_limit_count", "persistent_cookie_count"),
    constants: { max_lifetime_minutes: 1080 },
    rules: ordered({
      manual: any(unavailable, eq("exposed_value_count", 0)),
      fail: any(gt("over_limit_count", 0), gt("persistent_cookie_count", 0)),
      warn: incomplete,
      pass: all(eq("over_limit_count", 0), eq("persistent_cookie_count", 0)),
      failFirst: true,
    }),
  },
  "OKTA-AUTH-008": {
    inputs: input("idp_readable", "authenticator_readable", "certificate_method_count", "federal_tenant"),
    rules: ordered({
      manual: any(
        all(eq("idp_readable", false), eq("authenticator_readable", false)),
        all(eq("certificate_method_count", 0), any(eq("idp_readable", false), eq("authenticator_readable", false))),
        all(eq("certificate_method_count", 0), eq("federal_tenant", false)),
      ),
      fail: all(eq("certificate_method_count", 0), eq("federal_tenant", true)),
      warn: any(eq("idp_readable", false), eq("authenticator_readable", false)),
      pass: gt("certificate_method_count", 0),
    }),
  },
  "OKTA-AUTH-009": {
    inputs: input("readable", "complete", "classic_engine", "authenticator_count", "federal_tenant", "okta_verify_active", "fips_required", "restricted_count"),
    rules: ordered({
      manual: any(unavailable, eq("classic_engine", true)),
      fail: any(
        eq("authenticator_count", 0),
        all(eq("federal_tenant", true), any(gt("restricted_count", 0), all(eq("okta_verify_active", true), eq("fips_required", false)))),
      ),
      warn: any(
        incomplete,
        all(eq("federal_tenant", true), eq("okta_verify_active", false)),
        all(eq("federal_tenant", false), gt("restricted_count", 0)),
      ),
      pass: { op: "always" },
    }),
  },
  "OKTA-ADMIN-001": {
    inputs: input("readable", "complete", "privileged_user_count", "super_admin_count"),
    constants: { pass_maximum: 2, warn_maximum: 5 },
    rules: ordered({
      manual: any(unavailable, eq("privileged_user_count", 0)),
      fail: gt("super_admin_count", 5),
      warn: any(incomplete, gt("super_admin_count", 2)),
      pass: lte("super_admin_count", 2),
    }),
  },
  "OKTA-ADMIN-002": {
    inputs: input("readable", "complete", "privileged_user_count", "stale_count", "unknown_activity_count"),
    constants: { inactive_days: 90 },
    rules: ordered({
      manual: any(unavailable, eq("privileged_user_count", 0)),
      fail: gt("stale_count", 0),
      warn: any(incomplete, gt("unknown_activity_count", 0)),
      pass: { op: "always" },
      failFirst: true,
    }),
  },
  "OKTA-ADMIN-003": {
    inputs: input("readable", "complete", "privileged_group_count", "oversized_group_count"),
    constants: { maximum_members: 25 },
    rules: ordered({
      manual: any(unavailable, eq("privileged_group_count", 0)),
      warn: any(incomplete, gt("oversized_group_count", 0)),
      pass: eq("oversized_group_count", 0),
    }),
  },
  "OKTA-ADMIN-004": {
    inputs: input("readable", "complete", "privileged_user_count", "inspected_user_count", "unenrolled_count", "weak_factor_count"),
    rules: ordered({
      manual: any(unavailable, eq("privileged_user_count", 0), eq("inspected_user_count", 0)),
      fail: gt("unenrolled_count", 0),
      warn: any(incomplete, gt("weak_factor_count", 0)),
      pass: { op: "always" },
      failFirst: true,
    }),
  },
  "OKTA-ADMIN-005": {
    inputs: input("readable", "complete", "user_count", "stale_active_count", "never_activated_count", "unknown_activity_count", "attention_state_count"),
    constants: { inactive_days: 90, activation_days: 30 },
    rules: ordered({
      manual: any(unavailable, eq("user_count", 0)),
      fail: any(gt("stale_active_count", 0), gt("never_activated_count", 0)),
      warn: any(incomplete, gt("unknown_activity_count", 0), gt("attention_state_count", 0)),
      pass: { op: "always" },
      failFirst: true,
    }),
  },
  "OKTA-ADMIN-006": {
    inputs: input("support_readable", "third_party_readable", "support_present", "support_state", "third_party_admin"),
    rules: ordered({
      manual: any(ne("support_readable", true), eq("support_present", false)),
      warn: any(eq("third_party_readable", false), ne("support_state", "DISABLED"), ne("third_party_admin", false)),
      pass: all(eq("support_state", "DISABLED"), eq("third_party_admin", false)),
    }),
  },
  "OKTA-INTEG-001": {
    inputs: input("readable", "complete", "active_origin_count", "insecure_active_count"),
    rules: ordered({
      manual: unavailable,
      fail: gt("insecure_active_count", 0),
      warn: incomplete,
      info: eq("active_origin_count", 0),
      pass: { op: "always" },
      failFirst: true,
    }),
  },
  "OKTA-INTEG-002": {
    inputs: input("readable", "complete", "zone_count", "custom_zone_count"),
    rules: ordered({
      manual: any(unavailable, eq("zone_count", 0)),
      warn: any(incomplete, eq("custom_zone_count", 0)),
      pass: gt("custom_zone_count", 0),
    }),
  },
  "OKTA-INTEG-003": {
    inputs: input("readable", "complete", "app_count", "risky_active_count", "risky_inactive_count"),
    rules: ordered({
      manual: any(unavailable, eq("app_count", 0)),
      fail: gt("risky_active_count", 0),
      warn: any(incomplete, gt("risky_inactive_count", 0)),
      pass: { op: "always" },
      failFirst: true,
    }),
  },
  "OKTA-INTEG-004": {
    inputs: input("policy_readable", "complete", "risk_aware_rule_count", "custom_zone_count"),
    rules: ordered({
      manual: ne("policy_readable", true),
      fail: all(eq("risk_aware_rule_count", 0), eq("custom_zone_count", 0)),
      warn: any(incomplete, eq("risk_aware_rule_count", 0)),
      pass: gt("risk_aware_rule_count", 0),
    }),
  },
  "OKTA-INTEG-005": {
    inputs: input("readable", "complete", "app_count", "inactive_app_count"),
    rules: ordered({
      manual: any(unavailable, eq("app_count", 0)),
      warn: any(incomplete, gt("inactive_app_count", 0)),
      pass: eq("inactive_app_count", 0),
    }),
  },
  "OKTA-INTEG-006": {
    inputs: input("readable", "complete", "app_count", "provisioning_app_count", "deactivation_app_count"),
    rules: ordered({
      manual: any(unavailable, eq("app_count", 0)),
      fail: all(gt("provisioning_app_count", 0), eq("deactivation_app_count", 0)),
      warn: any(incomplete, eq("provisioning_app_count", 0)),
      pass: gt("deactivation_app_count", 0),
      failFirst: true,
    }),
  },
  "OKTA-MON-001": {
    inputs: input("streams_readable", "hooks_readable", "complete", "active_stream_count", "active_hook_count"),
    rules: ordered({
      manual: any(
        all(ne("streams_readable", true), ne("hooks_readable", true)),
        all(ne("streams_readable", true), eq("active_hook_count", 0)),
      ),
      fail: all(eq("active_stream_count", 0), eq("active_hook_count", 0)),
      warn: any(incomplete, eq("active_stream_count", 0)),
      pass: gt("active_stream_count", 0),
    }),
  },
  "OKTA-MON-002": {
    inputs: input("readable", "complete", "event_count"),
    rules: ordered({
      manual: unavailable,
      warn: any(incomplete, eq("event_count", 0)),
      pass: gt("event_count", 0),
    }),
  },
  "OKTA-MON-003": {
    inputs: input("readable", "configuration_present", "mode"),
    rules: ordered({
      manual: any(unavailable, eq("configuration_present", false)),
      fail: all(ne("mode", "block"), ne("mode", "audit"), ne("mode", "log_only")),
      warn: any(eq("mode", "audit"), eq("mode", "log_only")),
      pass: eq("mode", "block"),
    }),
  },
  "OKTA-MON-004": {
    inputs: input("readable", "complete", "active_behavior_count"),
    rules: ordered({
      manual: unavailable,
      warn: any(incomplete, eq("active_behavior_count", 0)),
      pass: gt("active_behavior_count", 0),
    }),
  },
  "OKTA-MON-005": {
    inputs: input("readable", "complete", "token_count", "ssws_auth", "stale_count", "undated_count"),
    constants: { maximum_age_days: 90 },
    rules: ordered({
      manual: any(unavailable, all(eq("token_count", 0), eq("ssws_auth", true))),
      warn: any(incomplete, gt("stale_count", 0), gt("undated_count", 0)),
      pass: { op: "always" },
    }),
  },
  "OKTA-MON-006": {
    inputs: input("readable", "complete", "policy_count"),
    rules: ordered({
      manual: unavailable,
      warn: any(incomplete, eq("policy_count", 0)),
      pass: gt("policy_count", 0),
    }),
  },
  "OKTA-MON-007": {
    inputs: input("readable", "complete", "token_count", "ssws_auth", "expired_count", "unrestricted_count", "missing_expiry_count", "long_window_count"),
    constants: { maximum_window_days: 30 },
    rules: ordered({
      manual: any(unavailable, all(eq("token_count", 0), eq("ssws_auth", true))),
      fail: gt("expired_count", 0),
      warn: any(incomplete, gt("unrestricted_count", 0), gt("missing_expiry_count", 0), gt("long_window_count", 0)),
      pass: { op: "always" },
      failFirst: true,
    }),
  },
  "OKTA-MON-008": {
    inputs: input("readable", "complete", "contact_count", "technical_contact_present", "technical_user_assigned", "technical_user_state", "technical_lookup_failed"),
    rules: ordered({
      manual: any(unavailable, eq("contact_count", 0)),
      fail: any(
        all(eq("technical_lookup_failed", false), eq("technical_contact_present", false)),
        all(eq("technical_lookup_failed", false), eq("technical_user_assigned", false)),
        all(ne("technical_user_state", ""), ne("technical_user_state", "ACTIVE")),
      ),
      warn: any(incomplete, eq("technical_lookup_failed", true), eq("technical_user_state", "")),
      pass: eq("technical_user_state", "ACTIVE"),
    }),
  },
  "OKTA-MON-009": {
    inputs: {},
    rules: [rule("manual", { op: "always" })],
  },
};

function owner(id: string): string {
  if (id.includes("-AUTH-")) return "okta_assess_authentication";
  if (id.includes("-ADMIN-")) return "okta_assess_admin_access";
  if (id.includes("-INTEG-")) return "okta_assess_integrations";
  return "okta_assess_monitoring";
}

const checks: BatchCheckDefinition[] = Object.entries(titles).map(([id, title], index) => {
  const decision = OKTA_EXECUTABLE_DECISIONS[id];
  const executable = deriveDecisionRules(id, decision.rules);
  return {
    id,
    control: index + 1,
    title,
    severity: id.endsWith("009") || id.includes("AUTH-001") || id.includes("AUTH-002") ? "high" : "medium",
    owner: owner(id),
    surfaces: OKTA_CHECK_SURFACES[id],
    evidenceFields: [...OKTA_CHECK_SURFACES[id], "complete_source_counts"],
    decisionInputs: decision.inputs,
    decisionConstants: decision.constants,
    decisionRules: executable.rules,
    derivedFactRules: executable.derivedFactRules,
    decision: decisions[id],
  };
});

const byOwner = (name: string): string[] => checks.filter((check) => check.owner === name).map((check) => check.id);

export const OKTA_RUNTIME_BEHAVIOR = [
  "Generic list truncation metadata is not complete for every Okta collection; the runtime still prevents pass when a dependent inventory is known partial, but some cap exits have less-specific prose.",
  "Administrator notification preferences have no shipped read implementation; OKTA-MON-009 remains manual and names Admin Console evidence.",
  "The generated rule input records the existing evidence-specific verdict after complete-cardinality calculations; this migration does not alter thresholds, sampling, text, or finding ordering.",
] as const;

export const OKTA_SPEC = buildBatchIntegrationSpec({
  slug: "okta-sec-inspector",
  displayName: "Okta Security Inspector",
  vendor: "Okta",
  category: "identity-and-access",
  summary: "Portable contract for the shipped read-only Okta identity, administrator, integration, and monitoring assessments.",
  sourceModule: "cli/extensions/grc-tools/okta.ts",
  baseServices: ["Okta Management API", "Okta OAuth 2.0"],
  authentication: OKTA_AUTH_RESOLVER,
  permissions: [
    ...[
      "okta.users.read", "okta.groups.read", "okta.apps.read", "okta.authenticators.read",
      "okta.authorizationServers.read", "okta.idps.read", "okta.trustedOrigins.read", "okta.policies.read",
      "okta.logs.read", "okta.eventHooks.read", "okta.logStreams.read", "okta.orgs.read",
      "okta.networkZones.read", "okta.behaviors.read", "okta.deviceAssurance.read", "okta.roles.read",
      "okta.apiTokens.read", "okta.threatInsights.read",
    ].map((value) => ({
      id: value,
      kind: "oauth-scope" as const,
      value,
      unlocks: OKTA_SURFACES.filter((surface) => {
        if (value === "okta.users.read") return ["users", "role-assignees", "user-factors", "group-members"].includes(surface.id);
        if (value === "okta.groups.read") return ["groups", "group-roles", "group-members", "group-rules"].includes(surface.id);
        if (value === "okta.apps.read") return surface.id === "apps";
        if (value === "okta.authenticators.read") return ["authenticators", "org-factors"].includes(surface.id);
        if (value === "okta.authorizationServers.read") return ["authorization-servers", "default-authorization-server"].includes(surface.id);
        if (value === "okta.idps.read") return surface.id === "idps";
        if (value === "okta.trustedOrigins.read") return surface.id === "trusted-origins";
        if (value === "okta.policies.read") return surface.id.includes("polic");
        if (value === "okta.logs.read") return surface.id === "system-log";
        if (value === "okta.eventHooks.read") return surface.id === "event-hooks";
        if (value === "okta.logStreams.read") return surface.id === "log-streams";
        if (value === "okta.orgs.read") return ["okta-support", "third-party-admin", "org-contacts"].includes(surface.id);
        if (value === "okta.networkZones.read") return surface.id === "network-zones";
        if (value === "okta.behaviors.read") return surface.id === "behaviors";
        if (value === "okta.deviceAssurance.read") return surface.id === "device-assurance";
        if (value === "okta.roles.read") return ["role-assignees", "user-roles", "group-roles"].includes(surface.id);
        if (value === "okta.apiTokens.read") return surface.id === "api-tokens";
        return surface.id === "threat-insight";
      }).map((surface) => surface.id),
      notes: "The OAuth service application needs this read scope; SSWS access instead follows the administrator role assigned to the token owner.",
    })),
    { id: "okta-admin-role", kind: "role", value: "Okta administrator role granting the same read surfaces for SSWS authentication", unlocks: OKTA_SURFACES.map((surface) => surface.id) },
  ],
  surfaces: OKTA_SURFACES,
  checks,
  tools: {
    okta_check_access: [],
    okta_assess_authentication: byOwner("okta_assess_authentication"),
    okta_assess_admin_access: byOwner("okta_assess_admin_access"),
    okta_assess_integrations: byOwner("okta_assess_integrations"),
    okta_assess_monitoring: byOwner("okta_assess_monitoring"),
    okta_export_audit_bundle: checks.map((check) => check.id),
  },
  pagination: [
    {
      surfaceIds: OKTA_SURFACES.filter((surface) => !["default-authorization-server", "okta-support", "third-party-admin", "threat-insight"].includes(surface.id)).map((surface) => surface.id),
      cursorFields: ["Link rel=next"],
      pageSize: 200,
      itemCap: null,
      pageCap: 50,
      totalSemantics: "No authoritative total is returned; completion requires the absence of a same-origin Link rel=next. Users use a 50-page cap and System Log uses a five-page cap.",
      stopConditions: ["No rel=next", "50-page list cap", "five-page System Log cap", "Repeated next URL", "Empty page with next URL", "Rejected cross-origin or user-information URL"],
    },
  ],
  rateLimit: {
    documentedLimit: "Endpoint-specific Okta rate-limit buckets",
    retryHeaders: ["Retry-After", "X-Rate-Limit-Reset"],
    retryableStatuses: [429, 500, 502, 503, 504],
    backoffPolicy: "Honor bounded Retry-After or reset delays, then use bounded exponential retry; preserve exhaustion as unreadable evidence.",
  },
  runtimeBehavior: OKTA_RUNTIME_BEHAVIOR,
  knownGaps: ["Lifecycle workflow and broader trust-center evidence remain manual or deferred."],
  sensitiveFields: ["apiToken", "clientAssertion", "privateKey", "credentials", "authorization", "cookie"],
  credentialFormats: ["SSWS tokens", "OAuth bearer tokens", "private keys", "signed JWT assertions"],
  output: buildBatchOutputContract({
    files: [
      "core_data/sign_on_policies.json", "core_data/sign_on_policy_rules.json", "core_data/password_policies.json", "core_data/password_policy_rules.json",
      "core_data/mfa_enrollment_policies.json", "core_data/access_policies.json", "core_data/access_policy_rules.json", "core_data/authenticators.json",
      "core_data/idps.json", "core_data/authorization_servers.json", "core_data/default_authorization_server.json", "core_data/org_factors.json",
      "core_data/users_with_role_assignments.json", "core_data/user_roles.json", "core_data/groups.json", "core_data/privileged_group_roles.json",
      "core_data/privileged_group_members.json", "core_data/users.json", "core_data/privileged_user_factors.json", "core_data/okta_support_access.json",
      "core_data/third_party_admin_setting.json", "core_data/apps.json", "core_data/trusted_origins.json", "core_data/network_zones.json",
      "core_data/group_rules.json", "core_data/event_hooks.json", "core_data/log_streams.json", "core_data/system_logs_recent.json",
      "core_data/behaviors.json", "core_data/threat_insight.json", "core_data/api_tokens.json", "core_data/device_assurance.json",
      "core_data/org_contacts.json", "core_data/collection_status.json", "analysis/authentication.json", "analysis/admin_access.json",
      "analysis/integrations.json", "analysis/monitoring.json", "analysis/findings.json", "compliance/executive_summary.md",
      "compliance/unified_compliance_matrix.md", "compliance/fedramp/fedramp_compliance_report.md",
      "compliance/fedramp/oscal_assessment_results.json", "compliance/disa_stig/stig_compliance_checklist.md",
      "compliance/irap/irap_compliance_report.md", "compliance/irap/essential_eight_assessment.md",
      "compliance/ismap/ismap_compliance_report.md", "compliance/soc2/soc2_compliance_report.md",
      "compliance/pci_dss/pci_dss_compliance_report.md", "QUICK_REFERENCE.md",
    ],
    conditionalFiles: ["_errors.log"],
    overwritePolicy: "Allocate a new <organization-host>-audit-bundle directory with a numeric suffix when either the directory or paired archive exists.",
    archivePairing: "Create <allocated-directory>.zip beside the allocated organization-host audit directory.",
  }),
});
