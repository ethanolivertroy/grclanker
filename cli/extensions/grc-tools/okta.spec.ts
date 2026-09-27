import { buildBatchIntegrationSpec, type BatchCheckDefinition } from "./batch-spec-builder.js";

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
  "OKTA-INTEG-001": "return fail when any ACTIVE trusted origin uses HTTP or a wildcard, pass when at least one ACTIVE origin exists and none is insecure, and manual when the complete inventory has no ACTIVE origin because origins are optional.",
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

function owner(id: string): string {
  if (id.includes("-AUTH-")) return "okta_assess_authentication";
  if (id.includes("-ADMIN-")) return "okta_assess_admin_access";
  if (id.includes("-INTEG-")) return "okta_assess_integrations";
  return "okta_assess_monitoring";
}

const checks: BatchCheckDefinition[] = Object.entries(titles).map(([id, title], index) => ({
  id,
  control: index + 1,
  title,
  severity: id.endsWith("009") || id.includes("AUTH-001") || id.includes("AUTH-002") ? "high" : "medium",
  owner: owner(id),
  decision: decisions[id],
}));

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
  authentication: {
    modes: ["SSWS API token", "OAuth service application private-key JWT", "prebuilt client assertion"],
    precedence: ["Explicit tool arguments", "Explicit config file", "Okta CLI-style config files", "OKTA_* environment variables"],
    environment: ["OKTA_ORG_URL", "OKTA_CLIENT_ORGURL", "OKTA_API_TOKEN", "OKTA_CLIENT_TOKEN", "OKTA_CLIENT_ID", "OKTA_CLIENT_PRIVATEKEY", "OKTA_CLIENT_PRIVATEKEY_ID"],
    configLocations: [".okta.yaml", "~/.okta/okta.yaml"],
    variants: ["Commercial, preview, and custom Okta organization origins"],
    configFields: ["orgUrl", "token", "clientId", "privateKey", "privateKeyId", "clientAssertion", "scopes"],
    refreshRequest: "POST /oauth2/v1/token with the client_credentials grant and a private_key_jwt assertion.",
  },
  permissions: ["Okta read-only Management API OAuth scopes for every requested surface", "An administrator role that can read policy, user, app, and System Log evidence"],
  surfaces: [
    { id: "users", path: "/api/v1/users", service: "Okta Management API", documentationUrl: "https://developer.okta.com/docs/api/openapi/okta-management/management/tag/User/", fields: ["id", "status", "profile", "lastLogin"] },
    { id: "policies", path: "/api/v1/policies", service: "Okta Management API", documentationUrl: "https://developer.okta.com/docs/api/openapi/okta-management/management/tag/Policy/", fields: ["id", "type", "status", "conditions", "settings"] },
    { id: "apps", path: "/api/v1/apps", service: "Okta Management API", documentationUrl: "https://developer.okta.com/docs/api/openapi/okta-management/management/tag/Application/", fields: ["id", "name", "label", "status", "settings", "credentials"] },
    { id: "system-log", path: "/api/v1/logs", service: "Okta Management API", documentationUrl: "https://developer.okta.com/docs/api/openapi/okta-management/management/tag/SystemLog/", fields: ["uuid", "published", "eventType", "severity", "outcome"] },
  ],
  checks,
  tools: {
    okta_check_access: [],
    okta_assess_authentication: byOwner("okta_assess_authentication"),
    okta_assess_admin_access: byOwner("okta_assess_admin_access"),
    okta_assess_integrations: byOwner("okta_assess_integrations"),
    okta_assess_monitoring: byOwner("okta_assess_monitoring"),
    okta_export_audit_bundle: checks.map((check) => check.id),
  },
  pagination: {
    cursorFields: ["Link rel=next", "after"],
    pageSize: null,
    itemCap: null,
    pageCap: null,
    totalSemantics: "Okta collections are complete only after no same-origin next link remains; per-tool item caps make affected datasets partial.",
    stopConditions: ["Proven exhaustion", "Configured item cap", "Repeated cursor", "Empty page with cursor", "Rejected off-origin or user-information next link"],
  },
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
  outputPrefix: "okta-audit",
});
