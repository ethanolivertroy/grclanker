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
