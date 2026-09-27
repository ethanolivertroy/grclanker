import { buildBatchIntegrationSpec, type BatchCheckDefinition } from "./batch-spec-builder.js";

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
const checks: BatchCheckDefinition[] = titles.map((title, index) => {
  const control = index + 1;
  return {
    id: `SF-${String(control).padStart(2, "0")}`,
    control,
    title,
    severity: [4].includes(control) ? "critical" : [3, 5, 6, 9, 10, 11, 12, 16, 17].includes(control) ? "high" : "medium",
    owner: ownerFor(control),
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
  authentication: {
    modes: ["JWT bearer", "username/password plus security token", "OAuth refresh token", "explicit access token"],
    precedence: ["Explicit access token and instance URL", "Explicit refresh token", "Explicit JWT credentials", "Password grant", "Credentials file and SF_* environment variables"],
    environment: ["SF_INSTANCE_URL", "SF_LOGIN_URL", "SF_USERNAME", "SF_PASSWORD", "SF_SECURITY_TOKEN", "SF_CONSUMER_KEY", "SF_CONSUMER_SECRET", "SF_PRIVATE_KEY", "SF_REFRESH_TOKEN", "SF_ACCESS_TOKEN"],
    configLocations: ["Explicit credentials JSON file"],
    variants: ["Production login", "Sandbox login", "Custom My Domain login"],
    configFields: ["instanceUrl", "loginUrl", "username", "password", "securityToken", "consumerKey", "consumerSecret", "privateKey", "refreshToken", "accessToken", "apiVersion"],
    refreshRequest: "POST /services/oauth2/token with the selected JWT bearer, refresh_token, or password grant.",
  },
  permissions: ["API Enabled", "View Setup and Configuration", "View Health Check", "View All Users", "Manage MFA in API", "Metadata API read privileges", "View Event Log Files where licensed"],
  surfaces: [
    { id: "standard-query", path: "/services/data/v64.0/query", service: "Salesforce REST API", documentationUrl: "https://developer.salesforce.com/docs/atlas.en-us.api_rest.meta/api_rest/resources_query.htm", fields: ["records", "totalSize", "done", "nextRecordsUrl"] },
    { id: "tooling-query", path: "/services/data/v64.0/tooling/query", service: "Salesforce Tooling API", documentationUrl: "https://developer.salesforce.com/docs/atlas.en-us.api_tooling.meta/api_tooling/intro_rest_resources.htm", fields: ["records", "totalSize", "done", "nextRecordsUrl"] },
    { id: "metadata-read", method: "POST", path: "/services/Soap/m/64.0", service: "Salesforce Metadata API", documentationUrl: "https://developer.salesforce.com/docs/atlas.en-us.api_meta.meta/api_meta/meta_readMetadata.htm", fields: ["SecuritySettings", "MyDomainSettings", "Profile", "ConnectedApp"] },
    { id: "limits", path: "/services/data/v64.0/limits", service: "Salesforce REST API", documentationUrl: "https://developer.salesforce.com/docs/atlas.en-us.api_rest.meta/api_rest/resources_limits.htm", fields: ["DailyApiRequests", "HourlyODataCallout", "DailyAsyncApexExecutions"] },
  ],
  checks,
  tools: {
    salesforce_check_access: [],
    salesforce_assess_platform_security: idsFor("salesforce_assess_platform_security"),
    salesforce_assess_identity_access: idsFor("salesforce_assess_identity_access"),
    salesforce_assess_data_protection: idsFor("salesforce_assess_data_protection"),
    salesforce_assess_monitoring_integrations: idsFor("salesforce_assess_monitoring_integrations"),
    salesforce_export_audit_bundle: checks.map((check) => check.id),
  },
  pagination: {
    cursorFields: ["nextRecordsUrl", "done", "totalSize"],
    pageSize: 2000,
    itemCap: 2000,
    pageCap: null,
    totalSemantics: "totalSize is authoritative when present; done=true and seen equal total prove completion.",
    stopConditions: ["done true with matching total", "Configured row cap", "Repeated nextRecordsUrl", "Empty page with continuation", "Missing or larger total", "Rejected cross-origin or user-information cursor"],
  },
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
  outputPrefix: "salesforce-audit",
});
