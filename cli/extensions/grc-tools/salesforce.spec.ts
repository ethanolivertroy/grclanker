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
const decisions = [
  "return pass for a Health Check score of at least 90, warn from 70 through 89, fail below 70, and manual when SecurityHealthCheck exposes no score.",
  "return pass when session timeout is at most 120 minutes, forced logout is enabled, and sessions are locked to the originating IP; warn when only the IP lock is missing, fail for an excessive timeout or disabled forced logout, and manual for absent values.",
  "evaluate minimum length 12, strongest complexity, expiration at most 90 days, and history at least five; return pass with no gap, warn with one gap, fail with two or more gaps, and manual when a required field is absent.",
  "return fail when direct-UI MFA is not required or more than 25 percent of visible active standard users lack a registered method, warn for a smaller unenrolled population or partial reads, and pass when complete evidence shows MFA required and every user enrolled.",
  "return pass when every sensitive profile has login IP ranges, per-request enforcement is enabled, and an org-wide trusted range exists; fail when none exists at either level, and warn or manual for mixed, unresolved, or unreadable coverage.",
  "return pass when every sensitive profile restricts login hours every day, fail when none does, and warn when only some do or profile resolution is incomplete.",
  "return pass when no visible active user is assigned a profile with API Enabled, warn when such users are below the configured ratio or evidence is partial, and fail when the configured excessive-access threshold is crossed.",
  "return fail when any sensitive-name field is broadly readable by more than five profile or permission-set grants, warn for narrower grants or partial rows, and manual when no field matches the classification patterns.",
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
const checks: BatchCheckDefinition[] = titles.map((title, index) => {
  const control = index + 1;
  return {
    id: `SF-${String(control).padStart(2, "0")}`,
    control,
    title,
    severity: [4].includes(control) ? "critical" : [3, 5, 6, 9, 10, 11, 12, 16, 17].includes(control) ? "high" : "medium",
    owner: ownerFor(control),
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
