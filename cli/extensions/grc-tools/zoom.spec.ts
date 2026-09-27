import { buildBatchIntegrationSpec, type BatchCheckDefinition } from "./batch-spec-builder.js";

const rows = [
  ["ZOOM-ID-01", 5, "SSO enforcement for all users", "critical", "zoom_assess_identity"],
  ["ZOOM-ID-02", 6, "Two-factor authentication for admins", "critical", "zoom_assess_identity"],
  ["ZOOM-ID-03", 14, "Managed domains verified", "high", "zoom_assess_identity"],
  ["ZOOM-ID-04", 6, "Administrative privilege concentration", "medium", "zoom_assess_identity"],
  ["ZOOM-ID-05", 16, "Personal and social sign-in methods blocked", "high", "zoom_assess_identity"],
  ["ZOOM-ID-06", 17, "Session inactivity timeout enforced", "medium", "zoom_assess_identity"],
  ["ZOOM-ID-07", 13, "Vanity URL configured and secured", "low", "zoom_assess_identity"],
  ["ZOOM-COLLAB-01", 12, "Trusted domain restrictions", "high", "zoom_assess_collaboration_governance"],
  ["ZOOM-COLLAB-02", 9, "In-meeting file transfer restricted", "high", "zoom_assess_collaboration_governance"],
  ["ZOOM-COLLAB-03", 10, "Cloud recording auto-delete retention", "high", "zoom_assess_collaboration_governance"],
  ["ZOOM-COLLAB-04", 19, "Zoom Phone recording policies enforced", "medium", "zoom_assess_collaboration_governance"],
  ["ZOOM-COLLAB-05", 24, "Admin operation logs readable and recent", "medium", "zoom_assess_collaboration_governance"],
  ["ZOOM-COLLAB-06", 15, "IM group restrictions enforced", "medium", "zoom_assess_collaboration_governance"],
  ["ZOOM-COLLAB-07", 12, "External contacts restricted", "medium", "zoom_assess_collaboration_governance"],
  ["ZOOM-COLLAB-08", 8, "Chat encryption enabled", "medium", "zoom_assess_collaboration_governance"],
  ["ZOOM-MTG-01", 1, "Meeting password enforcement and account lock", "critical", "zoom_assess_meeting_security"],
  ["ZOOM-MTG-02", 2, "Waiting room enabled by default", "critical", "zoom_assess_meeting_security"],
  ["ZOOM-MTG-03", 3, "Screen sharing restricted to host only", "high", "zoom_assess_meeting_security"],
  ["ZOOM-MTG-04", 20, "Local recording disabled", "high", "zoom_assess_meeting_security"],
  ["ZOOM-MTG-05", 7, "End-to-end encryption available and default", "high", "zoom_assess_meeting_security"],
  ["ZOOM-MTG-06", 22, "Embed password in join link disabled", "medium", "zoom_assess_meeting_security"],
  ["ZOOM-MTG-07", 25, "Personal Meeting ID usage restricted", "medium", "zoom_assess_meeting_security"],
  ["ZOOM-MTG-08", 23, "Only authenticated users can join meetings", "high", "zoom_assess_meeting_security"],
  ["ZOOM-MTG-09", 18, "Data routing control enabled", "critical", "zoom_assess_meeting_security"],
  ["ZOOM-MTG-10", 4, "Recording consent disclaimer shown to participants", "high", "zoom_assess_meeting_security"],
] as const;

const checks: BatchCheckDefinition[] = rows.map(([id, control, title, severity, owner]) => ({ id, control, title, severity, owner }));
const idsFor = (owner: string): string[] => checks.filter((check) => check.owner === owner).map((check) => check.id);

export const ZOOM_RUNTIME_BEHAVIOR = [
  "Account settings are read through documented option views and sampled group overrides; a pass requires complete account and group evidence plus every required account-level lock.",
  "User, role-member, group, operation-log, and IM-group verdict facts use complete seen and declared-total counts, while exported evidence may retain bounded record samples.",
  "The account API exposes neither a decisive Team Chat encryption setting nor account vanity URL field; those findings remain manual rather than inferred from unrelated fields.",
] as const;

export const ZOOM_SPEC = buildBatchIntegrationSpec({
  slug: "zoom-sec-inspector",
  displayName: "Zoom Security Inspector",
  vendor: "Zoom",
  category: "collaboration",
  summary: "Portable contract for the shipped Zoom identity, collaboration-governance, and meeting-security assessments.",
  sourceModule: "cli/extensions/grc-tools/zoom.ts",
  baseServices: ["Zoom REST API", "Zoom Server-to-Server OAuth"],
  authentication: {
    modes: ["Server-to-Server OAuth client credentials", "Explicit access token"],
    precedence: ["Explicit access token", "Explicit account/client credentials", "Config file", "ZOOM_* environment variables"],
    environment: ["ZOOM_ACCOUNT_ID", "ZOOM_CLIENT_ID", "ZOOM_CLIENT_SECRET", "ZOOM_ACCESS_TOKEN", "ZOOM_BASE_URL"],
    configLocations: [".zoom.json", ".grclanker-zoom.json"],
    variants: ["Master or sub-account ID supplied explicitly"],
    configFields: ["accountId", "clientId", "clientSecret", "accessToken", "baseUrl", "oauthBaseUrl", "timeoutMs"],
    refreshRequest: "POST /oauth/token?grant_type=account_credentials&account_id={accountId} with client Basic authentication.",
  },
  permissions: ["account:read:admin settings and lock-settings scopes", "user and role read scopes", "report:read:operation_logs:admin", "contact_group and Zoom Phone account-setting read scopes where licensed"],
  surfaces: [
    { id: "account-settings", path: "/v2/accounts/{accountId}/settings", service: "Zoom REST API", documentationUrl: "https://developers.zoom.us/docs/api/accounts/#tag/accounts/GET/accounts/{accountId}/settings", fields: ["security", "meeting_security", "schedule_meeting", "in_meeting", "recording", "chat"] },
    { id: "lock-settings", path: "/v2/accounts/{accountId}/lock_settings", service: "Zoom REST API", documentationUrl: "https://developers.zoom.us/docs/api/accounts/#tag/accounts/GET/accounts/{accountId}/lock_settings", fields: ["meeting_security", "schedule_meeting", "in_meeting", "recording", "chat"] },
    { id: "users", path: "/v2/users", service: "Zoom REST API", documentationUrl: "https://developers.zoom.us/docs/api/users/#tag/users/GET/users", fields: ["id", "email", "status", "type", "login_types"] },
    { id: "groups", path: "/v2/groups", service: "Zoom REST API", documentationUrl: "https://developers.zoom.us/docs/api/users/#tag/groups/GET/groups", fields: ["id", "name", "total_members"] },
    { id: "operation-logs", path: "/v2/report/operationlogs", service: "Zoom REST API", documentationUrl: "https://developers.zoom.us/docs/api/meetings/#tag/reports/GET/report/operationlogs", fields: ["time", "operator", "category_type", "operation_detail"] },
  ],
  checks,
  tools: {
    zoom_check_access: [],
    zoom_assess_identity: idsFor("zoom_assess_identity"),
    zoom_assess_collaboration_governance: idsFor("zoom_assess_collaboration_governance"),
    zoom_assess_meeting_security: idsFor("zoom_assess_meeting_security"),
    zoom_export_audit_bundle: checks.map((check) => check.id),
  },
  pagination: {
    cursorFields: ["next_page_token", "page_number", "page_count", "total_records"],
    pageSize: 300,
    itemCap: null,
    pageCap: 500,
    totalSemantics: "total_records is checked when returned; missing totals require explicit token exhaustion and never imply empty completeness.",
    stopConditions: ["No next_page_token", "Declared total reached", "Configured item cap", "Page cap", "Repeated token", "Empty page with token", "Missing or inconsistent total"],
  },
  rateLimit: {
    documentedLimit: "Zoom applies endpoint labels and app-level daily request limits",
    retryHeaders: ["Retry-After", "X-RateLimit-Category", "X-RateLimit-Remaining"],
    retryableStatuses: [429, 500, 502, 503, 504],
    backoffPolicy: "Honor Retry-After up to 30 seconds and retry three times with bounded backoff.",
  },
  runtimeBehavior: ZOOM_RUNTIME_BEHAVIOR,
  knownGaps: ["User OAuth, per-user settings drift, deeper Zoom Phone policy, and usage analytics are deferred."],
  sensitiveFields: ["client_secret", "access_token", "authorization", "cookie", "join_url", "start_url"],
  credentialFormats: ["Zoom OAuth bearer tokens", "OAuth client secrets", "meeting start and join URLs"],
  outputPrefix: "zoom-audit",
});
