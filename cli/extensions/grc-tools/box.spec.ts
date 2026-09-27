import { buildBatchIntegrationSpec, type BatchCheckDefinition } from "./batch-spec-builder.js";

const controls = [
  "SSO enforcement", "2FA for admins", "2FA for all users", "External collaboration restrictions",
  "Collaboration allowlist audit", "Sharing link policies", "Shared link expiration", "Shared link password policy",
  "Watermarking enabled", "Device trust and pins", "Classification labels", "Retention policies",
  "Legal hold policies", "Shield smart access policies", "Shield information barriers", "Enterprise event streaming",
  "Admin role minimization", "Co-admin permission scoping", "App approval process", "Custom terms of service",
  "Password policy strength", "Session duration limits", "IP allowlisting", "Inactive user detection",
  "Content access monitoring",
] as const;

const identity = new Set([1, 2, 3, 17, 18, 21, 22, 23, 24]);
const sharing = new Set([4, 5, 6, 7, 8, 9, 19, 20]);
const governance = new Set([10, 11, 12, 13]);
const ownerFor = (control: number): string => identity.has(control)
  ? "box_assess_identity_access"
  : sharing.has(control)
    ? "box_assess_sharing_collaboration"
    : governance.has(control)
      ? "box_assess_data_governance"
      : "box_assess_shield_monitoring";

const decisions = [
  "return pass when enterprise SSO is required and not in testing mode, warn when it is required but testing, unused, or not exposed, and fail when it is explicitly not required.",
  "return fail when enterprise MFA is required but any admin or co-admin is exempt, pass when MFA is required and the complete privileged inventory has no exemption, warn for unused or unknown settings, an incomplete inventory, or required SSO with Box-native MFA disabled, and fail when both MFA and required SSO are disabled.",
  "return pass when enterprise MFA is required and the complete user inventory has no non-privileged exemption, warn for any exemption, unused or unknown settings, an incomplete inventory, or required SSO with Box-native MFA disabled, and fail when neither MFA nor required SSO is enforced.",
  "return pass when external collaboration is enterprise-only or allowlist-only with at least one readable entry, fail when unrestricted, and warn for unused, unknown, empty, unreadable, or truncated-before-first-entry allowlist evidence.",
  "return fail when any allowlist entry is a public consumer email domain, warn for truncation, stale or undated entries, exemptions, or an empty allowlist while allowlist-only mode is selected, and pass when complete entries are recent non-public domains without exemptions or no allowlist is required and none exists.",
  "return fail when shared links default to open access, pass when the default is restricted and open links are not offered, and warn when the default is restricted but open links remain available or the setting is unused or unrecognized.",
  "return pass when mandatory expiration is enabled for all shared links, warn when only public links expire or the setting is unused or absent, and fail when mandatory expiration is explicitly disabled.",
  "always return manual because the enterprise configuration API does not expose whether passwords are required for open shared links.",
  "return pass when enterprise watermarking is enabled, fail when explicitly disabled, and warn when the flag is unused or absent.",
  "return warn when the complete device-pin inventory is empty and manual when pins exist because the API does not expose whether unpinned devices are blocked; a read that truncates before its first pin is also manual.",
  "return pass when the classification template defines at least one label and fail when a readable template or a 404 proves that it defines none.",
  "return pass when a complete retention-policy inventory has at least one active policy with visible assignments, warn when active policies lack assignments or any relevant inventory is truncated, and fail when a complete inventory has no active policy.",
  "return pass when a complete legal-hold inventory has at least one active or applying policy with visible assignments, and warn when policies or assignments are incomplete, active holds lack assignments, no hold is active, or no hold exists.",
  "return pass when at least one Shield smart-access or threat-detection rule is configured and fail when a readable complete Shield configuration has none.",
  "return pass when at least one enabled information barrier has a visible segment, and warn when barriers or segments are incomplete, enabled barriers have no visible segment, no barrier is enabled, or no barrier exists.",
  "return pass when the readable enterprise admin event stream contains at least one event in the lookback and warn when it contains none; this verdict proves stream readability only and does not prove SIEM consumption.",
  "return warn when the complete count of admins plus co-admins exceeds the configured maximum and pass when it is at or below that maximum.",
  "return pass when the complete user inventory has no co-admin and manual when any co-admin exists because individual co-admin permissions are not exposed.",
  "always return manual because app creation events and Shield integration lists do not expose the app approval policy.",
  "return pass when at least one managed-user custom terms record is enabled, fail when managed-user terms exist but are disabled, and fail when a complete terms inventory has no managed-user terms.",
  "return pass when minimum password length meets the configured target, weak-password prevention is enabled, and at least two of uppercase, numeric, and special-character minima are positive; warn when length is at least eight but any target is missed or the setting is unused or absent, and fail below eight.",
  "return fail when the base session duration or an enabled custom group duration exceeds the configured maximum, pass when every applicable duration is at or below it, and warn when a duration is unused, absent, or cannot be normalized.",
  "always return manual because Shield IP lists do not expose whether enterprise sign-in or access-policy IP restrictions are enforced.",
  "return pass when every active human user has a successful activity event in the lookback, fail when more than 25 percent lack one, and warn when at most 25 percent lack one, no active human user exists, or user or event coverage is incomplete.",
  "return pass when at least one Shield anomaly rule or Shield alert or block event exists, warn when one required source is unavailable, only ordinary access events exist, or the event window is incomplete, and fail when complete readable evidence has no anomaly rule, alert, block, or content-access event.",
] as const;

const checks: BatchCheckDefinition[] = controls.map((title, index) => {
  const control = index + 1;
  return {
    id: `BOX-${String(control).padStart(2, "0")}`,
    control,
    title,
    severity: [1, 2].includes(control) ? "critical" : [3, 4, 6, 14, 16, 17, 21, 25].includes(control) ? "high" : "medium",
    owner: ownerFor(control),
    decision: decisions[index],
  };
});
const idsFor = (owner: string): string[] => checks.filter((check) => check.owner === owner).map((check) => check.id);

export const BOX_RUNTIME_BEHAVIOR = [
  "Enterprise configuration categories can be returned but marked unused by Box; unused security settings never pass and render warning or manual evidence.",
  "Marker, offset, and event-stream walkers keep distinct completion rules, including repeated markers, empty pages, server totals, item caps, and stream-position exits.",
  "Five policy areas remain partly or wholly manual because the Box Content API does not expose a decisive read field; the runtime names Admin Console evidence.",
] as const;

export const BOX_SPEC = buildBatchIntegrationSpec({
  slug: "box-sec-inspector",
  displayName: "Box Security Inspector",
  vendor: "Box",
  category: "collaboration-and-content",
  summary: "Portable contract for the shipped Box identity, sharing, governance, Shield, and monitoring assessments.",
  sourceModule: "cli/extensions/grc-tools/box.ts",
  baseServices: ["Box Content API", "Box OAuth 2.0 token service"],
  authentication: {
    modes: ["JWT server authentication", "Client Credentials Grant", "OAuth refresh token", "Explicit access token"],
    precedence: ["Explicit arguments", "Explicit config path", "Box inspector config", "BOX_* environment variables"],
    environment: ["BOX_CLIENT_ID", "BOX_CLIENT_SECRET", "BOX_ENTERPRISE_ID", "BOX_ACCESS_TOKEN", "BOX_REFRESH_TOKEN", "BOX_JWT_CONFIG"],
    configLocations: ["~/.box-sec-inspector/config.yaml"],
    variants: ["Enterprise or user subject", "JWT RS256, RS384, or RS512 assertion"],
    configFields: ["clientId", "clientSecret", "enterpriseId", "subjectType", "subjectId", "accessToken", "refreshToken", "jwt"],
    refreshRequest: "POST https://api.box.com/oauth2/token using the selected JWT, client_credentials, or refresh_token grant.",
  },
  permissions: ["Box application access to enterprise users, groups, events, policies, legal holds, terms, and enterprise configuration", "Box Shield or governance plan entitlements for gated surfaces"],
  surfaces: [
    { id: "enterprise-users", path: "/2.0/users", service: "Box Content API", documentationUrl: "https://developer.box.com/reference/get-users/", fields: ["id", "login", "role", "status", "is_exempt_from_login_verification", "is_external_collab_restricted"] },
    { id: "enterprise-config", path: "/2.0/enterprise/configuration", service: "Box Content API", documentationUrl: "https://developer.box.com/reference/get-enterprise-configuration/", fields: ["user_settings", "security", "content_and_sharing"] },
    { id: "enterprise-events", path: "/2.0/events", service: "Box Content API", documentationUrl: "https://developer.box.com/reference/get-events/", fields: ["event_id", "event_type", "created_at", "created_by", "source", "additional_details"] },
    { id: "retention-policies", path: "/2.0/retention_policies", service: "Box Content API", documentationUrl: "https://developer.box.com/reference/get-retention-policies/", fields: ["id", "policy_name", "policy_type", "retention_length", "status"] },
    { id: "legal-hold-policies", path: "/2.0/legal_hold_policies", service: "Box Content API", documentationUrl: "https://developer.box.com/reference/get-legal-hold-policies/", fields: ["id", "policy_name", "status", "created_at"] },
  ],
  checks,
  tools: {
    box_check_access: [],
    box_assess_identity_access: idsFor("box_assess_identity_access"),
    box_assess_sharing_collaboration: idsFor("box_assess_sharing_collaboration"),
    box_assess_data_governance: idsFor("box_assess_data_governance"),
    box_assess_shield_monitoring: idsFor("box_assess_shield_monitoring"),
    box_export_audit_bundle: checks.map((check) => check.id),
  },
  pagination: {
    cursorFields: ["next_marker", "offset", "total_count", "next_stream_position"],
    pageSize: 100,
    itemCap: null,
    pageCap: null,
    totalSemantics: "Offset totals and event stream positions are checked independently; a remaining marker or total above seen records is truncated.",
    stopConditions: ["No next marker or total reached", "Configured item cap", "Fixed assignment cap", "Repeated marker or stream position", "Empty page with continuation", "Event page budget"],
  },
  rateLimit: {
    documentedLimit: "Box rate limits vary by endpoint, user, and enterprise",
    retryHeaders: ["Retry-After", "X-Rate-Limit-Limit", "X-Rate-Limit-Remaining"],
    retryableStatuses: [429, 500, 502, 503, 504],
    backoffPolicy: "Honor Retry-After up to 60 seconds and retry three times with bounded exponential delay.",
  },
  runtimeBehavior: BOX_RUNTIME_BEHAVIOR,
  knownGaps: ["CSV, HTML, SARIF, TUI output, and several policy reads remain absent."],
  sensitiveFields: ["client_secret", "private_key", "passphrase", "access_token", "refresh_token", "authorization", "login"],
  credentialFormats: ["Box OAuth access and refresh tokens", "JWT private keys and passphrases", "signed JWT assertions"],
  outputPrefix: "box-audit",
});
