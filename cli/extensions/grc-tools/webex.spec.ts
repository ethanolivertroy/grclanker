import { join } from "node:path";
import type {
  CheckContract,
  ControlContract,
  FrameworkKey,
  IntegrationSpecContract,
  RequestContract,
  VerdictCriteria,
} from "./spec-model.js";

export type WebexFieldSpec = true | { readonly [field: string]: WebexFieldSpec };
export type WebexSurfaceSpec = { readonly [field: string]: WebexFieldSpec };
export type WebexFrameworkKey = FrameworkKey;
export type WebexFrameworkMap = Record<WebexFrameworkKey, string[]>;

export const WEBEX_DOCS = {
  basics: "https://developer.webex.com/docs/api/basics",
  integrations: "https://developer.webex.com/docs/integrations",
  serviceApps: "https://developer.webex.com/docs/service-apps",
  bots: "https://developer.webex.com/docs/bots",
  complianceGuide: "https://developer.webex.com/docs/api/guides/compliance",
  peopleMe: "https://developer.webex.com/admin/docs/api/v1/people/get-my-own-details",
  peopleList: "https://developer.webex.com/admin/docs/api/v1/people/list-people",
  organizationsList: "https://developer.webex.com/admin/docs/api/v1/organizations/list-organizations",
  organizationGet: "https://developer.webex.com/admin/docs/api/v1/organizations/get-organization-details",
  authenticationConfig: "https://developer.webex.com/admin/docs/api/v1/identity-organization/update-organization-authentication-configuration-settings",
  rolesList: "https://developer.webex.com/admin/docs/api/v1/roles/list-roles",
  licensesList: "https://developer.webex.com/admin/docs/api/v1/licenses/list-licenses",
  eventsList: "https://developer.webex.com/admin/docs/api/v1/events/list-events",
  adminAuditEvents: "https://developer.webex.com/admin/docs/api/v1/admin-audit-events/list-admin-audit-events",
  adminRecordings: "https://developer.webex.com/admin/docs/api/v1/recordings/list-recordings-for-an-admin-or-compliance-officer",
  guestCount: "https://developer.webex.com/admin/docs/api/v1/guest-management/get-guest-count",
  hybridClusters: "https://developer.webex.com/admin/docs/api/v1/hybrid-clusters/list-hybrid-clusters",
  hybridConnectors: "https://developer.webex.com/admin/docs/api/v1/hybrid-connectors/list-hybrid-connectors",
  meetingsList: "https://developer.webex.com/meeting/docs/api/v1/meetings/list-meetings",
  meetingPreferences: "https://developer.webex.com/meeting/docs/api/v1/meeting-preferences/get-meeting-preference-details",
  meetingSites: "https://developer.webex.com/meeting/docs/api/v1/meeting-preferences/get-site-list",
  meetingCommonSettings: "https://developer.webex.com/meeting/docs/api/v1/site/get-meeting-common-settings-configuration",
  sessionTypes: "https://developer.webex.com/meeting/docs/api/v1/session-types",
  webhooksList: "https://developer.webex.com/meeting/docs/api/v1/webhooks/list-webhooks",
  devicesList: "https://developer.webex.com/calling/docs/api/v1/devices/list-devices",
  workspacesList: "https://developer.webex.com/calling/docs/api/v1/workspaces/list-workspaces",
  roomsList: "https://developer.webex.com/messaging/docs/api/v1/rooms/list-rooms",
} as const;

export const WEBEX_ENDPOINTS = {
  tokenRefresh: "/access_token",
  me: "/people/me",
  organizations: "/organizations",
  organization: "/organizations/{orgId}",
  people: "/people",
  roles: "/roles",
  licenses: "/licenses",
  events: "/events",
  adminAuditEvents: "/adminAudit/events",
  adminRecordings: "/admin/recordings",
  guestCount: "/guests/count",
  hybridClusters: "/hybrid/clusters",
  hybridConnectors: "/hybrid/connectors",
  meetings: "/meetings",
  meetingPreferences: "/meetingPreferences",
  meetingSites: "/meetingPreferences/sites",
  meetingCommonSettings: "/admin/meeting/config/commonSettings",
  devices: "/devices",
  workspaces: "/workspaces",
  rooms: "/rooms",
  webhooks: "/webhooks",
} as const;

export const WEBEX_VERDICT_VALUES = {
  minimumMeetingPasswordLength: 8,
  maximumUnassignedLicenseRatio: 0.2,
  adminAuditWindowDays: 30,
  operationalConnectorStatus: "operational",
  secureWebhookPrefix: "https://",
  inactiveWebhookStatus: "inactive",
  botPersonType: "bot",
  guestPersonType: "appuser",
  complianceOfficerRolePattern: "compliance officer",
  administratorRolePattern: "administrator",
} as const;

export const WEBEX_DEFAULTS = {
  outputDir: "./export/webex",
  timeoutMs: 30_000,
  configDir: join(".config", "webex-sec-inspector"),
  configFileNames: ["config.json", "config.yaml", "config.yml"],
  maxRetryAfterMs: 30_000,
  max429Retries: 2,
  maxListPages: 1000,
  minimumMeetingPasswordLength: WEBEX_VERDICT_VALUES.minimumMeetingPasswordLength,
  peopleLimit: 1000,
  eventLimit: 500,
  licenseLimit: 200,
  recordingLimit: 200,
  meetingLimit: 200,
  webhookLimit: 200,
  deviceLimit: 500,
  roomLimit: 500,
  genericLimit: 200,
  maxAdmins: 10,
  adminAuditWindowDays: WEBEX_VERDICT_VALUES.adminAuditWindowDays,
} as const;

export const WEBEX_PAGE_MAX = {
  people: 100,
  events: 100,
  adminAudit: 200,
  adminRecordings: 100,
  meetings: 100,
  devices: 100,
  workspaces: 100,
  rooms: 100,
  webhooks: 100,
} as const;

export const WEBEX_SCOPES = {
  ownDetailsRead: "spark:people_read",
  peopleRead: "spark-admin:people_read",
  organizationsRead: "spark-admin:organizations_read",
  rolesRead: "spark-admin:roles_read",
  licensesRead: "spark-admin:licenses_read",
  devicesRead: "spark-admin:devices_read",
  workspacesRead: "spark-admin:workspaces_read",
  hybridRead: "spark-admin:hybrid_clusters_read",
  eventsRead: "spark-compliance:events_read",
  adminAuditRead: "audit:events_read",
  adminRecordingsRead: "spark-compliance:recordings_read",
  guestIssuerRead: "guest-issuer:read",
  roomsRead: "spark:rooms_read",
  webhooksRead: "spark:webhooks_read",
  meetingScheduleRead: "meeting:schedules_read or meeting:admin_schedule_read",
  meetingAdminScheduleRead: "meeting:admin_schedule_read",
  meetingPreferencesRead: "meeting:preferences_read or meeting:admin_preferences_read",
  meetingAdminPreferencesRead: "meeting:admin_preferences_read",
  meetingAdminConfigRead: "meeting:admin_config_read",
} as const;

export const WEBEX_ENV = {
  token: "WEBEX_TOKEN",
  clientId: "WEBEX_CLIENT_ID",
  clientSecret: "WEBEX_CLIENT_SECRET",
  refreshToken: "WEBEX_REFRESH_TOKEN",
  orgId: "WEBEX_ORG_ID",
  apiBaseUrl: "WEBEX_API_BASE_URL",
  timeout: "WEBEX_TIMEOUT",
  configFile: "WEBEX_CONFIG_FILE",
} as const;

export const WEBEX_FRAMEWORK_LABELS: Record<WebexFrameworkKey, string> = {
  fedramp: "FedRAMP / NIST 800-53",
  cmmc: "CMMC",
  soc2: "SOC 2",
  cis: "CIS Controls",
  pci_dss: "PCI-DSS",
  disa_stig: "DISA STIG",
  irap: "IRAP / ISM",
  ismap: "ISMAP",
};

function frameworks(
  fedramp: string,
  cmmc: string,
  soc2: string,
  cis: string,
  pci: string,
  stig: string,
  irap: string,
  ismap: string,
): WebexFrameworkMap {
  const list = (value: string): string[] => value ? [value] : [];
  return { fedramp: list(fedramp), cmmc: list(cmmc), soc2: list(soc2), cis: list(cis), pci_dss: list(pci), disa_stig: list(stig), irap: list(irap), ismap: list(ismap) };
}

export const WEBEX_CONTROL_FRAMEWORKS: Record<number, WebexFrameworkMap> = {
  1: frameworks("IA-2(1)", "L2 3.5.3", "CC6.1", "16.2", "8.4.1", "SRG-APP-000148", "ISM-1546", "CPS-7.1"),
  2: frameworks("IA-2(2)", "L2 3.5.3", "CC6.1", "16.3", "8.4.2", "SRG-APP-000149", "ISM-1401", "CPS-7.2"),
  3: frameworks("AU-1", "L2 3.3.2", "CC7.2", "8.1", "12.5.2", "SRG-APP-000516", "ISM-0042", "CPS-12.1"),
  4: frameworks("AC-4", "L2 3.1.3", "CC6.6", "13.4", "1.3.7", "SRG-APP-000100", "ISM-1528", "CPS-11.1"),
  5: frameworks("AC-4(1)", "L2 3.1.3", "CC6.7", "13.4", "1.3.7", "SRG-APP-000100", "ISM-0947", "CPS-11.2"),
  6: frameworks("SC-28", "L2 3.13.16", "CC6.7", "14.8", "3.4.1", "SRG-APP-000428", "ISM-0457", "CPS-11.3"),
  7: frameworks("SI-12", "L2 3.8.9", "CC6.5", "14.8", "3.1", "SRG-APP-000504", "ISM-0859", "CPS-12.2"),
  8: frameworks("SC-8(1)", "L2 3.13.8", "CC6.7", "14.4", "4.1", "SRG-APP-000441", "ISM-0484", "CPS-11.4"),
  9: frameworks("AC-3", "L2 3.1.1", "CC6.1", "16.7", "7.1.3", "SRG-APP-000033", "ISM-1506", "CPS-8.1"),
  10: frameworks("IA-5", "L2 3.5.7", "CC6.1", "16.5", "8.2.3", "SRG-APP-000170", "ISM-1557", "CPS-7.3"),
  11: frameworks("AU-11", "L2 3.3.1", "CC7.3", "8.3", "10.7", "SRG-APP-000515", "ISM-0859", "CPS-12.3"),
  12: frameworks("SI-12", "L2 3.8.9", "CC6.5", "14.8", "3.1", "SRG-APP-000504", "ISM-0859", "CPS-12.4"),
  13: frameworks("AC-14", "L2 3.1.1", "CC6.1", "16.7", "7.1.3", "SRG-APP-000033", "ISM-1506", "CPS-8.2"),
  14: frameworks("AC-16", "L2 3.13.12", "CC6.7", "14.1", "9.6.1", "SRG-APP-000311", "ISM-0271", "CPS-11.5"),
  15: frameworks("CM-8", "L2 3.4.1", "CC6.8", "1.1", "2.4", "SRG-APP-000383", "ISM-1409", "CPS-10.1"),
  16: frameworks("SI-4", "L2 3.14.6", "CC7.1", "1.1", "10.6", "SRG-APP-000516", "ISM-0576", "CPS-12.5"),
  17: frameworks("SI-2", "L2 3.14.1", "CC7.1", "7.4", "6.2", "SRG-APP-000456", "ISM-1143", "CPS-13.1"),
  18: frameworks("CM-8(3)", "L2 3.4.1", "CC6.8", "1.4", "9.7.1", "SRG-APP-000383", "ISM-1482", "CPS-10.2"),
  19: frameworks("CM-7", "L2 3.4.6", "CC6.8", "4.8", "2.2.2", "SRG-APP-000141", "ISM-1407", "CPS-10.3"),
  20: frameworks("SC-8(1)", "L2 3.13.8", "CC6.7", "14.4", "4.1", "SRG-APP-000441", "ISM-0484", "CPS-11.6"),
  21: frameworks("SC-7(8)", "L2 3.13.1", "CC6.7", "13.4", "1.3.7", "SRG-APP-000516", "ISM-0947", "CPS-11.7"),
  22: frameworks("SC-8", "L2 3.13.8", "CC6.7", "14.4", "4.1", "SRG-APP-000439", "ISM-0484", "CPS-11.8"),
  23: frameworks("AC-3", "L2 3.1.1", "CC6.1", "", "", "SRG-APP-000033", "", ""),
  24: frameworks("CM-8", "L2 3.4.1", "CC6.8", "1.1", "2.4", "SRG-APP-000383", "ISM-1409", "CPS-10.4"),
  25: frameworks("AU-12", "L2 3.3.1", "CC7.2", "8.5", "10.2.2", "SRG-APP-000507", "ISM-0580", "CPS-12.6"),
};

const PERSON_FIELDS: WebexSurfaceSpec = { id: true, displayName: true, emails: true, type: true, roles: true, orgId: true, created: true };
const ORGANIZATION_FIELDS: WebexSurfaceSpec = { id: true, displayName: true, created: true };
const SITE_FIELDS: WebexSurfaceSpec = { siteUrl: true, default: true };
const SECURITY_OPTIONS_FIELDS: WebexSurfaceSpec = {
  joinBeforeHost: true,
  audioBeforeHost: true,
  firstAttendeeAsPresenter: true,
  unlistAllMeetings: true,
  requireLoginBeforeAccess: true,
  allowMobileScreenCapture: true,
  requireStrongPassword: true,
  passwordCriteria: {
    mixedCase: true,
    minLength: true,
    minNumeric: true,
    minAlpha: true,
    minSpecial: true,
    disallowDynamicWebText: true,
    disallowList: true,
    disallowValues: true,
  },
};

export const WEBEX_SURFACE_FIELDS = {
  me: PERSON_FIELDS,
  organizations: ORGANIZATION_FIELDS,
  organization: ORGANIZATION_FIELDS,
  people: PERSON_FIELDS,
  roles: { id: true, name: true },
  guest_count: { count: true },
  licenses: { id: true, name: true, totalUnits: true, consumedUnits: true, subscriptionId: true, siteUrl: true, siteType: true },
  events: { id: true, resource: true, type: true, actorId: true, actorOrgId: true, orgId: true, created: true },
  admin_audit_events: { id: true, actorId: true, actorOrgId: true, targetOrgId: true, created: true, data: { eventCategory: true, eventDescription: true, actionText: true, actorEmail: true, actorName: true, adminRoles: true, targetType: true, targetName: true } },
  admin_recordings: { id: true, meetingId: true, topic: true, createTime: true, timeRecorded: true, hostEmail: true, siteUrl: true, downloadUrl: true, playbackUrl: true, format: true, serviceType: true, durationSeconds: true, sizeBytes: true, status: true },
  rooms: { id: true, title: true, type: true, isLocked: true, isPublic: true, classificationId: true, teamId: true, ownerId: true, created: true, lastActivity: true },
  webhooks: { id: true, name: true, targetUrl: true, resource: true, event: true, secret: true, status: true, ownedBy: true, created: true },
  meeting_preferences: {
    personalMeetingRoom: { enabledAutoLock: true, autoLockMinutes: true, notifyHost: true, supportCoHost: true, supportAnyoneAsCoHost: true, allowFirstUserToBeCoHost: true, allowAuthenticatedDevices: true },
    audio: { defaultAudioType: true, enabledGlobalCallIn: true, enabledTollFree: true, enabledAutoConnection: true },
    schedulingOptions: { enabledJoinBeforeHost: true, joinBeforeHostMinutes: true, enabledAutoShareRecording: true, enabledWebexAssistantByDefault: true },
    sites: SITE_FIELDS,
  },
  meeting_sites: SITE_FIELDS,
  meeting_common_settings: { siteUrl: true, securityOptions: SECURITY_OPTIONS_FIELDS },
  meetings: { id: true, title: true, meetingType: true, state: true, start: true, end: true, hostEmail: true, siteUrl: true, webLink: true, password: true, unlockedMeetingJoinSecurity: true, enabledJoinBeforeHost: true, joinBeforeHostMinutes: true, enableAutomaticLock: true, automaticLockMinutes: true, publicMeeting: true },
  hybrid_clusters: { id: true, name: true, orgId: true, resourceGroupId: true },
  hybrid_connectors: { id: true, orgId: true, hybridClusterId: true, hostname: true, type: true, version: true, status: true, created: true },
  devices: { id: true, displayName: true, workspaceId: true, personId: true, orgId: true, product: true, type: true, software: true, upgradeChannel: true, connectionStatus: true, managedBy: true, created: true },
  workspaces: { id: true, displayName: true, type: true, orgId: true, created: true },
} as const satisfies Record<string, WebexSurfaceSpec>;

export type WebexSurfaceName = keyof typeof WEBEX_SURFACE_FIELDS;

function flattenedFields(spec: WebexSurfaceSpec, prefix = ""): string[] {
  return Object.entries(spec).flatMap(([key, value]) => {
    const path = prefix ? `${prefix}.${key}` : key;
    return value === true ? [path] : flattenedFields(value, path);
  });
}

const CONTROL_TITLES = [
  "SSO enforcement",
  "Admin MFA",
  "Compliance officer role",
  "External communications",
  "File sharing restrictions",
  "Recording storage control",
  "Recording retention",
  "End-to-end meeting encryption",
  "Meeting lobby controls",
  "Meeting password required",
  "eDiscovery and legal hold",
  "Data retention policy",
  "Guest access restrictions",
  "Space classification",
  "Hybrid cluster health",
  "Hybrid connector status",
  "Device firmware currency",
  "Unmanaged device blocking",
  "Bot management",
  "Webhook transport and signing",
  "Messaging data loss prevention",
  "Calling encryption",
  "Virtual background policy",
  "License utilization",
  "Admin activity audit",
] as const;

const WEBEX_CONTROLS: ControlContract[] = CONTROL_TITLES.map((title, index) => ({
  number: index + 1,
  title,
  frameworks: WEBEX_CONTROL_FRAMEWORKS[index + 1],
}));

function criteria(
  pass: string,
  warn: string,
  fail: string,
  manual: string,
  constants: VerdictCriteria["constants"] = {},
  emitted: { compliant?: "pass" | "manual"; noncompliant?: "fail" | "warn" | "manual"; partial?: "warn" | "manual" } = {},
): VerdictCriteria {
  const compliant = emitted.compliant ?? "pass";
  const noncompliant = emitted.noncompliant ?? "fail";
  const partial = emitted.partial ?? "warn";
  return {
    pass,
    warn,
    fail,
    manual,
    constants,
    examples: [
      { kind: "compliant", input: pass, expected: compliant, reason: compliant === "pass" ? "Complete evidence satisfies the pass predicate." : "The setting has no documented read interface, so compliant evidence remains manual." },
      { kind: "noncompliant", input: fail, expected: noncompliant, reason: `The noncompliant predicate emits ${noncompliant}.` },
      { kind: "partial", input: warn, expected: partial, reason: `The partial case emits ${partial}.` },
      { kind: "unreadable", input: manual, expected: "manual", reason: "The required source cannot be evaluated automatically." },
    ],
  };
}

const ALWAYS_MANUAL = (instruction: string): VerdictCriteria => criteria(
  "No automatic pass is emitted.",
  "No automatic warn is emitted unless supporting inventory is partial.",
  "No automatic fail is emitted.",
  instruction,
  {},
  { compliant: "manual", noncompliant: "manual", partial: "manual" },
);

function check(
  id: string,
  controlNumbers: readonly number[],
  title: string,
  severity: CheckContract["severity"],
  owningTool: string,
  sourceSurfaceIds: readonly string[],
  verdictCriteria: VerdictCriteria,
): CheckContract {
  return { id, controlNumbers, title, severity, owningTool, sourceSurfaceIds, criteria: verdictCriteria };
}

const IDENTITY_TOOL = "webex_assess_identity";
const COLLAB_TOOL = "webex_assess_collaboration_governance";
const MEETING_TOOL = "webex_assess_meeting_hybrid_security";

export const WEBEX_CHECKS: readonly CheckContract[] = [
  check("WEBEX-ID-01", [1], "SSO enforcement", "critical", IDENTITY_TOOL, ["organization"], ALWAYS_MANUAL("Export Control Hub Organization Settings > Authentication showing SSO enabled; the Organizations read exposes only id, displayName, and created.")),
  check("WEBEX-ID-02", [2], "Admin MFA enforcement", "critical", IDENTITY_TOOL, ["people", "roles"], ALWAYS_MANUAL("Export Control Hub Organization Settings > Authentication and the administrator list with MFA status for every administrator; the only documented mfaEnabled shape is on a write request and People has no MFA field.")),
  check("WEBEX-ID-03", [3], "Compliance Officer assignment", "high", IDENTITY_TOOL, ["people", "roles"], criteria(
    "People and roles are readable, the people population is nonempty and complete, and at least one human has a role whose name contains 'Compliance Officer' case-insensitively.",
    "At least one Compliance Officer is visible, but the people listing is truncated.",
    "People and roles are readable and the nonempty people population contains no Compliance Officer.",
    "People or roles is unreadable, or GET /people returns zero people; export the Control Hub Users list filtered to Compliance Officer.",
    { roleNameContains: WEBEX_VERDICT_VALUES.complianceOfficerRolePattern },
  )),
  check("WEBEX-ID-04", [25], "Administrative privilege concentration", "medium", IDENTITY_TOOL, ["people", "roles"], criteria(
    "People and roles are readable and complete, at least one human has a role containing 'Administrator', and the administrator count is at most max_admins.",
    "No administrator is visible, the people list is truncated, or administrator count exceeds max_admins; max_admins defaults to 10.",
    "No fail verdict is emitted; concentration above the threshold requires review rather than proving noncompliance.",
    "People or roles is unreadable, or GET /people returns zero people; export the Control Hub administrator list.",
    { administratorRoleContains: WEBEX_VERDICT_VALUES.administratorRolePattern, defaultMaxAdmins: WEBEX_DEFAULTS.maxAdmins },
    { noncompliant: "warn" },
  )),
  check("WEBEX-ID-05", [19], "Bot account inventory", "medium", IDENTITY_TOOL, ["people"], criteria(
    "GET /people is readable, nonempty and complete; inventory records every Person.type equal to 'bot'.",
    "GET /people is readable and nonempty but truncated.",
    "No fail verdict is emitted because bot presence is an inventory for comparison with the approved register.",
    "GET /people is unreadable or returns zero people; export Control Hub Apps > Bots.",
    { botPersonType: WEBEX_VERDICT_VALUES.botPersonType },
    { noncompliant: "warn" },
  )),
  check("WEBEX-ID-06", [19], "Bot approval state", "medium", IDENTITY_TOOL, ["people"], ALWAYS_MANUAL("Export Control Hub Management > Apps bot management and reconcile it with WEBEX-ID-05; no documented read field exposes bot approval state.")),
  check("WEBEX-ID-07", [13], "Guest account inventory", "medium", IDENTITY_TOOL, ["people", "guest-count"], criteria(
    "GET /people is readable, nonempty and complete, GET /guests/count is readable, and Person.type='appuser' records are inventoried for reconciliation with WEBEX-MTG-03.",
    "The people listing is truncated or GET /guests/count is unreadable, so the otherwise complete inventory cannot pass.",
    "No fail verdict is emitted because the inventory does not itself settle guest-access policy.",
    "GET /people is unreadable or returns zero people; export the Control Hub guest user list.",
    { guestPersonType: WEBEX_VERDICT_VALUES.guestPersonType },
    { noncompliant: "warn" },
  )),
  check("WEBEX-COLLAB-01", [4], "External communications policy", "high", COLLAB_TOOL, ["organization"], ALWAYS_MANUAL("Export Control Hub Messaging external communication allow-list settings; no documented read endpoint exposes the policy.")),
  check("WEBEX-COLLAB-02", [5, 21], "File sharing restrictions and messaging DLP", "high", COLLAB_TOOL, ["events"], ALWAYS_MANUAL("Export Control Hub file-sharing controls and DLP or CASB integration evidence; Events is supporting inventory only and exposes no policy-state field.")),
  check("WEBEX-COLLAB-03", [6, 7, 12], "Recording storage and retention governance", "medium", COLLAB_TOOL, ["admin-recordings"], ALWAYS_MANUAL("Export Control Hub recording and messaging retention and storage settings; the admin recordings read exposes recordings but no retention or storage-location policy.")),
  check("WEBEX-COLLAB-04", [14], "Space classification coverage", "medium", COLLAB_TOOL, ["rooms", "me"], criteria(
    "Rooms is readable and nonempty, every visible room has classificationId, the listing is complete, and token type is verified as non-bot.",
    "Every visible room has classificationId but the listing is truncated, the token is a bot, or GET /people/me cannot prove token type.",
    "At least one visible room lacks classificationId.",
    "Rooms is unreadable or empty; export Control Hub space classification settings.",
    {},
  )),
  check("WEBEX-COLLAB-05", [20], "Webhook HTTPS and signing secret", "high", COLLAB_TOOL, ["webhooks", "me"], criteria(
    "Webhooks is readable and nonempty, every visible webhook targetUrl starts with 'https://' and has a nonempty secret, the list is complete, and token type is verified as non-bot.",
    "Every visible webhook is secure but the list is truncated, the token is a bot, or token type cannot be verified.",
    "At least one visible webhook lacks an HTTPS targetUrl or a nonempty signing secret.",
    "Webhooks is unreadable or empty; collect webhook inventories from every integration owner.",
    { secureTargetPrefix: WEBEX_VERDICT_VALUES.secureWebhookPrefix },
  )),
  check("WEBEX-COLLAB-06", [24], "License utilization review", "low", COLLAB_TOOL, ["licenses"], criteria(
    "Licenses is readable and complete, totalUnits is positive, and unassigned units divided by total units is at most 0.20.",
    "The unassigned ratio exceeds 0.20 or the license listing is truncated.",
    "No fail verdict is emitted; excess unassigned capacity is a review condition.",
    "Licenses is unreadable, empty, or has totalUnits equal to zero; export the Control Hub subscriptions and usage report.",
    { maximumUnassignedRatio: WEBEX_VERDICT_VALUES.maximumUnassignedLicenseRatio },
    { noncompliant: "warn" },
  )),
  check("WEBEX-COLLAB-07", [25], "Admin activity audit visibility", "high", COLLAB_TOOL, ["admin-audit-events"], criteria(
    "Admin audit events is readable, nonempty and complete for the last 30 days.",
    "The read returns zero events or is truncated; confirm the log is populated and reviewed.",
    "No fail verdict is emitted because an empty window needs reviewer confirmation.",
    "Organization context is unavailable or admin audit events is unreadable; export the Control Hub admin audit log.",
    { windowDays: WEBEX_VERDICT_VALUES.adminAuditWindowDays },
    { noncompliant: "warn" },
  )),
  check("WEBEX-COLLAB-08", [11], "eDiscovery and legal hold capability", "high", COLLAB_TOOL, ["events"], ALWAYS_MANUAL("Export Control Hub eDiscovery and legal-hold configuration; the public compliance guide exposes no read endpoint for configuration and events older than 90 days require Pro Pack.")),
  check("WEBEX-MTG-01", [8, 22], "Meeting E2EE and calling SRTP defaults", "high", MEETING_TOOL, ["meeting-preferences", "meeting-common-settings"], ALWAYS_MANUAL("Export the Control Hub meeting session type showing end-to-end encryption and the calling security configuration showing SRTP; the documented reads expose neither setting.")),
  check("WEBEX-MTG-02", [9], "Meeting lobby and join-before-host defaults", "high", MEETING_TOOL, ["meeting-sites", "meeting-common-settings", "meetings", "meeting-preferences", "me"], criteria(
    "Every readable site reports joinBeforeHost=false, audioBeforeHost=false and unlistAllMeetings=true; the site list and all sites are complete; meetings, meeting preferences and token type are readable.",
    "joinBeforeHost=false but audioBeforeHost is absent or unlistAllMeetings is not true, or otherwise-passing evidence has partial site or secondary coverage.",
    "Any site reports joinBeforeHost=true or audioBeforeHost=true.",
    "No site common settings are readable or any site omits joinBeforeHost; collect each site's Control Hub Common Settings > Security page.",
    { joinBeforeHost: false, audioBeforeHost: false, unlistAllMeetings: true },
  )),
  check("WEBEX-MTG-03", [13], "Guest meeting access policy", "medium", MEETING_TOOL, ["meeting-sites", "meeting-common-settings", "me"], criteria(
    "Every readable site reports requireLoginBeforeAccess=true, site coverage is complete, and token type is readable.",
    "All readable sites require login but site coverage or token-type evidence is partial.",
    "Any readable site reports requireLoginBeforeAccess=false.",
    "No site common settings are readable or any site omits requireLoginBeforeAccess; collect each site's Control Hub Common Settings > Security page.",
    { requireLoginBeforeAccess: true },
  )),
  check("WEBEX-MTG-04", [15, 16], "Hybrid cluster and connector health", "high", MEETING_TOOL, ["hybrid-clusters", "hybrid-connectors"], criteria(
    "Both inventories are readable, at least one connector exists, every connector status equals 'operational', and neither listing is truncated.",
    "Every connector is operational but either listing is truncated.",
    "Clusters exist with no connectors, or any connector status is not 'operational'.",
    "Either inventory is unreadable, or both are empty and deployment applicability must be confirmed in Control Hub.",
    { operationalStatus: WEBEX_VERDICT_VALUES.operationalConnectorStatus },
  )),
  check("WEBEX-MTG-05", [17, 18], "Device firmware and management posture", "high", MEETING_TOOL, ["devices", "workspaces"], ALWAYS_MANUAL("Compare inventoried software and upgrade channels with Cisco RoomOS lifecycle guidance and export the Control Hub device activation policy; documented device reads expose no end-of-life or blocking-policy field.")),
  check("WEBEX-MTG-06", [10], "Meeting password policy", "high", MEETING_TOOL, ["meeting-sites", "meeting-common-settings", "meetings", "meeting-preferences", "me"], criteria(
    "Every readable site reports requireStrongPassword=true and passwordCriteria.minLength at least 8; site coverage and all secondary evidence are complete.",
    "Strong passwords are required but minLength is absent or below 8, or otherwise-passing evidence has partial site or secondary coverage.",
    "Any readable site reports requireStrongPassword=false.",
    "No site common settings are readable or any site omits requireStrongPassword; collect each site's Control Hub Common Settings > Security page.",
    { minimumLength: WEBEX_VERDICT_VALUES.minimumMeetingPasswordLength },
  )),
  check("WEBEX-MTG-07", [23], "Virtual background policy", "low", MEETING_TOOL, ["meeting-common-settings"], ALWAYS_MANUAL("Export the Control Hub meeting settings page for virtual backgrounds; no field is exposed by meeting preferences, common settings, or session types.")),
];

const API_SURFACE_INPUTS = [
  ["me", WEBEX_ENDPOINTS.me, WEBEX_DOCS.peopleMe, "me"],
  ["organizations", WEBEX_ENDPOINTS.organizations, WEBEX_DOCS.organizationsList, "organizations"],
  ["organization", WEBEX_ENDPOINTS.organization, WEBEX_DOCS.organizationGet, "organization"],
  ["people", WEBEX_ENDPOINTS.people, WEBEX_DOCS.peopleList, "people"],
  ["roles", WEBEX_ENDPOINTS.roles, WEBEX_DOCS.rolesList, "roles"],
  ["licenses", WEBEX_ENDPOINTS.licenses, WEBEX_DOCS.licensesList, "licenses"],
  ["events", WEBEX_ENDPOINTS.events, WEBEX_DOCS.eventsList, "events"],
  ["admin-audit-events", WEBEX_ENDPOINTS.adminAuditEvents, WEBEX_DOCS.adminAuditEvents, "admin_audit_events"],
  ["admin-recordings", WEBEX_ENDPOINTS.adminRecordings, WEBEX_DOCS.adminRecordings, "admin_recordings"],
  ["guest-count", WEBEX_ENDPOINTS.guestCount, WEBEX_DOCS.guestCount, "guest_count"],
  ["hybrid-clusters", WEBEX_ENDPOINTS.hybridClusters, WEBEX_DOCS.hybridClusters, "hybrid_clusters"],
  ["hybrid-connectors", WEBEX_ENDPOINTS.hybridConnectors, WEBEX_DOCS.hybridConnectors, "hybrid_connectors"],
  ["meetings", WEBEX_ENDPOINTS.meetings, WEBEX_DOCS.meetingsList, "meetings"],
  ["meeting-preferences", WEBEX_ENDPOINTS.meetingPreferences, WEBEX_DOCS.meetingPreferences, "meeting_preferences"],
  ["meeting-sites", WEBEX_ENDPOINTS.meetingSites, WEBEX_DOCS.meetingSites, "meeting_sites"],
  ["meeting-common-settings", WEBEX_ENDPOINTS.meetingCommonSettings, WEBEX_DOCS.meetingCommonSettings, "meeting_common_settings"],
  ["devices", WEBEX_ENDPOINTS.devices, WEBEX_DOCS.devicesList, "devices"],
  ["workspaces", WEBEX_ENDPOINTS.workspaces, WEBEX_DOCS.workspacesList, "workspaces"],
  ["rooms", WEBEX_ENDPOINTS.rooms, WEBEX_DOCS.roomsList, "rooms"],
  ["webhooks", WEBEX_ENDPOINTS.webhooks, WEBEX_DOCS.webhooksList, "webhooks"],
] as const;

const WEBEX_GET_HEADERS = ["Accept: application/json", "Authorization: Bearer <access token>"] as const;

function webexRequest(
  parameters: RequestContract["parameters"] = [],
  responseShape = "JSON object; list operations read the items array and also accept a top-level array.",
): RequestContract {
  return {
    clientRegion: "The configured Webex API origin; there is no regional client selection.",
    headers: WEBEX_GET_HEADERS,
    parameters,
    responseShape,
  };
}

const orgIdParameter = { name: "orgId", location: "query", required: false, value: "Configured organization identifier", when: "Only when org_id is configured." } as const;
const listLimitParameter = (maximum: number) => ({ name: "max", location: "query" as const, required: false, value: String(maximum), when: "Sent on every page for this surface." });

export const WEBEX_REQUESTS: Readonly<Record<string, RequestContract>> = {
  "token-refresh": {
    clientRegion: "The configured Webex API origin.",
    headers: ["Content-Type: application/x-www-form-urlencoded", "Accept: application/json"],
    parameters: [
      { name: "grant_type", location: "form-body", required: true, value: "refresh_token" },
      { name: "client_id", location: "form-body", required: true, value: "Configured client identifier" },
      { name: "client_secret", location: "form-body", required: true, value: "Configured client secret" },
      { name: "refresh_token", location: "form-body", required: true, value: "Configured refresh token" },
    ],
    responseShape: "JSON object containing a nonempty access_token string.",
  },
  me: webexRequest(),
  organizations: webexRequest(),
  organization: webexRequest([{ name: "orgId", location: "path", required: true, value: "URL-encoded organization identifier" }]),
  people: webexRequest([orgIdParameter, listLimitParameter(WEBEX_PAGE_MAX.people)]),
  roles: webexRequest(),
  licenses: webexRequest([orgIdParameter]),
  events: webexRequest([listLimitParameter(WEBEX_PAGE_MAX.events)]),
  "admin-audit-events": webexRequest([
    { name: "orgId", location: "query", required: true, value: "Resolved organization identifier" },
    { name: "from", location: "query", required: true, value: `Current time minus ${WEBEX_VERDICT_VALUES.adminAuditWindowDays} days, ISO 8601` },
    { name: "to", location: "query", required: true, value: "Current time, ISO 8601" },
    listLimitParameter(WEBEX_PAGE_MAX.adminAudit),
  ]),
  "admin-recordings": webexRequest([listLimitParameter(WEBEX_PAGE_MAX.adminRecordings)]),
  "guest-count": webexRequest([], "A bare decimal count in text/plain or a JSON object containing one numeric value."),
  "hybrid-clusters": webexRequest([orgIdParameter]),
  "hybrid-connectors": webexRequest([orgIdParameter]),
  meetings: webexRequest([listLimitParameter(WEBEX_PAGE_MAX.meetings)]),
  "meeting-preferences": webexRequest(),
  "meeting-sites": webexRequest(),
  "meeting-common-settings": webexRequest([
    { name: "siteUrl", location: "query", required: false, value: "One site URL from meeting-sites", when: "Once per listed site; omit only for the preferred-site fallback." },
  ]),
  devices: webexRequest([orgIdParameter, listLimitParameter(WEBEX_PAGE_MAX.devices)]),
  workspaces: webexRequest([orgIdParameter, listLimitParameter(WEBEX_PAGE_MAX.workspaces)]),
  rooms: webexRequest([listLimitParameter(WEBEX_PAGE_MAX.rooms)]),
  webhooks: webexRequest([listLimitParameter(WEBEX_PAGE_MAX.webhooks)]),
};

const WEBEX_EXPORT = {
  files: [
    "QUICK_REFERENCE.md",
    "metadata.json",
    "core_data/access.json",
    "core_data/{category}/{surface}.json",
    "analysis/{category}.json",
    "analysis/findings.json",
    "compliance/executive_summary.md",
    "compliance/unified_compliance_matrix.md",
    "compliance/{framework}/{report}.md",
  ],
  conditionalFiles: ["_errors.log"],
  artifacts: [
    { path: "QUICK_REFERENCE.md", format: "markdown", requiredWhen: "Always", schema: "Heading, five bundle-orientation bullets, then a four-step recommended reading order.", serialization: "UTF-8 with a trailing newline." },
    { path: "metadata.json", format: "json", requiredWhen: "Always", schema: "Object: generated_at string, org_id string|null, token_type person|bot|appuser|unknown, source_chain string[], config_file basename|string|null.", serialization: "Scrub recursively, then two-space JSON with insertion-order keys and one trailing newline." },
    { path: "core_data/access.json", format: "json", requiredWhen: "Always", schema: "WebexAccessCheckResult record described below.", serialization: "Scrub recursively, then two-space JSON with insertion-order keys and one trailing newline." },
    { path: "core_data/{category}/{surface}.json", format: "json", requiredWhen: "For every collected assessment surface", schema: "Readable surface: projected object or array using that surface allowlist. Unreadable surface: {error: scrubbed string, status: number|null}.", serialization: "Project first, scrub recursively, then two-space JSON with one trailing newline." },
    { path: "analysis/{category}.json", format: "json", requiredWhen: "For identity, collaboration-governance and meeting-hybrid-security", schema: "Object: title string, category string, summary object, findings WebexFinding[], errors string[].", serialization: "Scrub recursively, then two-space JSON with insertion-order keys and one trailing newline." },
    { path: "analysis/findings.json", format: "json", requiredWhen: "Always", schema: "Array of WebexFinding records in assessment order: identity, collaboration governance, meeting/hybrid.", serialization: "Scrub recursively, then two-space JSON with one trailing newline." },
    { path: "compliance/executive_summary.md", format: "markdown", requiredWhen: "Always", schema: "Org and generated timestamp; Result Counts; Highest Priority Findings sorted by status rank and capped at 12; optional Partial Collection Warnings.", serialization: "UTF-8 Markdown with one trailing newline." },
    { path: "compliance/unified_compliance_matrix.md", format: "markdown", requiredWhen: "Always", schema: "Finding, spec control, uppercase status, then one column for each of eight frameworks.", serialization: "UTF-8 Markdown table with one trailing newline." },
    { path: "compliance/{framework}/{report}.md", format: "markdown", requiredWhen: "One file for every configured framework", schema: "Framework heading, mapped-finding count, then Requirement, Finding, Status, Title, Summary table.", serialization: "UTF-8 Markdown with one trailing newline." },
    { path: "_errors.log", format: "text", requiredWhen: "At least one assessment collection error exists", schema: "Deduplicated lines prefixed by assessment category, one error per line.", serialization: "UTF-8 text with one final newline." },
    { path: "{allocated-bundle-name}.zip", format: "zip", requiredWhen: "Always after directory files are complete", schema: "Archive contains every bundle file under relative paths with no enclosing bundle directory.", serialization: "Zip archive paired to the exact allocated directory basename; credentials are scrubbed before files enter the archive." },
  ],
  overwritePolicy: "Allocate a new suffixed bundle directory on every rerun; never replace an earlier bundle.",
  pathSafetyPolicy: "Reject traversal, output roots outside the configured parent, symlink roots, and symlinked parent directories.",
  archivePairing: "Write a zip archive beside the bundle directory using the exact allocated directory name plus .zip.",
  recordSchemas: {
    WebexFinding: ["id:string", "control:number[]", "title:string", "severity:critical|high|medium|low|info", "status:pass|warn|fail|manual", "summary:string", "evidence?:object", "mappings:string[]", "frameworks:{fedramp,cmmc,soc2,cis,pci_dss,disa_stig,irap,ismap}:string[]"],
    WebexAssessment: ["title:string", "category:string", "summary:object", "findings:WebexFinding[]", "errors:string[]", "rawData:surface-name -> projected value or unreadable marker"],
    WebexAccessCheckResult: ["status:healthy|limited", "orgId?:string", "tokenType:person|bot|appuser|unknown", "adminCapable:boolean", "surfaces:WebexAccessSurface[]", "notes:string[]", "recommendedNextStep:string"],
    WebexAccessSurface: ["name:string", "endpoint:string", "doc:string", "status:readable|not_readable|not_configured|manual", "count?:number", "truncated?:boolean", "error?:string"],
    UnreadableSurface: ["error:scrubbed string", "status:number|null"],
  },
  jsonFormatting: "Before every JSON write, recursively scrub the complete value. Serialize with two-space indentation, preserve object insertion order, encode dates as ISO strings through normal JSON conversion, and append exactly one newline.",
} as const;

export const WEBEX_SPEC: IntegrationSpecContract = {
  identity: {
    slug: "webex-sec-inspector",
    displayName: "Webex Security Inspector",
    vendor: "Cisco",
    category: "saas-collaboration",
    kind: "security-inspector",
    version: "2.0",
    lastUpdated: "2026-09-27",
    summary: "Read-only Webex organization posture inspection across identity, collaboration governance, meetings, hybrid services, and devices.",
  },
  sourceModule: "cli/extensions/grc-tools/webex.spec.ts",
  baseServices: ["https://webexapis.com/v1"],
  apiSurfaces: [
    {
      id: "token-refresh",
      kind: "rest",
      method: "POST",
      path: WEBEX_ENDPOINTS.tokenRefresh,
      baseService: "https://webexapis.com/v1",
      documentationUrl: WEBEX_DOCS.integrations,
      fieldsConsumed: ["access_token"],
      projectionStage: "Authentication only. The access token is never exported.",
      request: WEBEX_REQUESTS["token-refresh"],
      intent: "auth-only",
    },
    ...API_SURFACE_INPUTS.map(([id, path, documentationUrl, projection]) => ({
      id,
      kind: "rest" as const,
      method: "GET" as const,
      path,
      baseService: "https://webexapis.com/v1",
      documentationUrl,
      fieldsConsumed: flattenedFields(WEBEX_SURFACE_FIELDS[projection]),
      projectionStage: "Fields name the normalized record written under core_data after allowlist projection and secret scrubbing.",
      request: WEBEX_REQUESTS[id],
      intent: id === "me" ? "auth-only" as const : "read" as const,
    })),
  ],
  authentication: {
    modes: ["Existing OAuth access token", "OAuth refresh-token exchange for an integration or service application"],
    credentialPrecedence: ["Explicit tool arguments", "Environment variables", "Configured file", "Default user configuration file"],
    environmentVariables: Object.values(WEBEX_ENV),
    configLocations: ["Path named by WEBEX_CONFIG_FILE", "~/.config/webex-sec-inspector/config.json", "~/.config/webex-sec-inspector/config.yaml", "~/.config/webex-sec-inspector/config.yml"],
    variants: ["Person token", "Guest token", "Bot token", "Integration token", "Service application token"],
    refreshRequest: "POST /access_token with application/x-www-form-urlencoded grant_type=refresh_token, client_id, client_secret and refresh_token; require a JSON access_token.",
    configFields: ["token", "client_id", "client_secret", "refresh_token", "org_id", "base_url", "timeout_seconds"],
    malformedConfigBehavior: "Reject unreadable, invalid, or non-object JSON/YAML with a fixed Webex configuration error. Never include parser text, source text, or credential values.",
  },
  permissions: [
    { id: "own-details-read", kind: "oauth-scope", value: WEBEX_SCOPES.ownDetailsRead, unlocks: ["me"] },
    { id: "people-read", kind: "oauth-scope", value: WEBEX_SCOPES.peopleRead, unlocks: ["people"] },
    { id: "organizations-read", kind: "oauth-scope", value: WEBEX_SCOPES.organizationsRead, unlocks: ["organizations", "organization"] },
    { id: "roles-read", kind: "oauth-scope", value: WEBEX_SCOPES.rolesRead, unlocks: ["roles"] },
    { id: "licenses-read", kind: "oauth-scope", value: WEBEX_SCOPES.licensesRead, unlocks: ["licenses"] },
    { id: "devices-read", kind: "oauth-scope", value: WEBEX_SCOPES.devicesRead, unlocks: ["devices"] },
    { id: "workspaces-read", kind: "oauth-scope", value: WEBEX_SCOPES.workspacesRead, unlocks: ["workspaces"] },
    { id: "hybrid-read", kind: "oauth-scope", value: WEBEX_SCOPES.hybridRead, unlocks: ["hybrid-clusters", "hybrid-connectors"] },
    { id: "events-read", kind: "oauth-scope", value: WEBEX_SCOPES.eventsRead, unlocks: ["events"] },
    { id: "admin-audit-read", kind: "oauth-scope", value: WEBEX_SCOPES.adminAuditRead, unlocks: ["admin-audit-events"] },
    { id: "meetings-read", kind: "oauth-scope", value: WEBEX_SCOPES.meetingScheduleRead, unlocks: ["meetings"] },
    { id: "recordings-read", kind: "oauth-scope", value: WEBEX_SCOPES.adminRecordingsRead, unlocks: ["admin-recordings"] },
    { id: "guest-count-read", kind: "oauth-scope", value: WEBEX_SCOPES.guestIssuerRead, unlocks: ["guest-count"] },
    { id: "preferences-read", kind: "oauth-scope", value: WEBEX_SCOPES.meetingPreferencesRead, unlocks: ["meeting-preferences", "meeting-sites"] },
    { id: "meeting-config-read", kind: "oauth-scope", value: WEBEX_SCOPES.meetingAdminConfigRead, unlocks: ["meeting-common-settings"] },
    { id: "rooms-read", kind: "oauth-scope", value: WEBEX_SCOPES.roomsRead, unlocks: ["rooms"] },
    { id: "webhooks-read", kind: "oauth-scope", value: WEBEX_SCOPES.webhooksRead, unlocks: ["webhooks"] },
    { id: "pro-pack", kind: "plan", value: "Webex Pro Pack", unlocks: ["events", "admin-audit-events"], notes: "Some compliance and longer-retention evidence depends on the tenant plan." },
  ],
  pagination: [
    {
      surfaceIds: ["organizations", "people", "roles", "licenses", "events", "admin-audit-events", "admin-recordings", "hybrid-clusters", "hybrid-connectors", "meetings", "meeting-sites", "devices", "workspaces", "rooms", "webhooks"],
      cursorFields: ["Link header rel=next"],
      pageSize: null,
      itemCap: null,
      pageCap: WEBEX_DEFAULTS.maxListPages,
      totalSemantics: "The service does not provide a dependable total for these walks; report items seen and whether exhaustion was proven.",
      stopConditions: ["No next link", "Configured item cap", "Page cap", "Repeated next link", "Empty page with next link", "Rejected cross-origin or userinfo-bearing next link"],
    },
  ],
  rateLimits: [{
    scope: "Webex REST API",
    documentedLimit: null,
    retryHeaders: ["Retry-After"],
    retryableStatuses: [429],
    backoffPolicy: `Retry at most ${WEBEX_DEFAULTS.max429Retries} times, cap each Retry-After delay at ${WEBEX_DEFAULTS.maxRetryAfterMs} milliseconds, then report the surface unreadable.`,
  }],
  controls: WEBEX_CONTROLS,
  checks: WEBEX_CHECKS,
  collectionStates: {
    complete: "The requested surface was read to proven exhaustion.",
    truncated: "The surface returned data, but a cap or pagination anomaly prevented proven exhaustion.",
    unreadable: "The request failed or the response did not match the documented shape.",
    denied: "The service refused the request; record the endpoint and observed status without treating the inventory as empty.",
    notRequested: "A dependent request was never issued because its parent inventory was unreadable; name the parent and invent no status.",
    notConfigured: "The surface requires tenant or organization context that was not configured or discoverable.",
  },
  redaction: {
    sharedContractVersion: "1.1",
    projections: Object.fromEntries(Object.entries(WEBEX_SURFACE_FIELDS).map(([surface, fields]) => [surface, flattenedFields(fields)])),
    projectionStage: "Each raw Webex object is allowlist-projected before it enters rawData or core_data. Sensitive keys are then redacted recursively, and every JSON write scrubs the complete value again.",
    sensitiveFields: ["token", "client_secret", "refresh_token", "password", "secret", "targetUrl query", "downloadUrl query", "playbackUrl query", "webLink query"],
    benignExceptions: ["Documented resource identifiers", "Organization identifiers", "Site host names"],
    credentialFormats: ["Bearer credentials", "OAuth client secrets", "Refresh tokens", "Webhook signing secrets", "Meeting passwords", "Credential-bearing URL parameters"],
    integrationRules: [
      "A key containing token, secret, password, passcode, hostpin, hostkey, authorization, accesscode, activationcode, or credential is replaced with [REDACTED], except passwordCriteria, requireStrongPassword, and excludePassword policy objects.",
      "Authorization Bearer and Basic values, credential assignments, cookies, URL user information, URL query and fragment values, and SIP URI pwd/password/pin/passcode/token/secret parameters are replaced.",
      "Webhook targetUrl, recording downloadUrl/playbackUrl, meeting webLink, and other URL-valued exported strings retain scheme, host and path but lose query, fragment and user information.",
      "Configured token, client secret and refresh token values are removed from error text before status/length rendering; non-JSON bodies are represented only by media type and byte length.",
      "Projection retains password and secret fields only so their presence is represented as [REDACTED], never their value.",
    ],
  },
  output: WEBEX_EXPORT,
  tools: [
    { name: "webex_check_access", checkIds: [], resultSchema: "Text table plus structured fields {tool, status, orgId?, tokenType, adminCapable, surfaces, notes, recommendedNextStep}." },
    { name: IDENTITY_TOOL, checkIds: WEBEX_CHECKS.filter((item) => item.owningTool === IDENTITY_TOOL).map((item) => item.id), resultSchema: "Text summary/table plus structured fields {tool, title, category, summary, findings, errors, rawData}." },
    { name: COLLAB_TOOL, checkIds: WEBEX_CHECKS.filter((item) => item.owningTool === COLLAB_TOOL).map((item) => item.id), resultSchema: "Text summary/table plus structured fields {tool, title, category, summary, findings, errors, rawData}." },
    { name: MEETING_TOOL, checkIds: WEBEX_CHECKS.filter((item) => item.owningTool === MEETING_TOOL).map((item) => item.id), resultSchema: "Text summary/table plus structured fields {tool, title, category, summary, findings, errors, rawData}." },
    { name: "webex_export_audit_bundle", checkIds: WEBEX_CHECKS.map((item) => item.id), resultSchema: "Text export receipt plus structured fields {tool, output_dir, zip_path, finding_count, file_count, error_count}.", output: WEBEX_EXPORT },
  ],
};
