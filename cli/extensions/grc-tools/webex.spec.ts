import { join } from "node:path";
import type {
  CheckContract,
  ControlContract,
  FrameworkKey,
  IntegrationSpecContract,
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

export const WEBEX_DEFAULTS = {
  outputDir: "./export/webex",
  timeoutMs: 30_000,
  configDir: join(".config", "webex-sec-inspector"),
  configFileNames: ["config.json", "config.yaml", "config.yml"],
  maxRetryAfterMs: 30_000,
  max429Retries: 2,
  maxListPages: 1000,
  minimumMeetingPasswordLength: 8,
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
  adminAuditWindowDays: 30,
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
  peopleRead: "spark-admin:people_read",
  organizationsRead: "spark-admin:organizations_read",
  rolesRead: "spark-admin:roles_read",
  licensesRead: "spark-admin:licenses_read",
  devicesRead: "spark-admin:devices_read",
  hybridRead: "spark-admin:hybrid_clusters_read",
  eventsRead: "spark-compliance:events_read",
  meetingScheduleRead: "meeting:schedules_read or meeting:admin_schedule_read",
  meetingAdminScheduleRead: "meeting:admin_schedule_read",
  meetingRecordingsRead: "meeting:admin_recordings_read",
  meetingPreferencesRead: "meeting:preferences_read or meeting:admin_preferences_read",
  meetingAdminPreferencesRead: "meeting:admin_preferences_read",
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

const AUTOMATED_CRITERIA: VerdictCriteria = {
  pass: "Every required source is complete and the observed settings satisfy the check.",
  warn: "The evidence is partial, scope-limited, or requires reviewer attention without proving noncompliance.",
  fail: "Complete readable evidence proves that the required setting is absent or noncompliant.",
  manual: "A required source is unreadable, denied, not requested, or not exposed by a documented read interface.",
};

const MANUAL_CRITERIA: VerdictCriteria = {
  pass: "Not emitted automatically. A reviewer may record pass only after examining the named administrative evidence.",
  warn: "Readable supporting inventory is incomplete or indicates that manual review is still required.",
  fail: "Not emitted automatically unless a documented read surface directly proves noncompliance.",
  manual: "Collect the administrative evidence named by the finding because no documented read interface settles the control.",
};

function check(
  id: string,
  controlNumbers: readonly number[],
  title: string,
  severity: CheckContract["severity"],
  owningTool: string,
  sourceSurfaceIds: readonly string[],
  manual = false,
): CheckContract {
  return { id, controlNumbers, title, severity, owningTool, sourceSurfaceIds, criteria: manual ? MANUAL_CRITERIA : AUTOMATED_CRITERIA };
}

const IDENTITY_TOOL = "webex_assess_identity";
const COLLAB_TOOL = "webex_assess_collaboration_governance";
const MEETING_TOOL = "webex_assess_meeting_hybrid_security";

export const WEBEX_CHECKS: readonly CheckContract[] = [
  check("WEBEX-ID-01", [1], "SSO enforcement", "critical", IDENTITY_TOOL, ["organization"], true),
  check("WEBEX-ID-02", [2], "Admin MFA enforcement", "critical", IDENTITY_TOOL, ["people", "roles"], true),
  check("WEBEX-ID-03", [3], "Compliance Officer assignment", "high", IDENTITY_TOOL, ["people", "roles"]),
  check("WEBEX-ID-04", [25], "Administrative privilege concentration", "medium", IDENTITY_TOOL, ["people", "roles"]),
  check("WEBEX-ID-05", [19], "Bot account inventory", "medium", IDENTITY_TOOL, ["people"]),
  check("WEBEX-ID-06", [19], "Bot approval state", "medium", IDENTITY_TOOL, ["people"], true),
  check("WEBEX-ID-07", [13], "Guest account inventory", "medium", IDENTITY_TOOL, ["people", "guest-count"]),
  check("WEBEX-COLLAB-01", [4], "External communications policy", "high", COLLAB_TOOL, ["organization"], true),
  check("WEBEX-COLLAB-02", [5, 21], "File sharing restrictions and messaging DLP", "high", COLLAB_TOOL, ["events"], true),
  check("WEBEX-COLLAB-03", [6, 7, 12], "Recording storage and retention governance", "medium", COLLAB_TOOL, ["admin-recordings"], true),
  check("WEBEX-COLLAB-04", [14], "Space classification coverage", "medium", COLLAB_TOOL, ["rooms", "me"]),
  check("WEBEX-COLLAB-05", [20], "Webhook HTTPS and signing secret", "high", COLLAB_TOOL, ["webhooks", "me"]),
  check("WEBEX-COLLAB-06", [24], "License utilization review", "low", COLLAB_TOOL, ["licenses"]),
  check("WEBEX-COLLAB-07", [25], "Admin activity audit visibility", "high", COLLAB_TOOL, ["admin-audit-events"]),
  check("WEBEX-COLLAB-08", [11], "eDiscovery and legal hold capability", "high", COLLAB_TOOL, ["events"], true),
  check("WEBEX-MTG-01", [8, 22], "Meeting E2EE and calling SRTP defaults", "high", MEETING_TOOL, ["meeting-preferences", "meeting-common-settings"], true),
  check("WEBEX-MTG-02", [9], "Meeting lobby and join-before-host defaults", "high", MEETING_TOOL, ["meeting-sites", "meeting-common-settings", "meetings", "meeting-preferences", "me"]),
  check("WEBEX-MTG-03", [13], "Guest meeting access policy", "medium", MEETING_TOOL, ["meeting-sites", "meeting-common-settings", "me"]),
  check("WEBEX-MTG-04", [15, 16], "Hybrid cluster and connector health", "high", MEETING_TOOL, ["hybrid-clusters", "hybrid-connectors"]),
  check("WEBEX-MTG-05", [17, 18], "Device firmware and management posture", "high", MEETING_TOOL, ["devices", "workspaces"], true),
  check("WEBEX-MTG-06", [10], "Meeting password policy", "high", MEETING_TOOL, ["meeting-sites", "meeting-common-settings", "meetings", "meeting-preferences", "me"]),
  check("WEBEX-MTG-07", [23], "Virtual background policy", "low", MEETING_TOOL, ["meeting-common-settings"], true),
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
  overwritePolicy: "Allocate a new suffixed bundle directory on every rerun; never replace an earlier bundle.",
  pathSafetyPolicy: "Reject traversal, output roots outside the configured parent, symlink roots, and symlinked parent directories.",
  archivePairing: "Write a zip archive beside the bundle directory using the exact allocated directory name plus .zip.",
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
  apiSurfaces: API_SURFACE_INPUTS.map(([id, path, documentationUrl, projection]) => ({
    id,
    kind: "rest",
    method: "GET",
    path,
    baseService: "https://webexapis.com/v1",
    documentationUrl,
    fieldsConsumed: flattenedFields(WEBEX_SURFACE_FIELDS[projection]),
    intent: id === "me" ? "auth-only" : "read",
  })),
  authentication: {
    modes: ["Existing OAuth access token", "OAuth refresh-token exchange for an integration or service application"],
    credentialPrecedence: ["Explicit tool arguments", "Environment variables", "Configured file", "Default user configuration file"],
    environmentVariables: ["WEBEX_TOKEN", "WEBEX_CLIENT_ID", "WEBEX_CLIENT_SECRET", "WEBEX_REFRESH_TOKEN", "WEBEX_ORG_ID", "WEBEX_BASE_URL", "WEBEX_CONFIG_FILE"],
    configLocations: ["Path named by WEBEX_CONFIG_FILE", "~/.config/webex-sec-inspector/config.json", "~/.config/webex-sec-inspector/config.yaml", "~/.config/webex-sec-inspector/config.yml"],
    variants: ["Person token", "Guest token", "Bot token", "Integration token", "Service application token"],
  },
  permissions: [
    { id: "people-read", kind: "oauth-scope", value: WEBEX_SCOPES.peopleRead, unlocks: ["people", "me"] },
    { id: "organizations-read", kind: "oauth-scope", value: WEBEX_SCOPES.organizationsRead, unlocks: ["organizations", "organization"] },
    { id: "roles-read", kind: "oauth-scope", value: WEBEX_SCOPES.rolesRead, unlocks: ["roles"] },
    { id: "licenses-read", kind: "oauth-scope", value: WEBEX_SCOPES.licensesRead, unlocks: ["licenses"] },
    { id: "devices-read", kind: "oauth-scope", value: WEBEX_SCOPES.devicesRead, unlocks: ["devices", "workspaces"] },
    { id: "hybrid-read", kind: "oauth-scope", value: WEBEX_SCOPES.hybridRead, unlocks: ["hybrid-clusters", "hybrid-connectors"] },
    { id: "events-read", kind: "oauth-scope", value: WEBEX_SCOPES.eventsRead, unlocks: ["events", "admin-audit-events"] },
    { id: "meetings-read", kind: "oauth-scope", value: WEBEX_SCOPES.meetingAdminScheduleRead, unlocks: ["meetings"] },
    { id: "recordings-read", kind: "oauth-scope", value: WEBEX_SCOPES.meetingRecordingsRead, unlocks: ["admin-recordings"] },
    { id: "preferences-read", kind: "oauth-scope", value: WEBEX_SCOPES.meetingAdminPreferencesRead, unlocks: ["meeting-preferences", "meeting-sites", "meeting-common-settings"] },
    { id: "pro-pack", kind: "plan", value: "Webex Pro Pack", unlocks: ["events", "admin-audit-events"], notes: "Some compliance and longer-retention evidence depends on the tenant plan." },
  ],
  pagination: [
    {
      surfaceIds: ["people", "licenses", "events", "admin-audit-events", "admin-recordings", "hybrid-clusters", "hybrid-connectors", "meetings", "meeting-sites", "devices", "workspaces", "rooms", "webhooks"],
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
    sharedContractVersion: "1.0",
    projections: Object.fromEntries(Object.entries(WEBEX_SURFACE_FIELDS).map(([surface, fields]) => [surface, flattenedFields(fields)])),
    sensitiveFields: ["token", "client_secret", "refresh_token", "password", "secret", "targetUrl query", "downloadUrl query", "playbackUrl query", "webLink query"],
    benignExceptions: ["Documented resource identifiers", "Organization identifiers", "Site host names"],
    credentialFormats: ["Bearer credentials", "OAuth client secrets", "Refresh tokens", "Webhook signing secrets", "Meeting passwords", "Credential-bearing URL parameters"],
  },
  output: WEBEX_EXPORT,
  tools: [
    { name: "webex_check_access", checkIds: [] },
    { name: IDENTITY_TOOL, checkIds: WEBEX_CHECKS.filter((item) => item.owningTool === IDENTITY_TOOL).map((item) => item.id) },
    { name: COLLAB_TOOL, checkIds: WEBEX_CHECKS.filter((item) => item.owningTool === COLLAB_TOOL).map((item) => item.id) },
    { name: MEETING_TOOL, checkIds: WEBEX_CHECKS.filter((item) => item.owningTool === MEETING_TOOL).map((item) => item.id) },
    { name: "webex_export_audit_bundle", checkIds: WEBEX_CHECKS.map((item) => item.id), output: WEBEX_EXPORT },
  ],
};
