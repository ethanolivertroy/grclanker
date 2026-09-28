import { LAUNCHDARKLY_AUTH_RESOLVER } from "./auth-resolver-contracts.js";
import {
  batch4FrameworkFiles,
  batch4Surface,
  buildBatch4Spec,
  type Batch4Control,
} from "./batch4-spec-helpers.js";
import { LAUNCHDARKLY_CONTROL_CATALOG } from "./launchdarkly.js";

const DOCS = "https://apidocs.launchdarkly.com/";
const surfaces = [
  batch4Surface("identity", "GET", "/api/v2/members; /api/v2/roles; /api/v2/teams", "LaunchDarkly REST API v2", DOCS, ["_id", "email", "role", "customRoles", "teams", "policy", "basePermissions"]),
  batch4Surface("access-control", "GET", "/api/v2/roles; /api/v2/teams; /api/v2/tokens", "LaunchDarkly REST API v2", DOCS, ["key", "name", "policy", "roles", "serviceToken", "creationDate", "lastUsed", "expiry"]),
  batch4Surface("environment-governance", "GET", "/api/v2/projects; /api/v2/projects/{project}/environments; /api/v2/projects/{project}/environments/{environment}/approval-settings; /api/v2/relay-auto-configs", "LaunchDarkly REST API v2", DOCS, ["key", "name", "secureMode", "defaultTtl", "critical", "requiredApprovals", "canReviewOwnRequest", "createdAt"]),
  batch4Surface("flag-hygiene", "GET", "/api/v2/flags/{project}; /api/v2/flag-statuses/{project}/{environment}", "LaunchDarkly REST API v2", DOCS, ["key", "environments", "targets", "rules", "prerequisites", "lastRequested", "temporary"]),
  batch4Surface("monitoring-integrations", "GET", "/api/v2/auditlog; /api/v2/integrations; /api/v2/webhooks", "LaunchDarkly REST API v2", DOCS, ["date", "kind", "name", "statements", "url", "sign", "on", "tags"]),
] as const;

const groups: Readonly<Record<string, readonly number[]>> = {
  launchdarkly_assess_identity: [1, 2, 3, 6, 24],
  launchdarkly_assess_access_control: [4, 5, 7, 8, 9, 10, 11],
  launchdarkly_assess_environment_governance: [16, 17, 18, 19, 22, 23],
  launchdarkly_assess_flag_hygiene: [14, 15, 25],
  launchdarkly_assess_monitoring_integrations: [12, 13, 20, 21],
};
const sourceByOwner: Readonly<Record<string, string>> = {
  launchdarkly_assess_identity: "identity",
  launchdarkly_assess_access_control: "access-control",
  launchdarkly_assess_environment_governance: "environment-governance",
  launchdarkly_assess_flag_hygiene: "flag-hygiene",
  launchdarkly_assess_monitoring_integrations: "monitoring-integrations",
};
const controls: Batch4Control[] = Object.entries(LAUNCHDARKLY_CONTROL_CATALOG).map(([numberText, definition]) => {
  const number = Number(numberText);
  const owner = Object.entries(groups).find(([, numbers]) => numbers.includes(number))?.[0];
  if (!owner) throw new Error(`No LaunchDarkly tool owner for control ${number}`);
  return {
    id: `LD-${String(number).padStart(2, "0")}`,
    control: number,
    title: definition.title,
    severity: definition.severity,
    owner,
    surfaces: [sourceByOwner[owner]],
    predicate: `Count complete-population LaunchDarkly resources that violate ${definition.title}, using the full role statement, approval object, environment configuration, or flag graph rather than display labels.`,
    frameworks: {
      fedramp: [definition.frameworks.fedramp],
      cmmc: [definition.frameworks.cmmc],
      soc2: [definition.frameworks.soc2],
      cis: [definition.frameworks.cis],
      pci_dss: [definition.frameworks.pci_dss],
      disa_stig: [definition.frameworks.stig],
      irap: [definition.frameworks.irap],
      ismap: [definition.frameworks.ismap],
    },
    emptyOutcome: [4, 5, 7, 8, 9, 10, 11, 14, 15, 20, 21, 22, 25].includes(number) ? "pass" : "manual",
  };
});

export const LAUNCHDARKLY_RUNTIME_BEHAVIOR = [
  "Custom-role evaluation uses every policy statement, resource selector, action, effect, and not-action field; a role name is never treated as proof of privilege.",
  "Project, environment, token, flag, status, audit, integration, and webhook listings each preserve their own cap, total, next offset, and exact completeness state.",
  "SDK-key posture uses environment creation and key-rotation metadata only where the API returns it; static Relay Proxy deployment visibility remains manual.",
] as const;

export const LAUNCHDARKLY_SPEC = buildBatch4Spec({
  slug: "launchdarkly-sec-inspector",
  displayName: "LaunchDarkly Security Inspector",
  vendor: "LaunchDarkly",
  category: "developer-platform",
  summary: "Portable contract for LaunchDarkly member, role, token, environment, flag, audit, integration, and webhook assessments.",
  sourceModule: "cli/extensions/grc-tools/launchdarkly.ts",
  baseServices: ["LaunchDarkly REST API v2"],
  authentication: LAUNCHDARKLY_AUTH_RESOLVER,
  surfaces,
  controls,
  tools: {
    launchdarkly_check_access: [],
    ...Object.fromEntries(Object.keys(groups).map((owner) => [owner, controls.filter((item) => item.owner === owner).map((item) => item.id)])),
    launchdarkly_export_audit_bundle: controls.map((item) => item.id),
  },
  pagination: [{
    surfaceIds: surfaces.map((surface) => surface.id),
    cursorFields: ["offset", "limit", "totalCount", "_links.next.href"],
    pageSize: 100,
    itemCap: 10000,
    pageCap: 100,
    totalSemantics: "Offset listings reconcile totalCount; linked listings require a same-origin terminal page without a next link.",
    stopConditions: ["Reported total reached", "Short or empty page", "No next link", "Item cap", "Page cap", "Repeated offset or next link", "Rejected next link"],
  }],
  documentedRateLimit: "LaunchDarkly returns route and global limits in X-Ratelimit-* response headers.",
  retryHeaders: ["Retry-After", "X-Ratelimit-Reset", "X-Ratelimit-Remaining", "X-Ratelimit-Route-Remaining"],
  runtimeBehavior: LAUNCHDARKLY_RUNTIME_BEHAVIOR,
  knownGaps: ["Account SSO enforcement, static Relay Proxy deployment posture, and complete integration enumeration remain manual where no public read exists."],
  sensitiveFields: ["api_token", "accessToken", "sdkKey", "mobileKey", "clientSideId", "secret", "url", "email", "authorization"],
  credentialFormats: ["LaunchDarkly API access tokens", "SDK keys", "mobile keys", "client-side IDs", "webhook secrets"],
  outputFiles: [
    "README.md", "QUICK_REFERENCE.md", "metadata.json", "core_data/access_check.json",
    "core_data/collection_status.json", "analysis/findings.json", "analysis/identity.json",
    "analysis/access_control.json", "analysis/environment_governance.json", "analysis/flag_hygiene.json",
    "analysis/monitoring_integrations.json", "compliance/executive_summary.md",
    "compliance/unified_compliance_matrix.md", ...batch4FrameworkFiles(),
  ],
  overwritePolicy: "Allocate launchdarkly-audit-<UTC timestamp> and append a numeric suffix until the directory and paired archive are both unused.",
  archivePairing: "Create <allocated-directory>.zip beside the LaunchDarkly audit directory with the identical suffix.",
});
