import { SPLUNK_AUTH_RESOLVER } from "./auth-resolver-contracts.js";
import {
  batch4FrameworkFiles,
  batch4Surface,
  buildBatch4Spec,
  type Batch4Control,
} from "./batch4-spec-helpers.js";
import { SPLUNK_CONTROLS } from "./splunk.js";
import type { FrameworkKey } from "./spec-model.js";

const DOCS = "https://help.splunk.com/en/splunk-enterprise/rest-api-reference";
const surfaces = [
  batch4Surface("authentication", "GET", "/services/authentication/users; /services/authentication/providers/services; /services/admin/passwords; /services/authorization/tokens", "Splunk REST API", DOCS, ["name", "roles", "type", "disabled", "minPasswordLength", "sessionTimeout", "status", "lastUsed"]),
  batch4Surface("access-control", "GET", "/services/authorization/roles; /services/authentication/users; /services/data/indexes; /servicesNS/-/-/data/ui/views", "Splunk REST API", DOCS, ["capabilities", "imported_roles", "srchIndexesAllowed", "eai:acl", "sharing", "perms"]),
  batch4Surface("data-protection", "GET", "/services/server/settings; /services/configs/conf-server; /services/data/inputs/tcp/ssl; /services/data/inputs/http", "Splunk REST API", DOCS, ["enableSplunkdSSL", "sslVersions", "cipherSuite", "disabled", "useSSL", "token"]),
  batch4Surface("audit-monitoring", "GET", "/services/search/jobs/export; /services/data/indexes/_audit", "Splunk REST API", DOCS, ["_time", "action", "user", "info", "index", "frozenTimePeriodInSecs"]),
  batch4Surface("platform-hardening", "GET", "/services/apps/local; /services/storage/collections/config; /servicesNS/-/-/saved/searches; ACS IP allowlist", "Splunk REST and ACS APIs", DOCS, ["disabled", "version", "eai:acl", "actions", "cron_schedule", "ipAllowLists"]),
] as const;

const frameworkKeys: readonly FrameworkKey[] = ["fedramp", "cmmc", "soc2", "cis", "pci_dss", "disa_stig", "irap", "ismap"];
const sourceFor = (number: number): string => (
  number <= 6 ? "authentication"
    : number <= 12 ? "access-control"
      : number <= 16 ? "data-protection"
        : number <= 18 ? "audit-monitoring"
          : "platform-hardening"
);
const ownerFor = (number: number): string => `splunk_assess_${sourceFor(number).replaceAll("-", "_")}`;
const controls: Batch4Control[] = SPLUNK_CONTROLS.map((definition) => ({
  id: definition.id,
  control: definition.number,
  title: definition.title,
  severity: definition.severity,
  owner: ownerFor(definition.number),
  surfaces: [sourceFor(definition.number)],
  predicate: `Count complete-population Splunk entries that violate ${definition.title}, resolving namespace and configuration precedence before comparing values and retaining absent required fields for review.`,
  frameworks: Object.fromEntries(frameworkKeys.map((key) => [key, definition.mappings[key === "pci_dss" ? "pci" : key === "disa_stig" ? "stig" : key].split(",").map((entry) => entry.trim())])) as Partial<Record<FrameworkKey, readonly string[]>>,
  emptyOutcome: [6, 11, 12, 16, 19, 20, 21, 22].includes(definition.number) ? "pass" : "manual",
}));

export const SPLUNK_RUNTIME_BEHAVIOR = [
  "Splunk configuration reads merge default, system, app, and user namespace values using the runtime's documented precedence before any check evaluates.",
  "REST offset paging and ACS next-link paging record the requested endpoint, item count, server total, and exact cap, malformed-link, repeated-link, or exhaustion stop.",
  "The per-client verify_ssl switch changes only the Splunk transport and does not mutate process-wide TLS behavior.",
] as const;

export const SPLUNK_SPEC = buildBatch4Spec({
  slug: "splunk-sec-inspector",
  displayName: "Splunk Security Inspector",
  vendor: "Splunk",
  category: "observability",
  summary: "Portable contract for Splunk authentication, authorization, transport, audit, and platform-hardening assessments.",
  sourceModule: "cli/extensions/grc-tools/splunk.ts",
  baseServices: ["Splunk management REST API", "Splunk Cloud Admin Config Service"],
  authentication: SPLUNK_AUTH_RESOLVER,
  surfaces,
  controls,
  tools: {
    splunk_check_access: [],
    splunk_assess_authentication: controls.filter((item) => item.owner === "splunk_assess_authentication").map((item) => item.id),
    splunk_assess_access_control: controls.filter((item) => item.owner === "splunk_assess_access_control").map((item) => item.id),
    splunk_assess_data_protection: controls.filter((item) => item.owner === "splunk_assess_data_protection").map((item) => item.id),
    splunk_assess_audit_monitoring: controls.filter((item) => item.owner === "splunk_assess_audit_monitoring").map((item) => item.id),
    splunk_assess_platform_hardening: controls.filter((item) => item.owner === "splunk_assess_platform_hardening").map((item) => item.id),
    splunk_export_audit_bundle: controls.map((item) => item.id),
  },
  pagination: [{
    surfaceIds: surfaces.map((surface) => surface.id),
    cursorFields: ["offset", "count", "paging.total", "links.next"],
    pageSize: 200,
    itemCap: 10000,
    pageCap: 100,
    totalSemantics: "REST listings reconcile paging.total; ACS listings require a same-origin links.next chain ending without a next link.",
    stopConditions: ["Reported total reached", "Short or empty page", "No next link", "Item cap", "Page cap", "Repeated next link", "Rejected off-origin next link"],
  }],
  documentedRateLimit: "Splunk Enterprise and Splunk Cloud limits vary by deployment and endpoint; 429 and Retry-After are authoritative when returned.",
  retryHeaders: ["Retry-After", "X-RateLimit-Remaining"],
  runtimeBehavior: SPLUNK_RUNTIME_BEHAVIOR,
  knownGaps: ["Enterprise Security content coverage and controls without a read status remain manual."],
  sensitiveFields: ["token", "password", "authorization", "cookie", "session", "hec_token", "email", "url"],
  credentialFormats: ["Splunk bearer tokens", "ACS tokens", "Basic credentials", "session cookies", "HEC tokens"],
  outputFiles: [
    "README.md", "QUICK_REFERENCE.md", "metadata.json", "core_data/access_check.json",
    "analysis/findings.json", "analysis/authentication.json", "analysis/access_control.json",
    "analysis/data_protection.json", "analysis/audit_monitoring.json", "analysis/platform_hardening.json",
    "compliance/executive_summary.md", "compliance/unified_compliance_matrix.md",
    ...batch4FrameworkFiles(),
  ],
  overwritePolicy: "Allocate splunk-audit-<UTC timestamp> and append a numeric suffix until neither the evidence directory nor archive exists.",
  archivePairing: "Create <allocated-directory>.zip beside the Splunk audit directory with the identical suffix.",
});
