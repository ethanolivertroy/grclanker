import { ANSIBLE_AUTH_RESOLVER } from "./auth-resolver-contracts.js";
import {
  batch4FrameworkFiles,
  batch4Surface,
  buildBatch4Spec,
  type Batch4Control,
} from "./batch4-spec-helpers.js";
import { ANSIBLE_CONTROLS } from "./ansible.js";

const DOCS = "https://docs.ansible.com/automation-controller/latest/html/controllerapi/api_ref.html";
const surfaces = [
  batch4Surface("job-health", "GET", "/api/v2/jobs/; /api/v2/workflow_jobs/", "Ansible Automation Controller API v2", DOCS, ["id", "name", "status", "started", "finished", "elapsed", "launch_type", "job_template", "failed"]),
  batch4Surface("host-coverage", "GET", "/api/v2/hosts/; /api/v2/inventory_sources/; /api/v2/job_templates/; /api/v2/schedules/; /api/v2/workflow_job_templates/", "Ansible Automation Controller API v2", DOCS, ["id", "name", "enabled", "last_job", "last_job_failed", "last_updated", "next_run", "inventory", "organization"]),
  batch4Surface("platform-security", "GET", "/api/v2/credentials/; /api/v2/tokens/; /api/v2/organizations/; /api/v2/teams/; /api/v2/settings/; /api/v2/activity_stream/; /api/v2/notification_templates/; /api/v2/projects/; /api/v2/execution_environments/", "Ansible Automation Controller API v2", DOCS, ["id", "name", "kind", "managed", "created", "modified", "inputs", "related", "summary_fields", "value"]),
] as const;

const groupControls: Readonly<Record<string, readonly number[]>> = {
  ansible_assess_job_health: [1, 2, 3, 4, 5, 28],
  ansible_assess_host_coverage: [6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  ansible_assess_platform_security: [16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 29, 30],
};
const sourceByOwner: Readonly<Record<string, string>> = {
  ansible_assess_job_health: "job-health",
  ansible_assess_host_coverage: "host-coverage",
  ansible_assess_platform_security: "platform-security",
};
const controls: Batch4Control[] = ANSIBLE_CONTROLS.map((definition) => {
  const owner = Object.entries(groupControls).find(([, numbers]) => numbers.includes(definition.control))?.[0];
  if (!owner) throw new Error(`No Ansible tool owner for control ${definition.control}`);
  return {
    id: definition.id,
    control: definition.control,
    title: definition.title,
    severity: definition.severity,
    owner,
    surfaces: [sourceByOwner[owner]],
    predicate: `Count complete-population Automation Controller records that violate ${definition.title}; sampled detail, restricted auditor visibility, missing timestamps, and failed related-resource reads remain explicit review evidence.`,
    frameworks: {
      fedramp: definition.mappings.fedramp.split(",").map((entry) => entry.trim()),
      cmmc: definition.mappings.cmmc.split(",").map((entry) => entry.trim()),
      soc2: definition.mappings.soc2.split(",").map((entry) => entry.trim()),
      cis: definition.mappings.cis.split(",").map((entry) => entry.trim()),
      pci_dss: definition.mappings.pci_dss.split(",").map((entry) => entry.trim()),
      disa_stig: definition.mappings.disa_stig.split(",").map((entry) => entry.trim()),
    },
    emptyOutcome: [2, 3, 5, 6, 7, 9, 10, 11, 13, 14, 16, 17, 18, 19, 20, 22, 23, 27, 29].includes(definition.control) ? "pass" : "manual",
  };
});

export const ANSIBLE_RUNTIME_BEHAVIOR = [
  "Controller list responses follow the server next URL only when it remains on the configured origin and carries no user information.",
  "Restricted auditor visibility is distinct from a complete empty inventory; count and negative facts stay null when the caller cannot enumerate the full tenant.",
  "Credential input values, token values, survey secrets, extra variables, and error payloads are projected and scrubbed before any report or archive sink.",
] as const;

export const ANSIBLE_SPEC = buildBatch4Spec({
  slug: "ansible-aap-audit",
  displayName: "Ansible Automation Platform Auditor",
  vendor: "Red Hat Ansible",
  category: "automation-platform",
  summary: "Portable contract for Ansible Automation Platform job, host, template, credential, RBAC, audit, project, and execution-environment assessments.",
  sourceModule: "cli/extensions/grc-tools/ansible.ts",
  baseServices: ["Ansible Automation Controller API v2"],
  authentication: ANSIBLE_AUTH_RESOLVER,
  surfaces,
  controls,
  tools: {
    ansible_check_access: [],
    ...Object.fromEntries(Object.keys(groupControls).map((owner) => [owner, controls.filter((item) => item.owner === owner).map((item) => item.id)])),
    ansible_export_audit_bundle: controls.map((item) => item.id),
  },
  pagination: [{
    surfaceIds: surfaces.map((surface) => surface.id),
    cursorFields: ["next", "previous", "count", "page", "page_size"],
    pageSize: 200,
    itemCap: 10000,
    pageCap: 100,
    totalSemantics: "Completion requires next=null and reconciliation of the projected item count with count.",
    stopConditions: ["next=null", "Reported count reached", "Item cap", "Page cap", "Repeated next URL", "Rejected off-origin next URL", "Empty page with next URL"],
  }],
  documentedRateLimit: "Automation Controller does not publish one universal request budget; 429 and Retry-After are handled when returned.",
  retryHeaders: ["Retry-After", "X-API-Time"],
  runtimeBehavior: ANSIBLE_RUNTIME_BEHAVIOR,
  knownGaps: ["Restricted auditor accounts may require manual evidence for settings or resources hidden by Automation Controller RBAC."],
  sensitiveFields: ["token", "password", "authorization", "inputs", "extra_vars", "survey_spec", "credential", "email", "url"],
  credentialFormats: ["AAP OAuth2 tokens", "Basic credentials", "vaulted and unvaulted variables", "credential input fields"],
  outputFiles: [
    "README.md", "QUICK_REFERENCE.md", "metadata.json", "core_data/access_check.json",
    "analysis/findings.json", "analysis/job_health.json", "analysis/host_coverage.json",
    "analysis/platform_security.json", "compliance/executive_summary.md",
    "compliance/unified_compliance_matrix.md", ...batch4FrameworkFiles().slice(0, 6),
  ],
  overwritePolicy: "Allocate ansible-aap-audit-<UTC timestamp> and append a numeric suffix while either paired path exists.",
  archivePairing: "Create <allocated-directory>.zip beside the Ansible AAP audit directory with the identical suffix.",
});
