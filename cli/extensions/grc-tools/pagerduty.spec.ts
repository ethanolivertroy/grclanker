import { PAGERDUTY_AUTH_RESOLVER } from "./auth-resolver-contracts.js";
import {
  batch4FrameworkFiles,
  batch4Surface,
  buildBatch4Spec,
  type Batch4Control,
} from "./batch4-spec-helpers.js";
import { PAGERDUTY_CONTROLS, findingId } from "./pagerduty.js";

const DOCS = "https://developer.pagerduty.com/api-reference/";
const surfaces = [
  batch4Surface("access-control", "GET", "/abilities; /users; /teams; /team_memberships", "PagerDuty REST API v2", DOCS, ["abilities", "id", "role", "teams", "contact_methods", "notification_rules", "html_url"]),
  batch4Surface("incident-response", "GET", "/services; /escalation_policies; /priorities; /incident_workflows; workflow_triggers", "PagerDuty REST API v2", DOCS, ["id", "name", "escalation_policy", "escalation_rules", "repeat_enabled", "incident_urgency_rule", "acknowledgement_timeout", "auto_resolve_timeout"]),
  batch4Surface("oncall-coverage", "GET", "/schedules; /schedules/{id}; /oncalls", "PagerDuty REST API v2", DOCS, ["id", "schedule_layers", "rendered_schedule_entries", "user", "start", "end", "escalation_level"]),
  batch4Surface("audit-logging", "GET", "/audit/records", "PagerDuty Audit REST API", DOCS, ["id", "execution_time", "actors", "action", "details", "root_resource"]),
  batch4Surface("integration-security", "GET", "/extensions; /webhook_subscriptions; /business_services; dependencies; /change_events", "PagerDuty REST API v2", DOCS, ["id", "type", "endpoint_url", "delivery_method", "active", "filter", "relationships", "timestamp"]),
] as const;

const groups: Readonly<Record<string, readonly number[]>> = {
  pagerduty_assess_access_control: [1, 2, 3, 4, 24],
  pagerduty_assess_incident_response: [5, 6, 7, 10, 19, 20, 22, 23],
  pagerduty_assess_oncall_coverage: [8, 9, 17, 18],
  pagerduty_assess_audit_logging: [11, 12, 13],
  pagerduty_assess_integration_security: [14, 15, 16, 21, 25],
};
const sourceByOwner: Readonly<Record<string, string>> = {
  pagerduty_assess_access_control: "access-control",
  pagerduty_assess_incident_response: "incident-response",
  pagerduty_assess_oncall_coverage: "oncall-coverage",
  pagerduty_assess_audit_logging: "audit-logging",
  pagerduty_assess_integration_security: "integration-security",
};
const controls: Batch4Control[] = PAGERDUTY_CONTROLS.map((definition) => {
  const owner = Object.entries(groups).find(([, numbers]) => numbers.includes(definition.control))?.[0];
  if (!owner) throw new Error(`No PagerDuty tool owner for control ${definition.control}`);
  return {
    id: findingId(definition.control),
    control: definition.control,
    title: definition.title,
    severity: definition.severity,
    owner,
    surfaces: [sourceByOwner[owner]],
    predicate: `Count complete-population PagerDuty records that violate ${definition.title}; credential scope, plan gates, missing dates, and failed child reads remain explicit evidence states.`,
    frameworks: {
      fedramp: [definition.mappings.fedramp],
      cmmc: [definition.mappings.cmmc],
      soc2: [definition.mappings.soc2],
      cis: [definition.mappings.cis],
      pci_dss: [definition.mappings.pci_dss],
      disa_stig: [definition.mappings.disa_stig],
      irap: [definition.mappings.irap],
      ismap: [definition.mappings.ismap],
    },
    emptyOutcome: [3, 9, 10, 13, 14, 15, 16, 20, 21, 25].includes(definition.control) ? "pass" : "manual",
  };
});

export const PAGERDUTY_RUNTIME_BEHAVIOR = [
  "Classic offset endpoints and cursor endpoints use separate walkers; the documented 10,000-record offset ceiling is a truncation boundary, not exhaustion.",
  "Credential scope, account subdomain, service region, From header, plan-gated abilities, and per-resource child failures are retained as distinct collection facts.",
  "Webhook URLs are projected to safe origin data, secret headers and integration keys are withheld, and every missing date remains unknown rather than fresh.",
] as const;

export const PAGERDUTY_SPEC = buildBatch4Spec({
  slug: "pagerduty-sec-inspector",
  displayName: "PagerDuty Security Inspector",
  vendor: "PagerDuty",
  category: "incident-response",
  summary: "Portable contract for PagerDuty access, escalation, on-call, audit, webhook, dependency, and change-event assessments.",
  sourceModule: "cli/extensions/grc-tools/pagerduty.ts",
  baseServices: ["PagerDuty REST API v2", "PagerDuty Audit API", "PagerDuty Identity API"],
  authentication: PAGERDUTY_AUTH_RESOLVER,
  surfaces,
  controls,
  tools: {
    pagerduty_check_access: [],
    ...Object.fromEntries(Object.keys(groups).map((owner) => [owner, controls.filter((item) => item.owner === owner).map((item) => item.id)])),
    pagerduty_export_audit_bundle: controls.map((item) => item.id),
  },
  pagination: [
    {
      surfaceIds: ["access-control", "incident-response", "oncall-coverage"],
      cursorFields: ["offset", "limit", "more", "total"],
      pageSize: 100,
      itemCap: 10000,
      pageCap: 100,
      totalSemantics: "Classic endpoints require more=false and reconciliation with total; reaching offset 10000 is truncated unless exhaustion was already proved.",
      stopConditions: ["more=false", "Reported total reached", "10,000-record ceiling", "Item cap", "Page cap", "Empty page with more=true"],
    },
    {
      surfaceIds: ["audit-logging", "integration-security"],
      cursorFields: ["cursor", "next_cursor", "more"],
      pageSize: 100,
      itemCap: 10000,
      pageCap: 100,
      totalSemantics: "Cursor endpoints require more=false or an absent next cursor after a non-anomalous page.",
      stopConditions: ["more=false", "No next cursor", "Repeated cursor", "Empty page with cursor", "Item cap", "Page cap"],
    },
  ],
  documentedRateLimit: "PagerDuty publishes account-specific REST limits in X-RateLimit-* headers.",
  retryHeaders: ["Retry-After", "X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset"],
  runtimeBehavior: PAGERDUTY_RUNTIME_BEHAVIOR,
  knownGaps: ["SSO enforcement, API-key inventory, and analytics-role visibility remain plan- or permission-gated manual evidence."],
  sensitiveFields: ["api_token", "access_token", "client_secret", "authorization", "integration_key", "routing_key", "headers", "email", "url"],
  credentialFormats: ["PagerDuty REST API tokens", "OAuth access tokens", "OAuth client secrets", "integration and routing keys", "webhook custom headers"],
  outputFiles: [
    "README.md", "QUICK_REFERENCE.md", "metadata.json", "core_data/access_check.json",
    "core_data/credential_scope.json", "core_data/abilities.json", "core_data/users.json",
    "core_data/teams.json", "core_data/team_members.json", "core_data/services.json",
    "core_data/escalation_policies.json", "core_data/priorities.json", "core_data/incident_workflows.json",
    "core_data/incident_workflow_triggers.json", "core_data/schedules.json", "core_data/schedule_details.json",
    "core_data/oncalls.json", "core_data/audit_records_recent.json", "core_data/audit_records_retention_probe.json",
    "core_data/extensions.json", "core_data/webhook_subscriptions.json", "core_data/business_services.json",
    "core_data/business_service_dependencies.json", "core_data/change_events.json", "analysis/findings.json",
    "analysis/access_control.json", "analysis/incident_response.json", "analysis/oncall_coverage.json",
    "analysis/audit_logging.json", "analysis/integration_security.json", "compliance/executive_summary.md",
    "compliance/unified_compliance_matrix.md", ...batch4FrameworkFiles({
      "compliance/disa_stig/disa_stig_compliance_report.md": "compliance/disa_stig/stig_compliance_checklist.md",
    }),
  ],
  overwritePolicy: "Allocate pagerduty-audit-<UTC timestamp> and append a numeric suffix while either paired path exists.",
  archivePairing: "Create <allocated-directory>.zip beside the PagerDuty audit directory with the same suffix.",
});
