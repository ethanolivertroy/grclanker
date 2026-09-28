import { SNOWFLAKE_AUTH_RESOLVER } from "./auth-resolver-contracts.js";
import {
  batch4FrameworksFromMappings,
  batch4Surface,
  buildBatch4Spec,
  type Batch4Control,
} from "./batch4-spec-helpers.js";
import { SNOWFLAKE_CONTROLS, SNOWFLAKE_FRAMEWORKS } from "./snowflake.js";

const DOCS = "https://docs.snowflake.com/en/developer-guide/sql-api/index";
const surfaces = [
  batch4Surface("network-authentication-sql", "POST", "SQL API: SHOW NETWORK POLICIES; SHOW PARAMETERS; SHOW USERS; SHOW SECURITY INTEGRATIONS; POLICY_REFERENCES", "Snowflake SQL REST API v2", DOCS, ["name", "value", "type", "disabled", "has_password", "has_rsa_public_key", "mins_to_unlock", "ref_entity_name"]),
  batch4Surface("access-control-sql", "POST", "SQL API: ACCOUNT_USAGE.ROLES, GRANTS_TO_ROLES, GRANTS_TO_USERS, QUERY_HISTORY", "Snowflake SQL REST API v2", DOCS, ["role", "grantee_name", "privilege", "granted_on", "name", "user_name", "query_text", "start_time"]),
  batch4Surface("monitoring-lifecycle-sql", "POST", "SQL API: ACCOUNT_USAGE.LOGIN_HISTORY, USERS, ACCESS_HISTORY; SHOW WAREHOUSES; SHOW PARAMETERS", "Snowflake SQL REST API v2", DOCS, ["event_timestamp", "is_success", "user_name", "last_success_login", "auto_suspend", "retention_time"]),
  batch4Surface("data-protection-sql", "POST", "SQL API: POLICY_REFERENCES, TAG_REFERENCES, SHOW INTEGRATIONS, SHOW STAGES, SHOW DATABASES, SHOW SHARES, SHOW REPLICATION GROUPS", "Snowflake SQL REST API v2", DOCS, ["policy_name", "ref_entity_name", "type", "enabled", "storage_integration", "retention_time", "kind", "owner"]),
] as const;

const groupControls: Readonly<Record<string, readonly number[]>> = {
  snowflake_assess_network_and_authentication: [1, 2, 3, 4, 5, 6, 25],
  snowflake_assess_access_control: [7, 8, 9, 10, 16],
  snowflake_assess_monitoring_and_lifecycle: [11, 12, 13, 24],
  snowflake_assess_data_protection: [14, 15, 17, 18, 19, 20, 21, 22, 23],
};
const sourceByOwner: Readonly<Record<string, string>> = {
  snowflake_assess_network_and_authentication: "network-authentication-sql",
  snowflake_assess_access_control: "access-control-sql",
  snowflake_assess_monitoring_and_lifecycle: "monitoring-lifecycle-sql",
  snowflake_assess_data_protection: "data-protection-sql",
};
const controls: Batch4Control[] = Object.values(SNOWFLAKE_CONTROLS).map((definition) => {
  const owner = Object.entries(groupControls).find(([, numbers]) => numbers.includes(definition.control))?.[0];
  if (!owner) throw new Error(`No Snowflake tool owner for control ${definition.control}`);
  return {
    id: definition.id,
    control: definition.control,
    title: definition.title,
    severity: definition.severity,
    owner,
    surfaces: [sourceByOwner[owner]],
    predicate: `Count complete SQL result rows that violate ${definition.title}; role-sensitive empty results, denied statements, missing columns, and unfinished async statements remain unknown.`,
    frameworks: batch4FrameworksFromMappings(definition.mappings),
    emptyOutcome: [9, 10, 11, 12, 14, 15, 16, 17, 18, 22, 23].includes(definition.control) ? "pass" : "manual",
    manualOnly: [20, 21].includes(definition.control),
  };
});

export const SNOWFLAKE_RUNTIME_BEHAVIOR = [
  "Every submitted SQL statement passes a read-only statement guard before POST /api/v2/statements and preserves its exact statement handle, columns, rows, partition metadata, and error state.",
  "HTTP 202 statements are polled to a terminal state within the configured timeout; every advertised partition is fetched and a missing or failed partition makes the statement incomplete.",
  "An empty ACCOUNT_USAGE or SHOW result passes only when the caller role is known to have complete visibility for that check; otherwise it remains manual.",
] as const;

export const SNOWFLAKE_SPEC = buildBatch4Spec({
  slug: "snowflake-sec-inspector",
  displayName: "Snowflake Security Inspector",
  vendor: "Snowflake",
  category: "data-platform",
  summary: "Portable contract for Snowflake network, authentication, access-control, monitoring, retention, and data-protection assessments.",
  sourceModule: "cli/extensions/grc-tools/snowflake.ts",
  baseServices: ["Snowflake SQL REST API v2"],
  authentication: SNOWFLAKE_AUTH_RESOLVER,
  surfaces,
  controls,
  tools: {
    snowflake_check_access: [],
    ...Object.fromEntries(Object.keys(groupControls).map((owner) => [owner, controls.filter((item) => item.owner === owner).map((item) => item.id)])),
    snowflake_export_audit_bundle: controls.map((item) => item.id),
  },
  pagination: [{
    surfaceIds: surfaces.map((surface) => surface.id),
    cursorFields: ["statementHandle", "partitionInfo", "partition", "rowType", "numRows"],
    pageSize: null,
    itemCap: null,
    pageCap: null,
    totalSemantics: "Completion requires a terminal successful statement and successful retrieval of every partition advertised by partitionInfo.",
    stopConditions: ["Terminal successful statement with all partitions", "Statement timeout", "Terminal SQL error", "Missing statement handle", "Partition failure", "Row/column shape mismatch"],
  }],
  documentedRateLimit: "Snowflake SQL API concurrency and request limits depend on account and warehouse configuration; 429 and Retry-After are authoritative.",
  retryHeaders: ["Retry-After", "X-Snowflake-Request-Id"],
  runtimeBehavior: SNOWFLAKE_RUNTIME_BEHAVIOR,
  knownGaps: ["Tri-Secret Secure and customer-managed-key controls remain manual because SQL metadata does not expose decisive key-management state."],
  sensitiveFields: ["private_key", "private_key_passphrase", "token", "authorization", "query_text", "email", "host"],
  credentialFormats: ["Snowflake key-pair PEM", "OAuth tokens", "programmatic access tokens", "JWT assertions"],
  outputFiles: [
    "README.md", "QUICK_REFERENCE.md", "metadata.json", "core_data/access_check.json",
    "analysis/findings.json", "analysis/network_and_authentication.json", "analysis/access_control.json",
    "analysis/monitoring_and_lifecycle.json", "analysis/data_protection.json",
    "compliance/executive_summary.md", "compliance/unified_compliance_matrix.md",
    ...SNOWFLAKE_FRAMEWORKS.map((framework) => `compliance/${framework.toLowerCase().replaceAll(" ", "_").replaceAll("-", "_")}.md`),
  ],
  overwritePolicy: "Allocate snowflake-audit-<UTC timestamp> and append a numeric suffix while either the output directory or archive exists.",
  archivePairing: "Create <allocated-directory>.zip beside the Snowflake audit directory with the same suffix.",
});
