import { GITHUB_AUTH_RESOLVER } from "./auth-resolver-contracts.js";
import {
  batch4FrameworkFiles,
  batch4Surface,
  buildBatch4Spec,
  type Batch4Control,
} from "./batch4-spec-helpers.js";
import { GITHUB_CHECKS } from "./github.js";

const REST_DOCS = "https://docs.github.com/en/rest";
const surfaces = [
  batch4Surface("org-access", "GET", "/orgs/{org}; members; outside_collaborators; audit-log; GraphQL organization identity connections", "GitHub REST API 2022-11-28 and GraphQL API", REST_DOCS, ["two_factor_requirement_enabled", "default_repository_permission", "members_can_create_public_repositories", "members_can_fork_private_repositories", "login", "role", "samlIdentityProvider", "externalIdentities", "ipAllowListEntries"]),
  batch4Surface("repo-protection", "GET", "/orgs/{org}/repos; /repos/{owner}/{repo}/rules/branches/{branch}; branches/{branch}/protection; rulesets", "GitHub REST API 2022-11-28", REST_DOCS, ["default_branch", "archived", "rules", "required_pull_request_reviews", "required_status_checks", "required_signatures", "allow_force_pushes", "allow_deletions"]),
  batch4Surface("actions-security", "GET", "/orgs/{org}/actions/permissions; workflow; selected-actions; runners; runner-groups", "GitHub REST API 2022-11-28", REST_DOCS, ["enabled_repositories", "allowed_actions", "default_workflow_permissions", "can_approve_pull_request_reviews", "visibility", "selected_repositories_url"]),
  batch4Surface("code-security", "GET", "/orgs/{org}/code-security/configurations; configurations/defaults", "GitHub REST API 2022-11-28", REST_DOCS, ["name", "enforcement", "code_scanning_default_setup", "secret_scanning", "secret_scanning_push_protection", "dependabot_alerts", "dependabot_security_updates"]),
  batch4Surface("integrations", "GET", "/orgs/{org}/hooks; installations; credential-authorizations; repository hooks and deploy keys", "GitHub REST API 2022-11-28", REST_DOCS, ["active", "config.url", "config.insecure_ssl", "config.secret", "permissions", "repository_selection", "suspended_at", "read_only", "created_at"]),
] as const;

const controlByCheck: Readonly<Record<string, number>> = {
  "GITHUB-ORG-006": 1, "GITHUB-ORG-001": 2, "GITHUB-ORG-007": 3, "GITHUB-ORG-008": 4,
  "GITHUB-ORG-002": 5, "GITHUB-ORG-004": 5, "GITHUB-ORG-009": 6, "GITHUB-ORG-010": 7,
  "GITHUB-ORG-003": 8, "GITHUB-INTEG-004": 9, "GITHUB-REPO-002": 10, "GITHUB-REPO-004": 10,
  "GITHUB-REPO-006": 11, "GITHUB-REPO-007": 12, "GITHUB-REPO-003": 13, "GITHUB-REPO-005": 13,
  "GITHUB-REPO-001": 14, "GITHUB-CODE-001": 15, "GITHUB-CODE-005": 15,
  "GITHUB-CODE-002": 16, "GITHUB-CODE-003": 16, "GITHUB-CODE-004": 17, "GITHUB-CODE-006": 18,
  "GITHUB-ORG-005": 19, "GITHUB-ORG-011": 19, "GITHUB-INTEG-001": 20,
  "GITHUB-ACT-001": 21, "GITHUB-ACT-002": 21, "GITHUB-ACT-003": 21, "GITHUB-ACT-005": 21,
  "GITHUB-ACT-004": 22, "GITHUB-INTEG-002": 23, "GITHUB-INTEG-003": 24, "GITHUB-INTEG-005": 25,
};
const sourceByCategory = {
  org_access: "org-access",
  repo_protection: "repo-protection",
  actions_security: "actions-security",
  code_security: "code-security",
  integrations: "integrations",
} as const;
const ownerByCategory = {
  org_access: "github_assess_org_access",
  repo_protection: "github_assess_repo_protection",
  actions_security: "github_assess_actions_security",
  code_security: "github_assess_code_security",
  integrations: "github_assess_integrations",
} as const;
const manualChecks = new Set(["GITHUB-INTEG-004", "GITHUB-CODE-006", "GITHUB-ORG-011", "GITHUB-INTEG-005"]);
const controls: Batch4Control[] = Object.values(GITHUB_CHECKS).map((definition) => ({
  id: definition.id,
  control: controlByCheck[definition.id],
  title: definition.title,
  severity: definition.severity,
  owner: ownerByCategory[definition.category],
  surfaces: [sourceByCategory[definition.category]],
  predicate: `Count complete-population GitHub organization, repository, branch, runner, code-security, hook, key, or installation records that violate ${definition.title}; per-repository failures remain named witnesses and never become compliant emptiness.`,
  frameworks: {
    fedramp: definition.frameworks.fedramp,
    cmmc: definition.frameworks.cmmc,
    soc2: definition.frameworks.soc2,
    cis: definition.frameworks.cis,
    pci_dss: definition.frameworks.pci_dss,
    disa_stig: definition.frameworks.disa_stig,
    irap: definition.frameworks.irap,
    ismap: definition.frameworks.ismap,
  },
  emptyOutcome: ["GITHUB-ORG-003", "GITHUB-INTEG-001", "GITHUB-INTEG-002", "GITHUB-INTEG-003", "GITHUB-ACT-004"].includes(definition.id) ? "pass" : "manual",
  manualOnly: manualChecks.has(definition.id),
}));

export const GITHUB_RUNTIME_BEHAVIOR = [
  "REST Link pagination and GraphQL connection pagination retain independent totals, pageInfo, repeated-cursor, null-cursor, cap, and per-repository failure states.",
  "Effective branch protection merges organization rulesets, repository rulesets, branch rules, and legacy protection without treating an unreadable layer as absent.",
  "GitHub App private keys and API error bodies are reduced to fixed safe error envelopes before in-memory evidence, formatted output, bundle files, or archives are produced.",
] as const;

export const GITHUB_SPEC = buildBatch4Spec({
  slug: "github-sec-inspector",
  displayName: "GitHub Security Inspector",
  vendor: "GitHub",
  category: "developer-platform",
  summary: "Portable contract for GitHub organization, repository, Actions, code-security, webhook, key, and App-installation assessments.",
  sourceModule: "cli/extensions/grc-tools/github.ts",
  baseServices: ["GitHub REST API 2022-11-28", "GitHub GraphQL API"],
  authentication: GITHUB_AUTH_RESOLVER,
  surfaces,
  controls,
  tools: {
    github_check_access: [],
    ...Object.fromEntries(Object.values(ownerByCategory).map((owner) => [owner, controls.filter((item) => item.owner === owner).map((item) => item.id)])),
    github_export_audit_bundle: controls.map((item) => item.id),
  },
  pagination: [
    {
      surfaceIds: surfaces.map((surface) => surface.id),
      cursorFields: ["Link rel=next", "pageInfo.hasNextPage", "pageInfo.endCursor", "totalCount"],
      pageSize: 100,
      itemCap: 10000,
      pageCap: 100,
      totalSemantics: "REST walks require no rel=next; GraphQL walks require hasNextPage=false and reconciliation with every totalCount.",
      stopConditions: ["No next link", "hasNextPage=false", "Missing endCursor", "Repeated cursor or next URL", "Item cap", "Page cap", "Total mismatch", "Rejected off-origin link"],
    },
  ],
  documentedRateLimit: "REST primary and secondary rate limits and GraphQL point limits are account-specific and reported in response headers and rateLimit objects.",
  retryHeaders: ["Retry-After", "X-RateLimit-Remaining", "X-RateLimit-Reset", "X-RateLimit-Resource"],
  runtimeBehavior: GITHUB_RUNTIME_BEHAVIOR,
  knownGaps: ["Audit streaming, repository security-policy presence, package visibility, interactive OAuth, and organization-wide alert enumeration remain manual or deferred."],
  sensitiveFields: ["token", "private_key", "authorization", "cookie", "config.secret", "openssh_public_key", "email", "url", "query"],
  credentialFormats: ["GitHub PAT prefixes", "GitHub App installation tokens", "PEM private keys", "Bearer and Basic headers", "webhook secrets"],
  outputFiles: [
    "README.md", "QUICK_REFERENCE.md", "metadata.json", "core_data/access_check.json",
    "analysis/findings.json", "analysis/org_access.json", "analysis/repo_protection.json",
    "analysis/actions_security.json", "analysis/code_security.json", "analysis/integrations.json",
    "compliance/executive_summary.md", "compliance/unified_compliance_matrix.md",
    ...batch4FrameworkFiles(),
  ],
  overwritePolicy: "Allocate github-<organization>-audit-<UTC timestamp> and append a numeric suffix while either paired path exists.",
  archivePairing: "Create <allocated-directory>.zip beside the GitHub audit directory with the identical suffix.",
});
