import test from "node:test";
import assert from "node:assert/strict";
import {
  existsSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { generateKeyPairSync } from "node:crypto";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { inflateRawSync } from "node:zlib";

import {
  GitHubAuditorClient,
  advanceGraphqlPage,
  assessGitHubActionsSecurity,
  assessGitHubCodeSecurity,
  assessGitHubIntegrations,
  assessGitHubOrgAccess,
  assessGitHubRepoProtection,
  buildAuditLogWindow,
  clearGitHubTokenCacheForTests,
  collectGitHubActionsData,
  collectGitHubCodeSecurityData,
  collectGitHubIntegrationsData,
  collectGitHubOrgAccessData,
  collectGitHubRepoProtectionData,
  exportGitHubAuditBundle,
  redactSensitiveKeys,
  resolveGitHubConfiguration,
  resolveSecureOutputPath,
  runGitHubAccessCheck,
} from "../dist/extensions/grc-tools/github.js";

function createTempBase(prefix) {
  return mkdtempSync(join(tmpdir(), prefix));
}

function dataset(data, error) {
  return error ? { data, error } : { data };
}

function createSampleConfig(overrides = {}) {
  return {
    organization: "example-org",
    authMode: "pat",
    apiToken: "ghp_test",
    apiBaseUrl: "https://api.github.com",
    lookbackDays: 30,
    sourceChain: ["tests"],
    ...overrides,
  };
}

function createSamlSnapshot(overrides = {}) {
  return {
    requiresTwoFactorAuthentication: true,
    samlIdentityProvider: {
      ssoUrl: "https://idp.example.test/sso",
      issuer: "https://idp.example.test",
      digestMethod: "http://www.w3.org/2001/04/xmlenc#sha256",
      signatureMethod: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
    },
    externalIdentities: [
      { guid: "1", samlIdentity: { nameId: "alice@example.test" }, scimIdentity: { username: "alice" }, user: { login: "alice" } },
      { guid: "2", samlIdentity: { nameId: "bob@example.test" }, scimIdentity: null, user: { login: "bob" } },
      { guid: "3", samlIdentity: { nameId: "carol@example.test" }, scimIdentity: null, user: { login: "carol" } },
    ],
    externalIdentitiesTotalCount: 3,
    externalIdentitiesTruncated: false,
    errors: [],
    ...overrides,
  };
}

function createIpAllowListSnapshot(overrides = {}) {
  return {
    ipAllowListEnabledSetting: "ENABLED",
    ipAllowListForInstalledAppsEnabledSetting: "ENABLED",
    entries: [
      { allowListValue: "203.0.113.0/24", isActive: true, name: "HQ egress", createdAt: "2025-01-01T00:00:00Z" },
      { allowListValue: "198.51.100.7", isActive: false, name: "old office", createdAt: "2024-01-01T00:00:00Z" },
    ],
    entriesTotalCount: 2,
    entriesTruncated: false,
    errors: [],
    ...overrides,
  };
}

function createEnterpriseSnapshot(overrides = {}) {
  return {
    slug: "example-enterprise",
    ownerInfo: {
      samlIdentityProvider: null,
      oidcProvider: { providerType: "AAD", tenantId: "tenant-123" },
      twoFactorRequiredSetting: "ENABLED",
      affiliatedUsersWithTwoFactorDisabledExist: false,
      ipAllowListEnabledSetting: "ENABLED",
      ipAllowListForInstalledAppsEnabledSetting: "ENABLED",
      ipAllowListUserLevelEnforcementEnabledSetting: "DISABLED",
    },
    errors: [],
    ...overrides,
  };
}

function createAuditLogSnapshot(overrides = {}) {
  return {
    events: [{ action: "repo.create" }, { action: "member.added" }],
    truncated: false,
    limit: 200,
    lookbackDays: 30,
    createdSince: "2026-08-22",
    phrase: "created:>=2026-08-22",
    ...overrides,
  };
}

function createOrgAccessData(overrides = {}) {
  return {
    org: dataset({
      login: "example-org",
      two_factor_requirement_enabled: true,
      default_repository_permission: "read",
      web_commit_signoff_required: true,
      members_can_create_repositories: true,
      members_can_create_public_repositories: false,
      members_can_create_private_repositories: true,
      members_can_create_internal_repositories: true,
      members_can_fork_private_repositories: false,
    }),
    members: dataset([{ login: "alice" }, { login: "bob" }, { login: "carol" }]),
    adminMembers: dataset([{ login: "alice" }, { login: "bob" }]),
    twoFactorDisabledMembers: dataset([]),
    outsideCollaborators: dataset([{ login: "vendor-one" }, { login: "vendor-two" }]),
    invitations: dataset([{ id: 1 }]),
    organizationRoles: dataset([{ id: 1 }, { id: 2 }]),
    credentialAuthorizations: dataset([{ credential_id: 1 }]),
    auditLog: dataset(createAuditLogSnapshot()),
    hooks: dataset([{ id: 100 }]),
    appInstallations: dataset([{ id: 99 }]),
    samlIdentity: dataset(createSamlSnapshot()),
    ipAllowList: dataset(createIpAllowListSnapshot()),
    enterpriseIdentity: dataset(createEnterpriseSnapshot()),
    ...overrides,
  };
}

function findingStatus(result, id) {
  const finding = result.findings.find((entry) => entry.id === id);
  assert.ok(finding, `missing finding ${id}`);
  return finding.status;
}

function createBranchRules() {
  return {
    "example-org/app-one": {
      rules: [
        {
          type: "pull_request",
          parameters: { required_approving_review_count: 2, require_code_owner_review: true, dismiss_stale_reviews_on_push: true, require_last_push_approval: true, required_review_thread_resolution: false, allowed_merge_methods: ["squash"] },
          ruleset_source_type: "Organization",
          ruleset_source: "example-org",
          ruleset_id: 1,
        },
        {
          type: "required_status_checks",
          parameters: { strict_required_status_checks_policy: true, do_not_enforce_on_create: false, required_status_checks: [{ context: "ci" }] },
          ruleset_source_type: "Organization",
          ruleset_source: "example-org",
          ruleset_id: 1,
        },
        { type: "required_signatures", ruleset_source_type: "Organization", ruleset_source: "example-org", ruleset_id: 1 },
        { type: "non_fast_forward", ruleset_source_type: "Organization", ruleset_source: "example-org", ruleset_id: 1 },
        { type: "deletion", ruleset_source_type: "Organization", ruleset_source: "example-org", ruleset_id: 1 },
      ],
    },
    "example-org/app-two": {
      rules: [
        { type: "non_fast_forward", ruleset_source_type: "Repository", ruleset_source: "example-org/app-two", ruleset_id: 2 },
      ],
    },
  };
}

function createRepoProtectionData(overrides = {}) {
  return {
    org: dataset({
      login: "example-org",
      web_commit_signoff_required: true,
    }),
    branchRules: dataset(createBranchRules()),
    repositories: dataset([
      {
        full_name: "example-org/app-one",
        name: "app-one",
        default_branch: "main",
        archived: false,
        disabled: false,
        owner: { login: "example-org" },
      },
      {
        full_name: "example-org/app-two",
        name: "app-two",
        default_branch: "main",
        archived: false,
        disabled: false,
        owner: { login: "example-org" },
      },
    ]),
    orgRulesets: dataset([
      {
        id: 1,
        enforcement: "active",
        rules: [
          { type: "pull_request" },
          { type: "required_status_checks" },
          { type: "required_signatures" },
          { type: "non_fast_forward" },
          { type: "deletion" },
        ],
      },
    ]),
    repoRulesets: dataset({
      "example-org/app-one": [
        {
          id: 2,
          enforcement: "active",
          rules: [
            { type: "required_signatures" },
            { type: "non_fast_forward" },
          ],
        },
      ],
      "example-org/app-two": [],
    }),
    branchProtections: dataset({
      "example-org/app-one": {
        required_pull_request_reviews: { required_approving_review_count: 2 },
        required_status_checks: { strict: true, contexts: ["ci"] },
        required_signatures: { enabled: true },
        allow_force_pushes: { enabled: false },
        allow_deletions: { enabled: false },
      },
      "example-org/app-two": {
        required_pull_request_reviews: { required_approving_review_count: 1 },
        required_status_checks: { strict: true, contexts: ["ci"] },
        required_signatures: { enabled: false },
        allow_force_pushes: { enabled: false },
        allow_deletions: { enabled: false },
      },
    }),
    ...overrides,
  };
}

function createActionsData() {
  return {
    actionsPermissions: dataset({
      enabled_repositories: "all",
      allowed_actions: "all",
    }),
    selectedActions: dataset({
      github_owned_allowed: false,
      verified_allowed: false,
      patterns_allowed: [],
    }),
    workflowPermissions: dataset({
      default_workflow_permissions: "write",
      can_approve_pull_request_reviews: true,
    }),
    runnerGroups: dataset([
      {
        id: 1,
        visibility: "all",
        allows_public_repositories: true,
      },
    ]),
    runners: dataset([{ id: 1 }, { id: 2 }]),
  };
}

function createIntegrationsData(overrides = {}) {
  return {
    org: dataset({ login: "example-org", deploy_keys_enabled_for_repositories: true }),
    hooks: dataset([
      { id: 100, active: true, config: { url: "https://siem.example.test/github", content_type: "json", insecure_ssl: "0", secret: "********" } },
    ]),
    appInstallations: dataset([
      {
        id: 99,
        app_slug: "compliance-bot",
        repository_selection: "selected",
        permissions: { metadata: "read", contents: "read", security_events: "read" },
        suspended_at: null,
        created_at: "2025-01-01T00:00:00Z",
        updated_at: "2026-01-01T00:00:00Z",
      },
    ]),
    credentialAuthorizations: dataset([{ login: "alice", credential_type: "OAuth app token", credential_authorized_at: "2026-01-01T00:00:00Z" }]),
    repositories: dataset([
      { full_name: "example-org/app-one", name: "app-one", default_branch: "main", owner: { login: "example-org" } },
      { full_name: "example-org/app-two", name: "app-two", default_branch: "main", owner: { login: "example-org" } },
    ]),
    repoHooks: dataset({
      "example-org/app-one": { items: [{ id: 5, config: { url: "https://ci.example.test/hook", insecure_ssl: "0", secret: "********" } }] },
      "example-org/app-two": { items: [] },
    }),
    deployKeys: dataset({
      "example-org/app-one": { items: [{ id: 1, title: "reader", read_only: true, created_at: "2026-06-01T00:00:00Z", last_used: "2026-09-01T00:00:00Z" }] },
      "example-org/app-two": { items: [] },
    }),
    ...overrides,
  };
}

function createCodeSecurityConfiguration(overrides = {}) {
  return {
    id: 1,
    name: "Default security baseline",
    target_type: "organization",
    description: "Baseline applied to new repositories",
    enforcement: "enforced",
    advanced_security: "enabled",
    dependency_graph: "enabled",
    dependabot_alerts: "enabled",
    dependabot_security_updates: "enabled",
    code_scanning_default_setup: "enabled",
    secret_scanning: "enabled",
    secret_scanning_push_protection: "enabled",
    ...overrides,
  };
}

function createCodeSecurityData(overrides = {}) {
  const configuration = createCodeSecurityConfiguration({
    secret_scanning_push_protection: "disabled",
    dependabot_security_updates: "disabled",
  });
  return {
    org: dataset({
      login: "example-org",
      secret_scanning_enabled_for_new_repositories: true,
      secret_scanning_push_protection_enabled_for_new_repositories: false,
      dependabot_alerts_enabled_for_new_repositories: true,
      dependabot_security_updates_enabled_for_new_repositories: false,
    }),
    repositories: dataset([{ id: 1 }, { id: 2 }]),
    codeSecurityConfigurations: dataset([configuration]),
    codeSecurityDefaults: dataset([{ default_for_new_repos: "all", configuration }]),
    ...overrides,
  };
}

test("resolveGitHubConfiguration prefers explicit args over environment values", async () => {
  const resolved = await resolveGitHubConfiguration(
    {
      organization: "https://github.com/arg-org",
      api_token: "arg-token",
      lookback_days: 45,
    },
    {
      GITHUB_ORG: "env-org",
      GH_TOKEN: "env-token",
      GITHUB_API_BASE_URL: "api.github.enterprise.local/api/v3",
      GITHUB_LOOKBACK_DAYS: "14",
    },
  );

  assert.equal(resolved.organization, "arg-org");
  assert.equal(resolved.apiToken, "arg-token");
  assert.equal(resolved.authMode, "pat");
  assert.equal(resolved.lookbackDays, 45);
  assert.equal(resolved.apiBaseUrl, "https://api.github.enterprise.local/api/v3");
  assert.equal(resolved.graphqlUrl, "https://api.github.enterprise.local/api/graphql");
  assert.deepEqual(resolved.sourceChain, ["environment", "arguments"]);
});

test("resolveGitHubConfiguration honors the spec env aliases for API, GraphQL, and enterprise", async () => {
  const fromSpecNames = await resolveGitHubConfiguration({}, {
    GITHUB_ORG: "env-org",
    GITHUB_TOKEN: "env-token",
    GITHUB_ENTERPRISE: "https://github.com/env-enterprise/",
    GITHUB_API_URL: "https://ghes.example.test/api/v3/",
    GITHUB_GRAPHQL_URL: "https://ghes.example.test/api/graphql",
  });
  assert.equal(fromSpecNames.enterprise, "env-enterprise");
  assert.equal(fromSpecNames.apiBaseUrl, "https://ghes.example.test/api/v3");
  assert.equal(fromSpecNames.graphqlUrl, "https://ghes.example.test/api/graphql");

  const specNameWins = await resolveGitHubConfiguration({}, {
    GITHUB_ORG: "env-org",
    GITHUB_TOKEN: "env-token",
    GITHUB_API_URL: "https://spec.example.test/api/v3",
    GITHUB_API_BASE_URL: "https://legacy.example.test/api/v3",
  });
  assert.equal(specNameWins.apiBaseUrl, "https://spec.example.test/api/v3");
  assert.equal(specNameWins.graphqlUrl, "https://spec.example.test/api/graphql");

  const defaults = await resolveGitHubConfiguration({ organization: "example-org", api_token: "token" }, {});
  assert.equal(defaults.apiBaseUrl, "https://api.github.com");
  assert.equal(defaults.graphqlUrl, "https://api.github.com/graphql");
  assert.equal(defaults.enterprise, undefined);

  const explicitArgs = await resolveGitHubConfiguration(
    { organization: "example-org", api_token: "token", enterprise: "arg-enterprise", graphql_url: "https://gql.example.test/graphql" },
    { GITHUB_ENTERPRISE: "env-enterprise", GITHUB_GRAPHQL_URL: "https://env.example.test/graphql" },
  );
  assert.equal(explicitArgs.enterprise, "arg-enterprise");
  assert.equal(explicitArgs.graphqlUrl, "https://gql.example.test/graphql");
});

test("GitHubAuditorClient.graphql posts to the GraphQL endpoint and surfaces partial errors", async () => {
  const seen = [];
  const config = createSampleConfig({ graphqlUrl: "https://api.github.test/graphql", apiBaseUrl: "https://api.github.test" });
  const fetchImpl = async (input, init = {}) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    seen.push({ url: url.toString(), method: init.method, headers: init.headers, body: JSON.parse(init.body) });
    if (seen.length === 1) {
      return new Response(
        JSON.stringify({ data: { organization: { login: "example-org", ipAllowListEnabledSetting: "ENABLED" } } }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }
    return new Response(
      JSON.stringify({
        data: { organization: { login: "example-org", samlIdentityProvider: null } },
        errors: [{ type: "FORBIDDEN", message: "Resource not accessible by integration", path: ["organization", "samlIdentityProvider"] }],
      }),
      { status: 200, headers: { "content-type": "application/json" } },
    );
  };

  const client = new GitHubAuditorClient(config, fetchImpl);
  const clean = await client.graphql("query($login: String!) { organization(login: $login) { login ipAllowListEnabledSetting } }", { login: "example-org" });
  assert.equal(seen[0].url, "https://api.github.test/graphql");
  assert.equal(seen[0].method, "POST");
  assert.equal(seen[0].headers.Authorization, "Bearer ghp_test");
  assert.equal(seen[0].body.variables.login, "example-org");
  assert.match(seen[0].body.query, /ipAllowListEnabledSetting/);
  assert.deepEqual(clean.errors, []);
  assert.equal(clean.data.organization.ipAllowListEnabledSetting, "ENABLED");

  const partial = await client.graphql("query { organization(login: \"example-org\") { login samlIdentityProvider { ssoUrl } } }");
  assert.equal(partial.data.organization.samlIdentityProvider, null);
  assert.equal(partial.errors.length, 1);
  assert.equal(partial.errors[0].type, "FORBIDDEN");
  assert.deepEqual(partial.errors[0].path, ["organization", "samlIdentityProvider"]);

  const failing = new GitHubAuditorClient(config, async () => new Response(
    JSON.stringify({ message: "Bad credentials" }),
    { status: 401, headers: { "content-type": "application/json" } },
  ));
  await assert.rejects(() => failing.graphql("query { viewer { login } }"), /Bad credentials/);
});

test("resolveGitHubConfiguration loads GitHub App private key from a file path", async () => {
  const base = createTempBase("grclanker-github-config-");
  const privateKeyPath = join(base, "github-app.pem");
  writeFileSync(privateKeyPath, "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n");

  const resolved = await resolveGitHubConfiguration({
    organization: "example-org",
    auth_mode: "app",
    app_id: "123",
    app_private_key_path: privateKeyPath,
    installation_id: "456",
  });

  assert.equal(resolved.authMode, "app");
  assert.equal(resolved.appId, "123");
  assert.equal(resolved.installationId, "456");
  assert.match(resolved.appPrivateKey, /BEGIN PRIVATE KEY/);
});

test("GitHubAuditorClient handles installation token refresh, rate limits, and pagination", async () => {
  clearGitHubTokenCacheForTests();
  const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const pem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  const state = {
    tokenRequests: 0,
    repo401Count: 0,
    rulesetRateLimitCount: 0,
  };

  const config = createSampleConfig({
    organization: "example-org",
    authMode: "app",
    apiToken: undefined,
    appId: "12345",
    appPrivateKey: pem,
    installationId: "98765",
    apiBaseUrl: "https://api.github.test",
  });

  const fetchImpl = async (input, init = {}) => {
    const url = new URL(typeof input === "string" ? input : input.toString());

    if (url.pathname === "/app/installations/98765/access_tokens") {
      state.tokenRequests += 1;
      return new Response(
        JSON.stringify({
          token: `ghs_token_${state.tokenRequests}`,
          expires_at: "2035-01-01T00:00:00Z",
        }),
        { status: 201, headers: { "content-type": "application/json" } },
      );
    }

    if (url.pathname === "/orgs/example-org/repos") {
      if (url.searchParams.get("page") === "2") {
        return new Response(
          JSON.stringify([{ full_name: "example-org/repo-two" }]),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }

      if (state.repo401Count === 0) {
        state.repo401Count += 1;
        return new Response(
          JSON.stringify({ message: "Bad credentials" }),
          { status: 401, headers: { "content-type": "application/json" } },
        );
      }

      return new Response(
        JSON.stringify([{ full_name: "example-org/repo-one" }]),
        {
          status: 200,
          headers: {
            "content-type": "application/json",
            link: '<https://api.github.test/orgs/example-org/repos?per_page=100&type=all&page=2>; rel="next"',
          },
        },
      );
    }

    if (url.pathname === "/orgs/example-org/rulesets") {
      if (state.rulesetRateLimitCount === 0) {
        state.rulesetRateLimitCount += 1;
        return new Response(
          JSON.stringify({ message: "secondary rate limit" }),
          {
            status: 403,
            headers: {
              "content-type": "application/json",
              "x-ratelimit-remaining": "0",
              "x-ratelimit-reset": String(Math.floor(Date.now() / 1000)),
            },
          },
        );
      }

      return new Response(
        JSON.stringify([{ id: 1, enforcement: "active", rules: [] }]),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }

    throw new Error(`Unexpected request: ${url.toString()}`);
  };

  const client = new GitHubAuditorClient(config, fetchImpl);
  const repos = await client.listRepositories();
  const rulesets = await client.listOrgRulesets();

  assert.equal(repos.length, 2);
  assert.equal(rulesets.length, 1);
  assert.equal(state.tokenRequests, 2);
  assert.equal(state.repo401Count, 1);
  assert.equal(state.rulesetRateLimitCount, 1);
});

test("GitHub assessment helpers classify sample posture correctly", () => {
  const config = createSampleConfig();
  const orgAccess = assessGitHubOrgAccess(createOrgAccessData(), config);
  const repoProtection = assessGitHubRepoProtection(createRepoProtectionData(), config);
  const actions = assessGitHubActionsSecurity(createActionsData(), config);
  const codeSecurity = assessGitHubCodeSecurity(createCodeSecurityData(), config);

  assert.equal(orgAccess.findings.find((finding) => finding.id === "GITHUB-ORG-001")?.status, "Pass");
  assert.equal(orgAccess.findings.find((finding) => finding.id === "GITHUB-ORG-003")?.status, "Partial");
  assert.equal(repoProtection.findings.find((finding) => finding.id === "GITHUB-REPO-003")?.status, "Partial");
  assert.equal(actions.findings.find((finding) => finding.id === "GITHUB-ACT-001")?.status, "Fail");
  assert.equal(actions.findings.find((finding) => finding.id === "GITHUB-ACT-002")?.status, "Fail");
  assert.equal(codeSecurity.findings.find((finding) => finding.id === "GITHUB-CODE-002")?.status, "Pass");
  assert.equal(codeSecurity.findings.find((finding) => finding.id === "GITHUB-CODE-003")?.status, "Fail");
});

test("org access identity findings pass on a fully documented compliant tenant", () => {
  const config = createSampleConfig({ enterprise: "example-enterprise" });
  const result = assessGitHubOrgAccess(createOrgAccessData(), config);
  assert.equal(findingStatus(result, "GITHUB-ORG-001"), "Pass");
  assert.equal(findingStatus(result, "GITHUB-ORG-006"), "Pass");
  assert.equal(findingStatus(result, "GITHUB-ORG-007"), "Pass");
  assert.equal(findingStatus(result, "GITHUB-ORG-008"), "Pass");
  assert.equal(findingStatus(result, "GITHUB-ORG-009"), "Pass");
  assert.equal(findingStatus(result, "GITHUB-ORG-010"), "Pass");
  assert.equal(result.findings.length, 11);
  for (const finding of result.findings) {
    assert.ok(finding.frameworks.fedramp.length > 0, `${finding.id} lacks FedRAMP mapping`);
    assert.ok(finding.frameworks.cis.length > 0, `${finding.id} lacks CIS mapping`);
  }
});

test("org access identity findings fail or warn on weak posture", () => {
  const config = createSampleConfig({ enterprise: "example-enterprise" });
  const weak = assessGitHubOrgAccess(createOrgAccessData({
    org: dataset({
      login: "example-org",
      two_factor_requirement_enabled: false,
      default_repository_permission: "write",
      members_can_create_public_repositories: true,
      members_can_fork_private_repositories: true,
    }),
    twoFactorDisabledMembers: dataset([{ login: "dave" }]),
    samlIdentity: dataset(createSamlSnapshot({ samlIdentityProvider: null, externalIdentities: [], externalIdentitiesTotalCount: null })),
    ipAllowList: dataset(createIpAllowListSnapshot({ ipAllowListEnabledSetting: "DISABLED" })),
    enterpriseIdentity: dataset(createEnterpriseSnapshot({ ownerInfo: { samlIdentityProvider: null, oidcProvider: null } })),
  }), config);
  assert.equal(findingStatus(weak, "GITHUB-ORG-001"), "Fail");
  assert.match(weak.findings.find((entry) => entry.id === "GITHUB-ORG-001").summary, /1 member\(s\) currently have 2FA disabled/);
  assert.equal(findingStatus(weak, "GITHUB-ORG-006"), "Fail");
  assert.equal(findingStatus(weak, "GITHUB-ORG-007"), "Fail");
  assert.equal(findingStatus(weak, "GITHUB-ORG-008"), "Fail");
  assert.equal(findingStatus(weak, "GITHUB-ORG-009"), "Fail");
  assert.equal(findingStatus(weak, "GITHUB-ORG-010"), "Fail");

  const partiallyLinked = assessGitHubOrgAccess(createOrgAccessData({
    members: dataset([{ login: "alice" }, { login: "bob" }, { login: "carol" }, { login: "mallory" }]),
    ipAllowList: dataset(createIpAllowListSnapshot({ ipAllowListForInstalledAppsEnabledSetting: "DISABLED" })),
    enterpriseIdentity: dataset(createEnterpriseSnapshot({ ownerInfo: { samlIdentityProvider: { ssoUrl: "https://idp.example.test/sso", issuer: "x" }, oidcProvider: null } })),
  }), config);
  assert.equal(findingStatus(partiallyLinked, "GITHUB-ORG-006"), "Partial");
  assert.match(partiallyLinked.findings.find((entry) => entry.id === "GITHUB-ORG-006").summary, /1 of 4 member\(s\) have no linked SAML identity/);
  assert.equal(findingStatus(partiallyLinked, "GITHUB-ORG-007"), "Partial");
  assert.equal(findingStatus(partiallyLinked, "GITHUB-ORG-008"), "Partial");

  const noActiveEntries = assessGitHubOrgAccess(createOrgAccessData({
    ipAllowList: dataset(createIpAllowListSnapshot({ entries: [{ allowListValue: "10.0.0.1", isActive: false }] })),
  }), config);
  assert.equal(findingStatus(noActiveEntries, "GITHUB-ORG-008"), "Partial");

  const enterpriseSsoOnly = assessGitHubOrgAccess(createOrgAccessData({
    samlIdentity: dataset(createSamlSnapshot({ samlIdentityProvider: null, externalIdentities: [] })),
  }), config);
  assert.equal(findingStatus(enterpriseSsoOnly, "GITHUB-ORG-006"), "Pass");
  assert.match(enterpriseSsoOnly.findings.find((entry) => entry.id === "GITHUB-ORG-006").summary, /enterprise example-enterprise carries an identity provider \(OIDC\)/);
});

test("org access identity findings render manual when scoped out or forbidden", () => {
  const noEnterprise = assessGitHubOrgAccess(createOrgAccessData({
    enterpriseIdentity: dataset(null),
    samlIdentity: dataset(createSamlSnapshot({ samlIdentityProvider: null, externalIdentities: [] })),
  }), createSampleConfig());
  assert.equal(findingStatus(noEnterprise, "GITHUB-ORG-007"), "Manual");
  assert.match(noEnterprise.findings.find((entry) => entry.id === "GITHUB-ORG-007").summary, /Scoped out/);
  assert.equal(findingStatus(noEnterprise, "GITHUB-ORG-006"), "Fail");

  const forbiddenSaml = assessGitHubOrgAccess(createOrgAccessData({
    samlIdentity: dataset(createSamlSnapshot({
      samlIdentityProvider: null,
      externalIdentities: [],
      errors: [{ type: "FORBIDDEN", message: "Resource not accessible by integration", path: ["organization", "samlIdentityProvider"] }],
    })),
    ipAllowList: dataset(createIpAllowListSnapshot({ ipAllowListEnabledSetting: null, errors: [{ type: "FORBIDDEN", message: "nope", path: ["organization", "ipAllowListEnabledSetting"] }] })),
    twoFactorDisabledMembers: dataset([], "GitHub request failed (422): filter is only available to organization owners"),
    enterpriseIdentity: dataset(createEnterpriseSnapshot({ ownerInfo: null, errors: [{ type: "FORBIDDEN", message: "nope", path: ["enterprise", "ownerInfo"] }] })),
  }), createSampleConfig({ enterprise: "example-enterprise" }));
  assert.equal(findingStatus(forbiddenSaml, "GITHUB-ORG-006"), "Manual");
  assert.equal(findingStatus(forbiddenSaml, "GITHUB-ORG-007"), "Manual");
  assert.equal(findingStatus(forbiddenSaml, "GITHUB-ORG-008"), "Manual");
  assert.equal(findingStatus(forbiddenSaml, "GITHUB-ORG-001"), "Partial");

  const ownerOnlyFieldsMissing = assessGitHubOrgAccess(createOrgAccessData({
    org: dataset({ login: "example-org", two_factor_requirement_enabled: true, default_repository_permission: "read" }),
  }), createSampleConfig());
  assert.equal(findingStatus(ownerOnlyFieldsMissing, "GITHUB-ORG-009"), "Manual");
  assert.equal(findingStatus(ownerOnlyFieldsMissing, "GITHUB-ORG-010"), "Manual");
});

test("GitHubAuditorClient identity collectors paginate GraphQL connections and use the documented 2FA filter", async () => {
  const config = createSampleConfig({ apiBaseUrl: "https://api.github.test", graphqlUrl: "https://api.github.test/graphql", enterprise: "example-enterprise" });
  const requests = [];
  const fetchImpl = async (input, init = {}) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    requests.push({ url, init });
    if (url.pathname === "/orgs/example-org/members") {
      assert.equal(url.searchParams.get("filter"), "2fa_disabled");
      return new Response(JSON.stringify([{ login: "dave" }]), { status: 200, headers: { "content-type": "application/json" } });
    }
    const body = JSON.parse(init.body);
    if (body.query.includes("GrclankerOrganizationSaml")) {
      assert.equal(body.variables.login, "example-org");
      assert.equal(body.variables.first, 100);
      const secondPage = body.variables.after === "cursor-1";
      return new Response(JSON.stringify({
        data: {
          organization: {
            login: "example-org",
            requiresTwoFactorAuthentication: true,
            samlIdentityProvider: {
              ssoUrl: "https://idp.example.test/sso",
              issuer: "https://idp.example.test",
              digestMethod: null,
              signatureMethod: null,
              externalIdentities: {
                totalCount: 2,
                pageInfo: { hasNextPage: !secondPage, endCursor: secondPage ? null : "cursor-1" },
                nodes: [secondPage
                  ? { guid: "2", samlIdentity: { nameId: "bob@example.test" }, scimIdentity: null, user: { login: "bob" } }
                  : { guid: "1", samlIdentity: { nameId: "alice@example.test" }, scimIdentity: null, user: { login: "alice" } }],
              },
            },
          },
        },
      }), { status: 200, headers: { "content-type": "application/json" } });
    }
    if (body.query.includes("GrclankerOrganizationIpAllowList")) {
      const secondPage = body.variables.after === "ip-cursor";
      return new Response(JSON.stringify({
        data: {
          organization: {
            login: "example-org",
            ipAllowListEnabledSetting: "ENABLED",
            ipAllowListForInstalledAppsEnabledSetting: "DISABLED",
            ipAllowListEntries: {
              totalCount: 2,
              pageInfo: { hasNextPage: !secondPage, endCursor: secondPage ? null : "ip-cursor" },
              nodes: [{ allowListValue: secondPage ? "10.0.0.2" : "10.0.0.1", isActive: true, name: null, createdAt: "2025-01-01T00:00:00Z" }],
            },
          },
        },
      }), { status: 200, headers: { "content-type": "application/json" } });
    }
    if (body.query.includes("GrclankerEnterpriseIdentity")) {
      assert.equal(body.variables.slug, "example-enterprise");
      return new Response(JSON.stringify({
        data: { enterprise: { slug: "example-enterprise", ownerInfo: null } },
        errors: [{ type: "FORBIDDEN", message: "Resource not accessible", path: ["enterprise", "ownerInfo"] }],
      }), { status: 200, headers: { "content-type": "application/json" } });
    }
    throw new Error(`Unexpected request: ${url}`);
  };

  const client = new GitHubAuditorClient(config, fetchImpl);
  const disabled = await client.listTwoFactorDisabledMembers();
  assert.deepEqual(disabled.map((member) => member.login), ["dave"]);

  const saml = await client.getSamlIdentitySnapshot();
  assert.equal(saml.requiresTwoFactorAuthentication, true);
  assert.equal(saml.samlIdentityProvider.ssoUrl, "https://idp.example.test/sso");
  assert.deepEqual(saml.externalIdentities.map((identity) => identity.user.login), ["alice", "bob"]);
  assert.equal(saml.externalIdentitiesTotalCount, 2);
  assert.equal(saml.externalIdentitiesTruncated, false);

  const ipAllowList = await client.getIpAllowListSnapshot();
  assert.equal(ipAllowList.ipAllowListEnabledSetting, "ENABLED");
  assert.deepEqual(ipAllowList.entries.map((entry) => entry.allowListValue), ["10.0.0.1", "10.0.0.2"]);

  const enterprise = await client.getEnterpriseIdentitySnapshot();
  assert.equal(enterprise.slug, "example-enterprise");
  assert.equal(enterprise.ownerInfo, null);
  assert.equal(enterprise.errors[0].type, "FORBIDDEN");

  const noEnterprise = new GitHubAuditorClient(createSampleConfig(), fetchImpl);
  assert.equal(await noEnterprise.getEnterpriseIdentitySnapshot(), null);
  assert.equal(requests.filter((entry) => entry.url.pathname === "/graphql").length, 5);
});

function jsonResponse(body, headers = {}) {
  return new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json", ...headers } });
}

function createGraphqlPagingFetch({ samlPageInfo, ipPageInfo, samlTotal = 7000, ipTotal = 7000 }) {
  let samlPages = 0;
  let ipPages = 0;
  const fetchImpl = async (input, init) => {
    const body = JSON.parse(init.body);
    if (body.query.includes("GrclankerOrganizationSaml")) {
      samlPages += 1;
      return jsonResponse({
        data: {
          organization: {
            requiresTwoFactorAuthentication: true,
            samlIdentityProvider: {
              ssoUrl: "https://idp.example.test/sso",
              issuer: "https://idp.example.test",
              digestMethod: null,
              signatureMethod: null,
              externalIdentities: {
                totalCount: samlTotal,
                pageInfo: samlPageInfo(samlPages, body.variables.after),
                nodes: [{ guid: String(samlPages), samlIdentity: { nameId: `user${samlPages}@example.test` }, scimIdentity: null, user: { login: `user${samlPages}` } }],
              },
            },
          },
        },
      });
    }
    if (body.query.includes("GrclankerOrganizationIpAllowList")) {
      ipPages += 1;
      return jsonResponse({
        data: {
          organization: {
            ipAllowListEnabledSetting: "ENABLED",
            ipAllowListForInstalledAppsEnabledSetting: "ENABLED",
            ipAllowListEntries: {
              totalCount: ipTotal,
              pageInfo: ipPageInfo(ipPages, body.variables.after),
              nodes: [{ allowListValue: `10.0.0.${ipPages}`, isActive: true, name: null, createdAt: "2025-01-01T00:00:00Z" }],
            },
          },
        },
      });
    }
    throw new Error(`Unexpected GraphQL query: ${body.query.slice(0, 40)}`);
  };
  return { fetchImpl, pagesFetched: () => ({ saml: samlPages, ip: ipPages }) };
}

function createGraphqlConfig() {
  return createSampleConfig({ graphqlUrl: "https://api.github.com/graphql" });
}

function createTruncationOrgData(saml, ipAllowList) {
  return createOrgAccessData({
    members: dataset([{ login: "user1" }, { login: "user2" }]),
    samlIdentity: dataset(saml),
    ipAllowList: dataset(ipAllowList),
  });
}

test("GraphQL paging reports truncated when hasNextPage is true without an endCursor and demotes ORG-006 and ORG-008", async () => {
  const missingCursor = () => ({ hasNextPage: true, endCursor: null });
  const { fetchImpl, pagesFetched } = createGraphqlPagingFetch({ samlPageInfo: missingCursor, ipPageInfo: missingCursor });
  const client = new GitHubAuditorClient(createGraphqlConfig(), fetchImpl);

  const saml = await client.getSamlIdentitySnapshot();
  assert.equal(saml.externalIdentities.length, 1);
  assert.equal(saml.externalIdentitiesTotalCount, 7000);
  assert.equal(saml.externalIdentitiesTruncated, true);
  const ipAllowList = await client.getIpAllowListSnapshot();
  assert.equal(ipAllowList.entries.length, 1);
  assert.equal(ipAllowList.entriesTruncated, true);
  assert.deepEqual(pagesFetched(), { saml: 1, ip: 1 });

  const result = assessGitHubOrgAccess(createTruncationOrgData(saml, ipAllowList), createSampleConfig());
  const byId = Object.fromEntries(result.findings.map((finding) => [finding.id, finding]));
  assert.equal(byId["GITHUB-ORG-006"].status, "Partial");
  assert.match(byId["GITHUB-ORG-006"].evidence.join("\n"), /totalCount 7000, truncated/);
  assert.equal(byId["GITHUB-ORG-008"].status, "Partial");
  assert.match(byId["GITHUB-ORG-008"].evidence.join("\n"), /ip_allow_list_entries = 1 \(active 1, totalCount 7000, truncated\)/);
});

test("GraphQL paging reports truncated at the page cap and demotes ORG-006 and ORG-008", async () => {
  const endless = (page) => ({ hasNextPage: true, endCursor: `cursor-${page}` });
  const { fetchImpl, pagesFetched } = createGraphqlPagingFetch({ samlPageInfo: endless, ipPageInfo: endless });
  const client = new GitHubAuditorClient(createGraphqlConfig(), fetchImpl);

  const saml = await client.getSamlIdentitySnapshot();
  const ipAllowList = await client.getIpAllowListSnapshot();
  assert.deepEqual(pagesFetched(), { saml: 50, ip: 50 });
  assert.equal(saml.externalIdentities.length, 50);
  assert.equal(saml.externalIdentitiesTruncated, true);
  assert.equal(ipAllowList.entries.length, 50);
  assert.equal(ipAllowList.entriesTruncated, true);

  const result = assessGitHubOrgAccess(createTruncationOrgData(saml, ipAllowList), createSampleConfig());
  const byId = Object.fromEntries(result.findings.map((finding) => [finding.id, finding]));
  assert.notEqual(byId["GITHUB-ORG-006"].status, "Pass");
  assert.notEqual(byId["GITHUB-ORG-008"].status, "Pass");
});

test("GraphQL paging reports truncated when totalCount exceeds the collected nodes or the cursor repeats", async () => {
  const complete = () => ({ hasNextPage: false, endCursor: null });
  const shortfall = createGraphqlPagingFetch({ samlPageInfo: complete, ipPageInfo: complete, samlTotal: 3, ipTotal: 9 });
  const client = new GitHubAuditorClient(createGraphqlConfig(), shortfall.fetchImpl);
  const saml = await client.getSamlIdentitySnapshot();
  assert.equal(saml.externalIdentitiesTruncated, true, "totalCount 3 with one node collected is a shortfall");
  const ipAllowList = await client.getIpAllowListSnapshot();
  assert.equal(ipAllowList.entriesTruncated, true);
  assert.deepEqual(shortfall.pagesFetched(), { saml: 1, ip: 1 });

  const stuck = createGraphqlPagingFetch({
    samlPageInfo: () => ({ hasNextPage: true, endCursor: "same-cursor" }),
    ipPageInfo: () => ({ hasNextPage: true, endCursor: "same-cursor" }),
  });
  const stuckClient = new GitHubAuditorClient(createGraphqlConfig(), stuck.fetchImpl);
  const stuckSaml = await stuckClient.getSamlIdentitySnapshot();
  assert.equal(stuckSaml.externalIdentitiesTruncated, true);
  assert.deepEqual(stuck.pagesFetched().saml, 2, "a repeating cursor stops after the second page");

  assert.deepEqual(advanceGraphqlPage({ hasNextPage: false, endCursor: "x" }, null, 1), { nextCursor: null, truncated: false });
  assert.deepEqual(advanceGraphqlPage({ hasNextPage: true, endCursor: null }, null, 1), { nextCursor: null, truncated: true });
  assert.deepEqual(advanceGraphqlPage({ hasNextPage: true, endCursor: "b" }, "a", 1), { nextCursor: "b", truncated: false });
  assert.deepEqual(advanceGraphqlPage({ hasNextPage: true, endCursor: "b" }, "a", 50), { nextCursor: null, truncated: true });
});

test("audit log collection uses the created:>= phrase window and reports the record cap through the snapshot", async () => {
  const window = buildAuditLogWindow(30, new Date("2026-09-21T17:00:00Z"));
  assert.deepEqual(window, { createdSince: "2026-08-22", phrase: "created:>=2026-08-22" });

  const buildFetch = (pages) => {
    const seen = [];
    const fetchImpl = async (input) => {
      const url = new URL(typeof input === "string" ? input : input.toString());
      seen.push(url);
      const pageIndex = Number(url.searchParams.get("page") ?? "1") - 1;
      const page = pages[pageIndex];
      const headers = page.next
        ? { link: `<${url.origin}${url.pathname}?${url.searchParams.toString().replace(/&page=\d+/, "")}&page=${pageIndex + 2}>; rel="next"` }
        : {};
      return jsonResponse(page.records, headers);
    };
    return { fetchImpl, seen };
  };
  const events = (count, offset = 0) => Array.from({ length: count }, (_, index) => ({ action: "repo.create", "@timestamp": offset + index }));

  const exact = buildFetch([{ records: events(100), next: true }, { records: events(100, 100), next: false }]);
  const exactSnapshot = await new GitHubAuditorClient(createSampleConfig(), exact.fetchImpl).listAuditLog(30);
  assert.equal(exactSnapshot.events.length, 200);
  assert.equal(exactSnapshot.truncated, false, "exactly 200 events with no next link is complete");
  assert.equal(exactSnapshot.limit, 200);
  assert.equal(exact.seen[0].searchParams.get("phrase"), `created:>=${exactSnapshot.createdSince}`);
  assert.equal(exact.seen[0].searchParams.get("include"), "all");
  assert.equal(exact.seen[0].searchParams.has("after"), false, "after is a pagination cursor, not a timestamp");

  const capped = buildFetch([{ records: events(100), next: true }, { records: events(100, 100), next: true }, { records: events(100, 200), next: false }]);
  const cappedSnapshot = await new GitHubAuditorClient(createSampleConfig(), capped.fetchImpl).listAuditLog(30);
  assert.equal(cappedSnapshot.events.length, 200);
  assert.equal(cappedSnapshot.truncated, true, "a next link after the cap means events were left behind");
  assert.equal(capped.seen.length, 2, "the collector stops requesting pages at the cap");

  const overflow = buildFetch([{ records: events(100), next: true }, { records: events(150, 100), next: false }]);
  const overflowSnapshot = await new GitHubAuditorClient(createSampleConfig(), overflow.fetchImpl).listAuditLog(30);
  assert.equal(overflowSnapshot.events.length, 200);
  assert.equal(overflowSnapshot.truncated, true, "records dropped inside a page mark the sample truncated");

  const small = buildFetch([{ records: events(3), next: false }]);
  const smallSnapshot = await new GitHubAuditorClient(createSampleConfig(), small.fetchImpl).listAuditLog(30);
  assert.equal(smallSnapshot.truncated, false);

  // A Link header that points back at the first page can never complete the inventory.
  const loopingFetch = async (input) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    return jsonResponse([{ login: "alice" }], { link: `<${url.origin}${url.pathname}?${url.searchParams.toString()}>; rel="next"` });
  };
  const loopingClient = new GitHubAuditorClient(createSampleConfig(), loopingFetch);
  const loopingAudit = await loopingClient.listAuditLog(30);
  assert.equal(loopingAudit.truncated, true, "the capped audit log reports the repeated page as truncation");
  assert.equal(loopingAudit.events.length, 1);
  await assert.rejects(() => loopingClient.listMembers(), /repeated a page already fetched/);

  const cappedResult = assessGitHubOrgAccess(createOrgAccessData({ auditLog: dataset(cappedSnapshot) }), createSampleConfig());
  const cappedFinding = cappedResult.findings.find((finding) => finding.id === "GITHUB-ORG-005");
  assert.match(cappedFinding.summary, /sample capped at 200 events, so this is a visibility check/);
  assert.match(cappedFinding.evidence.join("\n"), /audit_log_window = phrase created:>=/);
  const exactResult = assessGitHubOrgAccess(createOrgAccessData({ auditLog: dataset(exactSnapshot) }), createSampleConfig());
  const exactFinding = exactResult.findings.find((finding) => finding.id === "GITHUB-ORG-005");
  assert.doesNotMatch(exactFinding.summary, /capped/);
  assert.match(exactFinding.evidence.join("\n"), /audit_events_last_30_days = 200 \(complete within the window\)/);
});

test("repo protection findings read review and status-check detail from rules and legacy protection", () => {
  const config = createSampleConfig();
  const mixed = assessGitHubRepoProtection(createRepoProtectionData(), config);
  assert.equal(mixed.findings.length, 7);
  assert.equal(findingStatus(mixed, "GITHUB-REPO-002"), "Pass");
  assert.equal(findingStatus(mixed, "GITHUB-REPO-003"), "Partial");
  assert.equal(findingStatus(mixed, "GITHUB-REPO-004"), "Pass");
  assert.equal(findingStatus(mixed, "GITHUB-REPO-006"), "Pass");
  assert.equal(findingStatus(mixed, "GITHUB-REPO-007"), "Pass");
  assert.equal(findingStatus(mixed, "GITHUB-REPO-001"), "Partial");
  assert.match(mixed.findings.find((entry) => entry.id === "GITHUB-REPO-001").summary, /1 of 2 active default branches receive organization-sourced rules/);

  const rulesOnly = assessGitHubRepoProtection(createRepoProtectionData({
    branchProtections: dataset({ "example-org/app-one": null, "example-org/app-two": null }),
    branchRules: dataset({
      "example-org/app-one": createBranchRules()["example-org/app-one"],
      "example-org/app-two": createBranchRules()["example-org/app-one"],
    }),
  }), config);
  for (const id of ["GITHUB-REPO-001", "GITHUB-REPO-002", "GITHUB-REPO-003", "GITHUB-REPO-004", "GITHUB-REPO-006", "GITHUB-REPO-007"]) {
    assert.equal(findingStatus(rulesOnly, id), "Pass", `${id} should pass from organization-sourced rules alone`);
  }

  const legacyOnly = assessGitHubRepoProtection(createRepoProtectionData({
    branchRules: dataset({ "example-org/app-one": { rules: [] }, "example-org/app-two": { rules: [] } }),
    branchProtections: dataset({
      "example-org/app-one": {
        required_pull_request_reviews: { required_approving_review_count: 1, require_code_owner_reviews: true, dismiss_stale_reviews: true, require_last_push_approval: false },
        required_status_checks: { strict: false, contexts: [], checks: [{ context: "build", app_id: 15368 }] },
        enforce_admins: { enabled: true },
        required_signatures: { enabled: true },
        allow_force_pushes: { enabled: false },
        allow_deletions: { enabled: false },
      },
      "example-org/app-two": {
        required_pull_request_reviews: { required_approving_review_count: 0 },
        required_status_checks: { strict: true, contexts: [] },
        enforce_admins: { enabled: false },
        required_signatures: { enabled: false },
        allow_force_pushes: { enabled: true },
        allow_deletions: { enabled: false },
      },
    }),
  }), config);
  assert.equal(findingStatus(legacyOnly, "GITHUB-REPO-002"), "Partial");
  assert.equal(findingStatus(legacyOnly, "GITHUB-REPO-006"), "Partial");
  assert.match(legacyOnly.findings.find((entry) => entry.id === "GITHUB-REPO-006").evidence.join("\n"), /repos_requiring_pull_request_without_review_count = 1/);
  assert.equal(findingStatus(legacyOnly, "GITHUB-REPO-007"), "Partial");
  assert.equal(findingStatus(legacyOnly, "GITHUB-REPO-004"), "Partial");

  const unprotected = assessGitHubRepoProtection(createRepoProtectionData({
    orgRulesets: dataset([]),
    branchRules: dataset({ "example-org/app-one": { rules: [] }, "example-org/app-two": { rules: [] } }),
    branchProtections: dataset({ "example-org/app-one": null, "example-org/app-two": null }),
  }), config);
  for (const id of ["GITHUB-REPO-001", "GITHUB-REPO-002", "GITHUB-REPO-003", "GITHUB-REPO-004", "GITHUB-REPO-006", "GITHUB-REPO-007"]) {
    assert.equal(findingStatus(unprotected, id), "Fail", `${id} should fail with no protection`);
  }
});

test("repo protection findings never pass on unreadable or partially readable inventories", () => {
  const config = createSampleConfig();
  const unreadableRepos = assessGitHubRepoProtection(createRepoProtectionData({
    repositories: dataset([], "GitHub request failed (403): Resource not accessible"),
    branchRules: dataset({}),
    branchProtections: dataset({}),
  }), config);
  for (const id of ["GITHUB-REPO-001", "GITHUB-REPO-002", "GITHUB-REPO-003", "GITHUB-REPO-004", "GITHUB-REPO-006", "GITHUB-REPO-007"]) {
    assert.equal(findingStatus(unreadableRepos, id), "Manual", `${id} should be manual when repositories are unreadable`);
  }

  const partiallyReadable = assessGitHubRepoProtection(createRepoProtectionData({
    branchProtections: dataset({}, "GitHub request failed (403): branch protection requires admin"),
    branchRules: dataset({
      "example-org/app-one": createBranchRules()["example-org/app-one"],
      "example-org/app-two": { rules: null, error: "GitHub request failed (403): forbidden" },
    }),
  }), config);
  for (const id of ["GITHUB-REPO-002", "GITHUB-REPO-003", "GITHUB-REPO-004", "GITHUB-REPO-006", "GITHUB-REPO-007"]) {
    assert.equal(findingStatus(partiallyReadable, id), "Partial", `${id} should be partial when one repo is not evaluable`);
    assert.match(partiallyReadable.findings.find((entry) => entry.id === id).summary, /1 repositories could not be evaluated/);
  }

  const noRepos = assessGitHubRepoProtection(createRepoProtectionData({
    repositories: dataset([]),
    branchRules: dataset({}),
    branchProtections: dataset({}),
  }), config);
  assert.equal(findingStatus(noRepos, "GITHUB-REPO-002"), "Info");
  assert.equal(findingStatus(noRepos, "GITHUB-REPO-006"), "Info");
});

test("collectGitHubRepoProtectionData reads branch rules per repository and records per-repo failures", async () => {
  const requests = [];
  const client = new GitHubAuditorClient(createSampleConfig({ apiBaseUrl: "https://api.github.test" }), async (input) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    requests.push(url.pathname + url.search);
    const json = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
    if (url.pathname === "/orgs/example-org") return json({ login: "example-org" });
    if (url.pathname === "/orgs/example-org/repos") {
      return json([
        { full_name: "example-org/app-one", name: "app-one", default_branch: "main", owner: { login: "example-org" } },
        { full_name: "example-org/app-two", name: "app-two", default_branch: "release/2026", owner: { login: "example-org" } },
        { full_name: "example-org/old", name: "old", default_branch: "main", archived: true, owner: { login: "example-org" } },
      ]);
    }
    if (url.pathname === "/orgs/example-org/rulesets") return json([]);
    if (url.pathname.endsWith("/rulesets")) return json([]);
    if (url.pathname.endsWith("/protection")) return json({ message: "Not Found" }, 404);
    if (url.pathname === "/repos/example-org/app-one/rules/branches/main") {
      return json([{ type: "pull_request", parameters: { required_approving_review_count: 1 }, ruleset_source_type: "Organization", ruleset_source: "example-org", ruleset_id: 7 }]);
    }
    if (url.pathname === "/repos/example-org/app-two/rules/branches/release%2F2026") {
      return json({ message: "Resource not accessible by integration" }, 403);
    }
    throw new Error(`Unexpected request: ${url}`);
  });

  const data = await collectGitHubRepoProtectionData(client);
  assert.equal(data.branchRules.error, undefined);
  assert.equal(data.branchRules.data["example-org/app-one"].rules.length, 1);
  assert.equal(data.branchRules.data["example-org/app-two"].rules, null);
  assert.match(data.branchRules.data["example-org/app-two"].error, /403/);
  assert.equal(data.branchRules.data["example-org/old"], undefined);
  assert.ok(requests.includes("/repos/example-org/app-one/rules/branches/main?per_page=100"));
  assert.ok(requests.includes("/repos/example-org/app-two/rules/branches/release%2F2026?per_page=100"));
});

test("integrations findings classify webhook, deploy key, and app installation posture", () => {
  const config = createSampleConfig();
  const now = Date.parse("2026-09-21T00:00:00Z");
  const healthy = assessGitHubIntegrations(createIntegrationsData(), config, now);
  assert.equal(healthy.findings.length, 5);
  assert.equal(findingStatus(healthy, "GITHUB-INTEG-001"), "Pass");
  assert.equal(findingStatus(healthy, "GITHUB-INTEG-002"), "Pass");
  assert.equal(findingStatus(healthy, "GITHUB-INTEG-003"), "Pass");
  assert.equal(findingStatus(healthy, "GITHUB-INTEG-004"), "Manual");
  assert.match(healthy.findings.find((entry) => entry.id === "GITHUB-INTEG-004").evidence.join("\n"), /organization-full \(REST\) and Organization \(GraphQL\) carry no field/);

  const weak = assessGitHubIntegrations(createIntegrationsData({
    hooks: dataset([
      { id: 100, active: true, config: { url: "http://siem.example.test/github", insecure_ssl: "1", content_type: "json" } },
    ]),
    repoHooks: dataset({
      "example-org/app-one": { items: [{ id: 5, config: { url: "https://ci.example.test/hook", insecure_ssl: 1, secret: "********" } }] },
      "example-org/app-two": { items: [] },
    }),
    deployKeys: dataset({
      "example-org/app-one": { items: [{ id: 1, title: "writer", read_only: false, created_at: "2026-06-01T00:00:00Z" }] },
      "example-org/app-two": { items: [{ id: 2, title: "ancient", read_only: true, created_at: "2024-01-01T00:00:00Z" }] },
    }),
    appInstallations: dataset([
      { id: 1, app_slug: "everything-bot", repository_selection: "all", permissions: { contents: "write", administration: "write" }, suspended_at: null, updated_at: "2026-01-01T00:00:00Z" },
      { id: 2, app_slug: "root-bot", repository_selection: "selected", permissions: { organization_administration: "admin" }, suspended_at: null, updated_at: "2026-01-01T00:00:00Z" },
    ]),
  }), config, now);
  assert.equal(findingStatus(weak, "GITHUB-INTEG-001"), "Fail");
  assert.match(weak.findings.find((entry) => entry.id === "GITHUB-INTEG-001").summary, /2 webhook\(s\)/);
  assert.equal(findingStatus(weak, "GITHUB-INTEG-002"), "Fail");
  assert.match(weak.findings.find((entry) => entry.id === "GITHUB-INTEG-002").summary, /1 write-capable and 1 stale/);
  assert.equal(findingStatus(weak, "GITHUB-INTEG-003"), "Fail");
  assert.match(weak.findings.find((entry) => entry.id === "GITHUB-INTEG-003").summary, /2 of 2 GitHub App installation\(s\)/);

  const undatedAndSuspended = assessGitHubIntegrations(createIntegrationsData({
    deployKeys: dataset({
      "example-org/app-one": { items: [{ id: 1, title: "mystery", read_only: true, created_at: null }] },
      "example-org/app-two": { items: [] },
    }),
    appInstallations: dataset([
      { id: 3, app_slug: "sleepy-bot", repository_selection: "selected", permissions: { metadata: "read" }, suspended_at: "2026-02-01T00:00:00Z", updated_at: "2026-01-01T00:00:00Z" },
    ]),
  }), config, now);
  assert.equal(findingStatus(undatedAndSuspended, "GITHUB-INTEG-002"), "Partial");
  assert.equal(findingStatus(undatedAndSuspended, "GITHUB-INTEG-003"), "Partial");

  const keysDisabledByPolicy = assessGitHubIntegrations(createIntegrationsData({
    org: dataset({ login: "example-org", deploy_keys_enabled_for_repositories: false }),
    repositories: dataset([], "GitHub request failed (403): forbidden"),
    deployKeys: dataset({}),
    repoHooks: dataset({}),
  }), config, now);
  assert.equal(findingStatus(keysDisabledByPolicy, "GITHUB-INTEG-002"), "Pass");
  assert.equal(findingStatus(keysDisabledByPolicy, "GITHUB-INTEG-001"), "Partial");
});

test("integrations findings never pass on unreadable or partially readable inventories", () => {
  const config = createSampleConfig();
  const now = Date.parse("2026-09-21T00:00:00Z");
  const forbidden = assessGitHubIntegrations(createIntegrationsData({
    org: dataset(null, "GitHub request failed (403): forbidden"),
    hooks: dataset([], "GitHub request failed (403): forbidden"),
    appInstallations: dataset([], "GitHub request failed (403): forbidden"),
    credentialAuthorizations: dataset([], "GitHub request failed (403): forbidden"),
    repositories: dataset([], "GitHub request failed (403): forbidden"),
    repoHooks: dataset({}),
    deployKeys: dataset({}),
  }), config, now);
  for (const finding of forbidden.findings) {
    assert.equal(finding.status, "Manual", `${finding.id} should be manual when everything is forbidden`);
  }

  const partialRepos = assessGitHubIntegrations(createIntegrationsData({
    repoHooks: dataset({
      "example-org/app-one": { items: [] },
      "example-org/app-two": { items: null, error: "GitHub request failed (403): admin required" },
    }),
    deployKeys: dataset({
      "example-org/app-one": { items: [] },
      "example-org/app-two": { items: null, error: "GitHub request failed (403): admin required" },
    }),
  }), config, now);
  assert.equal(findingStatus(partialRepos, "GITHUB-INTEG-001"), "Partial");
  assert.equal(findingStatus(partialRepos, "GITHUB-INTEG-002"), "Partial");

  const empty = assessGitHubIntegrations(createIntegrationsData({
    hooks: dataset([]),
    appInstallations: dataset([]),
    repoHooks: dataset({ "example-org/app-one": { items: [] }, "example-org/app-two": { items: [] } }),
    deployKeys: dataset({ "example-org/app-one": { items: [] }, "example-org/app-two": { items: [] } }),
  }), config, now);
  for (const id of ["GITHUB-INTEG-001", "GITHUB-INTEG-002", "GITHUB-INTEG-003"]) {
    assert.equal(findingStatus(empty, id), "Pass");
    assert.match(empty.findings.find((entry) => entry.id === id).summary, /empty inventory is compliant/);
  }
});

test("collectGitHubIntegrationsData fans out repository hooks and deploy keys with per-repo error capture", async () => {
  const requests = [];
  const client = new GitHubAuditorClient(createSampleConfig({ apiBaseUrl: "https://api.github.test" }), async (input) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    requests.push(url.pathname);
    const json = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
    if (url.pathname === "/orgs/example-org") return json({ login: "example-org", deploy_keys_enabled_for_repositories: true });
    if (url.pathname === "/orgs/example-org/hooks") return json([{ id: 1, config: { url: "https://a.example.test", insecure_ssl: "0", secret: "********" } }]);
    if (url.pathname === "/orgs/example-org/installations") return json({ total_count: 1, installations: [{ id: 9, app_slug: "bot", permissions: { metadata: "read" }, repository_selection: "selected" }] });
    if (url.pathname === "/orgs/example-org/credential-authorizations") return json({ message: "Not Found" }, 404);
    if (url.pathname === "/orgs/example-org/repos") {
      return json([
        { full_name: "example-org/app-one", name: "app-one", owner: { login: "example-org" } },
        { full_name: "example-org/app-two", name: "app-two", owner: { login: "example-org" } },
      ]);
    }
    if (url.pathname === "/repos/example-org/app-one/hooks") return json([]);
    if (url.pathname === "/repos/example-org/app-two/hooks") return json({ message: "Must have admin rights" }, 403);
    if (url.pathname === "/repos/example-org/app-one/keys") return json([{ id: 1, read_only: true, created_at: "2026-01-01T00:00:00Z" }]);
    if (url.pathname === "/repos/example-org/app-two/keys") return json([]);
    throw new Error(`Unexpected request: ${url}`);
  });

  const data = await collectGitHubIntegrationsData(client);
  assert.equal(data.appInstallations.data.length, 1);
  assert.match(data.credentialAuthorizations.error, /404/);
  assert.deepEqual(data.repoHooks.data["example-org/app-one"].items, []);
  assert.equal(data.repoHooks.data["example-org/app-two"].items, null);
  assert.match(data.repoHooks.data["example-org/app-two"].error, /403/);
  assert.equal(data.deployKeys.data["example-org/app-one"].items.length, 1);
  assert.ok(requests.includes("/repos/example-org/app-two/keys"));
});

test("runGitHubAccessCheck reports healthy and limited surfaces", async () => {
  const config = createSampleConfig();
  const healthy = await runGitHubAccessCheck(
    {
      async requestJson(path) {
        if (path.includes("audit-log")) {
          return { response: new Response(JSON.stringify([{ action: "repo.create" }]), { status: 200, headers: { "content-type": "application/json" } }), payload: [{ action: "repo.create" }], rawText: "[]" };
        }
        return { response: new Response(JSON.stringify({ ok: true }), { status: 200, headers: { "content-type": "application/json" } }), payload: { ok: true }, rawText: "{}" };
      },
    },
    config,
  );
  assert.equal(healthy.status, "healthy");

  const limited = await runGitHubAccessCheck(
    {
      async requestJson(path) {
        if (path.includes("organization-roles")) {
          throw new Error("not readable");
        }
        return { response: new Response(JSON.stringify({ message: "forbidden" }), { status: 403, headers: { "content-type": "application/json" } }), payload: { message: "forbidden" }, rawText: "{}" };
      },
    },
    config,
  );
  assert.equal(limited.status, "limited");
});

test("exportGitHubAuditBundle writes evidence and respects secure output roots", async () => {
  const outputRoot = createTempBase("grclanker-github-export-");
  const config = createSampleConfig();
  const result = await exportGitHubAuditBundle(
    {
      async getOrganization() {
        return createOrgAccessData().org.data;
      },
      async listMembers(role = "all") {
        return role === "admin" ? createOrgAccessData().adminMembers.data : createOrgAccessData().members.data;
      },
      async listTwoFactorDisabledMembers() {
        return [];
      },
      async getSamlIdentitySnapshot() {
        return createSamlSnapshot();
      },
      async getIpAllowListSnapshot() {
        return createIpAllowListSnapshot();
      },
      async getEnterpriseIdentitySnapshot() {
        return createEnterpriseSnapshot();
      },
      async listOutsideCollaborators() {
        return createOrgAccessData().outsideCollaborators.data;
      },
      async listInvitations() {
        return createOrgAccessData().invitations.data;
      },
      async listOrganizationRoles() {
        return createOrgAccessData().organizationRoles.data;
      },
      async listCredentialAuthorizations() {
        return createOrgAccessData().credentialAuthorizations.data;
      },
      async listAuditLog() {
        return createOrgAccessData().auditLog.data;
      },
      async listHooks() {
        return createOrgAccessData().hooks.data;
      },
      async listInstallations() {
        return createOrgAccessData().appInstallations.data;
      },
      async listRepositories() {
        return createRepoProtectionData().repositories.data;
      },
      async listOrgRulesets() {
        return createRepoProtectionData().orgRulesets.data;
      },
      async listRepoRulesets(_owner, repo) {
        return createRepoProtectionData().repoRulesets.data[`example-org/${repo}`] ?? [];
      },
      async getBranchProtection(_owner, repo) {
        return createRepoProtectionData().branchProtections.data[`example-org/${repo}`] ?? null;
      },
      async listBranchRules(_owner, repo) {
        return createBranchRules()[`example-org/${repo}`]?.rules ?? [];
      },
      async getOrgActionsPermissions() {
        return createActionsData().actionsPermissions.data;
      },
      async getOrgSelectedActions() {
        return createActionsData().selectedActions.data;
      },
      async getOrgWorkflowPermissions() {
        return createActionsData().workflowPermissions.data;
      },
      async listRunnerGroups() {
        return createActionsData().runnerGroups.data;
      },
      async listRunners() {
        return createActionsData().runners.data;
      },
      async listCodeSecurityConfigurations() {
        return createCodeSecurityData().codeSecurityConfigurations.data;
      },
      async listCodeSecurityDefaultConfigurations() {
        return createCodeSecurityData().codeSecurityDefaults.data;
      },
      async listRepoHooks(_owner, repo) {
        return createIntegrationsData().repoHooks.data[`example-org/${repo}`]?.items ?? [];
      },
      async listDeployKeys(_owner, repo) {
        return createIntegrationsData().deployKeys.data[`example-org/${repo}`]?.items ?? [];
      },
    },
    config,
    outputRoot,
  );

  assert.ok(existsSync(join(result.outputDir, "QUICK_REFERENCE.md")));
  assert.ok(!existsSync(join(result.outputDir, "_errors.log")), "a clean run writes no error log");
  assert.equal(result.errorCount, 0);
  assert.ok(existsSync(join(result.outputDir, "analysis", "org_access.json")));
  assert.ok(existsSync(join(result.outputDir, "analysis", "repo_protection.json")));
  assert.ok(existsSync(join(result.outputDir, "analysis", "integrations.json")));
  assert.ok(existsSync(join(result.outputDir, "core_data", "integrations.json")));
  assert.ok(existsSync(join(result.outputDir, "compliance", "executive_summary.md")));
  assert.ok(existsSync(result.zipPath));
  assert.ok(result.findingCount > 0);

  const summary = readFileSync(join(result.outputDir, "compliance", "executive_summary.md"), "utf8");
  assert.match(summary, /GitHub Audit Executive Summary/);
  assert.throws(() => resolveSecureOutputPath(outputRoot, "../escape"));

  const symlinkBase = createTempBase("grclanker-github-symlink-");
  const target = join(symlinkBase, "target");
  const link = join(symlinkBase, "link");
  writeFileSync(target, "target");
  symlinkSync(target, link);
  assert.throws(() => resolveSecureOutputPath(link, "nested"));
});

class ForbiddenError extends Error {
  constructor() {
    super("HTTP 403 Forbidden: Resource not accessible by integration");
    this.status = 403;
  }
}

const SELF_CHECK_CONFIG = createSampleConfig({
  graphqlUrl: "https://api.github.com/graphql",
  enterprise: "example-enterprise",
});

const SELF_CHECK_ORG = {
  login: "example-org",
  two_factor_requirement_enabled: true,
  default_repository_permission: "read",
  web_commit_signoff_required: true,
  members_can_create_repositories: true,
  members_can_create_public_repositories: false,
  members_can_create_private_repositories: true,
  members_can_create_internal_repositories: true,
  members_can_fork_private_repositories: false,
  deploy_keys_enabled_for_repositories: true,
  advanced_security_enabled_for_new_repositories: true,
  dependabot_alerts_enabled_for_new_repositories: true,
  dependabot_security_updates_enabled_for_new_repositories: true,
  dependency_graph_enabled_for_new_repositories: true,
  secret_scanning_enabled_for_new_repositories: true,
  secret_scanning_push_protection_enabled_for_new_repositories: true,
};

const SELF_CHECK_REPOS = [
  { full_name: "example-org/app-one", name: "app-one", default_branch: "main", archived: false, disabled: false, owner: { login: "example-org" } },
  { full_name: "example-org/app-two", name: "app-two", default_branch: "main", archived: false, disabled: false, owner: { login: "example-org" } },
];

const SELF_CHECK_RULES = [
  {
    type: "pull_request",
    parameters: { required_approving_review_count: 2, require_code_owner_review: true, dismiss_stale_reviews_on_push: true, require_last_push_approval: true, required_review_thread_resolution: true, allowed_merge_methods: ["squash"] },
    ruleset_source_type: "Organization",
    ruleset_source: "example-org",
    ruleset_id: 1,
  },
  {
    type: "required_status_checks",
    parameters: { strict_required_status_checks_policy: true, do_not_enforce_on_create: false, required_status_checks: [{ context: "ci" }] },
    ruleset_source_type: "Organization",
    ruleset_source: "example-org",
    ruleset_id: 1,
  },
  { type: "required_signatures", ruleset_source_type: "Organization", ruleset_source: "example-org", ruleset_id: 1 },
  { type: "non_fast_forward", ruleset_source_type: "Organization", ruleset_source: "example-org", ruleset_id: 1 },
  { type: "deletion", ruleset_source_type: "Organization", ruleset_source: "example-org", ruleset_id: 1 },
];

const SELF_CHECK_PROTECTION = {
  required_pull_request_reviews: { required_approving_review_count: 2, dismiss_stale_reviews: true, require_code_owner_reviews: true },
  required_status_checks: { strict: true, contexts: ["ci"] },
  required_signatures: { enabled: true },
  allow_force_pushes: { enabled: false },
  allow_deletions: { enabled: false },
  enforce_admins: { enabled: true },
};

function createCompliantClient() {
  return {
    async getOrganization() { return SELF_CHECK_ORG; },
    async listMembers(role = "all") {
      return role === "admin" ? [{ login: "alice" }] : [{ login: "alice" }, { login: "bob" }, { login: "carol" }];
    },
    async listTwoFactorDisabledMembers() { return []; },
    async getSamlIdentitySnapshot() {
      return createSamlSnapshot({
        externalIdentities: [
          { guid: "1", samlIdentity: { nameId: "alice@example.test" }, scimIdentity: { username: "alice" }, user: { login: "alice" } },
          { guid: "2", samlIdentity: { nameId: "bob@example.test" }, scimIdentity: { username: "bob" }, user: { login: "bob" } },
          { guid: "3", samlIdentity: { nameId: "carol@example.test" }, scimIdentity: { username: "carol" }, user: { login: "carol" } },
        ],
      });
    },
    async getIpAllowListSnapshot() {
      return createIpAllowListSnapshot({
        entries: [{ allowListValue: "203.0.113.0/24", isActive: true, name: "HQ egress", createdAt: "2025-01-01T00:00:00Z" }],
        entriesTotalCount: 1,
      });
    },
    async getEnterpriseIdentitySnapshot() { return createEnterpriseSnapshot(); },
    async listOutsideCollaborators() { return []; },
    async listInvitations() { return []; },
    async listOrganizationRoles() { return [{ id: 1, name: "all_repo_read" }]; },
    async listCredentialAuthorizations() {
      return [{ login: "alice", credential_type: "personal access token", credential_authorized_at: "2026-01-01T00:00:00Z" }];
    },
    async listAuditLog() { return createAuditLogSnapshot({ events: [{ action: "repo.create", "@timestamp": 1758400000000 }] }); },
    async listHooks() {
      return [{ id: 100, active: true, config: { url: "https://siem.example.test/github", content_type: "json", insecure_ssl: "0", secret: "********" } }];
    },
    async listInstallations() {
      return [{ id: 99, app_slug: "compliance-bot", repository_selection: "selected", permissions: { metadata: "read", contents: "read" }, suspended_at: null, created_at: "2025-01-01T00:00:00Z", updated_at: "2026-01-01T00:00:00Z" }];
    },
    async listRepositories() { return SELF_CHECK_REPOS; },
    async listOrgRulesets() {
      return [{ id: 1, enforcement: "active", target: "branch", rules: SELF_CHECK_RULES.map((rule) => ({ type: rule.type })) }];
    },
    async listRepoRulesets() { return []; },
    async getBranchProtection() { return SELF_CHECK_PROTECTION; },
    async listBranchRules() { return SELF_CHECK_RULES; },
    async getOrgActionsPermissions() { return { enabled_repositories: "selected", allowed_actions: "selected" }; },
    async getOrgSelectedActions() { return { github_owned_allowed: true, verified_allowed: false, patterns_allowed: ["example-org/*"] }; },
    async getOrgWorkflowPermissions() { return { default_workflow_permissions: "read", can_approve_pull_request_reviews: false }; },
    async listRunnerGroups() {
      return [{ id: 1, name: "prod", visibility: "selected", allows_public_repositories: false, restricted_to_workflows: true }];
    },
    async listRunners() { return [{ id: 1, name: "runner-1", status: "online" }]; },
    async listCodeSecurityConfigurations() { return [createCodeSecurityConfiguration()]; },
    async listCodeSecurityDefaultConfigurations() {
      return [
        { default_for_new_repos: "public", configuration: createCodeSecurityConfiguration() },
        { default_for_new_repos: "private_and_internal", configuration: createCodeSecurityConfiguration({ id: 2, name: "Private baseline" }) },
      ];
    },
    async listRepoHooks() { return [{ id: 5, config: { url: "https://ci.example.test/hook", insecure_ssl: "0", secret: "********" } }]; },
    async listDeployKeys() { return [{ id: 1, title: "reader", read_only: true, created_at: "2026-06-01T00:00:00Z", last_used: "2026-09-01T00:00:00Z" }]; },
  };
}

function createForbiddenClient() {
  return Object.fromEntries(Object.keys(createCompliantClient()).map((name) => [name, async () => { throw new ForbiddenError(); }]));
}

function createEmptyClient() {
  return {
    ...createCompliantClient(),
    async listMembers() { return []; },
    async getSamlIdentitySnapshot() {
      return createSamlSnapshot({ samlIdentityProvider: null, externalIdentities: [], externalIdentitiesTotalCount: 0 });
    },
    async getIpAllowListSnapshot() { return createIpAllowListSnapshot({ entries: [], entriesTotalCount: 0 }); },
    async getEnterpriseIdentitySnapshot() { return createEnterpriseSnapshot({ ownerInfo: null }); },
    async listOrganizationRoles() { return []; },
    async listCredentialAuthorizations() { return []; },
    async listAuditLog() { return createAuditLogSnapshot({ events: [] }); },
    async listHooks() { return []; },
    async listInstallations() { return []; },
    async listRepositories() { return []; },
    async listOrgRulesets() { return []; },
    async listBranchRules() { return []; },
    async getBranchProtection() { return null; },
    async listRunnerGroups() { return []; },
    async listRunners() { return []; },
    async listCodeSecurityConfigurations() { return []; },
    async listCodeSecurityDefaultConfigurations() { return []; },
    async listRepoHooks() { return []; },
    async listDeployKeys() { return []; },
  };
}

function createPartialClient() {
  const base = createCompliantClient();
  return {
    ...base,
    async listMembers(role = "all") {
      if (role === "admin") throw new ForbiddenError();
      return base.listMembers(role);
    },
    async listTwoFactorDisabledMembers() { throw new ForbiddenError(); },
    async getSamlIdentitySnapshot() {
      return createSamlSnapshot({ externalIdentitiesTruncated: true, externalIdentitiesTotalCount: 5000 });
    },
    async getIpAllowListSnapshot() { return createIpAllowListSnapshot({ entriesTruncated: true, entriesTotalCount: 2000 }); },
    async getEnterpriseIdentitySnapshot() {
      return createEnterpriseSnapshot({ ownerInfo: null, errors: [{ type: "FORBIDDEN", message: "Resource not accessible", path: ["enterprise", "ownerInfo"] }] });
    },
    async listOutsideCollaborators() { throw new ForbiddenError(); },
    async listInstallations() { throw new ForbiddenError(); },
    async listAuditLog() {
      return createAuditLogSnapshot({
        events: Array.from({ length: 200 }, (_, index) => ({ action: "repo.create", "@timestamp": 1758400000000 + index })),
        truncated: true,
      });
    },
    async listRepoRulesets(_owner, repo) {
      if (repo === "app-two") throw new ForbiddenError();
      return [];
    },
    async getBranchProtection(_owner, repo) {
      if (repo === "app-two") throw new ForbiddenError();
      return SELF_CHECK_PROTECTION;
    },
    async listBranchRules(_owner, repo) {
      if (repo === "app-two") throw new ForbiddenError();
      return SELF_CHECK_RULES;
    },
    async listRunners() { throw new ForbiddenError(); },
    async listCodeSecurityConfigurations() { throw new ForbiddenError(); },
    async listCodeSecurityDefaultConfigurations() { throw new ForbiddenError(); },
    async listRepoHooks(_owner, repo) {
      if (repo === "app-two") throw new ForbiddenError();
      return base.listRepoHooks();
    },
    async listDeployKeys(_owner, repo) {
      if (repo === "app-two") throw new ForbiddenError();
      return base.listDeployKeys();
    },
  };
}

async function runAllAssessments(client) {
  const [orgAccess, repoProtection, actions, codeSecurity, integrations] = await Promise.all([
    collectGitHubOrgAccessData(client, SELF_CHECK_CONFIG),
    collectGitHubRepoProtectionData(client),
    collectGitHubActionsData(client),
    collectGitHubCodeSecurityData(client),
    collectGitHubIntegrationsData(client),
  ]);
  return [
    assessGitHubOrgAccess(orgAccess, SELF_CHECK_CONFIG),
    assessGitHubRepoProtection(repoProtection, SELF_CHECK_CONFIG),
    assessGitHubActionsSecurity(actions, SELF_CHECK_CONFIG),
    assessGitHubCodeSecurity(codeSecurity, SELF_CHECK_CONFIG),
    assessGitHubIntegrations(integrations, SELF_CHECK_CONFIG),
  ].flatMap((assessment) => assessment.findings);
}

function passingIds(findings) {
  return findings.filter((finding) => finding.status === "Pass").map((finding) => finding.id).sort();
}

// CODE-002 to CODE-005 are configuration-driven (default code security configurations), not
// setting-driven: the deprecated organization flags alone never carry a pass.
const SETTING_DRIVEN_IDS = [
  "GITHUB-ACT-001",
  "GITHUB-ACT-002",
  "GITHUB-ACT-003",
  "GITHUB-ACT-005",
  "GITHUB-ORG-002",
  "GITHUB-ORG-009",
  "GITHUB-ORG-010",
  "GITHUB-REPO-005",
];

test("self-check (a): every endpoint forbidden yields zero passes and names the cause", async () => {
  const findings = await runAllAssessments(createForbiddenClient());
  assert.equal(findings.length, 34);
  assert.deepEqual(passingIds(findings), []);
  for (const finding of findings) {
    assert.ok(["Manual", "Partial", "Fail", "Info"].includes(finding.status), `${finding.id} reported ${finding.status}`);
  }
  const manual = findings.filter((finding) => finding.status === "Manual");
  assert.ok(manual.length >= 33, `expected almost every finding manual, got ${manual.length}`);
  for (const finding of manual) {
    assert.ok(finding.manualNote || /unreadable|could not|not readable|unverified/i.test(finding.summary), `${finding.id} lacks a manual instruction`);
  }
});

test("self-check (b): empty inventories pass only where the control intent makes emptiness compliant", async () => {
  const findings = await runAllAssessments(createEmptyClient());
  const expectedPasses = [...SETTING_DRIVEN_IDS, "GITHUB-INTEG-003", "GITHUB-ORG-001", "GITHUB-ORG-003"].sort();
  assert.deepEqual(passingIds(findings), expectedPasses);
  const byId = Object.fromEntries(findings.map((finding) => [finding.id, finding]));
  assert.match(byId["GITHUB-ORG-001"].evidence.join("\n"), /two_factor_requirement_enabled = true/);
  assert.match(byId["GITHUB-ORG-003"].summary, /empty list is compliant/);
  assert.match(byId["GITHUB-INTEG-003"].summary, /empty inventory is compliant/);
  assert.equal(byId["GITHUB-ACT-004"].status, "Info");
  assert.match(byId["GITHUB-ACT-004"].summary, /not a pass/);
  assert.equal(byId["GITHUB-INTEG-001"].status, "Partial");
  assert.equal(byId["GITHUB-INTEG-002"].status, "Partial");
  assert.equal(byId["GITHUB-CODE-001"].status, "Fail");
  assert.match(byId["GITHUB-CODE-001"].summary, /empty configuration list is a fail/);
  for (const id of ["GITHUB-CODE-002", "GITHUB-CODE-003", "GITHUB-CODE-004"]) {
    assert.equal(byId[id].status, "Partial", `${id} must not pass when no default configuration exists even though the deprecated flag is true`);
    assert.match(byId[id].summary, /no default code security configuration applies/);
  }
  assert.equal(byId["GITHUB-CODE-005"].status, "Fail");
  assert.equal(byId["GITHUB-ORG-004"].status, "Manual");
  assert.equal(byId["GITHUB-ORG-005"].status, "Info");
  assert.equal(byId["GITHUB-ORG-006"].status, "Fail");
  assert.equal(byId["GITHUB-REPO-001"].status, "Fail");
  for (const id of ["GITHUB-REPO-002", "GITHUB-REPO-003", "GITHUB-REPO-004", "GITHUB-REPO-006", "GITHUB-REPO-007"]) {
    assert.equal(byId[id].status, "Info", `${id} should be Info on an empty repository inventory`);
  }
});

test("self-check (c): partial inventories never pass an inventory-driven control", async () => {
  const findings = await runAllAssessments(createPartialClient());
  const expectedPasses = [...SETTING_DRIVEN_IDS, "GITHUB-ORG-005"].sort();
  assert.deepEqual(passingIds(findings), expectedPasses);
  const byId = Object.fromEntries(findings.map((finding) => [finding.id, finding]));
  assert.match(byId["GITHUB-ORG-005"].summary, /visibility check, not a full population/);
  assert.equal(byId["GITHUB-ORG-001"].status, "Partial");
  assert.equal(byId["GITHUB-ORG-003"].status, "Manual");
  assert.equal(byId["GITHUB-ORG-004"].status, "Manual");
  assert.equal(byId["GITHUB-ORG-006"].status, "Partial");
  assert.equal(byId["GITHUB-ORG-007"].status, "Manual");
  assert.equal(byId["GITHUB-ORG-008"].status, "Partial");
  for (const id of ["GITHUB-REPO-001", "GITHUB-REPO-002", "GITHUB-REPO-003", "GITHUB-REPO-004", "GITHUB-REPO-006", "GITHUB-REPO-007"]) {
    assert.equal(byId[id].status, "Partial", `${id} should be Partial when one repository is unreadable`);
  }
  assert.equal(byId["GITHUB-ACT-004"].status, "Manual");
  assert.equal(byId["GITHUB-CODE-001"].status, "Manual");
  for (const id of ["GITHUB-CODE-002", "GITHUB-CODE-003", "GITHUB-CODE-004"]) {
    assert.equal(byId[id].status, "Partial", `${id} must not pass on the deprecated flag while the default configurations are unreadable`);
    assert.match(byId[id].summary, /enforcement is unverified/);
  }
  assert.equal(byId["GITHUB-CODE-005"].status, "Manual");
  assert.equal(byId["GITHUB-INTEG-001"].status, "Partial");
  assert.equal(byId["GITHUB-INTEG-002"].status, "Partial");
  assert.equal(byId["GITHUB-INTEG-003"].status, "Manual");
});

test("self-check (d): a compliant tenant built from documented fields passes every automatable control", async () => {
  const findings = await runAllAssessments(createCompliantClient());
  assert.equal(findings.length, 34);
  const notPassing = findings.filter((finding) => finding.status !== "Pass").map((finding) => `${finding.id}=${finding.status}`).sort();
  assert.deepEqual(notPassing, [
    "GITHUB-CODE-006=Manual",
    "GITHUB-INTEG-004=Manual",
    "GITHUB-INTEG-005=Manual",
    "GITHUB-ORG-011=Manual",
  ]);
  const byId = Object.fromEntries(findings.map((finding) => [finding.id, finding]));
  assert.match(byId["GITHUB-ORG-011"].evidence.join("\n"), /\/enterprises\/\{enterprise\}\/audit-log\/streams/);
  assert.match(byId["GITHUB-CODE-006"].evidence.join("\n"), /isSecurityPolicyEnabled/);
  assert.match(byId["GITHUB-INTEG-005"].evidence.join("\n"), /\/orgs\/\{org\}\/packages\?package_type=/);
  for (const id of ["GITHUB-CODE-006", "GITHUB-INTEG-004", "GITHUB-INTEG-005", "GITHUB-ORG-011"]) {
    assert.ok(byId[id].manualNote, `${id} must tell the reviewer what evidence to collect`);
  }
});

const SPEC_PATH = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "specs", "github-sec-inspector.spec.md");

function readSpecMappingTable() {
  const spec = readFileSync(SPEC_PATH, "utf8");
  const rows = new Map();
  const splitIds = (cell) => cell.split(",").map((entry) => entry.trim()).filter(Boolean);
  for (const line of spec.split("\n")) {
    const cells = line.split("|").map((cell) => cell.trim());
    // | # | Control | FedRAMP | CMMC | SOC 2 | CIS | PCI-DSS | DISA STIG | IRAP | ISMAP |
    if (cells.length !== 12 || !/^\d+$/.test(cells[1]) || !/^(?:[A-Z]{2}-\d|SRG)/.test(cells[3])) continue;
    rows.set(Number(cells[1]), {
      fedramp: splitIds(cells[3]),
      cmmc: splitIds(cells[4]),
      soc2: splitIds(cells[5]),
      cis: splitIds(cells[6]),
      pci_dss: splitIds(cells[7]),
      disa_stig: splitIds(cells[8]),
      irap: splitIds(cells[9]),
      ismap: splitIds(cells[10]),
    });
  }
  return rows;
}

function readSpecCoverageTable() {
  const spec = readFileSync(SPEC_PATH, "utf8");
  const coverage = new Map();
  for (const line of spec.split("\n")) {
    const cells = line.split("|").map((cell) => cell.trim());
    // | # | Control | Finding | Verdict semantics |
    if (cells.length !== 6 || !/^\d+$/.test(cells[1]) || !cells[3].startsWith("GITHUB-")) continue;
    coverage.set(Number(cells[1]), cells[3].split(",").map((entry) => entry.trim()));
  }
  return coverage;
}

test("every finding carries exactly the framework identifiers of its spec mapping row", async () => {
  const mappingRows = readSpecMappingTable();
  const coverage = readSpecCoverageTable();
  assert.equal(mappingRows.size, 25, "the spec mapping table has 25 rows");
  assert.equal(coverage.size, 25, "the spec coverage table has 25 rows");
  const findings = await runAllAssessments(createCompliantClient());
  const byId = Object.fromEntries(findings.map((finding) => [finding.id, finding]));
  const stripGeneral = ({ general: _general, ...frameworks }) => frameworks;

  const covered = new Set();
  for (const [control, ids] of coverage) {
    for (const id of ids) {
      assert.ok(byId[id], `${id} from coverage row ${control} is produced by the assessments`);
      assert.deepEqual(stripGeneral(byId[id].frameworks), mappingRows.get(control), `${id} must carry the control ${control} mapping row`);
      covered.add(id);
    }
  }
  // Findings without a numbered control: the extras carry the closest row, and the configuration
  // umbrella carries the union of the three code security rows it underpins.
  const union = (...controls) => {
    const merged = {};
    for (const control of controls) {
      for (const [framework, ids] of Object.entries(mappingRows.get(control))) {
        merged[framework] = [...(merged[framework] ?? []), ...ids.filter((id) => !(merged[framework] ?? []).includes(id))];
      }
    }
    return merged;
  };
  assert.deepEqual(stripGeneral(byId["GITHUB-ORG-004"].frameworks), mappingRows.get(5));
  assert.deepEqual(stripGeneral(byId["GITHUB-ORG-005"].frameworks), mappingRows.get(19));
  assert.deepEqual(stripGeneral(byId["GITHUB-REPO-005"].frameworks), mappingRows.get(13));
  assert.deepEqual(stripGeneral(byId["GITHUB-CODE-001"].frameworks), union(15, 16, 17));
  for (const id of ["GITHUB-ORG-004", "GITHUB-ORG-005", "GITHUB-REPO-005", "GITHUB-CODE-001"]) {
    covered.add(id);
  }
  assert.deepEqual(Object.keys(byId).filter((id) => !covered.has(id)), [], "every finding is either in the coverage table or an accounted extra");
});

function codeSecurityById(data) {
  const result = assessGitHubCodeSecurity(data, SELF_CHECK_CONFIG);
  return Object.fromEntries(result.findings.map((finding) => [finding.id, finding]));
}

test("self-check (e): unenforced pilot configurations never pass the code security default controls", () => {
  // A pilot: the configuration exists and enables everything, but it is not a default for any visibility.
  const pilot = createCodeSecurityConfiguration({ enforcement: "unenforced", name: "Pilot" });
  const pilotOnly = codeSecurityById({
    org: dataset({ login: "example-org" }),
    repositories: dataset([{ id: 1 }]),
    codeSecurityConfigurations: dataset([pilot]),
    codeSecurityDefaults: dataset([]),
  });
  assert.equal(pilotOnly["GITHUB-CODE-001"].status, "Partial");
  assert.match(pilotOnly["GITHUB-CODE-001"].summary, /none is applied to new repositories by default/);
  for (const id of ["GITHUB-CODE-002", "GITHUB-CODE-003", "GITHUB-CODE-004", "GITHUB-CODE-005"]) {
    assert.equal(pilotOnly[id].status, "Fail", `${id} must fail when no default configuration exists`);
    assert.match(pilotOnly[id].evidence.join("\n"), /default_configurations = 0/);
  }

  // A default that repository administrators can switch off: enabled but unenforced.
  const unenforcedDefault = codeSecurityById({
    org: dataset({ login: "example-org" }),
    repositories: dataset([{ id: 1 }]),
    codeSecurityConfigurations: dataset([pilot]),
    codeSecurityDefaults: dataset([{ default_for_new_repos: "all", configuration: pilot }]),
  });
  for (const id of ["GITHUB-CODE-002", "GITHUB-CODE-003", "GITHUB-CODE-004", "GITHUB-CODE-005"]) {
    assert.equal(unenforcedDefault[id].status, "Partial", `${id} must not pass on an unenforced default`);
    assert.match(unenforcedDefault[id].evidence.join("\n"), /enforcement = unenforced/);
  }
  assert.match(unenforcedDefault["GITHUB-CODE-002"].summary, /repository administrators can disable it/);
  assert.equal(unenforcedDefault["GITHUB-CODE-001"].status, "Pass");

  // The deprecated owner flags alone never carry a pass when the defaults contradict or are unreadable.
  const flagsOnly = codeSecurityById({
    org: dataset({
      login: "example-org",
      secret_scanning_enabled_for_new_repositories: true,
      secret_scanning_push_protection_enabled_for_new_repositories: true,
      dependabot_alerts_enabled_for_new_repositories: true,
      dependabot_security_updates_enabled_for_new_repositories: true,
    }),
    repositories: dataset([{ id: 1 }]),
    codeSecurityConfigurations: dataset([], "HTTP 403"),
    codeSecurityDefaults: dataset([], "HTTP 403"),
  });
  for (const id of ["GITHUB-CODE-002", "GITHUB-CODE-003", "GITHUB-CODE-004"]) {
    assert.equal(flagsOnly[id].status, "Partial", `${id} must not pass on the deprecated flag alone`);
  }
  assert.equal(flagsOnly["GITHUB-CODE-005"].status, "Manual");
  assert.equal(flagsOnly["GITHUB-CODE-001"].status, "Manual");

  // Coverage gaps: an enforced default for public repositories only, and a private default that disables a feature.
  const publicOnly = codeSecurityById({
    org: dataset({ login: "example-org" }),
    repositories: dataset([{ id: 1 }]),
    codeSecurityConfigurations: dataset([createCodeSecurityConfiguration()]),
    codeSecurityDefaults: dataset([{ default_for_new_repos: "public", configuration: createCodeSecurityConfiguration() }]),
  });
  assert.equal(publicOnly["GITHUB-CODE-002"].status, "Partial");
  assert.match(publicOnly["GITHUB-CODE-002"].summary, /public repositories only/);
  const privateDisabled = codeSecurityById({
    org: dataset({ login: "example-org" }),
    repositories: dataset([{ id: 1 }]),
    codeSecurityConfigurations: dataset([createCodeSecurityConfiguration()]),
    codeSecurityDefaults: dataset([
      { default_for_new_repos: "public", configuration: createCodeSecurityConfiguration() },
      { default_for_new_repos: "private_and_internal", configuration: createCodeSecurityConfiguration({ id: 2, secret_scanning_push_protection: "disabled" }) },
    ]),
  });
  assert.equal(privateDisabled["GITHUB-CODE-003"].status, "Partial");
  assert.match(privateDisabled["GITHUB-CODE-003"].summary, /enabled by default for public repositories only/);
  assert.equal(privateDisabled["GITHUB-CODE-002"].status, "Pass");
});

test("self-check (f): enforced defaults for every visibility pass without the deprecated owner flags", () => {
  const enforced = codeSecurityById({
    org: dataset({ login: "example-org" }),
    repositories: dataset([{ id: 1 }]),
    codeSecurityConfigurations: dataset([createCodeSecurityConfiguration(), createCodeSecurityConfiguration({ id: 3, name: "Pilot", enforcement: "unenforced" })]),
    codeSecurityDefaults: dataset([{ default_for_new_repos: "all", configuration: createCodeSecurityConfiguration({ enforcement: "enterprise_enforced" }) }]),
  });
  for (const id of ["GITHUB-CODE-001", "GITHUB-CODE-002", "GITHUB-CODE-003", "GITHUB-CODE-004", "GITHUB-CODE-005"]) {
    assert.equal(enforced[id].status, "Pass", `${id} should pass on an enterprise_enforced default covering all visibilities`);
  }
  assert.match(enforced["GITHUB-CODE-002"].summary, /enabled and enforced by default for new all repositories/);
  assert.match(enforced["GITHUB-CODE-002"].evidence.join("\n"), /secret_scanning_enabled_for_new_repositories = not returned \(deprecated, owner-only field\)/);
  assert.match(enforced["GITHUB-CODE-002"].evidence.join("\n"), /default_for_new_repos\[all\] = Default security baseline \(id 1\): secret_scanning = enabled, enforcement = enterprise_enforced/);
  assert.match(enforced["GITHUB-CODE-001"].summary, /1 default assignment\(s\)/);

  const split = codeSecurityById({
    org: dataset({ login: "example-org" }),
    repositories: dataset([{ id: 1 }]),
    codeSecurityConfigurations: dataset([createCodeSecurityConfiguration()]),
    codeSecurityDefaults: dataset([
      { default_for_new_repos: "public", configuration: createCodeSecurityConfiguration() },
      { default_for_new_repos: "private_and_internal", configuration: createCodeSecurityConfiguration({ id: 2, name: "Private baseline" }) },
    ]),
  });
  for (const id of ["GITHUB-CODE-002", "GITHUB-CODE-003", "GITHUB-CODE-004", "GITHUB-CODE-005"]) {
    assert.equal(split[id].status, "Pass", `${id} should pass when public and private_and_internal defaults are both enforced`);
  }
});

const CANARIES = {
  pat: "ghp_FAKE_PAT_CANARY_00",
  auditHookSecret: "FAKE_AUDIT_HOOK_SECRET_01",
  auditHookSecretWas: "FAKE_AUDIT_HOOK_SECRET_WAS_02",
  auditDataToken: "FAKE_AUDIT_DATA_TOKEN_03",
  auditDataNested: "FAKE_AUDIT_DATA_NESTED_04",
  auditOpenSshKey: "AAAAC3NzaC1lZDI1NTE5FAKE_OPENSSH_PUBLIC_KEY_05",
  tokenLastEight: "FAKE_TOKEN_LAST_EIGHT_06",
  credentialFingerprint: "FAKE_CREDENTIAL_FINGERPRINT_07",
  orgHookSecret: "FAKE_ORG_HOOK_SECRET_08",
  repoHookSecret: "FAKE_REPO_HOOK_SECRET_09",
  deployKeyMaterial: "AAAAC3NzaC1lZDI1NTE5FAKE_DEPLOY_KEY_MATERIAL_10",
  undocumentedOrgBag: "FAKE_UNDOCUMENTED_ORG_FIELD_11",
  invitationEmail: "canary-invitee@FAKE_INVITATION_EMAIL_12.test",
  runnerExtra: "FAKE_RUNNER_EXTRA_13",
};

function createCanaryFetch() {
  const configuration = createCodeSecurityConfiguration();
  const routes = [
    [/^\/orgs\/example-org$/, { ...SELF_CHECK_ORG, undocumented_bag: { anything: CANARIES.undocumentedOrgBag } }],
    [/^\/orgs\/example-org\/members$/, (url) => (url.searchParams.get("filter") === "2fa_disabled" ? [] : [{ login: "alice", id: 1 }, { login: "bob", id: 2 }])],
    [/^\/orgs\/example-org\/outside_collaborators$/, []],
    [/^\/orgs\/example-org\/invitations$/, [{ id: 7, login: "invitee", email: CANARIES.invitationEmail, role: "direct_member", created_at: "2026-09-01T00:00:00Z" }]],
    [/^\/orgs\/example-org\/organization-roles$/, { total_count: 1, roles: [{ id: 1, name: "all_repo_read" }] }],
    [/^\/orgs\/example-org\/credential-authorizations$/, [{
      login: "alice",
      credential_id: 1,
      credential_type: "personal access token",
      token_last_eight: CANARIES.tokenLastEight,
      fingerprint: CANARIES.credentialFingerprint,
      credential_authorized_at: "2026-01-01T00:00:00Z",
      scopes: ["repo", "read:org"],
    }]],
    [/^\/orgs\/example-org\/audit-log$/, [
      {
        "@timestamp": 1758400000000,
        action: "hook.create",
        actor: "alice",
        org: "example-org",
        hook_id: 100,
        config: [{ url: "https://siem.example.test/github", secret: CANARIES.auditHookSecret, content_type: "json" }],
        config_was: [{ url: "https://old.example.test/github", secret: CANARIES.auditHookSecretWas }],
        data: { token: CANARIES.auditDataToken, nested: { free_form: CANARIES.auditDataNested } },
      },
      { "@timestamp": 1758400001000, action: "public_key.create", actor: "bob", openssh_public_key: `ssh-ed25519 ${CANARIES.auditOpenSshKey}` },
    ]],
    [/^\/orgs\/example-org\/hooks$/, [{ id: 100, name: "web", active: true, events: ["push"], config: { url: "https://siem.example.test/github", content_type: "json", insecure_ssl: "0", secret: CANARIES.orgHookSecret } }]],
    [/^\/orgs\/example-org\/installations$/, { total_count: 1, installations: [{ id: 99, app_slug: "compliance-bot", repository_selection: "selected", permissions: { metadata: "read" }, suspended_at: null, created_at: "2025-01-01T00:00:00Z", updated_at: "2026-01-01T00:00:00Z", account: { login: "example-org" } }] }],
    [/^\/orgs\/example-org\/repos$/, SELF_CHECK_REPOS],
    [/^\/orgs\/example-org\/rulesets$/, [{ id: 1, enforcement: "active", target: "branch", rules: SELF_CHECK_RULES.map((rule) => ({ type: rule.type })) }]],
    [/^\/repos\/example-org\/[^/]+\/rulesets$/, []],
    [/^\/repos\/example-org\/[^/]+\/branches\/[^/]+\/protection$/, SELF_CHECK_PROTECTION],
    [/^\/repos\/example-org\/[^/]+\/rules\/branches\/[^/]+$/, SELF_CHECK_RULES],
    [/^\/repos\/example-org\/[^/]+\/hooks$/, [{ id: 5, name: "web", active: true, config: { url: "https://ci.example.test/hook", insecure_ssl: "0", secret: CANARIES.repoHookSecret } }]],
    [/^\/repos\/example-org\/[^/]+\/keys$/, [{ id: 1, title: "reader", key: `ssh-ed25519 ${CANARIES.deployKeyMaterial}`, read_only: true, verified: true, created_at: "2026-06-01T00:00:00Z", last_used: "2026-09-01T00:00:00Z" }]],
    [/^\/orgs\/example-org\/actions\/permissions$/, { enabled_repositories: "selected", allowed_actions: "selected" }],
    [/^\/orgs\/example-org\/actions\/permissions\/selected-actions$/, { github_owned_allowed: true, verified_allowed: false, patterns_allowed: ["example-org/*"] }],
    [/^\/orgs\/example-org\/actions\/permissions\/workflow$/, { default_workflow_permissions: "read", can_approve_pull_request_reviews: false }],
    [/^\/orgs\/example-org\/actions\/runner-groups$/, { total_count: 1, runner_groups: [{ id: 1, name: "prod", visibility: "selected", allows_public_repositories: false, restricted_to_workflows: true, runners_url: `https://api.github.com/${CANARIES.runnerExtra}` }] }],
    [/^\/orgs\/example-org\/actions\/runners$/, { total_count: 1, runners: [{ id: 1, name: "runner-1", os: "linux", status: "online", labels: [{ id: 1, name: "self-hosted", type: "read-only" }] }] }],
    [/^\/orgs\/example-org\/code-security\/configurations$/, [configuration]],
    [/^\/orgs\/example-org\/code-security\/configurations\/defaults$/, [{ default_for_new_repos: "all", configuration }]],
  ];
  const requests = [];
  const fetchImpl = async (input, init = {}) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    requests.push(url.pathname);
    assert.equal(init.headers.Authorization, `Bearer ${CANARIES.pat}`);
    if (url.pathname === "/graphql") {
      const body = JSON.parse(init.body);
      if (body.query.includes("GrclankerOrganizationSaml")) {
        return jsonResponse({ data: { organization: { requiresTwoFactorAuthentication: true, samlIdentityProvider: {
          ssoUrl: "https://idp.example.test/sso", issuer: "https://idp.example.test", digestMethod: null, signatureMethod: null,
          externalIdentities: { totalCount: 2, pageInfo: { hasNextPage: false, endCursor: null }, nodes: [
            { guid: "1", samlIdentity: { nameId: "alice@example.test" }, scimIdentity: null, user: { login: "alice" } },
            { guid: "2", samlIdentity: { nameId: "bob@example.test" }, scimIdentity: null, user: { login: "bob" } },
          ] } } } } });
      }
      if (body.query.includes("GrclankerOrganizationIpAllowList")) {
        return jsonResponse({ data: { organization: { ipAllowListEnabledSetting: "ENABLED", ipAllowListForInstalledAppsEnabledSetting: "ENABLED",
          ipAllowListEntries: { totalCount: 1, pageInfo: { hasNextPage: false, endCursor: null }, nodes: [{ allowListValue: "203.0.113.0/24", isActive: true, name: "HQ", createdAt: "2025-01-01T00:00:00Z" }] } } } });
      }
      if (body.query.includes("GrclankerEnterpriseIdentity")) {
        return jsonResponse({ data: { enterprise: { slug: "example-enterprise", ownerInfo: { oidcProvider: { providerType: "AAD", tenantId: "tenant" }, samlIdentityProvider: null } } } });
      }
      throw new Error(`Unexpected GraphQL query: ${body.query.slice(0, 40)}`);
    }
    for (const [pattern, payload] of routes) {
      if (pattern.test(url.pathname)) {
        return jsonResponse(typeof payload === "function" ? payload(url) : payload);
      }
    }
    throw new Error(`Unexpected request: ${url.pathname}`);
  };
  return { fetchImpl, requests };
}

function walkFiles(root) {
  const files = [];
  const visit = (dir) => {
    for (const entry of readdirSync(dir)) {
      const full = join(dir, entry);
      if (statSync(full).isDirectory()) {
        visit(full);
      } else {
        files.push(full);
      }
    }
  };
  visit(root);
  return files;
}

// Minimal zip reader (central directory + raw deflate) so the extracted archive is inspected
// without a shell dependency; archiver writes data descriptors, so sizes come from the directory.
function readZipEntries(buffer) {
  let eocd = -1;
  for (let offset = buffer.length - 22; offset >= Math.max(0, buffer.length - 65557); offset -= 1) {
    if (buffer.readUInt32LE(offset) === 0x06054b50) {
      eocd = offset;
      break;
    }
  }
  assert.notEqual(eocd, -1, "zip end of central directory record found");
  const entryCount = buffer.readUInt16LE(eocd + 10);
  let offset = buffer.readUInt32LE(eocd + 16);
  const entries = [];
  for (let index = 0; index < entryCount; index += 1) {
    assert.equal(buffer.readUInt32LE(offset), 0x02014b50, "central directory entry signature");
    const method = buffer.readUInt16LE(offset + 10);
    const compressedSize = buffer.readUInt32LE(offset + 20);
    const nameLength = buffer.readUInt16LE(offset + 28);
    const extraLength = buffer.readUInt16LE(offset + 30);
    const commentLength = buffer.readUInt16LE(offset + 32);
    const localOffset = buffer.readUInt32LE(offset + 42);
    const name = buffer.toString("utf8", offset + 46, offset + 46 + nameLength);
    assert.equal(buffer.readUInt32LE(localOffset), 0x04034b50, "local file header signature");
    const dataStart = localOffset + 30 + buffer.readUInt16LE(localOffset + 26) + buffer.readUInt16LE(localOffset + 28);
    const data = buffer.subarray(dataStart, dataStart + compressedSize);
    entries.push({ name, content: (method === 8 ? inflateRawSync(data) : data).toString("utf8") });
    offset += 46 + nameLength + extraLength + commentLength;
  }
  return entries;
}

test("rule 9: no credential-bearing value from any documented carrier reaches the bundle directory or the zip", async () => {
  const outputRoot = createTempBase("grclanker-github-canary-");
  const config = { ...SELF_CHECK_CONFIG, apiToken: CANARIES.pat, graphqlUrl: "https://api.github.com/graphql", enterprise: "example-enterprise" };
  const { fetchImpl, requests } = createCanaryFetch();
  const client = new GitHubAuditorClient(config, fetchImpl);
  const result = await exportGitHubAuditBundle(client, config, outputRoot);
  assert.ok(requests.includes("/orgs/example-org/audit-log"));
  assert.ok(requests.includes("/repos/example-org/app-one/keys"));

  const files = walkFiles(result.outputDir);
  assert.ok(files.some((file) => file.endsWith(join("core_data", "org_access.json"))));
  assert.ok(files.some((file) => file.endsWith(join("core_data", "integrations.json"))));
  assert.ok(!files.some((file) => file.endsWith("_errors.log")), "the canary tenant collects cleanly, so no carrier was skipped by an error");
  const carriers = [
    ...files.filter((file) => !file.endsWith(".zip")).map((file) => ({ name: relative(result.outputDir, file), content: readFileSync(file, "utf8") })),
    ...readZipEntries(readFileSync(result.zipPath)).map((entry) => ({ name: `zip:${entry.name}`, content: entry.content })),
  ];
  assert.ok(carriers.some((carrier) => carrier.name.startsWith("zip:")), "the zip contains entries");
  assert.ok(carriers.some((carrier) => carrier.name.startsWith("zip:") && carrier.name.includes("core_data/org_access.json")));
  const leaks = [];
  for (const carrier of carriers) {
    for (const [label, canary] of Object.entries(CANARIES)) {
      if (carrier.content.includes(canary)) {
        leaks.push(`${label} -> ${carrier.name}`);
      }
    }
  }
  assert.deepEqual(leaks, [], "no canary may appear in any bundle file or zip entry");
  assert.ok(carriers.find((carrier) => carrier.name === "zip:analysis/findings.json" || carrier.name.endsWith("/analysis/findings.json"))?.content.includes("GITHUB-ORG-001"), "zip entries decode to their content");

  // Presence markers survive so the verdicts and the evidence stay legible without the values.
  const orgAccess = JSON.parse(readFileSync(join(result.outputDir, "core_data", "org_access.json"), "utf8"));
  assert.equal(orgAccess.hooks.data[0].config.secret, "[redacted]");
  assert.equal(orgAccess.hooks.data[0].config.url, "https://siem.example.test/github");
  assert.deepEqual(Object.keys(orgAccess.auditLog.data.events[0]).sort(), ["@timestamp", "action", "actor", "org"]);
  assert.equal(orgAccess.credentialAuthorizations.data[0].token_last_eight, undefined);
  assert.equal(orgAccess.credentialAuthorizations.data[0].credential_type, "personal access token");
  assert.equal(orgAccess.org.data.undocumented_bag, undefined);
  assert.equal(orgAccess.invitations.data[0].email, undefined);
  const integrations = JSON.parse(readFileSync(join(result.outputDir, "core_data", "integrations.json"), "utf8"));
  const keyEntry = integrations.deployKeys.data["example-org/app-one"].items[0];
  assert.equal(keyEntry.key, undefined);
  assert.equal(keyEntry.read_only, true);
  assert.equal(integrations.repoHooks.data["example-org/app-one"].items[0].config.secret, "[redacted]");
  const findings = JSON.parse(readFileSync(join(result.outputDir, "analysis", "findings.json"), "utf8"));
  const byId = Object.fromEntries(findings.map((finding) => [finding.id, finding]));
  assert.equal(byId["GITHUB-INTEG-001"].status, "Pass", "webhook secrets still count as present after redaction");
  assert.equal(byId["GITHUB-INTEG-002"].status, "Pass");
  assert.equal(byId["GITHUB-ORG-005"].status, "Pass");
});

test("redactSensitiveKeys masks credential-named keys at any depth and leaves look-alike names alone", () => {
  const redacted = redactSensitiveKeys({
    secret: "value",
    nested: [{ Token: "t", "token_last_eight": "abc", access_token: "x", secret_scanning_default: "Pass", token_scopes: ["repo"] }],
    empty_secret: "",
    password: null,
    openssh_public_key: "ssh-ed25519 AAA",
  });
  assert.deepEqual(redacted, {
    secret: "[redacted]",
    nested: [{ Token: "[redacted]", token_last_eight: "[redacted]", access_token: "[redacted]", secret_scanning_default: "Pass", token_scopes: ["repo"] }],
    empty_secret: "",
    password: null,
    openssh_public_key: "[redacted]",
  });
});

test("exportGitHubAuditBundle records collector failures and never overwrites a prior bundle", async () => {
  const outputRoot = createTempBase("grclanker-github-rerun-");
  const first = await exportGitHubAuditBundle(createPartialClient(), SELF_CHECK_CONFIG, outputRoot);
  const second = await exportGitHubAuditBundle(createPartialClient(), SELF_CHECK_CONFIG, outputRoot);

  assert.notEqual(first.outputDir, second.outputDir);
  assert.notEqual(first.zipPath, second.zipPath);
  assert.equal(first.zipPath, `${first.outputDir}.zip`);
  assert.equal(second.zipPath, `${second.outputDir}.zip`);
  assert.ok(existsSync(first.zipPath));
  assert.ok(existsSync(second.zipPath));

  assert.ok(first.errorCount > 0);
  const errorLog = readFileSync(join(first.outputDir, "_errors.log"), "utf8");
  assert.match(errorLog, /HTTP 403/);
  const findings = JSON.parse(readFileSync(join(first.outputDir, "analysis", "findings.json"), "utf8"));
  assert.deepEqual(passingIds(findings), [...SETTING_DRIVEN_IDS, "GITHUB-ORG-005"].sort());
});
