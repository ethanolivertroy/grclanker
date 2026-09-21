import test from "node:test";
import assert from "node:assert/strict";
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { generateKeyPairSync } from "node:crypto";
import { join, resolve } from "node:path";

import {
  GitHubAuditorClient,
  assessGitHubActionsSecurity,
  assessGitHubCodeSecurity,
  assessGitHubOrgAccess,
  assessGitHubRepoProtection,
  clearGitHubTokenCacheForTests,
  collectGitHubRepoProtectionData,
  exportGitHubAuditBundle,
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
    auditLog: dataset([{ action: "repo.create" }, { action: "member.added" }]),
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

function createCodeSecurityData() {
  return {
    org: dataset({
      login: "example-org",
      secret_scanning_enabled_for_new_repositories: true,
      secret_scanning_push_protection_enabled_for_new_repositories: false,
      dependabot_alerts_enabled_for_new_repositories: true,
      dependabot_security_updates_enabled_for_new_repositories: false,
    }),
    repositories: dataset([{ id: 1 }, { id: 2 }]),
    codeSecurityConfigurations: dataset([
      {
        id: 1,
        name: "Default security baseline",
        default_for_new_repos: true,
        secret_scanning: "enabled",
        secret_scanning_push_protection: "disabled",
        dependabot_alerts: "enabled",
        dependabot_security_updates: "disabled",
        code_scanning_default_setup: "enabled",
      },
    ]),
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
  assert.equal(result.findings.length, 10);
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
  assert.equal(healthy.findings.length, 4);
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

  assert.ok(existsSync(join(result.outputDir, "README.md")));
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
