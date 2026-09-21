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

function createOrgAccessData() {
  return {
    org: dataset({
      login: "example-org",
      two_factor_requirement_enabled: true,
      default_repository_permission: "read",
      web_commit_signoff_required: true,
    }),
    members: dataset([{ login: "alice" }, { login: "bob" }, { login: "carol" }]),
    adminMembers: dataset([{ login: "alice" }, { login: "bob" }]),
    outsideCollaborators: dataset([{ login: "vendor-one" }, { login: "vendor-two" }]),
    invitations: dataset([{ id: 1 }]),
    organizationRoles: dataset([{ id: 1 }, { id: 2 }]),
    credentialAuthorizations: dataset([{ credential_id: 1 }]),
    auditLog: dataset([{ action: "repo.create" }, { action: "member.added" }]),
    hooks: dataset([{ id: 100 }]),
    appInstallations: dataset([{ id: 99 }]),
  };
}

function createRepoProtectionData() {
  return {
    org: dataset({
      login: "example-org",
      web_commit_signoff_required: true,
    }),
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
    },
    config,
    outputRoot,
  );

  assert.ok(existsSync(join(result.outputDir, "README.md")));
  assert.ok(existsSync(join(result.outputDir, "analysis", "org_access.json")));
  assert.ok(existsSync(join(result.outputDir, "analysis", "repo_protection.json")));
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
