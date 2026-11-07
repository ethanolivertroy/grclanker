import { resolveLiveSmokeConfiguration } from "./live-smoke-config.mjs";
import {
  GitHubAuditorClient,
  assessGitHubActionsSecurity,
  assessGitHubCodeSecurity,
  assessGitHubIntegrations,
  assessGitHubOrgAccess,
  assessGitHubRepoProtection,
  collectGitHubActionsData,
  collectGitHubCodeSecurityData,
  collectGitHubIntegrationsData,
  collectGitHubOrgAccessData,
  collectGitHubRepoProtectionData,
  resolveGitHubConfiguration,
  runGitHubAccessCheck,
} from "../dist/extensions/grc-tools/github.js";

function log(message) {
  process.stdout.write(`${message}\n`);
}


function describeSummary(summary) {
  return `Pass ${summary.Pass}, Partial ${summary.Partial}, Fail ${summary.Fail}, Manual ${summary.Manual}, Info ${summary.Info}`;
}

const ASSESSMENTS = [
  {
    name: "github_assess_org_access",
    run: async (client, config) => assessGitHubOrgAccess(await collectGitHubOrgAccessData(client, config), config),
  },
  {
    name: "github_assess_repo_protection",
    run: async (client, config) => assessGitHubRepoProtection(await collectGitHubRepoProtectionData(client), config),
  },
  {
    name: "github_assess_actions_security",
    run: async (client, config) => assessGitHubActionsSecurity(await collectGitHubActionsData(client), config),
  },
  {
    name: "github_assess_code_security",
    run: async (client, config) => assessGitHubCodeSecurity(await collectGitHubCodeSecurityData(client), config),
  },
  {
    name: "github_assess_integrations",
    run: async (client, config) => assessGitHubIntegrations(await collectGitHubIntegrationsData(client), config),
  },
];

try {
  const authentication = await resolveLiveSmokeConfiguration("GitHub", () => resolveGitHubConfiguration());
  if (authentication.kind === "unconfigured") process.exit(0);
  const config = authentication.config;
  const client = new GitHubAuditorClient(config);
  const access = await runGitHubAccessCheck(client, config);

  log(`GitHub org: ${access.organization}`);
  log(`API: ${config.apiBaseUrl} (GraphQL ${config.graphqlUrl}${config.enterprise ? `, enterprise ${config.enterprise}` : ""})`);
  log(`Access status: ${access.status}`);
  for (const probe of access.probes) {
    log(`- ${probe.key}: ${probe.status}`);
  }

  if (access.status !== "healthy") {
    throw new Error(
      "Live GitHub smoke test stopped because the supplied principal could not read enough core org-security surfaces.",
    );
  }

  let total = 0;
  for (const assessment of ASSESSMENTS) {
    const result = await assessment.run(client, config);
    total += result.findings.length;
    log(`${assessment.name}: ${result.findings.length} findings (${describeSummary(result.summary)})`);
    for (const finding of result.findings.filter((entry) => entry.status === "Fail")) {
      log(`  ! ${finding.id} ${finding.summary}`);
    }
  }
  log(`Total findings: ${total}`);
  log("Live GitHub smoke test passed.");
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`${message}\n`);
  process.exit(1);
}
