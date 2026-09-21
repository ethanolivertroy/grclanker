import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { join, resolve } from "node:path";

import {
  OktaAuditorClient,
  assessOktaAdminAccess,
  assessOktaAuthentication,
  assessOktaIntegrations,
  assessOktaMonitoring,
  collectOktaAdminAccessData,
  collectOktaAuthenticationData,
  collectOktaIntegrationData,
  collectOktaMonitoringData,
  resolveOktaConfiguration,
  runOktaAccessCheck,
} from "../dist/extensions/grc-tools/okta.js";

function log(message) {
  process.stdout.write(`${message}\n`);
}

function hasConfigHints() {
  return (
    Boolean(process.env.OKTA_CLIENT_ORGURL?.trim())
    || Boolean(process.env.OKTA_CLIENT_TOKEN?.trim())
    || Boolean(process.env.OKTA_CLIENT_CLIENTID?.trim())
    || Boolean(process.env.OKTA_CLIENT_PRIVATEKEY?.trim())
    || existsSync(resolve(process.cwd(), ".okta.yaml"))
    || existsSync(join(homedir(), ".okta", "okta.yaml"))
  );
}

function summarize(label, assessment) {
  log(`${label}: ${assessment.findings.length} findings`);
  log(
    `  Pass ${assessment.summary.Pass}, Partial ${assessment.summary.Partial}, Fail ${assessment.summary.Fail}, Manual ${assessment.summary.Manual}, Info ${assessment.summary.Info}`,
  );
  const errors = assessment.snapshotSummary.dataset_errors;
  if (errors > 0) {
    log(`  Dataset errors: ${errors} (findings backed by those datasets are rendered Manual)`);
  }
  for (const finding of assessment.findings) {
    log(`  - ${finding.id} ${finding.status}: ${finding.summary}`);
  }
}

function assertVerdictSafety(assessment) {
  for (const finding of assessment.findings) {
    if (finding.status === "Manual" && !finding.manualNote) {
      throw new Error(`${finding.id} is Manual without naming the evidence to collect.`);
    }
  }
}

try {
  if (!hasConfigHints()) {
    log(
      "Skipping live Okta smoke test: set Okta env vars or configure .okta.yaml / ~/.okta/okta.yaml to run against a real tenant.",
    );
    process.exit(0);
  }

  const config = await resolveOktaConfiguration();
  const client = new OktaAuditorClient(config);
  const access = await runOktaAccessCheck(client, config);

  log(`Okta org: ${access.organization}`);
  log(`Access status: ${access.status}`);
  for (const probe of access.probes) {
    log(`- ${probe.key}: ${probe.status}`);
  }

  if (access.status !== "healthy") {
    throw new Error(
      "Live Okta smoke test stopped because the audit principal could not read enough core endpoints.",
    );
  }

  const assessments = [
    ["okta_assess_authentication", assessOktaAuthentication(await collectOktaAuthenticationData(client), config)],
    ["okta_assess_admin_access", assessOktaAdminAccess(await collectOktaAdminAccessData(client), config)],
    ["okta_assess_integrations", assessOktaIntegrations(await collectOktaIntegrationData(client), config)],
    ["okta_assess_monitoring", assessOktaMonitoring(await collectOktaMonitoringData(client), config)],
  ];

  for (const [label, assessment] of assessments) {
    summarize(label, assessment);
    assertVerdictSafety(assessment);
  }

  const totalFindings = assessments.reduce((total, [, assessment]) => total + assessment.findings.length, 0);
  log(`Total findings across assess tools: ${totalFindings}`);
  log("Live Okta smoke test passed.");
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`${message}\n`);
  process.exit(1);
}
