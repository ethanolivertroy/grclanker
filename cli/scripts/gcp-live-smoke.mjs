import { existsSync } from "node:fs";

import {
  GcpAuditorClient,
  assessGcpDataProtection,
  assessGcpIdentity,
  assessGcpLoggingDetection,
  assessGcpNetworkSecurity,
  assessGcpOrgGuardrails,
  checkGcpAccess,
  defaultAdcPath,
  resolveGcpConfiguration,
} from "../dist/extensions/grc-tools/gcp.js";

function log(message) {
  process.stdout.write(`${message}\n`);
}

function hasCredentialHints() {
  return (
    Boolean(process.env.GCP_ACCESS_TOKEN?.trim())
    || Boolean(process.env.GOOGLE_OAUTH_ACCESS_TOKEN?.trim())
    || Boolean(process.env.GCP_CREDENTIALS_FILE?.trim())
    || Boolean(process.env.GOOGLE_APPLICATION_CREDENTIALS?.trim())
    || Boolean(process.env.GCP_ORGANIZATION_ID?.trim())
    || Boolean(process.env.GCP_ORG_ID?.trim())
    || Boolean(process.env.GCP_PROJECT_ID?.trim())
    || Boolean(process.env.GOOGLE_CLOUD_PROJECT?.trim())
    || existsSync(defaultAdcPath())
  );
}

function countStatuses(findings) {
  const counts = { pass: 0, warn: 0, fail: 0, manual: 0 };
  for (const finding of findings) counts[finding.status] += 1;
  return counts;
}

function logAssessment(result) {
  const counts = countStatuses(result.findings);
  log(`${result.title}: ${result.findings.length} findings`);
  log(`  pass ${counts.pass}, warn ${counts.warn}, fail ${counts.fail}, manual ${counts.manual}, collection errors ${result.errors.length}`);
  for (const finding of result.findings) {
    log(`  - ${finding.id} [${finding.status}] ${finding.title}`);
  }
}

try {
  if (!hasCredentialHints()) {
    log(
      "Skipping live GCP smoke test: set GCP_ORGANIZATION_ID (or GCP_ORG_ID) or GCP_PROJECT_ID plus GCP_ACCESS_TOKEN, GCP_CREDENTIALS_FILE, GOOGLE_APPLICATION_CREDENTIALS, or an ADC file to run against a real organization.",
    );
    process.exit(0);
  }

  const config = resolveGcpConfiguration();
  const client = new GcpAuditorClient(config);
  const access = await checkGcpAccess(client);

  log(`GCP organization: ${access.organizationId ?? "(none)"}`);
  log(`GCP project: ${access.projectId ?? "(none)"}`);
  log(`Credential chain: ${config.sourceChain.join(" > ")}`);
  log(`Access status: ${access.status}`);
  for (const surface of access.surfaces) {
    log(`- ${surface.name}: ${surface.status}${surface.error ? ` (${surface.error})` : ""}`);
  }

  if (access.status !== "healthy") {
    throw new Error(
      `Live GCP smoke test stopped because the audit principal could not read enough core surfaces. ${access.recommendedNextStep}`,
    );
  }

  const options = { maxProjects: 5, maxAssets: 200 };
  logAssessment(await assessGcpIdentity(client, { ...options, maxKeys: 50 }));
  logAssessment(await assessGcpLoggingDetection(client, { ...options, maxFindings: 50 }));
  logAssessment(await assessGcpOrgGuardrails(client, options));
  logAssessment(await assessGcpDataProtection(client, options));
  logAssessment(await assessGcpNetworkSecurity(client, options));
  log("Live GCP smoke test passed.");
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`${message}\n`);
  process.exit(1);
}
