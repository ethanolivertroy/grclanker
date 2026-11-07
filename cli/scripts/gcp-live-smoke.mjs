import { resolveLiveSmokeConfiguration } from "./live-smoke-config.mjs";

import {
  GcpAuditorClient,
  assessGcpDataProtection,
  assessGcpIdentity,
  assessGcpLoggingDetection,
  assessGcpNetworkSecurity,
  assessGcpOrgGuardrails,
  checkGcpAccess,
  resolveGcpConfiguration,
} from "../dist/extensions/grc-tools/gcp.js";

function log(message) {
  process.stdout.write(`${message}\n`);
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
  const authentication = await resolveLiveSmokeConfiguration("GCP", () => resolveGcpConfiguration());
  if (authentication.kind === "unconfigured") process.exit(0);
  const config = authentication.config;
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
