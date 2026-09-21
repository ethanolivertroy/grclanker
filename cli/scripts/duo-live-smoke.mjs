import {
  DuoAuditorClient,
  assessDuoAdminAccess,
  assessDuoAuthentication,
  assessDuoIntegrations,
  assessDuoMonitoring,
  collectDuoAdminAccessData,
  collectDuoAuthenticationData,
  collectDuoIntegrationData,
  collectDuoMonitoringData,
  resolveDuoConfiguration,
  runDuoAccessCheck,
} from "../dist/extensions/grc-tools/duo.js";

function log(message) {
  process.stdout.write(`${message}\n`);
}

function hasConfigHints() {
  return (
    Boolean(process.env.DUO_API_HOST?.trim())
    && Boolean(process.env.DUO_IKEY?.trim())
    && Boolean(process.env.DUO_SKEY?.trim())
  );
}

function logAssessment(label, assessment) {
  log(`${label} findings: ${assessment.findings.length}`);
  log(
    `  Pass ${assessment.summary.Pass}, Partial ${assessment.summary.Partial}, Fail ${assessment.summary.Fail}, Manual ${assessment.summary.Manual}, Info ${assessment.summary.Info}`,
  );
  for (const finding of assessment.findings) {
    log(`  - ${finding.id} ${finding.status}: ${finding.summary}`);
  }
}

try {
  if (!hasConfigHints()) {
    log(
      "Skipping live Duo smoke test: set DUO_API_HOST, DUO_IKEY, and DUO_SKEY to run against a real tenant.",
    );
    process.exit(0);
  }

  const config = resolveDuoConfiguration();
  const client = new DuoAuditorClient(config);
  const access = await runDuoAccessCheck(client, config);

  log(`Duo org: ${access.organization}`);
  log(`Access status: ${access.status}`);
  for (const probe of access.probes) {
    log(`- ${probe.key}: ${probe.status}`);
  }

  if (access.status !== "healthy") {
    throw new Error(
      "Live Duo smoke test stopped because the audit principal could not read enough core endpoints.",
    );
  }

  const authentication = assessDuoAuthentication(
    await collectDuoAuthenticationData(client, config.lookbackDays),
    config,
  );
  logAssessment("Authentication", authentication);

  const adminAccess = assessDuoAdminAccess(
    await collectDuoAdminAccessData(client, config.lookbackDays),
    config,
  );
  logAssessment("Admin access", adminAccess);

  const integrations = assessDuoIntegrations(await collectDuoIntegrationData(client), config);
  logAssessment("Integrations", integrations);

  const monitoring = assessDuoMonitoring(
    await collectDuoMonitoringData(client, config.lookbackDays),
    config,
  );
  logAssessment("Monitoring", monitoring);

  const allFindings = [authentication, adminAccess, integrations, monitoring].flatMap(
    (assessment) => assessment.findings,
  );
  const suspiciousPasses = allFindings.filter(
    (finding) => finding.status === "Pass" && finding.evidence.some((line) => line.startsWith("collection_error=")),
  );
  if (suspiciousPasses.length > 0) {
    throw new Error(
      `Verdict safety violated: ${suspiciousPasses.map((finding) => finding.id).join(", ")} passed with a collection error.`,
    );
  }

  log(`Total findings: ${allFindings.length}`);
  log("Live Duo smoke test passed.");
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`${message}\n`);
  process.exit(1);
}
