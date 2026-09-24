import {
  assessTenableScanProgram,
  checkTenableAccess,
  collectTenableScanProgramData,
  createTenableClients,
  resolveTenableConfiguration,
} from "../dist/extensions/grc-tools/tenable.js";

function log(message) {
  process.stdout.write(`${message}\n`);
}

function hasConfigHints() {
  const vmKeys = Boolean(process.env.TENABLE_ACCESS_KEY?.trim()) && Boolean(process.env.TENABLE_SECRET_KEY?.trim());
  const scKeys = Boolean(process.env.TENABLE_SC_URL?.trim())
    && Boolean(process.env.TENABLE_SC_ACCESS_KEY?.trim())
    && Boolean(process.env.TENABLE_SC_SECRET_KEY?.trim());
  return vmKeys || scKeys;
}

try {
  if (!hasConfigHints()) {
    log(
      "Skipping live Tenable smoke test: set TENABLE_ACCESS_KEY and TENABLE_SECRET_KEY (optionally TENABLE_URL for fedcloud.tenable.com or a Tenable Security Center host, or TENABLE_SC_URL with TENABLE_SC_ACCESS_KEY and TENABLE_SC_SECRET_KEY) to run against a real tenant.",
    );
    process.exit(0);
  }

  const config = resolveTenableConfiguration();
  const clients = createTenableClients(config);
  const access = await checkTenableAccess(clients);

  log(`Platform: ${access.platform}`);
  log(`Access status: ${access.status}`);
  log(`Caller is Administrator: ${access.callerIsAdministrator ?? "unknown"}`);
  for (const surface of access.surfaces) {
    log(`- ${surface.name}: ${surface.status}${surface.count !== undefined ? ` (${surface.count})` : ""}${surface.error ? ` ${surface.error}` : ""}`);
  }

  const assessment = assessTenableScanProgram(await collectTenableScanProgramData(clients));
  log("");
  log(`${assessment.title}: ${assessment.findings.length} findings`);
  for (const finding of assessment.findings) {
    log(`- ${finding.id} [${finding.status.toUpperCase()}] ${finding.summary}`);
  }
  if (assessment.errors.length > 0) {
    log("");
    log("Collection warnings:");
    for (const error of assessment.errors) log(`- ${error}`);
  }

  if (access.status !== "healthy") {
    log("");
    log("Live smoke completed with limited access; refused surfaces produced manual verdicts above.");
  }
  process.exit(0);
} catch (error) {
  process.stderr.write(`Tenable live smoke failed: ${error instanceof Error ? error.message : String(error)}\n`);
  process.exit(1);
}
