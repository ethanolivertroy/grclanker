import {
  SumologicApiClient,
  assessSumologicIdentity,
  checkSumologicAccess,
  resolveSumologicConfiguration,
} from "../dist/extensions/grc-tools/sumologic.js";

function log(message) {
  process.stdout.write(`${message}\n`);
}

function hasConfigHints() {
  return Boolean(process.env.SUMOLOGIC_ACCESS_ID?.trim()) && Boolean(process.env.SUMOLOGIC_ACCESS_KEY?.trim());
}

try {
  if (!hasConfigHints()) {
    log(
      "Skipping live Sumo Logic smoke test: set SUMOLOGIC_ACCESS_ID, SUMOLOGIC_ACCESS_KEY, and optionally SUMOLOGIC_ENDPOINT (deployment code or API URL) to run against a real org.",
    );
    process.exit(0);
  }

  const config = resolveSumologicConfiguration();
  const client = new SumologicApiClient(config);
  const access = await checkSumologicAccess(client);

  log(`Sumo Logic API: ${access.baseUrl}`);
  log(`Access status: ${access.status}`);
  for (const surface of access.surfaces) {
    log(`- ${surface.name}: ${surface.status}${surface.count === undefined ? "" : ` (${surface.count})`}`);
  }
  if (access.missingCapabilities.length > 0) {
    log(`Missing capabilities: ${access.missingCapabilities.join(", ")}`);
  }

  const identity = await assessSumologicIdentity(client);
  log(`Identity findings: ${identity.findings.length}`);
  for (const item of identity.findings) {
    log(`- ${item.id} ${item.status.toUpperCase()}: ${item.summary}`);
  }
  if (identity.errors.length > 0) {
    log(`Collection errors: ${identity.errors.length}`);
  }
  log("Live Sumo Logic smoke test passed.");
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`${message}\n`);
  process.exit(1);
}
