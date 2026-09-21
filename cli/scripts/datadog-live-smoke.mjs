import {
  DatadogApiClient,
  assessDatadogIdentity,
  checkDatadogAccess,
  resolveDatadogConfiguration,
} from "../dist/extensions/grc-tools/datadog.js";

function log(message) {
  process.stdout.write(`${message}\n`);
}

function hasCredentialHints() {
  const apiKey = process.env.DD_API_KEY?.trim() || process.env.DATADOG_API_KEY?.trim();
  const appKey = process.env.DD_APP_KEY?.trim()
    || process.env.DD_APPLICATION_KEY?.trim()
    || process.env.DATADOG_APP_KEY?.trim();
  return Boolean(apiKey) && Boolean(appKey);
}

function summarizeFindings(findings) {
  const counts = { pass: 0, warn: 0, fail: 0, manual: 0 };
  for (const finding of findings) {
    counts[finding.status] = (counts[finding.status] ?? 0) + 1;
  }
  return `Pass ${counts.pass}, Warn ${counts.warn}, Fail ${counts.fail}, Manual ${counts.manual}`;
}

try {
  if (!hasCredentialHints()) {
    log(
      "Skipping live Datadog smoke test: set DD_API_KEY and DD_APP_KEY (and optionally DD_SITE) to run against a real organization.",
    );
    process.exit(0);
  }

  const config = resolveDatadogConfiguration({}, process.env);
  const client = new DatadogApiClient(config);
  const access = await checkDatadogAccess(client);

  log(`Datadog site: ${access.site}`);
  log(`API key valid: ${access.apiKeyValid ? "yes" : "no"}`);
  log(`Access status: ${access.status}`);
  for (const surface of access.surfaces) {
    const count = surface.count === undefined ? "" : ` (${surface.count})`;
    log(`- ${surface.name}: ${surface.status}${count}`);
  }
  if (access.missingPermissions.length > 0) {
    log(`Missing permissions: ${access.missingPermissions.join(", ")}`);
  }

  if (access.status === "failed") {
    throw new Error(
      "Live Datadog smoke test stopped because the credentials could not read any core endpoint.",
    );
  }

  const identity = await assessDatadogIdentity(client);
  log(`Identity findings: ${identity.findings.length}`);
  log(`Summary: ${summarizeFindings(identity.findings)}`);
  for (const finding of identity.findings) {
    log(`- ${finding.id} [${finding.status}] ${finding.title}`);
  }
  if (identity.errors.length > 0) {
    log(`Collection errors: ${identity.errors.length}`);
    for (const error of identity.errors) {
      log(`  ${error}`);
    }
  }
  log("Live Datadog smoke test passed.");
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`${message}\n`);
  process.exit(1);
}
