import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

import {
  SplunkApiClient,
  assessSplunkAuthentication,
  checkSplunkAccess,
  resolveSplunkConfiguration,
} from "../dist/extensions/grc-tools/splunk.js";

function log(message) {
  process.stdout.write(`${message}\n`);
}

function hasConfigHints() {
  const env = process.env;
  const hasEnvUrl = Boolean(env.SPLUNK_URL?.trim());
  const hasEnvCredential = Boolean(env.SPLUNK_TOKEN?.trim())
    || (Boolean(env.SPLUNK_USERNAME?.trim()) && Boolean(env.SPLUNK_PASSWORD?.trim()));
  const configFile = env.SPLUNK_CONFIG_FILE?.trim() || join(homedir(), ".config", "grclanker", "splunk.json");
  return (hasEnvUrl && hasEnvCredential) || existsSync(configFile);
}

try {
  if (!hasConfigHints()) {
    log(
      "Skipping live Splunk smoke test: set SPLUNK_URL plus SPLUNK_TOKEN (or SPLUNK_USERNAME and SPLUNK_PASSWORD), or create ~/.config/grclanker/splunk.json, to run against a real deployment.",
    );
    process.exit(0);
  }

  const config = resolveSplunkConfiguration();
  const client = new SplunkApiClient(config);
  const access = await checkSplunkAccess(client);

  log(`Splunk URL: ${access.url}`);
  log(`Deployment: ${access.deployment.isCloud ? "Splunk Cloud Platform" : "Splunk Enterprise"} ${access.deployment.version ?? "(version unknown)"}`);
  log(`Access status: ${access.status}`);
  log(`Authenticated as: ${access.authenticatedAs ?? "unknown"}`);
  log(`ACS configured: ${access.acsConfigured ? "yes" : "no"}`);
  for (const surface of access.surfaces) {
    const count = surface.count === undefined ? "" : ` (${surface.count}${surface.total !== undefined && surface.total !== surface.count ? `/${surface.total}` : ""})`;
    log(`- ${surface.name}: ${surface.status}${count}`);
  }
  if (access.missingCapabilities.length > 0) {
    log(`Missing capabilities: ${access.missingCapabilities.join("; ")}`);
  }

  if (access.status !== "healthy") {
    throw new Error(
      "Live Splunk smoke test stopped because the audit credential could not read enough core endpoints; unreadable surfaces render as manual findings.",
    );
  }

  const authentication = await assessSplunkAuthentication(client);
  log(`Authentication findings: ${authentication.findings.length}`);
  log(
    `Summary: pass ${authentication.summary.pass}, warn ${authentication.summary.warn}, fail ${authentication.summary.fail}, manual ${authentication.summary.manual}`,
  );
  for (const finding of authentication.findings) {
    log(`- ${finding.id} [${finding.status}] ${finding.title}`);
  }
  if (authentication.errors.length > 0) {
    log(`Collection errors: ${authentication.errors.length}`);
  }
  log("Live Splunk smoke test passed.");
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`${message}\n`);
  process.exit(1);
}
