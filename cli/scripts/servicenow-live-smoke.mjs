import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { join, resolve } from "node:path";

import {
  ServicenowApiClient,
  assessServicenowPlatformHardening,
  checkServicenowAccess,
  resolveServicenowConfiguration,
} from "../dist/extensions/grc-tools/servicenow.js";

function log(message) {
  process.stdout.write(`${message}\n`);
}

function hasConfigHints() {
  return (
    Boolean(process.env.SERVICENOW_INSTANCE?.trim())
    || Boolean(process.env.SERVICENOW_URL?.trim())
    || Boolean(process.env.SERVICENOW_CONFIG_FILE?.trim())
    || existsSync(resolve(process.cwd(), ".servicenow.yaml"))
    || existsSync(join(homedir(), ".servicenow-sec-inspector", "config.yaml"))
  );
}

try {
  if (!hasConfigHints()) {
    log(
      "Skipping live ServiceNow smoke test: set SERVICENOW_INSTANCE or SERVICENOW_URL plus credentials (SERVICENOW_USERNAME and SERVICENOW_PASSWORD, or SERVICENOW_CLIENT_ID and SERVICENOW_CLIENT_SECRET), or configure .servicenow.yaml / ~/.servicenow-sec-inspector/config.yaml to run against a real instance.",
    );
    process.exit(0);
  }

  const config = resolveServicenowConfiguration();
  const client = new ServicenowApiClient(config);
  const access = await checkServicenowAccess(client);

  log(`ServiceNow instance: ${access.instanceUrl}`);
  log(`Auth mode: ${access.authMode}${access.identity ? ` as ${access.identity}` : ""}`);
  log(`Access status: ${access.status}`);
  for (const surface of access.surfaces) {
    log(`- ${surface.table}: ${surface.status}${surface.total !== undefined ? ` (total ${surface.total})` : ""}`);
  }

  if (access.status !== "healthy") {
    throw new Error(
      "Live ServiceNow smoke test stopped because the audit account could not read every core table; forbidden or ACL-filtered tables are listed above.",
    );
  }

  const hardening = await assessServicenowPlatformHardening(client);
  const counts = hardening.summary.status_counts;
  log(`Platform hardening findings: ${hardening.findings.length}`);
  log(`Summary: Pass ${counts.pass}, Warn ${counts.warn}, Fail ${counts.fail}, Manual ${counts.manual}`);
  for (const issue of hardening.errors) {
    log(`- collection issue: ${issue}`);
  }
  log("Live ServiceNow smoke test passed.");
} catch (error) {
  process.stderr.write(`Live ServiceNow smoke test failed: ${error instanceof Error ? error.message : String(error)}\n`);
  process.exit(1);
}
