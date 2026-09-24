import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

import {
  NewrelicApiClient,
  assessNewrelicIdentity,
  checkNewrelicAccess,
  resolveNewrelicConfiguration,
} from "../dist/extensions/grc-tools/newrelic.js";

function log(message) {
  process.stdout.write(`${message}\n`);
}

function hasConfigHints() {
  return (
    Boolean(process.env.NEW_RELIC_API_KEY?.trim())
    || Boolean(process.env.NEW_RELIC_SEC_INSPECTOR_CONFIG?.trim())
    || existsSync(join(homedir(), ".newrelic-sec-inspector", "config.yaml"))
  );
}

try {
  if (!hasConfigHints()) {
    log(
      "Skipping live New Relic smoke test: set NEW_RELIC_API_KEY (plus optional NEW_RELIC_ACCOUNT_ID and NEW_RELIC_REGION) or create ~/.newrelic-sec-inspector/config.yaml to run against a real organization.",
    );
    process.exit(0);
  }

  const config = resolveNewrelicConfiguration();
  const client = new NewrelicApiClient(config);
  const access = await checkNewrelicAccess(client);

  log(`New Relic region: ${access.region} (${config.nerdgraphUrl})`);
  log(`Accounts in scope: ${access.accountIds.join(", ") || "none resolved"}`);
  log(`Access status: ${access.status}`);
  for (const surface of access.surfaces) {
    log(`- ${surface.name} (${surface.required ? "required" : "optional"}): ${surface.status}${surface.error ? ` - ${surface.error}` : ""}`);
  }

  if (access.status !== "healthy") {
    throw new Error(
      "Live New Relic smoke test stopped because the API key could not read every required NerdGraph surface.",
    );
  }

  const identity = await assessNewrelicIdentity(client);
  log(`Identity findings: ${identity.findings.length}`);
  for (const item of identity.findings) {
    log(`- ${item.id}: ${item.status.toUpperCase()} - ${item.summary}`);
  }
  if (identity.errors.length > 0) {
    log("Partial collection warnings:");
    for (const error of identity.errors) {
      log(`- ${error}`);
    }
  }
  log("Live New Relic smoke test passed.");
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`${message}\n`);
  process.exit(1);
}
