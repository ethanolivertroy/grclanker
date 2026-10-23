import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

import {
  BoxApiClient,
  assessBoxIdentityAccess,
  checkBoxAccess,
  resolveBoxConfiguration,
  summarizeFindingStatuses,
} from "../dist/extensions/grc-tools/box.js";

function log(message) {
  process.stdout.write(`${message}\n`);
}

function hasValue(name) {
  return Boolean(process.env[name]?.trim());
}

function hasConfigHints() {
  const jwt = hasValue("BOX_JWT_CONFIG_PATH");
  const clientCredentials = hasValue("BOX_CLIENT_ID") && hasValue("BOX_CLIENT_SECRET");
  const ccg = clientCredentials && (hasValue("BOX_ENTERPRISE_ID") || hasValue("BOX_SUBJECT_ID"));
  const oauth = hasValue("BOX_ACCESS_TOKEN") || hasValue("BOX_TOKEN") || hasValue("BOX_DEVELOPER_TOKEN")
    || (hasValue("BOX_REFRESH_TOKEN") && clientCredentials);
  const configFile = hasValue("BOX_CONFIG_PATH") || existsSync(join(homedir(), ".box-sec-inspector", "config.yaml"));
  return jwt || ccg || oauth || configFile;
}

try {
  if (!hasConfigHints()) {
    log(
      "Skipping live Box smoke test: set BOX_JWT_CONFIG_PATH (JWT); BOX_CLIENT_ID and BOX_CLIENT_SECRET with BOX_ENTERPRISE_ID or BOX_SUBJECT_ID (Client Credentials Grant); BOX_ACCESS_TOKEN, BOX_TOKEN, or BOX_DEVELOPER_TOKEN, or BOX_REFRESH_TOKEN with BOX_CLIENT_ID and BOX_CLIENT_SECRET (OAuth 2.0); or a config file at BOX_CONFIG_PATH or ~/.box-sec-inspector/config.yaml to run against a real enterprise.",
    );
    process.exit(0);
  }

  const config = resolveBoxConfiguration();
  const client = new BoxApiClient(config);
  const access = await checkBoxAccess(client);

  log(`Box auth mode: ${config.authMode} (${config.sourceChain.join(" -> ")})`);
  log(`Box enterprise: ${access.enterpriseId ?? "unknown"}`);
  log(`Access status: ${access.status}`);
  for (const surface of access.surfaces) {
    log(`- ${surface.name}: ${surface.status}${surface.count === undefined ? "" : ` (${surface.count})`}${surface.error ? ` - ${surface.error}` : ""}`);
  }

  if (access.status !== "healthy") {
    throw new Error(
      "Live Box smoke test stopped because the audit principal could not read enough core endpoints (current user, enterprise configuration, users, and enterprise events are required).",
    );
  }

  const assessment = await assessBoxIdentityAccess(client, { lookbackDays: 30, eventLimit: 500 });
  const counts = summarizeFindingStatuses(assessment.findings);
  log(`Identity and access findings: ${assessment.findings.length}`);
  log(`Summary: Pass ${counts.pass}, Warn ${counts.warn}, Fail ${counts.fail}, Manual ${counts.manual}`);
  for (const error of assessment.errors) {
    log(`- collection warning: ${error}`);
  }
  for (const note of assessment.truncated) {
    log(`- truncated dataset: ${note}`);
  }
  log("Live Box smoke test passed.");
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`${message}\n`);
  process.exit(1);
}
