import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

import {
  WebexApiClient,
  assessWebexCollaborationGovernance,
  assessWebexIdentity,
  assessWebexMeetingHybridSecurity,
  checkWebexAccess,
  resolveWebexConfiguration,
} from "../dist/extensions/grc-tools/webex.js";

function log(message) {
  process.stdout.write(`${message}\n`);
}

function hasConfigHints() {
  const configDir = join(homedir(), ".config", "webex-sec-inspector");
  return (
    Boolean(process.env.WEBEX_TOKEN?.trim())
    || (Boolean(process.env.WEBEX_CLIENT_ID?.trim())
      && Boolean(process.env.WEBEX_CLIENT_SECRET?.trim())
      && Boolean(process.env.WEBEX_REFRESH_TOKEN?.trim()))
    || Boolean(process.env.WEBEX_CONFIG_FILE?.trim())
    || ["config.json", "config.yaml", "config.yml"].some((name) => existsSync(join(configDir, name)))
  );
}

function logAssessment(result) {
  log(`${result.title}: ${result.findings.length} findings (pass ${result.summary.pass}, warn ${result.summary.warn}, fail ${result.summary.fail}, manual ${result.summary.manual})`);
  for (const item of result.findings) {
    log(`- ${item.id} [${item.status}] ${item.title}`);
  }
  for (const error of result.errors) {
    log(`  ! ${error}`);
  }
}

try {
  if (!hasConfigHints()) {
    log(
      "Skipping live Webex smoke test: set WEBEX_TOKEN, or WEBEX_CLIENT_ID + WEBEX_CLIENT_SECRET + WEBEX_REFRESH_TOKEN, or ~/.config/webex-sec-inspector/config.{json,yaml} to run against a real org.",
    );
    process.exit(0);
  }

  const config = resolveWebexConfiguration();
  const client = new WebexApiClient(config);
  const access = await checkWebexAccess(client);

  log(`Webex org: ${access.orgId ?? "auto / unspecified"}`);
  log(`Token type: ${access.tokenType}`);
  log(`Access status: ${access.status}`);
  for (const surface of access.surfaces) {
    log(`- ${surface.name}: ${surface.status}${surface.count === undefined ? "" : ` (${surface.count})`}`);
  }

  logAssessment(await assessWebexIdentity(client));
  logAssessment(await assessWebexCollaborationGovernance(client));
  logAssessment(await assessWebexMeetingHybridSecurity(client));
  log("Live Webex smoke test passed.");
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`${message}\n`);
  process.exit(1);
}
