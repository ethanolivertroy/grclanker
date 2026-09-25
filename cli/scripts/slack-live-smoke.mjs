#!/usr/bin/env node
import {
  SlackApiClient,
  assessSlackAdminAccess,
  assessSlackChannelGovernance,
  assessSlackIdentity,
  assessSlackIntegrations,
  assessSlackMonitoring,
  checkSlackAccess,
  resolveSlackConfiguration,
} from "../dist/extensions/grc-tools/slack.js";

if (!process.env.SLACK_USER_TOKEN && !process.env.SLACK_BOT_TOKEN && !process.env.SLACK_CONFIG_FILE) {
  console.log("Skipping Slack live smoke: set SLACK_USER_TOKEN (or SLACK_BOT_TOKEN, or SLACK_CONFIG_FILE) to run.");
  process.exit(0);
}

const client = new SlackApiClient(resolveSlackConfiguration());
const access = await checkSlackAccess(client);
console.log(`slack_check_access: ${access.status} (${access.surfaces.filter((surface) => surface.status === "readable").length}/${access.surfaces.length} readable)`);

const assessments = [
  ["slack_assess_identity", assessSlackIdentity],
  ["slack_assess_admin_access", assessSlackAdminAccess],
  ["slack_assess_integrations", assessSlackIntegrations],
  ["slack_assess_channel_governance", assessSlackChannelGovernance],
  ["slack_assess_monitoring", assessSlackMonitoring],
];
let failures = 0;
for (const [name, run] of assessments) {
  try {
    const result = await run(client, {});
    const counts = result.findings.reduce((acc, item) => ({ ...acc, [item.status]: (acc[item.status] ?? 0) + 1 }), {});
    console.log(`${name}: ${result.findings.length} findings ${JSON.stringify(counts)}${result.errors.length > 0 ? ` errors=${result.errors.length}` : ""}`);
  } catch (error) {
    failures += 1;
    console.error(`${name} failed: ${error instanceof Error ? error.message : String(error)}`);
  }
}
process.exit(failures > 0 ? 1 : 0);
