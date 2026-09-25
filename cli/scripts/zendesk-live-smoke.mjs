import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

import {
  ZendeskApiClient,
  assessZendeskAccessControl,
  checkZendeskAccess,
  resolveZendeskConfiguration,
} from "../dist/extensions/grc-tools/zendesk.js";

function log(message) {
  process.stdout.write(`${message}\n`);
}

function hasCredentialHints() {
  const configPath = process.env.ZENDESK_CONFIG_FILE?.trim() || join(homedir(), ".zendesk", "config.json");
  return (
    Boolean(process.env.ZENDESK_API_TOKEN?.trim())
    || Boolean(process.env.ZENDESK_OAUTH_TOKEN?.trim())
    || Boolean(process.env.ZENDESK_ACCESS_TOKEN?.trim())
    || existsSync(configPath)
  );
}

try {
  if (!hasCredentialHints()) {
    log(
      "Skipping live Zendesk smoke test: set ZENDESK_SUBDOMAIN plus ZENDESK_EMAIL and ZENDESK_API_TOKEN (or ZENDESK_OAUTH_TOKEN), or create ~/.zendesk/config.json, to run against a real account.",
    );
    process.exit(0);
  }

  const config = resolveZendeskConfiguration();
  const client = new ZendeskApiClient(config);
  const access = await checkZendeskAccess(client);

  log(`Zendesk subdomain: ${access.subdomain} (auth: ${access.authMode}, role: ${access.currentUserRole ?? "unknown"})`);
  log(`Access status: ${access.status}`);
  for (const surface of access.surfaces) {
    log(`- ${surface.name}: ${surface.status}${surface.count === undefined ? "" : ` (${surface.count})`}`);
  }
  for (const missing of access.missingPermissions) {
    log(`! ${missing}`);
  }

  if (access.status !== "healthy" && access.status !== "limited") {
    throw new Error("Live Zendesk smoke test stopped because the access check did not complete.");
  }

  const assessment = await assessZendeskAccessControl(client);
  log(`Access control findings: ${assessment.findings.length}`);
  for (const item of assessment.findings) {
    log(`- ${item.id} ${item.status.toUpperCase()} ${item.title}`);
  }
  log(`Summary: pass ${assessment.summary.pass}, warn ${assessment.summary.warn}, fail ${assessment.summary.fail}, manual ${assessment.summary.manual}`);
  if (assessment.errors.length > 0) {
    log(`Collection warnings: ${assessment.errors.length}`);
  }
  log("Live Zendesk smoke test passed.");
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`${message}\n`);
  process.exit(1);
}
