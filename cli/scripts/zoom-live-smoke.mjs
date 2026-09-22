import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { join, resolve } from "node:path";

import {
  ZoomApiClient,
  assessZoomCollaborationGovernance,
  assessZoomIdentity,
  assessZoomMeetingSecurity,
  checkZoomAccess,
  resolveZoomConfiguration,
} from "../dist/extensions/grc-tools/zoom.js";

function log(message) {
  process.stdout.write(`${message}\n`);
}

function hasConfigHints() {
  return (
    Boolean(process.env.ZOOM_ACCOUNT_ID?.trim())
    || Boolean(process.env.ZOOM_TOKEN?.trim())
    || Boolean(process.env.ZOOM_CLIENT_ID?.trim())
    || Boolean(process.env.ZOOM_CONFIG_FILE?.trim())
    || existsSync(resolve(process.cwd(), ".zoom.json"))
    || existsSync(resolve(process.cwd(), ".grclanker-zoom.json"))
    || existsSync(join(homedir(), ".zoom.json"))
    || existsSync(join(homedir(), ".grclanker-zoom.json"))
    || existsSync(join(homedir(), ".config", "grclanker", "zoom.json"))
  );
}

function logAssessment(result) {
  const counts = { pass: 0, warn: 0, fail: 0, manual: 0 };
  for (const finding of result.findings) {
    counts[finding.status] += 1;
  }
  log(`${result.title}: ${result.findings.length} findings (pass ${counts.pass}, warn ${counts.warn}, fail ${counts.fail}, manual ${counts.manual})`);
  for (const finding of result.findings) {
    log(`- ${finding.id} [${finding.status}] ${finding.title}`);
  }
  for (const error of result.errors) {
    log(`  collection error: ${error}`);
  }
}

try {
  if (!hasConfigHints()) {
    log(
      "Skipping live Zoom smoke test: set ZOOM_ACCOUNT_ID with ZOOM_CLIENT_ID and ZOOM_CLIENT_SECRET (or ZOOM_TOKEN), or configure .zoom.json / ~/.zoom.json / ~/.config/grclanker/zoom.json to run against a real account.",
    );
    process.exit(0);
  }

  const config = resolveZoomConfiguration();
  const client = new ZoomApiClient(config);
  const access = await checkZoomAccess(client);

  log(`Zoom account: ${access.accountId}`);
  log(`Access status: ${access.status}`);
  for (const surface of access.surfaces) {
    log(`- ${surface.name}: ${surface.status}${surface.error ? ` (${surface.error})` : ""}`);
  }

  if (access.status !== "healthy") {
    throw new Error(
      "Live Zoom smoke test stopped because the Server-to-Server OAuth app could not read the core settings, users, roles, and groups surfaces.",
    );
  }

  logAssessment(await assessZoomIdentity(client));
  logAssessment(await assessZoomCollaborationGovernance(client));
  logAssessment(await assessZoomMeetingSecurity(client));
  log("Live Zoom smoke test passed.");
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`${message}\n`);
  process.exit(1);
}
