import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

import {
  QualysApiClient,
  assessQualysScanCoverage,
  checkQualysAccess,
  resolveQualysConfiguration,
} from "../dist/extensions/grc-tools/qualys.js";

function log(message) {
  process.stdout.write(`${message}\n`);
}

function hasCredentialHints() {
  const env = process.env;
  const hasBasic = Boolean(env.QUALYS_USERNAME?.trim() || env.QUALYS_USER?.trim()) && Boolean(env.QUALYS_PASSWORD?.trim());
  const hasToken = Boolean(env.QUALYS_TOKEN?.trim() || env.QUALYS_ACCESS_TOKEN?.trim());
  const configFile = env.QUALYS_CONFIG_FILE?.trim() || join(homedir(), ".qcrc");
  return hasBasic || hasToken || existsSync(configFile);
}

try {
  if (!hasCredentialHints()) {
    log(
      "Skipping live Qualys smoke test: set QUALYS_USERNAME and QUALYS_PASSWORD (plus QUALYS_PLATFORM), QUALYS_TOKEN, or a ~/.qcrc config file to run against a real subscription.",
    );
    process.exit(0);
  }

  const config = resolveQualysConfiguration({});
  const client = new QualysApiClient(config);
  const access = await checkQualysAccess(client);

  log(`Qualys platform: ${config.platform} (${config.baseUrl}), auth mode ${config.authMode}`);
  log(`Access status: ${access.status}`);
  for (const surface of access.surfaces) {
    log(`- ${surface.name} [${surface.module}]: ${surface.status}${surface.count === undefined ? "" : ` (${surface.count})`}`);
  }
  if (access.unavailableModules.length > 0) {
    log(`Unavailable modules: ${access.unavailableModules.join(", ")}`);
  }

  if (access.status === "limited") {
    throw new Error(
      "Live Qualys smoke test stopped because the API user could not read the core VM/VMDR surfaces.",
    );
  }

  const assessment = await assessQualysScanCoverage(client, {});
  const counts = { pass: 0, warn: 0, fail: 0, manual: 0 };
  for (const item of assessment.findings) counts[item.status] += 1;

  log(`Scan coverage findings: ${assessment.findings.length}`);
  log(`Summary: pass ${counts.pass}, warn ${counts.warn}, fail ${counts.fail}, manual ${counts.manual}`);
  if (assessment.errors.length > 0) {
    log(`Collection warnings: ${assessment.errors.length}`);
  }
  log("Live Qualys smoke test passed.");
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`${message}\n`);
  process.exit(1);
}
