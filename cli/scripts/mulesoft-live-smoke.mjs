import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

import {
  MulesoftApiClient,
  assessMulesoftIdentityAccess,
  checkMulesoftAccess,
  resolveMulesoftConfiguration,
} from "../dist/extensions/grc-tools/mulesoft.js";

function log(message) {
  process.stdout.write(`${message}\n`);
}

function hasValue(name) {
  return Boolean(process.env[name]?.trim());
}

function hasCredentialHints() {
  const configPath = process.env.MULESOFT_SEC_INSPECTOR_CONFIG?.trim()
    || process.env.ANYPOINT_CONFIG_FILE?.trim()
    || join(homedir(), ".config", "mulesoft-sec-inspector", "config.toml");
  return (
    (hasValue("ANYPOINT_CLIENT_ID") && hasValue("ANYPOINT_CLIENT_SECRET"))
    || (hasValue("ANYPOINT_USERNAME") && hasValue("ANYPOINT_PASSWORD"))
    || hasValue("ANYPOINT_TOKEN")
    || hasValue("ANYPOINT_ACCESS_TOKEN")
    || existsSync(configPath)
  );
}

try {
  if (!hasCredentialHints()) {
    log(
      "Skipping live MuleSoft smoke test: set ANYPOINT_ORG_ID plus ANYPOINT_CLIENT_ID/ANYPOINT_CLIENT_SECRET, "
      + "ANYPOINT_USERNAME/ANYPOINT_PASSWORD, or ANYPOINT_TOKEN (or configure ~/.config/mulesoft-sec-inspector/config.toml) "
      + "to run against a real Anypoint Platform organization.",
    );
    process.exit(0);
  }

  const config = resolveMulesoftConfiguration();
  const client = new MulesoftApiClient(config);
  const access = await checkMulesoftAccess(client);

  log(`Anypoint organization: ${access.organizationId}`);
  log(`Control plane: ${access.controlPlane} (${access.baseUrl})`);
  log(`Auth mode: ${access.authMode}`);
  log(`Access status: ${access.status}`);
  for (const surface of access.surfaces) {
    log(`- ${surface.name}: ${surface.status}${surface.count === undefined ? "" : ` (${surface.count})`}`);
  }
  if (access.missingPermissions.length > 0) {
    log(`Missing permissions: ${access.missingPermissions.join("; ")}`);
  }

  const coreSurfaces = new Set(["current_user", "organization", "members", "role_groups", "environments"]);
  const unreadableCore = access.surfaces.filter((surface) => coreSurfaces.has(surface.name) && surface.status !== "readable");
  if (unreadableCore.length > 0) {
    throw new Error(
      `Live MuleSoft smoke test stopped because core Access Management surfaces are not readable: ${unreadableCore.map((surface) => surface.name).join(", ")}.`,
    );
  }
  if (access.status !== "healthy") {
    log("Access is limited; continuing with the identity and access assessment using the readable surfaces.");
  }

  const assessment = await assessMulesoftIdentityAccess(client);
  const counts = { pass: 0, warn: 0, fail: 0, manual: 0 };
  for (const item of assessment.findings) counts[item.status] += 1;

  log(`Identity and access findings: ${assessment.findings.length}`);
  log(`Summary: Pass ${counts.pass}, Warn ${counts.warn}, Fail ${counts.fail}, Manual ${counts.manual}`);
  for (const item of assessment.findings) {
    log(`- ${item.id} [${item.status}] ${item.title}`);
  }
  if (assessment.errors.length > 0) {
    log(`Collection errors: ${assessment.errors.length}`);
    for (const error of assessment.errors) log(`  - ${client.redact(error)}`);
  }
  log("Live MuleSoft smoke test passed.");
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`${message}\n`);
  process.exit(1);
}
