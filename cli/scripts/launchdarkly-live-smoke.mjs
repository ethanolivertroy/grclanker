import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

import {
  LaunchdarklyApiClient,
  assessLaunchdarklyAccessControl,
  checkLaunchdarklyAccess,
  resolveLaunchdarklyConfiguration,
} from "../dist/extensions/grc-tools/launchdarkly.js";

function log(message) {
  process.stdout.write(`${message}\n`);
}

function hasConfigHints() {
  const configPath = process.env.LAUNCHDARKLY_CONFIG?.trim()
    || join(homedir(), ".config", "launchdarkly-sec-inspector", "config.toml");
  return (
    Boolean(process.env.LAUNCHDARKLY_API_TOKEN?.trim())
    || Boolean(process.env.LD_ACCESS_TOKEN?.trim())
    || existsSync(configPath)
  );
}

function countByStatus(findings, status) {
  return findings.filter((finding) => finding.status === status).length;
}

try {
  if (!hasConfigHints()) {
    log(
      "Skipping live LaunchDarkly smoke test: set LAUNCHDARKLY_API_TOKEN (optionally LAUNCHDARKLY_BASE_URL) or create ~/.config/launchdarkly-sec-inspector/config.toml to run against a real account.",
    );
    process.exit(0);
  }

  const config = resolveLaunchdarklyConfiguration();
  const client = new LaunchdarklyApiClient(config);
  const access = await checkLaunchdarklyAccess(client);

  log(`LaunchDarkly instance: ${access.baseUrl}`);
  log(`Account: ${access.callerIdentity.accountId ?? "unknown"} (token ${access.callerIdentity.tokenName ?? access.callerIdentity.tokenId ?? "unknown"})`);
  log(`Access status: ${access.status}`);
  for (const surface of access.surfaces) {
    log(`- ${surface.name}: ${surface.status}${surface.count === undefined ? "" : ` (${surface.count})`}`);
  }

  if (access.status !== "healthy") {
    throw new Error(
      "Live LaunchDarkly smoke test stopped because the access token could not read the core audit surfaces.",
    );
  }

  const assessment = await assessLaunchdarklyAccessControl(client);
  log(`Access control findings: ${assessment.findings.length}`);
  log(
    `Summary: Pass ${countByStatus(assessment.findings, "pass")}, Warn ${countByStatus(assessment.findings, "warn")}, Fail ${countByStatus(assessment.findings, "fail")}, Manual ${countByStatus(assessment.findings, "manual")}`,
  );
  for (const finding of assessment.findings) {
    log(`- ${finding.id} ${finding.status.toUpperCase()}: ${finding.title}`);
  }
  if (assessment.errors.length > 0) {
    log(`Partial collection warnings: ${assessment.errors.length}`);
  }
  log("Live LaunchDarkly smoke test passed.");
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`${message}\n`);
  process.exit(1);
}
