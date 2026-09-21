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
  const ccg = hasValue("BOX_CLIENT_ID") && hasValue("BOX_CLIENT_SECRET") && hasValue("BOX_ENTERPRISE_ID");
  const oauth = hasValue("BOX_ACCESS_TOKEN") || hasValue("BOX_DEVELOPER_TOKEN");
  return jwt || ccg || oauth;
}

try {
  if (!hasConfigHints()) {
    log(
      "Skipping live Box smoke test: set BOX_JWT_CONFIG_PATH (JWT), or BOX_CLIENT_ID, BOX_CLIENT_SECRET, and BOX_ENTERPRISE_ID (Client Credentials Grant), or BOX_ACCESS_TOKEN (OAuth 2.0) to run against a real enterprise.",
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
