import {
  SalesforceApiClient,
  assessSalesforcePlatformSecurity,
  checkSalesforceAccess,
  resolveSalesforceConfiguration,
} from "../dist/extensions/grc-tools/salesforce.js";

function log(message) {
  process.stdout.write(`${message}\n`);
}

function hasConfigHints() {
  const env = process.env;
  const hasJwt = Boolean(env.SF_CONSUMER_KEY?.trim() && env.SF_USERNAME?.trim() && (env.SF_PRIVATE_KEY_FILE?.trim() || env.SF_PRIVATE_KEY?.trim()));
  const hasPassword = Boolean(env.SF_USERNAME?.trim() && env.SF_PASSWORD?.trim() && env.SF_CONSUMER_KEY?.trim() && env.SF_CONSUMER_SECRET?.trim());
  const hasToken = Boolean(env.SF_ACCESS_TOKEN?.trim() && env.SF_INSTANCE_URL?.trim());
  const hasFile = Boolean(env.SF_CREDENTIALS_FILE?.trim());
  return hasJwt || hasPassword || hasToken || hasFile;
}

try {
  if (!hasConfigHints()) {
    log(
      "Skipping live Salesforce smoke test: set SF_CONSUMER_KEY, SF_USERNAME, and SF_PRIVATE_KEY_FILE (JWT bearer), "
      + "SF_USERNAME, SF_PASSWORD, SF_SECURITY_TOKEN, SF_CONSUMER_KEY, and SF_CONSUMER_SECRET (username-password), "
      + "SF_ACCESS_TOKEN with SF_INSTANCE_URL, or SF_CREDENTIALS_FILE to run against a real org.",
    );
    process.exit(0);
  }

  const config = resolveSalesforceConfiguration();
  const client = new SalesforceApiClient(config);
  const access = await checkSalesforceAccess(client);

  log(`Salesforce auth mode: ${access.authMode}`);
  log(`Instance: ${access.instanceUrl ?? "unknown"}`);
  log(`Access status: ${access.status}`);
  for (const surface of access.surfaces) {
    log(`- ${surface.name}: ${surface.status}${surface.count !== undefined ? ` (${surface.count})` : ""}`);
  }
  if (access.missingPermissions.length > 0) {
    log(`Likely missing permissions: ${access.missingPermissions.join("; ")}`);
  }

  const session = access.surfaces.find((surface) => surface.name === "oauth_session");
  if (!session || session.status !== "readable") {
    throw new Error("Live Salesforce smoke test stopped because no OAuth session could be established.");
  }

  const platform = await assessSalesforcePlatformSecurity(client);
  log(`Platform security findings: ${platform.findings.length}`);
  for (const item of platform.findings) {
    log(`- ${item.id} ${item.status.toUpperCase()}: ${item.summary}`);
  }
  if (platform.errors.length > 0) {
    log(`Collection errors: ${platform.errors.join(" | ")}`);
  }
  log("Live Salesforce smoke test passed.");
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`${message}\n`);
  process.exit(1);
}
