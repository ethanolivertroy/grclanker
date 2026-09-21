import {
  CrowdstrikeApiClient,
  assessCrowdstrikePreventionPolicies,
  checkCrowdstrikeAccess,
  resolveCrowdstrikeConfiguration,
} from "../dist/extensions/grc-tools/crowdstrike.js";

function log(message) {
  process.stdout.write(`${message}\n`);
}

function hasCredentialHints() {
  const clientId = process.env.CS_CLIENT_ID?.trim() || process.env.FALCON_CLIENT_ID?.trim();
  const clientSecret = process.env.CS_CLIENT_SECRET?.trim() || process.env.FALCON_CLIENT_SECRET?.trim();
  return Boolean(clientId) && Boolean(clientSecret);
}

try {
  if (!hasCredentialHints()) {
    log(
      "Skipping live CrowdStrike smoke test: set CS_CLIENT_ID and CS_CLIENT_SECRET (and optionally CS_BASE_URL or CS_CLOUD, CS_MEMBER_CID) to run against a real Falcon tenant.",
    );
    process.exit(0);
  }

  const config = resolveCrowdstrikeConfiguration();
  const client = new CrowdstrikeApiClient(config);
  const access = await checkCrowdstrikeAccess(client);

  log(`Falcon API: ${config.baseUrl}${config.cloud ? ` (${config.cloud})` : ""}`);
  log(`Access status: ${access.status}`);
  for (const surface of access.surfaces) {
    log(`- ${surface.name}: ${surface.status}${surface.count === undefined ? "" : ` (${surface.count})`}`);
  }
  if (access.missingScopes.length > 0) {
    log(`Missing scopes: ${access.missingScopes.join("; ")}`);
  }

  const prevention = access.surfaces.find((surface) => surface.name === "prevention_policies");
  if (!prevention || prevention.status !== "readable") {
    throw new Error(
      "Live CrowdStrike smoke test stopped because the API client cannot read prevention policies.",
    );
  }

  const assessment = await assessCrowdstrikePreventionPolicies(client);
  log(`Prevention policy findings: ${assessment.findings.length}`);
  for (const item of assessment.findings) {
    log(`- ${item.id} ${item.status.toUpperCase()}: ${item.summary}`);
  }
  if (assessment.errors.length > 0) {
    log(`Collection warnings: ${assessment.errors.join("; ")}`);
  }
  log("Live CrowdStrike smoke test passed.");
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`${message}\n`);
  process.exit(1);
}
