import {
  AzureAuditorClient,
  assessAzureIdentity,
  checkAzureAccess,
  resolveAzureConfiguration,
} from "../dist/extensions/grc-tools/azure.js";

function log(message) {
  process.stdout.write(`${message}\n`);
}

function hasConfigHints() {
  const env = process.env;
  const hasTenant = Boolean(env.AZURE_TENANT_ID?.trim()) && Boolean(env.AZURE_SUBSCRIPTION_ID?.trim());
  const hasTokens = Boolean(env.AZURE_GRAPH_TOKEN?.trim()) && Boolean(env.AZURE_MANAGEMENT_TOKEN?.trim() || env.AZURE_ACCESS_TOKEN?.trim());
  const hasClientCredentials = Boolean(env.AZURE_CLIENT_ID?.trim()) && Boolean(env.AZURE_CLIENT_SECRET?.trim());
  return hasTenant && (hasTokens || hasClientCredentials);
}

try {
  if (!hasConfigHints()) {
    log(
      "Skipping live Azure smoke test: set AZURE_TENANT_ID and AZURE_SUBSCRIPTION_ID plus either AZURE_GRAPH_TOKEN and AZURE_MANAGEMENT_TOKEN or AZURE_CLIENT_ID and AZURE_CLIENT_SECRET (optionally AZURE_AUTHORITY_HOST).",
    );
    process.exit(0);
  }

  const config = resolveAzureConfiguration({}, process.env, () => undefined);
  const client = new AzureAuditorClient(config);
  const access = await checkAzureAccess(client);

  log(`Azure tenant: ${access.tenantId} / subscription: ${access.subscriptionId} (${config.cloud?.name ?? "public"})`);
  log(`Access status: ${access.status}`);
  for (const surface of access.surfaces) {
    log(`- ${surface.name}: ${surface.status}${surface.error ? ` (${surface.error.slice(0, 80)})` : ""}`);
  }

  if (access.status !== "healthy") {
    throw new Error("Live Azure smoke test stopped because the audit principal could not read enough core endpoints.");
  }

  const identity = await assessAzureIdentity(client);
  const counts = { pass: 0, warn: 0, fail: 0, manual: 0 };
  for (const item of identity.findings) counts[item.status] += 1;
  log(`Identity findings: ${identity.findings.length}`);
  log(`Summary: Pass ${counts.pass}, Warn ${counts.warn}, Fail ${counts.fail}, Manual ${counts.manual}`);
  for (const error of identity.errors) log(`- error: ${error}`);
  log("Live Azure smoke test passed.");
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`${message}\n`);
  process.exit(1);
}
