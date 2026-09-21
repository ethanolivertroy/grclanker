import {
  CloudflareApiClient,
  assessCloudflareZoneSecurity,
  checkCloudflareAccess,
  resolveCloudflareConfiguration,
} from "../dist/extensions/grc-tools/cloudflare.js";

function log(message) {
  process.stdout.write(`${message}\n`);
}

function hasCredentials() {
  return (
    Boolean(process.env.CLOUDFLARE_API_TOKEN?.trim())
    || (Boolean(process.env.CLOUDFLARE_API_KEY?.trim()) && Boolean(process.env.CLOUDFLARE_EMAIL?.trim()))
  );
}

try {
  if (!hasCredentials()) {
    log("Skipping live Cloudflare smoke test: set CLOUDFLARE_API_TOKEN (or CLOUDFLARE_EMAIL + CLOUDFLARE_API_KEY) to run against a real account.");
    process.exit(0);
  }

  const config = resolveCloudflareConfiguration();
  const client = new CloudflareApiClient(config);
  const access = await checkCloudflareAccess(client);

  log(`Auth method: ${access.authMethod}`);
  log(`Account: ${access.accountId ?? "unresolved"}`);
  log(`Access status: ${access.status}`);
  for (const surface of access.surfaces) {
    log(`- ${surface.name}: ${surface.status}${surface.count === undefined ? "" : ` (${surface.count})`}`);
  }

  if (access.status !== "healthy") {
    throw new Error("Live Cloudflare smoke test stopped because the audit token could not read enough core surfaces.");
  }

  const zoneSecurity = await assessCloudflareZoneSecurity(client, { zoneLimit: 3 });
  log(`Zone security findings: ${zoneSecurity.findings.length}`);
  for (const item of zoneSecurity.findings) {
    log(`- ${item.id} ${item.status.toUpperCase()}: ${item.title}`);
  }
  if (zoneSecurity.errors.length > 0) {
    log(`Read errors: ${zoneSecurity.errors.length}`);
  }
  log("Live Cloudflare smoke test passed.");
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`${message}\n`);
  process.exit(1);
}
