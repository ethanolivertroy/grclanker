import { resolveLiveSmokeConfiguration } from "./live-smoke-config.mjs";
import {
  AzureAuditorClient,
  assessAzureIdentity,
  checkAzureAccess,
  resolveAzureConfiguration,
} from "../dist/extensions/grc-tools/azure.js";

function log(message) {
  process.stdout.write(`${message}\n`);
}


try {
  const authentication = await resolveLiveSmokeConfiguration("Azure", () => resolveAzureConfiguration());
  if (authentication.kind === "unconfigured") process.exit(0);
  const config = authentication.config;
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
