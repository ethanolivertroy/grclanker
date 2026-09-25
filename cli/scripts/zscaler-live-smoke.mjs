import {
  assessZiaAccessControl,
  assessZpa,
  checkZscalerAccess,
  createZscalerClients,
} from "../dist/extensions/grc-tools/zscaler.js";

function log(message) {
  process.stdout.write(`${message}\n`);
}

function hasZiaHints() {
  return (
    Boolean(process.env.ZIA_CLOUD?.trim() || process.env.ZIA_BASE_URL?.trim())
    && Boolean(process.env.ZIA_API_KEY?.trim())
    && Boolean(process.env.ZIA_USERNAME?.trim())
    && Boolean(process.env.ZIA_PASSWORD?.trim())
  );
}

function hasZpaHints() {
  return (
    Boolean(process.env.ZPA_CLIENT_ID?.trim())
    && Boolean(process.env.ZPA_CLIENT_SECRET?.trim())
    && Boolean(process.env.ZPA_CUSTOMER_ID?.trim())
  );
}

let clients;
try {
  if (!hasZiaHints() && !hasZpaHints()) {
    log(
      "Skipping live Zscaler smoke test: set ZIA_CLOUD, ZIA_API_KEY, ZIA_USERNAME, ZIA_PASSWORD and/or ZPA_CLIENT_ID, ZPA_CLIENT_SECRET, ZPA_CUSTOMER_ID (plus ZPA_CLOUD) to run against a real tenant.",
    );
    process.exit(0);
  }

  clients = createZscalerClients({}, process.env);
  const access = await checkZscalerAccess(clients);
  log(`Access check: ${access.status}`);
  for (const surface of access.surfaces) {
    log(`- ${surface.product} ${surface.name}: ${surface.status}${surface.count === undefined ? "" : ` (${surface.count})`}${surface.error ? ` ${surface.error}` : ""}`);
  }
  if (access.status === "unavailable") {
    throw new Error("No Zscaler surfaces were readable.");
  }

  const assessment = clients.zia
    ? await assessZiaAccessControl(clients.zia)
    : await assessZpa(clients.zpa);
  log(`${assessment.title}: ${JSON.stringify(assessment.summary.status_counts)}`);
  for (const item of assessment.findings) {
    log(`- ${item.id} ${item.status.toUpperCase()} ${item.title}: ${item.summary}`);
  }
  log("Live Zscaler smoke test passed.");
} catch (error) {
  log(`Live Zscaler smoke test failed: ${error instanceof Error ? error.message : String(error)}`);
  process.exitCode = 1;
} finally {
  await clients?.zia?.logout();
}
