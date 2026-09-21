import {
  assessPaloaltoCloudPosture,
  assessPaloaltoFirewallPolicy,
  checkPaloaltoAccess,
  createPaloaltoClients,
  resolvePaloaltoConfiguration,
} from "../dist/extensions/grc-tools/paloalto.js";

function log(message) {
  process.stdout.write(`${message}\n`);
}

function hasPrismaHints() {
  return Boolean(process.env.PRISMA_ACCESS_KEY_ID?.trim()) && Boolean(process.env.PRISMA_SECRET_KEY?.trim());
}

function hasPanosHints() {
  return (
    Boolean(process.env.PANOS_HOST?.trim())
    && (Boolean(process.env.PANOS_API_KEY?.trim())
      || (Boolean(process.env.PANOS_USERNAME?.trim()) && Boolean(process.env.PANOS_PASSWORD?.trim())))
  );
}

try {
  if (!hasPrismaHints() && !hasPanosHints()) {
    log(
      "Skipping live Palo Alto smoke test: set PRISMA_API_URL, PRISMA_ACCESS_KEY_ID, and PRISMA_SECRET_KEY and/or PANOS_HOST with PANOS_API_KEY (or PANOS_USERNAME and PANOS_PASSWORD) to run against real tenants or devices.",
    );
    process.exit(0);
  }

  const clients = createPaloaltoClients(resolvePaloaltoConfiguration());
  const access = await checkPaloaltoAccess(clients);
  log(`Products: ${access.products.join(", ")}`);
  log(`Access status: ${access.status}`);
  for (const surface of access.surfaces) {
    log(`- ${surface.product} ${surface.target} ${surface.name}: ${surface.status}${surface.error ? ` (${surface.error})` : ""}`);
  }
  if (access.status === "unconfigured") {
    throw new Error("Live Palo Alto smoke test stopped because no audit surface was configured.");
  }

  const assessment = clients.prisma
    ? await assessPaloaltoCloudPosture(clients)
    : await assessPaloaltoFirewallPolicy(clients);
  log(`${assessment.title}: ${assessment.findings.length} findings`);
  log(`Summary: pass ${assessment.summary.pass}, warn ${assessment.summary.warn}, fail ${assessment.summary.fail}, manual ${assessment.summary.manual}`);
  for (const error of assessment.errors) log(`- collection error: ${error}`);
  log("Live Palo Alto smoke test passed.");
} catch (error) {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exit(1);
}
