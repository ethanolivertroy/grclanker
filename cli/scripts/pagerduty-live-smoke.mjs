import {
  PagerdutyApiClient,
  checkPagerdutyAccess,
  resolvePagerdutyConfiguration,
  runPagerdutyIncidentResponseAssessment,
} from "../dist/extensions/grc-tools/pagerduty.js";

function log(message) {
  process.stdout.write(`${message}\n`);
}

function hasCredentialHints() {
  const env = process.env;
  const apiToken = env.PAGERDUTY_API_TOKEN ?? env.PAGERDUTY_API_KEY ?? env.PAGERDUTY_TOKEN ?? env.PD_API_KEY;
  const accessToken = env.PAGERDUTY_ACCESS_TOKEN ?? env.PAGERDUTY_OAUTH_TOKEN;
  const clientCredentials = env.PAGERDUTY_CLIENT_ID && env.PAGERDUTY_CLIENT_SECRET && env.PAGERDUTY_SUBDOMAIN;
  return Boolean(apiToken?.trim() || accessToken?.trim() || clientCredentials);
}

try {
  if (!hasCredentialHints()) {
    log(
      "Skipping live PagerDuty smoke test: set PAGERDUTY_API_TOKEN (or PAGERDUTY_ACCESS_TOKEN, or PAGERDUTY_CLIENT_ID, PAGERDUTY_CLIENT_SECRET, and PAGERDUTY_SUBDOMAIN) to run against a real account.",
    );
    process.exit(0);
  }

  const config = resolvePagerdutyConfiguration();
  const client = new PagerdutyApiClient(config);
  const access = await checkPagerdutyAccess(client);

  log(`PagerDuty region: ${access.region} (${config.baseUrl})`);
  log(`Auth mode: ${access.authMode}`);
  log(`Access status: ${access.status}`);
  for (const surface of access.surfaces) {
    log(`- ${surface.name}: ${surface.status}${surface.count === undefined ? "" : ` (${surface.count})`}`);
  }
  if (access.missingPermissions.length > 0) {
    log(`Missing permissions: ${access.missingPermissions.join("; ")}`);
  }

  const coreSurfaces = ["abilities", "users", "services", "escalation_policies"];
  const coreReadable = access.surfaces.filter((surface) => coreSurfaces.includes(surface.name) && surface.status === "readable");
  if (coreReadable.length !== coreSurfaces.length) {
    throw new Error(
      "Live PagerDuty smoke test stopped because the audit principal could not read the core abilities, users, services, and escalation policy endpoints.",
    );
  }

  const assessment = await runPagerdutyIncidentResponseAssessment(client, { serviceLimit: 100 });
  log(`Incident response findings: ${assessment.findings.length}`);
  log(
    `Summary: pass ${assessment.summary.pass}, warn ${assessment.summary.warn}, fail ${assessment.summary.fail}, manual ${assessment.summary.manual}`,
  );
  for (const item of assessment.findings) {
    log(`- ${item.id} [${item.status}] ${item.title}`);
  }
  if (assessment.errors.length > 0) {
    log(`Collection errors: ${assessment.errors.join("; ")}`);
  }
  log("Live PagerDuty smoke test passed.");
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`${message}\n`);
  process.exit(1);
}
