import {
  DuoAuditorClient,
  assessDuoAuthentication,
  collectDuoAuthenticationData,
  resolveDuoConfiguration,
  runDuoAccessCheck,
} from "../dist/extensions/grc-tools/duo.js";

function log(message) {
  process.stdout.write(`${message}\n`);
}

function hasConfigHints() {
  return (
    Boolean(process.env.DUO_API_HOST?.trim())
    && Boolean(process.env.DUO_IKEY?.trim())
    && Boolean(process.env.DUO_SKEY?.trim())
  );
}

try {
  if (!hasConfigHints()) {
    log(
      "Skipping live Duo smoke test: set DUO_API_HOST, DUO_IKEY, and DUO_SKEY to run against a real tenant.",
    );
    process.exit(0);
  }

  const config = resolveDuoConfiguration();
  const client = new DuoAuditorClient(config);
  const access = await runDuoAccessCheck(client, config);

  log(`Duo org: ${access.organization}`);
  log(`Access status: ${access.status}`);
  for (const probe of access.probes) {
    log(`- ${probe.key}: ${probe.status}`);
  }

  if (access.status !== "healthy") {
    throw new Error(
      "Live Duo smoke test stopped because the audit principal could not read enough core endpoints.",
    );
  }

  const authentication = await collectDuoAuthenticationData(client, config.lookbackDays);
  const assessment = assessDuoAuthentication(authentication, config);
  log(`Authentication findings: ${assessment.findings.length}`);
  log(
    `Summary: Pass ${assessment.summary.Pass}, Partial ${assessment.summary.Partial}, Fail ${assessment.summary.Fail}, Manual ${assessment.summary.Manual}, Info ${assessment.summary.Info}`,
  );
  log("Live Duo smoke test passed.");
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`${message}\n`);
  process.exit(1);
}
