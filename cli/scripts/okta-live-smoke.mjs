import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { join, resolve } from "node:path";

import {
  OktaAuditorClient,
  assessOktaAuthentication,
  collectOktaAuthenticationData,
  resolveOktaConfiguration,
  runOktaAccessCheck,
} from "../dist/extensions/grc-tools/okta.js";

function log(message) {
  process.stdout.write(`${message}\n`);
}

function hasConfigHints() {
  return (
    Boolean(process.env.OKTA_CLIENT_ORGURL?.trim())
    || Boolean(process.env.OKTA_CLIENT_TOKEN?.trim())
    || Boolean(process.env.OKTA_CLIENT_CLIENTID?.trim())
    || Boolean(process.env.OKTA_CLIENT_PRIVATEKEY?.trim())
    || existsSync(resolve(process.cwd(), ".okta.yaml"))
    || existsSync(join(homedir(), ".okta", "okta.yaml"))
  );
}

try {
  if (!hasConfigHints()) {
    log(
      "Skipping live Okta smoke test: set Okta env vars or configure .okta.yaml / ~/.okta/okta.yaml to run against a real tenant.",
    );
    process.exit(0);
  }

  const config = await resolveOktaConfiguration();
  const client = new OktaAuditorClient(config);
  const access = await runOktaAccessCheck(client, config);

  log(`Okta org: ${access.organization}`);
  log(`Access status: ${access.status}`);
  for (const probe of access.probes) {
    log(`- ${probe.key}: ${probe.status}`);
  }

  if (access.status !== "healthy") {
    throw new Error(
      "Live Okta smoke test stopped because the audit principal could not read enough core endpoints.",
    );
  }

  const authentication = await collectOktaAuthenticationData(client);
  const assessment = assessOktaAuthentication(authentication, config);

  log(`Authentication findings: ${assessment.findings.length}`);
  log(
    `Summary: Pass ${assessment.summary.Pass}, Partial ${assessment.summary.Partial}, Fail ${assessment.summary.Fail}, Manual ${assessment.summary.Manual}, Info ${assessment.summary.Info}`,
  );
  log("Live Okta smoke test passed.");
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`${message}\n`);
  process.exit(1);
}
