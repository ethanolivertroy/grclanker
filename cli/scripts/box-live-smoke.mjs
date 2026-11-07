import { resolveLiveSmokeConfiguration } from "./live-smoke-config.mjs";

import {
  BoxApiClient,
  assessBoxIdentityAccess,
  checkBoxAccess,
  resolveBoxConfiguration,
  summarizeFindingStatuses,
} from "../dist/extensions/grc-tools/box.js";

function log(message) {
  process.stdout.write(`${message}\n`);
}



try {
  const authentication = await resolveLiveSmokeConfiguration("Box", () => resolveBoxConfiguration());
  if (authentication.kind === "unconfigured") process.exit(0);
  const config = authentication.config;
  const client = new BoxApiClient(config);
  const access = await checkBoxAccess(client);

  log(`Box auth mode: ${config.authMode} (${config.sourceChain.join(" -> ")})`);
  log(`Box enterprise: ${access.enterpriseId ?? "unknown"}`);
  log(`Access status: ${access.status}`);
  for (const surface of access.surfaces) {
    log(`- ${surface.name}: ${surface.status}${surface.count === undefined ? "" : ` (${surface.count})`}${surface.error ? ` - ${surface.error}` : ""}`);
  }

  if (access.status !== "healthy") {
    throw new Error(
      "Live Box smoke test stopped because the audit principal could not read enough core endpoints (current user, enterprise configuration, users, and enterprise events are required).",
    );
  }

  const assessment = await assessBoxIdentityAccess(client, { lookbackDays: 30, eventLimit: 500 });
  const counts = summarizeFindingStatuses(assessment.findings);
  log(`Identity and access findings: ${assessment.findings.length}`);
  log(`Summary: Pass ${counts.pass}, Warn ${counts.warn}, Fail ${counts.fail}, Manual ${counts.manual}`);
  for (const error of assessment.errors) {
    log(`- collection warning: ${error}`);
  }
  for (const note of assessment.truncated) {
    log(`- truncated dataset: ${note}`);
  }
  log("Live Box smoke test passed.");
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`${message}\n`);
  process.exit(1);
}
