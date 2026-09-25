import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  GoogleWorkspaceAuditorClient,
  assessGwsAdminAccess,
  assessGwsIdentity,
  assessGwsIntegrations,
  assessGwsMonitoring,
  collectGwsAuditData,
  exportGwsAuditBundle,
  resolveGwsConfiguration,
  runGwsAccessCheck,
} from "../dist/extensions/grc-tools/gws.js";

function log(message) {
  process.stdout.write(`${message}\n`);
}

function hasConfigHints() {
  const hasServiceAccount = Boolean(
    (process.env.GWS_CREDENTIALS_FILE?.trim()
      || process.env.GWS_SERVICE_ACCOUNT_FILE?.trim()
      || process.env.GOOGLE_APPLICATION_CREDENTIALS?.trim()
      || process.env.GWS_CREDENTIALS_JSON?.trim()
      || process.env.GWS_SERVICE_ACCOUNT_JSON?.trim())
    && process.env.GWS_ADMIN_EMAIL?.trim(),
  );
  const hasAccessToken = Boolean(process.env.GWS_ACCESS_TOKEN?.trim());
  return hasServiceAccount || hasAccessToken;
}

function logAssessment(label, assessment) {
  log(`${label}: ${assessment.findings.length} findings`);
  log(
    `  Pass ${assessment.summary.Pass}, Partial ${assessment.summary.Partial}, Fail ${assessment.summary.Fail}, Manual ${assessment.summary.Manual}, Info ${assessment.summary.Info}`,
  );
  for (const finding of assessment.findings) {
    log(`  - ${finding.id} ${finding.status}: ${finding.summary}`);
  }
}

try {
  if (!hasConfigHints()) {
    log(
      "Skipping live Google Workspace smoke test: set GWS_CREDENTIALS_FILE + GWS_ADMIN_EMAIL (or GWS_CREDENTIALS_JSON + GWS_ADMIN_EMAIL) or GWS_ACCESS_TOKEN to run against a real tenant.",
    );
    process.exit(0);
  }

  const config = await resolveGwsConfiguration();
  const client = new GoogleWorkspaceAuditorClient(config);
  const access = await runGwsAccessCheck(client, config);

  log(`Google Workspace org: ${access.organization}`);
  log(`Access status: ${access.status}`);
  for (const probe of access.probes) {
    log(`- ${probe.key}: ${probe.status} (${probe.detail})`);
  }

  if (access.status !== "healthy") {
    throw new Error(
      "Live Google Workspace smoke test stopped because the supplied principal could not read enough core Directory / Reports surfaces.",
    );
  }

  const data = await collectGwsAuditData(client);
  logAssessment("gws_assess_identity", assessGwsIdentity(data.identity, config));
  logAssessment("gws_assess_admin_access", assessGwsAdminAccess(data.adminAccess, config));
  logAssessment("gws_assess_integrations", assessGwsIntegrations(data.integrations, config));
  logAssessment("gws_assess_monitoring", assessGwsMonitoring(data.monitoring, config));

  const outputRoot = mkdtempSync(join(tmpdir(), "grclanker-gws-live-"));
  const bundle = await exportGwsAuditBundle(client, config, outputRoot);
  log(`gws_export_audit_bundle: ${bundle.fileCount} files, ${bundle.findingCount} findings, ${bundle.errorCount} collection errors`);
  log(`  Output directory: ${bundle.outputDir}`);
  log(`  Zip archive: ${bundle.zipPath}`);
  if (bundle.findingCount !== 19) {
    throw new Error(`Expected 19 findings in the exported bundle, received ${bundle.findingCount}.`);
  }
  log("Live Google Workspace smoke test passed.");
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`${message}\n`);
  process.exit(1);
}
