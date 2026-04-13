import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

import {
  VantaAuditorClient,
  checkVantaAuditorAccess,
  exportVantaAuditPackage,
  resolveVantaCredentials,
} from "../dist/extensions/grc-tools/vanta.js";

function log(message) {
  process.stdout.write(`${message}\n`);
}

function sortAuditsByEndDateDesc(a, b) {
  return b.auditEndDate.localeCompare(a.auditEndDate);
}

try {
  let credentials;

  try {
    credentials = resolveVantaCredentials({}, process.env);
  } catch {
    log(
      "Skipping live Vanta smoke test: set VANTA_CLIENT_ID and VANTA_CLIENT_SECRET to run against the real Vanta Auditor API.",
    );
    process.exit(0);
  }

  const client = new VantaAuditorClient(credentials);
  const access = await checkVantaAuditorAccess(client);

  log(`Vanta access status: ${access.status}`);
  log(`Visible audits: ${access.visibleAuditCount}`);
  for (const note of access.notes) {
    log(`- ${note}`);
  }

  if (access.visibleAuditCount === 0) {
    log("Stopping before export because no audits were returned for these credentials.");
    process.exit(1);
  }

  const audits = (await client.listAudits()).sort(sortAuditsByEndDateDesc);
  const requestedAuditId = process.env.VANTA_AUDIT_ID?.trim();
  const audit = requestedAuditId
    ? audits.find((entry) => entry.id === requestedAuditId)
    : audits[0];

  if (!audit) {
    throw new Error(
      requestedAuditId
        ? `VANTA_AUDIT_ID "${requestedAuditId}" was not returned by Vanta for these credentials.`
        : "No Vanta audit could be selected for export.",
    );
  }

  const outputRoot = process.env.VANTA_SMOKE_OUTPUT_DIR?.trim()
    ? resolve(process.cwd(), process.env.VANTA_SMOKE_OUTPUT_DIR.trim())
    : mkdtempSync(join(tmpdir(), "grclanker-vanta-live-"));

  log(`Exporting audit ${audit.id} (${audit.framework}) for smoke testing...`);
  const result = await exportVantaAuditPackage(client, audit, outputRoot);

  log(`Export complete: ${result.outputDir}`);
  log(`Zip archive: ${result.zipPath}`);
  log(`Evidence items: ${result.totalEvidenceItems}`);
  log(`Files exported: ${result.totalFilesExported}`);
  log(`Control folders: ${result.totalControlFolders}`);

  if (result.errorCount > 0) {
    throw new Error(
      `Live smoke export completed with ${result.errorCount} warning(s). Inspect _errors.log in ${result.outputDir}.`,
    );
  }
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`${message}\n`);
  process.exit(1);
}
