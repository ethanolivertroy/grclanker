import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

import {
  OciAuditorClient,
  assessOciComputeAndStorage,
  assessOciIdentity,
  assessOciLoggingDetection,
  assessOciTenancyGuardrails,
  checkOciAccess,
  resolveOciConfiguration,
} from "../dist/extensions/grc-tools/oci.js";

function log(message) {
  process.stdout.write(`${message}\n`);
}

function hasOciBinary() {
  try {
    execFileSync("oci", ["--version"], { stdio: ["ignore", "pipe", "ignore"], timeout: 15_000 });
    return true;
  } catch {
    return false;
  }
}

function hasConfigHints() {
  return Boolean(process.env.OCI_CONFIG_FILE?.trim())
    || Boolean(process.env.OCI_TENANCY_OCID?.trim())
    || existsSync(join(homedir(), ".oci", "config"));
}

function summarize(result) {
  const counts = { pass: 0, warn: 0, fail: 0, manual: 0 };
  for (const item of result.findings) counts[item.status] += 1;
  log(`${result.title}: pass ${counts.pass}, warn ${counts.warn}, fail ${counts.fail}, manual ${counts.manual}, errors ${result.errors.length}`);
  for (const item of result.findings) {
    log(`- ${item.id} ${item.status.toUpperCase()}: ${item.summary}`);
  }
}

try {
  if (!hasConfigHints()) {
    log("Skipping live OCI smoke test: no ~/.oci/config, OCI_CONFIG_FILE, or OCI_TENANCY_OCID is present.");
    process.exit(0);
  }
  if (!hasOciBinary()) {
    log("Skipping live OCI smoke test: the oci CLI binary is not installed or not on PATH.");
    process.exit(0);
  }

  let config;
  try {
    config = resolveOciConfiguration({}, process.env);
  } catch (error) {
    log(`Skipping live OCI smoke test: ${error instanceof Error ? error.message : String(error)}`);
    process.exit(0);
  }

  const client = new OciAuditorClient(config);
  const access = await checkOciAccess(client);
  log(`OCI tenancy: ${access.tenancyOcid} (${config.region}, profile ${config.profile})`);
  log(`Access status: ${access.status}`);
  for (const surface of access.surfaces) {
    log(`- ${surface.name}: ${surface.status}${surface.error ? ` (${surface.error.split("\n")[0].slice(0, 120)})` : ""}`);
  }

  summarize(await assessOciIdentity(client));
  summarize(await assessOciLoggingDetection(client));
  summarize(await assessOciTenancyGuardrails(client));
  summarize(await assessOciComputeAndStorage(client));
  log("Live OCI smoke test completed.");
} catch (error) {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exit(1);
}
