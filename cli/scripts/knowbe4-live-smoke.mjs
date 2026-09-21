import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { join, resolve } from "node:path";

import {
  Knowbe4ApiClient,
  assessKnowbe4AccountGovernance,
  checkKnowbe4Access,
  collectKnowbe4Snapshot,
  resolveKnowbe4Configuration,
} from "../dist/extensions/grc-tools/knowbe4.js";

function log(message) {
  process.stdout.write(`${message}\n`);
}

function hasConfigHints() {
  const configFile = process.env.KNOWBE4_CONFIG_FILE?.trim();
  return (
    Boolean(process.env.KNOWBE4_API_TOKEN?.trim())
    || (Boolean(configFile) && existsSync(resolve(process.cwd(), configFile)))
    || existsSync(join(homedir(), ".knowbe4-inspector", "config.yaml"))
  );
}

try {
  if (!hasConfigHints()) {
    log(
      "Skipping live KnowBe4 smoke test: set KNOWBE4_API_TOKEN (and optionally KNOWBE4_REGION) or configure ~/.knowbe4-inspector/config.yaml to run against a real account.",
    );
    process.exit(0);
  }

  const config = resolveKnowbe4Configuration();
  const client = new Knowbe4ApiClient(config);
  const access = await checkKnowbe4Access(client);

  log(`KnowBe4 region: ${access.region} (${access.baseUrl})`);
  log(`Account: ${access.accountName ?? "unknown"}${access.subscriptionLevel ? ` (${access.subscriptionLevel})` : ""}`);
  log(`Access status: ${access.status}`);
  for (const surface of access.surfaces) {
    log(`- ${surface.name}: ${surface.status}${surface.error ? ` (${surface.error})` : ""}`);
  }

  if (access.status !== "healthy") {
    throw new Error(
      "Live KnowBe4 smoke test stopped because the Reporting API key could not read enough core endpoints.",
    );
  }

  const snapshot = await collectKnowbe4Snapshot(client, { scopes: ["governance"], redactPii: true });
  const assessment = assessKnowbe4AccountGovernance(snapshot, { redactPii: true });
  const counts = { pass: 0, warn: 0, fail: 0, manual: 0 };
  for (const item of assessment.findings) counts[item.status] += 1;

  log(`Governance findings: ${assessment.findings.length}`);
  for (const item of assessment.findings) {
    log(`- ${item.id} ${item.status.toUpperCase()}: ${item.title}`);
  }
  log(`Summary: Pass ${counts.pass}, Warn ${counts.warn}, Fail ${counts.fail}, Manual ${counts.manual}`);
  log(`Reporting API requests used: ${client.getRequestCount()}`);
  if (snapshot.errors.length > 0) {
    log(`Collection warnings: ${snapshot.errors.length}`);
  }
  log("Live KnowBe4 smoke test passed.");
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`${message}\n`);
  process.exit(1);
}
