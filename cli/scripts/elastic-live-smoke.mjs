import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { join, resolve } from "node:path";

import {
  ElasticApiClient,
  assessElasticTransportSecurity,
  checkElasticAccess,
  resolveElasticConfiguration,
} from "../dist/extensions/grc-tools/elastic.js";

function log(message) {
  process.stdout.write(`${message}\n`);
}

function hasConfigHints() {
  const explicitConfig = process.env.ELASTIC_SEC_INSPECTOR_CONFIG?.trim();
  return (
    Boolean(process.env.ELASTIC_URL?.trim())
    || Boolean(process.env.ELASTICSEARCH_URL?.trim())
    || Boolean(process.env.ELASTIC_API_KEY?.trim())
    || Boolean(process.env.ELASTIC_USERNAME?.trim())
    || Boolean(process.env.ELASTIC_BEARER_TOKEN?.trim())
    || (explicitConfig ? existsSync(resolve(process.cwd(), explicitConfig)) : false)
    || existsSync(join(homedir(), ".elastic-sec-inspector", "config.yaml"))
  );
}

try {
  if (!hasConfigHints()) {
    log(
      "Skipping live Elastic smoke test: set ELASTIC_URL plus ELASTIC_API_KEY (or ELASTIC_USERNAME and ELASTIC_PASSWORD), optionally KIBANA_URL, or configure ~/.elastic-sec-inspector/config.yaml to run against a real cluster.",
    );
    process.exit(0);
  }

  const config = resolveElasticConfiguration();
  const client = new ElasticApiClient(config);
  const access = await checkElasticAccess(client);

  log(`Elasticsearch: ${access.elasticsearchUrl}`);
  log(`Kibana: ${access.kibanaUrl ?? "not configured"}`);
  log(`Authenticated as: ${access.authenticatedAs ?? "unknown"} (${access.authenticationRealm ?? "unknown realm"})`);
  log(`Access status: ${access.status}`);
  for (const surface of access.surfaces) {
    log(`- ${surface.name}: ${surface.status}${surface.count === undefined ? "" : ` (${surface.count})`}`);
  }
  if (access.missingClusterPrivileges.length > 0) {
    log(`Missing cluster privileges: ${access.missingClusterPrivileges.join(", ")}`);
  }

  if (access.status !== "healthy") {
    throw new Error(
      "Live Elastic smoke test stopped because the audit principal could not read enough core surfaces.",
    );
  }

  const assessment = await assessElasticTransportSecurity(client);
  const counts = { pass: 0, warn: 0, fail: 0, manual: 0 };
  for (const item of assessment.findings) {
    counts[item.status] += 1;
    log(`- ${item.id} ${item.status.toUpperCase()}: ${item.summary}`);
  }
  log(`Transport security findings: ${assessment.findings.length}`);
  log(`Summary: pass ${counts.pass}, warn ${counts.warn}, fail ${counts.fail}, manual ${counts.manual}`);
  if (assessment.errors.length > 0) {
    log(`Collection errors: ${assessment.errors.length}`);
  }
  log("Live Elastic smoke test passed.");
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`${message}\n`);
  process.exit(1);
}
