import {
  AnsibleAapClient,
  assessAnsibleJobHealth,
  checkAnsibleAccess,
  resolveAnsibleConfiguration,
} from "../dist/extensions/grc-tools/ansible.js";

function log(message) {
  process.stdout.write(`${message}\n`);
}

function hasCredentials() {
  const hasUrl = Boolean(process.env.AAP_URL?.trim());
  const hasToken = Boolean(process.env.AAP_TOKEN?.trim());
  const hasSession = Boolean(process.env.AAP_USERNAME?.trim()) && Boolean(process.env.AAP_PASSWORD?.trim());
  return hasUrl && (hasToken || hasSession);
}

try {
  if (!hasCredentials()) {
    log("Skipping live Ansible AAP smoke test: set AAP_URL plus AAP_TOKEN (or AAP_USERNAME and AAP_PASSWORD) to run against a real controller.");
    process.exit(0);
  }

  const config = resolveAnsibleConfiguration();
  const client = new AnsibleAapClient(config);
  const access = await checkAnsibleAccess(client);

  log(`AAP controller: ${config.baseUrl}`);
  log(`Auth mode: ${config.token ? "token" : "session"}; TLS verification: ${config.verifySsl ? "enabled" : "disabled for this run"}`);
  log(`Access status: ${access.status}`);
  for (const note of access.notes) {
    log(`- ${note}`);
  }
  for (const surface of access.surfaces) {
    log(`- ${surface.name}: ${surface.status}${surface.count === undefined ? "" : ` (${surface.count})`}`);
  }

  if (access.status !== "healthy") {
    throw new Error("Live Ansible AAP smoke test stopped because the audit account could not read enough audit surfaces.");
  }

  const jobHealth = await assessAnsibleJobHealth(client, { days: 30, jobLimit: 200 });
  log(`Job health findings: ${jobHealth.findings.length}`);
  log(`Summary: Pass ${jobHealth.summary.pass}, Warn ${jobHealth.summary.warn}, Fail ${jobHealth.summary.fail}, Manual ${jobHealth.summary.manual}`);
  for (const finding of jobHealth.findings) {
    log(`- ${finding.id} [${finding.status}] ${finding.title}`);
  }
  if (jobHealth.errors.length > 0) {
    log("Partial collection warnings:");
    for (const error of jobHealth.errors) log(`- ${error}`);
  }
  log("Live Ansible AAP smoke test passed.");
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`${message}\n`);
  process.exit(1);
}
