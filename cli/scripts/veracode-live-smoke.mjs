import {
  VeracodeApiClient,
  assessVeracodePolicyCompliance,
  checkVeracodeAccess,
  resolveVeracodeConfiguration,
} from "../dist/extensions/grc-tools/veracode.js";

function log(message) {
  process.stdout.write(`${message}\n`);
}

try {
  let config;
  try {
    config = resolveVeracodeConfiguration({}, process.env);
  } catch {
    log(
      "Skipping live Veracode smoke test: set VERACODE_API_KEY_ID and VERACODE_API_KEY_SECRET (or a ~/.veracode/credentials profile) to run against the real Veracode REST APIs.",
    );
    process.exit(0);
  }

  const client = new VeracodeApiClient(config);
  const access = await checkVeracodeAccess(client);
  log(`Veracode access status: ${access.status} (${config.baseUrl})`);
  for (const note of access.notes) {
    log(`- ${note}`);
  }
  for (const item of access.surfaces) {
    log(`  ${item.name}: ${item.status}${item.count === undefined ? "" : ` (${item.count})`}${item.error ? ` ${item.error}` : ""}`);
  }

  const assessment = await assessVeracodePolicyCompliance(client, {});
  log("");
  log(assessment.title);
  for (const item of assessment.findings) {
    log(`- ${item.id} [${item.status.toUpperCase()}] ${item.title}: ${item.summary}`);
  }
  for (const error of assessment.errors) {
    log(`  warning: ${error}`);
  }

  if (access.status !== "healthy") {
    log("Access check was limited; review the missing roles above.");
    process.exit(1);
  }
} catch (error) {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exit(1);
}
