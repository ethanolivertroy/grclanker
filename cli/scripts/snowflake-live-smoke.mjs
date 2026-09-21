import {
  SnowflakeSqlClient,
  assessSnowflakeNetworkAndAuthentication,
  checkSnowflakeAccess,
  redactSecrets,
  resolveSnowflakeConfiguration,
} from "../dist/extensions/grc-tools/snowflake.js";

function log(message) {
  process.stdout.write(`${message}\n`);
}

try {
  let config;

  try {
    config = resolveSnowflakeConfiguration({}, process.env);
  } catch {
    log(
      "Skipping live Snowflake smoke test: set SNOWFLAKE_ACCOUNT, SNOWFLAKE_USER, and either SNOWFLAKE_PRIVATE_KEY_PATH (or SNOWFLAKE_PRIVATE_KEY) or SNOWFLAKE_TOKEN, or configure ~/.snowflake/connections.toml, to run against a real account.",
    );
    process.exit(0);
  }

  const client = new SnowflakeSqlClient(config);
  const access = await checkSnowflakeAccess(client);

  log(`Snowflake access status: ${access.status}`);
  log(`Account: ${access.account}, user: ${access.user}, role: ${access.role ?? "(default)"}, full visibility: ${access.fullVisibility}`);
  for (const note of access.notes) {
    log(`- ${note}`);
  }
  for (const surface of access.surfaces.filter((entry) => entry.status !== "readable")) {
    log(`- ${surface.name}: ${surface.status}${surface.error ? ` (${surface.error.replace(/\s+/g, " ").slice(0, 120)})` : ""}`);
  }

  const assessment = await assessSnowflakeNetworkAndAuthentication(client);
  log("");
  log(`${assessment.title}: pass=${assessment.summary.pass} warn=${assessment.summary.warn} fail=${assessment.summary.fail} manual=${assessment.summary.manual}`);
  for (const finding of assessment.findings) {
    log(`- ${finding.id} [${finding.status.toUpperCase()}] ${finding.title}`);
  }

  if (access.status !== "healthy") {
    log("");
    log(`Access is limited: ${access.recommendedNextStep}`);
  }
  process.exit(0);
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`Live Snowflake smoke test failed: ${redactSecrets(message)}\n`);
  process.exit(1);
}
