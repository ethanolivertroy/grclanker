import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

import {
  AwsAuditorClient,
  assessAwsDataProtection,
  assessAwsIdentity,
  assessAwsLoggingDetection,
  assessAwsNetworkSecurity,
  assessAwsOrgGuardrails,
  checkAwsAccess,
  coveredAwsControls,
  resolveAwsConfiguration,
} from "../dist/extensions/grc-tools/aws.js";

function log(message) {
  process.stdout.write(`${message}\n`);
}

function hasConfigHints() {
  return (
    Boolean(process.env.AWS_PROFILE?.trim())
    || Boolean(process.env.AWS_ACCESS_KEY_ID?.trim())
    || Boolean(process.env.AWS_ROLE_ARN?.trim())
    || Boolean(process.env.AWS_WEB_IDENTITY_TOKEN_FILE?.trim())
    || Boolean(process.env.AWS_CONTAINER_CREDENTIALS_RELATIVE_URI?.trim())
    || Boolean(process.env.AWS_CONTAINER_CREDENTIALS_FULL_URI?.trim())
    || existsSync(join(homedir(), ".aws", "credentials"))
    || existsSync(join(homedir(), ".aws", "config"))
  );
}

function summarize(result) {
  const counts = { pass: 0, warn: 0, fail: 0, manual: 0 };
  for (const item of result.findings) counts[item.status] += 1;
  return counts;
}

function report(result) {
  const counts = summarize(result);
  log(`${result.title}: ${result.findings.length} findings (pass ${counts.pass}, warn ${counts.warn}, fail ${counts.fail}, manual ${counts.manual})`);
  for (const item of result.findings) {
    log(`- ${item.id} ${item.title}: ${item.status.toUpperCase()} (${item.severity})`);
    log(`  ${item.summary}`);
  }
  for (const error of result.errors ?? []) {
    log(`  ! ${error}`);
  }
  for (const item of result.findings) {
    if (item.status === "manual" && !item.summary.trim()) {
      throw new Error(`${item.id} is manual but does not state what evidence to collect.`);
    }
  }
}

try {
  if (!hasConfigHints()) {
    log(
      "Skipping live AWS smoke test: set AWS_PROFILE, AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY, or configure ~/.aws/credentials to run against a real account.",
    );
    process.exit(0);
  }

  const config = resolveAwsConfiguration({});
  const client = new AwsAuditorClient(config);
  const access = await checkAwsAccess(client);

  log(`AWS account: ${access.accountId ?? "unknown"} (${access.arn ?? "unknown principal"})`);
  log(`Region: ${config.region}; source chain: ${config.sourceChain.join(" -> ")}`);
  log(`Access status: ${access.status}`);
  for (const probe of access.surfaces) {
    log(`- ${probe.name} (${probe.service}): ${probe.status}${probe.count !== undefined ? ` [${probe.count}]` : ""}${probe.error ? ` ${probe.error}` : ""}`);
  }

  if (!access.accountId) {
    throw new Error("Live AWS smoke test stopped because sts:GetCallerIdentity did not return an account id.");
  }

  const regions = process.env.AWS_SMOKE_REGIONS?.split(",").map((value) => value.trim()).filter(Boolean);
  const assessments = [
    await assessAwsIdentity(client, {}),
    await assessAwsLoggingDetection(client),
    await assessAwsOrgGuardrails(client, {}),
    await assessAwsDataProtection(client, { regions: regions?.length ? regions : undefined }),
    await assessAwsNetworkSecurity(client, { regions: regions?.length ? regions : undefined }),
  ];

  for (const assessment of assessments) report(assessment);

  const findings = assessments.flatMap((assessment) => assessment.findings);
  const covered = coveredAwsControls(findings);
  log(`Total findings: ${findings.length}; spec controls covered: ${covered.length} of 25 (${covered.join(", ")})`);

  if (access.status !== "healthy") {
    log("Live AWS smoke test completed with limited access; unreadable surfaces rendered manual findings above.");
  }
  log("Live AWS smoke test passed.");
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`${message}\n`);
  process.exit(1);
}
