import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { readdir, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";
import {
  AWS_REQUESTS,
  AWS_SPEC,
  AWS_VERDICT_VALUES,
} from "../dist/extensions/grc-tools/aws.spec.js";
import {
  SHARED_COLLECTION_STATES,
  SHARED_DATASET_STATES,
  SHARED_INTEGRATION_CONTRACT_VERSION,
  SHARED_PAGINATION_STOP_KINDS,
  SHARED_REDACTION_RULES,
} from "../dist/extensions/grc-tools/hardening/contract.js";
import { collectDefinedGrcTools } from "../dist/extensions/grc-tools/spec-model.js";
import { PUBLISHED_INTEGRATION_SPECS } from "../dist/extensions/grc-tools/spec-registry.js";
import { resolveWebexConfiguration } from "../dist/extensions/grc-tools/webex.js";
import {
  WEBEX_ENV,
  WEBEX_SCOPES,
  WEBEX_SPEC,
  WEBEX_VERDICT_VALUES,
} from "../dist/extensions/grc-tools/webex.spec.js";
import {
  checkIntegrationSpecs,
  repoRoot,
  renderAllIntegrationSpecs,
} from "../scripts/generate-integration-specs.mjs";

const expectedDatasetStates = ["complete", "truncated", "unreadable", "not_requested"];
const expectedCollectionStates = ["complete", "truncated", "unreadable", "denied", "not_requested", "not_configured"];
const expectedPaginationStops = [
  "exhausted",
  "limit",
  "page_cap",
  "repeated_cursor",
  "empty_page_with_cursor",
  "time_budget",
  "missing_total",
  "rejected_next_link",
];

test("generated integration specs are current", async () => {
  assert.deepEqual(await checkIntegrationSpecs(), []);
});

test("published registry entries have complete, internally linked contracts", () => {
  assert.deepEqual(PUBLISHED_INTEGRATION_SPECS.map((entry) => entry.contract.identity.slug), [
    "aws-sec-inspector",
    "webex-sec-inspector",
  ]);

  for (const entry of PUBLISHED_INTEGRATION_SPECS) {
    const { contract } = entry;
    assert.ok(contract.apiSurfaces.length > 0, `${contract.identity.slug}: surfaces`);
    assert.ok(contract.permissions.length > 0, `${contract.identity.slug}: permissions`);
    assert.ok(contract.controls.length > 0, `${contract.identity.slug}: controls`);
    assert.ok(contract.checks.length > 0, `${contract.identity.slug}: checks`);
    assert.ok(contract.output.files.length > 0, `${contract.identity.slug}: output`);

    const registered = collectDefinedGrcTools(entry.registerTools);
    assert.deepEqual(
      registered.map((tool) => tool.definition.name).sort(),
      contract.tools.map((tool) => tool.name).sort(),
      `${contract.identity.slug}: every registered pilot tool has a contract`,
    );

    const toolNames = new Set(contract.tools.map((tool) => tool.name));
    const surfaceIds = new Set(contract.apiSurfaces.map((surface) => surface.id));
    const checkIds = new Set();
    for (const check of contract.checks) {
      assert.ok(!checkIds.has(check.id), `${contract.identity.slug}: duplicate ${check.id}`);
      checkIds.add(check.id);
      assert.ok(toolNames.has(check.owningTool), `${check.id}: owning tool`);
      assert.ok(check.sourceSurfaceIds.every((id) => surfaceIds.has(id)), `${check.id}: source surface`);
    }
    for (const permission of contract.permissions) {
      assert.ok(permission.unlocks.every((id) => surfaceIds.has(id)), `${permission.id}: unlocked surface`);
    }
    for (const tool of contract.tools) {
      assert.ok(tool.checkIds.every((id) => checkIds.has(id)), `${tool.name}: check id`);
    }
  }
});

test("shared contract vocabulary stays aligned with hardening helpers", () => {
  assert.equal(SHARED_INTEGRATION_CONTRACT_VERSION, "1.1");
  assert.deepEqual(SHARED_DATASET_STATES, expectedDatasetStates);
  assert.deepEqual(SHARED_COLLECTION_STATES, expectedCollectionStates);
  assert.deepEqual(SHARED_PAGINATION_STOP_KINDS, expectedPaginationStops);
  assert.deepEqual(SHARED_REDACTION_RULES.map((rule) => rule.id), [
    "configured-values",
    "credential-carriers",
    "urls",
    "bare-token-shapes",
    "credential-subtrees",
    "name-value-records",
    "depth-cap",
    "error-bodies",
    "two-pass-sink",
  ]);
});

test("every finding publishes exact criteria, constants, and four portability examples", () => {
  for (const spec of [AWS_SPEC, WEBEX_SPEC]) {
    const generic = new Set(spec.checks.map((check) => check.criteria.pass));
    assert.ok(generic.size > spec.checks.length / 2, `${spec.identity.slug}: criteria are check-specific`);
    for (const check of spec.checks) {
      for (const status of ["pass", "warn", "fail", "manual"]) {
        assert.ok(check.criteria[status].length > 20, `${check.id}: exact ${status} predicate`);
      }
      assert.deepEqual(
        check.criteria.examples.map((example) => example.kind).sort(),
        ["compliant", "noncompliant", "partial", "unreadable"],
        `${check.id}: example classes`,
      );
      assert.ok(check.criteria.examples.every((example) => example.input.length > 20 && example.reason.length > 20), `${check.id}: useful examples`);
    }
  }
  assert.equal(AWS_SPEC.checks.find((check) => check.id === "AWS-IAM-03").criteria.constants.minimumLength, AWS_VERDICT_VALUES.minimumPasswordLength);
  assert.equal(WEBEX_SPEC.checks.find((check) => check.id === "WEBEX-MTG-06").criteria.constants.minimumLength, WEBEX_VERDICT_VALUES.minimumMeetingPasswordLength);
});

test("request and pagination metadata matches the concrete pilot clients", () => {
  for (const spec of [AWS_SPEC, WEBEX_SPEC]) {
    for (const surface of spec.apiSurfaces) {
      assert.ok(surface.request, `${surface.id}: request`);
      assert.ok(surface.request.clientRegion.length > 0, `${surface.id}: client selection`);
      assert.ok(surface.request.responseShape.length > 0, `${surface.id}: response shape`);
      assert.ok(surface.projectionStage.length > 0, `${surface.id}: projection meaning`);
    }
  }

  const accountBlock = AWS_SPEC.apiSurfaces.find((surface) => surface.id === "s3-get-account-public-access-block");
  assert.deepEqual(
    {
      service: accountBlock.sdkService,
      operation: accountBlock.operation,
      action: accountBlock.iamAction,
      docs: accountBlock.documentationUrl,
      input: accountBlock.request.parameters.map((parameter) => parameter.name),
    },
    {
      service: "s3-control",
      operation: "GetPublicAccessBlock",
      action: "s3:GetAccountPublicAccessBlock",
      docs: "https://docs.aws.amazon.com/AmazonS3/latest/API/API_control_GetPublicAccessBlock.html",
      input: ["AccountId"],
    },
  );
  assert.equal(AWS_REQUESTS["kms-list-keys"].parameters.find((parameter) => parameter.name === "Limit").value, "1000");

  const iamMarkers = AWS_SPEC.pagination.find((entry) => entry.cursorFields.includes("IsTruncated"));
  assert.ok(!iamMarkers.surfaceIds.includes("organizations-list-policies"));
  const nextTokens = AWS_SPEC.pagination.find((entry) => entry.surfaceIds.includes("organizations-list-policies"));
  assert.ok(nextTokens.cursorFields.includes("NextToken"));
  const kms = AWS_SPEC.pagination.find((entry) => entry.surfaceIds.includes("kms-list-keys"));
  assert.equal(kms.pageSize, 1000);

  const webexPaged = WEBEX_SPEC.pagination[0].surfaceIds;
  assert.ok(webexPaged.includes("organizations"));
  assert.ok(webexPaged.includes("roles"));
});

test("Webex environment and scope metadata is the runtime source of truth", () => {
  assert.deepEqual(WEBEX_SPEC.authentication.environmentVariables, Object.values(WEBEX_ENV));
  const direct = resolveWebexConfiguration({}, {
    [WEBEX_ENV.token]: "token-for-env-test",
    [WEBEX_ENV.orgId]: "org-env",
    [WEBEX_ENV.apiBaseUrl]: "https://proxy.example.test/v1",
    [WEBEX_ENV.timeout]: "17",
  });
  assert.equal(direct.token, "token-for-env-test");
  assert.equal(direct.orgId, "org-env");
  assert.equal(direct.baseUrl, "https://proxy.example.test/v1");
  assert.equal(direct.timeoutMs, 17_000);

  const refreshed = resolveWebexConfiguration({}, {
    [WEBEX_ENV.clientId]: "client-env",
    [WEBEX_ENV.clientSecret]: "secret-env",
    [WEBEX_ENV.refreshToken]: "refresh-env",
  });
  assert.deepEqual(refreshed.refresh, { clientId: "client-env", clientSecret: "secret-env", refreshToken: "refresh-env" });

  const root = mkdtempSync(join(tmpdir(), "grclanker-webex-spec-env-"));
  const configPath = join(root, "webex.json");
  writeFileSync(configPath, JSON.stringify({ token: "file-token", org_id: "file-org" }));
  try {
    const fromFile = resolveWebexConfiguration({}, { [WEBEX_ENV.configFile]: configPath });
    assert.equal(fromFile.token, "file-token");
    assert.equal(fromFile.orgId, "file-org");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }

  const permissionMap = Object.fromEntries(WEBEX_SPEC.permissions.map((permission) => [permission.value, permission.unlocks]));
  assert.deepEqual(permissionMap[WEBEX_SCOPES.ownDetailsRead], ["me"]);
  assert.deepEqual(permissionMap[WEBEX_SCOPES.adminAuditRead], ["admin-audit-events"]);
  assert.deepEqual(permissionMap[WEBEX_SCOPES.adminRecordingsRead], ["admin-recordings"]);
  assert.deepEqual(permissionMap[WEBEX_SCOPES.meetingAdminConfigRead], ["meeting-common-settings"]);
});

test("rendered requirements remain language-neutral and preserve mapping table shapes", async () => {
  const outputs = await renderAllIntegrationSpecs();
  for (const entry of PUBLISHED_INTEGRATION_SPECS) {
    const outputPath = resolve(repoRoot, entry.outputPath);
    const markdown = outputs.get(outputPath);
    assert.ok(markdown, entry.outputPath);
    assert.doesNotMatch(markdown, /\b(?:TypeScript|ReadonlyArray|Type\.Object|defineGrcTool|prepareArguments)\b/);
    assert.doesNotMatch(markdown, /\binterface\s+[A-Z][A-Za-z0-9_]*\s*(?:\{|<)/);

    const mappingRows = markdown.split("\n").filter((line) => {
      const cells = line.split("|").map((cell) => cell.trim());
      return cells.length === 12 && /^\d+$/.test(cells[1]);
    });
    const coverageRows = markdown.split("\n").filter((line) => {
      const cells = line.split("|").map((cell) => cell.trim());
      return cells.length === 6 && /^\d+$/.test(cells[1]);
    });
    assert.equal(mappingRows.length, entry.contract.controls.length, `${entry.outputPath}: mapping table rows`);
    assert.equal(coverageRows.length, entry.contract.controls.length, `${entry.outputPath}: coverage table rows`);
  }
});

test("export contracts include the files asserted by pilot bundle tests", () => {
  const bySlug = Object.fromEntries(PUBLISHED_INTEGRATION_SPECS.map((entry) => [entry.contract.identity.slug, entry.contract.output]));
  for (const file of [
    "core_data/access.json",
    "analysis/findings.json",
    "compliance/executive_summary.md",
    "compliance/unified_compliance_matrix.md",
  ]) {
    assert.ok(bySlug["aws-sec-inspector"].files.includes(file), `AWS ${file}`);
    assert.ok(bySlug["webex-sec-inspector"].files.includes(file), `Webex ${file}`);
  }
  assert.ok(bySlug["aws-sec-inspector"].conditionalFiles.includes("_errors.log"));
  assert.ok(bySlug["webex-sec-inspector"].conditionalFiles.includes("_errors.log"));
  for (const [slug, output] of Object.entries(bySlug)) {
    assert.ok(output.artifacts.length >= output.files.length, `${slug}: artifact schemas`);
    assert.ok(Object.keys(output.recordSchemas).length >= 5, `${slug}: record schemas`);
    assert.match(output.jsonFormatting, /two-space/);
  }
});

test("every generated pilot spec has one registry owner and llms.txt lists every root spec", async () => {
  const specsDir = resolve(repoRoot, "specs");
  const names = (await readdir(specsDir)).filter((name) => name.endsWith(".spec.md")).sort();
  const owners = new Map(PUBLISHED_INTEGRATION_SPECS.map((entry) => [entry.outputPath.replace("specs/", ""), entry]));

  for (const name of names) {
    const markdown = await readFile(resolve(specsDir, name), "utf8");
    if (markdown.includes("<!-- generated integration spec -->")) {
      assert.ok(owners.has(name), `${name}: generated spec owner`);
    }
  }

  const llms = await readFile(resolve(repoRoot, "public/llms.txt"), "utf8");
  const listed = [...llms.matchAll(/\/specs\/([^)\s]+\.spec\.md)\)/g)].map((match) => match[1]).sort();
  assert.deepEqual([...new Set(listed)], names);
  assert.doesNotMatch(llms, /Each spec describes a Go CLI/);
});
