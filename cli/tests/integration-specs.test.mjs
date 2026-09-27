import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import { resolve } from "node:path";
import test from "node:test";
import {
  SHARED_COLLECTION_STATES,
  SHARED_DATASET_STATES,
  SHARED_INTEGRATION_CONTRACT_VERSION,
  SHARED_PAGINATION_STOP_KINDS,
} from "../dist/extensions/grc-tools/hardening/contract.js";
import { collectDefinedGrcTools } from "../dist/extensions/grc-tools/spec-model.js";
import { PUBLISHED_INTEGRATION_SPECS } from "../dist/extensions/grc-tools/spec-registry.js";
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
  assert.equal(SHARED_INTEGRATION_CONTRACT_VERSION, "1.0");
  assert.deepEqual(SHARED_DATASET_STATES, expectedDatasetStates);
  assert.deepEqual(SHARED_COLLECTION_STATES, expectedCollectionStates);
  assert.deepEqual(SHARED_PAGINATION_STOP_KINDS, expectedPaginationStops);
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
