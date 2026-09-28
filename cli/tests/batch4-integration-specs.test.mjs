import assert from "node:assert/strict";
import test from "node:test";

import {
  ANSIBLE_AUTH_RESOLVER,
  DATADOG_AUTH_RESOLVER,
  ELASTIC_AUTH_RESOLVER,
  GITHUB_AUTH_RESOLVER,
  LAUNCHDARKLY_AUTH_RESOLVER,
  MULESOFT_AUTH_RESOLVER,
  NEWRELIC_AUTH_RESOLVER,
  PAGERDUTY_AUTH_RESOLVER,
  SNOWFLAKE_AUTH_RESOLVER,
  SPLUNK_AUTH_RESOLVER,
  SUMOLOGIC_AUTH_RESOLVER,
} from "../dist/extensions/grc-tools/auth-resolver-contracts.js";
import { ANSIBLE_RUNTIME_BEHAVIOR, ANSIBLE_SPEC } from "../dist/extensions/grc-tools/ansible.spec.js";
import { DATADOG_RUNTIME_BEHAVIOR, DATADOG_SPEC } from "../dist/extensions/grc-tools/datadog.spec.js";
import { ELASTIC_RUNTIME_BEHAVIOR, ELASTIC_SPEC } from "../dist/extensions/grc-tools/elastic.spec.js";
import { GITHUB_RUNTIME_BEHAVIOR, GITHUB_SPEC } from "../dist/extensions/grc-tools/github.spec.js";
import { LAUNCHDARKLY_RUNTIME_BEHAVIOR, LAUNCHDARKLY_SPEC } from "../dist/extensions/grc-tools/launchdarkly.spec.js";
import { MULESOFT_RUNTIME_BEHAVIOR, MULESOFT_SPEC } from "../dist/extensions/grc-tools/mulesoft.spec.js";
import { NEWRELIC_RUNTIME_BEHAVIOR, NEWRELIC_SPEC } from "../dist/extensions/grc-tools/newrelic.spec.js";
import { PAGERDUTY_RUNTIME_BEHAVIOR, PAGERDUTY_SPEC } from "../dist/extensions/grc-tools/pagerduty.spec.js";
import { SNOWFLAKE_RUNTIME_BEHAVIOR, SNOWFLAKE_SPEC } from "../dist/extensions/grc-tools/snowflake.spec.js";
import { SPLUNK_RUNTIME_BEHAVIOR, SPLUNK_SPEC } from "../dist/extensions/grc-tools/splunk.spec.js";
import { SUMOLOGIC_RUNTIME_BEHAVIOR, SUMOLOGIC_SPEC } from "../dist/extensions/grc-tools/sumologic.spec.js";
import { PUBLISHED_INTEGRATION_SPECS } from "../dist/extensions/grc-tools/spec-registry.js";
import { collectDefinedGrcTools, evaluateCheckVerdict } from "../dist/extensions/grc-tools/spec-model.js";
import { renderAllIntegrationSpecs, validateDecisionInputs } from "../scripts/generate-integration-specs.mjs";

const batch = [
  [ANSIBLE_SPEC, ANSIBLE_RUNTIME_BEHAVIOR, ANSIBLE_AUTH_RESOLVER],
  [DATADOG_SPEC, DATADOG_RUNTIME_BEHAVIOR, DATADOG_AUTH_RESOLVER],
  [ELASTIC_SPEC, ELASTIC_RUNTIME_BEHAVIOR, ELASTIC_AUTH_RESOLVER],
  [GITHUB_SPEC, GITHUB_RUNTIME_BEHAVIOR, GITHUB_AUTH_RESOLVER],
  [LAUNCHDARKLY_SPEC, LAUNCHDARKLY_RUNTIME_BEHAVIOR, LAUNCHDARKLY_AUTH_RESOLVER],
  [MULESOFT_SPEC, MULESOFT_RUNTIME_BEHAVIOR, MULESOFT_AUTH_RESOLVER],
  [NEWRELIC_SPEC, NEWRELIC_RUNTIME_BEHAVIOR, NEWRELIC_AUTH_RESOLVER],
  [PAGERDUTY_SPEC, PAGERDUTY_RUNTIME_BEHAVIOR, PAGERDUTY_AUTH_RESOLVER],
  [SNOWFLAKE_SPEC, SNOWFLAKE_RUNTIME_BEHAVIOR, SNOWFLAKE_AUTH_RESOLVER],
  [SPLUNK_SPEC, SPLUNK_RUNTIME_BEHAVIOR, SPLUNK_AUTH_RESOLVER],
  [SUMOLOGIC_SPEC, SUMOLOGIC_RUNTIME_BEHAVIOR, SUMOLOGIC_AUTH_RESOLVER],
];

test("batch 4 publishes the eleven requested adjacent contracts", () => {
  assert.deepEqual(batch.map(([spec]) => spec.identity.slug).sort(), [
    "ansible-aap-audit",
    "datadog-sec-inspector",
    "elastic-sec-inspector",
    "github-sec-inspector",
    "launchdarkly-sec-inspector",
    "mulesoft-sec-inspector",
    "newrelic-sec-inspector",
    "pagerduty-sec-inspector",
    "snowflake-sec-inspector",
    "splunk-sec-inspector",
    "sumologic-sec-inspector",
  ]);
  assert.equal(batch.reduce((total, [spec]) => total + spec.controls.length, 0), 261);
  assert.equal(batch.reduce((total, [spec]) => total + spec.checks.length, 0), 270);
});

test("batch 4 registry ownership and non-enumerable tool metadata are exact", () => {
  for (const [spec] of batch) {
    const entry = PUBLISHED_INTEGRATION_SPECS.find((candidate) => candidate.contract === spec);
    assert.ok(entry, `${spec.identity.slug}: published`);
    const tools = collectDefinedGrcTools(entry.registerTools);
    assert.deepEqual(tools.map((tool) => tool.definition.name).sort(), spec.tools.map((tool) => tool.name).sort());
    for (const tool of tools) {
      const enumerable = JSON.stringify({ ...tool.definition });
      assert.ok(Object.getOwnPropertySymbols(tool.definition).length > 0, `${tool.definition.name}: metadata symbol`);
      assert.equal(JSON.stringify({ ...tool.definition }), enumerable, `${tool.definition.name}: enumerable bytes`);
    }
  }
});

test("batch 4 facts are declared, primitive, null-safe, and sample-safe", () => {
  const forbidden = /(?:^|_)(?:status|label|verdict|outcome|compliance|compliant)(?:_|$)/;
  let automatedChecks = 0;
  let inputs = 0;
  for (const [spec] of batch) {
    validateDecisionInputs(spec);
    for (const check of spec.checks) {
      inputs += check.evidenceFields.length;
      assert.equal(evaluateCheckVerdict(check, {}), "manual", `${check.id}: missing`);
      assert.deepEqual(Object.keys(check.evidenceFieldDefinitions).sort(), [...check.evidenceFields].sort());
      assert.equal(Object.keys(check.derivedFactRules ?? {}).length, check.criteria.rules.length);
      for (const name of check.evidenceFields) {
        assert.doesNotMatch(name, forbidden, `${check.id}.${name}`);
        const description = check.evidenceFieldDefinitions[name];
        assert.match(description, /Semantic owner:/);
        assert.match(description, /Type\/domain:/);
        assert.match(description, /Source\/owner:/);
        assert.match(description, /Completeness\/sample semantics:/);
        assert.match(description, /Null\/missing meaning:/);
      }
      if (!check.evidenceFields.includes("evidence_complete")) continue;
      automatedChecks += 1;
      const complete = {
        evidence_readable: true,
        evidence_complete: true,
        inventory_count: 2,
        violation_count: 0,
        review_count: 0,
      };
      assert.equal(evaluateCheckVerdict(check, complete), "pass", `${check.id}: complete`);
      assert.equal(evaluateCheckVerdict(check, { ...complete, evidence_complete: false }), "warn", `${check.id}: partial`);
      assert.equal(evaluateCheckVerdict(check, { ...complete, evidence_readable: false }), "manual", `${check.id}: unreadable`);
      assert.notEqual(evaluateCheckVerdict(check, { ...complete, evidence_complete: false, violation_count: 1 }), "pass", `${check.id}: violation`);
      assert.throws(
        () => evaluateCheckVerdict(check, { ...complete, legacy_selected_status: "pass" }),
        new RegExp(`${check.id} received undeclared decision input`),
      );
    }
  }
  assert.equal(automatedChecks, 264);
  assert.equal(inputs, 1320);
});

test("batch 4 completeness names every check dataset and all failure modes", () => {
  const modes = ["denied", "error", "missing-required-field", "not-collected", "not-configured", "truncated"];
  let contracts = 0;
  for (const [spec] of batch) {
    const surfaces = new Set(spec.apiSurfaces.map((surface) => surface.id));
    for (const check of spec.checks) {
      for (const [name, contract] of Object.entries(check.completeness ?? {})) {
        contracts += 1;
        assert.match(contract.semantics, new RegExp(`For ${check.id},`));
        assert.match(contract.semantics, /Finding previews and exported samples never establish source cardinality\./);
        for (const source of contract.sources) {
          assert.ok(surfaces.has(source.surfaceId), `${check.id}.${name}.${source.surfaceId}`);
          assert.deepEqual([...source.falseWhen].sort(), [...modes].sort());
          for (const mode of modes) assert.match(contract.semantics, new RegExp(`\\b${mode}\\b`));
        }
      }
    }
  }
  assert.equal(contracts, 264);
});

test("batch 4 authentication, operations, pagination, exports, and generated prose render deterministically", async () => {
  for (const [spec, behavior, resolver] of batch) {
    assert.deepEqual(spec.authentication.credentialPrecedence, resolver.precedence);
    assert.deepEqual(spec.authentication.environmentVariables, resolver.environment);
    assert.deepEqual(spec.authentication.configLocations, resolver.configLocations);
    assert.deepEqual(spec.authentication.configFields, resolver.configFields);
    assert.deepEqual(spec.authentication.modes, resolver.modes);
    assert.deepEqual(spec.authentication.variants, resolver.variants);
    assert.deepEqual(spec.knownGaps.slice(0, behavior.length), behavior);
    assert.ok(spec.apiSurfaces.every((surface) => surface.method && surface.path && surface.fieldsConsumed.length > 0));
    assert.ok(spec.pagination.every((entry) => entry.stopConditions.length > 0 && entry.totalSemantics.length > 40));
    for (const path of [...spec.output.files, ...spec.output.conditionalFiles]) {
      assert.ok(spec.output.artifacts.some((artifact) => artifact.path === path), `${spec.identity.slug}: ${path}`);
    }
  }
  const first = await renderAllIntegrationSpecs();
  const second = await renderAllIntegrationSpecs();
  assert.deepEqual([...first], [...second]);
  for (const [spec] of batch) {
    const entry = PUBLISHED_INTEGRATION_SPECS.find((candidate) => candidate.contract === spec);
    const markdown = [...first.entries()].find(([path]) => path.endsWith(entry.outputPath.replace("specs/", "")))?.[1];
    assert.ok(markdown, entry.outputPath);
    assert.match(markdown, /Rules are evaluated from lowest order number to highest/);
    assert.match(markdown, /Portable derivation/);
    assert.doesNotMatch(markdown, /\b(?:TypeScript|ReadonlyArray|Type\.Object|defineGrcTool|batch4Spec|cli\/extensions)\b/);
  }
});
