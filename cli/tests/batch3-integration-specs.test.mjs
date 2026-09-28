import assert from "node:assert/strict";
import test from "node:test";

import {
  CROWDSTRIKE_AUTH_RESOLVER,
  KNOWBE4_AUTH_RESOLVER,
  QUALYS_AUTH_RESOLVER,
  TENABLE_AUTH_RESOLVER,
  VERACODE_AUTH_RESOLVER,
} from "../dist/extensions/grc-tools/auth-resolver-contracts.js";
import { CROWDSTRIKE_RUNTIME_BEHAVIOR, CROWDSTRIKE_SPEC } from "../dist/extensions/grc-tools/crowdstrike.spec.js";
import { KNOWBE4_RUNTIME_BEHAVIOR, KNOWBE4_SPEC } from "../dist/extensions/grc-tools/knowbe4.spec.js";
import { QUALYS_RUNTIME_BEHAVIOR, QUALYS_SPEC } from "../dist/extensions/grc-tools/qualys.spec.js";
import { PUBLISHED_INTEGRATION_SPECS } from "../dist/extensions/grc-tools/spec-registry.js";
import {
  collectDefinedGrcTools,
  evaluateCheckVerdict,
} from "../dist/extensions/grc-tools/spec-model.js";
import { TENABLE_RUNTIME_BEHAVIOR, TENABLE_SPEC } from "../dist/extensions/grc-tools/tenable.spec.js";
import { VERACODE_RUNTIME_BEHAVIOR, VERACODE_SPEC } from "../dist/extensions/grc-tools/veracode.spec.js";
import {
  renderAllIntegrationSpecs,
  validateDecisionInputs,
} from "../scripts/generate-integration-specs.mjs";

const batch = [
  [CROWDSTRIKE_SPEC, CROWDSTRIKE_RUNTIME_BEHAVIOR, CROWDSTRIKE_AUTH_RESOLVER],
  [KNOWBE4_SPEC, KNOWBE4_RUNTIME_BEHAVIOR, KNOWBE4_AUTH_RESOLVER],
  [QUALYS_SPEC, QUALYS_RUNTIME_BEHAVIOR, QUALYS_AUTH_RESOLVER],
  [TENABLE_SPEC, TENABLE_RUNTIME_BEHAVIOR, TENABLE_AUTH_RESOLVER],
  [VERACODE_SPEC, VERACODE_RUNTIME_BEHAVIOR, VERACODE_AUTH_RESOLVER],
];

test("batch 3 publishes exactly the five requested adjacent contracts", () => {
  assert.deepEqual(batch.map(([spec]) => spec.identity.slug).sort(), [
    "crowdstrike-sec-inspector",
    "knowbe4-sec-inspector",
    "qualys-sec-inspector",
    "tenable-sec-inspector",
    "veracode-sec-inspector",
  ]);
  assert.equal(batch.reduce((total, [spec]) => total + spec.checks.length, 0), 105);
});

test("batch 3 tools carry non-enumerable metadata and registry ownership is exact", () => {
  for (const [spec] of batch) {
    const published = PUBLISHED_INTEGRATION_SPECS.find((entry) => entry.contract === spec);
    assert.ok(published, `${spec.identity.slug}: published`);
    const tools = collectDefinedGrcTools(published.registerTools);
    assert.deepEqual(tools.map((tool) => tool.definition.name).sort(), spec.tools.map((tool) => tool.name).sort());
    for (const tool of tools) {
      const enumerable = JSON.stringify({ ...tool.definition });
      assert.ok(Object.getOwnPropertySymbols(tool.definition).length > 0, `${tool.definition.name}: metadata symbol`);
      assert.equal(JSON.stringify({ ...tool.definition }), enumerable, `${tool.definition.name}: enumerable bytes`);
    }
  }
});

test("batch 3 portable facts reject undeclared, missing, null, and sampled-pass inputs", () => {
  const forbidden = /(?:^|_)(?:status|label|verdict|outcome|compliance|compliant)(?:_|$)/;
  let inputs = 0;
  for (const [spec] of batch) {
    validateDecisionInputs(spec);
    for (const check of spec.checks) {
      inputs += check.evidenceFields.length;
      assert.equal(evaluateCheckVerdict(check, {}), "manual", `${check.id}: missing`);
      assert.throws(
        () => evaluateCheckVerdict(check, { legacy_selected_status: "pass" }),
        new RegExp(`${check.id} received undeclared decision input`),
      );
      assert.equal(Object.keys(check.derivedFactRules ?? {}).length, check.criteria.rules.length, `${check.id}: exact branch derivation`);
      assert.ok(check.criteria.rules.every((rule) => rule.condition.op === "eq"), `${check.id}: ordered derived facts`);
      for (const name of check.evidenceFields) {
        assert.doesNotMatch(name, forbidden, `${check.id}.${name}`);
        const description = check.evidenceFieldDefinitions[name];
        assert.ok(description.length >= 80, `${check.id}.${name}: portable source, domain, completeness, and null semantics`);
        assert.match(description, /Semantic owner:/);
        assert.match(description, /Type\/domain:/);
        assert.match(description, /Source\/owner:/);
        assert.match(description, /Completeness\/sample semantics:/);
        assert.match(description, /Null\/missing meaning:/);
      }
      if (check.evidenceFields.includes("evidence_complete")) {
        const complete = {
          evidence_readable: true,
          evidence_complete: true,
          inventory_count: 2,
          violation_count: 0,
          review_count: 0,
        };
        assert.equal(evaluateCheckVerdict(check, complete), "pass", `${check.id}: complete population`);
        assert.equal(evaluateCheckVerdict(check, { ...complete, evidence_complete: false }), "warn", `${check.id}: sample cannot pass`);
        assert.equal(evaluateCheckVerdict(check, { ...complete, evidence_complete: false, violation_count: 1 }), "fail", `${check.id}: proved violation precedence`);
        assert.equal(evaluateCheckVerdict(check, { ...complete, evidence_readable: false }), "manual", `${check.id}: denied`);
      }
    }
  }
  assert.equal(inputs, 520);
});

test("batch 3 completeness names exact datasets and all six collection failure modes", () => {
  const expectedModes = ["denied", "error", "missing-required-field", "not-collected", "not-configured", "truncated"];
  let contracts = 0;
  let sources = 0;
  for (const [spec] of batch) {
    const surfaceIds = new Set(spec.apiSurfaces.map((surface) => surface.id));
    for (const check of spec.checks) {
      const completeFields = check.evidenceFields.filter((name) => name.includes("complete")).sort();
      assert.deepEqual(Object.keys(check.completeness ?? {}).sort(), completeFields, `${check.id}: completeness coverage`);
      for (const [name, contract] of Object.entries(check.completeness ?? {})) {
        contracts += 1;
        assert.ok(contract.semantics.length >= 80, `${check.id}.${name}: exact semantics`);
        assert.deepEqual(new Set(contract.sources.map((source) => source.surfaceId)).size, contract.sources.length);
        for (const source of contract.sources) {
          sources += 1;
          assert.ok(surfaceIds.has(source.surfaceId), `${check.id}.${name}.${source.surfaceId}`);
          assert.deepEqual([...source.falseWhen].sort(), expectedModes);
        }
      }
    }
  }
  assert.equal(contracts, 104);
  assert.ok(sources > contracts);
});

test("batch 3 constants, authentication, permissions, pagination, and output contracts render", async () => {
  let numericConstants = 0;
  for (const [spec, behavior, resolver] of batch) {
    numericConstants += spec.checks.reduce(
      (total, check) => total + Object.values(check.criteria.constants).filter((value) => typeof value === "number").length,
      0,
    );
    assert.deepEqual(spec.authentication.credentialPrecedence, resolver.precedence);
    assert.deepEqual(spec.authentication.environmentVariables, resolver.environment);
    assert.deepEqual(spec.authentication.configLocations, resolver.configLocations);
    assert.deepEqual(spec.authentication.configFields, resolver.configFields);
    assert.deepEqual(spec.authentication.modes, resolver.modes);
    assert.deepEqual(spec.authentication.variants, resolver.variants);
    assert.deepEqual(spec.knownGaps.slice(0, behavior.length), behavior);
    assert.ok(spec.permissions.length > 0);
    assert.ok(spec.pagination.length > 0);
    for (const path of [...spec.output.files, ...spec.output.conditionalFiles]) {
      assert.ok(spec.output.artifacts.some((artifact) => artifact.path === path), `${spec.identity.slug}: ${path}`);
    }
  }
  assert.equal(numericConstants, 68);

  const first = await renderAllIntegrationSpecs();
  const second = await renderAllIntegrationSpecs();
  assert.deepEqual([...first], [...second]);
  for (const [spec] of batch) {
    const entry = PUBLISHED_INTEGRATION_SPECS.find((candidate) => candidate.contract === spec);
    const suffix = entry.outputPath.replace("specs/", "");
    const markdown = [...first.entries()].find(([path]) => path.endsWith(suffix))?.[1];
    assert.ok(markdown, entry.outputPath);
    assert.match(markdown, /Rules are evaluated from lowest order number to highest/);
    assert.match(markdown, /Portable derivation/);
    assert.doesNotMatch(markdown, /\b(?:TypeScript|ReadonlyArray|Type\.Object|defineGrcTool|prepareArguments|cli\/extensions)\b/);
  }
});
