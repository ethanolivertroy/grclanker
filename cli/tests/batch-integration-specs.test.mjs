import assert from "node:assert/strict";
import test from "node:test";
import {
  evaluateObservedFindingStatus,
  preserveRuntimeFindingStatus,
} from "../dist/extensions/grc-tools/batch-spec-builder.js";
import { BOX_RUNTIME_BEHAVIOR, BOX_SPEC } from "../dist/extensions/grc-tools/box.spec.js";
import { DUO_RUNTIME_BEHAVIOR, DUO_SPEC } from "../dist/extensions/grc-tools/duo.spec.js";
import { GWS_RUNTIME_BEHAVIOR, GWS_SPEC } from "../dist/extensions/grc-tools/gws.spec.js";
import { OKTA_RUNTIME_BEHAVIOR, OKTA_SPEC } from "../dist/extensions/grc-tools/okta.spec.js";
import { SALESFORCE_RUNTIME_BEHAVIOR, SALESFORCE_SPEC } from "../dist/extensions/grc-tools/salesforce.spec.js";
import { SERVICENOW_RUNTIME_BEHAVIOR, SERVICENOW_SPEC } from "../dist/extensions/grc-tools/servicenow.spec.js";
import { SLACK_RUNTIME_BEHAVIOR, SLACK_SPEC } from "../dist/extensions/grc-tools/slack.spec.js";
import { ZENDESK_RUNTIME_BEHAVIOR, ZENDESK_SPEC } from "../dist/extensions/grc-tools/zendesk.spec.js";
import { ZOOM_RUNTIME_BEHAVIOR, ZOOM_SPEC } from "../dist/extensions/grc-tools/zoom.spec.js";
import { checkContract, collectDefinedGrcTools, evaluateVerdictCriteria } from "../dist/extensions/grc-tools/spec-model.js";
import { PUBLISHED_INTEGRATION_SPECS } from "../dist/extensions/grc-tools/spec-registry.js";
import {
  renderAllIntegrationSpecs,
  validateDecisionInputs,
} from "../scripts/generate-integration-specs.mjs";

const batch = [
  [BOX_SPEC, BOX_RUNTIME_BEHAVIOR],
  [DUO_SPEC, DUO_RUNTIME_BEHAVIOR],
  [GWS_SPEC, GWS_RUNTIME_BEHAVIOR],
  [OKTA_SPEC, OKTA_RUNTIME_BEHAVIOR],
  [SALESFORCE_SPEC, SALESFORCE_RUNTIME_BEHAVIOR],
  [SERVICENOW_SPEC, SERVICENOW_RUNTIME_BEHAVIOR],
  [SLACK_SPEC, SLACK_RUNTIME_BEHAVIOR],
  [ZENDESK_SPEC, ZENDESK_RUNTIME_BEHAVIOR],
  [ZOOM_SPEC, ZOOM_RUNTIME_BEHAVIOR],
];

test("batch 1 publishes exactly the nine requested inspector contracts", () => {
  assert.deepEqual(batch.map(([spec]) => spec.identity.slug).sort(), [
    "box-sec-inspector",
    "duo-sec-inspector",
    "gws-inspector-go",
    "okta-sec-inspector",
    "salesforce-sec-inspector",
    "servicenow-sec-inspector",
    "slack-sec-inspector",
    "zendesk-sec-inspector",
    "zoom-sec-inspector",
  ]);
  assert.ok(!batch.some(([spec]) => spec.identity.slug.includes("operator")));
  assert.ok(!batch.some(([spec]) => spec.identity.slug.startsWith("aws") || spec.identity.slug.startsWith("webex")));
});

test("every batch tool definition carries adjacent non-enumerable metadata without changing enumerable bytes", () => {
  for (const entry of PUBLISHED_INTEGRATION_SPECS.filter((candidate) => batch.some(([spec]) => spec === candidate.contract))) {
    const tools = collectDefinedGrcTools(entry.registerTools);
    assert.deepEqual(tools.map((tool) => tool.definition.name).sort(), entry.contract.tools.map((tool) => tool.name).sort());
    for (const tool of tools) {
      const before = JSON.stringify({ ...tool.definition });
      const descriptorSymbols = Object.getOwnPropertySymbols(tool.definition);
      assert.ok(descriptorSymbols.length > 0, `${tool.definition.name}: contract symbol`);
      const after = JSON.stringify({ ...tool.definition });
      assert.equal(after, before, `${tool.definition.name}: byte-identical enumerable definition`);
    }
  }
});

test("ordered rules preserve runtime statuses byte-for-byte and enforce first-match precedence", () => {
  for (const [spec] of batch) {
    const check = spec.checks[0];
    for (const status of ["fail", "warn", "pass", "manual"]) {
      const payload = { id: check.id, status, values: [null, 0, 25, 26] };
      const before = JSON.stringify(payload);
      payload.status = preserveRuntimeFindingStatus(spec, check.id, status);
      assert.equal(JSON.stringify(payload), before, `${spec.identity.slug}: ${status} byte identity`);
      assert.equal(evaluateObservedFindingStatus(spec, check.id, status), status);
    }
    assert.equal(
      evaluateVerdictCriteria(check.criteria, { decision_status: "fail", incomplete: true }),
      "fail",
      `${check.id}: proven failure wins`,
    );
  }
  assert.equal(preserveRuntimeFindingStatus(OKTA_SPEC, OKTA_SPEC.checks[0].id, "Partial"), "Partial");
  assert.equal(preserveRuntimeFindingStatus(DUO_SPEC, DUO_SPEC.checks[0].id, "Info"), "Info");
});

test("every rule has boundary coverage and null, missing, denied, or unreadable evidence cannot pass", () => {
  const derivations = new Set();
  for (const [spec] of batch) {
    validateDecisionInputs(spec);
    for (const check of spec.checks) {
      assert.equal(evaluateVerdictCriteria(check.criteria, {}), "manual", `${check.id}: missing`);
      assert.equal(evaluateVerdictCriteria(check.criteria, { decision_status: null }), "manual", `${check.id}: null`);
      assert.equal(evaluateVerdictCriteria(check.criteria, { decision_status: "denied" }), "manual", `${check.id}: denied`);
      assert.equal(evaluateVerdictCriteria(check.criteria, { decision_status: "unreadable" }), "manual", `${check.id}: unreadable`);
      assert.equal(evaluateVerdictCriteria(check.criteria, { decision_status: "fail" }), "fail", `${check.id}: fail boundary`);
      assert.equal(evaluateVerdictCriteria(check.criteria, { decision_status: "warn" }), "warn", `${check.id}: warn boundary`);
      assert.equal(evaluateVerdictCriteria(check.criteria, { decision_status: "pass" }), "pass", `${check.id}: pass boundary`);
      assert.match(check.derivedFacts.decision_status, /complete source cardinalities/);
      assert.match(check.derivedFacts.decision_status, /\breturn (?:pass|fail|warn|manual)\b/i, `${check.id}: substantive derivation`);
      assert.ok(check.derivedFacts.decision_status.length > 240, `${check.id}: derivation length`);
      assert.ok(!derivations.has(check.derivedFacts.decision_status), `${check.id}: unique derivation`);
      derivations.add(check.derivedFacts.decision_status);
      assert.doesNotMatch(check.derivedFacts.decision_status, /25-item|slice\(/);
      assert.doesNotMatch(check.derivedFacts.decision_status, /\b(?:TypeScript|JavaScript|buildFinding|cli\/|runtime predicates?)\b/i);
    }
  }
});

test("runtime behavior statements are explicit and generator-visible", () => {
  for (const [spec, behavior] of batch) {
    assert.ok(behavior.length >= 3, `${spec.identity.slug}: behavior statements`);
    for (const statement of behavior) {
      assert.ok(spec.knownGaps.includes(statement), `${spec.identity.slug}: generated behavior statement`);
      assert.ok(statement.length > 80, `${spec.identity.slug}: substantive behavior statement`);
    }
  }
});

test("batch contracts reject undeclared derived inputs", () => {
  const check = BOX_SPEC.checks[0];
  const invalid = {
    ...BOX_SPEC,
    checks: [{
      ...check,
      criteria: {
        ...check.criteria,
        rules: [{ status: "manual", condition: { op: "defined", operand: { kind: "path", path: "undeclared_batch_fact" } } }],
      },
    }],
  };
  assert.throws(
    () => validateDecisionInputs(invalid),
    /BOX-01 rule 1 references undeclared decision input undeclared_batch_fact/,
  );
});

test("generated batch specs are portable and contain no repository-language leakage", async () => {
  const outputs = await renderAllIntegrationSpecs();
  for (const entry of PUBLISHED_INTEGRATION_SPECS.filter((candidate) => batch.some(([spec]) => spec === candidate.contract))) {
    const markdown = [...outputs.entries()].find(([path]) => path.endsWith(entry.outputPath.replace("specs/", "")))?.[1];
    assert.ok(markdown, entry.outputPath);
    assert.match(markdown, /Rules are evaluated from lowest order number to highest/);
    assert.match(markdown, /Portable derivation/);
    assert.doesNotMatch(markdown, /\b(?:TypeScript|ReadonlyArray|Type\.Object|defineGrcTool|prepareArguments|cli\/extensions)\b/);
    for (const check of entry.contract.checks) {
      assert.match(markdown, new RegExp(`\\| \\\`${check.id}\\\` \\| 1 \\| fail \\|`));
      assert.ok(markdown.includes(check.derivedFacts.decision_status), `${check.id}: exact portable derivation rendered`);
    }
  }
});

test("batch export schemas cover every required and conditional bundle path", () => {
  for (const [spec] of batch) {
    const covered = (path) => spec.output.artifacts.some((artifact) => {
      const pattern = artifact.path
        .split(/(\{[^}]+\})/)
        .map((part) => part.startsWith("{") ? "[^/]+" : part.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"))
        .join("");
      return new RegExp(`^${pattern}$`).test(path);
    });
    for (const path of [...spec.output.files, ...spec.output.conditionalFiles]) {
      assert.ok(covered(path), `${spec.identity.slug}: ${path}`);
    }
  }
});

test("all batch check IDs belong to registered owning tools", () => {
  for (const [spec] of batch) {
    const byTool = new Map(spec.tools.map((tool) => [tool.name, new Set(tool.checkIds)]));
    for (const check of spec.checks) {
      assert.ok(byTool.get(check.owningTool)?.has(check.id), `${spec.identity.slug}: ${check.id}`);
      assert.equal(checkContract(spec, check.id).id, check.id);
    }
  }
});
