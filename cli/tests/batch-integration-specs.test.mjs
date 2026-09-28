import assert from "node:assert/strict";
import test from "node:test";
import {
  evaluateBatchCheckVerdict,
  evaluateObservedFindingStatus,
  materializeBatchCheckVerdict,
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
import { checkContract, collectDefinedGrcTools, evaluateCheckVerdict, evaluateVerdictCriteria } from "../dist/extensions/grc-tools/spec-model.js";
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
    for (const check of spec.checks) {
      if (check.id.startsWith("OKTA-")) continue;
      const emitted = new Set(check.criteria.rules.map((rule) => rule.status));
      for (const status of emitted) {
        const payload = { id: check.id, status, values: [null, 0, 25, 26] };
        const before = JSON.stringify(payload);
        payload.status = preserveRuntimeFindingStatus(spec, check.id, status);
        assert.equal(JSON.stringify(payload), before, `${check.id}: ${status} byte identity`);
        assert.equal(evaluateObservedFindingStatus(spec, check.id, status), status);
      }
      const named = (suffix) => Object.keys(check.derivedFacts).find((name) => name.endsWith(`_${suffix}`));
      const readable = named("required_evidence_readable");
      const complete = named("required_evidence_complete");
      const failure = named("failure_matches");
      if (emitted.has("fail")) {
        assert.equal(evaluateVerdictCriteria(check.criteria, {
          [readable]: true,
          [complete]: false,
          [failure]: true,
        }), "fail", `${check.id}: proven failure wins over incomplete companion evidence`);
      }
    }
  }
  assert.equal(preserveRuntimeFindingStatus(DUO_SPEC, DUO_SPEC.checks[0].id, "Info"), "Info");
});

test("every rule has boundary coverage and null, missing, denied, or unreadable evidence cannot pass", () => {
  const derivations = new Set();
  for (const [spec] of batch) {
    validateDecisionInputs(spec);
    for (const check of spec.checks) {
      if (check.id.startsWith("OKTA-")) {
        const nullFacts = Object.fromEntries(check.evidenceFields.map((name) => [name, null]));
        assert.equal(evaluateCheckVerdict(check, {}), "manual", `${check.id}: missing`);
        assert.notEqual(evaluateCheckVerdict(check, nullFacts), "pass", `${check.id}: null cannot pass`);
        assert.throws(
          () => evaluateCheckVerdict(check, { ...nullFacts, undeclared_okta_input: true }),
          new RegExp(`${check.id} received undeclared decision input`),
        );
        continue;
      }
      const named = (suffix) => Object.keys(check.derivedFacts).find((name) => name.endsWith(`_${suffix}`));
      const readable = named("required_evidence_readable");
      const complete = named("required_evidence_complete");
      const failure = named("failure_matches");
      const warning = named("warning_matches");
      const compliant = named("compliant_matches");
      const emitted = new Set(check.criteria.rules.map((rule) => rule.status));
      assert.ok(readable && complete && failure && warning && compliant, `${check.id}: declared decision facts`);
      assert.equal(evaluateVerdictCriteria(check.criteria, {}), "manual", `${check.id}: missing`);
      assert.equal(evaluateVerdictCriteria(check.criteria, { [readable]: null }), "manual", `${check.id}: null`);
      assert.equal(evaluateVerdictCriteria(check.criteria, { [readable]: false, collection_state: "denied" }), "manual", `${check.id}: denied`);
      assert.equal(evaluateVerdictCriteria(check.criteria, { [readable]: false, collection_state: "unreadable" }), "manual", `${check.id}: unreadable`);
      if (emitted.has("fail")) {
        assert.equal(evaluateVerdictCriteria(check.criteria, { [readable]: true, [complete]: true, [failure]: true }), "fail", `${check.id}: fail boundary`);
      }
      if (emitted.has("warn")) {
        assert.equal(evaluateVerdictCriteria(check.criteria, { [readable]: true, [complete]: false, [warning]: false }), "warn", `${check.id}: partial boundary`);
      }
      if (emitted.has("pass")) {
        assert.equal(evaluateVerdictCriteria(check.criteria, { [readable]: true, [complete]: true, [compliant]: true }), "pass", `${check.id}: pass boundary`);
        assert.notEqual(evaluateVerdictCriteria(check.criteria, { [readable]: false, [complete]: true, [compliant]: true }), "pass", `${check.id}: unreadable cannot pass`);
      }
      const decisionDerivations = Object.entries(check.derivedFacts)
        .filter(([name]) => /_(?:failure|warning|compliant)_matches$/.test(name))
        .map(([, derivation]) => derivation);
      assert.equal(decisionDerivations.length, 3, `${check.id}: branch derivations`);
      for (const derivation of decisionDerivations) {
        assert.match(derivation, /complete counts|complete source cardinalities/i, `${check.id}: complete cardinality`);
        assert.match(derivation, /\breturn (?:pass|fail|warn|manual)\b/i, `${check.id}: substantive derivation`);
        assert.ok(derivation.length > 180, `${check.id}: derivation length`);
        assert.doesNotMatch(derivation, /25-item|slice\(/);
        assert.doesNotMatch(derivation, /\b(?:TypeScript|JavaScript|buildFinding|cli\/|runtime predicates?)\b/i);
      }
      const uniqueDerivation = decisionDerivations.join("\n");
      assert.ok(!derivations.has(uniqueDerivation), `${check.id}: unique derivation`);
      derivations.add(uniqueDerivation);
    }
  }
});

test("Okta executable rules ignore legacy status and use complete counts with ordered precedence", () => {
  const phishingFacts = {
    readable: true,
    complete: true,
    classic_engine: false,
    authenticator_count: 2,
    phishing_resistant_count: 1,
    strong_count: 1,
  };
  assert.equal(materializeBatchCheckVerdict(OKTA_SPEC, "OKTA-AUTH-001", phishingFacts, "Fail"), "Pass");
  assert.equal(materializeBatchCheckVerdict(OKTA_SPEC, "OKTA-AUTH-001", {
    ...phishingFacts,
    phishing_resistant_count: 0,
    strong_count: 0,
  }, "Pass"), "Fail");
  assert.equal(evaluateBatchCheckVerdict(OKTA_SPEC, "OKTA-AUTH-006", {
    readable: true,
    complete: false,
    exposed_value_count: 26,
    over_limit_count: 1,
  }), "fail", "proven violation precedes partial evidence");
  assert.equal(evaluateBatchCheckVerdict(OKTA_SPEC, "OKTA-AUTH-003", {
    readable: true,
    complete: true,
    inventory_count: 26,
    policy_count: 26,
    compliant_policy_count: 25,
    all_policies_compliant: false,
  }), "warn", "the complete 26-policy count, not a 25-item sample, controls the result");
  assert.equal(evaluateBatchCheckVerdict(OKTA_SPEC, "OKTA-AUTH-003", {
    readable: true,
    complete: true,
    inventory_count: 25,
    policy_count: 25,
    compliant_policy_count: 25,
    all_policies_compliant: true,
  }), "pass");
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
      assert.match(markdown, new RegExp(`\\| \\\`${check.id}\\\` \\| 1 \\| (?:fail|manual) \\|`));
      for (const derivation of Object.values(check.derivedFacts)) {
        assert.ok(markdown.includes(derivation), `${check.id}: exact portable derivation rendered`);
      }
    }
  }
});

test("contracts enumerate exact surfaces, permission unlocks, framework mappings, and ServiceNow auth support", () => {
  const emptySurfaceChecks = new Set([
    "BOX-08",
    "OKTA-MON-009",
    "SLACK-ADMIN-04",
    "SLACK-ADMIN-06",
    "SLACK-APP-05",
    "SLACK-APP-07",
    "SLACK-CHAN-04",
    "SLACK-CHAN-05",
    "SLACK-MON-06",
    "ZOOM-ID-07",
    "ZOOM-COLLAB-08",
  ]);
  for (const [spec] of batch) {
    const surfaceIds = new Set(spec.apiSurfaces.map((surface) => surface.id));
    assert.equal(surfaceIds.size, spec.apiSurfaces.length, `${spec.identity.slug}: unique surfaces`);
    for (const check of spec.checks) {
      if (!emptySurfaceChecks.has(check.id)) assert.ok(check.sourceSurfaceIds.length > 0, `${check.id}: source surfaces`);
      for (const surface of check.sourceSurfaceIds) assert.ok(surfaceIds.has(surface), `${check.id}: ${surface}`);
      for (const controlNumber of check.controlNumbers) {
        const control = spec.controls.find((candidate) => candidate.number === controlNumber);
        assert.ok(control, `${check.id}: runtime control`);
        assert.ok(Object.values(control.frameworks).some((values) => values.length > 0), `${check.id}: runtime framework mappings`);
      }
    }
    for (const permission of spec.permissions) {
      assert.ok(["oauth-scope", "iam-action", "role", "license", "plan"].includes(permission.kind), `${permission.id}: permission kind`);
      assert.ok(permission.unlocks.length > 0, `${permission.id}: permission unlocks`);
      for (const surface of permission.unlocks) assert.ok(surfaceIds.has(surface), `${permission.id}: ${surface}`);
    }
  }
  assert.ok(!SERVICENOW_SPEC.authentication.modes.some((mode) => /mtls/i.test(mode)));
  assert.ok(SERVICENOW_SPEC.knownGaps.some((gap) => /reject.*unsupported-mode/i.test(gap)));
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
