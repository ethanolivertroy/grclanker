import assert from "node:assert/strict";
import test from "node:test";
import {
  evaluateBatchCheckVerdict,
  materializeBatchCheckVerdict,
} from "../dist/extensions/grc-tools/batch-spec-builder.js";
import {
  BOX_AUTH_RESOLVER,
  DUO_AUTH_RESOLVER,
  GWS_AUTH_RESOLVER,
  OKTA_AUTH_RESOLVER,
  SALESFORCE_AUTH_RESOLVER,
  SERVICENOW_AUTH_RESOLVER,
  SLACK_AUTH_RESOLVER,
  ZENDESK_AUTH_RESOLVER,
  ZOOM_AUTH_RESOLVER,
} from "../dist/extensions/grc-tools/auth-resolver-contracts.js";
import { BOX_RUNTIME_BEHAVIOR, BOX_SPEC } from "../dist/extensions/grc-tools/box.spec.js";
import { DUO_RUNTIME_BEHAVIOR, DUO_SPEC } from "../dist/extensions/grc-tools/duo.spec.js";
import { GWS_RUNTIME_BEHAVIOR, GWS_SPEC } from "../dist/extensions/grc-tools/gws.spec.js";
import { OKTA_RUNTIME_BEHAVIOR, OKTA_SPEC } from "../dist/extensions/grc-tools/okta.spec.js";
import { resolveOktaConfiguration } from "../dist/extensions/grc-tools/okta.js";
import { resolveDuoConfiguration } from "../dist/extensions/grc-tools/duo.js";
import { resolveGwsConfiguration } from "../dist/extensions/grc-tools/gws.js";
import { resolveBoxConfiguration } from "../dist/extensions/grc-tools/box.js";
import { resolveSlackConfiguration } from "../dist/extensions/grc-tools/slack.js";
import { resolveZoomConfiguration } from "../dist/extensions/grc-tools/zoom.js";
import { resolveZendeskConfiguration } from "../dist/extensions/grc-tools/zendesk.js";
import { resolveSalesforceConfiguration } from "../dist/extensions/grc-tools/salesforce.js";
import { resolveServicenowConfiguration } from "../dist/extensions/grc-tools/servicenow.js";
import { SALESFORCE_RUNTIME_BEHAVIOR, SALESFORCE_SPEC } from "../dist/extensions/grc-tools/salesforce.spec.js";
import { SERVICENOW_RUNTIME_BEHAVIOR, SERVICENOW_SPEC } from "../dist/extensions/grc-tools/servicenow.spec.js";
import { SLACK_RUNTIME_BEHAVIOR, SLACK_SPEC } from "../dist/extensions/grc-tools/slack.spec.js";
import { ZENDESK_RUNTIME_BEHAVIOR, ZENDESK_SPEC } from "../dist/extensions/grc-tools/zendesk.spec.js";
import { ZOOM_RUNTIME_BEHAVIOR, ZOOM_SPEC } from "../dist/extensions/grc-tools/zoom.spec.js";
import {
  checkContract,
  collectDefinedGrcTools,
  evaluateCheckVerdict,
  evaluateVerdictCondition,
  evaluateVerdictCriteria,
} from "../dist/extensions/grc-tools/spec-model.js";
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
const usesExecutableEvidenceRules = (check) => /^(?:OKTA|DUO|GWS|BOX|SLACK|ZOOM|ZD|SF|SNOW)-/.test(check.id);
const ABSENT = Symbol("absent");
const DEFINED = Symbol("defined");

function mergeAssignments(left, right) {
  const merged = new Map(left);
  for (const [name, value] of right) {
    if (merged.has(name)) {
      const existing = merged.get(name);
      if (existing === DEFINED && value !== ABSENT) {
        merged.set(name, value);
        continue;
      }
      if (value === DEFINED && existing !== ABSENT) continue;
      if (!Object.is(existing, value)) return undefined;
    }
    merged.set(name, value);
  }
  return merged;
}

function combineAssignments(left, right) {
  const combined = [];
  for (const first of left) {
    for (const second of right) {
      const merged = mergeAssignments(first, second);
      if (merged) combined.push(merged);
    }
  }
  return combined;
}

function operandState(operand, constants) {
  if (operand.kind === "value") return { known: true, value: operand.value };
  if (operand.kind === "path" && Object.hasOwn(constants, operand.path)) {
    return { known: true, value: constants[operand.path] };
  }
  if (operand.kind !== "path") throw new Error(`Unsupported witness operand ${operand.kind}`);
  return { known: false, path: operand.path };
}

function comparisonWitnesses(condition, desired, constants, domains) {
  const left = operandState(condition.left, constants);
  const right = operandState(condition.right, constants);
  const leftValues = left.known
    ? [left.value]
    : [...domains.numbers, ...domains.strings, null, "__not_numeric__"];
  const rightValues = right.known
    ? [right.value]
    : [...domains.numbers, ...domains.strings, null, "__not_numeric__"];
  return leftValues.flatMap((leftValue) => rightValues.flatMap((rightValue) => {
    const assignment = new Map();
    if (!left.known) assignment.set(left.path, leftValue);
    if (!right.known) assignment.set(right.path, rightValue);
    const facts = { ...constants, ...rawFacts(assignment) };
    return evaluateVerdictCondition(condition, facts) === desired ? [assignment] : [];
  }));
}

function ratioWitnesses(condition, desired, constants) {
  const numerator = operandState(condition.numerator, constants);
  const denominator = operandState(condition.denominator, constants);
  const threshold = operandState(condition.threshold, constants);
  if (!threshold.known) throw new Error("Ratio witness thresholds must be constants or literal values");
  const delta = Math.abs(Number(threshold.value)) >= 2 ? 1 : 0.1;
  const scaledTargets = [
    Number(threshold.value) - delta,
    Number(threshold.value),
    Number(threshold.value) + delta,
  ];
  const denominators = denominator.known ? [denominator.value] : [1, 2, 3, 10, 100];
  const candidates = [];
  for (const denominatorValue of denominators) {
    const numeratorValues = numerator.known
      ? [numerator.value]
      : scaledTargets.map((target) => (target / (condition.scale ?? 1)) * Number(denominatorValue));
    for (const numeratorValue of numeratorValues) {
      const assignment = new Map();
      if (!numerator.known) assignment.set(numerator.path, numeratorValue);
      if (!denominator.known) assignment.set(denominator.path, denominatorValue);
      const facts = { ...constants, ...rawFacts(assignment) };
      if (evaluateVerdictCondition(condition, facts) === desired) candidates.push(assignment);
    }
  }
  if (!desired && !numerator.known) candidates.push(new Map([[numerator.path, null]]));
  return candidates;
}

function conditionWitnesses(condition, desired, constants, domains) {
  switch (condition.op) {
    case "always":
      return desired ? [new Map()] : [];
    case "not":
      return conditionWitnesses(condition.condition, !desired, constants, domains);
    case "and":
      if (desired) {
        return condition.conditions.reduce(
          (candidates, child) => combineAssignments(candidates, conditionWitnesses(child, true, constants, domains)),
          [new Map()],
        );
      }
      return condition.conditions.flatMap((child) => conditionWitnesses(child, false, constants, domains));
    case "or":
      if (desired) return condition.conditions.flatMap((child) => conditionWitnesses(child, true, constants, domains));
      return condition.conditions.reduce(
        (candidates, child) => combineAssignments(candidates, conditionWitnesses(child, false, constants, domains)),
        [new Map()],
      );
    case "eq":
    case "ne":
    case "gt":
    case "gte":
    case "lt":
    case "lte":
      return comparisonWitnesses(condition, desired, constants, domains);
    case "ratio":
      return ratioWitnesses(condition, desired, constants);
    case "defined": {
      const operand = operandState(condition.operand, constants);
      if (operand.known) return (operand.value !== undefined) === desired ? [new Map()] : [];
      return [new Map([[operand.path, desired ? DEFINED : ABSENT]])];
    }
    case "matches": {
      const operand = operandState(condition.operand, constants);
      if (operand.known) {
        const actual = new RegExp(condition.pattern, condition.flags).test(String(operand.value));
        return actual === desired ? [new Map()] : [];
      }
      return [new Map([[operand.path, desired ? "all participants" : "__not_matching__"]])];
    }
    default:
      throw new Error(`Unsupported witness condition ${condition.op}`);
  }
}

function rawFacts(assignment) {
  return Object.fromEntries(
    [...assignment]
      .filter(([, value]) => value !== ABSENT)
      .map(([name, value]) => [name, value === DEFINED ? 0 : value]),
  );
}

function witnessDomains(branches, constants) {
  const numbers = new Set([-1, 0, 1]);
  const strings = new Set(["__other__", "all participants"]);
  const add = (value) => {
    if (typeof value === "number" && Number.isFinite(value)) {
      numbers.add(value - 1);
      numbers.add(value);
      numbers.add(value + 1);
    }
    if (typeof value === "string") strings.add(value);
  };
  for (const value of Object.values(constants)) add(value);
  const walk = (condition) => {
    if (condition.left?.kind === "value") add(condition.left.value);
    if (condition.right?.kind === "value") add(condition.right.value);
    if (condition.operand?.kind === "value") add(condition.operand.value);
    if (condition.numerator?.kind === "value") add(condition.numerator.value);
    if (condition.denominator?.kind === "value") add(condition.denominator.value);
    if (condition.threshold?.kind === "value") add(condition.threshold.value);
    for (const child of condition.conditions ?? []) walk(child);
    if (condition.condition) walk(condition.condition);
  };
  for (const branch of branches) walk(branch.condition);
  return {
    numbers: [...numbers].sort((left, right) => left - right),
    strings: [...strings].sort(),
  };
}

function orderedBranchWitness(check, branchIndex) {
  const branches = Object.values(check.derivedFactRules ?? {});
  const domains = witnessDomains(branches, check.criteria.constants);
  const constraints = [
    ...branches.slice(0, branchIndex).map((branch) => [branch.condition, false]),
    [branches[branchIndex].condition, true],
  ];
  let candidates = [new Map()];
  for (const [condition, desired] of constraints) {
    candidates = combineAssignments(
      candidates,
      conditionWitnesses(condition, desired, check.criteria.constants, domains),
    );
  }
  return candidates.map(rawFacts).find((facts) => constraints.every(([condition, desired]) => (
    evaluateVerdictCondition(condition, { ...check.criteria.constants, ...facts }) === desired
  )));
}

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

test("Okta, Duo, GWS, Box, Slack, and Zoom execute declared derived facts with ordered first-match precedence", () => {
  for (const spec of [OKTA_SPEC, DUO_SPEC, GWS_SPEC, BOX_SPEC, SLACK_SPEC, ZOOM_SPEC]) {
    for (const check of spec.checks) {
      assert.ok(Object.keys(check.derivedFactRules ?? {}).length > 0, `${check.id}: executable derived facts`);
      assert.ok(check.criteria.rules.every((entry) => entry.condition.op === "eq"), `${check.id}: outcomes consume derived branches`);
      const branches = Object.values(check.derivedFactRules);
      assert.equal(branches.length, check.criteria.rules.length, `${check.id}: one executable derivation per outcome`);
      for (const [index, rule] of check.criteria.rules.entries()) {
        const witness = orderedBranchWitness(check, index);
        const isFinalSafetyFallback = index === check.criteria.rules.length - 1
          && branches[index].condition.op === "always"
          && rule.status === "manual";
        if (!witness && isFinalSafetyFallback) {
          assert.equal(evaluateCheckVerdict(check, {}), "manual", `${check.id}: safety fallback handles missing evidence`);
          continue;
        }
        assert.ok(witness, `${check.id}: executable evidence reaches ordered branch ${index + 1} (${rule.status})`);
        assert.equal(
          evaluateCheckVerdict(check, witness),
          rule.status,
          `${check.id}: branch ${index + 1} executes at its exact comparison boundary after every earlier branch is false`,
        );
      }
      const nullFacts = Object.fromEntries(check.evidenceFields.map((name) => [name, null]));
      assert.equal(evaluateCheckVerdict(check, {}), "manual", `${check.id}: missing evidence`);
      assert.notEqual(evaluateCheckVerdict(check, nullFacts), "pass", `${check.id}: null evidence`);
      assert.throws(
        () => evaluateCheckVerdict(check, { ...nullFacts, legacy_selected_status: "pass" }),
        new RegExp(`${check.id} received undeclared decision input`),
      );
    }
  }
});

test("Okta, Duo, GWS, Box, Slack, and Zoom decision inputs contain no preselected conclusion tokens", () => {
  const forbidden = /(?:^|_)(?:status|label|verdict|outcome|compliance|compliant|availability|available|enforcement|enforced)(?:_|$)/;
  for (const spec of [OKTA_SPEC, DUO_SPEC, GWS_SPEC, BOX_SPEC, SLACK_SPEC, ZOOM_SPEC]) {
    for (const check of spec.checks) {
      for (const inputName of check.evidenceFields) {
        assert.doesNotMatch(inputName, forbidden, `${check.id}: ${inputName}`);
      }
    }
  }
});

test("Okta Info is an explicit evidence outcome and cannot be selected by a legacy label", () => {
  const emptyOrigins = {
    readable: true,
    complete: true,
    active_origin_count: 0,
    insecure_active_count: 0,
  };
  assert.equal(evaluateBatchCheckVerdict(OKTA_SPEC, "OKTA-INTEG-001", emptyOrigins), "info");
  assert.equal(materializeBatchCheckVerdict(OKTA_SPEC, "OKTA-INTEG-001", emptyOrigins), "Info");
  assert.throws(
    () => evaluateBatchCheckVerdict(OKTA_SPEC, "OKTA-INTEG-001", { ...emptyOrigins, manualLabel: "Manual" }),
    /OKTA-INTEG-001 received undeclared decision input/,
  );
  assert.equal(evaluateBatchCheckVerdict(OKTA_SPEC, "OKTA-INTEG-001", {
    ...emptyOrigins,
    active_origin_count: 1,
  }), "pass");
});

test("all batch rules reject null, missing, denied, or unreadable evidence", () => {
  const derivations = new Set();
  for (const [spec] of batch) {
    validateDecisionInputs(spec);
    for (const check of spec.checks) {
      if (usesExecutableEvidenceRules(check)) {
        const nullFacts = Object.fromEntries(check.evidenceFields.map((name) => [name, null]));
        assert.equal(evaluateCheckVerdict(check, {}), "manual", `${check.id}: missing`);
        assert.notEqual(evaluateCheckVerdict(check, nullFacts), "pass", `${check.id}: null cannot pass`);
        assert.throws(
          () => evaluateCheckVerdict(check, { ...nullFacts, undeclared_evidence_input: true }),
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
  assert.equal(materializeBatchCheckVerdict(OKTA_SPEC, "OKTA-AUTH-001", phishingFacts), "Pass");
  assert.equal(materializeBatchCheckVerdict(OKTA_SPEC, "OKTA-AUTH-001", {
    ...phishingFacts,
    phishing_resistant_count: 0,
    strong_count: 0,
  }), "Fail");
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
    gap_count: 1,
  }), "warn", "the complete 26-policy count, not a 25-item sample, controls the result");
  assert.equal(evaluateBatchCheckVerdict(OKTA_SPEC, "OKTA-AUTH-003", {
    readable: true,
    complete: true,
    inventory_count: 25,
    policy_count: 25,
    gap_count: 0,
  }), "pass");
});

test("Duo executable rules ignore legacy status and use complete evidence with ordered precedence", () => {
  const base = {
    readable: true,
    complete: true,
    user_count: 26,
    known_enrollment_count: 26,
    enrolled_user_count: 26,
    bypass_user_count: 0,
    unenrolled_user_count: 0,
  };
  assert.equal(materializeBatchCheckVerdict(DUO_SPEC, "DUO-AUTH-008", base), "Pass");
  assert.equal(materializeBatchCheckVerdict(DUO_SPEC, "DUO-AUTH-008", {
    ...base,
    bypass_user_count: 1,
  }), "Fail", "mutating primitive evidence changes the verdict");
  assert.equal(evaluateBatchCheckVerdict(DUO_SPEC, "DUO-AUTH-008", {
    ...base,
    complete: false,
    bypass_user_count: 1,
  }), "fail", "a proven bypass violation precedes partial inventory evidence");
  assert.equal(evaluateBatchCheckVerdict(DUO_SPEC, "DUO-AUTH-008", {
    ...base,
    complete: false,
  }), "warn", "a 26-user incomplete inventory cannot pass based on a 25-item rendering sample");
});

test("GWS executable rules ignore legacy status and use complete evidence with ordered precedence", () => {
  const base = {
    readable: true,
    complete: true,
    active_user_count: 100,
    two_step_required_user_count: 98,
  };
  assert.equal(materializeBatchCheckVerdict(GWS_SPEC, "GWS-ID-002", base), "Pass");
  assert.equal(materializeBatchCheckVerdict(GWS_SPEC, "GWS-ID-002", {
    ...base,
    two_step_required_user_count: 84,
  }), "Fail", "mutating primitive directory counts changes the verdict");
  assert.equal(evaluateBatchCheckVerdict(GWS_SPEC, "GWS-MON-002", {
    readable: true,
    complete: false,
    event_count: 26,
    suspicious_login_count: 6,
  }), "fail", "a proven suspicious-login violation precedes partial audit evidence");
  assert.equal(evaluateBatchCheckVerdict(GWS_SPEC, "GWS-MON-002", {
    readable: true,
    complete: false,
    event_count: 26,
    suspicious_login_count: 0,
  }), "warn", "complete source cardinality, not a capped 25-item sample, controls pass");
});

test("Box executable rules ignore legacy status and preserve boundaries, precedence, and complete counts", () => {
  const legacyStatus = "pass";
  const passwordFacts = {
    settings_readable: true,
    unused_setting_count: 0,
    minimum_length: 14,
    required_minimum_length: 14,
    weak_password_prevention: true,
    complexity_rule_count: 2,
  };
  assert.equal(evaluateBatchCheckVerdict(BOX_SPEC, "BOX-21", passwordFacts), "pass");
  assert.equal(evaluateBatchCheckVerdict(BOX_SPEC, "BOX-21", {
    ...passwordFacts,
    minimum_length: 7,
  }), "fail", "mutating password evidence changes the verdict while the legacy status is held constant");
  assert.equal(legacyStatus, "pass");

  const inactivityFacts = {
    users_readable: true,
    events_readable: true,
    users_truncated: false,
    user_count: 100,
    admin_count: 1,
    events_truncated: false,
    active_user_count: 100,
    inactive_user_count: 25,
  };
  assert.equal(evaluateBatchCheckVerdict(BOX_SPEC, "BOX-24", inactivityFacts), "warn");
  assert.equal(evaluateBatchCheckVerdict(BOX_SPEC, "BOX-24", {
    ...inactivityFacts,
    inactive_user_count: 26,
  }), "fail", "the greater-than-25-percent boundary uses the full inventory count");
  assert.equal(evaluateBatchCheckVerdict(BOX_SPEC, "BOX-05", {
    allowlist_readable: true,
    config_readable: true,
    exempt_targets_readable: true,
    complete: false,
    allowlist_entry_count: 26,
    public_domain_count: 1,
    stale_entry_count: 0,
    undated_entry_count: 0,
    exempt_target_count: 0,
    external_status: "limit_collaboration_to_allowlisted_domains",
  }), "fail", "a public-domain violation precedes partial evidence");
  assert.equal(evaluateBatchCheckVerdict(BOX_SPEC, "BOX-17", {
    users_readable: true,
    users_truncated: false,
    user_count: 26,
    admin_count: 1,
    privileged_user_count: 26,
    max_admins: 25,
  }), "warn", "the complete 26-user inventory, not a 25-item evidence sample, controls the result");
});

test("Slack executable rules ignore legacy status and preserve boundaries, precedence, and complete counts", () => {
  const legacyStatus = "pass";
  const uploadFacts = {
    preferences_readable: true,
    setting_value: "disallow_all",
    coverage_complete: true,
  };
  assert.equal(evaluateBatchCheckVerdict(SLACK_SPEC, "SLACK-APP-06", uploadFacts), "pass");
  assert.equal(evaluateBatchCheckVerdict(SLACK_SPEC, "SLACK-APP-06", {
    ...uploadFacts,
    setting_value: "allow_all",
  }), "fail", "mutating the preference evidence changes the verdict while the legacy status is held constant");
  assert.equal(legacyStatus, "pass");
  assert.equal(evaluateBatchCheckVerdict(SLACK_SPEC, "SLACK-MON-02", {
    audit_readable: true,
    audit_complete: true,
    latest_age_days: 1,
  }), "pass");
  assert.equal(evaluateBatchCheckVerdict(SLACK_SPEC, "SLACK-MON-02", {
    audit_readable: true,
    audit_complete: true,
    latest_age_days: 1.01,
  }), "fail", "audit recency fails strictly above one day");
  assert.equal(evaluateBatchCheckVerdict(SLACK_SPEC, "SLACK-ADMIN-01", {
    teams_readable: true,
    admin_inventory_count: 26,
    complete: false,
    excessive_admin_workspace_count: 1,
  }), "fail", "a proven excessive-admin violation precedes partial evidence");
  assert.equal(evaluateBatchCheckVerdict(SLACK_SPEC, "SLACK-ID-01", {
    users_readable: true,
    users_complete: false,
    active_user_count: 26,
    without_mfa_count: 0,
    unknown_mfa_count: 0,
  }), "warn", "the complete 26-user collector state, not a 25-item rendering sample, prevents pass");
});

test("Zoom executable rules ignore legacy status and preserve boundaries, precedence, and complete counts", () => {
  const legacyStatus = "pass";
  const meetingFacts = {
    settings_readable: true,
    setting_present: true,
    setting_value: true,
    lock_value: true,
    relaxing_group_count: 0,
    group_list_state: "ok",
    unreadable_group_setting_count: 0,
    group_list_truncated: false,
  };
  assert.equal(evaluateBatchCheckVerdict(ZOOM_SPEC, "ZOOM-MTG-01", meetingFacts), "pass");
  assert.equal(evaluateBatchCheckVerdict(ZOOM_SPEC, "ZOOM-MTG-01", {
    ...meetingFacts,
    setting_value: false,
  }), "fail", "mutating the meeting setting changes the verdict while the legacy status is held constant");
  assert.equal(legacyStatus, "pass");
  assert.equal(evaluateBatchCheckVerdict(ZOOM_SPEC, "ZOOM-ID-04", {
    roles_readable: true,
    admin_role_count: 1,
    member_read_denied: false,
    complete: true,
    admin_count: 5,
    max_admins: 5,
  }), "pass");
  assert.equal(evaluateBatchCheckVerdict(ZOOM_SPEC, "ZOOM-ID-04", {
    roles_readable: true,
    admin_role_count: 1,
    member_read_denied: false,
    complete: true,
    admin_count: 6,
    max_admins: 5,
  }), "warn", "administrator concentration changes immediately above the configured maximum");
  assert.equal(evaluateBatchCheckVerdict(ZOOM_SPEC, "ZOOM-ID-03", {
    readable: true,
    complete: false,
    count: 26,
    bad_count: 1,
  }), "fail", "a proven unverified domain precedes partial evidence");
  assert.equal(evaluateBatchCheckVerdict(ZOOM_SPEC, "ZOOM-ID-01", {
    readable: true,
    complete: false,
    count: 26,
    bad_count: 0,
    unknown_count: 0,
  }), "warn", "the complete 26-user collector state, not a 25-item evidence sample, prevents pass");
});

test("Zendesk executable rules ignore legacy status and preserve boundaries, precedence, and complete counts", () => {
  const legacyStatus = "pass";
  const sessionFacts = {
    readable: true,
    timeout_present: true,
    severe: false,
    issue_count: 0,
  };
  assert.equal(evaluateBatchCheckVerdict(ZENDESK_SPEC, "ZD-05", sessionFacts), "pass");
  assert.equal(evaluateBatchCheckVerdict(ZENDESK_SPEC, "ZD-05", {
    ...sessionFacts,
    severe: true,
    issue_count: 1,
  }), "fail", "mutating the timeout evidence changes the verdict while the legacy status is held constant");
  assert.equal(legacyStatus, "pass");
  assert.equal(evaluateBatchCheckVerdict(ZENDESK_SPEC, "ZD-10", {
    readable: true,
    dateable: true,
    oldest_age_days: 365,
    required_retention_days: 365,
  }), "pass", "retention passes exactly at the configured threshold");
  assert.equal(evaluateBatchCheckVerdict(ZENDESK_SPEC, "ZD-10", {
    readable: true,
    dateable: true,
    oldest_age_days: 364,
    required_retention_days: 365,
  }), "warn", "retention warns immediately below the configured threshold");
  assert.equal(evaluateBatchCheckVerdict(ZENDESK_SPEC, "ZD-24", {
    any_readable: true,
    complete: false,
    insecure_count: 1,
    unauthenticated_webhook_count: 0,
  }), "fail", "a proven insecure destination precedes partial evidence");
  assert.equal(evaluateBatchCheckVerdict(ZENDESK_SPEC, "ZD-07", {
    team_readable: true,
    admin_count: 26,
    admin_threshold: 25,
    stale_admin_count: 0,
    undated_admin_count: 0,
    complete: true,
  }), "fail", "the complete 26-admin inventory, not a 25-item evidence sample, controls the result");
});

test("Salesforce executable rules ignore legacy status and preserve boundaries, precedence, and complete counts", () => {
  const legacyStatus = "pass";
  const passwordFacts = {
    settings_readable: true,
    required_fields_present: true,
    gap_count: 0,
  };
  assert.equal(evaluateBatchCheckVerdict(SALESFORCE_SPEC, "SF-03", passwordFacts), "pass");
  assert.equal(evaluateBatchCheckVerdict(SALESFORCE_SPEC, "SF-03", {
    ...passwordFacts,
    gap_count: 2,
  }), "fail", "mutating password-policy evidence changes the verdict while the legacy status is held constant");
  assert.equal(legacyStatus, "pass");
  assert.equal(evaluateBatchCheckVerdict(SALESFORCE_SPEC, "SF-02", {
    settings_readable: true,
    required_fields_present: true,
    timeout_minutes: 120,
    force_logout: true,
    lock_to_ip: true,
  }), "pass", "session timeout passes exactly at 120 minutes");
  assert.equal(evaluateBatchCheckVerdict(SALESFORCE_SPEC, "SF-02", {
    settings_readable: true,
    required_fields_present: true,
    timeout_minutes: 121,
    force_logout: true,
    lock_to_ip: true,
  }), "fail", "session timeout fails immediately above 120 minutes");
  assert.equal(evaluateBatchCheckVerdict(SALESFORCE_SPEC, "SF-14", {
    readable: true,
    login_count: 26,
    complete: false,
    severe_anomaly: true,
    warning_anomaly: true,
  }), "warn", "the runtime's partial-window guard precedes sample anomaly classifications");
  assert.equal(evaluateBatchCheckVerdict(SALESFORCE_SPEC, "SF-10", {
    population_sane: true,
    complete: true,
    admin_count: 26,
    max_admins: 25,
    stale_admin_count: 0,
    undated_admin_count: 0,
  }), "fail", "the complete 26-admin inventory, not a 25-item evidence sample, controls the result");
});

test("ServiceNow executable rules ignore legacy status and preserve boundaries, precedence, and complete counts", () => {
  const legacyStatus = "pass";
  const accessFacts = {
    readable: true,
    complete: true,
    user_count: 100,
    admin_assignment_count: 5,
    admin_count: 5,
    max_admins: 5,
    stale_admin_count: 0,
    warning_count: 0,
  };
  assert.equal(materializeBatchCheckVerdict(SERVICENOW_SPEC, "SNOW-04", accessFacts, legacyStatus), "Pass");
  assert.equal(materializeBatchCheckVerdict(SERVICENOW_SPEC, "SNOW-04", {
    ...accessFacts,
    admin_count: 6,
  }, legacyStatus), "Fail", "mutating raw administrator evidence changes the verdict while the legacy status is held constant");
  assert.equal(legacyStatus, "pass");
  assert.equal(evaluateBatchCheckVerdict(SERVICENOW_SPEC, "SNOW-04", {
    ...accessFacts,
    admin_count: 26,
    max_admins: 25,
  }), "fail", "the complete 26-admin collector count, not a capped 25-name rendering sample, controls the result");
  assert.equal(evaluateBatchCheckVerdict(SERVICENOW_SPEC, "SNOW-04", {
    ...accessFacts,
    admin_count: 25,
    max_admins: 25,
  }), "pass", "administrator concentration passes exactly at the configured maximum");
  assert.equal(evaluateBatchCheckVerdict(SERVICENOW_SPEC, "SNOW-04", {
    ...accessFacts,
    complete: false,
    admin_count: 26,
    max_admins: 25,
  }), "fail", "a proven administrator violation precedes partial companion evidence");
  assert.equal(evaluateBatchCheckVerdict(SERVICENOW_SPEC, "SNOW-04", {
    ...accessFacts,
    complete: false,
  }), "warn", "partial evidence cannot pass");
  assert.equal(evaluateBatchCheckVerdict(SERVICENOW_SPEC, "SNOW-04", {
    ...accessFacts,
    readable: false,
  }), "manual", "unreadable evidence cannot pass");
  assert.equal(evaluateBatchCheckVerdict(SERVICENOW_SPEC, "SNOW-08", {
    readable: true,
    complete: false,
    providers_complete: false,
    provider_count: 0,
    expired_certificate_count: 0,
    concern_count: 0,
  }), "manual", "a missing provider in a partial provider inventory remains unknown");
  assert.equal(evaluateBatchCheckVerdict(SERVICENOW_SPEC, "SNOW-08", {
    readable: true,
    complete: false,
    providers_complete: true,
    provider_count: 0,
    expired_certificate_count: 0,
    concern_count: 0,
  }), "fail", "a provider absence proved by complete provider inventories precedes partial companion evidence");
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

test("all-nine authentication environment names exactly match the variables read by each resolver", async () => {
  const trackedEnvironment = (values = {}) => {
    const accessed = new Set();
    const env = new Proxy(values, {
      get(target, property) {
        if (typeof property === "string" && /^[A-Z][A-Z0-9_]+$/.test(property)) accessed.add(property);
        return target[property];
      },
    });
    return { env, accessed };
  };
  const cases = [
    [OKTA_SPEC, OKTA_AUTH_RESOLVER, resolveOktaConfiguration, {
      OKTA_CLIENT_ORGURL: "https://example.okta.com",
      OKTA_CLIENT_TOKEN: "token-value",
    }, [{}, undefined, "/tmp/grclanker-auth-contract", "/tmp/grclanker-auth-contract"]],
    [DUO_SPEC, DUO_AUTH_RESOLVER, resolveDuoConfiguration, {
      DUO_API_HOST: "api-example.duosecurity.com",
      DUO_IKEY: "integration-key",
      DUO_SKEY: "secret-key",
    }, []],
    [GWS_SPEC, GWS_AUTH_RESOLVER, resolveGwsConfiguration, {
      GWS_AUTH_MODE: "access_token",
      GWS_ACCESS_TOKEN: "access-token",
    }, []],
    [BOX_SPEC, BOX_AUTH_RESOLVER, resolveBoxConfiguration, {
      BOX_ACCESS_TOKEN: "access-token",
    }, [{}, undefined, { cwd: "/tmp/grclanker-auth-contract", homeDir: "/tmp/grclanker-auth-contract" }]],
    [SLACK_SPEC, SLACK_AUTH_RESOLVER, resolveSlackConfiguration, {
      SLACK_USER_TOKEN: "xoxp-test-token",
    }, []],
    [ZOOM_SPEC, ZOOM_AUTH_RESOLVER, resolveZoomConfiguration, {
      ZOOM_ACCOUNT_ID: "account-id",
      ZOOM_TOKEN: "access-token",
    }, [], [{
      ZOOM_ACCOUNT_ID: "account-id",
      ZOOM_ACCESS_TOKEN: "access-token",
    }]],
    [ZENDESK_SPEC, ZENDESK_AUTH_RESOLVER, resolveZendeskConfiguration, {
      ZENDESK_SUBDOMAIN: "example",
      ZENDESK_OAUTH_TOKEN: "oauth-token",
    }, [{}, undefined, "/tmp/grclanker-auth-contract"]],
    [SALESFORCE_SPEC, SALESFORCE_AUTH_RESOLVER, resolveSalesforceConfiguration, {
      SF_INSTANCE_URL: "https://example.my.salesforce.com",
      SF_ACCESS_TOKEN: "access-token",
    }, []],
    [SERVICENOW_SPEC, SERVICENOW_AUTH_RESOLVER, resolveServicenowConfiguration, {
      SERVICENOW_INSTANCE: "example",
      SERVICENOW_USERNAME: "audit-user",
      SERVICENOW_PASSWORD: "password-value",
    }, [{}, undefined, { cwd: "/tmp/grclanker-auth-contract", homeDir: "/tmp/grclanker-auth-contract" }]],
  ];
  for (const [spec, resolverContract, resolver, values, extraArguments, fallbackValues = []] of cases) {
    const { env, accessed } = trackedEnvironment(values);
    const args = extraArguments.length > 0 ? [...extraArguments] : [{}];
    args[1] = env;
    await resolver(...args);
    for (const fallback of fallbackValues) {
      const fallbackProbe = trackedEnvironment(fallback);
      const fallbackArgs = extraArguments.length > 0 ? [...extraArguments] : [{}];
      fallbackArgs[1] = fallbackProbe.env;
      await resolver(...fallbackArgs);
      for (const variable of fallbackProbe.accessed) accessed.add(variable);
    }
    const emptyProbe = trackedEnvironment();
    const emptyArgs = extraArguments.length > 0 ? [...extraArguments] : [{}];
    emptyArgs[1] = emptyProbe.env;
    try {
      await resolver(...emptyArgs);
    } catch {
      // Missing credentials are expected. This probe forces fallback aliases
      // behind short-circuiting primary variables to be observed.
    }
    for (const variable of emptyProbe.accessed) accessed.add(variable);
    assert.deepEqual(
      [...accessed].sort(),
      [...resolverContract.environment].sort(),
      `${spec.identity.slug}: no missing or invented resolver environment names`,
    );
    assert.deepEqual(spec.authentication.environmentVariables, resolverContract.environment);
    assert.deepEqual(spec.authentication.configLocations, resolverContract.configLocations);
    assert.deepEqual(spec.authentication.configFields, resolverContract.configFields);
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
