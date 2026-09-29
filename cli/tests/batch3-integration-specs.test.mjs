import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
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
  evaluateBatchRuntimeCheckVerdict,
} from "../dist/extensions/grc-tools/batch-spec-builder.js";
import {
  collectDefinedGrcTools,
  evaluateCheckVerdict,
  evaluateVerdictCondition,
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
  const forbidden = /(?:^|_)(?:status|label|verdict|outcome)(?:_|$)/;
  let inputs = 0;
  for (const [spec] of batch) {
    validateDecisionInputs(spec);
    for (const check of spec.checks) {
      inputs += check.evidenceFields.length;
      assert.equal(evaluateCheckVerdict(check, {}), "manual", `${check.id}: missing`);
      const nullFacts = Object.fromEntries(check.evidenceFields.map((name) => [name, null]));
      assert.notEqual(evaluateCheckVerdict(check, nullFacts), "pass", `${check.id}: all-null facts`);
      assert.throws(
        () => evaluateCheckVerdict(check, { ...nullFacts, legacy_selected_status: "pass" }),
        new RegExp(`${check.id} received undeclared decision input`),
      );
      assert.deepEqual(
        Object.keys(check.evidenceFieldDefinitions).sort(),
        [...check.evidenceFields].sort(),
        `${check.id}: every raw fact has exactly one definition`,
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
    }
  }
  assert.equal(inputs, 669);
});

test("batch 3 completeness names exact datasets and all six collection failure modes", () => {
  const expectedModes = ["denied", "error", "missing-required-field", "not-collected", "not-configured", "truncated"];
  const parentTruncationNoChange = new Set([
    "TENABLE-07.sc-scanners",
    "TENABLE-11.groups",
    "TENABLE-11.permissions",
    "TENABLE-19.asset-export-jobs",
    "TENABLE-19.vuln-export-jobs",
  ]);
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
        assert.match(contract.semantics, new RegExp(name));
        assert.match(contract.semantics, /Finding previews and exported samples never establish source cardinality\./);
        assert.doesNotMatch(contract.semantics, /\bevidence_complete\b|For [A-Z0-9-]+, For /);
        for (const source of contract.sources) {
          sources += 1;
          assert.ok(surfaceIds.has(source.surfaceId), `${check.id}.${name}.${source.surfaceId}`);
          const sourceKey = `${check.id}.${source.surfaceId}`;
          const expectedFalseWhen = parentTruncationNoChange.has(sourceKey)
            ? expectedModes.filter((mode) => mode !== "truncated")
            : expectedModes;
          assert.deepEqual([...source.falseWhen].sort(), expectedFalseWhen, sourceKey);
          assert.match(contract.semantics, new RegExp(source.surfaceId));
          for (const mode of expectedModes) {
            assert.match(contract.semantics, new RegExp(`\\b${mode}\\b`), `${check.id}.${name}.${source.surfaceId}.${mode}`);
          }
        }
      }
    }
  }
  assert.equal(contracts, 104);
  assert.ok(sources > contracts);
});

test("batch 3 rules are ordered, derived exactly once, and retain explicit fail and review branches", () => {
  let checks = 0;
  let failAndWarn = 0;
  for (const [spec] of batch) {
    for (const check of spec.checks) {
      assert.equal(check.criteria.rules.length, Object.keys(check.derivedFactRules).length, `${check.id}: one derivation per branch`);
      assert.ok(check.criteria.rules.every((rule) => rule.condition.op === "eq"), `${check.id}: criteria execute ordered derived facts`);
      assert.equal(check.criteria.rules.at(-1)?.status, "manual", `${check.id}: explicit manual fallback`);
      const failIndex = check.criteria.rules.findIndex((rule) => rule.status === "fail");
      const warnIndex = check.criteria.rules.findIndex((rule) => rule.status === "warn");
      if (failIndex >= 0 && warnIndex >= 0) {
        failAndWarn += 1;
      }
      checks += 1;
    }
  }
  assert.equal(checks, 105);
  assert.ok(failAndWarn >= 80);
});

test("all numeric constants are finite and every executable numeric boundary is referenced by a rule", () => {
  let constants = 0;
  let executableBoundaries = 0;
  const collectPaths = (value, paths = new Set()) => {
    if (value === null || typeof value !== "object") return paths;
    if (value.kind === "path") paths.add(value.path);
    for (const child of Object.values(value)) collectPaths(child, paths);
    return paths;
  };
  for (const [spec] of batch) {
    for (const check of spec.checks) {
      const rulePaths = collectPaths(check.derivedFactRules);
      for (const [name, threshold] of Object.entries(check.criteria.constants)) {
        if (typeof threshold !== "number") continue;
        assert.ok(Number.isFinite(threshold), `${check.id}.${name}: finite`);
        if (rulePaths.has(name)) executableBoundaries += 1;
        constants += 1;
      }
    }
  }
  assert.equal(constants, 87);
  assert.equal(executableBoundaries, 87);
});

test("hidden threshold bands execute below, equal, and above against primitive facts", () => {
  const byId = new Map(batch.flatMap(([spec]) => spec.checks.map((check) => [check.id, check])));
  const verdict = (id, facts) => evaluateCheckVerdict(byId.get(id), facts);

  const cs14 = { cs_14_host_and_group_reads_succeeded: true, cs_14_host_and_group_lists_complete: true, cs_14_host_count: 100, cs_14_host_group_count: 1 };
  assert.deepEqual([79, 80, 81, 94, 95, 96].map((count) => verdict("CS-14", { ...cs14, cs_14_assigned_host_count: count })), ["fail", "warn", "warn", "warn", "pass", "pass"]);

  const cs22 = { cs_22_alert_read_succeeded: true, cs_22_alert_list_complete: true, cs_22_dated_alert_count: 100, cs_22_undated_alert_count: 0 };
  assert.deepEqual([79, 80, 81, 94, 95, 96].map((count) => verdict("CS-22", { ...cs22, cs_22_sla_compliant_alert_count: count })), ["fail", "warn", "warn", "warn", "pass", "pass"]);

  const cs23 = { cs_23_contained_host_read_succeeded: true, cs_23_contained_host_list_complete: true, cs_23_contained_host_count: 1, cs_23_undated_contained_host_count: 0 };
  const cs23Check = byId.get("CS-23");
  const overSla = Object.values(cs23Check.derivedFactRules).find((rule) =>
    rule.condition.op === "gt"
    && rule.condition.right.kind === "path"
    && rule.condition.right.path === "containment_sla_hours");
  assert.ok(overSla);
  assert.deepEqual([71, 72, 73].map((hours) => evaluateVerdictCondition(overSla.condition, {
    ...cs23Check.criteria.constants,
    ...cs23,
    cs_23_max_containment_age_hours: hours,
  })), [false, false, true]);
  assert.deepEqual([71, 72, 73].map((hours) => verdict("CS-23", { ...cs23, cs_23_max_containment_age_hours: hours })), ["warn", "warn", "warn"], "inherited parent keeps every active containment at warn");

  const tenable03 = { tenable_03_asset_and_network_reads_succeeded: true, tenable_03_asset_export_and_networks_complete: true, tenable_03_exported_asset_count: 100, tenable_03_expected_asset_count: 100 };
  assert.deepEqual([94, 95, 96].map((count) => verdict("TENABLE-03", { ...tenable03, tenable_03_fresh_asset_count: count })), ["fail", "pass", "pass"]);
  const tenable05 = { tenable_05_agent_reads_succeeded: true, tenable_05_agent_and_asset_sources_complete: true, tenable_05_agent_count: 100, tenable_05_agent_review_count: 0 };
  assert.deepEqual([9, 10, 11].map((count) => verdict("TENABLE-05", { ...tenable05, tenable_05_unhealthy_agent_count: count })), ["pass", "pass", "fail"]);
  const tenable06 = { tenable_06_agent_group_reads_succeeded: true, tenable_06_agent_and_group_lists_complete: true, tenable_06_agent_count: 100, tenable_06_agent_group_count: 1 };
  assert.deepEqual([9, 10, 11].map((count) => verdict("TENABLE-06", { ...tenable06, tenable_06_ungrouped_agent_count: count })), ["warn", "warn", "fail"]);

  const qualys10 = { qualys_c10_host_and_detection_reads_succeeded: true, qualys_c10_host_and_detection_lists_complete: true, qualys_c10_detection_list_complete: true, qualys_c10_sla_scoped_detection_count: 100, qualys_c10_dated_detection_count: 100, qualys_c10_undated_detection_count: 0 };
  assert.deepEqual([79, 80, 81, 94, 95, 96].map((count) => verdict("QUALYS-C10", { ...qualys10, qualys_c10_on_sla_detection_count: count })), ["fail", "warn", "warn", "warn", "pass", "pass"]);

  const kb04 = { knowbe4_04_user_and_enrollment_reads_succeeded: true, knowbe4_04_user_and_enrollment_lists_complete: true, knowbe4_04_new_user_count: 100 };
  assert.deepEqual([4, 5, 6].map((percent) => verdict("KNOWBE4-04", { ...kb04, knowbe4_04_late_or_missing_enrollment_count: percent, knowbe4_04_late_enrollment_percent: percent })), ["warn", "warn", "fail"]);
  const kb07 = { knowbe4_07_test_reads_succeeded: true, knowbe4_07_test_and_recipient_lists_complete: true, knowbe4_07_security_tests_compared: 2 };
  assert.deepEqual([4, 5, 6].map((delta) => verdict("KNOWBE4-07", { ...kb07, knowbe4_07_failure_rate_delta_points: delta })), ["warn", "warn", "fail"]);
  const kb10 = { knowbe4_10_remediation_reads_succeeded: true, knowbe4_10_recipient_and_enrollment_reads_complete: true, knowbe4_10_failed_user_count: 100, knowbe4_10_no_remediation_due: false };
  assert.deepEqual([49, 50, 51, 89, 90, 91].map((percent) => verdict("KNOWBE4-10", { ...kb10, knowbe4_10_remediated_percent: percent })), ["fail", "warn", "warn", "warn", "pass", "pass"]);
  const kb19 = { knowbe4_19_security_test_reads_succeeded: true, knowbe4_19_security_test_and_recipient_lists_complete: true, knowbe4_19_delivered_recipient_count: 100, knowbe4_19_configured_minimum_percent: 50, knowbe4_19_configured_fail_percent: 25 };
  assert.deepEqual([24, 25, 26, 49, 50, 51].map((percent) => verdict("KNOWBE4-19", { ...kb19, knowbe4_19_report_rate_percent: percent })), ["fail", "warn", "warn", "warn", "pass", "pass"]);
});

test("all 87 runtime-observable numeric constants and 13 set or pattern branches have executable metadata boundaries", () => {
  const conditionNodes = (condition) => {
    const nodes = [condition];
    if (condition.op === "and" || condition.op === "or") {
      for (const child of condition.conditions) nodes.push(...conditionNodes(child));
    } else if (condition.op === "not") {
      nodes.push(...conditionNodes(condition.condition));
    }
    return nodes;
  };
  const path = (operand) => operand?.kind === "path" ? operand.path : undefined;
  const baseFacts = (check) => {
    const facts = {};
    for (const name of check.evidenceFields) {
      const definition = check.evidenceFieldDefinitions[name];
      if (name.endsWith("_configured_value")) facts[name] = null;
      else if (/Type\/domain: [^.]*boolean/.test(definition)) facts[name] = !name.endsWith("_no_remediation_due");
      else if (/Type\/domain: [^.]*array/.test(definition)) facts[name] = [];
      else if (/Type\/domain: [^.]*number/.test(definition)) {
        facts[name] = name.endsWith("_population_count") ? 1
          : /(?:failure|violation|review|undated|missing|without|unreadable|external|shared)/.test(name)
          ? 0
          : /(?:percent|pct|ratio|coverage|compliant)/.test(name) ? 100 : 1;
      } else {
        facts[name] = "observed";
      }
    }
    for (const rule of Object.values(check.derivedFactRules)) {
      for (const node of conditionNodes(rule.condition)) {
        if (!["gt", "gte", "lt", "lte"].includes(node.op)) continue;
        const left = path(node.left);
        const right = path(node.right);
        if (!left || !right || typeof check.criteria.constants[right] !== "number") continue;
        const boundary = check.criteria.constants[right];
        facts[left] = node.op === "gt" || node.op === "lt" ? boundary : node.op === "gte" ? boundary - 1 : boundary + 1;
      }
    }
    if (check.id === "TENABLE-05") {
      facts.tenable_05_agent_count = 100;
      facts.tenable_05_unhealthy_agent_count = 0;
    }
    return facts;
  };
  let numericBranches = 0;
  let collectionBranches = 0;
  for (const [spec] of batch) {
    for (const check of spec.checks) {
      const derived = Object.values(check.derivedFactRules);
      const baseline = baseFacts(check);
      for (const [constant, value] of Object.entries(check.criteria.constants)) {
        const nodes = derived.flatMap((rule) => conditionNodes(rule.condition));
        if (typeof value === "number") {
          const node = nodes.find((candidate) =>
            ["gt", "gte", "lt", "lte"].includes(candidate.op)
              ? path(candidate.left) === constant || path(candidate.right) === constant
              : candidate.op === "ratio" && path(candidate.threshold) === constant);
          assert.ok(node, `${check.id}.${constant}: executable comparison`);
          const observed = node.op === "ratio"
            ? path(node.numerator)
            : path(node.left) === constant ? path(node.right) : path(node.left);
          assert.ok(observed && check.evidenceFields.includes(observed), `${check.id}.${constant}: raw observed fact`);
          const delta = Number.isInteger(value) ? 1 : 0.01;
          const denominator = node.op === "ratio" ? 100 : 1;
          const scale = node.op === "ratio" ? node.scale ?? 1 : 1;
          if (node.op === "ratio") baseline[path(node.denominator)] = denominator;
          const observedValues = [value - delta, value, value + delta]
            .map((boundaryValue) => boundaryValue * denominator / scale);
          const matches = observedValues.map((observedValue) =>
            evaluateVerdictCondition(node, { ...check.criteria.constants, ...baseline, [observed]: observedValue }));
          assert.ok(new Set(matches).size > 1, `${check.id}.${constant}: below/equal/above branch transition`);
          numericBranches += 1;
          continue;
        }
        if (!["string", "object"].includes(typeof value)) continue;
        const node = nodes.find((candidate) =>
          ["intersects", "matchesAny"].includes(candidate.op)
          && [path(candidate.left), path(candidate.right), path(candidate.patterns)].includes(constant));
        if (!node) continue;
        const observed = node.op === "intersects"
          ? path(path(node.left) === constant ? node.right : node.left)
          : path(node.candidates);
        assert.ok(observed && check.evidenceFields.includes(observed), `${check.id}.${constant}: raw collection fact`);
        const match = constant === "shared_account_pattern"
          ? "shared-admin"
          : constant === "sensitive_exclusion_path_patterns"
            ? "C:\\Windows"
            : Array.isArray(value) ? value[0] : value;
        const missFacts = { ...baseline, [observed]: ["definitely-not-a-match"] };
        const matchFacts = { ...baseline, [observed]: [match] };
        assert.notEqual(
          evaluateBatchRuntimeCheckVerdict(spec, check.id, missFacts),
          evaluateBatchRuntimeCheckVerdict(spec, check.id, matchFacts),
          `${check.id}.${constant}: set/pattern outcome transition`,
        );
        collectionBranches += 1;
      }
    }
  }
  assert.equal(numericBranches, 87);
  assert.equal(collectionBranches, 13);
});

test("batch 3 runtimes consume spec verdicts without legacy status bridges", async () => {
  const modules = ["crowdstrike", "knowbe4", "qualys", "tenable", "veracode"];
  for (const moduleName of modules) {
    const source = await readFile(new URL(`../extensions/grc-tools/${moduleName}.ts`, import.meta.url), "utf8");
    assert.match(source, /evaluateBatchRuntimeCheckVerdict/);
    assert.doesNotMatch(source, /_legacyStatus/);
    assert.doesNotMatch(source, /violation_count\s*:\s*status\s*===/);
    assert.doesNotMatch(source, /review_count\s*:\s*status\s*===/);
    assert.doesNotMatch(source, /legacy_selected_(?:status|verdict|label)|preselected_(?:status|verdict|label)/i);
  }
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
  assert.equal(numericConstants, 87);

  const first = await renderAllIntegrationSpecs();
  const second = await renderAllIntegrationSpecs();
  assert.deepEqual([...first], [...second]);
  for (const [spec] of batch) {
    const entry = PUBLISHED_INTEGRATION_SPECS.find((candidate) => candidate.contract === spec);
    const suffix = entry.outputPath.replace("specs/", "");
    const markdown = [...first.entries()].find(([path]) => path.endsWith(suffix))?.[1];
    assert.ok(markdown, entry.outputPath);
    assert.match(markdown, /Rules are evaluated from lowest order number to highest/);
    assert.match(markdown, /Decision predicate/);
    for (const check of spec.checks) {
      for (const [name, value] of Object.entries(check.criteria.constants)) {
        if (typeof value !== "number") continue;
        assert.match(markdown, new RegExp(`\\b${name}\\b[^\\n]*${String(value).replace(".", "\\.")}`));
      }
    }
    assert.doesNotMatch(
      markdown,
      /\b(?:TypeScript|ReadonlyArray|Type\.Object|defineGrcTool|prepareArguments|evaluateBatchRuntimeCheckVerdict|batch[23](?:Checks|Completeness)|cli\/extensions)\b/,
    );
    assert.doesNotMatch(markdown, /all explicitly named source datasets|check-specific source and precedence semantics|name-derived|generic decision/i);
    assert.doesNotMatch(markdown, /\bevidence_complete\b|For [A-Z0-9-]+, For |shipped parent|without changing bytes|migration/i);
    for (const check of spec.checks) {
      for (const example of check.criteria.examples) {
        assert.match(example.input, new RegExp(`^${check.id} ${check.title.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}:`), `${check.id}.${example.kind}: concrete example`);
        assert.equal(example.expected, check.criteria.rules.find((rule) => rule.status === example.expected)?.status ?? example.expected);
      }
      const portableText = JSON.stringify(check);
      assert.doesNotMatch(portableText, /generic fact phrase|compatibility|legacy|inherited verdict|report-only|runtime candidate/i);
    }
  }
});

test("Qualys metadata matches every concrete VM/PC v2 and QPS request parameter", () => {
  const byId = new Map(QUALYS_SPEC.apiSurfaces.map((surface) => [surface.id, surface]));
  const expectedVmParameters = {
    "scheduled-scans": ["action", "show_notifications"],
    scans: ["action", "launched_after_datetime", "show_ags", "show_op"],
    hosts: ["action", "details", "show_tags", "truncation_limit"],
    "option-profiles": ["action"],
    "excluded-ips": ["action"],
    "asset-groups": ["action", "show_attributes", "truncation_limit"],
    appliances: ["action", "output_mode"],
    "auth-records": ["action"],
    "compliance-policies": ["action", "details"],
    detections: ["action", "status", "severities", "show_qds", "truncation_limit", "output_format"],
    "knowledge-base": ["action", "details", "ids"],
    "scheduled-reports": ["action", "is_active"],
    reports: ["action"],
    "activity-log": ["action", "since_datetime", "truncation_limit"],
    "user-list": [],
  };
  for (const [id, names] of Object.entries(expectedVmParameters)) {
    const surface = byId.get(id);
    assert.ok(surface, id);
    assert.equal(surface.method, "GET", `${id}: VM/PC and Administration reads use GET`);
    assert.ok(surface.request.headers.includes("X-Requested-With: grclanker"), id);
    assert.deepEqual(surface.request.parameters.map((entry) => entry.name), names, id);
  }
  assert.equal(byId.get("detections").request.parameters.find((entry) => entry.name === "status").value, "Active,New,Re-Opened");

  const qpsIds = ["connectors", "cloud-agents", "tags", "users", "was-webapps", "was-scans", "was-scan-history", "was-auth-records", "was-schedules"];
  for (const id of qpsIds) {
    const surface = byId.get(id);
    assert.equal(surface.method, "POST", `${id}: every QPS search is POST`);
    assert.deepEqual(
      surface.request.parameters.slice(0, 2).map((entry) => entry.name),
      ["ServiceRequest.preferences.limitResults", "ServiceRequest.preferences.startFromId"],
      `${id}: exact QPS pagination envelope`,
    );
  }
});
