import assert from "node:assert/strict";

import { BATCH3_RUNTIME_FACTS } from "../../dist/extensions/grc-tools/batch3-spec-helpers.js";
import { evaluateVerdictCondition } from "../../dist/extensions/grc-tools/spec-model.js";

function conditionNodes(condition) {
  const nodes = [condition];
  if (condition.op === "and" || condition.op === "or") {
    for (const child of condition.conditions) nodes.push(...conditionNodes(child));
  } else if (condition.op === "not") {
    nodes.push(...conditionNodes(condition.condition));
  }
  return nodes;
}

function pathOf(operand) {
  return operand?.kind === "path" ? operand.path : undefined;
}

function literalOf(operand) {
  return operand?.kind === "literal" ? operand.value : undefined;
}

function valueOf(operand, constants, facts) {
  const path = pathOf(operand);
  if (path !== undefined) return Object.hasOwn(constants, path) ? constants[path] : facts[path];
  return literalOf(operand);
}

function setOperand(operand, value, constants, facts) {
  const path = pathOf(operand);
  if (path !== undefined && !Object.hasOwn(constants, path)) facts[path] = value;
}

function comparisonValues(operator, boundary) {
  const delta = Number.isInteger(boundary) ? 1 : 0.01;
  return [boundary - delta, boundary, boundary + delta].map((value) => {
    switch (operator) {
      case "gt":
        return { value, matches: value > boundary };
      case "gte":
        return { value, matches: value >= boundary };
      case "lt":
        return { value, matches: value < boundary };
      case "lte":
        return { value, matches: value <= boundary };
      default:
        throw new Error(`Unsupported numeric operator ${operator}`);
    }
  });
}

function satisfy(condition, constants, facts, desired = true) {
  switch (condition.op) {
    case "always":
      return;
    case "defined": {
      const path = pathOf(condition.value);
      if (path !== undefined && !Object.hasOwn(constants, path)) facts[path] = desired ? (facts[path] ?? 1) : null;
      return;
    }
    case "not":
      satisfy(condition.condition, constants, facts, !desired);
      return;
    case "and":
      if (desired) {
        for (const child of condition.conditions) satisfy(child, constants, facts, true);
      } else {
        satisfy(condition.conditions[0], constants, facts, false);
      }
      return;
    case "or":
      if (desired) {
        satisfy(condition.conditions[0], constants, facts, true);
      } else {
        for (const child of condition.conditions) satisfy(child, constants, facts, false);
      }
      return;
    case "eq":
    case "ne": {
      const shouldEqual = condition.op === "eq" ? desired : !desired;
      const left = valueOf(condition.left, constants, facts);
      const right = valueOf(condition.right, constants, facts);
      if (pathOf(condition.left) !== undefined && !Object.hasOwn(constants, pathOf(condition.left))) {
        setOperand(condition.left, shouldEqual ? right : (typeof right === "boolean" ? !right : Number(right ?? 0) + 1), constants, facts);
      } else {
        setOperand(condition.right, shouldEqual ? left : (typeof left === "boolean" ? !left : Number(left ?? 0) + 1), constants, facts);
      }
      return;
    }
    case "gt":
    case "gte":
    case "lt":
    case "lte": {
      const leftPath = pathOf(condition.left);
      const rightPath = pathOf(condition.right);
      const left = valueOf(condition.left, constants, facts);
      const right = valueOf(condition.right, constants, facts);
      const boundaryOnRight = rightPath !== undefined && Object.hasOwn(constants, rightPath);
      const boundary = Number(boundaryOnRight ? right : left);
      const matching = comparisonValues(condition.op, boundary).find((candidate) => candidate.matches === desired);
      const observedValue = matching?.value ?? boundary;
      if (boundaryOnRight) setOperand(condition.left, observedValue, constants, facts);
      else if (leftPath !== undefined && Object.hasOwn(constants, leftPath)) setOperand(condition.right, observedValue, constants, facts);
      else {
        setOperand(condition.right, 1, constants, facts);
        const adjusted = condition.op === "gt" || condition.op === "gte"
          ? (desired ? 2 : 0)
          : (desired ? 0 : 2);
        setOperand(condition.left, adjusted, constants, facts);
      }
      return;
    }
    case "ratio": {
      const threshold = Number(valueOf(condition.threshold, constants, facts));
      const denominator = 100;
      const scale = condition.scale ?? 1;
      const matching = comparisonValues(condition.comparator, threshold).find((candidate) => candidate.matches === desired);
      setOperand(condition.denominator, denominator, constants, facts);
      setOperand(condition.numerator, (matching?.value ?? threshold) * denominator / scale, constants, facts);
      return;
    }
    case "intersects": {
      const leftPath = pathOf(condition.left);
      const rightPath = pathOf(condition.right);
      const constantPath = Object.hasOwn(constants, leftPath) ? leftPath : rightPath;
      const observed = constantPath === leftPath ? condition.right : condition.left;
      const constant = constants[constantPath];
      setOperand(observed, desired ? [Array.isArray(constant) ? constant[0] : constant] : ["definitely-not-a-match"], constants, facts);
      return;
    }
    case "matchesAny": {
      const patterns = constants[pathOf(condition.patterns)];
      const sample = pathOf(condition.patterns) === "shared_account_pattern"
        ? "shared-admin"
        : pathOf(condition.patterns) === "sensitive_exclusion_path_patterns"
          ? "C:\\Windows"
          : Array.isArray(patterns) ? patterns[0] : patterns;
      setOperand(condition.candidates, desired ? [sample] : ["definitely-not-a-match"], constants, facts);
      return;
    }
    default:
      throw new Error(`Unsupported verdict condition ${condition.op}`);
  }
}

function runtimeSeeds(findings) {
  const seeds = new Map();
  for (const finding of findings) {
    const facts = finding[BATCH3_RUNTIME_FACTS];
    if (!facts) continue;
    const seed = seeds.get(finding.id) ?? {};
    for (const [name, value] of Object.entries(facts)) {
      if (value !== null && value !== undefined) seed[name] = value;
    }
    seeds.set(finding.id, seed);
  }
  return seeds;
}

function neutralFacts(check, runtimeSeed) {
  const facts = { ...runtimeSeed };
  for (const name of check.evidenceFields) {
    const definition = check.evidenceFieldDefinitions[name];
    if (name.endsWith("_configured_value") && (facts[name] === null || facts[name] === undefined)) {
      facts[name] = 1;
    } else if (/Type\/domain: [^.]*boolean/.test(definition)) {
      facts[name] = name.endsWith("_no_remediation_due") ? false : true;
    } else if (/Type\/domain: [^.]*array/.test(definition)) {
      facts[name] = [];
    } else if (/Type\/domain: [^.]*number/.test(definition)) {
      if (/(?:failure|violation|review|undated|missing|without|unreadable|shared|external)/.test(name)) facts[name] = 0;
      else if (/(?:population|total|count|denominator)/.test(name)) facts[name] = 100;
      else if (/(?:percent|pct|ratio|coverage|compliant)/.test(name)) facts[name] = 100;
      else facts[name] = 0;
    } else if (facts[name] === null || facts[name] === undefined) {
      facts[name] = "observed";
    }
  }
  return facts;
}

function firstMatchingRule(check, facts) {
  const context = { ...check.criteria.constants, ...facts };
  return Object.entries(check.derivedFactRules)
    .find(([, rule]) => evaluateVerdictCondition(rule.condition, context))?.[0];
}

export function certifyRuntimeRuleDecisiveness(spec, findings, expected) {
  const seeds = runtimeSeeds(findings);
  let numeric = 0;
  let collections = 0;
  let decisive = 0;

  for (const check of spec.checks) {
    const seed = seeds.get(check.id) ?? {};
    const rules = Object.entries(check.derivedFactRules);
    const nodesByRule = rules.map(([id, rule]) => [id, conditionNodes(rule.condition)]);
    for (const [constant, constantValue] of Object.entries(check.criteria.constants)) {
      if (typeof constantValue === "number") {
        const match = nodesByRule.flatMap(([id, nodes]) => nodes.map((node) => ({ id, node }))).find(({ node }) =>
          ["gt", "gte", "lt", "lte"].includes(node.op)
            ? [pathOf(node.left), pathOf(node.right)].includes(constant)
            : node.op === "ratio" && pathOf(node.threshold) === constant);
        if (!match) continue;
        const observed = match.node.op === "ratio"
          ? pathOf(match.node.numerator)
          : pathOf(match.node.left) === constant ? pathOf(match.node.right) : pathOf(match.node.left);
        assert.notEqual(seed[observed], undefined, `${check.id}.${constant}: observed fact came from an assessor`);
        const baseline = neutralFacts(check, seed);
        satisfy(check.derivedFactRules[match.id].condition, check.criteria.constants, baseline, true);
        const denominator = match.node.op === "ratio" ? 100 : 1;
        const scale = match.node.op === "ratio" ? match.node.scale ?? 1 : 1;
        const variants = comparisonValues(match.node.op === "ratio" ? match.node.comparator : match.node.op, constantValue)
          .map(({ value, matches }) => {
            const facts = { ...baseline, [observed]: value * denominator / scale };
            return {
              branchMatches: evaluateVerdictCondition(check.derivedFactRules[match.id].condition, { ...check.criteria.constants, ...facts }),
              first: firstMatchingRule(check, facts),
              matches,
            };
          });
        assert.deepEqual(variants.map((variant) => variant.branchMatches), variants.map((variant) => variant.matches), `${check.id}.${constant}: below/equal/above condition`);
        assert.ok(variants.some((variant) => variant.matches && variant.first === match.id), `${check.id}.${constant}: verdict-deciding branch`);
        assert.ok(new Set(variants.map((variant) => variant.first)).size > 1, `${check.id}.${constant}: actual ordered outcome transition`);
        numeric += 1;
        decisive += 1;
        continue;
      }

      const match = nodesByRule.flatMap(([id, nodes]) => nodes.map((node) => ({ id, node }))).find(({ node }) =>
        ["intersects", "matchesAny"].includes(node.op)
        && [pathOf(node.left), pathOf(node.right), pathOf(node.patterns)].includes(constant));
      if (!match) continue;
      const observed = match.node.op === "intersects"
        ? pathOf(pathOf(match.node.left) === constant ? match.node.right : match.node.left)
        : pathOf(match.node.candidates);
      assert.notEqual(seed[observed], undefined, `${check.id}.${constant}: observed collection came from an assessor`);
      const matchingFacts = neutralFacts(check, seed);
      satisfy(check.derivedFactRules[match.id].condition, check.criteria.constants, matchingFacts, true);
      const missingFacts = { ...matchingFacts };
      satisfy(match.node, check.criteria.constants, missingFacts, false);
      assert.equal(firstMatchingRule(check, matchingFacts), match.id, `${check.id}.${constant}: verdict-deciding collection branch`);
      assert.notEqual(firstMatchingRule(check, missingFacts), match.id, `${check.id}.${constant}: miss transition`);
      collections += 1;
      decisive += 1;
    }
  }

  assert.deepEqual({ numeric, collections, decisive }, {
    numeric: expected.numeric,
    collections: expected.collections,
    decisive: expected.numeric + expected.collections,
  });
  return { numeric, collections, decisive };
}
