/**
 * Runtime conformance checks for builder-generated integration specs. Every check
 * drives the shipped runtime instead of restating the spec: recorded client
 * requests against declared surfaces, completeness failure modes through the real
 * assessors, and observed decision facts against each ordered rule and threshold.
 */
import { observeBatchDecisionFacts } from "../../dist/extensions/grc-tools/batch-spec-builder.js";
import {
  checkContract,
  evaluateVerdictOperand,
  renderVerdictCondition,
  resolveCheckDecisionFacts,
  selectCheckVerdictRule,
} from "../../dist/extensions/grc-tools/spec-model.js";
import { differentialRunActive } from "./byte-differential-fixtures.mjs";

const RUNTIME_STATUSES = { Pass: "pass", Partial: "warn", Fail: "fail", Manual: "manual", Info: "info" };
const BODY_LOCATIONS = new Set(["json-body", "form-body"]);
const SENT_LOCATIONS = new Set(["query", "header", ...BODY_LOCATIONS]);

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** `{name}` placeholders match `placeholder`; every other character is literal. */
function templatePattern(template, placeholder) {
  return template
    .split(/(\{[^}]+\})/)
    .map((part) => /^\{[^}]+\}$/.test(part) ? placeholder : escapeRegExp(part))
    .join("");
}

function exactPattern(template) {
  return new RegExp(`^${templatePattern(template, ".+")}$`);
}

function splitPath(path) {
  const index = path.indexOf("?");
  return index < 0 ? [path, ""] : [path.slice(0, index), path.slice(index + 1)];
}

function recordedBody(body, contentType) {
  if (body instanceof URLSearchParams) return Object.fromEntries(body);
  if (typeof body !== "string") return undefined;
  if (/x-www-form-urlencoded/i.test(contentType)) return Object.fromEntries(new URLSearchParams(body));
  try {
    return JSON.parse(body);
  } catch {
    return body;
  }
}

/** Wraps a `fetch` implementation and records every request it receives, in call order. */
export function recordFetchRequests(fetchImpl) {
  const requests = [];
  const fetch = async (input, init = {}) => {
    const fromRequest = input instanceof Request ? input : undefined;
    const headers = new Headers(init.headers ?? fromRequest?.headers);
    const request = {
      method: (init.method ?? fromRequest?.method ?? "GET").toUpperCase(),
      url: fromRequest?.url ?? String(input),
      headers: Object.fromEntries(headers),
      body: undefined,
    };
    requests.push(request);
    const body = init.body === undefined && fromRequest?.body ? await fromRequest.clone().text() : init.body;
    request.body = recordedBody(body, headers.get("content-type") ?? "");
    return fetchImpl(input, init);
  };
  return { fetch, requests };
}

function surfaceMatchers(spec) {
  return spec.apiSurfaces.filter((surface) => surface.path).map((surface) => {
    const [template, query] = splitPath(surface.path);
    return {
      surface,
      method: surface.method ?? "GET",
      hostQualified: !template.startsWith("/"),
      path: new RegExp(`^${templatePattern(template, "[^/]+")}$`),
      embeddedQuery: [...new URLSearchParams(query)].map(([name, value]) => ({ name, value, pattern: exactPattern(value) })),
      literalLength: template.replace(/\{[^}]+\}/g, "").length,
    };
  });
}

/** Pairs each entry with a distinct value it matches; returns the unpaired values, or undefined when an entry has no value. */
function pairDistinct(entries, values) {
  if (entries.length === 0) return values;
  const [entry, ...rest] = entries;
  for (const [index, value] of values.entries()) {
    if (!entry.pattern.test(value)) continue;
    const unpaired = pairDistinct(rest, values.filter((_, other) => other !== index));
    if (unpaired) return unpaired;
  }
  return undefined;
}

/** Received values left after every embedded query entry claims its own, by name; undefined when an entry goes unclaimed. */
function embeddedQueryLeftovers(matcher, url) {
  const leftovers = new Map();
  for (const name of new Set(matcher.embeddedQuery.map((entry) => entry.name))) {
    const unpaired = pairDistinct(matcher.embeddedQuery.filter((entry) => entry.name === name), url.searchParams.getAll(name));
    if (!unpaired) return undefined;
    leftovers.set(name, unpaired);
  }
  return leftovers;
}

function matchSurface(matchers, method, url) {
  const candidates = matchers.filter((matcher) => matcher.method === method
    && matcher.path.test(matcher.hostQualified ? `${url.host}${url.pathname}` : url.pathname)
    && embeddedQueryLeftovers(matcher, url) !== undefined);
  candidates.sort((left, right) => right.literalLength - left.literalLength
    || right.embeddedQuery.length - left.embeddedQuery.length);
  return candidates[0];
}

function bodyMember(body, name) {
  return name.split(".").reduce(
    (value, segment) => value !== null && typeof value === "object" ? value[segment] : undefined,
    body,
  );
}

function wireText(value) {
  return value !== null && typeof value === "object" ? JSON.stringify(value) : String(value);
}

function sentValues(request, url, parameter) {
  switch (parameter.location) {
    case "query":
      return url.searchParams.getAll(parameter.name);
    case "header": {
      const value = request.headers[parameter.name.toLowerCase()];
      return value === undefined ? [] : [value];
    }
    case "json-body":
    case "form-body": {
      const value = bodyMember(request.body, parameter.name);
      return value === undefined ? [] : [wireText(value)];
    }
    default:
      return [];
  }
}

/** Body member paths no declared name covers; a declared name covers everything beneath it. */
function undeclaredBodyMembers(body, declared, prefix = "") {
  return Object.entries(body).flatMap(([key, value]) => {
    const member = `${prefix}${key}`;
    if (declared.includes(member)) return [];
    const declaresBeneath = declared.some((name) => name.startsWith(`${member}.`));
    return declaresBeneath && value !== null && typeof value === "object" && !Array.isArray(value)
      ? undeclaredBodyMembers(value, declared, `${member}.`)
      : [member];
  });
}

function declaredHeaders(surface) {
  return surface.request.headers.flatMap((header) => {
    const match = /^([A-Za-z0-9-]+):\s?(.*)$/.exec(header);
    return match ? [{ name: match[1].toLowerCase(), pattern: exactPattern(match[2]) }] : [];
  });
}

function requestViolations(matcher, request, url) {
  const { surface } = matcher;
  const label = `${surface.id} ${request.method} ${url.pathname}${url.search}`;
  const violations = [];
  const parameters = surface.request.parameters.filter((parameter) => SENT_LOCATIONS.has(parameter.location));
  for (const parameter of parameters) {
    const values = sentValues(request, url, parameter);
    if (values.length === 0) {
      if (parameter.required && !parameter.when) {
        violations.push(`${label}: omits required ${parameter.location} parameter ${parameter.name}`);
      }
      continue;
    }
    // A value with whitespace describes a rule; anything else is the exact wire value.
    if (/\s/.test(parameter.value)) continue;
    const pattern = exactPattern(parameter.value);
    for (const value of values) {
      if (!pattern.test(value)) {
        violations.push(`${label}: sends ${parameter.location} parameter ${parameter.name}=${value}, not ${parameter.value}`);
      }
    }
  }
  const declaredQuery = new Set(parameters.filter((parameter) => parameter.location === "query").map((parameter) => parameter.name));
  const leftovers = embeddedQueryLeftovers(matcher, url);
  for (const name of new Set(url.searchParams.keys())) {
    if (!leftovers.has(name)) {
      if (!declaredQuery.has(name)) violations.push(`${label}: sends undeclared query parameter ${name}`);
      continue;
    }
    const embedded = matcher.embeddedQuery.filter((entry) => entry.name === name);
    for (const value of leftovers.get(name)) {
      violations.push(embedded.some(({ pattern }) => pattern.test(value))
        ? `${label}: repeats embedded query parameter ${name}=${value}`
        : `${label}: sends query parameter ${name}=${value}, not ${embedded.map((entry) => entry.value).join(" or ")}`);
    }
  }
  if (request.body !== null && typeof request.body === "object") {
    const declaredBody = parameters.filter((parameter) => BODY_LOCATIONS.has(parameter.location)).map((parameter) => parameter.name);
    for (const member of undeclaredBodyMembers(request.body, declaredBody)) {
      violations.push(`${label}: sends undeclared body member ${member}`);
    }
  }
  for (const header of declaredHeaders(surface)) {
    const value = request.headers[header.name];
    if (value === undefined) violations.push(`${label}: omits declared header ${header.name}`);
    else if (!header.pattern.test(value)) violations.push(`${label}: sends header ${header.name} in an undeclared format`);
  }
  return violations;
}

function pageSizeViolations(spec) {
  const surfaces = new Map(spec.apiSurfaces.map((surface) => [surface.id, surface]));
  return spec.pagination.flatMap((entry) => {
    if (typeof entry.pageSize !== "number") return [];
    const pageSize = String(entry.pageSize);
    return entry.surfaceIds.flatMap((surfaceId) => {
      const surface = surfaces.get(surfaceId);
      if (!surface?.path) return [];
      const embedded = [...new URLSearchParams(splitPath(surface.path)[1]).values()];
      const declared = surface.request.parameters
        .filter((parameter) => parameter.location === "query" || BODY_LOCATIONS.has(parameter.location))
        .map((parameter) => parameter.value);
      return [...embedded, ...declared].includes(pageSize)
        ? []
        : [`${surfaceId}: page size ${pageSize} is not sent by any declared request parameter`];
    });
  });
}

/**
 * Compares requests recorded from the real clients with the spec. Every request
 * must match exactly one declared method and path, send only declared parameters
 * with their exact declared values, and carry each `Name: value` header; every
 * declared path surface must be requested unless `uncalled` explains why not.
 */
export function requestConformance(spec, requests, { uncalled = {} } = {}) {
  const matchers = surfaceMatchers(spec);
  const violations = [];
  const requested = new Set();
  for (const request of requests) {
    const url = new URL(request.url);
    const matcher = matchSurface(matchers, request.method, url);
    if (!matcher) {
      violations.push(`undeclared request ${request.method} ${url.host}${url.pathname}${url.search}`);
      continue;
    }
    requested.add(matcher.surface.id);
    violations.push(...requestViolations(matcher, request, url));
  }
  for (const { surface } of matchers) {
    const reason = uncalled[surface.id];
    if (reason !== undefined && !String(reason).trim()) violations.push(`${surface.id}: uncalled exemption needs a reason`);
    if (requested.has(surface.id)) {
      if (reason !== undefined) violations.push(`${surface.id}: exempted as uncalled but was requested`);
    } else if (reason === undefined) {
      violations.push(`${surface.id} ${surface.method ?? "GET"} ${surface.path} was never requested`);
    }
  }
  for (const surfaceId of Object.keys(uncalled)) {
    if (!matchers.some(({ surface }) => surface.id === surfaceId)) violations.push(`${surfaceId}: uncalled exemption names no path surface`);
  }
  violations.push(...pageSizeViolations(spec));
  return { violations: [...new Set(violations)], requestedSurfaceIds: [...requested].sort() };
}

export function assertRequestConformance(assert, spec, requests, options) {
  const report = requestConformance(spec, requests, options);
  assert.deepEqual(report.violations, [], `${spec.identity.slug}: recorded requests match the declared surfaces`);
  return report;
}

function findingStatuses(result) {
  const findings = Array.isArray(result) ? result : result?.findings;
  if (!Array.isArray(findings)) throw new Error("assess must return findings or an object with a findings array");
  return new Map(findings.map((finding) => [finding.id, RUNTIME_STATUSES[finding.status] ?? String(finding.status).toLowerCase()]));
}

/**
 * Puts each declared completeness source into each failure mode that makes its
 * completeness input false, reruns the shipped assessment, and reports checks that
 * still pass. `createInput` returns a fresh healthy input on which every swept
 * check passes. `applyFailure(input, { surfaceId, mode })` returns the failed input,
 * or undefined when the shipped collectors cannot produce that state, which is
 * reported because the spec then declares an impossible failure.
 */
export async function sweepCheckCompleteness({ spec, createInput, applyFailure, assess, checkIds }) {
  const inScope = new Set(checkIds ?? spec.checks.map((check) => check.id));
  const declared = new Map();
  for (const check of spec.checks) {
    if (!inScope.has(check.id)) continue;
    for (const contract of Object.values(check.completeness ?? {})) {
      for (const source of contract.sources) {
        for (const mode of source.falseWhen) {
          const key = `${source.surfaceId} ${mode}`;
          if (!declared.has(key)) declared.set(key, { surfaceId: source.surfaceId, mode, checkIds: new Set() });
          declared.get(key).checkIds.add(check.id);
        }
      }
    }
  }
  const baseline = findingStatuses(await assess(createInput()));
  const report = { combinations: 0, baselineNotPassing: [], unreachable: [], undemoted: [] };
  const swept = [...new Set([...declared.values()].flatMap((entry) => [...entry.checkIds]))].sort();
  for (const checkId of swept) {
    const status = baseline.get(checkId);
    if (status !== "pass") report.baselineNotPassing.push(`${checkId}: ${status ?? "missing"}`);
  }
  for (const { surfaceId, mode, checkIds: affected } of declared.values()) {
    const checks = [...affected].sort();
    const input = await applyFailure(createInput(), { surfaceId, mode });
    if (input === undefined) {
      report.unreachable.push(`${surfaceId} ${mode} (${checks.join(", ")})`);
      continue;
    }
    const statuses = findingStatuses(await assess(input));
    for (const checkId of checks) {
      if (baseline.get(checkId) !== "pass") continue;
      report.combinations += 1;
      const status = statuses.get(checkId);
      if (status === undefined || status === "pass") {
        report.undemoted.push(`${checkId} ${surfaceId} ${mode}: ${status ?? "missing"}`);
      }
    }
  }
  return report;
}

/**
 * Collects the decision facts the shipped runtime evaluates for one spec, keyed by
 * check ID. Differential runs observe nothing because their baseline may predate
 * the spec, so tests that consume these facts must be `portableContractTest`s.
 */
export function observeRuntimeDecisionFacts(spec) {
  const factsByCheck = new Map();
  if (differentialRunActive) return { factsByCheck, stop() {} };
  const slug = spec.identity.slug;
  const seen = new Set();
  const stop = observeBatchDecisionFacts((capture) => {
    if (capture.integration !== slug) return;
    for (const [checkId, facts] of capture.checks) {
      const signature = `${checkId} ${JSON.stringify(facts)}`;
      if (seen.has(signature)) continue;
      seen.add(signature);
      if (!factsByCheck.has(checkId)) factsByCheck.set(checkId, []);
      factsByCheck.get(checkId).push(facts);
    }
  });
  return { factsByCheck, stop };
}

function checksInScope(spec, checkIds) {
  return checkIds ? checkIds.map((checkId) => checkContract(spec, checkId)) : spec.checks;
}

function exemptionKeys(spec, entries, keyOf, describe) {
  const keys = new Map();
  for (const entry of entries) {
    if (!String(entry.reason ?? "").trim()) throw new Error(`${describe(entry)}: unreachable exemption needs a reason`);
    checkContract(spec, entry.checkId);
    keys.set(keyOf(entry), describe(entry));
  }
  return keys;
}

const SIDE_REQUIREMENTS = {
  gt: ["at", "above"],
  lte: ["at", "above"],
  gte: ["at", "below"],
  lt: ["at", "below"],
  eq: ["at", "off"],
  ne: ["at", "off"],
};

function comparisonsIn(condition, scope = []) {
  switch (condition.op) {
    case "and":
    case "or":
      return condition.conditions.flatMap((entry) => comparisonsIn(entry, scope));
    case "not":
      return comparisonsIn(condition.condition, scope);
    case "some":
    case "every":
      return comparisonsIn(condition.condition, [...scope, condition.path]);
    case "gt":
    case "gte":
    case "lt":
    case "lte":
    case "eq":
    case "ne":
    case "ratio":
      return [{ comparison: condition, scope }];
    case "always":
    case "defined":
    case "null":
    case "matches":
      return [];
    default:
      throw new Error(`Boundary coverage does not understand condition op ${condition.op}`);
  }
}

function constantOperand(operand, constants) {
  if (operand.kind === "value") return { value: operand.value };
  if (operand.kind === "path" && Object.hasOwn(constants, operand.path)) return { value: constants[operand.path] };
  return undefined;
}

/** Ordering and ratio comparisons over facts have thresholds; equality counts only against a numeric constant. */
function isThreshold(comparison, constants) {
  if (comparison.op === "ratio") {
    return [comparison.numerator, comparison.denominator, comparison.threshold]
      .some((operand) => !constantOperand(operand, constants));
  }
  const left = constantOperand(comparison.left, constants);
  const right = constantOperand(comparison.right, constants);
  if (left && right) return false;
  if (comparison.op === "eq" || comparison.op === "ne") {
    return typeof (left ?? right)?.value === "number";
  }
  return true;
}

function scopedItems(scope, facts) {
  let items = [undefined];
  for (const path of scope) {
    items = items.flatMap((item) => {
      const value = evaluateVerdictOperand({ kind: "path", path }, facts, item);
      return Array.isArray(value) ? value : [];
    });
  }
  return items;
}

/** Mirrors the evaluator's coercion so a side is reported only where the evaluator compares values. */
function thresholdDelta(comparison, facts, item) {
  const value = (operand) => evaluateVerdictOperand(operand, facts, item);
  if (comparison.op === "ratio") {
    const [numerator, denominator, threshold] = [comparison.numerator, comparison.denominator, comparison.threshold]
      .map((operand) => value(operand))
      .map((entry) => entry === null || entry === undefined ? Number.NaN : Number(entry));
    if (![numerator, denominator, threshold].every(Number.isFinite) || denominator <= 0) return undefined;
    const scaled = (numerator / denominator) * (comparison.scale ?? 1);
    const ratio = comparison.roundDigits === undefined
      ? scaled
      : Math.round(scaled * (10 ** comparison.roundDigits)) / (10 ** comparison.roundDigits);
    return ratio - threshold;
  }
  const left = value(comparison.left);
  const right = value(comparison.right);
  if (comparison.op === "eq" || comparison.op === "ne") {
    return typeof left === "number" && typeof right === "number" ? left - right : undefined;
  }
  if (left === null || left === undefined || right === null || right === undefined) return undefined;
  const delta = Number(left) - Number(right);
  return Number.isNaN(delta) ? undefined : delta;
}

function sideOf(op, delta) {
  if (delta === 0) return "at";
  if (op === "eq" || op === "ne") return "off";
  return delta < 0 ? "below" : "above";
}

/**
 * Reports threshold comparisons in a check's rules and derived facts that the
 * observed runtime facts never put at the boundary and on the adjacent side where
 * the comparison changes outcome. Feeding these inputs through the differential
 * corpus is what proves boundary parity with the baseline runtime.
 */
export function certifyRuntimeBoundaryCoverage(spec, factsByCheck, { checkIds, unreachable = [] } = {}) {
  const exemptions = exemptionKeys(
    spec,
    unreachable,
    (entry) => `${entry.checkId} ${entry.condition} ${entry.side}`,
    (entry) => `${entry.checkId} ${entry.side} of ${entry.condition}`,
  );
  const used = new Set();
  const gaps = [];
  let comparisons = 0;
  for (const check of checksInScope(spec, checkIds)) {
    const resolved = (factsByCheck.get(check.id) ?? []).map((facts) => resolveCheckDecisionFacts(check, facts));
    const locations = [
      ...check.criteria.rules.map((rule, index) => [`rule ${index + 1}`, rule.condition]),
      ...Object.entries(check.derivedFactRules ?? {}).map(([name, rule]) => [`derived fact ${name}`, rule.condition]),
    ];
    for (const [location, condition] of locations) {
      for (const { comparison, scope } of comparisonsIn(condition)) {
        if (!isThreshold(comparison, check.criteria.constants)) continue;
        comparisons += 1;
        const op = comparison.op === "ratio" ? comparison.comparator : comparison.op;
        const observed = new Set();
        for (const facts of resolved) {
          for (const item of scopedItems(scope, facts)) {
            const delta = thresholdDelta(comparison, facts, item);
            if (delta !== undefined) observed.add(sideOf(op, delta));
          }
        }
        const rendered = renderVerdictCondition(comparison);
        const absent = SIDE_REQUIREMENTS[op].filter((side) => {
          const key = `${check.id} ${rendered} ${side}`;
          if (!exemptions.has(key)) return !observed.has(side);
          used.add(key);
          if (observed.has(side)) gaps.push(`${exemptions.get(key)} is exempted as unreachable but runtime facts reach it`);
          return false;
        });
        if (absent.length > 0) {
          gaps.push(`${check.id} ${location}: runtime facts never fall ${absent.join(" or ")} the boundary of ${rendered}`);
        }
      }
    }
  }
  for (const [key, description] of exemptions) {
    if (!used.has(key)) gaps.push(`${description} names no threshold comparison`);
  }
  return { comparisons, gaps };
}

/**
 * Reports ordered rules that no observed runtime fact set selects. Each rule must
 * be the first match for at least one real assessment, so every status branch the
 * spec publishes is exercised through the shipped runtime.
 */
export function certifyRuntimeRuleDecisiveness(spec, factsByCheck, { checkIds, unreachable = [] } = {}) {
  const exemptions = exemptionKeys(
    spec,
    unreachable,
    (entry) => `${entry.checkId} ${entry.order}`,
    (entry) => `${entry.checkId} rule ${entry.order}`,
  );
  const used = new Set();
  const gaps = [];
  for (const check of checksInScope(spec, checkIds)) {
    const reached = new Set((factsByCheck.get(check.id) ?? []).map((facts) => selectCheckVerdictRule(check, facts).index + 1));
    check.criteria.rules.forEach((rule, index) => {
      const order = index + 1;
      const key = `${check.id} ${order}`;
      if (exemptions.has(key)) {
        used.add(key);
        if (reached.has(order)) gaps.push(`${exemptions.get(key)} is exempted as unreachable but runtime facts select it`);
        return;
      }
      if (!reached.has(order)) {
        gaps.push(`${check.id} rule ${order} (${rule.status}) is never selected by runtime facts: ${renderVerdictCondition(rule.condition)}`);
      }
    });
  }
  for (const [key, description] of exemptions) {
    if (!used.has(key)) gaps.push(`${description} names no rule`);
  }
  return { gaps };
}
