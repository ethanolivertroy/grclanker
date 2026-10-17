import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { pathToFileURL } from "node:url";

import {
  buildBatchIntegrationSpec,
  buildBatchOutputContract,
  deriveDecisionRules,
  evaluateBatchRuntimeCheckVerdict,
} from "../dist/extensions/grc-tools/batch-spec-builder.js";
import {
  checkContract,
  evaluateCheckVerdict,
  evaluateVerdictOperand,
  renderVerdictCondition,
  resolveCheckDecisionFacts,
  selectCheckVerdictRule,
} from "../dist/extensions/grc-tools/spec-model.js";
import { discoverDifferentialTests, stubUnavailableImports } from "../scripts/batch-byte-differential.mjs";
import { renderIntegrationSpec } from "../scripts/generate-integration-specs.mjs";
import {
  certifyRuntimeBoundaryCoverage,
  certifyRuntimeRuleDecisiveness,
  observeRuntimeDecisionFacts,
  recordFetchRequests,
  requestConformance,
  sweepCheckCompleteness,
} from "./helpers/spec-conformance.mjs";

const ORIGIN = "https://api.example.test";
const DEFAULT_PROJECTION = "The collector projects the response to the listed verdict fields before evidence export.";
const path = (name) => ({ kind: "path", path: name });
const value = (entry) => ({ kind: "value", value: entry });
const notDefined = (name) => ({ op: "not", condition: { op: "defined", operand: path(name) } });
const isFalse = (name) => ({ op: "eq", left: path(name), right: value(false) });
const ADMIN_LIMIT = { op: "gt", left: path("admin_count"), right: path("max_admins") };
const INACTIVE_LIMIT = { op: "gt", left: path("$.days_inactive"), right: path("max_inactive_days") };
const RATE_LIMIT = {
  documentedLimit: null,
  retryHeaders: ["Retry-After"],
  retryableStatuses: [429],
  backoffPolicy: "Honor Retry-After, otherwise back off exponentially.",
};
const USERS_REQUEST = {
  headers: ["Authorization: Bearer {token}", "Accept: application/json"],
  parameters: [
    { name: "limit", location: "query", required: true, value: "200" },
    {
      name: "cursor",
      location: "query",
      required: false,
      value: "The opaque cursor returned by the previous page.",
      when: "After the first page.",
    },
  ],
};
const ROLES_REQUEST = {
  headers: ["Authorization: Bearer {token}", "Content-Type: application/json"],
  parameters: [
    { name: "id", location: "path", required: true, value: "The user identifier from the users inventory." },
    { name: "filter.kind", location: "json-body", required: true, value: "admin" },
  ],
};
const EXAMPLES = [
  { kind: "unreadable", facts: {}, expected: "manual", reason: "No administrator count was collected." },
  {
    kind: "noncompliant",
    facts: { admin_count: 4, users_complete: false },
    expected: "fail",
    reason: "A proven excess outranks the partial inventory.",
  },
  {
    kind: "partial",
    facts: { admin_count: 3, users_complete: false },
    expected: "warn",
    reason: "A partial inventory cannot prove the limit holds.",
  },
  {
    kind: "compliant",
    facts: { admin_count: 3, users_complete: true },
    expected: "pass",
    reason: "Exactly max_admins administrators is within the limit.",
  },
];

function exampleSurfaces(overrides = {}) {
  return [
    {
      id: "users",
      path: "/v1/users?status=active",
      service: "Example API",
      documentationUrl: "https://docs.example.test/users",
      fields: ["id", "role"],
      request: USERS_REQUEST,
      ...overrides.users,
    },
    {
      id: "roles",
      method: "POST",
      path: "/v1/users/{id}/roles",
      service: "Example API",
      documentationUrl: "https://docs.example.test/roles",
      fields: ["role", "days_inactive"],
      request: ROLES_REQUEST,
      ...overrides.roles,
    },
  ];
}

function exampleChecks(overrides = {}) {
  const admins = deriveDecisionRules("EX-1", [
    { status: "manual", condition: notDefined("admin_count") },
    { status: "fail", condition: ADMIN_LIMIT },
    { status: "warn", condition: isFalse("users_complete") },
    { status: "pass", condition: { op: "always" } },
  ]);
  const inactive = deriveDecisionRules("EX-2", [
    { status: "manual", condition: notDefined("admins") },
    { status: "fail", condition: { op: "some", path: "admins", condition: INACTIVE_LIMIT } },
    { status: "warn", condition: isFalse("admins_complete") },
    { status: "pass", condition: { op: "always" } },
  ]);
  return [
    {
      id: "EX-1",
      control: 1,
      title: "Administrator count stays within the approved limit",
      severity: "high",
      owner: "example_assess_identity",
      surfaces: ["users"],
      evidenceFields: ["users"],
      decisionInputs: {
        admin_count: "Users whose role is administrator across the users inventory.",
        users_complete: "True only when the users inventory was read to exhaustion.",
      },
      decisionConstants: { max_admins: 3 },
      decisionRules: admins.rules,
      derivedFactRules: admins.derivedFactRules,
      completeness: {
        users_complete: {
          sources: [{ surfaceId: "users", falseWhen: ["truncated", "denied"] }],
          semantics: "Every users page was read without a cap, truncation, or denial.",
        },
      },
      decision: "Fail when more than max_admins users are administrators, warn when the users inventory is partial, otherwise pass.",
      ...overrides["EX-1"],
    },
    {
      id: "EX-2",
      control: 2,
      title: "Administrators are active",
      severity: "medium",
      owner: "example_assess_identity",
      surfaces: ["users", "roles"],
      evidenceFields: ["roles"],
      decisionInputs: {
        admins: "Administrator role assignments, each with the days since the administrator last signed in.",
        admins_complete: "True only when every administrator role read succeeded.",
      },
      decisionConstants: { max_inactive_days: 90 },
      decisionRules: inactive.rules,
      derivedFactRules: inactive.derivedFactRules,
      completeness: {
        admins_complete: {
          sources: [{ surfaceId: "roles", falseWhen: ["error", "not-configured"] }],
          semantics: "Every administrator role read returned a readable assignment list.",
        },
      },
      decision: "Fail when any administrator has been inactive for more than max_inactive_days days, warn when a role read failed, otherwise pass.",
      ...overrides["EX-2"],
    },
  ];
}

function exampleDefinition(overrides = {}) {
  return {
    slug: "example-sec-inspector",
    displayName: "Example",
    vendor: "Example",
    category: "identity",
    summary: "Assesses administrator hygiene in a fictional identity service.",
    sourceModule: "cli/extensions/grc-tools/example.ts",
    baseServices: [ORIGIN],
    authentication: {
      modes: ["Bearer token"],
      precedence: ["Tool arguments", "EXAMPLE_TOKEN"],
      environment: ["EXAMPLE_TOKEN"],
      configLocations: [],
      variants: [],
      configFields: ["token"],
    },
    permissions: [{ id: "reader", kind: "role", value: "Reader", unlocks: ["users", "roles"] }],
    surfaces: exampleSurfaces(),
    checks: exampleChecks(),
    tools: { example_assess_identity: ["EX-1", "EX-2"] },
    pagination: [{
      surfaceIds: ["users"],
      cursorFields: ["next_cursor"],
      pageSize: 200,
      itemCap: "none",
      pageCap: null,
      totalSemantics: "No total is reported; an empty next_cursor proves exhaustion.",
      stopConditions: ["next_cursor is empty"],
    }],
    rateLimit: RATE_LIMIT,
    runtimeBehavior: [],
    knownGaps: [],
    sensitiveFields: ["token"],
    credentialFormats: [],
    output: buildBatchOutputContract({
      files: ["analysis/findings.json"],
      overwritePolicy: "Replace the previous bundle.",
      archivePairing: "Write a zip archive beside the bundle directory.",
    }),
    ...overrides,
  };
}

const buildExample = (overrides) => buildBatchIntegrationSpec(exampleDefinition(overrides));
const withExamples = (examples) => ({ checks: exampleChecks({ "EX-1": { examples } }) });

test("builder defaults keep the text published for existing batch specs", () => {
  const spec = buildExample();
  assert.equal(spec.identity.lastUpdated, "2026-09-27");
  assert.deepEqual(spec.apiSurfaces.map((surface) => surface.projectionStage), [DEFAULT_PROJECTION, DEFAULT_PROJECTION]);
  assert.match(spec.redaction.projectionStage, /^Project records to verdict-consumed fields/);
  assert.equal(spec.redaction.integrationRules.length, 3);
  assert.match(checkContract(spec, "EX-1").evidenceFieldDefinitions.admin_count, /before any 25-item finding preview/);
  assert.equal(Object.hasOwn(spec.rateLimits[0], "retryableStatusRanges"), false);
  assert.ok(checkContract(spec, "EX-1").criteria.examples.every((example) => example.facts === undefined));
});

test("builder overrides replace only the named defaults", () => {
  const defaults = buildExample();
  const spec = buildExample({
    lastUpdated: "2026-10-17",
    findingPreviewLimit: 50,
    redaction: { integrationRules: ["Withhold every vendor response body."] },
    surfaces: exampleSurfaces({ roles: { projectionStage: "The collector keeps only role names and inactivity days." } }),
  });
  assert.equal(spec.identity.lastUpdated, "2026-10-17");
  assert.match(checkContract(spec, "EX-1").evidenceFieldDefinitions.admin_count, /before any 50-item finding preview/);
  assert.deepEqual(
    spec.apiSurfaces.map((surface) => surface.projectionStage),
    [DEFAULT_PROJECTION, "The collector keeps only role names and inactivity days."],
  );
  assert.deepEqual(spec.redaction.integrationRules, ["Withhold every vendor response body."]);
  assert.equal(spec.redaction.projectionStage, defaults.redaction.projectionStage);
  assert.throws(() => buildExample({ lastUpdated: "October 17, 2026" }), {
    message: "example-sec-inspector lastUpdated must be an ISO date",
  });
  for (const findingPreviewLimit of [0, 2.5]) {
    assert.throws(() => buildExample({ findingPreviewLimit }), {
      message: "example-sec-inspector findingPreviewLimit must be a positive integer",
    });
  }
});

test("declared request contracts pass through and must account for every path placeholder", () => {
  const roles = (spec) => spec.apiSurfaces.find((surface) => surface.id === "roles");
  assert.deepEqual(roles(buildExample()).request.parameters, ROLES_REQUEST.parameters);
  assert.deepEqual(roles(buildExample()).request.headers, ROLES_REQUEST.headers);
  assert.deepEqual(roles(buildExample({ surfaces: exampleSurfaces({ roles: { request: undefined } }) })).request, {
    clientRegion: "Use the configured Example API origin; never follow a server link to a different origin.",
    headers: ["Authorization appropriate to the selected authentication mode", "Accept: application/json"],
    parameters: [],
    responseShape: "A JSON object or list containing only the documented role, days_inactive members consumed by verdicts.",
  });

  const invalid = (surfaceOverrides) => () => buildExample({ surfaces: exampleSurfaces(surfaceOverrides) });
  const bodyOnly = ROLES_REQUEST.parameters.filter((parameter) => parameter.location !== "path");
  assert.throws(invalid({ roles: { request: { ...ROLES_REQUEST, parameters: bodyOnly } } }), {
    message: "roles path placeholder {id} has no path parameter",
  });
  assert.throws(invalid({ roles: { path: "/v1/roles" } }), {
    message: "roles path parameter id has no {id} placeholder",
  });
  assert.throws(invalid({ roles: { request: { ...ROLES_REQUEST, parameters: [...ROLES_REQUEST.parameters, ROLES_REQUEST.parameters[0]] } } }), {
    message: "roles declares request parameter path:id more than once",
  });
  const status = { name: "status", location: "query", required: true, value: "active" };
  assert.throws(invalid({ users: { request: { ...USERS_REQUEST, parameters: [...USERS_REQUEST.parameters, status] } } }), {
    message: "users declares query parameter status that its path already embeds",
  });
});

test("retryable status ranges are published and may not overlap single statuses", () => {
  const withRanges = (retryableStatuses, retryableStatusRanges) => buildExample({
    rateLimit: { ...RATE_LIMIT, retryableStatuses, retryableStatusRanges },
  });
  assert.deepEqual(withRanges([429], [{ from: 500, to: 599 }]).rateLimits[0].retryableStatusRanges, [{ from: 500, to: 599 }]);
  for (const [from, to] of [[599, 500], [500, 600], [99, 200]]) {
    assert.throws(() => withRanges([429], [{ from, to }]), {
      message: `Retryable status range ${from}-${to} must be an ascending HTTP status range`,
    });
  }
  assert.throws(() => withRanges([429, 503], [{ from: 500, to: 599 }]), {
    message: "Retryable statuses 503 repeat a declared retryable status range",
  });
});

test("executable examples render their facts and must reproduce every rule status", () => {
  const examples = checkContract(buildExample(withExamples(EXAMPLES)), "EX-1").criteria.examples;
  assert.deepEqual(examples.map((example) => example.facts), EXAMPLES.map((example) => example.facts));
  assert.deepEqual(examples.map((example) => example.input), [
    "No primitive decision inputs are supplied.",
    "`admin_count` = 4; `users_complete` = false",
    "`admin_count` = 3; `users_complete` = false",
    "`admin_count` = 3; `users_complete` = true",
  ]);

  const replacing = (index, replacement) => EXAMPLES.map((example, position) => position === index ? replacement : example);
  assert.throws(() => buildExample(withExamples(replacing(3, { ...EXAMPLES[3], facts: { admin_count: 4, users_complete: true } }))), {
    message: "EX-1 compliant example evaluates to fail, not pass",
  });
  assert.throws(() => buildExample(withExamples(EXAMPLES.filter((example) => example.kind !== "partial"))), {
    message: "EX-1 executable examples do not demonstrate warn",
  });
  assert.throws(() => buildExample(withExamples(replacing(0, { ...EXAMPLES[0], facts: { admin_count: undefined } }))), {
    message: "EX-1 unreadable example sets admin_count to undefined; omit missing inputs instead",
  });
  assert.throws(() => buildExample(withExamples(replacing(3, { ...EXAMPLES[3], facts: { admin_total: 3 } }))), {
    message: "EX-1 compliant example is not executable: EX-1 received undeclared decision input(s): admin_total",
  });
});

test("generated markdown separates executable examples and renders status ranges and compound headers", () => {
  const spec = buildExample({
    ...withExamples(EXAMPLES),
    rateLimit: { ...RATE_LIMIT, retryableStatusRanges: [{ from: 500, to: 599 }] },
    surfaces: exampleSurfaces({
      users: { request: { ...USERS_REQUEST, headers: ["Authorization: Bearer {token}", "Accept: application/json; charset=utf-8"] } },
    }),
  });
  const lines = renderIntegrationSpec({ contract: spec, narrativePath: "example.md" }, "Example narrative.", []).split("\n");
  assert.ok(lines.includes("| Example | Not published | `Retry-After` | 429, 500-599 | Honor Retry-After, otherwise back off exponentially. |"));
  assert.ok(lines.includes("| `users` | headers | Authorization: Bearer {token}; `Accept: application/json; charset=utf-8` | yes |"));
  assert.ok(lines.includes("| `EX-1` | noncompliant | `admin_count` = 4; `users_complete` = false | fail | A proven excess outranks the partial inventory. |"));
  const executable = lines.indexOf("### Executable criterion examples");
  const illustrative = lines.indexOf("### Illustrative criterion notes");
  assert.ok(executable > 0 && illustrative > executable, "executable examples precede illustrative notes");
  const nextHeading = lines.findIndex((line, index) => index > illustrative && line.startsWith("#"));
  const illustrativeRows = lines.slice(illustrative, nextHeading).filter((line) => line.startsWith("| `EX-"));
  assert.equal(illustrativeRows.length, 4);
  assert.ok(illustrativeRows.every((line) => line.startsWith("| `EX-2` |")), "executable examples are not repeated as notes");
});

test("selected verdict rules expose the first match over resolved constants and derived facts", () => {
  const check = checkContract(buildExample(), "EX-1");
  const facts = { admin_count: 4, users_complete: false };
  const resolved = resolveCheckDecisionFacts(check, facts);
  assert.equal(resolved.max_admins, 3);
  assert.equal(resolved.ex_1_branch_02_matches, true);
  assert.equal(resolved.ex_1_branch_03_matches, true);
  const selected = selectCheckVerdictRule(check, facts);
  assert.equal(selected.index, 1);
  assert.equal(selected.rule, check.criteria.rules[1]);
  assert.equal(evaluateCheckVerdict(check, facts), "fail");
  assert.throws(() => resolveCheckDecisionFacts(check, { admin_count: 1, sample: [] }), {
    message: "EX-1 received undeclared decision input(s): sample",
  });

  const admins = { admins: [{ days_inactive: 91 }] };
  assert.equal(evaluateVerdictOperand(path("$.days_inactive"), admins, admins.admins[0]), 91);
  assert.equal(evaluateVerdictOperand({ kind: "length", path: "admins" }, admins), 1);
  assert.equal(evaluateVerdictOperand({ kind: "path", path: "missing", fallback: 0 }, admins), 0);
});

async function recordCalls(calls) {
  const recorder = recordFetchRequests(async () => new Response("{}"));
  for (const [url, init] of calls) await recorder.fetch(`${ORIGIN}${url}`, init);
  return recorder.requests;
}

const BEARER = { Authorization: "Bearer example-token", Accept: "application/json" };
const CONFORMING_CALLS = [
  ["/v1/users?status=active&limit=200", { headers: BEARER }],
  ["/v1/users?status=active&limit=200&cursor=page-2", { headers: BEARER }],
  ["/v1/users/42/roles", {
    method: "POST",
    headers: { ...BEARER, "Content-Type": "application/json" },
    body: JSON.stringify({ filter: { kind: "admin" } }),
  }],
];

test("recorded fetch requests keep the method, URL, lowercased headers, and parsed body", async () => {
  const forwarded = [];
  const recorder = recordFetchRequests(async (input, init) => {
    forwarded.push(input instanceof Request && input.body ? await input.text() : input);
    return new Response("{}");
  });
  await recorder.fetch(`${ORIGIN}/v1/users/42/roles`, {
    method: "post",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ filter: { kind: "admin" } }),
  });
  await recorder.fetch(`${ORIGIN}/oauth/token`, { method: "POST", body: new URLSearchParams({ grant_type: "client_credentials" }) });
  await recorder.fetch(`${ORIGIN}/oauth/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: "grant_type=client_credentials",
  });
  await recorder.fetch(new Request(`${ORIGIN}/v1/users`, { headers: { Accept: "application/json" } }));
  await recorder.fetch(new Request(`${ORIGIN}/v1/users/42/roles`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ filter: { kind: "admin" } }),
  }));
  assert.equal(forwarded.length, 5);
  assert.equal(forwarded[4], JSON.stringify({ filter: { kind: "admin" } }), "the forwarded Request body stays unread");
  assert.deepEqual(recorder.requests, [
    { method: "POST", url: `${ORIGIN}/v1/users/42/roles`, headers: { "content-type": "application/json" }, body: { filter: { kind: "admin" } } },
    { method: "POST", url: `${ORIGIN}/oauth/token`, headers: {}, body: { grant_type: "client_credentials" } },
    {
      method: "POST",
      url: `${ORIGIN}/oauth/token`,
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: { grant_type: "client_credentials" },
    },
    { method: "GET", url: `${ORIGIN}/v1/users`, headers: { accept: "application/json" }, body: undefined },
    { method: "POST", url: `${ORIGIN}/v1/users/42/roles`, headers: { "content-type": "application/json" }, body: { filter: { kind: "admin" } } },
  ]);
});

test("request conformance accepts requests that match the declared surfaces exactly", async () => {
  assert.deepEqual(requestConformance(buildExample(), await recordCalls(CONFORMING_CALLS)), {
    violations: [],
    requestedSurfaceIds: ["roles", "users"],
  });
});

test("request conformance reports undeclared requests, parameter values, body members, and header formats", async () => {
  const requests = await recordCalls([
    ["/v1/users?status=active&limit=50", { headers: BEARER }],
    ["/v1/users?status=active&debug=1", { headers: { Authorization: "Bearer example-token" } }],
    ["/v1/groups", { headers: BEARER }],
    ["/v1/users?limit=200", { headers: BEARER }],
    ["/v1/users?status=active&status=deleted&limit=200", { headers: BEARER }],
    ["/v1/users/42/roles", {
      method: "POST",
      headers: { Authorization: "Basic abc", "Content-Type": "application/json" },
      body: JSON.stringify({ filter: { kind: "user", scope: "all" }, extra: true }),
    }],
  ]);
  assert.deepEqual(requestConformance(buildExample(), requests).violations, [
    "users GET /v1/users?status=active&limit=50: sends query parameter limit=50, not 200",
    "users GET /v1/users?status=active&debug=1: omits required query parameter limit",
    "users GET /v1/users?status=active&debug=1: sends undeclared query parameter debug",
    "users GET /v1/users?status=active&debug=1: omits declared header accept",
    "undeclared request GET api.example.test/v1/groups",
    "undeclared request GET api.example.test/v1/users?limit=200",
    "users GET /v1/users?status=active&status=deleted&limit=200: sends query parameter status=deleted, not active",
    "roles POST /v1/users/42/roles: sends json-body parameter filter.kind=user, not admin",
    "roles POST /v1/users/42/roles: sends undeclared body member filter.scope",
    "roles POST /v1/users/42/roles: sends undeclared body member extra",
    "roles POST /v1/users/42/roles: sends header authorization in an undeclared format",
  ]);
});

test("request conformance requires every path surface to be requested or exempted with a reason", async () => {
  const spec = buildExample();
  const usersOnly = await recordCalls(CONFORMING_CALLS.slice(0, 1));
  const violations = (uncalled) => requestConformance(spec, usersOnly, { uncalled }).violations;
  const disabled = "Role reads run only when the operator enables role review.";
  assert.deepEqual(violations(undefined), ["roles POST /v1/users/{id}/roles was never requested"]);
  assert.deepEqual(violations({ roles: disabled }), []);
  assert.deepEqual(violations({ roles: " " }), ["roles: uncalled exemption needs a reason"]);
  assert.deepEqual(violations({ users: disabled, roles: disabled }), ["users: exempted as uncalled but was requested"]);
  assert.deepEqual(violations({ groups: disabled, roles: disabled }), ["groups: uncalled exemption names no path surface"]);
});

test("request conformance requires a declared parameter to send each published page size", async () => {
  const pagination = [{ ...exampleDefinition().pagination[0], pageSize: 500 }];
  assert.deepEqual(requestConformance(buildExample({ pagination }), await recordCalls(CONFORMING_CALLS)).violations, [
    "users: page size 500 is not sent by any declared request parameter",
  ]);
});

const healthyInput = () => ({ users: "complete", roles: "complete" });
const failSource = (input, { surfaceId, mode }) => mode === "not-configured" ? undefined : { ...input, [surfaceId]: mode };
function assessSources(input, passingStates = ["complete"]) {
  const status = (surfaceId) => passingStates.includes(input[surfaceId]) ? "Pass" : "Partial";
  return { findings: [{ id: "EX-1", status: status("users") }, { id: "EX-2", status: status("roles") }] };
}

test("completeness sweep drives every declared source failure through the assessment", async () => {
  const report = await sweepCheckCompleteness({
    spec: buildExample(),
    createInput: healthyInput,
    applyFailure: failSource,
    assess: (input) => assessSources(input),
  });
  assert.deepEqual(report, {
    combinations: 3,
    baselineNotPassing: [],
    unreachable: ["roles not-configured (EX-2)"],
    undemoted: [],
  });
});

test("completeness sweep reports failures that still pass and checks that never pass", async () => {
  const spec = buildExample();
  const undemoted = await sweepCheckCompleteness({
    spec,
    createInput: healthyInput,
    applyFailure: failSource,
    assess: (input) => assessSources(input, ["complete", "error"]),
  });
  assert.deepEqual(undemoted.undemoted, ["EX-2 roles error: pass"]);
  const failing = await sweepCheckCompleteness({
    spec,
    checkIds: ["EX-1"],
    createInput: () => ({ ...healthyInput(), users: "truncated" }),
    applyFailure: failSource,
    assess: (input) => assessSources(input),
  });
  assert.deepEqual(failing, { combinations: 0, baselineNotPassing: ["EX-1: warn"], unreachable: [], undemoted: [] });
});

test("runtime decision facts are observed per spec, filtered to declared inputs, and deduplicated", () => {
  const spec = buildExample();
  const other = buildExample({ slug: "other-sec-inspector" });
  const observed = observeRuntimeDecisionFacts(spec);
  try {
    evaluateBatchRuntimeCheckVerdict(spec, "EX-1", { admin_count: 3, users_complete: true, rendered_sample: ["alice"] });
    evaluateBatchRuntimeCheckVerdict(spec, "EX-1", { admin_count: 3, users_complete: true });
    evaluateBatchRuntimeCheckVerdict(spec, "EX-2", { admins: [], admins_complete: true });
    evaluateBatchRuntimeCheckVerdict(other, "EX-1", { admin_count: 9, users_complete: true });
  } finally {
    observed.stop();
  }
  evaluateBatchRuntimeCheckVerdict(spec, "EX-1", { admin_count: 7, users_complete: true });
  assert.deepEqual([...observed.factsByCheck], [
    ["EX-1", [{ admin_count: 3, users_complete: true }]],
    ["EX-2", [{ admins: [], admins_complete: true }]],
  ]);
});

test("rule decisiveness reports ordered rules that no runtime fact set selects", () => {
  const spec = buildExample();
  const factsByCheck = new Map([
    ["EX-1", [{}, { admin_count: 4, users_complete: true }, { admin_count: 1, users_complete: true }]],
  ]);
  const certify = (unreachable) => certifyRuntimeRuleDecisiveness(spec, factsByCheck, { checkIds: ["EX-1"], unreachable }).gaps;
  const warnRule = checkContract(spec, "EX-1").criteria.rules[2];
  const neverSelected = `EX-1 rule 3 (warn) is never selected by runtime facts: ${renderVerdictCondition(warnRule.condition)}`;
  assert.deepEqual(certify(), [neverSelected]);
  assert.deepEqual(certify([{ checkId: "EX-1", order: 3, reason: "The collector cannot report a partial users inventory." }]), []);
  assert.deepEqual(certify([{ checkId: "EX-1", order: 2, reason: "Claimed unreachable." }]), [
    "EX-1 rule 2 is exempted as unreachable but runtime facts select it",
    neverSelected,
  ]);
  assert.deepEqual(certify([{ checkId: "EX-1", order: 9, reason: "No such rule." }]), [neverSelected, "EX-1 rule 9 names no rule"]);
  assert.throws(() => certify([{ checkId: "EX-1", order: 3, reason: "" }]), {
    message: "EX-1 rule 3: unreachable exemption needs a reason",
  });
});

test("boundary coverage requires runtime facts at and beyond each threshold, including inside collections", () => {
  const spec = buildExample();
  const adminLimit = renderVerdictCondition(ADMIN_LIMIT);
  const covered = new Map([
    ["EX-1", [{ admin_count: 3, users_complete: true }, { admin_count: 4, users_complete: true }]],
    ["EX-2", [{ admins: [{ days_inactive: 90 }, { days_inactive: 91 }], admins_complete: true }]],
  ]);
  assert.deepEqual(certifyRuntimeBoundaryCoverage(spec, covered), { comparisons: 2, gaps: [] });
  const offBoundary = new Map([
    ["EX-1", [{ admin_count: 1, users_complete: true }, { admin_count: 4, users_complete: true }]],
    ["EX-2", [{ admins: [{ days_inactive: 10 }], admins_complete: true }]],
  ]);
  assert.deepEqual(certifyRuntimeBoundaryCoverage(spec, offBoundary).gaps, [
    `EX-1 derived fact ex_1_branch_02_matches: runtime facts never fall at the boundary of ${adminLimit}`,
    `EX-2 derived fact ex_2_branch_02_matches: runtime facts never fall at or above the boundary of ${renderVerdictCondition(INACTIVE_LIMIT)}`,
  ]);

  const certifyAdmins = (facts, unreachable) => certifyRuntimeBoundaryCoverage(
    spec,
    new Map([["EX-1", facts]]),
    { checkIds: ["EX-1"], unreachable },
  ).gaps;
  const exemptAt = [{ checkId: "EX-1", condition: adminLimit, side: "at", reason: "Exactly max_admins administrators cannot be seeded." }];
  assert.deepEqual(certifyAdmins(offBoundary.get("EX-1"), exemptAt), []);
  assert.deepEqual(certifyAdmins(covered.get("EX-1"), exemptAt), [
    `EX-1 at of ${adminLimit} is exempted as unreachable but runtime facts reach it`,
  ]);
  assert.deepEqual(
    certifyAdmins(covered.get("EX-1"), [{ checkId: "EX-1", condition: "admin_count > 5", side: "at", reason: "Stale exemption." }]),
    ["EX-1 at of admin_count > 5 names no threshold comparison"],
  );
});

test("boundary coverage treats ratios and numeric equality in ordered rules as thresholds", () => {
  const ratio = {
    op: "ratio",
    numerator: path("covered"),
    denominator: path("total"),
    comparator: "lt",
    threshold: path("min_pct"),
    scale: 100,
  };
  const openFindings = { op: "ne", left: path("open_findings"), right: value(0) };
  const spec = {
    identity: { slug: "ratio-sec-inspector" },
    checks: [{
      id: "RATIO-1",
      evidenceFields: ["covered", "total", "open_findings", "mode"],
      criteria: {
        constants: { min_pct: 95 },
        rules: [
          { status: "fail", condition: openFindings },
          { status: "warn", condition: ratio },
          { status: "info", condition: { op: "eq", left: path("mode"), right: value("audit") } },
          { status: "pass", condition: { op: "lte", left: value(1), right: path("min_pct") } },
          { status: "manual", condition: { op: "always" } },
        ],
      },
    }],
  };
  const certify = (facts) => certifyRuntimeBoundaryCoverage(spec, new Map([["RATIO-1", facts]]));
  assert.deepEqual(certify([
    { open_findings: 0, covered: 95, total: 100 },
    { open_findings: 2, covered: 90, total: 100 },
  ]), { comparisons: 2, gaps: [] });
  assert.deepEqual(certify([
    { open_findings: 0, covered: 95, total: 100 },
    { open_findings: 0, covered: 5, total: 0 },
  ]).gaps, [
    `RATIO-1 rule 1: runtime facts never fall off the boundary of ${renderVerdictCondition(openFindings)}`,
    `RATIO-1 rule 2: runtime facts never fall below the boundary of ${renderVerdictCondition(ratio)}`,
  ]);
});

test("differential import stubbing keeps available bindings and defers missing ones until use", async () => {
  const source = [
    'import assert from "node:assert/strict";',
    'import { kept, removed as renamed } from "../dist/present.js";',
    'import * as absent from "../dist/absent.js";',
    'import local from "./helpers/local.mjs";',
    "",
  ].join("\n");
  const baselineExports = { "../dist/present.js": ["kept"], "../dist/absent.js": null };
  const rewritten = stubUnavailableImports(source, (specifier) => baselineExports[specifier]);
  assert.match(rewritten, /^function __differentialUnavailable\(/);
  for (const line of [
    'import assert from "node:assert/strict";',
    'import { kept } from "../dist/present.js";',
    'const renamed = __differentialUnavailable("../dist/present.js", "removed");',
    'const absent = __differentialUnavailable("../dist/absent.js", "*");',
    'import local from "./helpers/local.mjs";',
  ]) {
    assert.ok(rewritten.split("\n").includes(line), line);
  }
  assert.equal(stubUnavailableImports(source, () => undefined), source);

  const directory = mkdtempSync(join(tmpdir(), "grclanker-differential-stub-"));
  try {
    const modulePath = join(directory, "stubbed.mjs");
    writeFileSync(modulePath, stubUnavailableImports(
      'import { NEW_SPEC } from "./new.spec.js";\nexport const read = () => NEW_SPEC.checks;\n',
      () => null,
    ));
    const { read } = await import(pathToFileURL(modulePath).href);
    assert.throws(read, {
      message: "NEW_SPEC from ./new.spec.js does not exist in the differential baseline; use it only inside portableContractTest",
    });
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("differential discovery selects runtime tests that write byte fixtures", () => {
  const root = mkdtempSync(join(tmpdir(), "grclanker-differential-discovery-"));
  try {
    mkdirSync(join(root, "cli", "tests"), { recursive: true });
    mkdirSync(join(root, "cli", "extensions", "grc-tools"), { recursive: true });
    const write = (relative, contents) => writeFileSync(join(root, relative), contents);
    const fixtureCall = (integration) => `writeByteDifferentialFixture("${integration}", "compliant", {});\n`;
    write("cli/extensions/grc-tools/alpha.ts", "");
    write("cli/extensions/grc-tools/beta.ts", "");
    write("cli/tests/alpha.test.mjs", fixtureCall("alpha"));
    write("cli/tests/beta.test.mjs", "// Writes no fixtures.\n");
    write("cli/tests/gamma.test.mjs", fixtureCall("gamma"));
    write("cli/tests/alpha-helper.mjs", fixtureCall("alpha"));
    assert.deepEqual(discoverDifferentialTests(root), ["alpha.test.mjs"]);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
