import assert from "node:assert/strict";
import test from "node:test";

import {
  AZURE_AUTH_RESOLVER,
  CLOUDFLARE_AUTH_RESOLVER,
  GCP_AUTH_RESOLVER,
  OCI_AUTH_RESOLVER,
  PALOALTO_AUTH_RESOLVER,
  ZSCALER_AUTH_RESOLVER,
} from "../dist/extensions/grc-tools/auth-resolver-contracts.js";
import {
  checkContract,
  collectDefinedGrcTools,
  evaluateCheckVerdict,
} from "../dist/extensions/grc-tools/spec-model.js";
import { AZURE_RUNTIME_BEHAVIOR, AZURE_SPEC } from "../dist/extensions/grc-tools/azure.spec.js";
import { resolveAzureConfiguration } from "../dist/extensions/grc-tools/azure.js";
import { CLOUDFLARE_RUNTIME_BEHAVIOR, CLOUDFLARE_SPEC } from "../dist/extensions/grc-tools/cloudflare.spec.js";
import { resolveCloudflareConfiguration } from "../dist/extensions/grc-tools/cloudflare.js";
import { GCP_RUNTIME_BEHAVIOR, GCP_SPEC } from "../dist/extensions/grc-tools/gcp.spec.js";
import { resolveGcpConfiguration } from "../dist/extensions/grc-tools/gcp.js";
import { OCI_RUNTIME_BEHAVIOR, OCI_SPEC } from "../dist/extensions/grc-tools/oci.spec.js";
import { resolveOciConfiguration } from "../dist/extensions/grc-tools/oci.js";
import { PALOALTO_RUNTIME_BEHAVIOR, PALOALTO_SPEC } from "../dist/extensions/grc-tools/paloalto.spec.js";
import { resolvePaloaltoConfiguration } from "../dist/extensions/grc-tools/paloalto.js";
import { PUBLISHED_INTEGRATION_SPECS } from "../dist/extensions/grc-tools/spec-registry.js";
import { ZSCALER_RUNTIME_BEHAVIOR, ZSCALER_SPEC } from "../dist/extensions/grc-tools/zscaler.spec.js";
import { resolveZscalerConfiguration } from "../dist/extensions/grc-tools/zscaler.js";
import {
  renderAllIntegrationSpecs,
  validateDecisionInputs,
} from "../scripts/generate-integration-specs.mjs";

const batch = [
  [AZURE_SPEC, AZURE_RUNTIME_BEHAVIOR, AZURE_AUTH_RESOLVER],
  [CLOUDFLARE_SPEC, CLOUDFLARE_RUNTIME_BEHAVIOR, CLOUDFLARE_AUTH_RESOLVER],
  [GCP_SPEC, GCP_RUNTIME_BEHAVIOR, GCP_AUTH_RESOLVER],
  [OCI_SPEC, OCI_RUNTIME_BEHAVIOR, OCI_AUTH_RESOLVER],
  [PALOALTO_SPEC, PALOALTO_RUNTIME_BEHAVIOR, PALOALTO_AUTH_RESOLVER],
  [ZSCALER_SPEC, ZSCALER_RUNTIME_BEHAVIOR, ZSCALER_AUTH_RESOLVER],
];

test("batch 2 publishes exactly the six requested adjacent contracts", () => {
  assert.deepEqual(batch.map(([spec]) => spec.identity.slug).sort(), [
    "azure-sec-inspector",
    "cloudflare-sec-inspector",
    "gcp-sec-inspector",
    "oci-sec-inspector",
    "paloalto-sec-inspector",
    "zscaler-sec-inspector",
  ]);
});

test("batch 2 tool definitions carry non-enumerable contracts without changing enumerable bytes", () => {
  const entries = PUBLISHED_INTEGRATION_SPECS.filter((entry) => batch.some(([spec]) => spec === entry.contract));
  assert.equal(entries.length, batch.length);
  for (const entry of entries) {
    const tools = collectDefinedGrcTools(entry.registerTools);
    assert.deepEqual(tools.map((tool) => tool.definition.name).sort(), entry.contract.tools.map((tool) => tool.name).sort());
    for (const tool of tools) {
      const before = JSON.stringify({ ...tool.definition });
      assert.ok(Object.getOwnPropertySymbols(tool.definition).length > 0, `${tool.definition.name}: metadata symbol`);
      assert.equal(JSON.stringify({ ...tool.definition }), before, `${tool.definition.name}: enumerable bytes`);
    }
  }
});

test("batch 2 executable decisions reject undeclared, missing, and null evidence", () => {
  const forbidden = /(?:^|_)(?:status|label|verdict|outcome|compliance|compliant|availability|available|enforcement|enforced)(?:_|$)/;
  for (const [spec] of batch) {
    validateDecisionInputs(spec);
    for (const check of spec.checks) {
      assert.ok(Object.keys(check.derivedFactRules ?? {}).length > 0, `${check.id}: derived rules`);
      assert.equal(Object.keys(check.derivedFactRules).length, check.criteria.rules.length, `${check.id}: branch parity`);
      assert.ok(check.criteria.rules.every((rule) => rule.condition.op === "eq"), `${check.id}: first-match rules consume derived facts`);
      assert.equal(evaluateCheckVerdict(check, {}), "manual", `${check.id}: missing`);
      const nullFacts = Object.fromEntries(check.evidenceFields.map((name) => [name, null]));
      assert.notEqual(evaluateCheckVerdict(check, nullFacts), "pass", `${check.id}: null`);
      assert.throws(
        () => evaluateCheckVerdict(check, { ...nullFacts, legacy_selected_status: "pass" }),
        new RegExp(`${check.id} received undeclared decision input`),
      );
      for (const name of check.evidenceFields) assert.doesNotMatch(name, forbidden, `${check.id}: ${name}`);
    }
  }
});

test("batch 2 generic decisions use complete source counts and preserve violation precedence", () => {
  for (const [spec] of batch) {
    for (const check of spec.checks.filter((candidate) => candidate.evidenceFields.includes("violation_count"))) {
      const complete = {
        evidence_readable: true,
        evidence_complete: true,
        inventory_count: 26,
        violation_count: 0,
        review_count: 0,
      };
      assert.equal(evaluateCheckVerdict(check, complete), "pass", `${check.id}: complete 26-record inventory`);
      assert.equal(evaluateCheckVerdict(check, { ...complete, evidence_complete: false }), "warn", `${check.id}: partial cannot pass`);
      const violationRule = check.criteria.rules.find((rule) => ["fail", "warn"].includes(rule.status) && (
        check.derivedFactRules[rule.condition.left.path]?.condition?.op === "gt"
      ));
      assert.ok(violationRule, `${check.id}: explicit violation branch`);
      assert.equal(
        evaluateCheckVerdict(check, { ...complete, evidence_complete: false, violation_count: 1 }),
        violationRule.status,
        `${check.id}: proved violation precedes partial companion evidence`,
      );
      assert.equal(evaluateCheckVerdict(check, { ...complete, evidence_readable: false }), "manual", `${check.id}: denied`);
    }
  }
});

test("batch 2 contracts use exact runtime resolver metadata", () => {
  for (const [spec, , resolver] of batch) {
    assert.deepEqual(spec.authentication.credentialPrecedence, resolver.precedence);
    assert.deepEqual(spec.authentication.environmentVariables, resolver.environment);
    assert.deepEqual(spec.authentication.configLocations, resolver.configLocations);
    assert.deepEqual(spec.authentication.configFields, resolver.configFields);
    assert.deepEqual(spec.authentication.modes, resolver.modes);
    assert.deepEqual(spec.authentication.variants, resolver.variants);
    assert.equal(spec.authentication.refreshRequest, resolver.refreshRequest);
  }
});

test("batch 2 resolvers read exactly their declared environment names", async () => {
  const trackedEnvironment = () => {
    const accessed = new Set();
    return {
      accessed,
      env: new Proxy({}, {
        get(_target, property) {
          if (typeof property === "string" && /^[A-Z][A-Z0-9_]+$/.test(property)) accessed.add(property);
          return undefined;
        },
      }),
    };
  };
  const cases = [
    [AZURE_AUTH_RESOLVER, resolveAzureConfiguration, [() => undefined]],
    [GCP_AUTH_RESOLVER, resolveGcpConfiguration, [() => undefined, () => undefined]],
    [OCI_AUTH_RESOLVER, resolveOciConfiguration, [() => undefined]],
    [CLOUDFLARE_AUTH_RESOLVER, resolveCloudflareConfiguration, []],
    [PALOALTO_AUTH_RESOLVER, resolvePaloaltoConfiguration, [() => undefined]],
    [ZSCALER_AUTH_RESOLVER, resolveZscalerConfiguration, [() => undefined]],
  ];
  for (const [contract, resolver, extras] of cases) {
    const { env, accessed } = trackedEnvironment();
    try {
      await resolver({}, env, ...extras);
    } catch {
      // Missing credentials are expected; the empty probe exercises resolver fallbacks.
    }
    assert.deepEqual([...accessed].sort(), [...contract.environment].sort());
  }
});

test("batch 2 registry, ownership, framework, and output contracts are complete", () => {
  const outputPaths = new Set();
  for (const [spec, behavior] of batch) {
    assert.deepEqual(spec.knownGaps.slice(0, behavior.length), behavior);
    const surfaceIds = new Set(spec.apiSurfaces.map((surface) => surface.id));
    const tools = new Map(spec.tools.map((tool) => [tool.name, new Set(tool.checkIds)]));
    for (const check of spec.checks) {
      assert.equal(checkContract(spec, check.id), check);
      assert.ok(tools.get(check.owningTool)?.has(check.id), `${check.id}: owning tool`);
      for (const surface of check.sourceSurfaceIds) assert.ok(surfaceIds.has(surface), `${check.id}: ${surface}`);
      for (const controlNumber of check.controlNumbers) {
        const control = spec.controls.find((candidate) => candidate.number === controlNumber);
        assert.ok(control, `${check.id}: control ${controlNumber}`);
        assert.ok(Object.values(control.frameworks).every(Array.isArray), `${check.id}: framework mapping shape`);
      }
    }
    const entry = PUBLISHED_INTEGRATION_SPECS.find((candidate) => candidate.contract === spec);
    assert.ok(entry, `${spec.identity.slug}: registry`);
    assert.ok(!outputPaths.has(entry.outputPath), `${entry.outputPath}: unique output`);
    outputPaths.add(entry.outputPath);
    for (const path of [...spec.output.files, ...spec.output.conditionalFiles]) {
      assert.ok(spec.output.artifacts.some((artifact) => artifact.path === path), `${spec.identity.slug}: ${path}`);
    }
  }
  assert.ok(CLOUDFLARE_SPEC.knownGaps.some((gap) => /CF-ZONE-15.*framework mapping/i.test(gap)));
});

test("batch 2 generated specs are deterministic, portable, and repository-language free", async () => {
  const first = await renderAllIntegrationSpecs();
  const second = await renderAllIntegrationSpecs();
  assert.deepEqual([...first], [...second]);
  for (const entry of PUBLISHED_INTEGRATION_SPECS.filter((candidate) => batch.some(([spec]) => spec === candidate.contract))) {
    const suffix = entry.outputPath.replace("specs/", "");
    const markdown = [...first.entries()].find(([path]) => path.endsWith(suffix))?.[1];
    assert.ok(markdown, entry.outputPath);
    assert.match(markdown, /Rules are evaluated from lowest order number to highest/);
    assert.match(markdown, /Portable derivation/);
    assert.doesNotMatch(markdown, /\b(?:TypeScript|ReadonlyArray|Type\.Object|defineGrcTool|prepareArguments|cli\/extensions)\b/);
  }
});
