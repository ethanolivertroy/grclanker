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
  const documentedRawVendorStatusFields = new Set(["CF-IAM-02:verified_status"]);
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
      assert.deepEqual(
        Object.keys(check.evidenceFieldDescriptions ?? {}).sort(),
        [...check.evidenceFields].sort(),
        `${check.id}: every declared raw input has exactly one rendered description`,
      );
      for (const name of check.evidenceFields) {
        if (!documentedRawVendorStatusFields.has(`${check.id}:${name}`)) {
          assert.doesNotMatch(name, forbidden, `${check.id}: ${name}`);
        }
        const description = check.evidenceFieldDescriptions?.[name] ?? "";
        assert.ok(description.length >= 40, `${check.id}: ${name} has a substantive portable description`);
        assert.doesNotMatch(
          description,
          /Primitive value computed|complete unsliced .* value for|evidence-derived boolean for|implementation|repository|TypeScript/i,
          `${check.id}: ${name}`,
        );
      }
    }
  }
});

test("batch 2 threshold metadata is exhaustive and renders immutable defaults", () => {
  const scalarConstants = Object.fromEntries(batch.flatMap(([spec]) => spec.checks.flatMap((check) =>
    Object.entries(check.criteria.constants)
      .filter(([, value]) => typeof value === "number")
      .map(([name, value]) => [`${check.id}:${name}`, value]),
  )).sort(([left], [right]) => left.localeCompare(right)));
  assert.deepEqual(scalarConstants, {
    "AZURE-ID-03:warning_ratio_maximum": 0.1,
    "AZURE-ID-04:fail_above_assignments": 10,
    "AZURE-ID-04:maximum_global_admins": 4,
    "AZURE-ID-04:pass_maximum_assignments": 5,
    "AZURE-ID-05:expiring_days": 30,
    "AZURE-ID-05:long_lived_days": 730,
    "AZURE-ID-06:maximum_permanent_privileged_assignments": 2,
    "AZURE-ID-08:stale_days": 90,
    "AZURE-ID-12:expiring_days": 30,
    "AZURE-ID-12:long_lived_days": 730,
    "AZURE-MON-01:pass_minimum_ratio": 0.75,
    "AZURE-MON-01:warn_minimum_ratio": 0.5,
    "AZURE-MON-06:minimum_retention_days": 90,
    "AZURE-SUB-01:default_maximum_owner_assignments": 2,
    "AZURE-SUB-02:default_maximum_contributor_assignments": 5,
    "CF-IAM-03:default_maximum_super_administrators": 2,
    "CF-TRF-04:audit_log_lookback_days": 30,
    "CF-TRF-05:stale_ip_access_rule_days": 365,
    "CF-ZONE-04:minimum_hsts_max_age_seconds": 15_552_000,
    "CF-ZONE-10:certificate_expiry_warning_days": 30,
    "GCP-DATA-03:maximum_kms_rotation_days": 365,
    "GCP-IAM-02:default_maximum_service_account_key_age_days": 90,
    "GCP-LOG-04:minimum_log_retention_days": 90,
    "OCI-GRD-04:maximum_bastion_ttl_seconds": 10_800,
    "OCI-GRD-04:maximum_session_hours": 8,
    "OCI-GRD-05:maximum_key_rotation_days": 365,
    "OCI-GRD-05:minimum_aes_key_bytes": 32,
    "OCI-GRD-05:minimum_rsa_key_bytes": 512,
    "OCI-GRD-06:long_lived_preauthenticated_request_days": 30,
    "OCI-IAM-01:minimum_password_length_required": 14,
    "OCI-IAM-03:maximum_credential_age_days": 365,
    "OCI-LOG-06:minimum_audit_retention_days": 365,
    "PA-01:default_minimum_pass_rate_percent": 90,
    "PA-01:warning_margin_percentage_points": 20,
    "PA-07:maximum_critical_cves": 0,
    "PA-08:minimum_host_compliance_rate_percent": 90,
    "PA-19:default_maximum_superusers": 3,
    "ZS-04:default_maximum_ssl_exemptions": 50,
    "ZS-07:default_maximum_super_administrators": 5,
    "ZS-11:default_stale_connector_days": 30,
    "ZS-13:default_maximum_timeout_hours": 24,
    "ZS-24:default_certificate_expiry_warning_days": 30,
    "ZS-25:maximum_security_allowlist_urls": 100,
  });
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

test("portable numeric operands reject booleans and numeric strings", () => {
  const check = checkContract(PALOALTO_SPEC, "PA-01");
  const base = {
    evidence_readable: true,
    evidence_complete: true,
    passed_resource_count: 60,
    total_resource_count: 100,
  };
  assert.equal(evaluateCheckVerdict(check, { ...base, minimum_pass_rate_percent: 90 }), "fail");
  assert.equal(evaluateCheckVerdict(check, { ...base, minimum_pass_rate_percent: "90" }), "manual");
  assert.equal(evaluateCheckVerdict(check, { ...base, minimum_pass_rate_percent: true }), "manual");
});

test("batch 2 configurable and numeric decision boundaries execute below, equal, and above", () => {
  const cases = [];
  const add = (spec, id, facts, expected) => cases.push({ spec, id, facts, expected });
  const azureBase = { readable: true, complete: true, inventory_count: 20 };
  for (const [without_mfa_ratio, expected] of [[0.09, "warn"], [0.1, "warn"], [0.11, "fail"]]) {
    add(AZURE_SPEC, "AZURE-ID-03", { ...azureBase, without_mfa_count: 1, without_mfa_ratio }, expected);
  }
  for (const [privileged_assignment_count, expected] of [[5, "pass"], [6, "warn"], [11, "fail"]]) {
    add(AZURE_SPEC, "AZURE-ID-04", { ...azureBase, global_admin_count: 0, privileged_assignment_count }, expected);
  }
  for (const [permanent_privileged_count, expected] of [[0, "pass"], [2, "warn"], [3, "fail"]]) {
    add(AZURE_SPEC, "AZURE-ID-06", { ...azureBase, eligible_assignment_count: 1, permanent_privileged_count }, expected);
  }
  for (const [matching_assignment_count, expected] of [[0, "pass"], [2, "warn"], [3, "fail"]]) {
    add(AZURE_SPEC, "AZURE-SUB-01", { ...azureBase, matching_assignment_count, warn_maximum: 2 }, expected);
  }
  for (const [matching_assignment_count, expected] of [[0, "pass"], [5, "warn"], [6, "fail"]]) {
    add(AZURE_SPEC, "AZURE-SUB-02", { ...azureBase, matching_assignment_count, warn_maximum: 5 }, expected);
  }
  for (const [score_ratio, expected] of [[0.49, "fail"], [0.5, "warn"], [0.75, "pass"]]) {
    add(AZURE_SPEC, "AZURE-MON-01", { readable: true, maximum_score: 100, score_ratio }, expected);
  }
  const cloudflareBase = {
    evidence_readable: true,
    evidence_complete: true,
    member_count: 10,
    member_without_two_factor_count: 0,
  };
  for (const [super_administrator_count, maximum_super_administrator_count, expected] of [
    [1, 2, "pass"], [2, 2, "pass"], [3, 2, "fail"],
    [4, 5, "pass"], [5, 5, "pass"], [6, 5, "fail"],
  ]) {
    add(CLOUDFLARE_SPEC, "CF-IAM-03", {
      ...cloudflareBase,
      super_administrator_count,
      maximum_super_administrator_count,
    }, expected);
  }
  for (const [minimum_password_length, expected] of [[13, "fail"], [14, "pass"], [15, "pass"]]) {
    add(OCI_SPEC, "OCI-IAM-01", {
      evidence_readable: true,
      minimum_password_length,
      lowercase_required: true,
      uppercase_required: true,
      numeric_required: true,
      special_required: true,
    }, expected);
  }
  const paloaltoBase = {
    evidence_readable: true,
    evidence_complete: true,
    panos_configured: true,
    prisma_configured: true,
    panos_administrator_count: 5,
    password_complexity_disabled_device_count: 0,
    local_password_only_administrator_count: 0,
    prisma_system_admin_role_count: 0,
    prisma_role_count: 1,
  };
  for (const [panos_superuser_count, maximum_superuser_count, expected] of [
    [2, 3, "pass"], [3, 3, "pass"], [4, 3, "fail"],
    [4, 5, "pass"], [5, 5, "pass"], [6, 5, "fail"],
  ]) {
    add(PALOALTO_SPEC, "PA-19", { ...paloaltoBase, panos_superuser_count, maximum_superuser_count }, expected);
  }
  const zscalerSslBase = {
    evidence_readable: true,
    evidence_complete: true,
    rule_count: 2,
    decrypt_rule_count: 1,
    blanket_bypass_rule_count: 0,
    exemptions_readable: true,
    location_without_ssl_scan_count: 0,
  };
  for (const [exemption_count, maximum_exemption_count, expected] of [
    [49, 50, "pass"], [50, 50, "pass"], [51, 50, "warn"],
    [9, 10, "pass"], [10, 10, "pass"], [11, 10, "warn"],
  ]) {
    add(ZSCALER_SPEC, "ZS-04", { ...zscalerSslBase, exemption_count, maximum_exemption_count }, expected);
  }
  const zscalerBaseline = {
    evidence_readable: true,
    atp_setting_count: 7,
    malware_setting_count: 5,
    missing_atp_flag_count: 0,
    missing_malware_flag_count: 0,
    block_unscannable_files: true,
  };
  for (const [allowlist_url_count, expected] of [[99, "pass"], [100, "pass"], [101, "warn"]]) {
    add(ZSCALER_SPEC, "ZS-25", { ...zscalerBaseline, allowlist_url_count }, expected);
  }
  assert.equal(cases.length, 42);
  for (const { spec, id, facts, expected } of cases) {
    assert.equal(evaluateCheckVerdict(checkContract(spec, id), facts), expected, `${id}: ${JSON.stringify(facts)}`);
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
  assert.ok(CLOUDFLARE_SPEC.knownGaps.some((gap) => /framework mapping.*CF-ZONE-15|CF-ZONE-15.*mapping/i.test(gap)));
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
