import test from "node:test";
import assert from "node:assert/strict";

import { getRegisteredToolSummaries } from "../dist/pi/tool-catalog.js";

const SNAKE_CASE = /^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$/;
const STANDARD_TOOL_FAMILY =
  /_(?:check_access|assess_[a-z0-9]+(?:_[a-z0-9]+)*|export_audit_bundle)$/;

// These tools intentionally expose reference lookups or workspace workflows
// instead of the check/assess/export integration family.
const REFERENCE_AND_WORKSPACE_TOOL_EXCEPTIONS = [
  "cmvp_get_module",
  "cmvp_search_historical",
  "cmvp_search_in_process",
  "cmvp_search_modules",
  "fedramp_check_sources",
  "fedramp_generate_ads_bundle",
  "fedramp_generate_ads_site",
  "fedramp_get_ksi",
  "fedramp_get_process",
  "fedramp_get_requirement",
  "fedramp_plan_ads_package",
  "fedramp_plan_process_artifacts",
  "fedramp_search_frmr",
  "kevs_check_ransomware",
  "kevs_get_epss",
  "kevs_recent",
  "kevs_search",
  "oscal_assemble_ssp",
  "oscal_check_trestle",
  "oscal_create_model",
  "oscal_generate_ssp_markdown",
  "oscal_import_model",
  "oscal_init_workspace",
  "oscal_validate_model",
  "scf_get_control",
  "scf_get_crosswalk",
  "scf_get_evidence_request",
  "scf_search_controls",
];

// The operator bridge mirrors gws CLI operations rather than the native
// check/assess/export family.
const GWS_OPERATOR_TOOL_EXCEPTIONS = [
  "gws_ops_check_cli",
  "gws_ops_collect_evidence_bundle",
  "gws_ops_investigate_alerts",
  "gws_ops_review_tokens",
  "gws_ops_trace_admin_activity",
];

// Vanta's API surface currently provides these narrower list/export actions.
const VANTA_TOOL_EXCEPTIONS = [
  "vanta_export_audit",
  "vanta_list_audits",
];

const TOOL_FAMILY_EXCEPTIONS = new Set([
  ...REFERENCE_AND_WORKSPACE_TOOL_EXCEPTIONS,
  ...GWS_OPERATOR_TOOL_EXCEPTIONS,
  ...VANTA_TOOL_EXCEPTIONS,
]);

function asObject(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
  return value;
}

function normalizeDescription(value) {
  return typeof value === "string"
    ? value.trim().replace(/\s+/g, " ").toLowerCase()
    : "";
}

function lintDomainRegistry(tools) {
  const errors = [];
  const names = new Map();
  const descriptions = new Map();

  for (const tool of tools) {
    const normalizedName = tool.name.toLowerCase();
    const previousName = names.get(normalizedName);
    if (previousName) {
      errors.push(`${tool.name}: case-insensitive duplicate of ${previousName}`);
    } else {
      names.set(normalizedName, tool.name);
    }

    if (!SNAKE_CASE.test(tool.name)) {
      errors.push(`${tool.name}: tool name must be lowercase snake_case`);
    }

    const normalizedDescription = normalizeDescription(tool.description);
    if (!normalizedDescription) {
      errors.push(`${tool.name}: tool description must be non-empty`);
    } else {
      const previousDescription = descriptions.get(normalizedDescription);
      if (previousDescription) {
        errors.push(`${tool.name}: normalized description duplicates ${previousDescription}`);
      } else {
        descriptions.set(normalizedDescription, tool.name);
      }
    }

    if (!STANDARD_TOOL_FAMILY.test(tool.name) && !TOOL_FAMILY_EXCEPTIONS.has(tool.name)) {
      errors.push(`${tool.name}: tool name does not follow a registered family convention`);
    }

    const schema = asObject(tool.parameters);
    const properties = asObject(schema?.properties);
    if (!properties) {
      errors.push(`${tool.name}: parameter schema must define top-level properties`);
      continue;
    }

    for (const [parameterName, rawParameter] of Object.entries(properties)) {
      if (!SNAKE_CASE.test(parameterName)) {
        errors.push(`${tool.name}.${parameterName}: parameter name must be snake_case`);
      }

      const parameter = asObject(rawParameter);
      if (!normalizeDescription(parameter?.description)) {
        errors.push(`${tool.name}.${parameterName}: parameter needs a top-level description`);
      }
    }

    if (schema.required !== undefined && !Array.isArray(schema.required)) {
      errors.push(`${tool.name}: required must be a string list`);
      continue;
    }

    const required = schema.required ?? [];
    if (required.some((value) => typeof value !== "string")) {
      errors.push(`${tool.name}: required must contain only strings`);
      continue;
    }

    if (new Set(required).size !== required.length) {
      errors.push(`${tool.name}: required must not contain duplicates`);
    }
    for (const parameterName of required) {
      if (!(parameterName in properties)) {
        errors.push(`${tool.name}: required parameter ${parameterName} is missing from properties`);
      }
    }
  }

  return errors;
}

test("built domain tool registry meets quality invariants", () => {
  const domainTools = getRegisteredToolSummaries().filter((tool) => tool.kind === "domain");
  const errors = lintDomainRegistry(domainTools);

  assert.deepEqual(errors, [], errors.join("\n"));
});

test("registry quality lint rejects a malformed synthetic registry", () => {
  const malformedTools = [
    {
      name: "BadTool",
      description: "Duplicate description",
      parameters: {
        properties: {
          badParam: { type: "string" },
        },
        required: ["badParam", "badParam", "missing"],
      },
    },
    {
      name: "badtool",
      description: "  duplicate   DESCRIPTION ",
      parameters: {
        properties: {},
        required: [],
      },
    },
  ];

  const errors = lintDomainRegistry(malformedTools).join("\n");
  assert.match(errors, /case-insensitive duplicate/);
  assert.match(errors, /tool name must be lowercase snake_case/);
  assert.match(errors, /normalized description duplicates/);
  assert.match(errors, /parameter name must be snake_case/);
  assert.match(errors, /parameter needs a top-level description/);
  assert.match(errors, /required must not contain duplicates/);
  assert.match(errors, /required parameter missing is missing from properties/);
  assert.match(errors, /does not follow a registered family convention/);
});
