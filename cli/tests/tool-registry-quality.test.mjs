import test from "node:test";
import assert from "node:assert/strict";

import { getRegisteredToolSummaries } from "../dist/pi/tool-catalog.js";

const SNAKE_CASE = /^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$/;
const STANDARD_TOOL_FAMILY =
  /_(?:check_access|assess_[a-z0-9]+(?:_[a-z0-9]+)*|export_[a-z0-9]+(?:_[a-z0-9]+)*)$/;

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

// Vanta's API surface currently provides this narrower list action.
const VANTA_TOOL_EXCEPTIONS = ["vanta_list_audits"];

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

function lintDomainRegistry(tools, familyExceptions = TOOL_FAMILY_EXCEPTIONS) {
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

    if (!STANDARD_TOOL_FAMILY.test(tool.name) && !familyExceptions.has(tool.name)) {
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

  for (const exceptionName of familyExceptions) {
    if (!names.has(exceptionName)) {
      errors.push(`${exceptionName}: naming exception is not registered`);
    }
    if (STANDARD_TOOL_FAMILY.test(exceptionName)) {
      errors.push(`${exceptionName}: conventional tool must not remain a naming exception`);
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

  const errors = lintDomainRegistry(malformedTools, new Set()).join("\n");
  assert.match(errors, /case-insensitive duplicate/);
  assert.match(errors, /tool name must be lowercase snake_case/);
  assert.match(errors, /normalized description duplicates/);
  assert.match(errors, /parameter name must be snake_case/);
  assert.match(errors, /parameter needs a top-level description/);
  assert.match(errors, /required must not contain duplicates/);
  assert.match(errors, /required parameter missing is missing from properties/);
  assert.match(errors, /does not follow a registered family convention/);
});

test("registry quality lint rejects an empty tool description", () => {
  const errors = lintDomainRegistry([
    {
      name: "synthetic_check_access",
      description: " \n ",
      parameters: { properties: {}, required: [] },
    },
  ], new Set());

  assert.deepEqual(errors, ["synthetic_check_access: tool description must be non-empty"]);
});

test("registry quality lint handles malformed and omitted schema fields", () => {
  const validWithoutRequired = {
    name: "optional_schema_check_access",
    description: "Valid schema with no required parameters.",
    parameters: {
      properties: {
        optional_value: {
          type: "string",
          description: "Optional value.",
        },
      },
    },
  };
  assert.deepEqual(lintDomainRegistry([validWithoutRequired], new Set()), []);

  const malformedTools = [
    {
      name: "missing_properties_check_access",
      description: "Schema with missing properties.",
      parameters: { required: [] },
    },
    {
      name: "malformed_properties_check_access",
      description: "Schema with malformed properties.",
      parameters: { properties: [], required: [] },
    },
    {
      name: "malformed_required_check_access",
      description: "Schema with malformed required.",
      parameters: { properties: {}, required: "value" },
    },
    {
      name: "non_string_required_check_access",
      description: "Schema with a non-string required entry.",
      parameters: {
        properties: {
          value: {
            type: "string",
            description: "Required value.",
          },
        },
        required: ["value", 42],
      },
    },
    {
      name: "missing_required_property_check_access",
      description: "Schema requiring an undeclared property.",
      parameters: { properties: {}, required: ["missing"] },
    },
  ];

  const errors = lintDomainRegistry(malformedTools, new Set()).join("\n");
  assert.match(errors, /missing_properties_check_access: parameter schema must define top-level properties/);
  assert.match(errors, /malformed_properties_check_access: parameter schema must define top-level properties/);
  assert.match(errors, /malformed_required_check_access: required must be a string list/);
  assert.match(errors, /non_string_required_check_access: required must contain only strings/);
  assert.match(
    errors,
    /missing_required_property_check_access: required parameter missing is missing from properties/,
  );
});
