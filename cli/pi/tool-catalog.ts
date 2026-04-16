import type { ExtensionAPI, ToolDefinition } from "@mariozechner/pi-coding-agent";
import grcTools from "../extensions/grc-tools.js";

export interface RegisteredToolSummary {
  name: string;
  label: string;
  description: string;
  group: string;
  kind: "compute" | "domain";
  parameters?: unknown;
  parameterSummaries: RegisteredToolParameter[];
}

export interface RegisteredToolParameter {
  name: string;
  type: string;
  required: boolean;
  description?: string;
  defaultValue?: unknown;
  enumValues?: unknown[];
}

const COMPUTE_TOOL_NAMES = new Set(["bash", "read", "write", "edit", "ls", "find", "grep"]);

const DOMAIN_GROUPS: Array<[prefix: string, label: string]> = [
  ["ansible_", "Ansible AAP"],
  ["fedramp_", "FedRAMP"],
  ["cmvp_", "CMVP"],
  ["kevs_", "KEV / EPSS"],
  ["scf_", "SCF"],
  ["oscal_", "OSCAL"],
  ["gws_ops_", "Google Workspace Operator"],
  ["gws_", "Google Workspace"],
  ["github_", "GitHub"],
  ["okta_", "Okta"],
  ["duo_", "Duo"],
  ["slack_", "Slack"],
  ["vanta_", "Vanta"],
];

function resolveToolGroup(name: string): { group: string; kind: RegisteredToolSummary["kind"] } {
  if (COMPUTE_TOOL_NAMES.has(name)) {
    return { group: "Compute Backend", kind: "compute" };
  }

  const match = DOMAIN_GROUPS.find(([prefix]) => name.startsWith(prefix));
  return { group: match?.[1] ?? "Other Domain Tools", kind: "domain" };
}

function asObject(value: unknown): Record<string, unknown> | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
  return value as Record<string, unknown>;
}

function schemaVariants(schema: Record<string, unknown>): Record<string, unknown>[] {
  const anyOf = Array.isArray(schema.anyOf) ? schema.anyOf : undefined;
  const oneOf = Array.isArray(schema.oneOf) ? schema.oneOf : undefined;
  const variants = anyOf ?? oneOf;
  return variants?.map(asObject).filter((value): value is Record<string, unknown> => Boolean(value)) ?? [];
}

function formatSchemaType(schema: Record<string, unknown>): string {
  const variants = schemaVariants(schema);
  if (variants.length > 0) {
    return variants.map(formatSchemaType).join(" | ");
  }

  if (Array.isArray(schema.enum)) {
    return schema.enum.map((value) => JSON.stringify(value)).join(" | ");
  }

  if ("const" in schema) {
    return JSON.stringify(schema.const);
  }

  if (Array.isArray(schema.type)) {
    return schema.type.join(" | ");
  }

  return typeof schema.type === "string" ? schema.type : "value";
}

function schemaEnumValues(schema: Record<string, unknown>): unknown[] | undefined {
  if (Array.isArray(schema.enum)) return schema.enum;

  const variants = schemaVariants(schema);
  const constValues = variants
    .filter((variant) => "const" in variant)
    .map((variant) => variant.const);
  if (constValues.length > 0) return constValues;

  return undefined;
}

function getParameterSummaries(parameters: unknown): RegisteredToolParameter[] {
  const schema = asObject(parameters);
  const properties = asObject(schema?.properties);
  if (!schema || !properties) return [];

  const required = new Set(
    Array.isArray(schema.required)
      ? schema.required.filter((value): value is string => typeof value === "string")
      : [],
  );

  return Object.entries(properties).map(([name, rawProperty]) => {
    const property = asObject(rawProperty) ?? {};
    return {
      name,
      type: formatSchemaType(property),
      required: required.has(name),
      description: typeof property.description === "string" ? property.description : undefined,
      defaultValue: property.default,
      enumValues: schemaEnumValues(property),
    };
  });
}

export function getRegisteredToolSummaries(): RegisteredToolSummary[] {
  const registeredTools: ToolDefinition[] = [];

  const api = {
    registerTool(tool: ToolDefinition) {
      registeredTools.push(tool);
    },
    on() {
      return undefined;
    },
  } as unknown as ExtensionAPI;

  grcTools(api);

  return registeredTools.map((tool) => {
    const { group, kind } = resolveToolGroup(tool.name);
    return {
      name: tool.name,
      label: tool.label,
      description: tool.description,
      group,
      kind,
      parameters: tool.parameters,
      parameterSummaries: getParameterSummaries(tool.parameters),
    };
  });
}

export function groupRegisteredTools(
  tools: RegisteredToolSummary[],
): Array<{ group: string; kind: RegisteredToolSummary["kind"]; tools: RegisteredToolSummary[] }> {
  const groups = new Map<string, { group: string; kind: RegisteredToolSummary["kind"]; tools: RegisteredToolSummary[] }>();

  for (const tool of tools) {
    const key = `${tool.kind}:${tool.group}`;
    const existing = groups.get(key);
    if (existing) {
      existing.tools.push(tool);
    } else {
      groups.set(key, { group: tool.group, kind: tool.kind, tools: [tool] });
    }
  }

  return [...groups.values()].sort((left, right) => {
    if (left.kind !== right.kind) return left.kind === "compute" ? -1 : 1;
    return left.group.localeCompare(right.group);
  });
}

export function formatToolCatalogText(tools: RegisteredToolSummary[]): string {
  const domainCount = tools.filter((tool) => tool.kind === "domain").length;
  const computeCount = tools.filter((tool) => tool.kind === "compute").length;
  const lines = [
    "grclanker tools",
    "",
    `${domainCount} domain tools + ${computeCount} compute backend tools are wired into the bundled extension.`,
    "",
  ];

  for (const group of groupRegisteredTools(tools)) {
    lines.push(`${group.group} (${group.tools.length})`);
    for (const tool of group.tools.sort((left, right) => left.name.localeCompare(right.name))) {
      lines.push(`  ${tool.name} - ${tool.label}`);
    }
    lines.push("");
  }

  return lines.join("\n").trimEnd();
}

export function findRegisteredTool(
  tools: RegisteredToolSummary[],
  name: string,
): RegisteredToolSummary | undefined {
  const normalized = name.trim().toLowerCase();
  return tools.find((tool) => tool.name.toLowerCase() === normalized);
}

export function formatToolDetailText(tool: RegisteredToolSummary): string {
  const lines = [
    `grclanker tool: ${tool.name}`,
    "",
    `Group: ${tool.group}`,
    `Kind: ${tool.kind}`,
    `Label: ${tool.label}`,
    "",
    "Description:",
    `  ${tool.description}`,
    "",
    "Parameters:",
  ];

  if (tool.parameterSummaries.length === 0) {
    lines.push("  none");
  } else {
    for (const parameter of tool.parameterSummaries) {
      const required = parameter.required ? "required" : "optional";
      const description = parameter.description ? ` - ${parameter.description}` : "";
      const defaultValue =
        parameter.defaultValue === undefined ? "" : ` default=${JSON.stringify(parameter.defaultValue)}`;
      lines.push(`  ${parameter.name} (${parameter.type}, ${required}${defaultValue})${description}`);
    }
  }

  return lines.join("\n");
}
