import { readdir, readFile, rm, writeFile } from "node:fs/promises";
import { dirname, relative, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import {
  SHARED_COLLECTION_STATES,
  SHARED_INTEGRATION_CONTRACT_VERSION,
  SHARED_INTEGRATION_REQUIREMENTS,
  SHARED_REDACTION_RULES,
} from "../dist/extensions/grc-tools/hardening/contract.js";
import { collectDefinedGrcTools } from "../dist/extensions/grc-tools/spec-model.js";
import { PUBLISHED_INTEGRATION_SPECS } from "../dist/extensions/grc-tools/spec-registry.js";

const scriptDir = dirname(fileURLToPath(import.meta.url));
export const repoRoot = resolve(scriptDir, "../..");
export const sharedContractPath = resolve(repoRoot, "specs/integration-contract.md");
const generatedMarker = "<!-- generated integration spec -->";
const reservedHeading = /^#{1,6}\s+(?:Tools|Authentication|API surfaces|Checks|Pagination|Hardening|Export layout)\b/im;
const frameworkColumns = [
  ["fedramp", "FedRAMP"],
  ["cmmc", "CMMC"],
  ["soc2", "SOC 2"],
  ["cis", "CIS"],
  ["pci_dss", "PCI-DSS"],
  ["disa_stig", "DISA STIG"],
  ["irap", "IRAP"],
  ["ismap", "ISMAP"],
];

function escapeCell(value) {
  return String(value).replaceAll("|", "\\|").replaceAll("\n", " ");
}

function listCell(values) {
  return values.length > 0 ? values.map((value) => `\`${escapeCell(value)}\``).join(", ") : "None";
}

function bullets(values) {
  return values.map((value) => `- ${value}`).join("\n");
}

function formatFrontmatter(spec) {
  const { identity } = spec;
  return [
    "---",
    `slug: ${JSON.stringify(identity.slug)}`,
    `name: ${JSON.stringify(identity.displayName)}`,
    `vendor: ${JSON.stringify(identity.vendor)}`,
    `category: ${JSON.stringify(identity.category)}`,
    'language: "language-neutral"',
    'status: "generated"',
    `version: ${JSON.stringify(identity.version)}`,
    `last_updated: ${JSON.stringify(identity.lastUpdated)}`,
    'source_repo: "https://github.com/ethanolivertroy/grclanker"',
    `implementation_kind: ${JSON.stringify(identity.kind)}`,
    "---",
  ].join("\n");
}

function parameterRows(definition) {
  const schema = definition.parameters ?? {};
  const properties = schema.properties ?? {};
  const required = new Set(schema.required ?? []);
  return Object.entries(properties).map(([name, property]) => {
    const type = Array.isArray(property.anyOf)
      ? property.anyOf.map((entry) => entry.type).filter(Boolean).join(" or ")
      : property.type ?? "value";
    return `| \`${escapeCell(name)}\` | ${escapeCell(type)} | ${required.has(name) ? "yes" : "no"} | ${escapeCell(property.description ?? "")} |`;
  });
}

function renderTools(spec, tools) {
  const lines = [
    "## Tools",
    "",
    "| Tool | Purpose | Finding IDs | Result shape |",
    "|---|---|---|---|",
  ];
  for (const { definition, contract } of tools) {
    lines.push(`| \`${definition.name}\` | ${escapeCell(definition.description)} | ${listCell(contract.checkIds)} | ${escapeCell(contract.resultSchema ?? "Registered tool result")} |`);
  }
  lines.push("", "### Parameters", "");
  for (const { definition } of tools) {
    lines.push(`#### \`${definition.name}\``, "", "| Parameter | Kind | Required | Meaning |", "|---|---|---|---|");
    const rows = parameterRows(definition);
    lines.push(...(rows.length > 0 ? rows : ["| None |  |  |  |"]), "");
  }
  return lines.join("\n");
}

function renderAuthentication(spec) {
  const auth = spec.authentication;
  return [
    "## Authentication",
    "",
    "Supported modes:",
    "",
    bullets(auth.modes),
    "",
    "Credential precedence, highest first:",
    "",
    auth.credentialPrecedence.map((value, index) => `${index + 1}. ${value}`).join("\n"),
    "",
    `Environment variables: ${listCell(auth.environmentVariables)}`,
    "",
    `Configuration locations: ${auth.configLocations.join(", ")}`,
    "",
    `Credential and deployment variants: ${auth.variants.join(", ")}`,
    "",
    `Configuration fields: ${listCell(auth.configFields)}`,
    "",
    `Malformed configuration: ${auth.malformedConfigBehavior}`,
    ...(auth.refreshRequest ? ["", `Credential refresh: ${auth.refreshRequest}`] : []),
  ].join("\n");
}

function renderPermissions(spec) {
  return [
    "## Permissions",
    "",
    "| Kind | Permission, role, or plan | Unlocks | Notes |",
    "|---|---|---|---|",
    ...spec.permissions.map((entry) => `| ${escapeCell(entry.kind)} | \`${escapeCell(entry.value)}\` | ${listCell(entry.unlocks)} | ${escapeCell(entry.notes ?? "")} |`),
  ].join("\n");
}

function renderSurfaces(spec) {
  const surfaceTable = [
    "## API surfaces",
    "",
    "| ID | Interface | Read operation | Service or client | IAM action | Intent | Projection stage | Fields consumed | Reference |",
    "|---|---|---|---|---|---|---|---|---|",
    ...spec.apiSurfaces.map((surface) => {
      const operation = surface.kind === "rest" ? `${surface.method} ${surface.path}` : surface.operation;
      return `| \`${surface.id}\` | ${surface.kind === "rest" ? "HTTP" : "service operation"} | \`${escapeCell(operation)}\` | ${escapeCell(surface.sdkService ?? surface.baseService)} | ${surface.iamAction ? `\`${escapeCell(surface.iamAction)}\`` : "N/A"} | ${escapeCell(surface.intent)} | ${escapeCell(surface.projectionStage)} | ${listCell(surface.fieldsConsumed)} | [Official documentation](${surface.documentationUrl}) |`;
    }),
  ];
  const requestRows = spec.apiSurfaces.flatMap((surface) => {
    const base = [
      `| \`${surface.id}\` | client | ${escapeCell(surface.request.clientRegion)} | yes |`,
      `| \`${surface.id}\` | headers | ${escapeCell(surface.request.headers.join("; ") || "None")} | yes |`,
      `| \`${surface.id}\` | response | ${escapeCell(surface.request.responseShape)} | yes |`,
    ];
    return [
      ...base,
      ...surface.request.parameters.map((parameter) => `| \`${surface.id}\` | ${escapeCell(`${parameter.location}:${parameter.name}`)} | ${escapeCell(parameter.value)}${parameter.when ? `; ${escapeCell(parameter.when)}` : ""} | ${parameter.required ? "yes" : "no"} |`),
    ];
  });
  return [
    ...surfaceTable,
    "",
    "### Request construction",
    "",
    "| Surface | Input | Exact value or rule | Required |",
    "|---|---|---|---|",
    ...requestRows,
  ].join("\n");
}

function renderPagination(spec) {
  const rows = spec.pagination.map((entry) => [
    `| ${listCell(entry.surfaceIds)} | ${listCell(entry.cursorFields)} | ${entry.pageSize ?? "service default"} | ${entry.itemCap ?? "caller limit"} | ${entry.pageCap ?? "none"}`,
    `${escapeCell(entry.totalSemantics)} | ${escapeCell(entry.stopConditions.join("; "))} |`,
  ].join(" | "));
  return [
    "## Pagination",
    "",
    "| Surfaces | Cursor or marker | Page size | Item cap | Page cap | Total semantics | Stop conditions |",
    "|---|---|---|---|---|---|---|",
    ...rows,
  ].join("\n");
}

function renderRateLimits(spec) {
  return [
    "## Rate limits",
    "",
    "| Scope | Documented limit | Retry headers | Retryable statuses | Policy |",
    "|---|---|---|---|---|",
    ...spec.rateLimits.map((entry) => `| ${escapeCell(entry.scope)} | ${escapeCell(entry.documentedLimit ?? "Not published")} | ${listCell(entry.retryHeaders)} | ${entry.retryableStatuses.join(", ")} | ${escapeCell(entry.backoffPolicy)} |`),
  ].join("\n");
}

function renderChecks(spec) {
  const checksByControl = new Map(spec.controls.map((control) => [
    control.number,
    spec.checks.filter((check) => check.controlNumbers.includes(control.number)),
  ]));
  const constantRows = spec.checks.flatMap((check) => Object.entries(check.criteria.constants)
    .map(([name, value]) => `| \`${check.id}\` | \`${name}\` | ${escapeCell(Array.isArray(value) ? value.join(", ") : value)} |`));
  const exampleRows = spec.checks.flatMap((check) => check.criteria.examples
    .map((example) => `| \`${check.id}\` | ${example.kind} | ${escapeCell(example.input)} | ${example.expected} | ${escapeCell(example.reason)} |`));
  return [
    "## Checks",
    "",
    "### Control coverage",
    "",
    "| # | Control | Finding | Verdict semantics |",
    "|---|---|---|---|",
    ...spec.controls.map((control) => {
      const checks = checksByControl.get(control.number) ?? [];
      const semantics = checks.length > 0
        ? checks.map((check) => check.criteria.manual).filter((value, index, values) => values.indexOf(value) === index).join(" ")
        : "No automated finding is published for this control.";
      return `| ${control.number} | ${escapeCell(control.title)} | ${checks.map((check) => check.id).join(", ")} | ${escapeCell(semantics)} |`;
    }),
    "",
    "### Finding criteria",
    "",
    "| Finding | Severity | Owning tool | Sources | Evidence fields | Pass | Warn | Fail | Manual |",
    "|---|---|---|---|---|---|---|---|---|",
    ...spec.checks.map((check) => `| \`${check.id}\` | ${check.severity} | \`${check.owningTool}\` | ${listCell(check.sourceSurfaceIds)} | ${listCell(check.evidenceFields)} | ${escapeCell(check.criteria.pass)} | ${escapeCell(check.criteria.warn)} | ${escapeCell(check.criteria.fail)} | ${escapeCell(check.criteria.manual)} |`),
    "",
    "### Criterion constants",
    "",
    "| Finding | Name | Value |",
    "|---|---|---|",
    ...(constantRows.length > 0 ? constantRows : ["| None |  |  |"]),
    "",
    "### Criterion examples",
    "",
    "| Finding | Case | Input condition | Expected | Reason |",
    "|---|---|---|---|---|",
    ...exampleRows,
    "",
    "### Compliance framework mappings",
    "",
    `| # | Control | ${frameworkColumns.map(([, label]) => label).join(" | ")} |`,
    `|---|---|${frameworkColumns.map(() => "---").join("|")}|`,
    ...spec.controls.map((control) => `| ${control.number} | ${escapeCell(control.title)} | ${frameworkColumns.map(([key]) => escapeCell(control.frameworks[key].join(", ") || "-")).join(" | ")} |`),
  ].join("\n");
}

function renderCollectionStates(spec) {
  const labels = [
    ["complete", spec.collectionStates.complete],
    ["truncated", spec.collectionStates.truncated],
    ["unreadable", spec.collectionStates.unreadable],
    ["denied", spec.collectionStates.denied],
    ["not requested", spec.collectionStates.notRequested],
    ["not configured", spec.collectionStates.notConfigured],
  ];
  return [
    "## Collection states",
    "",
    "| State | Required rendering |",
    "|---|---|",
    ...labels.map(([state, text]) => `| ${state} | ${escapeCell(text)} |`),
  ].join("\n");
}

function renderRedaction(spec) {
  return [
    "## Integration-specific scrubbing",
    "",
    `Shared contract version: ${spec.redaction.sharedContractVersion}.`,
    "",
    `Projection stage: ${spec.redaction.projectionStage}`,
    "",
    `Sensitive fields and values: ${spec.redaction.sensitiveFields.join(", ")}`,
    "",
    `Credential formats: ${spec.redaction.credentialFormats.join(", ")}`,
    "",
    `Reviewed benign exceptions: ${spec.redaction.benignExceptions.join(", ")}`,
    "",
    "Integration-specific rules:",
    "",
    bullets(spec.redaction.integrationRules),
    "",
    "Projected fields by surface:",
    "",
    "| Surface | Allowed fields |",
    "|---|---|",
    ...Object.entries(spec.redaction.projections).map(([surface, fields]) => `| \`${surface}\` | ${listCell(fields)} |`),
  ].join("\n");
}

function renderExport(spec) {
  return [
    "## Export layout",
    "",
    "Required paths:",
    "",
    bullets(spec.output.files.map((path) => `\`${path}\``)),
    "",
    "Conditional paths:",
    "",
    bullets(spec.output.conditionalFiles.map((path) => `\`${path}\``)),
    "",
    "### Artifact schemas",
    "",
    "| Path | Format | Required when | Schema | Serialization |",
    "|---|---|---|---|---|",
    ...spec.output.artifacts.map((artifact) => `| \`${artifact.path}\` | ${artifact.format} | ${escapeCell(artifact.requiredWhen)} | ${escapeCell(artifact.schema)} | ${escapeCell(artifact.serialization)} |`),
    "",
    "### Record schemas",
    "",
    ...Object.entries(spec.output.recordSchemas).flatMap(([name, fields]) => [
      `#### ${name}`,
      "",
      ...fields.map((field) => `- \`${field}\``),
      "",
    ]),
    `JSON formatting: ${spec.output.jsonFormatting}`,
    "",
    `Overwrite policy: ${spec.output.overwritePolicy}`,
    "",
    `Path safety: ${spec.output.pathSafetyPolicy}`,
    "",
    `Archive pairing: ${spec.output.archivePairing}`,
  ].join("\n");
}

export function validateNarrative(narrative, path) {
  if (reservedHeading.test(narrative)) {
    throw new Error(`${path} uses a heading reserved for generated content`);
  }
  if (/^---\s*$/m.test(narrative)) {
    throw new Error(`${path} must not contain frontmatter`);
  }
}

export function renderIntegrationSpec(entry, narrative, tools) {
  const spec = entry.contract;
  validateNarrative(narrative, entry.narrativePath);
  return [
    formatFrontmatter(spec),
    "",
    generatedMarker,
    "> Generated from the executable integration registry, registered tool definitions, and the adjacent narrative source. Edit those sources, not this file.",
    "",
    `# ${spec.identity.displayName}`,
    "",
    spec.identity.summary,
    "",
    narrative.trim(),
    "",
    "## Shared integration contract",
    "",
    `This specification requires [shared integration contract version ${SHARED_INTEGRATION_CONTRACT_VERSION}](./integration-contract.md). The raw contract is available at https://raw.githubusercontent.com/ethanolivertroy/grclanker/main/specs/integration-contract.md.`,
    ...(spec.knownGaps.length > 0 ? ["", "## Known runtime gaps", "", ...spec.knownGaps.map((gap) => `- ${gap}`)] : []),
    "",
    renderTools(spec, tools),
    "",
    renderAuthentication(spec),
    "",
    renderPermissions(spec),
    "",
    renderSurfaces(spec),
    "",
    renderPagination(spec),
    "",
    renderRateLimits(spec),
    "",
    renderChecks(spec),
    "",
    renderCollectionStates(spec),
    "",
    renderRedaction(spec),
    "",
    renderExport(spec),
    "",
  ].join("\n");
}

export function renderSharedContract() {
  const sections = [
    ["Collection and null semantics", SHARED_INTEGRATION_REQUIREMENTS.collection],
    ["Pagination and truncation", SHARED_INTEGRATION_REQUIREMENTS.pagination],
    ["Verdict integrity", SHARED_INTEGRATION_REQUIREMENTS.verdicts],
    ["Credential and error scrubbing", SHARED_INTEGRATION_REQUIREMENTS.scrubbing],
    ["Safe evidence bundles", SHARED_INTEGRATION_REQUIREMENTS.exports],
  ];
  return [
    "---",
    'slug: "integration-contract"',
    'name: "Shared Integration Contract"',
    'vendor: "grclanker"',
    'category: "community-specs"',
    'language: "language-neutral"',
    'status: "generated"',
    `version: ${JSON.stringify(SHARED_INTEGRATION_CONTRACT_VERSION)}`,
    'last_updated: "2026-09-27"',
    'source_repo: "https://github.com/ethanolivertroy/grclanker"',
    "---",
    "",
    "<!-- generated shared integration contract -->",
    "> Generated from the executable shared hardening vocabulary and credential scrubber contract. Edit those sources, not this file.",
    "",
    "# Shared integration contract",
    "",
    "Every portable integration implementation must reproduce these rules. Integration specifications list only additions and reviewed exceptions.",
    "",
    `Contract version: ${SHARED_INTEGRATION_CONTRACT_VERSION}`,
    "",
    ...sections.flatMap(([heading, requirements]) => [`## ${heading}`, "", ...requirements.map((requirement) => `- ${requirement}`), ""]),
    "## Exact redaction rules",
    "",
    "| Rule | Match | Replacement | Must keep |",
    "|---|---|---|---|",
    ...SHARED_REDACTION_RULES.map((rule) => `| \`${rule.id}\` | ${escapeCell(rule.match)} | ${escapeCell(rule.replacement)} | ${escapeCell(rule.preserve)} |`),
    "",
    "## Collection-state vocabulary",
    "",
    SHARED_COLLECTION_STATES.map((state) => `- \`${state.replaceAll("_", " ")}\``).join("\n"),
    "",
  ].join("\n");
}

export async function renderAllIntegrationSpecs() {
  const outputs = new Map([[sharedContractPath, renderSharedContract()]]);
  for (const entry of PUBLISHED_INTEGRATION_SPECS) {
    const narrativePath = resolve(repoRoot, entry.narrativePath);
    const narrative = await readFile(narrativePath, "utf8");
    const tools = collectDefinedGrcTools(entry.registerTools);
    const expectedNames = entry.contract.tools.map((tool) => tool.name).sort();
    const actualNames = tools.map((tool) => tool.definition.name).sort();
    if (JSON.stringify(expectedNames) !== JSON.stringify(actualNames)) {
      throw new Error(`${entry.contract.identity.slug} registered tools do not match its published tool contracts`);
    }
    outputs.set(resolve(repoRoot, entry.outputPath), renderIntegrationSpec(entry, narrative, tools));
  }
  return outputs;
}

async function generatedSpecPaths() {
  const specsDir = resolve(repoRoot, "specs");
  const names = await readdir(specsDir);
  const paths = names.filter((name) => name.endsWith(".spec.md")).map((name) => resolve(specsDir, name));
  const generated = [];
  for (const path of paths) {
    if ((await readFile(path, "utf8")).includes(generatedMarker)) generated.push(path);
  }
  return generated;
}

export async function checkIntegrationSpecs() {
  const outputs = await renderAllIntegrationSpecs();
  const stale = [];
  for (const [path, expected] of outputs) {
    const actual = await readFile(path, "utf8").catch(() => undefined);
    if (actual !== expected) stale.push(relative(repoRoot, path));
  }
  const expectedGenerated = new Set([...outputs.keys()].filter((path) => path.endsWith(".spec.md")));
  for (const path of await generatedSpecPaths()) {
    if (!expectedGenerated.has(path)) stale.push(relative(repoRoot, path));
  }
  return [...new Set(stale)].sort();
}

export async function writeIntegrationSpecs() {
  const outputs = await renderAllIntegrationSpecs();
  for (const [path, content] of outputs) await writeFile(path, content, "utf8");
  const expectedGenerated = new Set([...outputs.keys()].filter((path) => path.endsWith(".spec.md")));
  for (const path of await generatedSpecPaths()) {
    if (!expectedGenerated.has(path)) await rm(path);
  }
  return [...outputs.keys()];
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  if (process.argv.includes("--check")) {
    const stale = await checkIntegrationSpecs();
    if (stale.length > 0) {
      console.error("Generated integration specs are stale:");
      for (const path of stale) console.error(`- ${path}`);
      console.error("Run: npm --prefix cli run sync:integration-specs");
      process.exitCode = 1;
    } else {
      console.log("Generated integration specs are current.");
    }
  } else {
    const paths = await writeIntegrationSpecs();
    for (const path of paths) console.log(`Wrote ${relative(repoRoot, path)}`);
  }
}
