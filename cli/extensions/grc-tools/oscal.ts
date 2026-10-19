/**
 * OSCAL + compliance-trestle helpers for grclanker.
 *
 * This slice keeps the interface practical:
 * - verify trestle availability
 * - initialize a trestle workspace
 * - import or create starter OSCAL models
 * - validate existing models
 * - run the SSP markdown round-trip used by compliance-trestle authoring
 */
import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readdirSync } from "node:fs";
import { readdir } from "node:fs/promises";
import { isAbsolute, join, resolve } from "node:path";
import { Type } from "@sinclair/typebox";
import { errorResult, formatTable, textResult } from "./shared.js";

const DEFAULT_WORKSPACE_DIR = "./oscal-workspace";
const TRESTLE_ENV_KEYS = ["GRCLANKER_TRESTLE_BIN", "TRESTLE_BIN"] as const;

const OSCAL_MODEL_DIRS = {
  catalog: "catalogs",
  profile: "profiles",
  "component-definition": "component-definitions",
  "system-security-plan": "system-security-plans",
  "assessment-plan": "assessment-plans",
  "assessment-results": "assessment-results",
  "plan-of-action-and-milestones": "plan-of-action-and-milestones",
} as const;

export type OscalModelType = keyof typeof OSCAL_MODEL_DIRS;
type WorkspaceMode = "full" | "local" | "govdocs";
type FileFormat = "json" | "yaml" | "yml";

type OscalCheckArgs = {
  workspace_dir?: string;
};

type OscalInitArgs = {
  workspace_dir?: string;
  mode?: WorkspaceMode;
};

type OscalImportArgs = {
  workspace_dir: string;
  file: string;
  output: string;
  regenerate_uuids?: boolean;
};

type OscalCreateArgs = {
  workspace_dir: string;
  model_type: string;
  name: string;
  format?: FileFormat;
  include_optional_fields?: boolean;
};

type OscalValidateArgs = {
  workspace_dir: string;
  file?: string;
  model_type?: string;
  name?: string;
  all?: boolean;
  quiet?: boolean;
};

type OscalSspGenerateArgs = {
  workspace_dir: string;
  profile: string;
  output: string;
  component_definitions?: string[];
  leveraged_ssp?: string;
  yaml_header?: string;
  force_overwrite?: boolean;
  overwrite_header_values?: boolean;
  include_all_parts?: boolean;
};

type OscalSspAssembleArgs = {
  workspace_dir: string;
  markdown: string;
  output: string;
  component_definitions?: string[];
  source_ssp_name?: string;
  regenerate_uuids?: boolean;
  version?: string;
};

type TrestleExecution = {
  executable: string;
  displayExecutable: string;
  exitCode: number;
  stdout: string;
  stderr: string;
};

type TrestleCommandOptions = {
  cwd: string;
  env?: NodeJS.ProcessEnv;
  signal?: AbortSignal;
};

export type TrestleRunner = (
  args: string[],
  options: TrestleCommandOptions,
) => Promise<TrestleExecution>;

export interface TrestleWorkspaceInspection {
  workspaceDir: string;
  exists: boolean;
  isWorkspace: boolean;
  hasDist: boolean;
  modelCounts: Record<OscalModelType, number>;
}

export interface OscalTrestleStatus {
  installed: boolean;
  version?: string;
  executable?: string;
  workspace: TrestleWorkspaceInspection;
  recommendedNextStep: string;
  notes: string[];
}

export interface OscalImportResult {
  workspaceDir: string;
  outputName: string;
  modelType: OscalModelType | null;
  importedPath: string | null;
}

export interface OscalCreateResult {
  workspaceDir: string;
  modelType: OscalModelType;
  modelName: string;
  format: FileFormat;
  filePath: string;
}

export interface OscalValidateResult {
  workspaceDir: string;
  selector: string;
}

export interface OscalSspGenerateResult {
  workspaceDir: string;
  outputDir: string;
  controlMarkdownCount: number;
  hasInheritanceView: boolean;
}

export interface OscalSspAssembleResult {
  workspaceDir: string;
  outputName: string;
  filePath: string | null;
}

const MODEL_TYPE_ALIASES = new Map<string, OscalModelType>([
  ["catalog", "catalog"],
  ["profile", "profile"],
  ["componentdefinition", "component-definition"],
  ["componentdef", "component-definition"],
  ["compdef", "component-definition"],
  ["component", "component-definition"],
  ["systemsecurityplan", "system-security-plan"],
  ["ssp", "system-security-plan"],
  ["assessmentplan", "assessment-plan"],
  ["sap", "assessment-plan"],
  ["assessmentresults", "assessment-results"],
  ["sar", "assessment-results"],
  ["planofactionandmilestones", "plan-of-action-and-milestones"],
  ["poam", "plan-of-action-and-milestones"],
  ["poamitem", "plan-of-action-and-milestones"],
]);

function asString(value: unknown): string | undefined {
  if (typeof value === "string") {
    const trimmed = value.trim();
    return trimmed.length > 0 ? trimmed : undefined;
  }

  if (typeof value === "number" && Number.isFinite(value)) {
    return String(value);
  }

  return undefined;
}

function asBoolean(value: unknown): boolean | undefined {
  if (typeof value === "boolean") return value;

  if (typeof value === "string") {
    const normalized = value.trim().toLowerCase();
    if (normalized === "true") return true;
    if (normalized === "false") return false;
  }

  return undefined;
}

function canonicalizeChoice(value: string): string {
  return value.trim().toLowerCase().replace(/[^a-z0-9]+/g, "");
}

export function resolveOscalModelType(value: string): OscalModelType {
  const match = MODEL_TYPE_ALIASES.get(canonicalizeChoice(value));
  if (!match) {
    throw new Error(
      `Unsupported OSCAL model type "${value}". Use catalog, profile, component-definition, system-security-plan (ssp), assessment-plan (sap), assessment-results (sar), or plan-of-action-and-milestones (poam).`,
    );
  }
  return match;
}

function normalizeWorkspaceMode(value: unknown): WorkspaceMode {
  const normalized = asString(value)?.toLowerCase();
  if (normalized === "full" || normalized === "local" || normalized === "govdocs") {
    return normalized;
  }
  return "local";
}

function normalizeFileFormat(value: unknown): FileFormat {
  const normalized = asString(value)?.toLowerCase();
  if (normalized === "yaml" || normalized === "yml" || normalized === "json") {
    return normalized;
  }
  return "json";
}

function normalizeWorkspaceDir(value: unknown, fallback: string): string {
  return resolve(process.cwd(), asString(value) ?? fallback);
}

function normalizeStringList(value: unknown): string[] | undefined {
  if (Array.isArray(value)) {
    const items = value
      .map((entry) => asString(entry))
      .filter((entry): entry is string => Boolean(entry));
    return items.length > 0 ? items : undefined;
  }

  const single = asString(value);
  if (!single) return undefined;
  return single.split(",").map((item) => item.trim()).filter(Boolean);
}

function normalizeCheckArgs(args: unknown): OscalCheckArgs {
  if (args && typeof args === "object") {
    const value = args as Record<string, unknown>;
    return {
      workspace_dir: asString(value.workspace_dir) ?? asString(value.workspace),
    };
  }
  return {};
}

function normalizeInitArgs(args: unknown): OscalInitArgs {
  if (args && typeof args === "object") {
    const value = args as Record<string, unknown>;
    return {
      workspace_dir: asString(value.workspace_dir) ?? asString(value.workspace),
      mode: normalizeWorkspaceMode(value.mode),
    };
  }
  return { mode: "local" };
}

function normalizeImportArgs(args: unknown): OscalImportArgs {
  if (typeof args === "string") {
    return {
      workspace_dir: normalizeWorkspaceDir(undefined, DEFAULT_WORKSPACE_DIR),
      file: args,
      output: "imported-model",
    };
  }

  if (args && typeof args === "object") {
    const value = args as Record<string, unknown>;
    return {
      workspace_dir: normalizeWorkspaceDir(
        value.workspace_dir ?? value.workspace,
        DEFAULT_WORKSPACE_DIR,
      ),
      file: asString(value.file) ?? asString(value.path) ?? asString(value.url) ?? "",
      output: asString(value.output) ?? asString(value.name) ?? "imported-model",
      regenerate_uuids: asBoolean(value.regenerate_uuids) ?? asBoolean(value.regenerate),
    };
  }

  return {
    workspace_dir: normalizeWorkspaceDir(undefined, DEFAULT_WORKSPACE_DIR),
    file: "",
    output: "imported-model",
  };
}

function normalizeCreateArgs(args: unknown): OscalCreateArgs {
  if (typeof args === "string") {
    return {
      workspace_dir: normalizeWorkspaceDir(undefined, DEFAULT_WORKSPACE_DIR),
      model_type: args,
      name: "sample-model",
      format: "json",
    };
  }

  if (args && typeof args === "object") {
    const value = args as Record<string, unknown>;
    return {
      workspace_dir: normalizeWorkspaceDir(
        value.workspace_dir ?? value.workspace,
        DEFAULT_WORKSPACE_DIR,
      ),
      model_type:
        asString(value.model_type) ??
        asString(value.type) ??
        asString(value.model) ??
        "",
      name: asString(value.name) ?? asString(value.output) ?? "sample-model",
      format: normalizeFileFormat(value.format ?? value.extension),
      include_optional_fields:
        asBoolean(value.include_optional_fields) ??
        asBoolean(value.includeOptionalFields) ??
        asBoolean(value.include_optional),
    };
  }

  return {
    workspace_dir: normalizeWorkspaceDir(undefined, DEFAULT_WORKSPACE_DIR),
    model_type: "",
    name: "sample-model",
    format: "json",
  };
}

function normalizeValidateArgs(args: unknown): OscalValidateArgs {
  if (typeof args === "string") {
    return {
      workspace_dir: normalizeWorkspaceDir(undefined, DEFAULT_WORKSPACE_DIR),
      file: args,
      quiet: true,
    };
  }

  if (args && typeof args === "object") {
    const value = args as Record<string, unknown>;
    return {
      workspace_dir: normalizeWorkspaceDir(
        value.workspace_dir ?? value.workspace,
        DEFAULT_WORKSPACE_DIR,
      ),
      file: asString(value.file) ?? asString(value.path),
      model_type: asString(value.model_type) ?? asString(value.type),
      name: asString(value.name),
      all: asBoolean(value.all),
      quiet: asBoolean(value.quiet) ?? true,
    };
  }

  return {
    workspace_dir: normalizeWorkspaceDir(undefined, DEFAULT_WORKSPACE_DIR),
    quiet: true,
  };
}

function normalizeSspGenerateArgs(args: unknown): OscalSspGenerateArgs {
  if (args && typeof args === "object") {
    const value = args as Record<string, unknown>;
    return {
      workspace_dir: normalizeWorkspaceDir(
        value.workspace_dir ?? value.workspace,
        DEFAULT_WORKSPACE_DIR,
      ),
      profile: asString(value.profile) ?? "",
      output: asString(value.output) ?? asString(value.markdown_dir) ?? "ssp-markdown",
      component_definitions:
        normalizeStringList(value.component_definitions) ??
        normalizeStringList(value.compdefs),
      leveraged_ssp: asString(value.leveraged_ssp) ?? asString(value.leveragedSsp),
      yaml_header: asString(value.yaml_header) ?? asString(value.yamlHeader),
      force_overwrite: asBoolean(value.force_overwrite) ?? asBoolean(value.forceOverwrite),
      overwrite_header_values:
        asBoolean(value.overwrite_header_values) ??
        asBoolean(value.overwriteHeaderValues),
      include_all_parts:
        asBoolean(value.include_all_parts) ?? asBoolean(value.includeAllParts),
    };
  }

  return {
    workspace_dir: normalizeWorkspaceDir(undefined, DEFAULT_WORKSPACE_DIR),
    profile: "",
    output: "ssp-markdown",
  };
}

function normalizeSspAssembleArgs(args: unknown): OscalSspAssembleArgs {
  if (args && typeof args === "object") {
    const value = args as Record<string, unknown>;
    return {
      workspace_dir: normalizeWorkspaceDir(
        value.workspace_dir ?? value.workspace,
        DEFAULT_WORKSPACE_DIR,
      ),
      markdown: asString(value.markdown) ?? asString(value.markdown_dir) ?? "",
      output: asString(value.output) ?? asString(value.name) ?? "assembled-ssp",
      component_definitions:
        normalizeStringList(value.component_definitions) ??
        normalizeStringList(value.compdefs),
      source_ssp_name: asString(value.source_ssp_name) ?? asString(value.name),
      regenerate_uuids:
        asBoolean(value.regenerate_uuids) ?? asBoolean(value.regenerate),
      version: asString(value.version),
    };
  }

  return {
    workspace_dir: normalizeWorkspaceDir(undefined, DEFAULT_WORKSPACE_DIR),
    markdown: "",
    output: "assembled-ssp",
  };
}

function findExecutableOnPath(command: string): string | undefined {
  const locator = process.platform === "win32" ? "where" : "which";
  const result = spawnSync(locator, [command], { encoding: "utf8" });
  if (result.status !== 0) return undefined;
  return result.stdout
    .split(/\r?\n/)
    .map((line) => line.trim())
    .find((line) => line.length > 0);
}

export function resolveTrestleExecutable(
  env: NodeJS.ProcessEnv = process.env,
): { executable: string; displayExecutable: string } {
  for (const key of TRESTLE_ENV_KEYS) {
    const configured = env[key]?.trim();
    if (configured) {
      return {
        executable: configured,
        displayExecutable: configured,
      };
    }
  }

  const found = findExecutableOnPath("trestle");
  if (found) {
    return {
      executable: found,
      displayExecutable: found,
    };
  }

  return {
    executable: "trestle",
    displayExecutable: "trestle",
  };
}

function buildTrestleInstallGuidance(): string {
  return [
    "Trestle is not installed or not on PATH.",
    "Install it with `python3 -m pip install compliance-trestle`, or point `GRCLANKER_TRESTLE_BIN` at the trestle executable.",
  ].join(" ");
}

async function runTrestleCommand(
  args: string[],
  options: TrestleCommandOptions,
): Promise<TrestleExecution> {
  options.signal?.throwIfAborted();
  const resolved = resolveTrestleExecutable(options.env);
  return new Promise((resolvePromise, reject) => {
    const child = spawn(resolved.executable, args, {
      cwd: options.cwd,
      env: { ...process.env, ...options.env },
      stdio: ["ignore", "pipe", "pipe"],
      signal: options.signal,
    });

    let stdout = "";
    let stderr = "";

    child.stdout.on("data", (chunk) => {
      stdout += chunk.toString();
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString();
    });

    child.on("error", (error) => {
      const code = (error as NodeJS.ErrnoException).code;
      if (code === "ENOENT") {
        reject(new Error(buildTrestleInstallGuidance()));
        return;
      }
      reject(error);
    });

    child.on("close", (exitCode) => {
      resolvePromise({
        executable: resolved.executable,
        displayExecutable: resolved.displayExecutable,
        exitCode: exitCode ?? 1,
        stdout: stdout.trim(),
        stderr: stderr.trim(),
      });
    });
  });
}

function trestleRunnerFor(signal: AbortSignal | undefined): TrestleRunner {
  return signal ? (args, options) => runTrestleCommand(args, { ...options, signal }) : runTrestleCommand;
}

function ensureWorkspaceExists(workspaceDir: string): void {
  if (!existsSync(workspaceDir)) {
    throw new Error(
      `Workspace directory "${workspaceDir}" does not exist. Run oscal_init_workspace first.`,
    );
  }
}

function ensureTrestleWorkspace(workspaceDir: string): void {
  ensureWorkspaceExists(workspaceDir);
  if (!existsSync(join(workspaceDir, ".trestle"))) {
    throw new Error(
      `Workspace "${workspaceDir}" is not a trestle workspace yet. Run oscal_init_workspace first.`,
    );
  }
}

export function inspectTrestleWorkspace(workspaceDir: string): TrestleWorkspaceInspection {
  const resolvedDir = resolve(process.cwd(), workspaceDir);
  const exists = existsSync(resolvedDir);
  const isWorkspace = exists && existsSync(join(resolvedDir, ".trestle"));
  const hasDist = exists && existsSync(join(resolvedDir, "dist"));
  const modelCounts = Object.fromEntries(
    Object.keys(OSCAL_MODEL_DIRS).map((modelType) => [modelType, 0]),
  ) as Record<OscalModelType, number>;

  if (exists) {
    for (const [modelType, dirName] of Object.entries(OSCAL_MODEL_DIRS) as Array<
      [OscalModelType, string]
    >) {
      const modelDir = join(resolvedDir, dirName);
      if (!existsSync(modelDir)) continue;
      const count = readdirSync(modelDir, { withFileTypes: true })
        .filter((entry) => entry.isDirectory())
        .length;
      modelCounts[modelType] = count;
    }
  }

  return {
    workspaceDir: resolvedDir,
    exists,
    isWorkspace,
    hasDist,
    modelCounts,
  };
}

function summarizeCommandFailure(result: TrestleExecution): string {
  const message = [result.stderr, result.stdout].find((value) => value.trim().length > 0);
  return message ?? "trestle returned a non-zero exit code without additional output.";
}

function resolveRelativeToWorkspace(workspaceDir: string, value: string): string {
  if (/^[a-z]+:\/\//i.test(value)) {
    return value;
  }

  if (value.startsWith("/")) {
    return value;
  }

  return resolve(workspaceDir, value);
}

function joinCommaList(values: string[] | undefined): string | undefined {
  if (!values?.length) return undefined;
  return values.join(",");
}

async function countMarkdownFiles(
  root: string,
  ignoredDirectories: Set<string> = new Set(),
): Promise<number> {
  let count = 0;
  const entries = await readdir(root, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = join(root, entry.name);
    if (entry.isDirectory()) {
      if (ignoredDirectories.has(entry.name)) {
        continue;
      }
      count += await countMarkdownFiles(fullPath, ignoredDirectories);
      continue;
    }

    if (entry.isFile() && entry.name.toLowerCase().endsWith(".md")) {
      count += 1;
    }
  }
  return count;
}

function assertWorkspaceSegment(value: string, label: string): void {
  const trimmed = value.trim();
  if (!trimmed) {
    throw new Error(`A non-empty ${label} is required.`);
  }
  if (
    isAbsolute(trimmed) ||
    trimmed === "." ||
    trimmed === ".." ||
    trimmed.includes("/") ||
    trimmed.includes("\\") ||
    trimmed.includes("\0")
  ) {
    throw new Error(`${label} must be a single name inside the workspace, not a path.`);
  }
}

function findImportedModelPath(workspaceDir: string, outputName: string): {
  modelType: OscalModelType | null;
  filePath: string | null;
} {
  for (const [modelType, dirName] of Object.entries(OSCAL_MODEL_DIRS) as Array<
    [OscalModelType, string]
  >) {
    const folder = join(workspaceDir, dirName, outputName);
    if (!existsSync(folder)) continue;
    for (const extension of ["json", "yaml", "yml"]) {
      const candidate = join(folder, `${modelType}.${extension}`);
      if (existsSync(candidate)) {
        return { modelType, filePath: candidate };
      }
    }
  }

  return { modelType: null, filePath: null };
}

function buildWorkspaceTable(inspection: TrestleWorkspaceInspection): string {
  const rows = (Object.entries(OSCAL_MODEL_DIRS) as Array<[OscalModelType, string]>)
    .map(([modelType]) => [modelType, String(inspection.modelCounts[modelType] ?? 0)]);
  return formatTable(["model_type", "count"], rows);
}

function buildCheckText(status: OscalTrestleStatus): string {
  const lines = [
    status.installed
      ? "Trestle is installed and ready for OSCAL work."
      : "Trestle is not available yet.",
    `  Workspace dir: ${status.workspace.workspaceDir}`,
    `  Workspace:     ${status.workspace.isWorkspace ? "initialized" : "not initialized"}`,
    `  Next step:     ${status.recommendedNextStep}`,
  ];

  if (status.version) {
    lines.splice(1, 0, `  Version:       ${status.version}`);
  }

  if (status.executable) {
    lines.splice(status.version ? 2 : 1, 0, `  Executable:    ${status.executable}`);
  }

  const sections = [lines.join("\n")];

  if (status.workspace.exists) {
    sections.push(`Workspace contents:\n${buildWorkspaceTable(status.workspace)}`);
  }

  if (status.notes.length > 0) {
    sections.push(`Notes:\n${status.notes.map((note) => `- ${note}`).join("\n")}`);
  }

  return sections.join("\n\n");
}

function buildInitText(
  workspace: TrestleWorkspaceInspection,
  mode: WorkspaceMode,
  alreadyInitialized: boolean,
): string {
  const status = alreadyInitialized ? "already initialized" : "initialized";
  return [
    `Trestle workspace ${status}.`,
    `  Workspace dir: ${workspace.workspaceDir}`,
    `  Mode:          ${mode}`,
    `  Dist folder:   ${workspace.hasDist ? "present" : "not created"}`,
    "",
    buildWorkspaceTable(workspace),
  ].join("\n");
}

function buildCreateText(result: OscalCreateResult): string {
  return [
    `Created OSCAL ${result.modelType} model "${result.modelName}".`,
    `  Workspace dir: ${result.workspaceDir}`,
    `  Format:        ${result.format}`,
    `  File:          ${result.filePath}`,
  ].join("\n");
}

function buildImportText(result: OscalImportResult): string {
  return [
    `Imported OSCAL model "${result.outputName}".`,
    `  Workspace dir: ${result.workspaceDir}`,
    `  Model type:    ${result.modelType ?? "unknown"}`,
    `  File:          ${result.importedPath ?? "Unable to determine created file path"}`,
  ].join("\n");
}

function buildValidateText(result: OscalValidateResult): string {
  return [
    "OSCAL validation passed.",
    `  Workspace dir: ${result.workspaceDir}`,
    `  Target:        ${result.selector}`,
  ].join("\n");
}

function buildSspGenerateText(result: OscalSspGenerateResult): string {
  return [
    `Generated SSP markdown in "${result.outputDir}".`,
    `  Workspace dir:     ${result.workspaceDir}`,
    `  Control markdowns: ${result.controlMarkdownCount}`,
    `  Inheritance view:  ${result.hasInheritanceView ? "present" : "not requested"}`,
  ].join("\n");
}

function buildSspAssembleText(result: OscalSspAssembleResult): string {
  return [
    `Assembled SSP "${result.outputName}".`,
    `  Workspace dir: ${result.workspaceDir}`,
    `  File:          ${result.filePath ?? "Unable to determine output file path"}`,
  ].join("\n");
}

export async function checkOscalTrestle(
  args: OscalCheckArgs,
  runner: TrestleRunner = runTrestleCommand,
): Promise<OscalTrestleStatus> {
  const workspaceDir = normalizeWorkspaceDir(args.workspace_dir, ".");
  const workspace = inspectTrestleWorkspace(workspaceDir);

  try {
    const versionResult = await runner(["version"], {
      cwd: workspace.exists ? workspace.workspaceDir : process.cwd(),
    });

    if (versionResult.exitCode !== 0) {
      throw new Error(summarizeCommandFailure(versionResult));
    }

    return {
      installed: true,
      version: versionResult.stdout || versionResult.stderr,
      executable: versionResult.displayExecutable,
      workspace,
      recommendedNextStep: workspace.isWorkspace
        ? "Use oscal_create_model, oscal_import_model, or oscal_generate_ssp_markdown."
        : `Run oscal_init_workspace with workspace_dir "${workspace.workspaceDir}".`,
      notes: workspace.isWorkspace
        ? [
            "The current OSCAL slice is trestle-backed, so validation and SSP authoring follow trestle's workspace conventions.",
          ]
        : [
            "No trestle workspace was detected at this path yet.",
          ],
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return {
      installed: false,
      workspace,
      recommendedNextStep:
        "Install compliance-trestle first, then run oscal_init_workspace to create a workspace.",
      notes: [message],
    };
  }
}

export async function initOscalWorkspace(
  args: OscalInitArgs,
  runner: TrestleRunner = runTrestleCommand,
): Promise<{ workspace: TrestleWorkspaceInspection; mode: WorkspaceMode; alreadyInitialized: boolean }> {
  const workspaceDir = normalizeWorkspaceDir(args.workspace_dir, DEFAULT_WORKSPACE_DIR);
  const mode = normalizeWorkspaceMode(args.mode);
  mkdirSync(workspaceDir, { recursive: true });

  const current = inspectTrestleWorkspace(workspaceDir);
  if (current.isWorkspace) {
    return { workspace: current, mode, alreadyInitialized: true };
  }

  const flag = mode === "local" ? "--local" : mode === "govdocs" ? "--govdocs" : "--full";
  const result = await runner(["init", flag], { cwd: workspaceDir });
  if (result.exitCode !== 0) {
    throw new Error(summarizeCommandFailure(result));
  }

  return {
    workspace: inspectTrestleWorkspace(workspaceDir),
    mode,
    alreadyInitialized: false,
  };
}

export async function importOscalModel(
  args: OscalImportArgs,
  runner: TrestleRunner = runTrestleCommand,
): Promise<OscalImportResult> {
  if (!args.file.trim()) {
    throw new Error("A file path or URL is required for oscal_import_model.");
  }
  assertWorkspaceSegment(args.output, "output name");

  ensureTrestleWorkspace(args.workspace_dir);

  const result = await runner(
    [
      "import",
      "-f",
      args.file,
      "-o",
      args.output,
      ...(args.regenerate_uuids ? ["-r"] : []),
    ],
    { cwd: args.workspace_dir },
  );

  if (result.exitCode !== 0) {
    throw new Error(summarizeCommandFailure(result));
  }

  const imported = findImportedModelPath(args.workspace_dir, args.output);
  return {
    workspaceDir: args.workspace_dir,
    outputName: args.output,
    modelType: imported.modelType,
    importedPath: imported.filePath,
  };
}

export async function createOscalModel(
  args: OscalCreateArgs,
  runner: TrestleRunner = runTrestleCommand,
): Promise<OscalCreateResult> {
  const modelType = resolveOscalModelType(args.model_type);
  assertWorkspaceSegment(args.name, "model name");

  ensureTrestleWorkspace(args.workspace_dir);

  const format = normalizeFileFormat(args.format);
  const result = await runner(
    [
      "create",
      "-t",
      modelType,
      "-o",
      args.name,
      "-x",
      format,
      ...(args.include_optional_fields ? ["--include-optional-fields"] : []),
    ],
    { cwd: args.workspace_dir },
  );

  if (result.exitCode !== 0) {
    throw new Error(summarizeCommandFailure(result));
  }

  const filePath = join(
    args.workspace_dir,
    OSCAL_MODEL_DIRS[modelType],
    args.name,
    `${modelType}.${format}`,
  );

  if (!existsSync(filePath)) {
    throw new Error(
      `trestle reported success, but the created model was not found at "${filePath}".`,
    );
  }

  return {
    workspaceDir: args.workspace_dir,
    modelType,
    modelName: args.name,
    format,
    filePath,
  };
}

export async function validateOscalModel(
  args: OscalValidateArgs,
  runner: TrestleRunner = runTrestleCommand,
): Promise<OscalValidateResult> {
  ensureTrestleWorkspace(args.workspace_dir);

  const commandArgs = ["validate"];
  let selector = "";

  if (args.all) {
    commandArgs.push("-a");
    selector = "all workspace models";
  } else if (args.file) {
    commandArgs.push("-f", resolveRelativeToWorkspace(args.workspace_dir, args.file));
    selector = resolveRelativeToWorkspace(args.workspace_dir, args.file);
  } else if (args.model_type && args.name) {
    const modelType = resolveOscalModelType(args.model_type);
    assertWorkspaceSegment(args.name, "model name");
    commandArgs.push("-t", modelType, "-n", args.name);
    selector = `${modelType}:${args.name}`;
  } else if (args.model_type) {
    const modelType = resolveOscalModelType(args.model_type);
    commandArgs.push("-t", modelType);
    selector = modelType;
  } else {
    throw new Error(
      "Choose a validation target with file, model_type (+ optional name), or all=true.",
    );
  }

  if (args.quiet !== false) {
    commandArgs.push("-q");
  }

  const result = await runner(commandArgs, { cwd: args.workspace_dir });
  if (result.exitCode !== 0) {
    throw new Error(summarizeCommandFailure(result));
  }

  return {
    workspaceDir: args.workspace_dir,
    selector,
  };
}

export async function generateOscalSspMarkdown(
  args: OscalSspGenerateArgs,
  runner: TrestleRunner = runTrestleCommand,
): Promise<OscalSspGenerateResult> {
  ensureTrestleWorkspace(args.workspace_dir);
  if (!args.profile.trim()) {
    throw new Error("A profile name or href is required for oscal_generate_ssp_markdown.");
  }
  assertWorkspaceSegment(args.output, "output directory name");
  for (const name of args.component_definitions ?? []) {
    assertWorkspaceSegment(name, "component definition name");
  }
  if (args.leveraged_ssp) assertWorkspaceSegment(args.leveraged_ssp, "leveraged SSP name");

  const commandArgs = [
    "author",
    "ssp-generate",
    "-p",
    args.profile,
    "-o",
    args.output,
  ];

  const compdefs = joinCommaList(args.component_definitions);
  if (compdefs) commandArgs.push("-cd", compdefs);
  if (args.leveraged_ssp) commandArgs.push("-ls", args.leveraged_ssp);
  if (args.yaml_header) {
    commandArgs.push("-y", resolveRelativeToWorkspace(args.workspace_dir, args.yaml_header));
  }
  if (args.force_overwrite) commandArgs.push("-fo");
  if (args.overwrite_header_values) commandArgs.push("-ohv");
  if (args.include_all_parts) commandArgs.push("-iap");

  const result = await runner(commandArgs, { cwd: args.workspace_dir });
  if (result.exitCode !== 0) {
    throw new Error(summarizeCommandFailure(result));
  }

  const outputDir = join(args.workspace_dir, args.output);
  if (!existsSync(outputDir)) {
    throw new Error(
      `trestle reported success, but the markdown directory was not found at "${outputDir}".`,
    );
  }

  return {
    workspaceDir: args.workspace_dir,
    outputDir,
    controlMarkdownCount: await countMarkdownFiles(outputDir, new Set(["inheritance"])),
    hasInheritanceView: existsSync(join(outputDir, "inheritance")),
  };
}

export async function assembleOscalSsp(
  args: OscalSspAssembleArgs,
  runner: TrestleRunner = runTrestleCommand,
): Promise<OscalSspAssembleResult> {
  ensureTrestleWorkspace(args.workspace_dir);
  if (!args.markdown.trim()) {
    throw new Error("A markdown directory is required for oscal_assemble_ssp.");
  }
  assertWorkspaceSegment(args.output, "output name");
  for (const name of args.component_definitions ?? []) {
    assertWorkspaceSegment(name, "component definition name");
  }
  if (args.source_ssp_name) assertWorkspaceSegment(args.source_ssp_name, "source SSP name");

  const commandArgs = [
    "author",
    "ssp-assemble",
    "-m",
    args.markdown,
    "-o",
    args.output,
  ];
  const compdefs = joinCommaList(args.component_definitions);
  if (compdefs) commandArgs.push("-cd", compdefs);
  if (args.source_ssp_name) commandArgs.push("-n", args.source_ssp_name);
  if (args.regenerate_uuids) commandArgs.push("-r");
  if (args.version) commandArgs.push("-vn", args.version);

  const result = await runner(commandArgs, { cwd: args.workspace_dir });
  if (result.exitCode !== 0) {
    throw new Error(summarizeCommandFailure(result));
  }

  const filePath = findImportedModelPath(args.workspace_dir, args.output).filePath;
  return {
    workspaceDir: args.workspace_dir,
    outputName: args.output,
    filePath,
  };
}

export function registerOscalTools(pi: any): void {
  pi.registerTool({
    name: "oscal_check_trestle",
    label: "Check OSCAL trestle setup",
    description:
      "Check whether compliance-trestle is installed, report the active trestle version, and inspect whether a given directory is already initialized as a trestle workspace.",
    parameters: Type.Object({
      workspace_dir: Type.Optional(
        Type.String({
          description:
            "Optional workspace path to inspect. Defaults to the current directory.",
        }),
      ),
    }),
    prepareArguments: normalizeCheckArgs,
    async execute(_toolCallId: string, args: OscalCheckArgs, signal?: AbortSignal) {
      const status = await checkOscalTrestle(args, trestleRunnerFor(signal));
      return textResult(buildCheckText(status), {
        tool: "oscal_check_trestle",
        installed: status.installed,
        version: status.version ?? null,
        executable: status.executable ?? null,
        workspace_dir: status.workspace.workspaceDir,
        workspace_initialized: status.workspace.isWorkspace,
        has_dist: status.workspace.hasDist,
        model_counts: status.workspace.modelCounts,
        recommended_next_step: status.recommendedNextStep,
        notes: status.notes,
      });
    },
  });

  pi.registerTool({
    name: "oscal_init_workspace",
    label: "Initialize OSCAL workspace",
    description:
      "Create a compliance-trestle workspace for OSCAL content. Defaults to a local-only workspace under ./oscal-workspace.",
    parameters: Type.Object({
      workspace_dir: Type.Optional(
        Type.String({
          description:
            "Directory to initialize as the trestle workspace. Defaults to ./oscal-workspace.",
        }),
      ),
      mode: Type.Optional(
        Type.Union(
          [
            Type.Literal("local"),
            Type.Literal("full"),
            Type.Literal("govdocs"),
          ],
          {
            description:
              "Workspace mode: local for OSCAL-only source files, full for source plus dist outputs, govdocs for governed-docs only.",
          },
        ),
      ),
    }),
    prepareArguments: normalizeInitArgs,
    async execute(_toolCallId: string, args: OscalInitArgs, signal?: AbortSignal) {
      try {
        const result = await initOscalWorkspace(args, trestleRunnerFor(signal));
        return textResult(
          buildInitText(result.workspace, result.mode, result.alreadyInitialized),
          {
            tool: "oscal_init_workspace",
            workspace_dir: result.workspace.workspaceDir,
            mode: result.mode,
            already_initialized: result.alreadyInitialized,
            has_dist: result.workspace.hasDist,
            model_counts: result.workspace.modelCounts,
          },
        );
      } catch (error) {
        return errorResult(
          `OSCAL workspace init failed: ${error instanceof Error ? error.message : String(error)}`,
          { tool: "oscal_init_workspace" },
        );
      }
    },
  });

  pi.registerTool({
    name: "oscal_import_model",
    label: "Import OSCAL model",
    description:
      "Import an existing OSCAL file or URL into a trestle workspace so it can be managed, validated, and used by later SSP authoring commands.",
    parameters: Type.Object({
      workspace_dir: Type.String({
        description: "Path to an initialized trestle workspace.",
      }),
      file: Type.String({
        description: "Path or URL to an OSCAL json/yaml file to import.",
      }),
      output: Type.String({
        description:
          "Alias for the imported model inside the workspace, such as fedramp-moderate or acme-ssp.",
      }),
      regenerate_uuids: Type.Optional(
        Type.Boolean({
          description:
            "When true, regenerate UUIDs during import to avoid collisions with existing content.",
        }),
      ),
    }),
    prepareArguments: normalizeImportArgs,
    async execute(_toolCallId: string, args: OscalImportArgs, signal?: AbortSignal) {
      try {
        const result = await importOscalModel(args, trestleRunnerFor(signal));
        return textResult(buildImportText(result), {
          tool: "oscal_import_model",
          workspace_dir: result.workspaceDir,
          output_name: result.outputName,
          model_type: result.modelType,
          imported_path: result.importedPath,
        });
      } catch (error) {
        return errorResult(
          `OSCAL import failed: ${error instanceof Error ? error.message : String(error)}`,
          {
            tool: "oscal_import_model",
            workspace_dir: args.workspace_dir,
            output: args.output,
          },
        );
      }
    },
  });

  pi.registerTool({
    name: "oscal_create_model",
    label: "Create OSCAL model",
    description:
      "Create a starter OSCAL model in a trestle workspace. Supports SSP, SAR, POA&M, profiles, catalogs, and component definitions.",
    parameters: Type.Object({
      workspace_dir: Type.String({
        description: "Path to an initialized trestle workspace.",
      }),
      model_type: Type.String({
        description:
          "OSCAL model type such as ssp, sar, poam, profile, catalog, or component-definition.",
      }),
      name: Type.String({
        description: "Model alias to create inside the workspace.",
      }),
      format: Type.Optional(
        Type.Union(
          [
            Type.Literal("json"),
            Type.Literal("yaml"),
            Type.Literal("yml"),
          ],
          {
            description: "Output format. Defaults to json.",
          },
        ),
      ),
      include_optional_fields: Type.Optional(
        Type.Boolean({
          description:
            "When true, include optional OSCAL fields in the generated starter model.",
        }),
      ),
    }),
    prepareArguments: normalizeCreateArgs,
    async execute(_toolCallId: string, args: OscalCreateArgs, signal?: AbortSignal) {
      try {
        const result = await createOscalModel(args, trestleRunnerFor(signal));
        return textResult(buildCreateText(result), {
          tool: "oscal_create_model",
          workspace_dir: result.workspaceDir,
          model_type: result.modelType,
          name: result.modelName,
          format: result.format,
          file_path: result.filePath,
        });
      } catch (error) {
        return errorResult(
          `OSCAL model creation failed: ${error instanceof Error ? error.message : String(error)}`,
          {
            tool: "oscal_create_model",
            workspace_dir: args.workspace_dir,
            model_type: args.model_type,
            name: args.name,
          },
        );
      }
    },
  });

  pi.registerTool({
    name: "oscal_validate_model",
    label: "Validate OSCAL model",
    description:
      "Validate one OSCAL file, a named model in a trestle workspace, all models of a type, or the entire workspace.",
    parameters: Type.Object({
      workspace_dir: Type.String({
        description: "Path to an initialized trestle workspace.",
      }),
      file: Type.Optional(
        Type.String({
          description:
            "Specific OSCAL file or model directory to validate. Relative paths are resolved from the workspace root.",
        }),
      ),
      model_type: Type.Optional(
        Type.String({
          description:
            "Optional model type such as ssp, sar, poam, profile, catalog, or component-definition.",
        }),
      ),
      name: Type.Optional(
        Type.String({
          description:
            "Optional model alias when validating one named model by type.",
        }),
      ),
      all: Type.Optional(
        Type.Boolean({
          description: "Validate the full workspace when true.",
        }),
      ),
      quiet: Type.Optional(
        Type.Boolean({
          description:
            "Suppress trestle's verbose success messages. Defaults to true.",
        }),
      ),
    }),
    prepareArguments: normalizeValidateArgs,
    async execute(_toolCallId: string, args: OscalValidateArgs, signal?: AbortSignal) {
      try {
        const result = await validateOscalModel(args, trestleRunnerFor(signal));
        return textResult(buildValidateText(result), {
          tool: "oscal_validate_model",
          workspace_dir: result.workspaceDir,
          selector: result.selector,
        });
      } catch (error) {
        return errorResult(
          `OSCAL validation failed: ${error instanceof Error ? error.message : String(error)}`,
          {
            tool: "oscal_validate_model",
            workspace_dir: args.workspace_dir,
            file: args.file ?? null,
            model_type: args.model_type ?? null,
            name: args.name ?? null,
            all: args.all ?? false,
          },
        );
      }
    },
  });

  pi.registerTool({
    name: "oscal_generate_ssp_markdown",
    label: "Generate SSP markdown",
    description:
      "Run trestle's SSP markdown generator from a profile and optional component definitions, producing editable markdown for control implementation authoring.",
    parameters: Type.Object({
      workspace_dir: Type.String({
        description: "Path to an initialized trestle workspace.",
      }),
      profile: Type.String({
        description:
          "Profile name in the workspace or an href/URI that trestle can resolve.",
      }),
      output: Type.String({
        description:
          "Name of the markdown output directory to create under the workspace.",
      }),
      component_definitions: Type.Optional(
        Type.Array(
          Type.String(),
          {
            description:
              "Optional component-definition names already present in the workspace.",
          },
        ),
      ),
      leveraged_ssp: Type.Optional(
        Type.String({
          description:
            "Optional leveraged SSP name or href for inheritance view generation.",
        }),
      ),
      yaml_header: Type.Optional(
        Type.String({
          description:
            "Optional path to a YAML header file to inject into the generated markdown.",
        }),
      ),
      force_overwrite: Type.Optional(
        Type.Boolean({
          description:
            "Overwrite existing markdown content in the output directory before regeneration.",
        }),
      ),
      overwrite_header_values: Type.Optional(
        Type.Boolean({
          description:
            "Allow the input YAML header to overwrite header values already present in existing markdown.",
        }),
      ),
      include_all_parts: Type.Optional(
        Type.Boolean({
          description:
            "Write all control parts for the main system component, not just the parts with rules.",
        }),
      ),
    }),
    prepareArguments: normalizeSspGenerateArgs,
    async execute(_toolCallId: string, args: OscalSspGenerateArgs, signal?: AbortSignal) {
      try {
        const result = await generateOscalSspMarkdown(args, trestleRunnerFor(signal));
        return textResult(buildSspGenerateText(result), {
          tool: "oscal_generate_ssp_markdown",
          workspace_dir: result.workspaceDir,
          output_dir: result.outputDir,
          control_markdown_count: result.controlMarkdownCount,
          has_inheritance_view: result.hasInheritanceView,
        });
      } catch (error) {
        return errorResult(
          `OSCAL SSP markdown generation failed: ${error instanceof Error ? error.message : String(error)}`,
          {
            tool: "oscal_generate_ssp_markdown",
            workspace_dir: args.workspace_dir,
            profile: args.profile,
            output: args.output,
          },
        );
      }
    },
  });

  pi.registerTool({
    name: "oscal_assemble_ssp",
    label: "Assemble SSP from markdown",
    description:
      "Run trestle's SSP assembler to turn authored markdown back into an OSCAL System Security Plan in the workspace.",
    parameters: Type.Object({
      workspace_dir: Type.String({
        description: "Path to an initialized trestle workspace.",
      }),
      markdown: Type.String({
        description:
          "Markdown directory name or path previously generated by oscal_generate_ssp_markdown.",
      }),
      output: Type.String({
        description: "Name of the output SSP model to write in the workspace.",
      }),
      component_definitions: Type.Optional(
        Type.Array(
          Type.String(),
          {
            description:
              "Optional component-definition names that should be merged during assembly.",
          },
        ),
      ),
      source_ssp_name: Type.Optional(
        Type.String({
          description:
            "Optional existing SSP name to use as the merge target instead of creating a fresh sample.",
        }),
      ),
      regenerate_uuids: Type.Optional(
        Type.Boolean({
          description:
            "When true, regenerate UUIDs on the assembled SSP before writing it out.",
        }),
      ),
      version: Type.Optional(
        Type.String({
          description: "Optional version string to stamp onto the assembled SSP.",
        }),
      ),
    }),
    prepareArguments: normalizeSspAssembleArgs,
    async execute(_toolCallId: string, args: OscalSspAssembleArgs, signal?: AbortSignal) {
      try {
        const result = await assembleOscalSsp(args, trestleRunnerFor(signal));
        return textResult(buildSspAssembleText(result), {
          tool: "oscal_assemble_ssp",
          workspace_dir: result.workspaceDir,
          output_name: result.outputName,
          file_path: result.filePath,
        });
      } catch (error) {
        return errorResult(
          `OSCAL SSP assembly failed: ${error instanceof Error ? error.message : String(error)}`,
          {
            tool: "oscal_assemble_ssp",
            workspace_dir: args.workspace_dir,
            markdown: args.markdown,
            output: args.output,
          },
        );
      }
    },
  });
}
