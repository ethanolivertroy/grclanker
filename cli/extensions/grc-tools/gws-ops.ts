/**
 * Google Workspace CLI operator bridge for read-only GRC investigation.
 *
 * This module intentionally complements the native GWS compliance tools.
 * It shells out to `gws` when installed, runs a curated set of read-only
 * investigation commands, and packages the resulting evidence for operators.
 *
 * Command shapes, flags, exit codes, and environment variables are taken from
 * the published googleworkspace/cli README
 * (https://github.com/googleworkspace/cli#readme): `gws <service> <resource>
 * <method> --params '<json>'`, `--version`, structured exit codes 0-5, and the
 * GOOGLE_WORKSPACE_CLI_TOKEN > GOOGLE_WORKSPACE_CLI_CREDENTIALS_FILE > stored
 * credential precedence. The `admin-reports` alias is registered in
 * crates/google-workspace/src/services.rs; the `service:version` form is parsed
 * by parse_service_and_version in crates/google-workspace-cli/src/main.rs.
 */
import { spawn, spawnSync } from "node:child_process";
import { createWriteStream, existsSync, lstatSync, mkdirSync, realpathSync } from "node:fs";
import { chmod, readdir, writeFile } from "node:fs/promises";
import { dirname, join, relative, resolve } from "node:path";
import { ZipArchive } from "archiver";
import { Type } from "@sinclair/typebox";
import { errorResult, formatTable, textResult } from "./shared.js";

type JsonRecord = Record<string, unknown>;
type GwsCliErrorKind = "missing" | "auth" | "api" | "validation" | "discovery" | "internal";
type GwsOpsMode = "execute" | "dry_run";
type ActivityCategory = "alerts" | "admin_activity" | "token_activity";

const DEFAULT_OUTPUT_DIR = "./export/gws-ops";
const DEFAULT_LOOKBACK_DAYS = 14;
const DEFAULT_MAX_RESULTS = 50;
const MAX_RESULTS_LIMIT = 250;
const GWS_BIN_ENV_KEYS = ["GRCLANKER_GWS_BIN"] as const;

export class GwsCliCommandError extends Error {
  kind: GwsCliErrorKind;
  command: string;
  exitCode?: number;

  constructor(kind: GwsCliErrorKind, message: string, command: string, exitCode?: number) {
    super(message);
    this.name = "GwsCliCommandError";
    this.kind = kind;
    this.command = command;
    this.exitCode = exitCode;
  }
}

interface GwsCliExecutable {
  executable: string;
  displayExecutable: string;
  installed: boolean;
  source: "argument" | "environment" | "path" | "default";
}

interface GwsCliContext {
  gwsBin?: string;
  configDir?: string;
}

interface GwsOpsBaseArgs extends GwsCliContext {
  dry_run?: boolean;
}

interface GwsOpsActivityArgs extends GwsOpsBaseArgs {
  lookback_days?: number;
  max_results?: number;
}

interface GwsOpsAlertArgs extends GwsOpsBaseArgs {
  max_results?: number;
  filter?: string;
}

interface GwsOpsBundleArgs extends GwsOpsBaseArgs {
  lookback_days?: number;
  max_results?: number;
  filter?: string;
  output_dir?: string;
}

interface GwsCliCommandRequest {
  executable: GwsCliExecutable;
  args: string[];
  env: NodeJS.ProcessEnv;
  /** `gws --version` prints plain text; every curated API command must return JSON. */
  expectJson?: boolean;
}

interface GwsCliExecution {
  executable: string;
  displayExecutable: string;
  args: string[];
  command: string;
  stdout: string;
  stderr: string;
  exitCode: number;
  parsed?: unknown;
}

type GwsCliRunner = (request: GwsCliCommandRequest) => Promise<GwsCliExecution>;

interface GwsOpsCommandPreview {
  label: string;
  command: string;
  args: string[];
}

interface GwsOpsCheckResult {
  status: "ready" | "preview";
  mode: GwsOpsMode;
  executable: string;
  version: string;
  command: GwsOpsCommandPreview;
  probe?: GwsCliExecution;
  notes: string[];
}

interface GwsOpsActivityRecord {
  timestamp?: string;
  actor?: string;
  application?: string;
  eventNames: string[];
  id?: string;
  detail?: string;
  severity?: string;
  status?: string;
  source?: string;
}

interface GwsOpsActivityResult {
  title: string;
  category: ActivityCategory;
  mode: GwsOpsMode;
  count: number;
  /** False when the CLI response carried a nextPageToken, so the page is a partial view. */
  complete: boolean;
  nextPageToken?: string;
  command: GwsOpsCommandPreview;
  raw?: unknown;
  records?: GwsOpsActivityRecord[];
  notes: string[];
  text: string;
}

interface GwsOpsBundleResult {
  outputDir: string;
  zipPath: string;
  fileCount: number;
  commandCount: number;
  recordCount: number;
  categories: Record<ActivityCategory, number>;
}

function asRecord(value: unknown): JsonRecord {
  return value && typeof value === "object" ? value as JsonRecord : {};
}

function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function asString(value: unknown): string | undefined {
  return typeof value === "string" && value.trim().length > 0 ? value.trim() : undefined;
}

function asNumber(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function safeLower(value: unknown): string {
  return asString(value)?.toLowerCase() ?? "";
}

function summarizeError(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function shellEscape(part: string): string {
  if (/^[A-Za-z0-9_./:@=,+-]+$/.test(part)) return part;
  return `'${part.replace(/'/g, `'\"'\"'`)}'`;
}

function buildCommandString(executable: string, args: string[]): string {
  return [executable, ...args].map(shellEscape).join(" ");
}

function parseStructuredOutput(stdout: string): unknown {
  const trimmed = stdout.trim();
  if (!trimmed) return undefined;
  if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
    return JSON.parse(trimmed) as unknown;
  }

  const lines = trimmed
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
  if (lines.length === 0) return undefined;

  const parsed = lines.map((line) => JSON.parse(line) as unknown);
  return parsed.length === 1 ? parsed[0] : parsed;
}

function mapExitCodeToKind(exitCode: number): GwsCliErrorKind {
  switch (exitCode) {
    case 2:
      return "auth";
    case 3:
      return "validation";
    case 4:
      return "discovery";
    case 1:
      return "api";
    default:
      return "internal";
  }
}

function formatErrorMessage(result: GwsCliExecution): string {
  const parts = [result.stderr.trim(), result.stdout.trim()].filter(Boolean);
  return parts[0] ?? "gws returned a non-zero exit code without additional output.";
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

function commandExists(command: string): boolean {
  if (command.includes("/") || command.includes("\\")) {
    return existsSync(command);
  }
  return Boolean(findExecutableOnPath(command));
}

export function resolveGwsCliExecutable(
  args: GwsCliContext = {},
  env: NodeJS.ProcessEnv = process.env,
): GwsCliExecutable {
  const direct = asString(args.gwsBin);
  if (direct) {
    return {
      executable: direct,
      displayExecutable: direct,
      installed: commandExists(direct),
      source: "argument",
    };
  }

  for (const key of GWS_BIN_ENV_KEYS) {
    const configured = asString(env[key]);
    if (configured) {
      return {
        executable: configured,
        displayExecutable: configured,
        installed: commandExists(configured),
        source: "environment",
      };
    }
  }

  const found = findExecutableOnPath("gws");
  if (found) {
    return {
      executable: found,
      displayExecutable: found,
      installed: true,
      source: "path",
    };
  }

  return {
    executable: "gws",
    displayExecutable: "gws",
    installed: false,
    source: "default",
  };
}

function buildGwsCliInstallGuidance(): string {
  return [
    "Google Workspace CLI (`gws`) is not installed or not on PATH.",
    "Install it with `brew install googleworkspace-cli`, `npm install -g @googleworkspace/cli`, or download a binary from https://github.com/googleworkspace/cli/releases.",
  ].join(" ");
}

export const defaultGwsCliRunner: GwsCliRunner = async (request) => {
  const { executable, args, env } = request;
  const expectJson = request.expectJson !== false;
  const command = buildCommandString(executable.displayExecutable, args);

  return await new Promise<GwsCliExecution>((resolvePromise, rejectPromise) => {
    const child = spawn(executable.executable, args, {
      env,
      stdio: ["ignore", "pipe", "pipe"],
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
        rejectPromise(new GwsCliCommandError("missing", buildGwsCliInstallGuidance(), command));
        return;
      }
      rejectPromise(error);
    });

    child.on("close", (exitCode) => {
      const execution: GwsCliExecution = {
        executable: executable.executable,
        displayExecutable: executable.displayExecutable,
        args,
        command,
        stdout: stdout.trim(),
        stderr: stderr.trim(),
        exitCode: exitCode ?? 1,
      };

      if (execution.exitCode !== 0) {
        rejectPromise(
          new GwsCliCommandError(
            mapExitCodeToKind(execution.exitCode),
            formatErrorMessage(execution),
            command,
            execution.exitCode,
          ),
        );
        return;
      }

      if (!expectJson) {
        resolvePromise(execution);
        return;
      }

      try {
        execution.parsed = parseStructuredOutput(execution.stdout);
      } catch (error) {
        rejectPromise(
          new GwsCliCommandError(
            "internal",
            `gws returned success, but grclanker could not parse the output as structured JSON: ${summarizeError(error)}`,
            command,
            execution.exitCode,
          ),
        );
        return;
      }

      resolvePromise(execution);
    });
  });
};

/**
 * The published gws source registers no `alertcenter` service alias
 * (crates/google-workspace/src/services.rs), so a validation failure on the
 * Alert Center command is explained instead of surfacing as a bare exit code.
 */
function explainAlertCenterFailure(error: unknown): unknown {
  if (error instanceof GwsCliCommandError && error.kind === "validation") {
    return new GwsCliCommandError(
      "validation",
      `${error.message} The installed gws build rejected the alertcenter:v1beta1 service (exit 3, validation error); the published googleworkspace/cli source registers no alertcenter alias. Use gws_assess_monitoring for native Alert Center API coverage.`,
      error.command,
      error.exitCode,
    );
  }
  return error;
}

function buildRunnerEnv(args: GwsCliContext, env: NodeJS.ProcessEnv = process.env): NodeJS.ProcessEnv {
  const merged = { ...env };
  if (asString(args.configDir)) {
    merged.GOOGLE_WORKSPACE_CLI_CONFIG_DIR = args.configDir!.trim();
  }
  return merged;
}

async function runGwsVersion(
  args: GwsCliContext,
  runner: GwsCliRunner = defaultGwsCliRunner,
  env: NodeJS.ProcessEnv = process.env,
): Promise<{ version: string; command: string }> {
  const executable = resolveGwsCliExecutable(args, env);
  if (!executable.installed) {
    throw new GwsCliCommandError("missing", buildGwsCliInstallGuidance(), executable.displayExecutable);
  }
  const result = await runner({
    executable,
    args: ["--version"],
    env: buildRunnerEnv(args, env),
    expectJson: false,
  });
  return {
    version: result.stdout.trim() || "unknown",
    command: result.command,
  };
}

function isoLookback(days: number): string {
  return new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString();
}

function normalizeDryRun(value: unknown): boolean {
  return value === true;
}

function normalizeMaxResults(value: unknown): number {
  const numeric = asNumber(value);
  if (!numeric) return DEFAULT_MAX_RESULTS;
  return Math.max(1, Math.min(MAX_RESULTS_LIMIT, Math.trunc(numeric)));
}

function normalizeLookbackDays(value: unknown): number {
  const numeric = asNumber(value);
  if (!numeric) return DEFAULT_LOOKBACK_DAYS;
  return Math.max(1, Math.min(90, Math.trunc(numeric)));
}

function buildCommandPreview(executable: GwsCliExecutable, label: string, args: string[]): GwsOpsCommandPreview {
  return {
    label,
    args,
    command: buildCommandString(executable.displayExecutable, args),
  };
}

function buildAlertCommand(
  executable: GwsCliExecutable,
  args: GwsOpsAlertArgs,
): GwsOpsCommandPreview {
  const params: JsonRecord = {
    pageSize: normalizeMaxResults(args.max_results),
  };
  const filter = asString(args.filter);
  if (filter) params.filter = filter;
  return buildCommandPreview(
    executable,
    "Alert Center alert list",
    ["alertcenter:v1beta1", "alerts", "list", "--params", JSON.stringify(params)],
  );
}

function buildAdminActivityCommand(
  executable: GwsCliExecutable,
  args: GwsOpsActivityArgs,
  applicationName: "admin" | "token",
): GwsOpsCommandPreview {
  return buildCommandPreview(
    executable,
    applicationName === "admin" ? "Admin activity trace" : "Token activity trace",
    [
      "admin-reports",
      "activities",
      "list",
      "--params",
      JSON.stringify({
        userKey: "all",
        applicationName,
        maxResults: normalizeMaxResults(args.max_results),
        startTime: isoLookback(normalizeLookbackDays(args.lookback_days)),
      }),
    ],
  );
}

async function executePreview(
  preview: GwsOpsCommandPreview,
  args: GwsCliContext,
  runner: GwsCliRunner,
  env: NodeJS.ProcessEnv,
): Promise<GwsCliExecution> {
  const executable = resolveGwsCliExecutable(args, env);
  if (!executable.installed) {
    throw new GwsCliCommandError("missing", buildGwsCliInstallGuidance(), preview.command);
  }
  const result = await runner({
    executable,
    args: preview.args,
    env: buildRunnerEnv(args, env),
  });
  if (result.parsed === undefined) {
    try {
      result.parsed = parseStructuredOutput(result.stdout);
    } catch (error) {
      throw new GwsCliCommandError(
        "internal",
        `gws returned success, but grclanker could not parse the output as structured JSON: ${summarizeError(error)}`,
        result.command,
        result.exitCode,
      );
    }
  }
  return result;
}

/**
 * `--page-all` emits one JSON object per page (NDJSON); a single invocation
 * returns one page object. Both shapes normalize to a list of page objects.
 */
function pagesFromOutput(parsed: unknown, keys: string[]): JsonRecord[] {
  if (Array.isArray(parsed)) {
    const records = parsed.map((item) => asRecord(item));
    const looksLikePages = records.length > 0 && records.every((record) => keys.some((key) => Array.isArray(record[key])));
    return looksLikePages ? records : [{ [keys[0]]: records }];
  }
  return [asRecord(parsed)];
}

function recordsFromObject(parsed: unknown, keys: string[]): JsonRecord[] {
  const records: JsonRecord[] = [];
  for (const page of pagesFromOutput(parsed, keys)) {
    for (const key of keys) {
      const value = page[key];
      if (Array.isArray(value)) {
        records.push(...value.map((item) => asRecord(item)));
        break;
      }
    }
  }
  return records;
}

/** The last page's nextPageToken (documented on every list response) marks a partial view. */
function trailingPageToken(parsed: unknown, keys: string[]): string | undefined {
  const pages = pagesFromOutput(parsed, keys);
  const last = pages[pages.length - 1];
  return last ? asString(last.nextPageToken) : undefined;
}

function completenessNote(nextPageToken: string | undefined, count: number): string {
  return nextPageToken
    ? `Partial view: the CLI response carried a nextPageToken after ${count} record(s); more records exist beyond this page (re-run with a larger max_results or use --page-all).`
    : `Complete: the CLI response carried no nextPageToken, so the ${count} record(s) are the whole population for this query.`;
}

function normalizeAlertRecords(parsed: unknown): GwsOpsActivityRecord[] {
  return recordsFromObject(parsed, ["alerts", "items"]).map((alert) => ({
    id: asString(alert.alertId) ?? asString(alert.name),
    timestamp: asString(alert.createTime) ?? asString(alert.updateTime),
    detail: asString(alert.type) ?? asString(alert.alertSubtype),
    severity: asString(alert.severity),
    status: asString(alert.state) ?? asString(alert.status),
    source: asString(alert.source),
    actor: asString(asRecord(alert.metadata).assignee) ?? asString(asRecord(alert.assignee).email),
    application: "alertcenter",
    eventNames: asString(alert.type) ? [alert.type as string] : [],
  }));
}

function normalizeActivityRecords(parsed: unknown, applicationName: "admin" | "token"): GwsOpsActivityRecord[] {
  return recordsFromObject(parsed, ["items"]).map((item) => {
    const id = asRecord(item.id);
    const actor = asRecord(item.actor);
    const events = asArray(item.events).map((event) => asString(asRecord(event).name)).filter(Boolean) as string[];
    const applicationInfo = asRecord(actor.applicationInfo);
    return {
      id: asString(id.uniqueQualifier) ?? asString(id.time),
      timestamp: asString(id.time),
      actor: asString(actor.email) ?? asString(actor.callerType),
      application: asString(applicationInfo.applicationName) ?? applicationName,
      eventNames: events,
      detail: asString(actor.ipAddress),
    };
  });
}

function countUnique(values: Array<string | undefined>): number {
  return new Set(values.filter(Boolean)).size;
}

function formatActivityTable(records: GwsOpsActivityRecord[]): string {
  return formatTable(
    ["Time", "Actor", "Events", "Detail"],
    records.slice(0, 12).map((record) => [
      record.timestamp ?? "-",
      record.actor ?? "-",
      record.eventNames.join(", ") || record.application || "-",
      record.detail ?? record.status ?? record.severity ?? "-",
    ]),
  );
}

function renderActivityText(title: string, records: GwsOpsActivityRecord[], notes: string[]): string {
  return [
    title,
    `Records: ${records.length}`,
    records.length > 0 ? `Unique actors: ${countUnique(records.map((record) => record.actor))}` : "",
    "",
    records.length > 0 ? formatActivityTable(records) : "No records returned.",
    "",
    ...notes.map((note) => `- ${note}`),
  ].filter(Boolean).join("\n");
}

function renderCheckText(result: GwsOpsCheckResult): string {
  return [
    "Google Workspace CLI operator bridge",
    `Status: ${result.status}`,
    `Mode: ${result.mode}`,
    `Executable: ${result.executable}`,
    `Version: ${result.version}`,
    "",
    "Underlying command:",
    `- ${result.command.command}`,
    "",
    ...result.notes.map((note) => `- ${note}`),
  ].join("\n");
}

function safeDirName(value: string): string {
  const cleaned = value.toLowerCase().replace(/[^a-z0-9._-]+/g, "-").replace(/-+/g, "-").replace(/^-|-$/g, "");
  return cleaned || "gws-ops";
}

function ensurePrivateDir(pathname: string): void {
  mkdirSync(pathname, { recursive: true, mode: 0o700 });
  const rawStat = lstatSync(pathname);
  if (rawStat.isSymbolicLink()) {
    throw new Error(`Refusing to use symlink path: ${pathname}`);
  }
  const realPath = realpathSync(pathname);
  const stat = lstatSync(realPath);
  if (!stat.isDirectory() || stat.isSymbolicLink()) {
    throw new Error(`Refusing to use non-directory or symlink path: ${pathname}`);
  }
}

function resolveSecureOutputPath(baseDir: string, targetDir: string): string {
  ensurePrivateDir(baseDir);
  const realBase = realpathSync(baseDir);
  const resolvedTarget = resolve(realBase, targetDir);
  const relativeTarget = relative(realBase, resolvedTarget);

  if (
    relativeTarget === ".."
    || relativeTarget.startsWith(`..${join("/")}`)
    || relativeTarget.startsWith("..")
  ) {
    throw new Error(`Refusing to write outside ${realBase}: ${targetDir}`);
  }

  const pathSegments = relativeTarget.split(/[\\/]+/).filter(Boolean);
  let currentPath = realBase;
  for (const segment of pathSegments) {
    currentPath = join(currentPath, segment);
    if (!existsSync(currentPath)) break;
    const stat = lstatSync(currentPath);
    if (stat.isSymbolicLink()) {
      throw new Error(`Refusing to use symlinked parent directory: ${currentPath}`);
    }
  }

  const parent = dirname(resolvedTarget);
  ensurePrivateDir(parent);
  const realParent = realpathSync(parent);
  const stat = lstatSync(realParent);
  if (stat.isSymbolicLink()) {
    throw new Error(`Refusing to use symlinked parent directory: ${parent}`);
  }

  return resolvedTarget;
}

async function nextAvailableAuditDir(root: string, preferredName: string): Promise<string> {
  ensurePrivateDir(root);
  const suffixes = ["", "-2", "-3", "-4", "-5", "-6"];
  for (const suffix of suffixes) {
    const candidate = resolveSecureOutputPath(root, `${preferredName}${suffix}`);
    if (!existsSync(candidate) && !existsSync(`${candidate}.zip`)) {
      mkdirSync(candidate, { recursive: true, mode: 0o700 });
      await chmod(candidate, 0o700);
      return candidate;
    }
  }
  throw new Error(`Unable to allocate output directory under ${root}`);
}

async function writeSecureTextFile(rootDir: string, relativePathname: string, content: string): Promise<void> {
  const destination = resolveSecureOutputPath(rootDir, relativePathname);
  ensurePrivateDir(dirname(destination));
  await writeFile(destination, content, { encoding: "utf8", mode: 0o600 });
}

async function createZipArchive(sourceDir: string, zipPath: string): Promise<void> {
  await new Promise<void>((resolvePromise, rejectPromise) => {
    const output = createWriteStream(zipPath, { mode: 0o600, flags: "wx" });
    const archive = new ZipArchive({ zlib: { level: 9 } });

    output.on("close", () => resolvePromise());
    output.on("error", rejectPromise);
    archive.on("error", rejectPromise);
    archive.pipe(output);
    archive.directory(sourceDir, false);
    void archive.finalize();
  });
}

async function countFilesRecursively(pathname: string): Promise<number> {
  const entries = await readdir(pathname, { withFileTypes: true });
  let count = 0;
  for (const entry of entries) {
    const fullPath = join(pathname, entry.name);
    if (entry.isDirectory()) {
      count += await countFilesRecursively(fullPath);
    } else {
      count += 1;
    }
  }
  return count;
}

function serializeJson(value: unknown): string {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function buildBundleReadme(): string {
  return [
    "# Google Workspace CLI Operator Evidence Bundle",
    "",
    "- `raw/` contains the structured JSON returned by the Google Workspace CLI.",
    "- `analysis/` contains normalized investigation summaries prepared for GRC review.",
    "- `commands.json` records the exact read-only commands grclanker executed.",
    "- `summary.md` is the quickest human-readable starting point.",
    "",
    "This bundle is read-only evidence collection. It does not write back to the tenant.",
    "",
  ].join("\n");
}

export async function checkGwsCliAccess(
  args: GwsOpsBaseArgs = {},
  runner: GwsCliRunner = defaultGwsCliRunner,
  env: NodeJS.ProcessEnv = process.env,
): Promise<GwsOpsCheckResult> {
  const executable = resolveGwsCliExecutable(args, env);
  if (!executable.installed) {
    throw new GwsCliCommandError("missing", buildGwsCliInstallGuidance(), executable.displayExecutable);
  }

  const version = await runGwsVersion(args, runner, env);
  const command = buildAdminActivityCommand(executable, { max_results: 1, lookback_days: 7 }, "admin");
  const mode: GwsOpsMode = normalizeDryRun(args.dry_run) ? "dry_run" : "execute";

  if (mode === "dry_run") {
    return {
      status: "preview",
      mode,
      executable: executable.displayExecutable,
      version: version.version,
      command,
      notes: [
        "Dry-run mode only previewed the probe command.",
        "When executed, grclanker will use a read-only Admin Reports activity query to validate the current gws auth path.",
      ],
    };
  }

  const probe = await executePreview(command, args, runner, env);
  return {
    status: "ready",
    mode,
    executable: executable.displayExecutable,
    version: version.version,
    command,
    probe,
    notes: [
      "The operator bridge is optional and separate from grclanker's native Google Workspace audit tools.",
      "The probe succeeded with a read-only Admin Reports query.",
    ],
  };
}

export async function investigateGwsAlerts(
  args: GwsOpsAlertArgs = {},
  runner: GwsCliRunner = defaultGwsCliRunner,
  env: NodeJS.ProcessEnv = process.env,
): Promise<GwsOpsActivityResult> {
  const executable = resolveGwsCliExecutable(args, env);
  if (!executable.installed) {
    throw new GwsCliCommandError("missing", buildGwsCliInstallGuidance(), executable.displayExecutable);
  }

  const command = buildAlertCommand(executable, args);
  const mode: GwsOpsMode = normalizeDryRun(args.dry_run) ? "dry_run" : "execute";
  const notes = [
    asString(args.filter)
      ? `Alert filter passed through to gws: ${args.filter!.trim()}`
      : "No Alert Center filter was supplied; this query relies on page-size bounds instead of a time filter.",
  ];

  if (mode === "dry_run") {
    return {
      title: "Google Workspace alert investigation (preview)",
      category: "alerts",
      mode,
      count: 0,
      complete: false,
      command,
      notes: [
        "Dry-run mode only previewed the read-only Alert Center command.",
        "The published googleworkspace/cli source registers no alertcenter service alias; if the installed build rejects the command (exit 3), use gws_assess_monitoring instead.",
        ...notes,
      ],
      text: [
        "Google Workspace alert investigation (preview)",
        `Command: ${command.command}`,
        "",
        ...notes.map((note) => `- ${note}`),
      ].join("\n"),
    };
  }

  let execution: GwsCliExecution;
  try {
    execution = await executePreview(command, args, runner, env);
  } catch (error) {
    throw explainAlertCenterFailure(error);
  }
  const records = normalizeAlertRecords(execution.parsed);
  const nextPageToken = trailingPageToken(execution.parsed, ["alerts", "items"]);
  const allNotes = [
    ...notes,
    completenessNote(nextPageToken, records.length),
    "These records come directly from the Google Workspace CLI Alert Center response.",
  ];
  return {
    title: "Google Workspace alert investigation",
    category: "alerts",
    mode,
    count: records.length,
    complete: nextPageToken === undefined,
    nextPageToken,
    command,
    raw: execution.parsed,
    records,
    notes: allNotes,
    text: renderActivityText("Google Workspace alert investigation", records, allNotes),
  };
}

export async function traceGwsAdminActivity(
  args: GwsOpsActivityArgs = {},
  runner: GwsCliRunner = defaultGwsCliRunner,
  env: NodeJS.ProcessEnv = process.env,
): Promise<GwsOpsActivityResult> {
  const executable = resolveGwsCliExecutable(args, env);
  if (!executable.installed) {
    throw new GwsCliCommandError("missing", buildGwsCliInstallGuidance(), executable.displayExecutable);
  }

  const command = buildAdminActivityCommand(executable, args, "admin");
  const mode: GwsOpsMode = normalizeDryRun(args.dry_run) ? "dry_run" : "execute";
  const notes = [
    `Lookback window: ${normalizeLookbackDays(args.lookback_days)} day(s)`,
    `Max results: ${normalizeMaxResults(args.max_results)}`,
  ];

  if (mode === "dry_run") {
    return {
      title: "Google Workspace admin activity trace (preview)",
      category: "admin_activity",
      mode,
      count: 0,
      complete: false,
      command,
      notes: [
        "Dry-run mode only previewed the read-only Admin Reports command.",
        ...notes,
      ],
      text: [
        "Google Workspace admin activity trace (preview)",
        `Command: ${command.command}`,
        "",
        ...notes.map((note) => `- ${note}`),
      ].join("\n"),
    };
  }

  const execution = await executePreview(command, args, runner, env);
  const records = normalizeActivityRecords(execution.parsed, "admin");
  const nextPageToken = trailingPageToken(execution.parsed, ["items"]);
  const allNotes = [...notes, completenessNote(nextPageToken, records.length)];
  return {
    title: "Google Workspace admin activity trace",
    category: "admin_activity",
    mode,
    count: records.length,
    complete: nextPageToken === undefined,
    nextPageToken,
    command,
    raw: execution.parsed,
    records,
    notes: allNotes,
    text: renderActivityText("Google Workspace admin activity trace", records, allNotes),
  };
}

export async function reviewGwsTokenActivity(
  args: GwsOpsActivityArgs = {},
  runner: GwsCliRunner = defaultGwsCliRunner,
  env: NodeJS.ProcessEnv = process.env,
): Promise<GwsOpsActivityResult> {
  const executable = resolveGwsCliExecutable(args, env);
  if (!executable.installed) {
    throw new GwsCliCommandError("missing", buildGwsCliInstallGuidance(), executable.displayExecutable);
  }

  const command = buildAdminActivityCommand(executable, args, "token");
  const mode: GwsOpsMode = normalizeDryRun(args.dry_run) ? "dry_run" : "execute";
  const notes = [
    `Lookback window: ${normalizeLookbackDays(args.lookback_days)} day(s)`,
    `Max results: ${normalizeMaxResults(args.max_results)}`,
    "This workflow focuses on token and OAuth activity telemetry, not a full tenant-wide token inventory clone.",
    "Use gws_assess_integrations when you need the broader native compliance view.",
  ];

  if (mode === "dry_run") {
    return {
      title: "Google Workspace token activity review (preview)",
      category: "token_activity",
      mode,
      count: 0,
      complete: false,
      command,
      notes: [
        "Dry-run mode only previewed the read-only Admin Reports token query.",
        ...notes,
      ],
      text: [
        "Google Workspace token activity review (preview)",
        `Command: ${command.command}`,
        "",
        ...notes.map((note) => `- ${note}`),
      ].join("\n"),
    };
  }

  const execution = await executePreview(command, args, runner, env);
  const records = normalizeActivityRecords(execution.parsed, "token");
  const nextPageToken = trailingPageToken(execution.parsed, ["items"]);
  const allNotes = [...notes, completenessNote(nextPageToken, records.length)];
  return {
    title: "Google Workspace token activity review",
    category: "token_activity",
    mode,
    count: records.length,
    complete: nextPageToken === undefined,
    nextPageToken,
    command,
    raw: execution.parsed,
    records,
    notes: allNotes,
    text: renderActivityText("Google Workspace token activity review", records, allNotes),
  };
}

function buildBundleSummary(results: GwsOpsActivityResult[]): string {
  return [
    "# Google Workspace CLI Operator Evidence Summary",
    "",
    ...results.map((result) => [
      `## ${result.title}`,
      "",
      `- Category: ${result.category}`,
      `- Records: ${result.count}`,
      `- Complete page: ${result.complete ? "yes" : "no (nextPageToken present)"}`,
      `- Command: ${result.command.command}`,
      "",
      ...result.notes.map((note) => `- ${note}`),
      "",
    ].join("\n")),
  ].join("\n");
}

export async function collectGwsOperatorEvidenceBundle(
  args: GwsOpsBundleArgs = {},
  runner: GwsCliRunner = defaultGwsCliRunner,
  env: NodeJS.ProcessEnv = process.env,
): Promise<GwsOpsBundleResult | { mode: "dry_run"; commands: GwsOpsCommandPreview[] }> {
  const workflowArgs = {
    gwsBin: args.gwsBin,
    configDir: args.configDir,
    lookback_days: args.lookback_days,
    max_results: args.max_results,
  };

  if (normalizeDryRun(args.dry_run)) {
    const executable = resolveGwsCliExecutable(args, env);
    return {
      mode: "dry_run",
      commands: [
        buildAlertCommand(executable, args),
        buildAdminActivityCommand(executable, workflowArgs, "admin"),
        buildAdminActivityCommand(executable, workflowArgs, "token"),
      ],
    };
  }

  const alerts = await investigateGwsAlerts(args, runner, env);
  const adminActivity = await traceGwsAdminActivity(workflowArgs, runner, env);
  const tokenActivity = await reviewGwsTokenActivity(workflowArgs, runner, env);
  const results = [alerts, adminActivity, tokenActivity];

  const outputRoot = args.output_dir?.trim() || DEFAULT_OUTPUT_DIR;
  const outputDir = await nextAvailableAuditDir(outputRoot, safeDirName("gws-operator-evidence"));

  await writeSecureTextFile(outputDir, "README.md", buildBundleReadme());
  await writeSecureTextFile(outputDir, "summary.md", buildBundleSummary(results));
  await writeSecureTextFile(
    outputDir,
    "commands.json",
    serializeJson(results.map((result) => ({ category: result.category, ...result.command }))),
  );

  for (const result of results) {
    await writeSecureTextFile(outputDir, `analysis/${result.category}.json`, serializeJson({
      title: result.title,
      count: result.count,
      complete: result.complete,
      nextPageToken: result.nextPageToken ?? null,
      notes: result.notes,
      records: result.records ?? [],
    }));
    await writeSecureTextFile(outputDir, `raw/${result.category}.json`, serializeJson({
      command: result.command,
      raw: result.raw ?? null,
    }));
  }

  const zipPath = `${outputDir}.zip`;
  await createZipArchive(outputDir, zipPath);
  const fileCount = await countFilesRecursively(outputDir);

  return {
    outputDir,
    zipPath,
    fileCount,
    commandCount: results.length,
    recordCount: results.reduce((sum, result) => sum + result.count, 0),
    categories: {
      alerts: alerts.count,
      admin_activity: adminActivity.count,
      token_activity: tokenActivity.count,
    },
  };
}

function renderActivityToolResult(result: GwsOpsActivityResult) {
  return textResult(result.text, {
    category: result.category,
    mode: result.mode,
    count: result.count,
    command: result.command.command,
    records: result.records ?? [],
    notes: result.notes,
  });
}

function normalizeBaseArgs(args: Record<string, unknown>): GwsOpsBaseArgs {
  return {
    gwsBin: asString(args.gws_bin),
    configDir: asString(args.config_dir),
    dry_run: normalizeDryRun(args.dry_run),
  };
}

function normalizeActivityArgs(args: Record<string, unknown>): GwsOpsActivityArgs {
  return {
    ...normalizeBaseArgs(args),
    lookback_days: normalizeLookbackDays(args.lookback_days),
    max_results: normalizeMaxResults(args.max_results),
  };
}

function normalizeAlertArgs(args: Record<string, unknown>): GwsOpsAlertArgs {
  return {
    ...normalizeBaseArgs(args),
    max_results: normalizeMaxResults(args.max_results),
    filter: asString(args.filter),
  };
}

function normalizeBundleArgs(args: Record<string, unknown>): GwsOpsBundleArgs {
  return {
    ...normalizeActivityArgs(args),
    filter: asString(args.filter),
    output_dir: asString(args.output_dir),
  };
}

function renderBundleResult(
  result: GwsOpsBundleResult | { mode: "dry_run"; commands: GwsOpsCommandPreview[] },
) {
  if ("mode" in result && result.mode === "dry_run") {
    return textResult(
      [
        "Google Workspace operator evidence bundle (preview)",
        "",
        ...result.commands.map((command) => `- ${command.command}`),
      ].join("\n"),
      {
        mode: "dry_run",
        commands: result.commands.map((command) => command.command),
      },
    );
  }

  if (!("outputDir" in result)) {
    throw new Error("Unexpected Google Workspace operator bundle result shape.");
  }

  return textResult(
    [
      "Exported Google Workspace operator evidence bundle.",
      `Output directory: ${result.outputDir}`,
      `Zip archive: ${result.zipPath}`,
      `Files written: ${result.fileCount}`,
      `Commands executed: ${result.commandCount}`,
      `Records captured: ${result.recordCount}`,
    ].join("\n"),
    {
      output_dir: result.outputDir,
      zip_path: result.zipPath,
      file_count: result.fileCount,
      command_count: result.commandCount,
      record_count: result.recordCount,
      categories: result.categories,
    },
  );
}

export function registerGwsOperatorTools(pi: any): void {
  const baseParams = {
    gws_bin: Type.Optional(
      Type.String({
        description: "Optional Google Workspace CLI binary path. Falls back to GRCLANKER_GWS_BIN and PATH.",
      }),
    ),
    config_dir: Type.Optional(
      Type.String({
        description: "Optional GOOGLE_WORKSPACE_CLI_CONFIG_DIR override for this command.",
      }),
    ),
    dry_run: Type.Optional(
      Type.Boolean({
        description: "Preview the curated gws command without executing it.",
      }),
    ),
  } as const;

  const activityParams = {
    ...baseParams,
    lookback_days: Type.Optional(
      Type.Integer({
        minimum: 1,
        maximum: 90,
        description: `How many days of activity to review. Defaults to ${DEFAULT_LOOKBACK_DAYS}.`,
      }),
    ),
    max_results: Type.Optional(
      Type.Integer({
        minimum: 1,
        maximum: MAX_RESULTS_LIMIT,
        description: `Maximum records to request from gws. Defaults to ${DEFAULT_MAX_RESULTS}.`,
      }),
    ),
  } as const;

  pi.registerTool({
    name: "gws_ops_check_cli",
    label: "Check Google Workspace CLI operator bridge",
    description:
      "Verify that the optional Google Workspace CLI bridge is installed, show the active gws version, and preview or run a harmless read-only probe command.",
    parameters: Type.Object(baseParams),
    prepareArguments: normalizeBaseArgs,
    async execute(_toolCallId: string, args: GwsOpsBaseArgs) {
      try {
        const result = await checkGwsCliAccess(args);
        return textResult(renderCheckText(result), {
          status: result.status,
          mode: result.mode,
          executable: result.executable,
          version: result.version,
          command: result.command.command,
          notes: result.notes,
        });
      } catch (error) {
        return errorResult(
          `Google Workspace CLI bridge check failed: ${summarizeError(error)}`,
          {
            tool: "gws_ops_check_cli",
            kind: error instanceof GwsCliCommandError ? error.kind : "internal",
          },
        );
      }
    },
  });

  pi.registerTool({
    name: "gws_ops_investigate_alerts",
    label: "Investigate Google Workspace alerts with gws",
    description:
      "Use the optional Google Workspace CLI to run a curated, read-only Alert Center investigation workflow and return structured alert summaries plus the underlying command.",
    parameters: Type.Object({
      ...baseParams,
      max_results: activityParams.max_results,
      filter: Type.Optional(
        Type.String({
          description: "Optional raw Alert Center filter string to pass through to gws.",
        }),
      ),
    }),
    prepareArguments: normalizeAlertArgs,
    async execute(_toolCallId: string, args: GwsOpsAlertArgs) {
      try {
        return renderActivityToolResult(await investigateGwsAlerts(args));
      } catch (error) {
        return errorResult(
          `Google Workspace alert investigation failed: ${summarizeError(error)}`,
          {
            tool: "gws_ops_investigate_alerts",
            kind: error instanceof GwsCliCommandError ? error.kind : "internal",
          },
        );
      }
    },
  });

  pi.registerTool({
    name: "gws_ops_trace_admin_activity",
    label: "Trace Google Workspace admin activity with gws",
    description:
      "Use the optional Google Workspace CLI to run a curated, read-only Admin Reports workflow for recent privileged admin activity.",
    parameters: Type.Object(activityParams),
    prepareArguments: normalizeActivityArgs,
    async execute(_toolCallId: string, args: GwsOpsActivityArgs) {
      try {
        return renderActivityToolResult(await traceGwsAdminActivity(args));
      } catch (error) {
        return errorResult(
          `Google Workspace admin activity trace failed: ${summarizeError(error)}`,
          {
            tool: "gws_ops_trace_admin_activity",
            kind: error instanceof GwsCliCommandError ? error.kind : "internal",
          },
        );
      }
    },
  });

  pi.registerTool({
    name: "gws_ops_review_tokens",
    label: "Review Google Workspace token activity with gws",
    description:
      "Use the optional Google Workspace CLI to run a curated, read-only Admin Reports token activity workflow for OAuth and app-governance investigations.",
    parameters: Type.Object(activityParams),
    prepareArguments: normalizeActivityArgs,
    async execute(_toolCallId: string, args: GwsOpsActivityArgs) {
      try {
        return renderActivityToolResult(await reviewGwsTokenActivity(args));
      } catch (error) {
        return errorResult(
          `Google Workspace token activity review failed: ${summarizeError(error)}`,
          {
            tool: "gws_ops_review_tokens",
            kind: error instanceof GwsCliCommandError ? error.kind : "internal",
          },
        );
      }
    },
  });

  pi.registerTool({
    name: "gws_ops_collect_evidence_bundle",
    label: "Collect Google Workspace operator evidence bundle",
    description:
      "Run the curated read-only Google Workspace CLI alert, admin-activity, and token-activity workflows, then package the evidence and executed commands into a separate operator bundle.",
    parameters: Type.Object({
      ...activityParams,
      filter: Type.Optional(
        Type.String({
          description: "Optional raw Alert Center filter string to pass through to gws.",
        }),
      ),
      output_dir: Type.Optional(
        Type.String({
          description: `Optional output root for the operator bundle. Defaults to ${DEFAULT_OUTPUT_DIR}.`,
        }),
      ),
    }),
    prepareArguments: normalizeBundleArgs,
    async execute(_toolCallId: string, args: GwsOpsBundleArgs) {
      try {
        return renderBundleResult(await collectGwsOperatorEvidenceBundle(args));
      } catch (error) {
        return errorResult(
          `Google Workspace operator evidence collection failed: ${summarizeError(error)}`,
          {
            tool: "gws_ops_collect_evidence_bundle",
            kind: error instanceof GwsCliCommandError ? error.kind : "internal",
          },
        );
      }
    },
  });
}
