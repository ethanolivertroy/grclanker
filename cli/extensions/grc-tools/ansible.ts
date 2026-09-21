/**
 * Red Hat Ansible Automation Platform audit tools for grclanker.
 *
 * This native TypeScript surface implements the 30 controls of the community
 * ansible-sec-inspector spec with read-only AAP controller REST API checks.
 */
import {
  createWriteStream,
  existsSync,
  lstatSync,
  mkdirSync,
  realpathSync,
} from "node:fs";
import { chmod, readdir, writeFile } from "node:fs/promises";
import { request as httpRequest } from "node:http";
import { Agent as HttpsAgent, request as httpsRequest } from "node:https";
import { dirname, join, relative, resolve } from "node:path";
import { ZipArchive } from "archiver";
import { Type } from "@sinclair/typebox";
import { errorResult, formatTable, textResult } from "./shared.js";

const DEFAULT_LOOKBACK_DAYS = 90;
const DEFAULT_PAGE_SIZE = 100;
const DEFAULT_JOB_LIMIT = 500;
const DEFAULT_HOST_LIMIT = 1000;
const DEFAULT_TEMPLATE_LIMIT = 500;
const DEFAULT_SUMMARY_LIMIT = 2000;
const DEFAULT_USER_LIMIT = 200;
const DEFAULT_ROLE_PROBE_LIMIT = 50;
const DEFAULT_TIMEOUT_MS = 30_000;
const TOKEN_SKEW_MS = 5 * 60 * 1000;
const REMEDIATION_WINDOW_DAYS = 7;
const MISSED_RUN_MULTIPLIER = 1.5;
const DEFAULT_OUTPUT_DIR = "./export/ansible-aap";
const CRITICAL_TEMPLATE_PATTERN = /patch|harden|cis|stig|baseline|logging|audit|access|password|compliance|security|firewall/i;
const SECRET_KEY_PATTERN = /(password|passwd|secret|token|api[_-]?key|private[_-]?key|client[_-]?secret)/i;
const SECRET_ASSIGNMENT_PATTERN = /([A-Za-z0-9_.-]*(?:password|passwd|secret|token|api[_-]?key|private[_-]?key|client[_-]?secret)[A-Za-z0-9_.-]*)["']?\s*[:=]\s*["']?([^\s"',}\]]{4,})/gi;

type FetchImpl = typeof fetch;
type JsonRecord = Record<string, unknown>;

export interface AnsibleAapConfiguration {
  baseUrl: string;
  username?: string;
  password?: string;
  token?: string;
  timeoutMs: number;
  verifySsl: boolean;
  sourceChain: string[];
}

interface AnsibleAapClientOptions {
  fetchImpl?: FetchImpl;
  now?: () => Date;
}

interface AapListResponse<T> {
  count?: number;
  next?: string | null;
  previous?: string | null;
  results?: T[];
}

export interface AnsibleCollection {
  items: JsonRecord[];
  complete: boolean;
  total?: number;
  truncation?: string;
}

export interface Snapshot<T> {
  data: T;
  error?: string;
}

export interface AnsibleAccessSurface {
  name: string;
  endpoint: string;
  status: "readable" | "not_readable";
  count?: number;
  error?: string;
}

export interface AnsibleAccessCheckResult {
  status: "healthy" | "limited";
  currentUser?: JsonRecord;
  ping?: JsonRecord;
  surfaces: AnsibleAccessSurface[];
  notes: string[];
  recommendedNextStep: string;
}

export type AnsibleFindingStatus = "pass" | "warn" | "fail" | "manual";
export type AnsibleSeverity = "critical" | "high" | "medium" | "low" | "info";

export interface AnsibleFinding {
  id: string;
  control: number;
  title: string;
  severity: AnsibleSeverity;
  status: AnsibleFindingStatus;
  summary: string;
  evidence?: JsonRecord;
  mappings: string[];
}

export interface AnsibleAssessmentResult {
  category: string;
  title: string;
  summary: JsonRecord;
  findings: AnsibleFinding[];
  errors: string[];
}

export interface AnsibleAuditBundleResult {
  outputDir: string;
  zipPath: string;
  fileCount: number;
  findingCount: number;
  errorCount: number;
}

type CheckAccessArgs = {
  url?: string;
  username?: string;
  token?: string;
  timeout_seconds?: number;
  verify_ssl?: boolean;
};

type JobHealthArgs = CheckAccessArgs & {
  days?: number;
  job_limit?: number;
  min_success_rate?: number;
  max_manual_rate?: number;
};

type HostCoverageArgs = CheckAccessArgs & {
  days?: number;
  stale_host_days?: number;
  critical_stale_host_days?: number;
  stale_template_days?: number;
  host_limit?: number;
  inventory_source_limit?: number;
  template_limit?: number;
};

type PlatformSecurityArgs = CheckAccessArgs & {
  max_org_admins?: number;
  stale_credential_days?: number;
  stale_token_days?: number;
  max_shared_templates?: number;
  project_limit?: number;
  template_limit?: number;
  user_limit?: number;
};

type ExportAuditBundleArgs = JobHealthArgs & HostCoverageArgs & PlatformSecurityArgs & {
  output_dir?: string;
};

export interface JobHealthOptions {
  days?: number;
  jobLimit?: number;
  minSuccessRate?: number;
  maxManualRate?: number;
}

export interface HostCoverageOptions {
  days?: number;
  staleHostDays?: number;
  criticalStaleHostDays?: number;
  staleTemplateDays?: number;
  hostLimit?: number;
  inventorySourceLimit?: number;
  templateLimit?: number;
}

export interface PlatformSecurityOptions {
  maxOrgAdmins?: number;
  staleCredentialDays?: number;
  staleTokenDays?: number;
  maxSharedTemplates?: number;
  projectLimit?: number;
  templateLimit?: number;
  userLimit?: number;
}

type FrameworkKey = "fedramp" | "cmmc" | "soc2" | "cis" | "pci_dss" | "disa_stig";

interface ControlDefinition {
  control: number;
  id: string;
  title: string;
  severity: AnsibleSeverity;
  mappings: Record<FrameworkKey, string>;
}

const FRAMEWORK_KEYS: FrameworkKey[] = ["fedramp", "cmmc", "soc2", "cis", "pci_dss", "disa_stig"];

const FRAMEWORK_LABELS: Record<FrameworkKey, string> = {
  fedramp: "FedRAMP",
  cmmc: "CMMC",
  soc2: "SOC 2",
  cis: "CIS",
  pci_dss: "PCI-DSS",
  disa_stig: "STIG",
};

function control(
  controlNumber: number,
  id: string,
  title: string,
  severity: AnsibleSeverity,
  mappings: [string, string, string, string, string, string],
): ControlDefinition {
  return {
    control: controlNumber,
    id,
    title,
    severity,
    mappings: {
      fedramp: mappings[0],
      cmmc: mappings[1],
      soc2: mappings[2],
      cis: mappings[3],
      pci_dss: mappings[4],
      disa_stig: mappings[5],
    },
  };
}

export const ANSIBLE_CONTROLS: ControlDefinition[] = [
  control(1, "AAP-JOB-01", "Job success rate", "high", ["CA-7, SI-2", "CM.L2-3.4.1", "CC7.1, CC7.2", "16.12", "6.3.3", "SRG-APP-000456"]),
  control(2, "AAP-JOB-02", "Chronic playbook failures", "high", ["SI-2, CA-5", "CM.L2-3.4.1", "CC7.1, CC7.4", "7.4", "6.3.3", "SRG-APP-000456"]),
  control(3, "AAP-JOB-04", "Stuck or long-running jobs", "medium", ["CA-7, SI-4", "CM.L2-3.4.1", "CC7.1", "16.12", "6.3.3", "SRG-APP-000456"]),
  control(4, "AAP-JOB-03", "Manual launch rate", "medium", ["CM-3, CM-5", "CM.L2-3.4.3", "CC8.1", "4.1", "6.5.6", "SRG-APP-000380"]),
  control(5, "AAP-JOB-05", "Failed job remediation rate", "high", ["CA-5, SI-2", "CM.L2-3.4.1", "CC7.4", "7.2", "6.3.3", "SRG-APP-000456"]),
  control(6, "AAP-HOST-01", "Unmanaged hosts", "critical", ["CM-8, CM-8(1)", "CM.L2-3.4.1", "CC6.1", "1.1", "11.4", "SRG-APP-000516"]),
  control(7, "AAP-HOST-02", "Stale host coverage", "high", ["CM-8, SI-2", "CM.L2-3.4.1", "CC6.1, CC7.1", "1.1, 7.4", "11.4", "SRG-APP-000516"]),
  control(8, "AAP-HOST-03", "Inventory source sync health", "medium", ["CM-8(2)", "CM.L2-3.4.2", "CC6.1", "1.1", "11.4", "SRG-APP-000516"]),
  control(9, "AAP-HOST-05", "Host failure rate", "medium", ["CA-7, SI-4", "CM.L2-3.4.1", "CC7.1", "7.4", "11.4", "SRG-APP-000456"]),
  control(10, "AAP-HOST-04", "Disabled hosts", "low", ["CM-8", "CM.L2-3.4.1", "CC6.1", "1.1", "11.4", "SRG-APP-000516"]),
  control(11, "AAP-TMPL-01", "Stale job templates", "medium", ["CM-2, CM-7", "CM.L2-3.4.1", "CC8.1", "4.1", "6.5", "SRG-APP-000380"]),
  control(12, "AAP-TMPL-02", "Unscheduled critical templates", "high", ["CM-3, SI-2", "CM.L2-3.4.3", "CC8.1", "4.1", "6.5.6", "SRG-APP-000380"]),
  control(13, "AAP-SCHED-01", "Missed scheduled runs", "high", ["CA-7, CM-3", "CM.L2-3.4.3", "CC7.1, CC7.2", "4.1", "6.5.6", "SRG-APP-000380"]),
  control(14, "AAP-SCHED-02", "Disabled schedules", "medium", ["CM-3", "CM.L2-3.4.3", "CC8.1", "4.1", "6.5", "SRG-APP-000380"]),
  control(15, "AAP-TMPL-03", "Workflow coverage", "low", ["CM-3, SA-10", "CM.L2-3.4.3", "CC8.1", "4.1", "6.5", "SRG-APP-000380"]),
  control(16, "AAP-CRED-01", "Stale credentials", "high", ["IA-5, IA-5(1)", "IA.L2-3.5.7", "CC6.1", "5.2", "8.6.3", "SRG-APP-000174"]),
  control(17, "AAP-CRED-03", "Shared credential usage", "high", ["AC-6, IA-5", "AC.L2-3.1.5", "CC6.3", "5.4", "7.2.2", "SRG-APP-000340"]),
  control(18, "AAP-CRED-04", "Unvaulted secrets in templates and variables", "critical", ["IA-5(6), SC-28", "IA.L2-3.5.10", "CC6.1", "3.11", "3.5.1", "SRG-APP-000429"]),
  control(19, "AAP-CRED-05", "Credential ownership gaps", "medium", ["AC-2, IA-5", "AC.L2-3.1.1", "CC6.3", "5.1", "7.2.1", "SRG-APP-000033"]),
  control(20, "AAP-CRED-02", "OAuth2 token hygiene", "medium", ["IA-5(13), AC-2(3)", "IA.L2-3.5.10", "CC6.1", "5.2", "8.6.3", "SRG-APP-000174"]),
  control(21, "AAP-RBAC-01", "Organization admin count", "high", ["AC-6(5)", "AC.L2-3.1.6", "CC6.3", "5.4", "7.2.2", "SRG-APP-000340"]),
  control(22, "AAP-RBAC-03", "Team role audit", "high", ["AC-3, AC-6", "AC.L2-3.1.5", "CC6.3", "5.4, 6.8", "7.2.1", "SRG-APP-000033"]),
  control(23, "AAP-RBAC-04", "Execute versus admin separation", "high", ["AC-5, AC-6", "AC.L2-3.1.2", "CC6.3", "6.8", "7.2.2", "SRG-APP-000340"]),
  control(24, "AAP-RBAC-05", "Audit role coverage", "medium", ["AU-2, CA-7", "AU.L2-3.3.1", "CC7.2", "8.2", "10.1", "SRG-APP-000095"]),
  control(25, "AAP-RBAC-02", "External authentication enforcement", "critical", ["IA-2, IA-8", "IA.L2-3.5.3", "CC6.1", "5.6", "8.3", "SRG-APP-000148"]),
  control(26, "AAP-AUDIT-01", "Activity stream retention", "high", ["AU-2, AU-9", "AU.L2-3.3.1", "CC7.2, CC7.3", "8.2", "10.1", "SRG-APP-000095"]),
  control(27, "AAP-AUDIT-02", "Notification coverage", "medium", ["SI-4, IR-5", "SI.L2-3.14.6", "CC7.2", "8.11", "10.6", "SRG-APP-000481"]),
  control(28, "AAP-JOB-06", "Concurrent job limit", "low", ["SC-5, SI-4", "CM.L2-3.4.1", "CC7.1", "16.12", "6.3.3", "SRG-APP-000456"]),
  control(29, "AAP-PROJ-01", "Project SCM health", "medium", ["CM-2, SA-10", "CM.L2-3.4.2", "CC8.1", "4.8", "6.5", "SRG-APP-000380"]),
  control(30, "AAP-PLAT-01", "Execution environment inventory", "low", ["CM-7, CM-8", "CM.L2-3.4.1", "CC6.1", "2.2", "6.3.2", "SRG-APP-000516"]),
];

function controlDefinition(controlNumber: number): ControlDefinition {
  const definition = ANSIBLE_CONTROLS.find((item) => item.control === controlNumber);
  if (!definition) throw new Error(`Unknown Ansible control ${controlNumber}`);
  return definition;
}

function mappingsFor(definition: ControlDefinition): string[] {
  return FRAMEWORK_KEYS.flatMap((key) =>
    definition.mappings[key].split(",").map((entry) => `${FRAMEWORK_LABELS[key]} ${entry.trim()}`),
  );
}

function asObject(value: unknown): JsonRecord | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
  return value as JsonRecord;
}

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

function asNumber(value: unknown): number | undefined {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string" && value.trim().length > 0) {
    const parsed = Number(value);
    if (Number.isFinite(parsed)) return parsed;
  }
  return undefined;
}

function asBoolean(value: unknown): boolean | undefined {
  if (typeof value === "boolean") return value;
  if (typeof value === "string") {
    const normalized = value.trim().toLowerCase();
    if (["true", "1", "yes"].includes(normalized)) return true;
    if (["false", "0", "no"].includes(normalized)) return false;
  }
  return undefined;
}

function clampNumber(value: number | undefined, fallback: number, min: number, max: number): number {
  const parsed = Math.trunc(value ?? fallback);
  return Math.min(Math.max(parsed, min), max);
}

function normalizeBaseUrl(rawUrl: string): string {
  const parsed = new URL(rawUrl.trim());
  parsed.hash = "";
  parsed.search = "";
  parsed.pathname = parsed.pathname.replace(/\/+$/, "");
  if (parsed.pathname.endsWith("/api/v2")) {
    parsed.pathname = parsed.pathname.slice(0, -"/api/v2".length) || "/";
  } else if (parsed.pathname.endsWith("/api")) {
    parsed.pathname = parsed.pathname.slice(0, -"/api".length) || "/";
  }
  return parsed.toString().replace(/\/+$/, "");
}

function parseTimeoutSeconds(value: number | undefined): number {
  return clampNumber(value, DEFAULT_TIMEOUT_MS / 1000, 1, 300) * 1000;
}

export function resolveAnsibleConfiguration(
  input: JsonRecord = {},
  env: NodeJS.ProcessEnv = process.env,
): AnsibleAapConfiguration {
  if (asString(input.password) || asString(input.aap_password)) {
    throw new Error("AAP_PASSWORD must be provided via environment, not tool arguments.");
  }

  const sourceChain: string[] = [];
  const rawUrl = asString(input.url) ?? asString(input.base_url) ?? asString(env.AAP_URL);
  if (!rawUrl) {
    throw new Error("AAP_URL or a url argument is required.");
  }
  sourceChain.push(asString(input.url) || asString(input.base_url) ? "arguments" : "environment");

  const token = asString(input.token) ?? asString(env.AAP_TOKEN);
  const username = asString(input.username) ?? asString(env.AAP_USERNAME);
  const password = asString(env.AAP_PASSWORD);

  if (token) {
    sourceChain.push(asString(input.token) ? "arguments" : "environment");
  } else if (username && password) {
    sourceChain.push(asString(input.username) ? "arguments" : "environment");
    sourceChain.push("environment-password");
  } else {
    throw new Error("AAP_TOKEN or both AAP_USERNAME and AAP_PASSWORD are required.");
  }

  const timeoutSeconds = asNumber(input.timeout_seconds) ?? asNumber(env.AAP_TIMEOUT);
  const verifySsl = asBoolean(input.verify_ssl) ?? asBoolean(env.AAP_VERIFY_SSL) ?? true;

  return {
    baseUrl: normalizeBaseUrl(rawUrl),
    username,
    password,
    token,
    timeoutMs: parseTimeoutSeconds(timeoutSeconds),
    verifySsl,
    sourceChain: [...new Set(sourceChain)],
  };
}

/**
 * Builds a fetch implementation that disables TLS verification for its own
 * requests only, through a dedicated node:https agent. The process-wide
 * NODE_TLS_REJECT_UNAUTHORIZED variable is never touched.
 */
export function createTlsOptOutFetch(): FetchImpl {
  const agent = new HttpsAgent({ rejectUnauthorized: false });
  return async (input, init = {}) => {
    const url = new URL(typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url);
    const method = init.method ?? "GET";
    const headers: Record<string, string> = {};
    new Headers(init.headers ?? {}).forEach((value, key) => {
      headers[key] = value;
    });
    const body = typeof init.body === "string"
      ? init.body
      : init.body instanceof URLSearchParams
        ? init.body.toString()
        : undefined;

    return new Promise<Response>((resolvePromise, rejectPromise) => {
      const requestFn = url.protocol === "https:" ? httpsRequest : httpRequest;
      const req = requestFn(
        url,
        {
          method,
          headers,
          ...(url.protocol === "https:" ? { agent, rejectUnauthorized: false } : {}),
        },
        (response) => {
          const chunks: Buffer[] = [];
          response.on("data", (chunk: Buffer) => chunks.push(chunk));
          response.on("end", () => {
            const responseHeaders = new Headers();
            for (const [key, value] of Object.entries(response.headers)) {
              if (Array.isArray(value)) {
                for (const entry of value) responseHeaders.append(key, entry);
              } else if (typeof value === "string") {
                responseHeaders.set(key, value);
              }
            }
            const status = response.statusCode ?? 0;
            const payload = Buffer.concat(chunks);
            resolvePromise(new Response(status === 204 || status === 304 ? null : payload, {
              status,
              statusText: response.statusMessage ?? "",
              headers: responseHeaders,
            }));
          });
          response.on("error", rejectPromise);
        },
      );
      req.on("error", rejectPromise);
      init.signal?.addEventListener("abort", () => {
        req.destroy(new Error("Request aborted"));
      });
      if (body !== undefined) req.write(body);
      req.end();
    });
  };
}

function splitSetCookieHeader(value: string): string[] {
  return value.split(/,(?=\s*[^;,=\s]+=)/g);
}

function cookieHeaderFromHeaders(headers: Headers): string | undefined {
  const headersWithGetSetCookie = headers as Headers & { getSetCookie?: () => string[] };
  const setCookies =
    typeof headersWithGetSetCookie.getSetCookie === "function"
      ? headersWithGetSetCookie.getSetCookie()
      : headers.get("set-cookie")
        ? splitSetCookieHeader(headers.get("set-cookie") ?? "")
        : [];

  const cookies = setCookies
    .map((cookie) => cookie.split(";")[0]?.trim())
    .filter((cookie): cookie is string => Boolean(cookie));

  return cookies.length > 0 ? cookies.join("; ") : undefined;
}

function csrfTokenFromCookie(cookieHeader?: string): string | undefined {
  const match = cookieHeader?.match(/(?:^|;\s*)csrftoken=([^;]+)/i);
  return match?.[1];
}

function appendQuery(path: string, query: Record<string, string | number | boolean | undefined>): string {
  const base = path.startsWith("http://") || path.startsWith("https://")
    ? new URL(path)
    : new URL(path, "https://aap.local");

  for (const [key, value] of Object.entries(query)) {
    if (value === undefined) continue;
    base.searchParams.set(key, String(value));
  }

  if (path.startsWith("http://") || path.startsWith("https://")) {
    return base.toString();
  }

  return `${base.pathname}${base.search}`;
}

function extractText(value: unknown, fallback = ""): string {
  const text = asString(value);
  return text ?? fallback;
}

function extractTimestamp(value: unknown): string | undefined {
  if (typeof value === "string" && !Number.isNaN(Date.parse(value))) return value;
  return undefined;
}

function daysBetween(later: Date, earlierIso?: string): number | undefined {
  if (!earlierIso) return undefined;
  const earlier = new Date(earlierIso);
  if (Number.isNaN(earlier.getTime())) return undefined;
  return (later.getTime() - earlier.getTime()) / (24 * 60 * 60 * 1000);
}

function isFailureStatus(status: unknown): boolean {
  return ["failed", "error", "canceled", "cancelled"].includes(String(status ?? "").toLowerCase());
}

function isSuccessStatus(status: unknown): boolean {
  return String(status ?? "").toLowerCase() === "successful";
}

function isActiveStatus(status: unknown): boolean {
  return ["running", "pending", "waiting"].includes(String(status ?? "").toLowerCase());
}

function nameOf(item: JsonRecord): string {
  return extractText(item.name, extractText(item.username, extractText(item.id, "unknown")));
}

function summaryFields(item: JsonRecord): JsonRecord {
  return asObject(item.summary_fields) ?? {};
}

function formatPercent(value: number): string {
  return `${value.toFixed(1)}%`;
}

function serializeJson(value: unknown): string {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function safeDirName(value: string): string {
  const normalized = value
    .toLowerCase()
    .replace(/^https?:\/\//, "")
    .replace(/[^a-z0-9._-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 80);
  return normalized || "ansible-aap";
}

function ensurePrivateDir(pathname: string): void {
  mkdirSync(pathname, { recursive: true, mode: 0o700 });
  const realPath = realpathSync(pathname);
  const stat = lstatSync(realPath);
  if (!stat.isDirectory() || stat.isSymbolicLink()) {
    throw new Error(`Refusing to use non-directory or symlink path: ${pathname}`);
  }
}

export function resolveSecureOutputPath(baseDir: string, targetDir: string): string {
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
    const currentStat = lstatSync(currentPath);
    if (currentStat.isSymbolicLink()) {
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

async function nextAvailableAuditDir(root: string, preferredName: string): Promise<{ outputDir: string; zipPath: string }> {
  ensurePrivateDir(root);
  const suffixes = ["", "-2", "-3", "-4", "-5", "-6", "-7", "-8", "-9", "-10"];
  for (const suffix of suffixes) {
    const candidate = resolveSecureOutputPath(root, `${preferredName}${suffix}`);
    const zipCandidate = resolveSecureOutputPath(root, `${preferredName}${suffix}.zip`);
    if (!existsSync(candidate) && !existsSync(zipCandidate)) {
      mkdirSync(candidate, { recursive: true, mode: 0o700 });
      await chmod(candidate, 0o700);
      return { outputDir: candidate, zipPath: zipCandidate };
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
    const output = createWriteStream(zipPath, { mode: 0o600 });
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

export class AnsibleAapClient {
  private readonly fetchImpl: FetchImpl;
  private readonly now: () => Date;
  private sessionCookie?: string;
  private csrfToken?: string;
  private sessionPromise?: Promise<void>;
  private sessionExpiresAt?: number;

  constructor(
    private readonly config: AnsibleAapConfiguration,
    options: AnsibleAapClientOptions = {},
  ) {
    this.fetchImpl = options.fetchImpl ?? (config.verifySsl === false ? createTlsOptOutFetch() : fetch);
    this.now = options.now ?? (() => new Date());
  }

  private resolveUrl(pathOrUrl: string): string {
    if (pathOrUrl.startsWith("http://") || pathOrUrl.startsWith("https://")) {
      return pathOrUrl;
    }

    const normalizedPath = pathOrUrl.startsWith("/") ? pathOrUrl : `/api/v2/${pathOrUrl}`;
    return `${this.config.baseUrl}${normalizedPath}`;
  }

  private async fetchWithTimeout(url: string, init: RequestInit): Promise<Response> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.config.timeoutMs);
    try {
      return await this.fetchImpl(url, { ...init, signal: controller.signal });
    } finally {
      clearTimeout(timeout);
    }
  }

  private async ensureSession(): Promise<void> {
    if (this.config.token) return;
    if (this.sessionCookie && (this.sessionExpiresAt ?? 0) > Date.now() + TOKEN_SKEW_MS) return;
    if (this.sessionPromise) return this.sessionPromise;

    this.sessionPromise = this.createSession().finally(() => {
      this.sessionPromise = undefined;
    });
    return this.sessionPromise;
  }

  private async createSession(): Promise<void> {
    if (!this.config.username || !this.config.password) {
      throw new Error("AAP session auth requires AAP_USERNAME and AAP_PASSWORD.");
    }

    const loginUrl = this.resolveUrl("/api/login/");
    const initial = await this.fetchWithTimeout(loginUrl, {
      method: "GET",
      headers: { accept: "text/html,application/json" },
    });
    if (!initial.ok) {
      throw new Error(`AAP login bootstrap failed (${initial.status} ${initial.statusText}).`);
    }

    const bootstrapCookie = cookieHeaderFromHeaders(initial.headers);
    const csrfToken = csrfTokenFromCookie(bootstrapCookie);
    const body = new URLSearchParams({
      username: this.config.username,
      password: this.config.password,
    });

    const response = await this.fetchWithTimeout(loginUrl, {
      method: "POST",
      headers: {
        accept: "application/json",
        "content-type": "application/x-www-form-urlencoded",
        ...(bootstrapCookie ? { cookie: bootstrapCookie } : {}),
        ...(csrfToken ? { "x-csrftoken": csrfToken } : {}),
        referer: loginUrl,
      },
      body,
    });

    if (!response.ok) {
      throw new Error(`AAP session login failed (${response.status} ${response.statusText}).`);
    }

    const loginCookie = cookieHeaderFromHeaders(response.headers);
    this.sessionCookie = [bootstrapCookie, loginCookie].filter(Boolean).join("; ");
    this.csrfToken = csrfTokenFromCookie(this.sessionCookie) ?? csrfToken;
    this.sessionExpiresAt = Date.now() + 60 * 60 * 1000;
  }

  async get<T = unknown>(pathOrUrl: string): Promise<T> {
    await this.ensureSession();
    const headers: Record<string, string> = { accept: "application/json" };
    if (this.config.token) {
      headers.authorization = `Bearer ${this.config.token}`;
    } else {
      if (this.sessionCookie) headers.cookie = this.sessionCookie;
      if (this.csrfToken) headers["x-csrftoken"] = this.csrfToken;
    }

    const response = await this.fetchWithTimeout(this.resolveUrl(pathOrUrl), { method: "GET", headers });
    const text = await response.text();
    if (!response.ok) {
      throw new Error(`AAP request failed: ${pathOrUrl} (${response.status} ${response.statusText}) ${text.slice(0, 200)}`);
    }

    return text.length > 0 ? JSON.parse(text) as T : undefined as T;
  }

  async listCollection(
    path: string,
    query: Record<string, string | number | boolean | undefined> = {},
    options: { limit?: number } = {},
  ): Promise<AnsibleCollection> {
    const limit = options.limit ?? Number.POSITIVE_INFINITY;
    let next: string | null = appendQuery(path, { page_size: DEFAULT_PAGE_SIZE, ...query });
    const items: JsonRecord[] = [];
    let total: number | undefined;

    while (next && items.length < limit) {
      const page: AapListResponse<JsonRecord> | JsonRecord[] = await this.get<AapListResponse<JsonRecord> | JsonRecord[]>(next);
      const results = Array.isArray(page) ? page : page.results ?? [];
      if (!Array.isArray(page) && typeof page.count === "number") total = page.count;
      items.push(...results.slice(0, limit - items.length));
      next = Array.isArray(page) ? null : page.next ?? null;
    }

    if (next) {
      return {
        items,
        complete: false,
        total,
        truncation: `stopped at the requested limit of ${limit} with a next page still available`,
      };
    }
    return { items, complete: true, total: total ?? items.length };
  }

  async list<T = JsonRecord>(
    path: string,
    query: Record<string, string | number | boolean | undefined> = {},
    options: { limit?: number } = {},
  ): Promise<T[]> {
    const collection = await this.listCollection(path, query, options);
    return collection.items as T[];
  }

  async count(path: string): Promise<number> {
    const page = await this.get<AapListResponse<unknown>>(appendQuery(path, { page_size: 1 }));
    return typeof page.count === "number" ? page.count : page.results?.length ?? 0;
  }

  getNow(): Date {
    return this.now();
  }
}

export interface AnsibleClientSurface {
  getNow: () => Date;
  list: (path: string, query?: Record<string, string | number | boolean | undefined>, options?: { limit?: number }) => Promise<JsonRecord[]>;
  get?: (path: string) => Promise<unknown>;
  listCollection?: (path: string, query?: Record<string, string | number | boolean | undefined>, options?: { limit?: number }) => Promise<AnsibleCollection>;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function emptyCollection(): AnsibleCollection {
  return { items: [], complete: true, total: 0 };
}

async function collect(
  client: AnsibleClientSurface,
  label: string,
  path: string,
  query: Record<string, string | number | boolean | undefined> = {},
  limit?: number,
): Promise<Snapshot<AnsibleCollection>> {
  try {
    if (typeof client.listCollection === "function") {
      return { data: await client.listCollection(path, query, { limit }) };
    }
    const items = await client.list(path, query, { limit });
    const truncated = limit !== undefined && Number.isFinite(limit) && items.length >= limit;
    return {
      data: {
        items,
        complete: !truncated,
        total: truncated ? undefined : items.length,
        truncation: truncated ? `stopped at the requested limit of ${limit}` : undefined,
      },
    };
  } catch (error) {
    return { data: emptyCollection(), error: `${label} (${path}): ${errorMessage(error)}` };
  }
}

async function fetchObject(client: AnsibleClientSurface, label: string, path: string): Promise<Snapshot<JsonRecord | undefined>> {
  if (typeof client.get !== "function") {
    return { data: undefined, error: `${label} (${path}): client does not support object reads` };
  }
  try {
    return { data: asObject(await client.get(path)) };
  } catch (error) {
    return { data: undefined, error: `${label} (${path}): ${errorMessage(error)}` };
  }
}

interface InventoryView {
  label: string;
  items: JsonRecord[];
  error?: string;
  readable: boolean;
  empty: boolean;
  seen: number;
  total?: number;
  partial?: string;
}

function inventory(label: string, snapshot: Snapshot<AnsibleCollection>): InventoryView {
  const collection = snapshot.data;
  const readable = !snapshot.error;
  const partial = readable && !collection.complete
    ? `${label}: ${collection.items.length} of ${collection.total ?? "an unknown total of"} seen (${collection.truncation ?? "collection incomplete"})`
    : undefined;
  return {
    label,
    items: collection.items,
    error: snapshot.error,
    readable,
    empty: readable && collection.items.length === 0,
    seen: collection.items.length,
    total: collection.total,
    partial,
  };
}

export interface AnsibleScope {
  username?: string;
  superuser?: boolean;
  systemAuditor?: boolean;
  fullVisibility: boolean;
  note?: string;
}

function currentUserFromMe(value: unknown): JsonRecord | undefined {
  const object = asObject(value);
  if (!object) return undefined;
  if (Array.isArray(object.results)) return asObject(object.results[0]);
  return object;
}

async function probeScope(client: AnsibleClientSurface): Promise<Snapshot<AnsibleScope>> {
  const me = await fetchObject(client, "current user", "/api/v2/me/");
  const user = currentUserFromMe(me.data);
  if (me.error || !user) {
    return {
      data: { fullVisibility: false, note: "current user could not be read, so the visibility of the audit account is unknown" },
      error: me.error ?? "current user (/api/v2/me/): no user returned",
    };
  }
  const superuser = asBoolean(user.is_superuser);
  const systemAuditor = asBoolean(user.is_system_auditor);
  const fullVisibility = superuser === true || systemAuditor === true;
  return {
    data: {
      username: asString(user.username),
      superuser,
      systemAuditor,
      fullVisibility,
      note: fullVisibility
        ? undefined
        : `audit account ${asString(user.username) ?? ""} is neither a superuser nor a system auditor, so it only sees objects in its own organizations`.replace(/\s+/g, " "),
    },
  };
}

function scopeNotes(scope: Snapshot<AnsibleScope>): string[] {
  return scope.data.fullVisibility ? [] : [scope.data.note ?? "audit account visibility is unknown"];
}

function partialNotes(scope: Snapshot<AnsibleScope>, ...views: InventoryView[]): string[] {
  return [...scopeNotes(scope), ...views.map((view) => view.partial).filter((note): note is string => Boolean(note))];
}

function finding(
  controlNumber: number,
  status: AnsibleFindingStatus,
  summary: string,
  evidence?: JsonRecord,
  partialView: string[] = [],
  severityOverride?: AnsibleSeverity,
): AnsibleFinding {
  const definition = controlDefinition(controlNumber);
  const downgraded = status === "pass" && partialView.length > 0;
  return {
    id: definition.id,
    control: controlNumber,
    title: definition.title,
    severity: severityOverride ?? definition.severity,
    status: downgraded ? "warn" : status,
    summary: downgraded
      ? `${summary} Downgraded from pass to warn because the inventory is partial: ${partialView.join("; ")}.`
      : summary,
    evidence: partialView.length > 0 ? { ...(evidence ?? {}), partial_view: partialView } : evidence,
    mappings: mappingsFor(definition),
  };
}

function manualForUnreadable(controlNumber: number, view: InventoryView | { label: string; error?: string }, evidenceToCollect: string): AnsibleFinding {
  return finding(
    controlNumber,
    "manual",
    `${view.label} could not be read (${view.error ?? "unknown error"}), so this control cannot be verified from the API. Collect this evidence manually: ${evidenceToCollect}`,
    { error: view.error },
  );
}

function sample(items: JsonRecord[], picker: (item: JsonRecord) => unknown = nameOf, size = 10): unknown[] {
  return items.slice(0, size).map(picker);
}

function countByStatus(findings: AnsibleFinding[]): Record<AnsibleFindingStatus, number> {
  const counts: Record<AnsibleFindingStatus, number> = { pass: 0, warn: 0, fail: 0, manual: 0 };
  for (const item of findings) counts[item.status] += 1;
  return counts;
}

function severityRank(severity: AnsibleSeverity): number {
  switch (severity) {
    case "critical":
      return 0;
    case "high":
      return 1;
    case "medium":
      return 2;
    case "low":
      return 3;
    case "info":
      return 4;
    default: {
      const exhaustive: never = severity;
      return exhaustive;
    }
  }
}

function statusRank(status: AnsibleFindingStatus): number {
  switch (status) {
    case "fail":
      return 0;
    case "warn":
      return 1;
    case "manual":
      return 2;
    case "pass":
      return 3;
    default: {
      const exhaustive: never = status;
      return exhaustive;
    }
  }
}

async function readableSurface(client: AnsibleAapClient, name: string, endpoint: string): Promise<AnsibleAccessSurface> {
  try {
    return {
      name,
      endpoint,
      status: "readable",
      count: await client.count(endpoint),
    };
  } catch (error) {
    return {
      name,
      endpoint,
      status: "not_readable",
      error: errorMessage(error),
    };
  }
}

export async function checkAnsibleAccess(client: AnsibleAapClient): Promise<AnsibleAccessCheckResult> {
  const me = await client.get("/api/v2/me/");
  const currentUser = currentUserFromMe(me);
  const ping = await client.get<JsonRecord>("/api/v2/ping/").catch(() => undefined);

  const surfaces = await Promise.all([
    readableSurface(client, "organizations", "/api/v2/organizations/"),
    readableSurface(client, "users", "/api/v2/users/"),
    readableSurface(client, "teams", "/api/v2/teams/"),
    readableSurface(client, "inventories", "/api/v2/inventories/"),
    readableSurface(client, "hosts", "/api/v2/hosts/"),
    readableSurface(client, "job_templates", "/api/v2/job_templates/"),
    readableSurface(client, "workflow_job_templates", "/api/v2/workflow_job_templates/"),
    readableSurface(client, "jobs", "/api/v2/jobs/"),
    readableSurface(client, "job_host_summaries", "/api/v2/job_host_summaries/"),
    readableSurface(client, "credentials", "/api/v2/credentials/"),
    readableSurface(client, "schedules", "/api/v2/schedules/"),
    readableSurface(client, "projects", "/api/v2/projects/"),
    readableSurface(client, "execution_environments", "/api/v2/execution_environments/"),
    readableSurface(client, "instance_groups", "/api/v2/instance_groups/"),
    readableSurface(client, "notification_templates", "/api/v2/notification_templates/"),
    readableSurface(client, "activity_stream", "/api/v2/activity_stream/"),
    readableSurface(client, "auth_settings", "/api/v2/settings/authentication/"),
    readableSurface(client, "job_settings", "/api/v2/settings/jobs/"),
  ]);

  const readableCount = surfaces.filter((surface) => surface.status === "readable").length;
  const status = currentUser && readableCount >= 12 ? "healthy" : "limited";
  const superuser = currentUser ? asBoolean(currentUser.is_superuser) : undefined;
  const systemAuditor = currentUser ? asBoolean(currentUser.is_system_auditor) : undefined;
  const notes = [
    currentUser
      ? `Authenticated as ${extractText(currentUser.username, extractText(currentUser.email, "current AAP user"))}.`
      : "Authentication succeeded but /api/v2/me/ did not return a recognizable user.",
    superuser === true || systemAuditor === true
      ? `Account has full visibility (is_superuser=${String(superuser)}, is_system_auditor=${String(systemAuditor)}).`
      : "Account is not a superuser or system auditor; assessments will flag every would-be pass as a partial inventory.",
    `${readableCount}/${surfaces.length} audit surfaces are readable.`,
  ];

  return {
    status,
    currentUser,
    ping,
    surfaces,
    notes,
    recommendedNextStep:
      status === "healthy"
        ? "Run ansible_assess_job_health, ansible_assess_host_coverage, and ansible_assess_platform_security."
        : "Grant the audit account the System Auditor role so jobs, hosts, templates, schedules, credentials, teams, projects, the activity stream, and settings are readable.",
  };
}

interface TemplateStats {
  key: string;
  name: string;
  total: number;
  failed: number;
  leadingFailures: number;
}

function templateKey(job: JsonRecord): string {
  return String(job.unified_job_template ?? job.job_template ?? job.name ?? "unknown");
}

function groupJobsByTemplate(jobs: JsonRecord[]): Map<string, TemplateStats> {
  const byTemplate = new Map<string, TemplateStats>();
  for (const job of jobs) {
    const key = templateKey(job);
    const current = byTemplate.get(key) ?? { key, name: extractText(job.name, key), total: 0, failed: 0, leadingFailures: 0 };
    current.total += 1;
    if (isFailureStatus(job.status)) {
      current.failed += 1;
      if (current.leadingFailures === current.total - 1) current.leadingFailures += 1;
    }
    byTemplate.set(key, current);
  }
  return byTemplate;
}

export interface JobHealthData {
  days: number;
  since: string;
  scope: Snapshot<AnsibleScope>;
  jobs: Snapshot<AnsibleCollection>;
  jobSettings: Snapshot<JsonRecord | undefined>;
  instanceGroups: Snapshot<AnsibleCollection>;
}

export async function collectAnsibleJobHealthData(client: AnsibleClientSurface, options: JobHealthOptions = {}): Promise<JobHealthData> {
  const now = client.getNow();
  const days = clampNumber(options.days, DEFAULT_LOOKBACK_DAYS, 1, 365);
  const since = new Date(now.getTime() - days * 24 * 60 * 60 * 1000).toISOString();
  const scope = await probeScope(client);
  const jobs = await collect(
    client,
    "jobs",
    "/api/v2/jobs/",
    { type: "job", started__gt: since, order_by: "-started" },
    clampNumber(options.jobLimit, DEFAULT_JOB_LIMIT, 1, 5000),
  );
  const jobSettings = await fetchObject(client, "job settings", "/api/v2/settings/jobs/");
  const instanceGroups = await collect(client, "instance groups", "/api/v2/instance_groups/", {}, 200);
  return { days, since, scope, jobs, jobSettings, instanceGroups };
}

export function assessAnsibleJobHealthData(data: JobHealthData, now: Date, options: JobHealthOptions = {}): AnsibleAssessmentResult {
  const minSuccessRate = options.minSuccessRate ?? 90;
  const maxManualRate = options.maxManualRate ?? 25;
  const jobs = inventory("jobs", data.jobs);
  const groups = inventory("instance groups", data.instanceGroups);
  const partial = partialNotes(data.scope, jobs);
  const findings: AnsibleFinding[] = [];
  const errors = [data.scope.error, data.jobs.error, data.jobSettings.error, data.instanceGroups.error].filter((entry): entry is string => Boolean(entry));

  const jobEvidence = "the Jobs list in the controller UI filtered to the audit window, exported as CSV";
  if (!jobs.readable) {
    for (const controlNumber of [1, 2, 3, 4, 5]) findings.push(manualForUnreadable(controlNumber, jobs, jobEvidence));
  } else if (jobs.empty) {
    findings.push(finding(1, "fail", `No job executions were visible in the last ${data.days} days. An empty job history is treated as fail for this control because an automation program with no runs cannot demonstrate that baselines are enforced.`, { total: 0, days: data.days }));
    for (const controlNumber of [2, 3, 4, 5]) {
      findings.push(finding(controlNumber, "manual", `No job executions were visible in the last ${data.days} days, so there is no execution history to evaluate. Empty history is treated as manual for this control: confirm with the platform owners whether the controller is idle by design and collect ${jobEvidence}.`, { total: 0, days: data.days }));
    }
  } else {
    const all = jobs.items;
    const completed = all.filter((job) => isSuccessStatus(job.status) || isFailureStatus(job.status));
    const successful = completed.filter((job) => isSuccessStatus(job.status));
    const failed = completed.filter((job) => isFailureStatus(job.status));
    const successRate = completed.length === 0 ? 0 : (successful.length / completed.length) * 100;
    findings.push(
      completed.length === 0
        ? finding(1, "warn", `${all.length} jobs were visible but none has reached a terminal status, so a success rate cannot be computed yet.`, { total: all.length, completed: 0 }, partial)
        : finding(
          1,
          successRate < minSuccessRate ? "fail" : "pass",
          `${successful.length}/${completed.length} completed jobs succeeded (${formatPercent(successRate)}) against a ${minSuccessRate}% minimum over ${data.days} days; ${jobs.seen} jobs seen${jobs.total !== undefined ? ` of ${jobs.total}` : ""}.`,
          { total: all.length, completed: completed.length, successful: successful.length, failed: failed.length, success_rate: successRate, min_success_rate: minSuccessRate },
          partial,
        ),
    );

    const byTemplate = groupJobsByTemplate(all);
    const chronic = [...byTemplate.values()]
      .filter((template) => template.total >= 3 && (template.failed / template.total > 0.2 || template.leadingFailures > 3))
      .sort((left, right) => right.failed / right.total - left.failed / left.total)
      .slice(0, 10);
    findings.push(finding(
      2,
      chronic.length > 0 ? "fail" : "pass",
      chronic.length > 0
        ? `${chronic.length} job templates show more than 3 consecutive failures or a failure rate above 20% in the sampled window.`
        : `No job template with at least 3 runs exceeded 3 consecutive failures or a 20% failure rate across ${byTemplate.size} templates seen.`,
      { templates: chronic },
      partial,
    ));

    const baselines = new Map<string, number>();
    for (const [key, _stats] of byTemplate) {
      const durations = all
        .filter((job) => templateKey(job) === key && isSuccessStatus(job.status))
        .map((job) => asNumber(job.elapsed))
        .filter((value): value is number => value !== undefined && value > 0);
      if (durations.length > 0) baselines.set(key, durations.reduce((sum, value) => sum + value, 0) / durations.length);
    }
    const active = all.filter((job) => isActiveStatus(job.status));
    const undatedActive = active.filter((job) => !extractTimestamp(job.started));
    const unknownBaseline: JsonRecord[] = [];
    const stuck: JsonRecord[] = [];
    for (const job of active) {
      const started = extractTimestamp(job.started);
      if (!started) continue;
      const baseline = baselines.get(templateKey(job));
      const runningSeconds = (now.getTime() - new Date(started).getTime()) / 1000;
      if (baseline === undefined) {
        unknownBaseline.push({ id: job.id, name: job.name, running_seconds: Math.round(runningSeconds) });
        continue;
      }
      if (runningSeconds > 2 * baseline) {
        stuck.push({ id: job.id, name: job.name, status: job.status, running_seconds: Math.round(runningSeconds), baseline_seconds: Math.round(baseline) });
      }
    }
    findings.push(finding(
      3,
      stuck.length > 0 ? "warn" : undatedActive.length > 0 || unknownBaseline.length > 0 ? "warn" : "pass",
      stuck.length > 0
        ? `${stuck.length} running or pending jobs exceed 2x the average successful runtime of their template.`
        : undatedActive.length > 0 || unknownBaseline.length > 0
          ? `${active.length} running or pending jobs were seen; ${undatedActive.length} have no started timestamp and ${unknownBaseline.length} have no successful runtime baseline, so they cannot be cleared as healthy.`
          : `${active.length} running or pending jobs were seen and none exceeds 2x its template's average successful runtime.`,
      { active: active.length, stuck, undated_active: undatedActive.length, unknown_baseline: unknownBaseline },
      partial,
    ));

    const manual = all.filter((job) => String(job.launch_type ?? "").toLowerCase() === "manual");
    const manualRate = (manual.length / all.length) * 100;
    findings.push(finding(
      4,
      manualRate > maxManualRate ? "warn" : "pass",
      `${manual.length}/${all.length} jobs were launched manually (${formatPercent(manualRate)}) against a ${maxManualRate}% maximum.`,
      { manual: manual.length, total: all.length, manual_rate: manualRate, max_manual_rate: maxManualRate },
      partial,
    ));

    const undatedFailed: JsonRecord[] = [];
    const unremediated: JsonRecord[] = [];
    let pending = 0;
    let remediated = 0;
    for (const job of failed) {
      const failedAt = extractTimestamp(job.finished) ?? extractTimestamp(job.started);
      if (!failedAt) {
        undatedFailed.push({ id: job.id, name: job.name });
        continue;
      }
      const failedTime = new Date(failedAt).getTime();
      const followUp = successful.find((candidate) => {
        const started = extractTimestamp(candidate.started);
        if (!started || templateKey(candidate) !== templateKey(job)) return false;
        const startedTime = new Date(started).getTime();
        return startedTime > failedTime && startedTime - failedTime <= REMEDIATION_WINDOW_DAYS * 24 * 60 * 60 * 1000;
      });
      if (followUp) {
        remediated += 1;
      } else if (now.getTime() - failedTime > REMEDIATION_WINDOW_DAYS * 24 * 60 * 60 * 1000) {
        unremediated.push({ id: job.id, name: job.name, failed_at: failedAt });
      } else {
        pending += 1;
      }
    }
    findings.push(finding(
      5,
      failed.length === 0
        ? "pass"
        : unremediated.length > 0
          ? "fail"
          : undatedFailed.length > 0
            ? "warn"
            : "pass",
      failed.length === 0
        ? `No failed jobs in ${completed.length} completed jobs over ${data.days} days; an empty failed set is compliant by intent for this control.`
        : `${remediated}/${failed.length} failed jobs were followed by a successful run of the same template within ${REMEDIATION_WINDOW_DAYS} days; ${unremediated.length} were not, ${pending} are still inside the remediation window, and ${undatedFailed.length} have no timestamp.`,
      { failed: failed.length, remediated, unremediated: unremediated.slice(0, 10), pending, undated: undatedFailed.slice(0, 10) },
      partial,
    ));
  }

  const settings = data.jobSettings.data;
  const scheduleMaxJobs = settings ? asNumber(settings.SCHEDULE_MAX_JOBS) : undefined;
  const maxForksSetting = settings ? asNumber(settings.MAX_FORKS) : undefined;
  if (data.jobSettings.error || !settings) {
    findings.push(manualForUnreadable(28, { label: "job settings", error: data.jobSettings.error ?? "no settings object returned" }, "Settings > Jobs (Maximum Scheduled Jobs, Maximum Forks) and each instance group's Max concurrent jobs and Max forks values"));
  } else if (!groups.readable) {
    findings.push(manualForUnreadable(28, groups, "each instance group's Max concurrent jobs and Max forks values from Administration > Instance Groups"));
  } else if (groups.empty) {
    findings.push(finding(28, "manual", "No instance groups were visible, so concurrency limits cannot be verified. Empty inventory is treated as manual for this control: confirm the audit account can read Administration > Instance Groups.", { schedule_max_jobs: scheduleMaxJobs, max_forks: maxForksSetting }));
  } else {
    const unknown: string[] = [];
    const unlimited: string[] = [];
    for (const group of groups.items) {
      const maxConcurrent = asNumber(group.max_concurrent_jobs);
      const maxForks = asNumber(group.max_forks);
      if (maxConcurrent === undefined || maxForks === undefined) {
        unknown.push(nameOf(group));
      } else if (maxConcurrent === 0 && maxForks === 0) {
        unlimited.push(nameOf(group));
      }
    }
    const evidence = { schedule_max_jobs: scheduleMaxJobs, max_forks_setting: maxForksSetting, instance_groups: groups.seen, unlimited_groups: unlimited, unknown_groups: unknown };
    if (scheduleMaxJobs === undefined || unknown.length > 0) {
      findings.push(finding(28, "manual", `Concurrency limit fields are not exposed on this deployment (SCHEDULE_MAX_JOBS ${scheduleMaxJobs === undefined ? "absent" : "present"}, ${unknown.length} instance groups without max_concurrent_jobs or max_forks). Verify the instance group limits manually in Administration > Instance Groups.`, evidence));
    } else {
      findings.push(finding(
        28,
        unlimited.length > 0 ? "warn" : "pass",
        unlimited.length > 0
          ? `${unlimited.length}/${groups.seen} instance groups have neither max_concurrent_jobs nor max_forks set (0 means unlimited); SCHEDULE_MAX_JOBS is ${scheduleMaxJobs}.`
          : `All ${groups.seen} instance groups define a max_concurrent_jobs or max_forks limit and SCHEDULE_MAX_JOBS is ${scheduleMaxJobs}.`,
        evidence,
        partialNotes(data.scope, groups),
      ));
    }
  }

  findings.sort((left, right) => left.control - right.control);
  const counts = countByStatus(findings);
  return {
    category: "job-health",
    title: "Ansible AAP job execution health",
    summary: {
      days: data.days,
      total_jobs: jobs.seen,
      jobs_total_reported: jobs.total,
      successful: jobs.items.filter((job) => isSuccessStatus(job.status)).length,
      failed: jobs.items.filter((job) => isFailureStatus(job.status)).length,
      instance_groups: groups.seen,
      full_visibility: data.scope.data.fullVisibility,
      ...counts,
    },
    findings,
    errors,
  };
}

export async function assessAnsibleJobHealth(client: AnsibleClientSurface, options: JobHealthOptions = {}): Promise<AnsibleAssessmentResult> {
  const data = await collectAnsibleJobHealthData(client, options);
  return assessAnsibleJobHealthData(data, client.getNow(), options);
}

export interface HostCoverageData {
  days: number;
  since: string;
  scope: Snapshot<AnsibleScope>;
  hosts: Snapshot<AnsibleCollection>;
  inventorySources: Snapshot<AnsibleCollection>;
  hostSummaries: Snapshot<AnsibleCollection>;
  jobTemplates: Snapshot<AnsibleCollection>;
  schedules: Snapshot<AnsibleCollection>;
  workflowTemplates: Snapshot<AnsibleCollection>;
}

export async function collectAnsibleHostCoverageData(client: AnsibleClientSurface, options: HostCoverageOptions = {}): Promise<HostCoverageData> {
  const now = client.getNow();
  const days = clampNumber(options.days, DEFAULT_LOOKBACK_DAYS, 1, 365);
  const since = new Date(now.getTime() - days * 24 * 60 * 60 * 1000).toISOString();
  const scope = await probeScope(client);
  const hosts = await collect(client, "hosts", "/api/v2/hosts/", { order_by: "name" }, clampNumber(options.hostLimit, DEFAULT_HOST_LIMIT, 1, 10_000));
  const inventorySources = await collect(client, "inventory sources", "/api/v2/inventory_sources/", {}, clampNumber(options.inventorySourceLimit, 200, 1, 5000));
  const hostSummaries = await collect(client, "job host summaries", "/api/v2/job_host_summaries/", { created__gt: since, order_by: "-created" }, DEFAULT_SUMMARY_LIMIT);
  const templateLimit = clampNumber(options.templateLimit, DEFAULT_TEMPLATE_LIMIT, 1, 5000);
  const jobTemplates = await collect(client, "job templates", "/api/v2/job_templates/", { order_by: "name" }, templateLimit);
  const schedules = await collect(client, "schedules", "/api/v2/schedules/", {}, templateLimit * 2);
  const workflowTemplates = await collect(client, "workflow job templates", "/api/v2/workflow_job_templates/", {}, templateLimit);
  return { days, since, scope, hosts, inventorySources, hostSummaries, jobTemplates, schedules, workflowTemplates };
}

function hostLastJobFinished(host: JsonRecord): string | undefined {
  const lastJob = asObject(summaryFields(host).last_job);
  return extractTimestamp(lastJob?.finished);
}

interface RruleInterval {
  days: number;
  label: string;
}

export function parseRruleInterval(rrule: unknown): RruleInterval | undefined {
  const text = asString(rrule);
  if (!text) return undefined;
  const freq = text.match(/FREQ=([A-Z]+)/i)?.[1]?.toUpperCase();
  const interval = asNumber(text.match(/INTERVAL=(\d+)/i)?.[1]) ?? 1;
  const unitDays: Record<string, number> = { MINUTELY: 1 / (24 * 60), HOURLY: 1 / 24, DAILY: 1, WEEKLY: 7, MONTHLY: 30, YEARLY: 365 };
  if (!freq || !(freq in unitDays)) return undefined;
  return { days: unitDays[freq] * interval, label: `${freq} x${interval}` };
}

export function assessAnsibleHostCoverageData(data: HostCoverageData, now: Date, options: HostCoverageOptions = {}): AnsibleAssessmentResult {
  const staleDays = clampNumber(options.staleHostDays, 30, 1, 365);
  const criticalDays = clampNumber(options.criticalStaleHostDays, 60, staleDays, 730);
  const staleTemplateDays = clampNumber(options.staleTemplateDays, 90, 1, 730);
  const hosts = inventory("hosts", data.hosts);
  const sources = inventory("inventory sources", data.inventorySources);
  const summaries = inventory("job host summaries", data.hostSummaries);
  const templates = inventory("job templates", data.jobTemplates);
  const schedules = inventory("schedules", data.schedules);
  const workflows = inventory("workflow job templates", data.workflowTemplates);
  const findings: AnsibleFinding[] = [];
  const errors = [data.scope.error, data.hosts.error, data.inventorySources.error, data.hostSummaries.error, data.jobTemplates.error, data.schedules.error, data.workflowTemplates.error]
    .filter((entry): entry is string => Boolean(entry));

  const hostEvidence = "the Hosts list under each inventory in the controller UI, including the Last Job column";
  const hostPartial = partialNotes(data.scope, hosts);
  if (!hosts.readable) {
    for (const controlNumber of [6, 7, 10]) findings.push(manualForUnreadable(controlNumber, hosts, hostEvidence));
  } else if (hosts.empty) {
    for (const controlNumber of [6, 7, 10]) {
      findings.push(finding(controlNumber, "manual", `No hosts were visible. Empty inventory is treated as manual for this control because the audit account may not see the inventories; confirm inventory membership from ${hostEvidence}.`, { total_hosts: 0 }));
    }
  } else {
    const unmanaged = hosts.items.filter((host) => host.last_job === null || host.last_job === undefined);
    findings.push(finding(
      6,
      unmanaged.length > 0 ? "fail" : "pass",
      unmanaged.length > 0
        ? `${unmanaged.length}/${hosts.seen} hosts have last_job null and have never been touched by a job.`
        : `Every one of the ${hosts.seen} hosts seen has a last_job reference.`,
      { count: unmanaged.length, sample: sample(unmanaged) },
      hostPartial,
    ));

    const managed = hosts.items.filter((host) => !(host.last_job === null || host.last_job === undefined));
    const undated = managed.filter((host) => !hostLastJobFinished(host));
    const stale = managed.filter((host) => {
      const age = daysBetween(now, hostLastJobFinished(host));
      return age !== undefined && age > staleDays;
    });
    const criticalStale = managed.filter((host) => {
      const age = daysBetween(now, hostLastJobFinished(host));
      return age !== undefined && age > criticalDays;
    });
    findings.push(finding(
      7,
      stale.length > 0 ? "fail" : undated.length > 0 ? "warn" : "pass",
      stale.length > 0
        ? `${stale.length}/${managed.length} managed hosts have no completed job in more than ${staleDays} days; ${criticalStale.length} exceed ${criticalDays} days; ${undated.length} have no last job finished timestamp.`
        : undated.length > 0
          ? `No managed host exceeded ${staleDays} days, but ${undated.length}/${managed.length} have no summary_fields.last_job.finished timestamp and cannot be counted as fresh.`
          : `None of the ${managed.length} managed hosts exceeded the ${staleDays}-day stale coverage threshold.`,
      { stale_count: stale.length, critical_stale_count: criticalStale.length, undated_count: undated.length, sample: sample(stale) },
      hostPartial,
      criticalStale.length > 0 ? "critical" : undefined,
    ));

    const disabled = hosts.items.filter((host) => asBoolean(host.enabled) === false);
    const unknownEnabled = hosts.items.filter((host) => asBoolean(host.enabled) === undefined);
    const disabledRate = (disabled.length / hosts.seen) * 100;
    findings.push(finding(
      10,
      disabledRate > 5 ? "warn" : unknownEnabled.length > 0 ? "warn" : "pass",
      `${disabled.length}/${hosts.seen} hosts are disabled (${formatPercent(disabledRate)}) against a 5% ceiling${unknownEnabled.length > 0 ? `; ${unknownEnabled.length} hosts have no enabled flag and cannot be cleared` : ""}.`,
      { disabled_count: disabled.length, disabled_rate: disabledRate, unknown_enabled: unknownEnabled.length },
      hostPartial,
    ));
  }

  if (!sources.readable) {
    findings.push(manualForUnreadable(8, sources, "each inventory's Sources tab with Last Job Status and Last Updated values"));
  } else if (sources.empty) {
    findings.push(finding(8, "manual", "No dynamic inventory sources were visible. Empty inventory is treated as manual for this control: confirm that every inventory is intentionally static or that the audit account can read inventory sources.", { inventory_sources: 0 }));
  } else {
    const undated = sources.items.filter((source) => !extractTimestamp(source.last_updated));
    const unhealthy = sources.items.filter((source) => {
      const status = String(source.status ?? "").toLowerCase();
      const age = daysBetween(now, extractTimestamp(source.last_updated));
      return asBoolean(source.last_update_failed) === true || ["failed", "error"].includes(status) || (age !== undefined && age > staleDays);
    });
    findings.push(finding(
      8,
      unhealthy.length > 0 ? "warn" : undated.length > 0 ? "warn" : "pass",
      unhealthy.length > 0
        ? `${unhealthy.length}/${sources.seen} inventory sources report last_update_failed, a failed status, or a last_updated older than ${staleDays} days; ${undated.length} have never synced.`
        : undated.length > 0
          ? `No inventory source failed, but ${undated.length}/${sources.seen} have no last_updated timestamp and cannot be counted as synced.`
          : `All ${sources.seen} inventory sources synced successfully within ${staleDays} days.`,
      { count: unhealthy.length, undated_count: undated.length, sample: sample(unhealthy) },
      partialNotes(data.scope, sources),
    ));
  }

  if (!summaries.readable) {
    findings.push(manualForUnreadable(9, summaries, "per-host job results from each host's Jobs tab for the audit window"));
  } else if (summaries.empty) {
    findings.push(finding(9, "manual", `No job host summaries were visible for the last ${data.days} days. Empty inventory is treated as manual for this control because per-host failure rates need execution history; confirm with the platform owners.`, { summaries: 0, days: data.days }));
  } else {
    const perHost = new Map<string, { name: string; total: number; failed: number }>();
    for (const summary of summaries.items) {
      const key = String(summary.host ?? summary.host_name ?? "unknown");
      const current = perHost.get(key) ?? { name: extractText(summary.host_name, key), total: 0, failed: 0 };
      current.total += 1;
      if (asBoolean(summary.failed) === true) current.failed += 1;
      perHost.set(key, current);
    }
    const evaluated = [...perHost.values()].filter((host) => host.total >= 3);
    const flagged = evaluated.filter((host) => host.failed / host.total > 0.3);
    findings.push(finding(
      9,
      flagged.length > 0 ? "warn" : evaluated.length === 0 ? "warn" : "pass",
      flagged.length > 0
        ? `${flagged.length}/${evaluated.length} hosts with at least 3 runs failed more than 30% of their jobs in the last ${data.days} days.`
        : evaluated.length === 0
          ? `${perHost.size} hosts appeared in ${summaries.seen} job host summaries but none has 3 or more runs, so failure rates cannot be judged.`
          : `None of the ${evaluated.length} hosts with at least 3 runs exceeded a 30% failure rate (${summaries.seen} summaries seen).`,
      { hosts_seen: perHost.size, evaluated: evaluated.length, flagged: flagged.slice(0, 10) },
      partialNotes(data.scope, summaries),
    ));
  }

  const templateEvidence = "the Templates list with Last Ran and Schedules for each template";
  const templatePartial = partialNotes(data.scope, templates, schedules);
  if (!templates.readable) {
    for (const controlNumber of [11, 12]) findings.push(manualForUnreadable(controlNumber, templates, templateEvidence));
  } else if (templates.empty) {
    for (const controlNumber of [11, 12]) {
      findings.push(finding(controlNumber, "manual", `No job templates were visible. Empty inventory is treated as manual for this control: confirm the audit account can read templates or that no automation is defined.`, { job_templates: 0 }));
    }
  } else {
    const neverRan = templates.items.filter((template) => !extractTimestamp(template.last_job_run));
    const stale = templates.items.filter((template) => {
      const age = daysBetween(now, extractTimestamp(template.last_job_run));
      return age !== undefined && age > staleTemplateDays;
    });
    findings.push(finding(
      11,
      stale.length + neverRan.length > 0 ? "warn" : "pass",
      stale.length + neverRan.length > 0
        ? `${stale.length}/${templates.seen} job templates last ran more than ${staleTemplateDays} days ago and ${neverRan.length} have never run (last_job_run null).`
        : `All ${templates.seen} job templates ran within the last ${staleTemplateDays} days.`,
      { stale: sample(stale), never_ran: sample(neverRan) },
      templatePartial,
    ));

    const critical = templates.items.filter((template) =>
      CRITICAL_TEMPLATE_PATTERN.test([template.name, template.playbook, template.description].map((value) => extractText(value)).join(" ")),
    );
    if (!schedules.readable) {
      findings.push(manualForUnreadable(12, schedules, `the Schedules tab of the ${critical.length} critical templates`));
    } else if (critical.length === 0) {
      findings.push(finding(12, "manual", `None of the ${templates.seen} job templates matched the critical keyword list (patching, hardening, logging, access control), so unscheduled critical templates must be identified manually.`, { critical_templates: 0 }));
    } else {
      const scheduled = new Set(schedules.items.map((schedule) => String(schedule.unified_job_template ?? "")));
      const unscheduled = critical.filter((template) => !scheduled.has(String(template.id ?? "")));
      findings.push(finding(
        12,
        unscheduled.length > 0 ? "fail" : "pass",
        unscheduled.length > 0
          ? `${unscheduled.length}/${critical.length} critical job templates have no schedule.`
          : `All ${critical.length} critical job templates have at least one schedule.`,
        { critical_templates: critical.length, unscheduled: sample(unscheduled) },
        templatePartial,
      ));
    }
  }

  const scheduleEvidence = "the Schedules list with Enabled, Next Run, and the owning template's Last Ran";
  if (!schedules.readable) {
    for (const controlNumber of [13, 14]) findings.push(manualForUnreadable(controlNumber, schedules, scheduleEvidence));
  } else if (schedules.empty) {
    for (const controlNumber of [13, 14]) {
      findings.push(finding(controlNumber, "manual", "No schedules were visible. Empty inventory is treated as manual for this control: confirm whether automation is intentionally run without schedules (see control 12) or the audit account cannot read schedules.", { schedules: 0 }));
    }
  } else {
    const templateById = new Map(templates.items.map((template) => [String(template.id ?? ""), template]));
    const enabled = schedules.items.filter((schedule) => asBoolean(schedule.enabled) === true);
    const missed: JsonRecord[] = [];
    const unknown: JsonRecord[] = [];
    for (const schedule of enabled) {
      const nextRun = extractTimestamp(schedule.next_run);
      const interval = parseRruleInterval(schedule.rrule);
      const template = templateById.get(String(schedule.unified_job_template ?? ""));
      const lastRun = template ? extractTimestamp(template.last_job_run) : undefined;
      const entry = { id: schedule.id, name: schedule.name, next_run: nextRun ?? null, rrule: schedule.rrule, last_job_run: lastRun ?? null };
      if (!nextRun || new Date(nextRun).getTime() < now.getTime()) {
        missed.push({ ...entry, reason: nextRun ? "next_run is in the past" : "next_run is null on an enabled schedule" });
        continue;
      }
      if (!interval) {
        unknown.push({ ...entry, reason: "rrule frequency could not be parsed" });
        continue;
      }
      if (!template) {
        unknown.push({ ...entry, reason: "owning template not in the sampled templates" });
        continue;
      }
      if (!lastRun) {
        unknown.push({ ...entry, reason: "template has never run" });
        continue;
      }
      const age = daysBetween(now, lastRun) ?? 0;
      if (age > MISSED_RUN_MULTIPLIER * interval.days) {
        missed.push({ ...entry, reason: `last run ${age.toFixed(1)} days ago exceeds ${MISSED_RUN_MULTIPLIER}x the ${interval.label} interval` });
      }
    }
    findings.push(finding(
      13,
      missed.length > 0 ? "fail" : unknown.length > 0 ? "warn" : "pass",
      missed.length > 0
        ? `${missed.length}/${enabled.length} enabled schedules have a past or null next_run, or a last run older than ${MISSED_RUN_MULTIPLIER}x their interval.`
        : unknown.length > 0
          ? `No enabled schedule missed its window, but ${unknown.length}/${enabled.length} could not be fully evaluated (unparsed rrule, never-run or unsampled template).`
          : `All ${enabled.length} enabled schedules have a future next_run and a last run within ${MISSED_RUN_MULTIPLIER}x their interval.`,
      { enabled: enabled.length, missed: missed.slice(0, 10), unknown: unknown.slice(0, 10) },
      templatePartial,
    ));

    const disabled = schedules.items.filter((schedule) => asBoolean(schedule.enabled) === false);
    const unknownEnabled = schedules.items.filter((schedule) => asBoolean(schedule.enabled) === undefined);
    findings.push(finding(
      14,
      disabled.length > 0 ? "warn" : unknownEnabled.length > 0 ? "warn" : "pass",
      disabled.length > 0
        ? `${disabled.length}/${schedules.seen} schedules are disabled (enabled=false).`
        : unknownEnabled.length > 0
          ? `${unknownEnabled.length}/${schedules.seen} schedules have no enabled flag and cannot be cleared.`
          : `All ${schedules.seen} schedules are enabled.`,
      { disabled: sample(disabled), unknown_enabled: unknownEnabled.length },
      partialNotes(data.scope, schedules),
    ));
  }

  if (!workflows.readable) {
    findings.push(manualForUnreadable(15, workflows, "the Templates list filtered to Workflow Templates"));
  } else if (workflows.empty) {
    const automationDefined = templates.readable && !templates.empty;
    findings.push(finding(
      15,
      automationDefined ? "fail" : "manual",
      automationDefined
        ? `No workflow job templates exist while ${templates.seen} job templates do, so multi-step paths (patch, validate, notify) run as fragile single templates. An empty workflow inventory is treated as fail for this control when job templates exist.`
        : "No workflow job templates were visible and no job templates could be confirmed either. An empty workflow inventory is treated as manual for this control: confirm whether automation is defined and visible to the audit account.",
      { workflow_job_templates: 0, job_templates: templates.seen },
    ));
  } else {
    const criticalWorkflows = workflows.items.filter((workflow) =>
      CRITICAL_TEMPLATE_PATTERN.test([workflow.name, workflow.description].map((value) => extractText(value)).join(" ")),
    );
    findings.push(finding(
      15,
      criticalWorkflows.length > 0 ? "pass" : "warn",
      criticalWorkflows.length > 0
        ? `${workflows.seen} workflow job templates exist and ${criticalWorkflows.length} match the critical keyword list (patching, hardening, logging, access control).`
        : `${workflows.seen} workflow job templates exist but none matches the critical keyword list, so critical multi-step paths may still run as single templates.`,
      { workflow_job_templates: workflows.seen, critical_workflows: sample(criticalWorkflows), sample: sample(workflows.items) },
      partialNotes(data.scope, workflows, templates),
    ));
  }

  findings.sort((left, right) => left.control - right.control);
  const counts = countByStatus(findings);
  return {
    category: "host-coverage",
    title: "Ansible AAP host coverage and automation hygiene",
    summary: {
      total_hosts: hosts.seen,
      hosts_total_reported: hosts.total,
      inventory_sources: sources.seen,
      job_host_summaries: summaries.seen,
      job_templates: templates.seen,
      schedules: schedules.seen,
      workflow_job_templates: workflows.seen,
      full_visibility: data.scope.data.fullVisibility,
      ...counts,
    },
    findings,
    errors,
  };
}

export async function assessAnsibleHostCoverage(client: AnsibleClientSurface, options: HostCoverageOptions = {}): Promise<AnsibleAssessmentResult> {
  const data = await collectAnsibleHostCoverageData(client, options);
  return assessAnsibleHostCoverageData(data, client.getNow(), options);
}

function hasExternalAuth(settings: JsonRecord): boolean {
  return Object.entries(settings).some(([key, value]) => {
    const normalizedKey = key.toLowerCase();
    if (!normalizedKey.includes("ldap") && !normalizedKey.includes("saml") && !normalizedKey.includes("oidc")) {
      return false;
    }
    if (typeof value === "string") return value.trim().length > 0;
    if (typeof value === "boolean") return value;
    if (Array.isArray(value)) return value.length > 0;
    const object = asObject(value);
    if (object) return Object.values(object).some((entry) => Boolean(entry));
    return Boolean(value);
  });
}

export function findPlaintextSecrets(text: unknown): string[] {
  const value = asString(text);
  if (!value) return [];
  const matches: string[] = [];
  for (const match of value.matchAll(SECRET_ASSIGNMENT_PATTERN)) {
    const key = match[1];
    const candidate = match[2];
    if (!key || !candidate) continue;
    if (candidate.startsWith("{{") || candidate.startsWith("$encrypted$") || candidate.startsWith("!vault") || /^(null|none|~|""|'')$/i.test(candidate)) continue;
    matches.push(key);
  }
  return [...new Set(matches)];
}

export interface PlatformSecurityData {
  scope: Snapshot<AnsibleScope>;
  organizations: Snapshot<AnsibleCollection>;
  orgAdmins: Record<string, Snapshot<AnsibleCollection>>;
  users: Snapshot<AnsibleCollection>;
  userRoles: Record<string, Snapshot<AnsibleCollection>>;
  teams: Snapshot<AnsibleCollection>;
  teamRoles: Record<string, Snapshot<AnsibleCollection>>;
  credentials: Snapshot<AnsibleCollection>;
  credentialOwners: Record<string, { users: Snapshot<AnsibleCollection>; teams: Snapshot<AnsibleCollection> }>;
  tokens: Snapshot<AnsibleCollection>;
  projects: Snapshot<AnsibleCollection>;
  jobTemplates: Snapshot<AnsibleCollection>;
  surveySpecs: Record<string, Snapshot<JsonRecord | undefined>>;
  templateErrorNotifications: Record<string, Snapshot<AnsibleCollection>>;
  inventories: Snapshot<AnsibleCollection>;
  groups: Snapshot<AnsibleCollection>;
  executionEnvironments: Snapshot<AnsibleCollection>;
  notificationTemplates: Snapshot<AnsibleCollection>;
  notifications: Snapshot<AnsibleCollection>;
  activity: Snapshot<AnsibleCollection>;
  authSettings: Snapshot<JsonRecord | undefined>;
  systemSettings: Snapshot<JsonRecord | undefined>;
  loggingSettings: Snapshot<JsonRecord | undefined>;
}

export async function collectAnsiblePlatformSecurityData(client: AnsibleClientSurface, options: PlatformSecurityOptions = {}): Promise<PlatformSecurityData> {
  const maxOrgAdmins = clampNumber(options.maxOrgAdmins, 3, 1, 50);
  const templateLimit = clampNumber(options.templateLimit, DEFAULT_TEMPLATE_LIMIT, 1, 5000);
  const userLimit = clampNumber(options.userLimit, DEFAULT_USER_LIMIT, 1, 5000);
  const scope = await probeScope(client);
  const organizations = await collect(client, "organizations", "/api/v2/organizations/");
  const orgAdmins: Record<string, Snapshot<AnsibleCollection>> = {};
  for (const org of organizations.data.items) {
    const id = asString(org.id);
    if (!id) continue;
    orgAdmins[id] = await collect(client, `organization ${nameOf(org)} admins`, `/api/v2/organizations/${id}/admins/`, {}, maxOrgAdmins + 20);
  }
  const users = await collect(client, "users", "/api/v2/users/", { order_by: "username" }, userLimit);
  const userRoles: Record<string, Snapshot<AnsibleCollection>> = {};
  for (const user of users.data.items.slice(0, DEFAULT_ROLE_PROBE_LIMIT)) {
    const id = asString(user.id);
    if (!id) continue;
    userRoles[id] = await collect(client, `user ${nameOf(user)} roles`, `/api/v2/users/${id}/roles/`, {}, 500);
  }
  const teams = await collect(client, "teams", "/api/v2/teams/", {}, 200);
  const teamRoles: Record<string, Snapshot<AnsibleCollection>> = {};
  for (const team of teams.data.items) {
    const id = asString(team.id);
    if (!id) continue;
    teamRoles[id] = await collect(client, `team ${nameOf(team)} roles`, `/api/v2/teams/${id}/roles/`, {}, 500);
  }
  const credentials = await collect(client, "credentials", "/api/v2/credentials/", {}, 500);
  const credentialOwners: PlatformSecurityData["credentialOwners"] = {};
  for (const credential of credentials.data.items) {
    const id = asString(credential.id);
    if (!id || Array.isArray(summaryFields(credential).owners)) continue;
    credentialOwners[id] = {
      users: await collect(client, `credential ${nameOf(credential)} owner users`, `/api/v2/credentials/${id}/owner_users/`, {}, 100),
      teams: await collect(client, `credential ${nameOf(credential)} owner teams`, `/api/v2/credentials/${id}/owner_teams/`, {}, 100),
    };
  }
  const tokens = await collect(client, "OAuth2 tokens", "/api/v2/tokens/", {}, 1000);
  const projects = await collect(client, "projects", "/api/v2/projects/", {}, clampNumber(options.projectLimit, 500, 1, 5000));
  const jobTemplates = await collect(client, "job templates", "/api/v2/job_templates/", { order_by: "name" }, templateLimit);
  const surveySpecs: Record<string, Snapshot<JsonRecord | undefined>> = {};
  const templateErrorNotifications: Record<string, Snapshot<AnsibleCollection>> = {};
  for (const template of jobTemplates.data.items) {
    const id = asString(template.id);
    if (!id) continue;
    if (asBoolean(template.survey_enabled) === true && Object.keys(surveySpecs).length < 50) {
      surveySpecs[id] = await fetchObject(client, `job template ${nameOf(template)} survey spec`, `/api/v2/job_templates/${id}/survey_spec/`);
    }
    const isCritical = CRITICAL_TEMPLATE_PATTERN.test([template.name, template.playbook, template.description].map((value) => extractText(value)).join(" "));
    if (isCritical && Object.keys(templateErrorNotifications).length < 50) {
      templateErrorNotifications[id] = await collect(client, `job template ${nameOf(template)} error notifications`, `/api/v2/job_templates/${id}/notification_templates_error/`, {}, 50);
    }
  }
  const inventories = await collect(client, "inventories", "/api/v2/inventories/", {}, 200);
  const groups = await collect(client, "groups", "/api/v2/groups/", {}, 500);
  const executionEnvironments = await collect(client, "execution environments", "/api/v2/execution_environments/", {}, 200);
  const notificationTemplates = await collect(client, "notification templates", "/api/v2/notification_templates/", {}, 200);
  const notifications = await collect(client, "notifications", "/api/v2/notifications/", { order_by: "-created" }, 100);
  const activity = await collect(client, "activity stream", "/api/v2/activity_stream/", { order_by: "-timestamp" }, 10);
  const authSettings = await fetchObject(client, "authentication settings", "/api/v2/settings/authentication/");
  const systemSettings = await fetchObject(client, "system settings", "/api/v2/settings/system/");
  const loggingSettings = await fetchObject(client, "logging settings", "/api/v2/settings/logging/");
  return {
    scope,
    organizations,
    orgAdmins,
    users,
    userRoles,
    teams,
    teamRoles,
    credentials,
    credentialOwners,
    tokens,
    projects,
    jobTemplates,
    surveySpecs,
    templateErrorNotifications,
    inventories,
    groups,
    executionEnvironments,
    notificationTemplates,
    notifications,
    activity,
    authSettings,
    systemSettings,
    loggingSettings,
  };
}

function credentialKind(credential: JsonRecord): string {
  const typeName = asObject(summaryFields(credential).credential_type)?.name;
  return extractText(credential.kind, extractText(typeName, "unknown")).toLowerCase();
}

function isVaultCredential(credential: JsonRecord): boolean {
  return credentialKind(credential) === "vault";
}

function vaultId(credential: JsonRecord): string | undefined {
  return asString(asObject(credential.inputs)?.vault_id);
}

function roleName(role: JsonRecord): string {
  return extractText(role.name).toLowerCase();
}

function roleResourceType(role: JsonRecord): string {
  return extractText(summaryFields(role).resource_type).toLowerCase();
}

function isAdminRole(role: JsonRecord): boolean {
  return roleName(role).includes("admin");
}

export function assessAnsiblePlatformSecurityData(data: PlatformSecurityData, now: Date, options: PlatformSecurityOptions = {}): AnsibleAssessmentResult {
  const maxOrgAdmins = clampNumber(options.maxOrgAdmins, 3, 1, 50);
  const staleCredentialDays = clampNumber(options.staleCredentialDays, 90, 1, 730);
  const staleTokenDays = clampNumber(options.staleTokenDays, 90, 1, 730);
  const maxSharedTemplates = clampNumber(options.maxSharedTemplates, 5, 1, 100);
  const organizations = inventory("organizations", data.organizations);
  const users = inventory("users", data.users);
  const teams = inventory("teams", data.teams);
  const credentials = inventory("credentials", data.credentials);
  const tokens = inventory("OAuth2 tokens", data.tokens);
  const projects = inventory("projects", data.projects);
  const templates = inventory("job templates", data.jobTemplates);
  const inventories = inventory("inventories", data.inventories);
  const groups = inventory("groups", data.groups);
  const executionEnvironments = inventory("execution environments", data.executionEnvironments);
  const notificationTemplates = inventory("notification templates", data.notificationTemplates);
  const notifications = inventory("notifications", data.notifications);
  const activity = inventory("activity stream", data.activity);
  const findings: AnsibleFinding[] = [];
  const errors: string[] = [
    data.scope.error,
    data.organizations.error,
    ...Object.values(data.orgAdmins).map((snapshot) => snapshot.error),
    data.users.error,
    ...Object.values(data.userRoles).map((snapshot) => snapshot.error),
    data.teams.error,
    ...Object.values(data.teamRoles).map((snapshot) => snapshot.error),
    data.credentials.error,
    ...Object.values(data.credentialOwners).flatMap((owner) => [owner.users.error, owner.teams.error]),
    data.tokens.error,
    data.projects.error,
    data.jobTemplates.error,
    ...Object.values(data.surveySpecs).map((snapshot) => snapshot.error),
    ...Object.values(data.templateErrorNotifications).map((snapshot) => snapshot.error),
    data.inventories.error,
    data.groups.error,
    data.executionEnvironments.error,
    data.notificationTemplates.error,
    data.notifications.error,
    data.activity.error,
    data.authSettings.error,
    data.systemSettings.error,
    data.loggingSettings.error,
  ].filter((entry): entry is string => Boolean(entry));

  const credentialPartial = partialNotes(data.scope, credentials);
  const activeCredentials = credentials.items.filter((credential) => asBoolean(credential.managed) !== true);
  if (!credentials.readable) {
    for (const controlNumber of [16, 19]) findings.push(manualForUnreadable(controlNumber, credentials, "the Credentials list with Last Modified and the Access tab of each credential"));
  } else if (credentials.empty) {
    for (const controlNumber of [16, 19]) {
      findings.push(finding(controlNumber, "manual", "No credentials were visible. Empty inventory is treated as manual for this control because credentials are org scoped; confirm the audit account can read every organization's credentials.", { credentials: 0 }));
    }
  } else {
    const undated = activeCredentials.filter((credential) => !extractTimestamp(credential.modified));
    const stale = activeCredentials.filter((credential) => {
      const age = daysBetween(now, extractTimestamp(credential.modified));
      return age !== undefined && age > staleCredentialDays;
    });
    const staleByKind: Record<string, number> = {};
    for (const credential of stale) {
      const kind = credentialKind(credential);
      staleByKind[kind] = (staleByKind[kind] ?? 0) + 1;
    }
    findings.push(finding(
      16,
      stale.length > 0 ? "fail" : undated.length > 0 ? "warn" : "pass",
      stale.length > 0
        ? `${stale.length}/${activeCredentials.length} non-managed credentials were last modified more than ${staleCredentialDays} days ago (by kind: ${Object.entries(staleByKind).map(([kind, count]) => `${kind} ${count}`).join(", ")}); ${undated.length} have no modified timestamp.`
        : undated.length > 0
          ? `No credential exceeded ${staleCredentialDays} days, but ${undated.length} have no modified timestamp and cannot be counted as rotated.`
          : `All ${activeCredentials.length} non-managed credentials were modified within ${staleCredentialDays} days.`,
      { count: stale.length, undated_count: undated.length, stale_by_kind: staleByKind, sample: sample(stale, (item) => ({ name: nameOf(item), kind: credentialKind(item), modified: item.modified ?? null })) },
      credentialPartial,
    ));

    const orphaned: JsonRecord[] = [];
    const unknownOwners: JsonRecord[] = [];
    for (const credential of activeCredentials) {
      const owners = summaryFields(credential).owners;
      if (Array.isArray(owners)) {
        if (owners.length === 0) orphaned.push(credential);
        continue;
      }
      const lookup = data.credentialOwners[String(credential.id ?? "")];
      if (!lookup || lookup.users.error || lookup.teams.error) {
        unknownOwners.push(credential);
      } else if (lookup.users.data.items.length + lookup.teams.data.items.length === 0) {
        orphaned.push(credential);
      }
    }
    findings.push(finding(
      19,
      orphaned.length > 0 ? "warn" : unknownOwners.length > 0 ? "manual" : "pass",
      orphaned.length > 0
        ? `${orphaned.length}/${activeCredentials.length} credentials have no user, team, or organization owner.`
        : unknownOwners.length > 0
          ? `${unknownOwners.length} credentials expose no owners summary and their owner_users/owner_teams endpoints could not be read; review their Access tab manually.`
          : `Every one of the ${activeCredentials.length} non-managed credentials has at least one owner.`,
      { orphaned: sample(orphaned), unknown_owners: sample(unknownOwners) },
      credentialPartial,
    ));
  }

  const templatePartial = partialNotes(data.scope, templates);
  if (!templates.readable) {
    for (const controlNumber of [17, 18, 30]) findings.push(manualForUnreadable(controlNumber, templates, "each job template's Credentials, Variables, Survey, and Execution Environment fields"));
  } else if (templates.empty) {
    for (const controlNumber of [17, 18, 30]) {
      findings.push(finding(controlNumber, "manual", "No job templates were visible. Empty inventory is treated as manual for this control: confirm the audit account can read templates.", { job_templates: 0 }));
    }
  } else {
    const usage = new Map<string, { name: string; kind: string; templates: string[] }>();
    let templatesWithCredentialSummary = 0;
    const launchTimeCredentialTemplates = templates.items.filter((template) => asBoolean(template.ask_credential_on_launch) === true);
    for (const template of templates.items) {
      const creds = summaryFields(template).credentials;
      if (!Array.isArray(creds)) continue;
      templatesWithCredentialSummary += 1;
      for (const raw of creds) {
        const cred = asObject(raw);
        if (!cred) continue;
        const key = String(cred.id ?? cred.name ?? "unknown");
        const current = usage.get(key) ?? { name: extractText(cred.name, key), kind: credentialKind(cred), templates: [] };
        current.templates.push(nameOf(template));
        usage.set(key, current);
      }
    }
    const shared = [...usage.entries()].filter(([, entry]) => entry.templates.length > maxSharedTemplates).map(([id, entry]) => ({ id, name: entry.name, kind: entry.kind, template_count: entry.templates.length, templates: entry.templates.slice(0, 10) }));
    const launchTimeNote = launchTimeCredentialTemplates.length > 0
      ? ` ${launchTimeCredentialTemplates.length} templates set ask_credential_on_launch, so credentials chosen at launch are not counted here.`
      : "";
    findings.push(
      templatesWithCredentialSummary === 0
        ? finding(17, "manual", `None of the ${templates.seen} job templates exposed summary_fields.credentials, so credential usage cannot be counted from the API; review each template's Credentials field manually.${launchTimeNote}`, { job_templates: templates.seen, ask_credential_on_launch_templates: launchTimeCredentialTemplates.length })
        : finding(
          17,
          shared.length > 0 ? "fail" : "pass",
          shared.length > 0
            ? `${shared.length} credentials are attached to more than ${maxSharedTemplates} job templates.${launchTimeNote}`
            : `No credential is attached to more than ${maxSharedTemplates} of the ${templates.seen} job templates seen (${usage.size} distinct credentials in use).${launchTimeNote}`,
          { credentials_in_use: usage.size, shared, ask_credential_on_launch_templates: sample(launchTimeCredentialTemplates) },
          templatePartial,
        ),
    );

    const hits: JsonRecord[] = [];
    for (const template of templates.items) {
      const keys = findPlaintextSecrets(template.extra_vars);
      if (keys.length > 0) hits.push({ type: "job_template", name: nameOf(template), keys });
    }
    let surveysUnreadable = 0;
    for (const [templateId, snapshot] of Object.entries(data.surveySpecs)) {
      if (snapshot.error || !snapshot.data) {
        surveysUnreadable += 1;
        continue;
      }
      const spec = Array.isArray(snapshot.data.spec) ? snapshot.data.spec : [];
      const keys = spec
        .map((raw) => asObject(raw))
        .filter((question): question is JsonRecord => Boolean(question))
        .filter((question) => extractText(question.type) !== "password" && SECRET_KEY_PATTERN.test(extractText(question.variable)) && asString(question.default) !== undefined)
        .map((question) => extractText(question.variable));
      if (keys.length > 0) hits.push({ type: "survey_spec", template_id: templateId, keys });
    }
    for (const item of inventories.items) {
      const keys = findPlaintextSecrets(item.variables);
      if (keys.length > 0) hits.push({ type: "inventory", name: nameOf(item), keys });
    }
    for (const item of groups.items) {
      const keys = findPlaintextSecrets(item.variables);
      if (keys.length > 0) hits.push({ type: "group", name: nameOf(item), keys });
    }
    const variableSources = [inventories, groups].filter((view) => !view.readable);
    const launchTimeVariableTemplates = templates.items.filter((template) => asBoolean(template.ask_variables_on_launch) === true);
    const vaultCredentials = credentials.items.filter((credential) => isVaultCredential(credential));
    const vaultNote = credentials.readable
      ? ` ${vaultCredentials.length} Vault credentials (vault_id: ${vaultCredentials.map((credential) => vaultId(credential) ?? "default").join(", ") || "none"}) are defined for encrypted variables.`
      : " Vault credential usage could not be read.";
    const launchNote = launchTimeVariableTemplates.length > 0
      ? ` ${launchTimeVariableTemplates.length} templates set ask_variables_on_launch; launch-time extra_vars are not scanned.`
      : "";
    findings.push(finding(
      18,
      hits.length > 0 ? "fail" : surveysUnreadable > 0 || variableSources.length > 0 ? "manual" : "pass",
      hits.length > 0
        ? `${hits.length} templates, surveys, inventories, or groups carry plaintext values under secret-like variable names.${vaultNote}`
        : surveysUnreadable > 0 || variableSources.length > 0
          ? `No plaintext secret pattern matched, but ${surveysUnreadable} survey specs and ${variableSources.length} variable sources (${variableSources.map((view) => view.label).join(", ") || "none"}) could not be read; review them manually.${vaultNote}${launchNote}`
          : `No plaintext secret pattern matched across ${templates.seen} templates, ${Object.keys(data.surveySpecs).length} surveys, ${inventories.seen} inventories, and ${groups.seen} groups. Host variables are not scanned.${vaultNote}${launchNote}`,
      {
        hits: hits.slice(0, 20),
        surveys_scanned: Object.keys(data.surveySpecs).length,
        surveys_unreadable: surveysUnreadable,
        inventories: inventories.seen,
        groups: groups.seen,
        ask_variables_on_launch_templates: launchTimeVariableTemplates.length,
        vault_credentials: vaultCredentials.map((credential) => ({ name: nameOf(credential), vault_id: vaultId(credential) ?? null })),
      },
      partialNotes(data.scope, templates, inventories, groups),
    ));

    if (!executionEnvironments.readable) {
      findings.push(finding(30, "manual", `Execution environments could not be read (${executionEnvironments.error}); the controller may predate execution environments or the account cannot read them. Verify each template's Execution Environment field manually.`, { error: executionEnvironments.error }));
    } else if (executionEnvironments.empty) {
      findings.push(finding(30, "manual", "No execution environments were visible. Empty inventory is treated as manual for this control: confirm the controller version supports execution environments and the account can read them.", { execution_environments: 0 }));
    } else {
      const withoutField = templates.items.filter((template) => !("execution_environment" in template));
      const unpinned = templates.items.filter((template) => "execution_environment" in template && (template.execution_environment === null || template.execution_environment === undefined));
      const launchTime = unpinned.filter((template) => asBoolean(template.ask_execution_environment_on_launch) === true);
      const defaulted = unpinned.filter((template) => asBoolean(template.ask_execution_environment_on_launch) !== true);
      findings.push(
        withoutField.length > 0
          ? finding(30, "manual", `${withoutField.length}/${templates.seen} job templates do not expose an execution_environment field, so the control cannot be verified from the API on this version.`, { without_field: withoutField.length })
          : finding(
            30,
            unpinned.length > 0 ? "warn" : "pass",
            unpinned.length > 0
              ? `${defaulted.length}/${templates.seen} job templates rely on the default execution environment and ${launchTime.length} defer the choice to launch time (ask_execution_environment_on_launch); ${executionEnvironments.seen} execution environments are defined.`
              : `All ${templates.seen} job templates reference an explicit execution environment (${executionEnvironments.seen} defined).`,
            { defaulted: sample(defaulted), launch_time: sample(launchTime), execution_environments: sample(executionEnvironments.items, (item) => ({ name: item.name, image: item.image, pull: item.pull })) },
            partialNotes(data.scope, templates, executionEnvironments),
          ),
      );
    }
  }

  if (!tokens.readable) {
    findings.push(manualForUnreadable(20, tokens, "each user's Tokens tab (or the platform gateway token list on AAP 2.5) with Expires and Created values"));
  } else {
    const undated = tokens.items.filter((token) => !extractTimestamp(token.created));
    const risky = tokens.items.filter((token) => {
      const expires = extractTimestamp(token.expires);
      const createdAge = daysBetween(now, extractTimestamp(token.created));
      return !expires || (createdAge !== undefined && createdAge > staleTokenDays);
    });
    findings.push(finding(
      20,
      tokens.empty
        ? "pass"
        : risky.length > 0
          ? "warn"
          : undated.length > 0
            ? "warn"
            : "pass",
      tokens.empty
        ? "No OAuth2 tokens exist; an empty token inventory is compliant by intent for this control."
        : risky.length > 0
          ? `${risky.length}/${tokens.seen} tokens have no expiration or are older than ${staleTokenDays} days.`
          : `All ${tokens.seen} tokens expire and are newer than ${staleTokenDays} days${undated.length > 0 ? `, but ${undated.length} have no created timestamp` : ""}.`,
      { count: risky.length, undated_count: undated.length },
      partialNotes(data.scope, tokens),
    ));
  }

  const orgPartial = partialNotes(data.scope, organizations);
  if (!organizations.readable) {
    for (const controlNumber of [21, 24]) findings.push(manualForUnreadable(controlNumber, organizations, "each organization's Access tab listing Admin and Auditor role holders"));
  } else if (organizations.empty) {
    for (const controlNumber of [21, 24]) {
      findings.push(finding(controlNumber, "manual", "No organizations were visible. Empty inventory is treated as manual for this control: confirm the audit account can read organizations.", { organizations: 0 }));
    }
  } else {
    const counts: JsonRecord[] = [];
    const unreadable: string[] = [];
    for (const org of organizations.items) {
      const snapshot = data.orgAdmins[String(org.id ?? "")];
      if (!snapshot || snapshot.error) {
        unreadable.push(nameOf(org));
        continue;
      }
      counts.push({ id: org.id, name: nameOf(org), admin_count: snapshot.data.items.length, complete: snapshot.data.complete });
    }
    const excessive = counts.filter((org) => asNumber(org.admin_count)! > maxOrgAdmins);
    findings.push(finding(
      21,
      excessive.length > 0 ? "fail" : unreadable.length > 0 ? "manual" : "pass",
      excessive.length > 0
        ? `${excessive.length}/${organizations.seen} organizations have more than ${maxOrgAdmins} admins.`
        : unreadable.length > 0
          ? `No organization exceeded ${maxOrgAdmins} admins, but the admins list of ${unreadable.length} organizations (${unreadable.join(", ")}) could not be read; review them manually.`
          : `None of the ${organizations.seen} organizations exceeds ${maxOrgAdmins} admins.`,
      { organizations: counts, unreadable },
      orgPartial,
    ));
  }

  const usersPartial = partialNotes(data.scope, users, teams);
  const probedUserIds = Object.keys(data.userRoles);
  const roleProbeNote = users.seen > probedUserIds.length ? `user roles: ${probedUserIds.length} of ${users.seen} users probed` : undefined;
  if (!teams.readable) {
    findings.push(manualForUnreadable(22, teams, "each team's Roles tab"));
  } else if (teams.empty) {
    findings.push(finding(22, "manual", "No teams were visible. Empty inventory is treated as manual for this control: confirm whether access is granted directly to users instead of teams, and review the Access tab of each organization.", { teams: 0 }));
  } else {
    const orgAdminTeams: JsonRecord[] = [];
    const inventoryAdminTeams: JsonRecord[] = [];
    const unreadable: string[] = [];
    const totalInventories = inventories.readable && inventories.total !== undefined ? inventories.total : undefined;
    for (const team of teams.items) {
      const snapshot = data.teamRoles[String(team.id ?? "")];
      if (!snapshot || snapshot.error) {
        unreadable.push(nameOf(team));
        continue;
      }
      const roles = snapshot.data.items;
      const orgAdmin = roles.filter((role) => roleName(role) === "admin" && roleResourceType(role) === "organization");
      if (orgAdmin.length > 0) orgAdminTeams.push({ team: nameOf(team), organizations: orgAdmin.map((role) => summaryFields(role).resource_name) });
      const inventoryAdmin = roles.filter((role) => roleName(role) === "admin" && roleResourceType(role) === "inventory");
      if (totalInventories !== undefined && totalInventories > 0 && inventoryAdmin.length >= totalInventories) {
        inventoryAdminTeams.push({ team: nameOf(team), inventories: inventoryAdmin.length });
      }
    }
    findings.push(finding(
      22,
      orgAdminTeams.length + inventoryAdminTeams.length > 0 ? "fail" : unreadable.length > 0 ? "manual" : "pass",
      orgAdminTeams.length + inventoryAdminTeams.length > 0
        ? `${orgAdminTeams.length} teams hold the Admin role on an organization and ${inventoryAdminTeams.length} hold Admin on every visible inventory.`
        : unreadable.length > 0
          ? `No team holds organization-wide or inventory-wide Admin, but the roles of ${unreadable.length} teams could not be read; review them manually.`
          : `None of the ${teams.seen} teams holds the Admin role on an organization or on every inventory.`,
      { org_admin_teams: orgAdminTeams, inventory_admin_teams: inventoryAdminTeams, unreadable, total_inventories: totalInventories },
      usersPartial,
    ));
  }

  if (!users.readable) {
    findings.push(manualForUnreadable(23, users, "the Users list with System Administrator and System Auditor flags plus each user's Roles tab"));
    if (!findings.some((item) => item.control === 24)) {
      findings.push(manualForUnreadable(24, users, "the Users list with the System Auditor flag plus each organization's Access tab listing Auditor role holders"));
    }
  } else if (users.empty) {
    findings.push(finding(23, "manual", "No users were visible. Empty inventory is treated as manual for this control: confirm the audit account can read users.", { users: 0 }));
    if (!findings.some((item) => item.control === 24)) {
      findings.push(finding(24, "manual", "No users were visible, so auditor role holders cannot be enumerated. Empty inventory is treated as manual for this control.", { users: 0 }));
    }
  } else {
    const violations: JsonRecord[] = [];
    const unreadable: string[] = [];
    for (const user of users.items.slice(0, DEFAULT_ROLE_PROBE_LIMIT)) {
      const snapshot = data.userRoles[String(user.id ?? "")];
      if (!snapshot || snapshot.error) {
        unreadable.push(nameOf(user));
        continue;
      }
      const roles = snapshot.data.items;
      const executes = roles.filter((role) => roleName(role) === "execute");
      const admins = roles.filter((role) => isAdminRole(role) || roleName(role) === "system administrator");
      const superuser = asBoolean(user.is_superuser) === true;
      if (executes.length > 0 && (admins.length > 0 || superuser)) {
        violations.push({ user: nameOf(user), is_superuser: superuser, execute_roles: executes.length, admin_roles: admins.map((role) => `${role.name} on ${roleResourceType(role)} ${extractText(summaryFields(role).resource_name)}`).slice(0, 10) });
      }
    }
    const probePartial = [...usersPartial, ...(roleProbeNote ? [roleProbeNote] : [])];
    findings.push(finding(
      23,
      violations.length > 0 ? "fail" : unreadable.length > 0 ? "manual" : "pass",
      violations.length > 0
        ? `${violations.length} users combine an Execute role with admin rights (Admin-family roles or is_superuser).`
        : unreadable.length > 0
          ? `No probed user combines Execute with admin rights, but the roles of ${unreadable.length} users could not be read; review them manually.`
          : `None of the ${probedUserIds.length} probed users combines an Execute role with admin rights.`,
      { violations: violations.slice(0, 10), unreadable, probed_users: probedUserIds.length },
      probePartial,
    ));

    if (organizations.readable && !organizations.empty) {
      const systemAuditors = users.items.filter((user) => asBoolean(user.is_system_auditor) === true);
      const auditedOrgs = new Set<string>();
      for (const snapshot of Object.values(data.userRoles)) {
        for (const role of snapshot.data.items) {
          if (roleName(role) === "auditor" && roleResourceType(role) === "organization") auditedOrgs.add(extractText(summaryFields(role).resource_name, String(summaryFields(role).resource_id)));
        }
      }
      for (const snapshot of Object.values(data.teamRoles)) {
        for (const role of snapshot.data.items) {
          if (roleName(role) === "auditor" && roleResourceType(role) === "organization") auditedOrgs.add(extractText(summaryFields(role).resource_name, String(summaryFields(role).resource_id)));
        }
      }
      const uncovered = organizations.items.filter((org) => !auditedOrgs.has(nameOf(org)));
      const covered = systemAuditors.length > 0 || uncovered.length === 0;
      findings.push(finding(
        24,
        covered ? "pass" : "warn",
        covered
          ? `${systemAuditors.length} system auditors exist and ${auditedOrgs.size} organizations have an Auditor role holder among the probed users and teams.`
          : `No system auditor exists and ${uncovered.length}/${organizations.seen} organizations have no Auditor role holder among the probed users and teams.`,
        { system_auditors: sample(systemAuditors), audited_organizations: [...auditedOrgs], uncovered: sample(uncovered) },
        probePartial,
      ));
    }
  }

  const authSettings = data.authSettings.data;
  if (data.authSettings.error || !authSettings) {
    findings.push(manualForUnreadable(25, { label: "authentication settings", error: data.authSettings.error ?? "no settings object returned" }, "the LDAP, SAML, or OIDC authenticator configuration (Settings > Authentication, or the platform gateway Authentication page on AAP 2.5)"));
  } else {
    const externalKeys = Object.keys(authSettings).filter((key) => /ldap|saml|oidc/i.test(key));
    findings.push(
      externalKeys.length === 0
        ? finding(25, "manual", "The authentication settings category exposes no LDAP, SAML, or OIDC keys; on AAP 2.5 authenticators are managed by the platform gateway. Verify the configured authenticators in the gateway UI.", { keys: Object.keys(authSettings).length })
        : finding(
          25,
          hasExternalAuth(authSettings) ? "pass" : "fail",
          hasExternalAuth(authSettings)
            ? `LDAP, SAML, or OIDC settings are populated (${externalKeys.length} related keys).`
            : `${externalKeys.length} LDAP, SAML, or OIDC settings exist but none is populated, so only local accounts can authenticate.`,
          { detected_keys: externalKeys.slice(0, 20) },
          scopeNotes(data.scope),
        ),
    );
  }

  const systemSettings = data.systemSettings.data;
  const activityEnabled = systemSettings ? asBoolean(systemSettings.ACTIVITY_STREAM_ENABLED) : undefined;
  const loggingSettings = data.loggingSettings.data;
  const logAggregatorEnabled = loggingSettings ? asBoolean(loggingSettings.LOG_AGGREGATOR_ENABLED) : undefined;
  const auditEvidence = { activity_stream_enabled: activityEnabled, log_aggregator_enabled: logAggregatorEnabled, log_aggregator_type: loggingSettings ? asString(loggingSettings.LOG_AGGREGATOR_TYPE) : undefined };
  if (!activity.readable) {
    findings.push(manualForUnreadable(26, activity, "the Activity Stream page showing entries from the last 24 hours and Settings > System (Enable Activity Stream)"));
  } else if (activityEnabled === false) {
    findings.push(finding(26, "fail", "ACTIVITY_STREAM_ENABLED is false, so platform changes are not being recorded.", auditEvidence));
  } else if (activity.empty) {
    findings.push(finding(26, "fail", "No activity stream records were visible. Empty inventory is treated as fail for this control because a controller in use always produces activity.", { ...auditEvidence, visible_activity_records: 0 }));
  } else {
    const latest = extractTimestamp(activity.items[0]?.timestamp);
    const latestAge = daysBetween(now, latest);
    findings.push(finding(
      26,
      !latest ? "warn" : latestAge !== undefined && latestAge > 1 ? "fail" : "pass",
      !latest
        ? "The newest activity stream record has no timestamp, so freshness cannot be confirmed."
        : `Latest activity stream record is ${latestAge?.toFixed(1)} days old${activityEnabled === undefined ? " (ACTIVITY_STREAM_ENABLED not readable)" : ""}${logAggregatorEnabled === false ? "; external log aggregation is disabled" : ""}.`,
      { ...auditEvidence, visible_activity_records: activity.seen, latest_activity_age_days: latestAge },
      scopeNotes(data.scope),
    ));
  }

  if (!notificationTemplates.readable) {
    findings.push(manualForUnreadable(27, notificationTemplates, "the Notifications list and the Notifications tab of each critical job template"));
  } else if (notificationTemplates.empty) {
    findings.push(finding(27, "fail", "No notification templates exist, so job failures cannot alert anyone. An empty notification inventory is treated as fail for this control.", { notification_template_count: 0 }));
  } else {
    const critical = Object.entries(data.templateErrorNotifications);
    const covered = critical.filter(([, snapshot]) => !snapshot.error && snapshot.data.items.length > 0).length;
    const unreadable = critical.filter(([, snapshot]) => snapshot.error).length;
    const failedNotifications = notifications.items.filter((item) => String(item.status ?? "").toLowerCase() === "failed").length;
    findings.push(finding(
      27,
      critical.length === 0
        ? "manual"
        : covered === 0
          ? "warn"
          : failedNotifications > 0
            ? "warn"
            : unreadable > 0
              ? "manual"
              : "pass",
      critical.length === 0
        ? `${notificationTemplates.seen} notification templates exist but no job template matched the critical keyword list; confirm failure notifications on the templates that matter manually.`
        : covered === 0
          ? `${notificationTemplates.seen} notification templates exist but none of the ${critical.length} critical job templates has an error notification attached.`
          : `${covered}/${critical.length} critical job templates have an error notification attached; ${failedNotifications} of the last ${notifications.seen} notification deliveries failed${unreadable > 0 ? `; ${unreadable} template notification lists could not be read` : ""}.`,
      { notification_template_count: notificationTemplates.seen, critical_templates: critical.length, covered, unreadable, failed_notifications: failedNotifications },
      partialNotes(data.scope, notificationTemplates, templates),
    ));
  }

  if (!projects.readable) {
    findings.push(manualForUnreadable(29, projects, "the Projects list with SCM type and Last Job Status"));
  } else if (projects.empty) {
    findings.push(finding(29, "manual", "No projects were visible. Empty inventory is treated as manual for this control: confirm the audit account can read projects.", { projects: 0 }));
  } else {
    const undated = projects.items.filter((project) => extractText(project.scm_type) !== "" && extractText(project.scm_type) !== "manual" && !extractTimestamp(project.last_updated));
    const unhealthy = projects.items.filter((project) => {
      const scmType = extractText(project.scm_type).toLowerCase();
      return scmType === "" || scmType === "manual" || asBoolean(project.last_update_failed) === true;
    });
    findings.push(finding(
      29,
      unhealthy.length > 0 ? "warn" : undated.length > 0 ? "warn" : "pass",
      unhealthy.length > 0
        ? `${unhealthy.length}/${projects.seen} projects use manual SCM or have a failed latest update; ${undated.length} SCM projects have never synced.`
        : undated.length > 0
          ? `All ${projects.seen} projects use SCM without failed updates, but ${undated.length} have no last_updated timestamp.`
          : `All ${projects.seen} projects use SCM and their latest update succeeded.`,
      { count: unhealthy.length, undated_count: undated.length, sample: sample(unhealthy) },
      partialNotes(data.scope, projects),
    ));
  }

  findings.sort((left, right) => left.control - right.control);
  const counts = countByStatus(findings);
  return {
    category: "platform-security",
    title: "Ansible AAP platform security",
    summary: {
      organizations: organizations.seen,
      users: users.seen,
      teams: teams.seen,
      credentials: credentials.seen,
      tokens: tokens.seen,
      projects: projects.seen,
      job_templates: templates.seen,
      execution_environments: executionEnvironments.seen,
      notification_templates: notificationTemplates.seen,
      external_auth: authSettings ? hasExternalAuth(authSettings) : undefined,
      full_visibility: data.scope.data.fullVisibility,
      ...counts,
    },
    findings,
    errors,
  };
}

export async function assessAnsiblePlatformSecurity(client: AnsibleClientSurface, options: PlatformSecurityOptions = {}): Promise<AnsibleAssessmentResult> {
  const data = await collectAnsiblePlatformSecurityData(client, options);
  return assessAnsiblePlatformSecurityData(data, client.getNow(), options);
}

function formatAccessCheckText(result: AnsibleAccessCheckResult): string {
  const rows = result.surfaces.map((surface) => [
    surface.name,
    surface.status,
    surface.count === undefined ? "-" : String(surface.count),
    surface.error ? surface.error.replace(/\s+/g, " ").slice(0, 80) : "",
  ]);
  return [
    `Ansible AAP access check: ${result.status}`,
    "",
    ...result.notes,
    "",
    formatTable(["Surface", "Status", "Count", "Note"], rows),
    "",
    `Next: ${result.recommendedNextStep}`,
  ].join("\n");
}

function formatAssessmentText(result: AnsibleAssessmentResult): string {
  const rows = result.findings.map((item) => [
    item.id,
    String(item.control),
    item.severity.toUpperCase(),
    item.status.toUpperCase(),
    item.title,
    item.summary,
  ]);
  const summary = Object.entries(result.summary)
    .map(([key, value]) => `- ${key}: ${typeof value === "number" ? Number(value.toFixed(2)) : String(value)}`)
    .join("\n");
  return [
    result.title,
    "",
    "Summary:",
    summary,
    "",
    formatTable(["Finding", "Control", "Severity", "Status", "Title", "Summary"], rows),
    ...(result.errors.length > 0 ? ["", "Partial collection warnings:", ...result.errors.map((error) => `- ${error}`)] : []),
  ].join("\n");
}

function buildExecutiveSummary(config: AnsibleAapConfiguration, assessments: AnsibleAssessmentResult[], errors: string[], generatedAt: Date): string {
  const findings = assessments.flatMap((assessment) => assessment.findings);
  const counts = countByStatus(findings);
  const prioritized = findings
    .filter((item) => item.status === "fail" || item.status === "warn")
    .sort((left, right) => statusRank(left.status) - statusRank(right.status) || severityRank(left.severity) - severityRank(right.severity));
  const manual = findings.filter((item) => item.status === "manual");

  const lines = [
    "# Ansible AAP Security Inspection: Executive Summary",
    "",
    `- Target: ${config.baseUrl}`,
    `- Authentication mode: ${config.token ? "token" : "session"}`,
    `- TLS verification: ${config.verifySsl ? "enabled" : "disabled for this run (AAP_VERIFY_SSL=false)"}`,
    `- Generated: ${generatedAt.toISOString()}`,
    `- Controls assessed: ${findings.length} of ${ANSIBLE_CONTROLS.length}`,
    `- Findings: Pass ${counts.pass}, Warn ${counts.warn}, Fail ${counts.fail}, Manual ${counts.manual}`,
    "",
    "## Highest Priority Findings",
    "",
  ];
  if (prioritized.length === 0) {
    lines.push("- No failing or warning findings were generated.");
  } else {
    for (const item of prioritized.slice(0, 15)) {
      lines.push(`- ${item.id} (${item.severity.toUpperCase()} / ${item.status.toUpperCase()}) ${item.title}: ${item.summary}`);
    }
  }
  lines.push("", "## Manual Evidence Required", "");
  if (manual.length === 0) {
    lines.push("- None.");
  } else {
    for (const item of manual) lines.push(`- ${item.id} ${item.title}: ${item.summary}`);
  }
  if (errors.length > 0) {
    lines.push("", "## Partial Collection Warnings", "");
    for (const error of errors) lines.push(`- ${error}`);
  }
  return `${lines.join("\n")}\n`;
}

function buildUnifiedMatrix(findings: AnsibleFinding[]): string {
  const rows = findings.map((item) => {
    const definition = controlDefinition(item.control);
    return [
      item.id,
      String(item.control),
      item.status.toUpperCase(),
      item.severity.toUpperCase(),
      item.title,
      ...FRAMEWORK_KEYS.map((key) => definition.mappings[key]),
    ];
  });
  return [
    "# Ansible AAP Unified Compliance Matrix",
    "",
    formatTable(["Finding", "Control", "Status", "Severity", "Title", ...FRAMEWORK_KEYS.map((key) => FRAMEWORK_LABELS[key])], rows),
    "",
  ].join("\n");
}

function buildFrameworkReport(title: string, findings: AnsibleFinding[], framework: FrameworkKey): string {
  const rows = findings.map((item) => [
    controlDefinition(item.control).mappings[framework],
    item.id,
    item.status.toUpperCase(),
    item.severity.toUpperCase(),
    item.title,
    item.summary,
  ]);
  const counts = countByStatus(findings);
  return [
    `# ${title}`,
    "",
    `Findings: Pass ${counts.pass}, Warn ${counts.warn}, Fail ${counts.fail}, Manual ${counts.manual}`,
    "",
    formatTable([FRAMEWORK_LABELS[framework], "Finding", "Status", "Severity", "Title", "Summary"], rows),
    "",
    "Manual findings require evidence collected from the controller UI before asserting compliance.",
    "",
  ].join("\n");
}

function buildQuickReference(): string {
  return [
    "# Ansible AAP Audit Bundle Quick Reference",
    "",
    "- `core_data/` contains raw controller REST API responses captured during this assessment (credential secrets are masked by the API and passwords are never written).",
    "- `analysis/` contains normalized findings (`findings.json`), run metadata, and one JSON summary per assessment category.",
    "- `compliance/` contains the executive summary, the unified matrix, and one report per framework.",
    "- `_errors.log` appears only when some reads failed but the bundle still completed.",
    "- Every finding carries its spec control number (1 to 30 in specs/ansible-sec-inspector.spec.md).",
    "- Status `manual` means the API cannot verify the control on this deployment or with this account; the summary states the evidence to collect from the controller UI.",
    "",
    "Recommended reading order:",
    "1. `compliance/executive_summary.md`",
    "2. `compliance/unified_compliance_matrix.md`",
    "3. the framework report matching your engagement",
    "4. `analysis/*.json` for the evidence behind each finding",
    "",
  ].join("\n");
}

function buildBundleReadme(): string {
  return [
    "# Ansible AAP Evidence Bundle",
    "",
    "This bundle was generated by grclanker's native Ansible Automation Platform tools.",
    "",
    "See `QUICK_REFERENCE.md` for the layout. Secrets are not written to this bundle. AAP passwords must come from `AAP_PASSWORD` and are never accepted as tool arguments.",
  ].join("\n");
}

function snapshotRecord<T>(snapshots: Record<string, Snapshot<T>>): JsonRecord {
  return Object.fromEntries(Object.entries(snapshots).map(([key, snapshot]) => [key, { data: snapshot.data, error: snapshot.error }]));
}

export async function exportAnsibleAuditBundle(
  client: AnsibleClientSurface & Pick<AnsibleAapClient, "count" | "get">,
  config: AnsibleAapConfiguration,
  outputRoot: string,
  options: ExportAuditBundleArgs = {},
): Promise<AnsibleAuditBundleResult> {
  const generatedAt = client.getNow();
  const access = await checkAnsibleAccess(client as AnsibleAapClient);
  const jobHealthOptions: JobHealthOptions = {
    days: options.days,
    jobLimit: options.job_limit,
    minSuccessRate: options.min_success_rate,
    maxManualRate: options.max_manual_rate,
  };
  const hostCoverageOptions: HostCoverageOptions = {
    days: options.days,
    staleHostDays: options.stale_host_days,
    criticalStaleHostDays: options.critical_stale_host_days,
    staleTemplateDays: options.stale_template_days,
    hostLimit: options.host_limit,
    inventorySourceLimit: options.inventory_source_limit,
    templateLimit: options.template_limit,
  };
  const platformOptions: PlatformSecurityOptions = {
    maxOrgAdmins: options.max_org_admins,
    staleCredentialDays: options.stale_credential_days,
    staleTokenDays: options.stale_token_days,
    maxSharedTemplates: options.max_shared_templates,
    projectLimit: options.project_limit,
    templateLimit: options.template_limit,
    userLimit: options.user_limit,
  };
  const jobHealthData = await collectAnsibleJobHealthData(client, jobHealthOptions);
  const hostCoverageData = await collectAnsibleHostCoverageData(client, hostCoverageOptions);
  const platformData = await collectAnsiblePlatformSecurityData(client, platformOptions);
  const assessments = [
    assessAnsibleJobHealthData(jobHealthData, generatedAt, jobHealthOptions),
    assessAnsibleHostCoverageData(hostCoverageData, generatedAt, hostCoverageOptions),
    assessAnsiblePlatformSecurityData(platformData, generatedAt, platformOptions),
  ];
  const findings = assessments.flatMap((assessment) => assessment.findings);
  const errors = [...new Set(assessments.flatMap((assessment) => assessment.errors))];

  const targetName = safeDirName(`${new URL(config.baseUrl).host}-ansible-aap-audit`);
  const { outputDir, zipPath } = await nextAvailableAuditDir(outputRoot, targetName);

  const coreDataFiles: Array<[string, unknown]> = [
    ["core_data/access.json", access],
    ["core_data/scope.json", jobHealthData.scope],
    ["core_data/jobs.json", jobHealthData.jobs],
    ["core_data/job_settings.json", jobHealthData.jobSettings],
    ["core_data/instance_groups.json", jobHealthData.instanceGroups],
    ["core_data/hosts.json", hostCoverageData.hosts],
    ["core_data/inventory_sources.json", hostCoverageData.inventorySources],
    ["core_data/job_host_summaries.json", hostCoverageData.hostSummaries],
    ["core_data/job_templates.json", hostCoverageData.jobTemplates],
    ["core_data/schedules.json", hostCoverageData.schedules],
    ["core_data/workflow_job_templates.json", hostCoverageData.workflowTemplates],
    ["core_data/organizations.json", platformData.organizations],
    ["core_data/organization_admins.json", snapshotRecord(platformData.orgAdmins)],
    ["core_data/users.json", platformData.users],
    ["core_data/user_roles.json", snapshotRecord(platformData.userRoles)],
    ["core_data/teams.json", platformData.teams],
    ["core_data/team_roles.json", snapshotRecord(platformData.teamRoles)],
    ["core_data/credentials.json", platformData.credentials],
    ["core_data/tokens.json", platformData.tokens],
    ["core_data/projects.json", platformData.projects],
    ["core_data/survey_specs.json", snapshotRecord(platformData.surveySpecs)],
    ["core_data/template_error_notifications.json", snapshotRecord(platformData.templateErrorNotifications)],
    ["core_data/inventories.json", platformData.inventories],
    ["core_data/groups.json", platformData.groups],
    ["core_data/execution_environments.json", platformData.executionEnvironments],
    ["core_data/notification_templates.json", platformData.notificationTemplates],
    ["core_data/notifications.json", platformData.notifications],
    ["core_data/activity_stream.json", platformData.activity],
    ["core_data/settings_authentication.json", platformData.authSettings],
    ["core_data/settings_system.json", platformData.systemSettings],
    ["core_data/settings_logging.json", platformData.loggingSettings],
  ];
  for (const [pathName, value] of coreDataFiles) {
    await writeSecureTextFile(outputDir, pathName, serializeJson(value));
  }

  await writeSecureTextFile(outputDir, "README.md", buildBundleReadme());
  for (const assessment of assessments) {
    await writeSecureTextFile(outputDir, `analysis/${assessment.category}.json`, serializeJson(assessment));
    await writeSecureTextFile(outputDir, `analysis/${assessment.category}.md`, formatAssessmentText(assessment));
  }
  await writeSecureTextFile(outputDir, "analysis/findings.json", serializeJson(findings));
  await writeSecureTextFile(outputDir, "analysis/metadata.json", serializeJson({
    target: config.baseUrl,
    auth_mode: config.token ? "token" : "session",
    verify_ssl: config.verifySsl,
    source_chain: config.sourceChain,
    generated_at: generatedAt.toISOString(),
    controls_assessed: findings.length,
    controls_total: ANSIBLE_CONTROLS.length,
    options: {
      days: options.days ?? DEFAULT_LOOKBACK_DAYS,
      job_limit: options.job_limit ?? DEFAULT_JOB_LIMIT,
      host_limit: options.host_limit ?? DEFAULT_HOST_LIMIT,
      template_limit: options.template_limit ?? DEFAULT_TEMPLATE_LIMIT,
      user_limit: options.user_limit ?? DEFAULT_USER_LIMIT,
      min_success_rate: options.min_success_rate ?? 90,
      max_manual_rate: options.max_manual_rate ?? 25,
      stale_host_days: options.stale_host_days ?? 30,
      critical_stale_host_days: options.critical_stale_host_days ?? 60,
      stale_template_days: options.stale_template_days ?? 90,
      max_org_admins: options.max_org_admins ?? 3,
      stale_credential_days: options.stale_credential_days ?? 90,
      stale_token_days: options.stale_token_days ?? 90,
      max_shared_templates: options.max_shared_templates ?? 5,
    },
  }));

  await writeSecureTextFile(outputDir, "compliance/executive_summary.md", buildExecutiveSummary(config, assessments, errors, generatedAt));
  await writeSecureTextFile(outputDir, "compliance/unified_compliance_matrix.md", buildUnifiedMatrix(findings));
  const frameworkReports: Array<[string, string, FrameworkKey]> = [
    ["compliance/fedramp/fedramp_compliance_report.md", "FedRAMP / NIST 800-53 r5 Compliance Report", "fedramp"],
    ["compliance/cmmc/cmmc_compliance_report.md", "CMMC 2.0 Level 2 Compliance Report", "cmmc"],
    ["compliance/soc2/soc2_compliance_report.md", "SOC 2 Compliance Report", "soc2"],
    ["compliance/cis/cis_compliance_report.md", "CIS Controls v8 Compliance Report", "cis"],
    ["compliance/pci_dss/pci_dss_compliance_report.md", "PCI-DSS 4.0 Compliance Report", "pci_dss"],
    ["compliance/disa_stig/stig_compliance_checklist.md", "DISA STIG Compliance Checklist", "disa_stig"],
  ];
  for (const [pathName, title, framework] of frameworkReports) {
    await writeSecureTextFile(outputDir, pathName, buildFrameworkReport(title, findings, framework));
  }
  await writeSecureTextFile(outputDir, "QUICK_REFERENCE.md", buildQuickReference());
  if (errors.length > 0) {
    await writeSecureTextFile(outputDir, "_errors.log", `${errors.join("\n")}\n`);
  }

  await createZipArchive(outputDir, zipPath);

  return {
    outputDir,
    zipPath,
    fileCount: await countFilesRecursively(outputDir),
    findingCount: findings.length,
    errorCount: errors.length,
  };
}

function normalizeCheckAccessArgs(args: unknown): CheckAccessArgs {
  const value = asObject(args) ?? {};
  return {
    url: asString(value.url) ?? asString(value.base_url),
    username: asString(value.username),
    token: asString(value.token),
    timeout_seconds: asNumber(value.timeout_seconds),
    verify_ssl: asBoolean(value.verify_ssl),
  };
}

function normalizeJobHealthArgs(args: unknown): JobHealthArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeCheckAccessArgs(args),
    days: asNumber(value.days),
    job_limit: asNumber(value.job_limit),
    min_success_rate: asNumber(value.min_success_rate),
    max_manual_rate: asNumber(value.max_manual_rate),
  };
}

function normalizeHostCoverageArgs(args: unknown): HostCoverageArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeCheckAccessArgs(args),
    days: asNumber(value.days),
    stale_host_days: asNumber(value.stale_host_days),
    critical_stale_host_days: asNumber(value.critical_stale_host_days),
    stale_template_days: asNumber(value.stale_template_days),
    host_limit: asNumber(value.host_limit),
    inventory_source_limit: asNumber(value.inventory_source_limit),
    template_limit: asNumber(value.template_limit),
  };
}

function normalizePlatformSecurityArgs(args: unknown): PlatformSecurityArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeCheckAccessArgs(args),
    max_org_admins: asNumber(value.max_org_admins),
    stale_credential_days: asNumber(value.stale_credential_days),
    stale_token_days: asNumber(value.stale_token_days),
    max_shared_templates: asNumber(value.max_shared_templates),
    project_limit: asNumber(value.project_limit),
    template_limit: asNumber(value.template_limit),
    user_limit: asNumber(value.user_limit),
  };
}

function normalizeExportAuditBundleArgs(args: unknown): ExportAuditBundleArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeJobHealthArgs(args),
    ...normalizeHostCoverageArgs(args),
    ...normalizePlatformSecurityArgs(args),
    output_dir: asString(value.output_dir) ?? asString(value.output),
  };
}

function createClient(args: CheckAccessArgs): AnsibleAapClient {
  return new AnsibleAapClient(
    resolveAnsibleConfiguration({
      url: args.url,
      username: args.username,
      token: args.token,
      timeout_seconds: args.timeout_seconds,
      verify_ssl: args.verify_ssl,
    }),
  );
}

const authParams = {
  url: Type.Optional(Type.String({ description: "AAP base URL. Defaults to AAP_URL." })),
  username: Type.Optional(Type.String({ description: "AAP username for session auth. Defaults to AAP_USERNAME. Password must come from AAP_PASSWORD." })),
  token: Type.Optional(Type.String({ description: "AAP OAuth2 bearer token. Defaults to AAP_TOKEN." })),
  timeout_seconds: Type.Optional(Type.Number({ description: "Request timeout in seconds. Defaults to 30.", default: 30 })),
  verify_ssl: Type.Optional(Type.Boolean({ description: "Set false to skip TLS verification for this run only (approved non-production troubleshooting). Defaults to AAP_VERIFY_SSL or true." })),
};

const jobHealthParams = {
  days: Type.Optional(Type.Number({ description: "Lookback window in days. Defaults to 90.", default: 90 })),
  job_limit: Type.Optional(Type.Number({ description: "Maximum jobs to sample. Defaults to 500.", default: 500 })),
  min_success_rate: Type.Optional(Type.Number({ description: "Minimum acceptable job success percentage. Defaults to 90.", default: 90 })),
  max_manual_rate: Type.Optional(Type.Number({ description: "Maximum acceptable manual launch percentage. Defaults to 25.", default: 25 })),
};

const hostCoverageParams = {
  stale_host_days: Type.Optional(Type.Number({ description: "High stale-host threshold in days. Defaults to 30.", default: 30 })),
  critical_stale_host_days: Type.Optional(Type.Number({ description: "Critical stale-host threshold in days. Defaults to 60.", default: 60 })),
  stale_template_days: Type.Optional(Type.Number({ description: "Stale job template threshold in days. Defaults to 90.", default: 90 })),
  host_limit: Type.Optional(Type.Number({ description: "Maximum hosts to sample. Defaults to 1000.", default: 1000 })),
  inventory_source_limit: Type.Optional(Type.Number({ description: "Maximum inventory sources to sample. Defaults to 200.", default: 200 })),
  template_limit: Type.Optional(Type.Number({ description: "Maximum job templates to sample. Defaults to 500.", default: 500 })),
};

const platformSecurityParams = {
  max_org_admins: Type.Optional(Type.Number({ description: "Maximum expected admins per organization. Defaults to 3.", default: 3 })),
  stale_credential_days: Type.Optional(Type.Number({ description: "Credential age threshold in days. Defaults to 90.", default: 90 })),
  stale_token_days: Type.Optional(Type.Number({ description: "OAuth2 token age threshold in days. Defaults to 90.", default: 90 })),
  max_shared_templates: Type.Optional(Type.Number({ description: "Maximum job templates that may share one credential. Defaults to 5.", default: 5 })),
  project_limit: Type.Optional(Type.Number({ description: "Maximum projects to sample. Defaults to 500.", default: 500 })),
  user_limit: Type.Optional(Type.Number({ description: "Maximum users to sample. Defaults to 200.", default: 200 })),
};

export function registerAnsibleTools(pi: any): void {
  pi.registerTool({
    name: "ansible_check_access",
    label: "Check Ansible AAP audit access",
    description:
      "Validate read-only Ansible Automation Platform API access and show which job, host, template, schedule, credential, RBAC, and audit surfaces are readable.",
    parameters: Type.Object(authParams),
    prepareArguments: normalizeCheckAccessArgs,
    async execute(_toolCallId: string, args: CheckAccessArgs) {
      try {
        const result = await checkAnsibleAccess(createClient(args));
        return textResult(formatAccessCheckText(result), {
          tool: "ansible_check_access",
          ...result,
        });
      } catch (error) {
        return errorResult(
          `Ansible AAP access check failed: ${errorMessage(error)}`,
          { tool: "ansible_check_access" },
        );
      }
    },
  });

  pi.registerTool({
    name: "ansible_assess_job_health",
    label: "Assess Ansible AAP job health",
    description:
      "Assess Ansible Automation Platform job execution health (spec controls 1 to 5 and 28): success rate, chronic template failures, stuck jobs versus historical runtime, manual launch rate, failed job remediation within 7 days, and concurrent job limits.",
    parameters: Type.Object({ ...authParams, ...jobHealthParams }),
    prepareArguments: normalizeJobHealthArgs,
    async execute(_toolCallId: string, args: JobHealthArgs) {
      try {
        const result = await assessAnsibleJobHealth(createClient(args), {
          days: args.days,
          jobLimit: args.job_limit,
          minSuccessRate: args.min_success_rate,
          maxManualRate: args.max_manual_rate,
        });
        return textResult(formatAssessmentText(result), { tool: "ansible_assess_job_health", ...result });
      } catch (error) {
        return errorResult(
          `Ansible AAP job health assessment failed: ${errorMessage(error)}`,
          { tool: "ansible_assess_job_health" },
        );
      }
    },
  });

  pi.registerTool({
    name: "ansible_assess_host_coverage",
    label: "Assess Ansible AAP host coverage",
    description:
      "Assess Ansible Automation Platform host coverage and automation hygiene (spec controls 6 to 15): unmanaged and stale hosts, inventory source sync, host failure rate, disabled hosts, stale and unscheduled templates, missed and disabled schedules, and workflow coverage.",
    parameters: Type.Object({
      ...authParams,
      days: Type.Optional(Type.Number({ description: "Lookback window in days for per-host job results. Defaults to 90.", default: 90 })),
      ...hostCoverageParams,
    }),
    prepareArguments: normalizeHostCoverageArgs,
    async execute(_toolCallId: string, args: HostCoverageArgs) {
      try {
        const result = await assessAnsibleHostCoverage(createClient(args), {
          days: args.days,
          staleHostDays: args.stale_host_days,
          criticalStaleHostDays: args.critical_stale_host_days,
          staleTemplateDays: args.stale_template_days,
          hostLimit: args.host_limit,
          inventorySourceLimit: args.inventory_source_limit,
          templateLimit: args.template_limit,
        });
        return textResult(formatAssessmentText(result), { tool: "ansible_assess_host_coverage", ...result });
      } catch (error) {
        return errorResult(
          `Ansible AAP host coverage assessment failed: ${errorMessage(error)}`,
          { tool: "ansible_assess_host_coverage" },
        );
      }
    },
  });

  pi.registerTool({
    name: "ansible_assess_platform_security",
    label: "Assess Ansible AAP platform security",
    description:
      "Assess Ansible Automation Platform platform security (spec controls 16 to 27, 29, 30): credential age, sharing, plaintext secrets and ownership, OAuth2 tokens, org admins, team roles, execute versus admin separation, auditor coverage, external auth, activity stream, notifications, project SCM health, and execution environments.",
    parameters: Type.Object({ ...authParams, ...platformSecurityParams, template_limit: hostCoverageParams.template_limit }),
    prepareArguments: normalizePlatformSecurityArgs,
    async execute(_toolCallId: string, args: PlatformSecurityArgs) {
      try {
        const result = await assessAnsiblePlatformSecurity(createClient(args), {
          maxOrgAdmins: args.max_org_admins,
          staleCredentialDays: args.stale_credential_days,
          staleTokenDays: args.stale_token_days,
          maxSharedTemplates: args.max_shared_templates,
          projectLimit: args.project_limit,
          templateLimit: args.template_limit,
          userLimit: args.user_limit,
        });
        return textResult(formatAssessmentText(result), { tool: "ansible_assess_platform_security", ...result });
      } catch (error) {
        return errorResult(
          `Ansible AAP platform security assessment failed: ${errorMessage(error)}`,
          { tool: "ansible_assess_platform_security" },
        );
      }
    },
  });

  pi.registerTool({
    name: "ansible_export_audit_bundle",
    label: "Export Ansible AAP audit bundle",
    description:
      "Export an Ansible Automation Platform audit package covering all 30 spec controls with raw API snapshots (core_data/), normalized findings (analysis/), executive summary, unified matrix and per-framework reports (compliance/), QUICK_REFERENCE.md, an _errors.log for partial failures, and a zip archive.",
    parameters: Type.Object({
      ...authParams,
      output_dir: Type.Optional(Type.String({ description: `Output root. Defaults to ${DEFAULT_OUTPUT_DIR}.` })),
      ...jobHealthParams,
      ...hostCoverageParams,
      ...platformSecurityParams,
    }),
    prepareArguments: normalizeExportAuditBundleArgs,
    async execute(_toolCallId: string, args: ExportAuditBundleArgs) {
      try {
        const config = resolveAnsibleConfiguration({
          url: args.url,
          username: args.username,
          token: args.token,
          timeout_seconds: args.timeout_seconds,
          verify_ssl: args.verify_ssl,
        });
        const outputRoot = resolve(process.cwd(), args.output_dir?.trim() || DEFAULT_OUTPUT_DIR);
        const result = await exportAnsibleAuditBundle(
          new AnsibleAapClient(config),
          config,
          outputRoot,
          args,
        );
        return textResult(
          [
            "Ansible AAP audit bundle exported.",
            `Output dir: ${result.outputDir}`,
            `Zip archive: ${result.zipPath}`,
            `Findings: ${result.findingCount}`,
            `Files: ${result.fileCount}`,
            `Partial collection warnings: ${result.errorCount}`,
          ].join("\n"),
          {
            tool: "ansible_export_audit_bundle",
            output_dir: result.outputDir,
            zip_path: result.zipPath,
            finding_count: result.findingCount,
            file_count: result.fileCount,
            error_count: result.errorCount,
          },
        );
      } catch (error) {
        return errorResult(
          `Ansible AAP audit bundle export failed: ${errorMessage(error)}`,
          { tool: "ansible_export_audit_bundle" },
        );
      }
    },
  });
}
