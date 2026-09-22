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
const DEFAULT_TEMPLATE_PROBE_LIMIT = 50;
const DEFAULT_TIMEOUT_MS = 30_000;
const TOKEN_SKEW_MS = 5 * 60 * 1000;
const REMEDIATION_WINDOW_DAYS = 7;
const MISSED_RUN_MULTIPLIER = 1.5;
const DEFAULT_OUTPUT_DIR = "./export/ansible-aap";
const CRITICAL_TEMPLATE_PATTERN = /patch|harden|cis|stig|baseline|logging|audit|access|password|compliance|security|firewall/i;
const SECRET_KEY_PATTERN = /(password|passwd|secret|token|api[_-]?key|private[_-]?key|client[_-]?secret)/i;
const SECRET_ASSIGNMENT_PATTERN = /([A-Za-z0-9_.-]*(?:password|passwd|secret|token|api[_-]?key|private[_-]?key|client[_-]?secret)[A-Za-z0-9_.-]*)["']?\s*[:=]\s*["']?([^\s"',}\]]{4,})/gi;
export const ANSIBLE_REDACTION_MARKER = "[REDACTED]";
// Matched against a key name lowered and stripped of separators, so
// AUTH_LDAP_BIND_PASSWORD, refreshToken, ssh_key_data, X-Api-Key, and
// SOCIAL_AUTH_GITHUB_KEY all count as credential-bearing.
const CREDENTIAL_KEY_PATTERN = /(password|passwd|passphrase|secret|token|credential|authorization|signature|key)/;
const ENVIRONMENT_KEY_PATTERN = /env$/;
const URL_KEY_PATTERN = /(url|uri|endpoint|webhook)/;
const URL_SCHEME_PATTERN = /^[a-z][a-z0-9+.-]*:\/\//i;

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
  /** HTTP status the failed read observed; null when the failure was not an HTTP response. Absent when the read succeeded. */
  status?: number | null;
  /** Path the failed read requested, without its query string. Absent when the read succeeded. */
  endpoint?: string;
}

/** What core_data carries in place of a dataset whose read failed: never an empty list or object. */
export interface AnsibleNotCollectedMarker {
  collected: false;
  status: number | null;
  endpoint: string;
  error: string;
}

export interface AnsibleAccessSurface {
  name: string;
  endpoint: string;
  status: "readable" | "not_readable";
  /** Items the probe counted; null when the probe failed, so a denial never reads as an empty inventory. */
  count?: number | null;
  /** HTTP status the failing probe observed; null when the failure was not an HTTP response. */
  http_status?: number | null;
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

/**
 * Describes a non-JSON body by content type and byte length only. Proxy and
 * WAF pages can echo request headers, so the body text itself is never kept,
 * whatever content type the response claimed.
 */
function describeNonJsonBody(contentType: string | null, rawText: string): string {
  return `non-JSON body (${contentType?.split(";")[0]?.trim() || "unknown content type"}, ${Buffer.byteLength(rawText, "utf8")} bytes)`;
}

/**
 * Keeps only AAP's documented `detail` or `error` field of a failed JSON
 * response; any body that does not parse as JSON is replaced by its
 * status-and-length note so no slice of it reaches an error string.
 */
function responseDetail(text: string, contentType: string | null): string {
  if (text.length === 0) return "";
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return `: ${describeNonJsonBody(contentType, text)}`;
  }
  const object = asObject(parsed);
  const detail = asString(object?.detail) ?? asString(object?.error);
  return detail ? ` ${detail}` : "";
}

const REDACTED_ERROR_VALUE = "[REDACTED]";
const CONFIGURED_SECRETS = new Set<string>();
const MIN_CONFIGURED_SECRET_LENGTH = 4;

/**
 * The forms a configured secret can take inside an error string: plain, JSON-escaped, URL-encoded, base64,
 * and base64url (rule 9 scrub boundary: a configured secret is removed whatever its shape, in every form).
 */
function configuredSecretForms(value: string): string[] {
  const forms = new Set<string>([
    value,
    JSON.stringify(value).slice(1, -1),
    encodeURIComponent(value),
    Buffer.from(value, "utf8").toString("base64"),
    Buffer.from(value, "utf8").toString("base64url"),
  ]);
  return [...forms].filter((form) => form.length >= MIN_CONFIGURED_SECRET_LENGTH);
}

/** Secrets the running client was configured with or obtained; every recorded error string is scrubbed of them in every form. */
function registerConfiguredSecrets(...values: Array<string | undefined>): void {
  for (const value of values) {
    if (!value || value.length < MIN_CONFIGURED_SECRET_LENGTH) continue;
    for (const form of configuredSecretForms(value)) CONFIGURED_SECRETS.add(form);
  }
}

function escapeErrorRegExp(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** Replaces every configured secret form wherever it appears; a form under eight characters only where it stands as a whole token. */
function scrubConfiguredSecrets(text: string): string {
  let scrubbed = text;
  for (const secret of [...CONFIGURED_SECRETS].sort((left, right) => right.length - left.length)) {
    scrubbed = secret.length >= 8
      ? scrubbed.split(secret).join(REDACTED_ERROR_VALUE)
      : scrubbed.replace(new RegExp(`(?<![A-Za-z0-9])${escapeErrorRegExp(secret)}(?![A-Za-z0-9])`, "g"), REDACTED_ERROR_VALUE);
  }
  return scrubbed;
}

// The words that name a credential. A key ends in one of them; isCredentialNamedKey below decides how the word may
// be attached to the rest of the key. `skey` and `ikey` are Duo's secret key and integration key (DUO_SKEY, DUO_IKEY),
// both configured secrets of that integration; there is no bare `key`, so KmsKeyId, ssh_key_name, and the like stay
// identifiers.
const ERROR_CREDENTIAL_WORDS =
  "token|secret|passw(?:or)?d|pwd|api[_-]?key|apikey|auth[_-]?key|auth[_-]?email|session(?:[_-]?id)?|sid|cookie|csrftoken|authorization|auth|signature|sig|nonce|credentials?|access[_-]?key|private[_-]?key|skey|ikey";
const ERROR_CREDENTIAL_KEY_PATTERN = `[A-Za-z0-9_.-]*(?:${ERROR_CREDENTIAL_WORDS})`;
/**
 * key=value and key: value pairs whose key ends in a credential word (a key after "/" is a path segment, not a
 * key). The value runs to whitespace, a quote, `&`, `;`, `,`, a closing bracket, an angle bracket, or a
 * backslash (the compound-line rule), so a pair inside a query string, a header list, a JSON fragment, or a
 * parenthesis keeps the text after it. A value that is already the marker is not a value, so a second pass over a
 * scrubbed message changes nothing; scrubCredentialPairs decides whether the key names a credential.
 */
const ERROR_CREDENTIAL_PAIR_PATTERN = new RegExp(
  `(?<!/)\\b(${ERROR_CREDENTIAL_KEY_PATTERN})(["']?\\s*[=:]\\s*["']?)((?:(?:Bearer|Basic|Digest|Token|ApiKey)\\s+)?(?!\\[REDACTED\\])[^\\s"'&;,<>)\\]}\\\\]+)`,
  "gi",
);
const TRAILING_PUNCTUATION_PATTERN = /[.!?:)]+$/;

const ERROR_SCHEME_PATTERN = "(?:Bearer|Basic|Digest|Negotiate|SSWS|Token|ApiKey|Api-Key)";
/**
 * A quoted value: the opening quote (plain, or JSON-escaped when the message was itself serialized) with its
 * quote character captured, the value up to the matching close quote (so it may hold spaces and the other quote
 * character), and the close quote. Both patterns below place it after two capturing groups, so the quote
 * character is group 4 and the close quote group 5.
 */
const ERROR_QUOTED_VALUE_PATTERN = String.raw`(\\?(["']))(?:(?!\\?\4)[^\n\\])+(\\?\4)`;
/**
 * Codex P1 (quoted header value). `X-Api-Key: "value"`, `Cookie: sid='value'`, `Authorization: Bearer "value"`,
 * `\"X-Auth-Key\":\"value\"`: with or without spaces, single or double quotes, plain or JSON-escaped. The quotes
 * delimit the carrier, so the quoted value is removed whole whatever its shape; the pair rule above stops at the
 * opening quote and would judge a short or name-shaped value ("key", "prod-key") as prose. The header name, the
 * separator, the scheme, and the quotes stay so the message remains diagnosable.
 */
const ERROR_QUOTED_CREDENTIAL_PATTERN = new RegExp(
  String.raw`\b(${ERROR_CREDENTIAL_KEY_PATTERN})((?:\\?["'])?\s*[=:]\s*(?:${ERROR_SCHEME_PATTERN}\s*)?)${ERROR_QUOTED_VALUE_PATTERN}`,
  "gi",
);
// A scheme word that is itself quoted (`"Token":"..."`, a JSON key) or ends a compound key (`"x-api-key":`,
// `"settings.token":`) is a pair the rule above already handled.
const ERROR_QUOTED_SCHEME_PATTERN = new RegExp(String.raw`(?<!["'\\./-])\b(${ERROR_SCHEME_PATTERN})(\s*)${ERROR_QUOTED_VALUE_PATTERN}`, "gi");
const QUOTED_VALUE_REPLACEMENT = `$1$2$3${REDACTED_ERROR_VALUE}$5`;

const CREDENTIAL_KEY_WORD_PATTERN = new RegExp(`(?:${ERROR_CREDENTIAL_WORDS})$`, "i");
// Credential words that end too many ordinary words to count when glued to a lowercase prefix (`oauth`, `ssid`).
const WEAK_CREDENTIAL_WORD_PATTERN = /^(?:auth|sid|sig)$/i;
const PAIR_VALUE_SCHEME_PATTERN = /^(?:Bearer|Basic|Digest|Token|ApiKey)\s+/i;
const BARE_SCHEME_WORD_PATTERN = /^(?:Bearer|Basic|Digest|Token|ApiKey)$/i;

/**
 * Whether a key names a credential (reviewer D round 5 baseline). It does when it is a credential word
 * (`password`, `Token`, `skey`), sets one off with `_`, `-`, or `.` (`DB_PASSWORD`, `AZURE_CLIENT_SECRET`,
 * `x-api-key`, `Proxy-Authorization`), or is a lowerCamelCase, lowercase, or uppercase compound ending in one
 * (`accessToken`, `clientSecret`, `dbpassword`, `ACCESSTOKEN`). A PascalCase identifier that merely ends in the
 * word (`InvalidAuthenticationToken`, `ExpiredToken`) is an error code or a type name, and the text after its
 * colon is prose. A key that names an identifier (`AWS_ACCESS_KEY_ID`, `AZURE_TENANT_ID`, `CLOUDFLARE_EMAIL`)
 * never ends in a credential word, so its value is judged by its own shape alone.
 */
function isCredentialNamedKey(key: string): boolean {
  const word = CREDENTIAL_KEY_WORD_PATTERN.exec(key)?.[0];
  if (word === undefined) return false;
  const prefix = key.slice(0, key.length - word.length);
  if (prefix.length === 0 || /[_.-]$/.test(prefix)) return true;
  if (/^[A-Z]/.test(prefix) && /[a-z]/.test(prefix)) return false;
  return !WEAK_CREDENTIAL_WORD_PATTERN.test(word);
}

/**
 * The value of a pair whose key names a credential is the credential and is removed whatever its shape and
 * length (reviewer D round 5 baseline): `password=letmein`, `DB_PASSWORD=Sunshine`, `AZURE_CLIENT_SECRET: abc12`,
 * and `DUO_SKEY=p@ss` go the way `{"password":"letmein"}` already did. The key, the separator, a scheme word in
 * front of the value, and the sentence punctuation after it stay; a scheme word standing alone ("sent as
 * Authorization: Bearer") names the scheme and carries nothing.
 */
function scrubCredentialPairs(text: string): string {
  return text.replace(ERROR_CREDENTIAL_PAIR_PATTERN, (match: string, key: string, separator: string, value: string) => {
    if (!isCredentialNamedKey(key)) return match;
    const scheme = PAIR_VALUE_SCHEME_PATTERN.exec(value)?.[0] ?? "";
    const core = value.slice(scheme.length).replace(TRAILING_PUNCTUATION_PATTERN, "");
    if (core.length === 0 || BARE_SCHEME_WORD_PATTERN.test(core)) return match;
    return `${key}${separator}${scheme}${REDACTED_ERROR_VALUE}${value.slice(scheme.length + core.length)}`;
  });
}

/**
 * Header carriers whose value is free form: Cookie and Set-Cookie (session values with their attributes) and
 * Cloudflare's legacy X-Auth-Key / X-Auth-Email pair (the global API key and its account; round 4 item F). The
 * value is removed whatever its shape. Where it ends follows the compound-line rule shared by every scrubber:
 * a quoted value (a plain or JSON-escaped quote) ends at its closing quote, so a closed value that holds `; Name:`
 * is one value and the quotes stay around the marker; an unquoted value, or a quoted one that is never closed,
 * ends at the `;` or `,` that introduces the next `Name:` header token on the line, at a `<` or `>` (the header
 * quoted inside markup), at a `"` that closes the JSON string and container that carried the line (`"}`, `"]`),
 * at a JSON-escaped line break (`\n`, `\r`, `\u000a`, `\u000d` as backslash text, the end of the line inside a
 * serialized message), or
 * at the end of the line, so the next header keeps its name and gets its own carrier treatment. A value that is
 * already the marker is left alone, so a second pass over a scrubbed message leaves the text after the marker as
 * it is.
 *
 * The header name counts as a carrier at a line start, after any character that is not part of a name, and
 * after a JSON escape (reviewer D round 5 escapes): inside a serialized message the character before `Cookie`
 * is the escape's last letter (`\nCookie`, `\u000aCookie`), a word character to `\b`, and a boundary that
 * relied on `\b` left the free-form removal to the pair rule, which stops at the first `;` and judges every
 * later cookie pair on its own name and shape.
 */
const HEADER_CARRIER_PATTERN = /(?:(?<![A-Za-z0-9_])|(?<=\\[nrtbfv])|(?<=\\u[0-9A-Fa-f]{4}))(set-cookie|cookie|x-auth-key|x-auth-email)(\s*[:=]\s*)(?!\s*\[REDACTED\])/gi;
const HEADER_CARRIER_QUOTE_PATTERN = /^(\\?)(["'])/;
const NEXT_HEADER_TOKEN_PATTERN = /[;,]\s*[A-Za-z][A-Za-z0-9-]*\s*:/;
const MARKUP_OR_JSON_CLOSE_PATTERN = /[<>]|"(?=\s*[}\]])/;
const ESCAPED_LINE_BREAK_PATTERN = /\\(?:[nr]|u000[aAdD])/;

/** The end of a free-form header value that starts at `start`, and the quote (plain or escaped) that encloses a closed quoted value. */
function headerCarrierValueEnd(text: string, start: number): { end: number; quote?: string } {
  const newline = text.indexOf("\n", start);
  const line = text.slice(start, newline === -1 ? text.length : newline);
  const opening = HEADER_CARRIER_QUOTE_PATTERN.exec(line);
  if (opening) {
    const close = line.indexOf(opening[0], opening[0].length);
    if (close !== -1) return { end: start + close + opening[0].length, quote: opening[0] };
  }
  // An unterminated quote is part of the value; the stops are searched after it.
  const skip = opening ? opening[0].length : 0;
  const rest = line.slice(skip);
  const stops = [MARKUP_OR_JSON_CLOSE_PATTERN.exec(rest)?.index, NEXT_HEADER_TOKEN_PATTERN.exec(rest)?.index, ESCAPED_LINE_BREAK_PATTERN.exec(rest)?.index].filter(
    (index): index is number => index !== undefined,
  );
  return { end: start + skip + (stops.length > 0 ? Math.min(...stops) : rest.length) };
}

function scrubHeaderCarriers(text: string): string {
  let scrubbed = "";
  let cursor = 0;
  for (const match of text.matchAll(HEADER_CARRIER_PATTERN)) {
    // A carrier name inside a value already consumed (`Cookie: "a; X-Auth-Key: b"`) is part of that value.
    if (match.index < cursor) continue;
    const valueStart = match.index + match[0].length;
    const { end, quote } = headerCarrierValueEnd(text, valueStart);
    if (end === valueStart) continue;
    scrubbed += text.slice(cursor, valueStart) + (quote === undefined ? REDACTED_ERROR_VALUE : `${quote}${REDACTED_ERROR_VALUE}${quote}`);
    cursor = end;
  }
  return scrubbed + text.slice(cursor);
}

const ERROR_TEXT_PATTERNS: ReadonlyArray<readonly [RegExp, string]> = [
  // The free-form header carriers (Cookie, Set-Cookie, X-Auth-Key, X-Auth-Email) run first in scrubHeaderCarriers,
  // so the shape rules below only ever see the marker.
  // Quoted header and pair values next, whatever their shape, so the scheme and pair rules see the marker.
  [ERROR_QUOTED_CREDENTIAL_PATTERN, QUOTED_VALUE_REPLACEMENT],
  [ERROR_QUOTED_SCHEME_PATTERN, QUOTED_VALUE_REPLACEMENT],
  // Authorization scheme values wherever they appear (headers, cookies, HTML, JSON messages); the value must be
  // long, carry a digit or base64 symbol, or change case inside the word, so prose such as "Basic authentication"
  // and "Bearer Token" stays.
  // Case-sensitive so the inner-case-change test means what it says (under /i, [a-z][A-Z] is any two letters).
  [/\b(Bearer|bearer|BEARER|Basic|basic|BASIC|Digest|digest|Negotiate|negotiate|SSWS|Token|token|TOKEN|ApiKey|apikey|APIKEY|Api-Key|api-key)\s+(?=[A-Za-z0-9\-._~+/=:]{16,}|[A-Za-z0-9\-._~+/=:]*[\d+/=]|[A-Za-z0-9\-._~+/=:]*[a-z][A-Z])[A-Za-z0-9\-._~+/=:]{6,}/g, `$1 ${REDACTED_ERROR_VALUE}`],
  // JWT-shaped strings.
  [/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g, REDACTED_ERROR_VALUE],
  // PEM blocks, whole or cut off.
  [/-----BEGIN [A-Z0-9 ]+-----[\s\S]*?(?:-----END [A-Z0-9 ]+-----|$)/g, REDACTED_ERROR_VALUE],
  // AWS access key ids, 40-character secret access keys, long secret-shaped blobs, and hex digests.
  [/\b(?:AKIA|ASIA|AROA|AIDA|AGPA|ANPA|ANVA|APKA|ABIA|ACCA)[A-Z0-9]{16}\b/g, REDACTED_ERROR_VALUE],
  [/(?<![A-Za-z0-9/+=])[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+=])/g, REDACTED_ERROR_VALUE],
  // Long blobs must carry a digit so camelCase identifiers survive.
  [/(?<![A-Za-z0-9+_=-])(?=[A-Za-z0-9+_-]*\d)[A-Za-z0-9+_-]{40,}={0,2}(?![A-Za-z0-9+_=-])/g, REDACTED_ERROR_VALUE],
  [/\b[a-f0-9]{32,}\b/gi, REDACTED_ERROR_VALUE],
];

// URL userinfo and query strings anywhere in the string, not only when the string starts with a URL.
const ERROR_URL_PATTERN = /\b(https?:\/\/)(?:[^\s/@"'<>]+@)?([^\s?#"'<>]+)(\?[^\s#"'<>]*)?/gi;

/**
 * Rule 9 scrub boundary for bare values. A run of 16 or more token characters is removed when it is shaped
 * like a token (base64 symbols, digits scattered through its letters, or casing that breaks into one- and
 * two-letter camelCase pieces) and kept when it is shaped like a name: "-" or "_" separated segments that are
 * each letters in any casing, digits alone, or letters with one digit group (`prod-us-east-2026`,
 * `AWSLambdaBasicExecutionRole`, `sha256`), an uppercase code, or a canonical UUID. "/", ".", ":", "@", and
 * whitespace end a run, so path segments, hostnames, ARNs, and emails are judged piece by piece. Opaque
 * identifiers whose shape is a token's are removed from error text as well; they travel in structured fields.
 */
// Trailing "=" is base64 padding only when a delimiter follows it; before a marker (`API_KEY=[REDACTED]`) or a path
// (`AWS_SHARED_CREDENTIALS_FILE=/home/audit/.aws/credentials`) it is the pair's separator, so the key keeps its name.
const LONG_TOKEN_RUN_PATTERN = /[A-Za-z0-9+_-]{16,}(?:={1,2}(?![A-Za-z0-9&[/]))?/g;
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const UPPERCASE_CODE_PATTERN = /^[A-Z][A-Z_]*$|^[A-Z][A-Z0-9]*(?:[_-][A-Z0-9]+)+$/;
const MIN_LETTERS_FOR_CASING = 6;

const CAMEL_WORD_PATTERN = /[A-Z]+(?![a-z])|[A-Z]?[a-z]+/g;
const MAX_SHORT_WORD_LENGTH = 2;

/**
 * Token-shaped casing. Split at camelCase boundaries, a name is words and acronyms of three letters or more
 * (`GetAccessKeyLastUsed`, `AWSLambdaBasicExecutionRole`, `getHTTPSUrl`), while a random run breaks into
 * one- and two-letter pieces (`bPxRfiCYcanaryKEYqm`: b, Px, C, KE). Two or more such pieces making up at
 * least a third of the words is the token signal; one short word (`GetEbsEncryptionByDefault`) is a name.
 */
function hasTokenCasing(letters: string): boolean {
  if (letters.length < MIN_LETTERS_FOR_CASING) return false;
  const words = letters.match(CAMEL_WORD_PATTERN) ?? [];
  const shortWords = words.filter((word) => word.length <= MAX_SHORT_WORD_LENGTH).length;
  return shortWords >= 2 && shortWords * 3 >= words.length;
}

/** A "-" or "_" separated segment shaped like part of a name: empty, digits alone, or letters with at most one digit group and no token casing. */
function isNameSegment(segment: string): boolean {
  if (segment.length === 0 || /^\d+$/.test(segment)) return true;
  if (!/^[A-Za-z0-9]+$/.test(segment)) return false;
  if ((segment.match(/\d+/g) ?? []).length > 1) return false;
  return !hasTokenCasing(segment.replace(/\d+/g, ""));
}

function looksLikeToken(run: string): boolean {
  if (UUID_PATTERN.test(run) || UPPERCASE_CODE_PATTERN.test(run)) return false;
  if (/[+=]/.test(run)) return true;
  return run.split(/[-_]/).some((segment) => !isNameSegment(segment));
}

function scrubLongTokens(text: string): string {
  return text.replace(LONG_TOKEN_RUN_PATTERN, (run: string) => (looksLikeToken(run) ? REDACTED_ERROR_VALUE : run));
}

/**
 * Rule 9 sink for error text. AnsibleApiError scrubs its own message and errorMessage(), the only
 * conversion from a thrown error to recorded text (collection snapshots, object snapshots, access
 * surfaces, tool results), runs the same pass, so no path can carry a credential echoed by an upstream
 * error body, a transport error, or a URL into the audit output.
 */
export function redactErrorText(text: string): string {
  let scrubbed = scrubConfiguredSecrets(text);
  scrubbed = scrubbed.replace(ERROR_URL_PATTERN, (_match, scheme: string, hostPath: string, query?: string) =>
    `${scheme}${hostPath}${query ? `?${REDACTED_ERROR_VALUE}` : ""}`,
  );
  scrubbed = scrubHeaderCarriers(scrubbed);
  for (const [pattern, replacement] of ERROR_TEXT_PATTERNS) {
    scrubbed = scrubbed.replace(pattern, replacement);
  }
  scrubbed = scrubCredentialPairs(scrubbed);
  return scrubLongTokens(scrubbed);
}

export class AnsibleApiError extends Error {
  /** HTTP status the request observed; undefined for transport failures (timeouts, connection errors). */
  readonly status: number | undefined;
  /** Path the request was sent to, without its query string. */
  readonly endpoint: string;

  constructor(message: string, status: number | undefined, endpoint: string) {
    super(redactErrorText(message));
    this.name = "AnsibleApiError";
    this.status = status;
    this.endpoint = endpoint;
  }
}

/** Path component of a request target, so an error names the endpoint without its query string. */
function requestPath(target: string): string {
  try {
    return new URL(target, "https://aap.invalid").pathname;
  } catch {
    return target.split("?")[0] ?? target;
  }
}

/** Why a server-supplied link is not followed. Each class renders as fixed text that never carries the link. */
type NextLinkRefusal = "foreign_origin" | "userinfo" | "unparseable";

/**
 * Same-origin rule for every URL taken from a response (a list page's `next`): resolved against the configured
 * base the way a browser would, so AAP's root-relative `/api/v2/...?page=2` links land on the base and a
 * protocol-relative `//host/...` link names its own host, the link must keep the base's scheme, host, and port
 * and carry no userinfo. Anything else is refused before a request (and the token or session cookie) leaves for it.
 */
function nextLinkRefusal(target: string, base: string): NextLinkRefusal | undefined {
  let baseUrl: URL;
  let resolved: URL;
  try {
    baseUrl = new URL(base);
    resolved = new URL(target, baseUrl);
  } catch {
    return "unparseable";
  }
  if (resolved.username !== "" || resolved.password !== "") return "userinfo";
  if (resolved.origin === "null" || resolved.origin !== baseUrl.origin) return "foreign_origin";
  return undefined;
}

const NEXT_LINK_REFUSAL_NOTES: Readonly<Record<NextLinkRefusal, string>> = Object.freeze({
  foreign_origin: "the API advertised a next page on another origin (scheme, host, or port), so the walk was stopped; the link was not followed and no request was made for it",
  userinfo: "the API advertised a next page link carrying userinfo, so the walk was stopped; the link was not followed and no request was made for it",
  unparseable: "the API advertised a next page link that could not be parsed, so the walk was stopped; the link was not followed and no request was made for it",
});

/** Rendering of a request refused by the same-origin rule before it was made; the target itself is never recorded. */
const REQUEST_REFUSED_NOTE = "AAP request refused: the target is not on the configured origin, so no request was made.";
/** The `endpoint` of a refused request: none was sent, and the refused target must not be named. */
const REFUSED_ENDPOINT = "not requested";

function normalizeKeyName(key: string): string {
  return key.toLowerCase().replace(/[^a-z0-9]/g, "");
}

function isCredentialKeyName(key: string): boolean {
  return CREDENTIAL_KEY_PATTERN.test(normalizeKeyName(key));
}

function isEmptyValue(value: unknown): boolean {
  return value === undefined || value === null || value === "";
}

function redactedOr(value: unknown): unknown {
  return isEmptyValue(value) ? value : ANSIBLE_REDACTION_MARKER;
}

function urlOrigin(value: string, keepPath: boolean): string | undefined {
  try {
    const parsed = new URL(value);
    if (!parsed.host) return undefined;
    return keepPath ? `${parsed.protocol}//${parsed.host}${parsed.pathname}` : `${parsed.protocol}//${parsed.host}`;
  } catch {
    return undefined;
  }
}

function sanitizeUrlText(value: string): string {
  if (!URL_SCHEME_PATTERN.test(value)) return value;
  return urlOrigin(value, true) ?? ANSIBLE_REDACTION_MARKER;
}

/**
 * Drops userinfo, query strings, and fragments from an SCM URL while keeping
 * the repository path; scp-style user:secret@host forms are redacted whole.
 */
export function sanitizeScmUrl(value: unknown): unknown {
  if (typeof value !== "string" || value.length === 0) return value;
  return urlOrigin(value, true) ?? (/:[^@/]*@/.test(value) ? ANSIBLE_REDACTION_MARKER : value);
}

/**
 * Returns a deep copy of a settings or configuration tree in which every value
 * under a credential-bearing key, every value of an environment dictionary,
 * and every value of a {name, value} or {key, value} pair is replaced by the
 * redaction marker, and every URL string loses its userinfo and query string.
 */
export function redactCredentialTree(value: unknown, redactEveryValue = false): unknown {
  if (Array.isArray(value)) {
    return value.map((entry) => {
      const pair = asObject(entry);
      if (pair && "value" in pair && (typeof pair.name === "string" || typeof pair.key === "string")) {
        return {
          ...(redactCredentialTree(pair, redactEveryValue) as JsonRecord),
          ...(typeof pair.name === "string" ? { name: pair.name } : {}),
          ...(typeof pair.key === "string" ? { key: pair.key } : {}),
          value: redactedOr(pair.value),
        };
      }
      return redactCredentialTree(entry, redactEveryValue);
    });
  }
  const object = asObject(value);
  if (object) {
    const output: JsonRecord = {};
    for (const [key, entry] of Object.entries(object)) {
      if (redactEveryValue || isCredentialKeyName(key)) {
        output[key] = redactedOr(entry);
      } else {
        output[key] = redactCredentialTree(entry, ENVIRONMENT_KEY_PATTERN.test(normalizeKeyName(key)));
      }
    }
    return output;
  }
  if (typeof value === "string") return sanitizeUrlText(value);
  return value;
}

/** Top-level variable names of a YAML or JSON variables document, or the keys of a variables object. */
export function variableNames(value: unknown): string[] {
  const object = asObject(value);
  if (object) return Object.keys(object);
  const text = asString(value);
  if (!text) return [];
  try {
    const parsed = asObject(JSON.parse(text));
    if (parsed) return Object.keys(parsed);
  } catch {
    // YAML documents fall through to the line scan.
  }
  const names: string[] = [];
  for (const line of text.split(/\r?\n/)) {
    const match = line.match(/^([A-Za-z_][A-Za-z0-9_.-]*)\s*:/);
    if (match?.[1]) names.push(match[1]);
  }
  return [...new Set(names)];
}

/** Replaces a variables body with the redaction marker plus the variable names it declared. */
export function redactVariables(value: unknown): unknown {
  if (isEmptyValue(value)) return value;
  const names = variableNames(value);
  return names.length > 0 ? `${ANSIBLE_REDACTION_MARKER} (variable names: ${names.join(", ")})` : ANSIBLE_REDACTION_MARKER;
}

/**
 * The documented type of a projected field, or a projector that returns the value to keep (undefined to drop
 * it). `scalar` accepts a string, number, boolean, or null; every kind accepts null, the API's rendering of an
 * unset field.
 */
type FieldKind = "scalar" | "string" | "number" | "boolean";
type FieldRule = FieldKind | ((value: unknown) => unknown);
type FieldSpec = Readonly<Record<string, FieldRule>>;

function isScalar(value: unknown): value is string | number | boolean | null {
  return value === null || typeof value === "string" || typeof value === "number" || typeof value === "boolean";
}

function hasFieldKind(value: unknown, kind: FieldKind): boolean {
  switch (kind) {
    case "scalar":
      return isScalar(value);
    case "string":
      return typeof value === "string";
    case "number":
      return typeof value === "number" && Number.isFinite(value);
    case "boolean":
      return typeof value === "boolean";
    default: {
      const exhaustive: never = kind;
      throw new Error(`unhandled field kind ${String(exhaustive)}`);
    }
  }
}

/** A list whose entries are strings; entries of any other type are dropped. */
function stringList(value: unknown): string[] | undefined {
  return Array.isArray(value) ? value.filter((entry): entry is string => typeof entry === "string") : undefined;
}

/** An object whose values are scalars (an environment map); nested values are dropped. */
function scalarMap(value: unknown): JsonRecord | undefined {
  const object = asObject(value);
  return object ? Object.fromEntries(Object.entries(object).filter(([, entry]) => isScalar(entry))) : undefined;
}

/** A list of records projected one by one; entries that are not objects are dropped. */
function listOf(spec: FieldSpec): (value: unknown) => JsonRecord[] | undefined {
  return (value) => (Array.isArray(value) ? value.filter((entry) => asObject(entry) !== undefined).map((entry) => pickTyped(entry, spec)) : undefined);
}

/**
 * Projects the documented fields of a record in their documented types. A body that parsed to a primitive or
 * an array is not the documented object: it projects to nothing rather than reaching the `in` operator, whose
 * TypeError message would quote the value. A documented key whose value is not of its documented type (a
 * nested object or array where a scalar is documented, a string where a number is) is dropped rather than
 * copied verbatim, so an undocumented shape under a documented key never travels into the access check, a
 * finding, or the bundle (round 4 item E).
 */
function pickTyped(item: unknown, spec: FieldSpec): JsonRecord {
  const projected: JsonRecord = {};
  const object = asObject(item);
  if (!object) return projected;
  for (const [key, rule] of Object.entries(spec)) {
    if (!(key in object)) continue;
    const value = object[key];
    if (value === null) {
      projected[key] = null;
    } else if (typeof rule === "function") {
      const kept = rule(value);
      if (kept !== undefined) projected[key] = kept;
    } else if (hasFieldKind(value, rule)) {
      projected[key] = value;
    }
  }
  return projected;
}

/** Projects the documented fields of a record, each of which is a scalar (an id, a name, a flag, a timestamp, or null). */
function pick(item: unknown, keys: readonly string[]): JsonRecord {
  return pickTyped(item, Object.fromEntries(keys.map((key) => [key, "scalar" as const])));
}

function redactField(item: JsonRecord, key: string, redact: (value: unknown) => unknown = redactedOr): JsonRecord {
  return key in item ? { [key]: redact(item[key]) } : {};
}

function pickSummary(item: JsonRecord, field: string, keys: readonly string[]): JsonRecord | undefined {
  const entry = asObject(summaryFields(item)[field]);
  return entry ? pick(entry, keys) : undefined;
}

function pickSummaryList(item: JsonRecord, field: string, keys: readonly string[]): JsonRecord[] | undefined {
  const entries = summaryFields(item)[field];
  if (!Array.isArray(entries)) return undefined;
  return entries
    .map((entry) => asObject(entry))
    .filter((entry): entry is JsonRecord => Boolean(entry))
    .map((entry) => pick(entry, keys));
}

const USER_FIELDS: FieldSpec = Object.freeze({ id: "number", username: "string", is_superuser: "boolean", is_system_auditor: "boolean", external_account: "string", last_login: "string", created: "string", modified: "string" });
const PING_INSTANCE_FIELDS: FieldSpec = Object.freeze({ node: "string", node_type: "string", uuid: "string", heartbeat: "string", capacity: "number", version: "string" });
const PING_INSTANCE_GROUP_FIELDS: FieldSpec = Object.freeze({ name: "string", capacity: "number", instances: stringList });
const PING_FIELDS: FieldSpec = Object.freeze({ version: "string", active_node: "string", ha: "boolean", instances: listOf(PING_INSTANCE_FIELDS), instance_groups: listOf(PING_INSTANCE_GROUP_FIELDS) });
const JOB_FIELDS = ["id", "type", "name", "status", "failed", "launch_type", "started", "finished", "elapsed", "job_template", "unified_job_template", "inventory", "project", "playbook", "created"];
const TEMPLATE_FIELDS = ["id", "type", "name", "description", "playbook", "project", "inventory", "status", "last_job_run", "last_job_failed", "execution_environment", "survey_enabled", "ask_variables_on_launch", "ask_credential_on_launch", "ask_execution_environment_on_launch", "created", "modified"];
const SCHEDULE_FIELDS = ["id", "name", "unified_job_template", "enabled", "rrule", "next_run", "dtstart", "dtend", "created", "modified"];
const HOST_FIELDS = ["id", "name", "enabled", "inventory", "last_job", "last_job_host_summary", "has_active_failures", "has_inventory_sources", "created", "modified"];
const INVENTORY_SOURCE_FIELDS = ["id", "name", "source", "source_path", "inventory", "status", "last_updated", "last_update_failed", "last_job_run", "last_job_failed", "update_on_launch", "created", "modified"];
const INVENTORY_FIELDS = ["id", "name", "kind", "organization", "total_hosts", "hosts_with_active_failures", "total_groups", "has_inventory_sources", "total_inventory_sources", "inventory_sources_with_failures", "has_active_failures", "created", "modified"];
const GROUP_FIELDS = ["id", "name", "inventory", "created", "modified"];
const PROJECT_FIELDS = ["id", "name", "scm_type", "scm_branch", "scm_refspec", "scm_update_on_launch", "status", "last_updated", "last_update_failed", "last_job_run", "last_job_failed", "organization", "created", "modified"];
const CREDENTIAL_FIELDS = ["id", "name", "kind", "credential_type", "managed", "organization", "created", "modified"];
const TOKEN_FIELDS = ["id", "user", "application", "scope", "description", "created", "modified", "expires", "last_used"];
const ACTIVITY_FIELDS = ["id", "timestamp", "operation", "object1", "object2", "object_association"];
const NOTIFICATION_TEMPLATE_FIELDS = ["id", "name", "description", "notification_type", "organization", "created", "modified"];
const NOTIFICATION_FIELDS = ["id", "status", "notification_type", "notification_template", "notifications_sent", "created"];
const ORGANIZATION_FIELDS = ["id", "name", "description", "max_hosts", "created", "modified"];
const TEAM_FIELDS = ["id", "name", "description", "organization", "created", "modified"];
const ROLE_FIELDS = ["id", "name", "description"];
const INSTANCE_GROUP_FIELDS = ["id", "name", "max_concurrent_jobs", "max_forks", "is_container_group", "capacity", "consumed_capacity", "instances", "created", "modified"];
const JOB_HOST_SUMMARY_FIELDS = ["id", "job", "host", "host_name", "failed", "changed", "ok", "failures", "skipped", "unreachable", "created"];
const EXECUTION_ENVIRONMENT_FIELDS = ["id", "name", "description", "image", "pull", "organization", "credential", "managed", "created", "modified"];
const SURVEY_QUESTION_FIELDS = ["variable", "type", "required", "question_name", "min", "max"];
const JOB_SETTING_FIELDS: FieldSpec = Object.freeze({ SCHEDULE_MAX_JOBS: "number", MAX_FORKS: "number", DEFAULT_JOB_TIMEOUT: "number", DEFAULT_INVENTORY_UPDATE_TIMEOUT: "number", DEFAULT_PROJECT_UPDATE_TIMEOUT: "number", AD_HOC_COMMANDS: stringList, AWX_TASK_ENV: scalarMap, GALAXY_TASK_ENV: scalarMap });
const SUMMARY_CREDENTIAL_FIELDS = ["id", "name", "kind", "credential_type_id"];

/** The documented user fields in their documented types; anything else under those keys is dropped. */
export function projectUser(user: JsonRecord): JsonRecord {
  return pickTyped(user, USER_FIELDS);
}

function projectJob(job: JsonRecord): JsonRecord {
  return {
    ...pick(job, JOB_FIELDS),
    ...redactField(job, "extra_vars", redactVariables),
    summary_fields: { credentials: pickSummaryList(job, "credentials", SUMMARY_CREDENTIAL_FIELDS) },
  };
}

function projectTemplate(template: JsonRecord): JsonRecord {
  return {
    ...pick(template, TEMPLATE_FIELDS),
    ...redactField(template, "extra_vars", redactVariables),
    summary_fields: {
      credentials: pickSummaryList(template, "credentials", SUMMARY_CREDENTIAL_FIELDS),
      last_job: pickSummary(template, "last_job", ["id", "name", "status", "finished", "failed"]),
    },
  };
}

function projectSchedule(schedule: JsonRecord): JsonRecord {
  return { ...pick(schedule, SCHEDULE_FIELDS), ...redactField(schedule, "extra_data", redactVariables) };
}

function projectHost(host: JsonRecord): JsonRecord {
  return {
    ...pick(host, HOST_FIELDS),
    ...redactField(host, "variables", redactVariables),
    summary_fields: {
      last_job: pickSummary(host, "last_job", ["id", "name", "status", "finished", "failed"]),
      inventory: pickSummary(host, "inventory", ["id", "name"]),
    },
  };
}

function projectInventorySource(source: JsonRecord): JsonRecord {
  return { ...pick(source, INVENTORY_SOURCE_FIELDS), ...redactField(source, "source_vars", redactVariables) };
}

function projectInventory(item: JsonRecord): JsonRecord {
  return { ...pick(item, INVENTORY_FIELDS), ...redactField(item, "variables", redactVariables) };
}

function projectGroup(group: JsonRecord): JsonRecord {
  return { ...pick(group, GROUP_FIELDS), ...redactField(group, "variables", redactVariables) };
}

function projectProject(project: JsonRecord): JsonRecord {
  return { ...pick(project, PROJECT_FIELDS), ...redactField(project, "scm_url", sanitizeScmUrl) };
}

function projectCredential(credential: JsonRecord): JsonRecord {
  return {
    ...pick(credential, CREDENTIAL_FIELDS),
    ...redactField(credential, "inputs", (value) => redactCredentialTree(value, true)),
    summary_fields: {
      credential_type: pickSummary(credential, "credential_type", ["id", "name", "kind"]),
      owners: pickSummaryList(credential, "owners", ["id", "type", "name"]),
    },
  };
}

function projectToken(token: JsonRecord): JsonRecord {
  return { ...pick(token, TOKEN_FIELDS), ...redactField(token, "token"), ...redactField(token, "refresh_token") };
}

function projectActivity(entry: JsonRecord): JsonRecord {
  return {
    ...pick(entry, ACTIVITY_FIELDS),
    ...redactField(entry, "changes", redactVariables),
    summary_fields: { actor: pickSummary(entry, "actor", ["id", "username"]) },
  };
}

/**
 * Notification configurations mix vendor-masked passwords with raw webhook
 * URLs and header maps, so every value is redacted: URL keys keep scheme and
 * host, header maps keep their names, and everything else keeps the key only.
 */
function projectNotificationConfiguration(value: unknown): unknown {
  const configuration = asObject(value);
  if (!configuration) return redactedOr(value);
  const output: JsonRecord = {};
  for (const [key, entry] of Object.entries(configuration)) {
    const normalized = normalizeKeyName(key);
    if (normalized.endsWith("headers")) {
      output[key] = redactCredentialTree(entry, true);
    } else if (URL_KEY_PATTERN.test(normalized)) {
      output[key] = typeof entry === "string" && entry.length > 0 ? urlOrigin(entry, false) ?? ANSIBLE_REDACTION_MARKER : redactedOr(entry);
    } else {
      output[key] = redactedOr(entry);
    }
  }
  return output;
}

function projectNotificationTemplate(template: JsonRecord): JsonRecord {
  return {
    ...pick(template, NOTIFICATION_TEMPLATE_FIELDS),
    ...redactField(template, "notification_configuration", projectNotificationConfiguration),
  };
}

function projectNotification(notification: JsonRecord): JsonRecord {
  return pick(notification, NOTIFICATION_FIELDS);
}

function projectRole(role: JsonRecord): JsonRecord {
  return {
    ...pick(role, ROLE_FIELDS),
    summary_fields: pick(summaryFields(role), ["resource_type", "resource_type_display_name", "resource_name", "resource_id"]),
  };
}

function projectSurveySpec(spec: JsonRecord | undefined): JsonRecord | undefined {
  if (!spec) return spec;
  const questions = Array.isArray(spec.spec) ? spec.spec : [];
  return {
    ...pick(spec, ["name", "description"]),
    spec: questions
      .map((raw) => asObject(raw))
      .filter((question): question is JsonRecord => Boolean(question))
      .map((question) => ({ ...pick(question, SURVEY_QUESTION_FIELDS), ...redactField(question, "default") })),
  };
}

function projectJobSettings(settings: JsonRecord | undefined): JsonRecord | undefined {
  return settings ? redactCredentialTree(pickTyped(settings, JOB_SETTING_FIELDS)) as JsonRecord : settings;
}

function projectSettings(settings: JsonRecord | undefined): JsonRecord | undefined {
  return settings ? redactCredentialTree(settings) as JsonRecord : settings;
}

/**
 * The ping document's documented fields in their documented types (`version`, `active_node` strings, `ha` a
 * boolean, `instances` and `instance_groups` lists of records projected the same way); a body that is not a
 * JSON object (a string, number, or array) is not a ping and is dropped, and so is a nested value under one
 * of those keys.
 */
export function projectPing(ping: unknown): JsonRecord | undefined {
  const object = asObject(ping);
  return object ? pickTyped(object, PING_FIELDS) : undefined;
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
    registerConfiguredSecrets(config.token, config.password);
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
    const loginPath = requestPath(loginUrl);
    // Login responses are described by status only: their bodies are HTML pages that echo form values.
    const initial = await this.fetchWithTimeout(loginUrl, {
      method: "GET",
      headers: { accept: "text/html,application/json" },
    }).catch((error: unknown) => {
      throw new AnsibleApiError(`AAP login bootstrap failed (network error: ${errorMessage(error)}).`, undefined, loginPath);
    });
    if (!initial.ok) {
      throw new AnsibleApiError(`AAP login bootstrap failed (${initial.status} ${initial.statusText}).`, initial.status, loginPath);
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
    }).catch((error: unknown) => {
      throw new AnsibleApiError(`AAP session login failed (network error: ${errorMessage(error)}).`, undefined, loginPath);
    });

    if (!response.ok) {
      throw new AnsibleApiError(`AAP session login failed (${response.status} ${response.statusText}).`, response.status, loginPath);
    }

    const loginCookie = cookieHeaderFromHeaders(response.headers);
    this.sessionCookie = [bootstrapCookie, loginCookie].filter(Boolean).join("; ");
    this.csrfToken = csrfTokenFromCookie(this.sessionCookie) ?? csrfToken;
    this.sessionExpiresAt = Date.now() + 60 * 60 * 1000;
    // The session cookie and CSRF token are credentials for the rest of the run; scrub them from every
    // error string the way the configured token and password are.
    registerConfiguredSecrets(bootstrapCookie, loginCookie, this.csrfToken);
  }

  /**
   * Every failure of a GET surfaces as an AnsibleApiError that names the target, the observed status,
   * and only AAP's documented `detail`/`error` field; non-JSON bodies (2xx included) become a
   * status-and-length note and transport failures carry the transport message, all scrubbed.
   */
  async get<T = unknown>(pathOrUrl: string): Promise<T> {
    // The same-origin rule sits in front of the transport (and of the session login), so no target that left the
    // configured base can be fetched with the token or session cookie, whichever path handed it in. The error
    // names neither the target nor its path.
    if (nextLinkRefusal(pathOrUrl, this.config.baseUrl)) {
      throw new AnsibleApiError(REQUEST_REFUSED_NOTE, undefined, REFUSED_ENDPOINT);
    }
    await this.ensureSession();
    const headers: Record<string, string> = { accept: "application/json" };
    if (this.config.token) {
      headers.authorization = `Bearer ${this.config.token}`;
    } else {
      if (this.sessionCookie) headers.cookie = this.sessionCookie;
      if (this.csrfToken) headers["x-csrftoken"] = this.csrfToken;
    }

    const url = this.resolveUrl(pathOrUrl);
    const endpoint = requestPath(url);
    const response = await this.fetchWithTimeout(url, { method: "GET", headers }).catch((error: unknown) => {
      throw new AnsibleApiError(`AAP request failed: ${pathOrUrl} (network error: ${errorMessage(error)})`, undefined, endpoint);
    });
    const contentType = response.headers.get("content-type");
    const text = await response.text();
    if (!response.ok) {
      throw new AnsibleApiError(`AAP request failed: ${pathOrUrl} (${response.status} ${response.statusText})${responseDetail(text, contentType)}`, response.status, endpoint);
    }

    if (text.length === 0) return undefined as T;
    try {
      return JSON.parse(text) as T;
    } catch {
      throw new AnsibleApiError(`AAP request failed: ${pathOrUrl} (${response.status} ${response.statusText}): ${describeNonJsonBody(contentType, text)}`, response.status, endpoint);
    }
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
    let dropped = 0;
    let stalled: string | undefined;

    while (next && items.length < limit) {
      const page: AapListResponse<JsonRecord> | JsonRecord[] = await this.get<AapListResponse<JsonRecord> | JsonRecord[]>(next);
      const results = Array.isArray(page) ? page : page.results ?? [];
      if (!Array.isArray(page) && typeof page.count === "number") total = page.count;
      const remaining = limit - items.length;
      if (results.length > remaining) dropped += results.length - remaining;
      items.push(...results.slice(0, remaining));
      const following: string | null = Array.isArray(page) ? null : typeof page.next === "string" ? page.next : null;
      // A next link that leaves the configured origin is refused here, before get() would attach the credential
      // to it; the collection records the refusal as its truncation reason and the link itself is never recorded.
      const refusal = following ? nextLinkRefusal(following, this.config.baseUrl) : undefined;
      if (refusal) {
        stalled = NEXT_LINK_REFUSAL_NOTES[refusal];
        break;
      }
      if (following && following === next) {
        stalled = "the API repeated the same next page link, so the walk was stopped";
        break;
      }
      if (following && results.length === 0) {
        stalled = "the API returned an empty page while advertising a next page, so the walk was stopped";
        break;
      }
      next = following;
    }

    if (stalled) {
      return { items, complete: false, total, truncation: stalled };
    }
    if (next || dropped > 0) {
      return {
        items,
        complete: false,
        total,
        truncation: dropped > 0 && !next
          ? `stopped at the requested limit of ${limit}; ${dropped} items on the last page were not collected`
          : `stopped at the requested limit of ${limit} with a next page still available`,
      };
    }
    if (total !== undefined && items.length < total) {
      return {
        items,
        complete: false,
        total,
        truncation: `the API reported ${total} items but only ${items.length} were returned across every page`,
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

  async count(path: string): Promise<number | undefined> {
    const page = await this.get<AapListResponse<unknown>>(appendQuery(path, { page_size: 1 }));
    return typeof page.count === "number" ? page.count : undefined;
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

/**
 * A parser's message quotes the text it could not parse (V8: `Unexpected token '<', "<html>..." is not valid
 * JSON`), so a SyntaxError from any parse of a body or document is recorded by name only. Every JSON.parse in
 * this file already substitutes the status-and-length note in its own catch; this keeps the property even
 * for a parse failure that escapes one.
 */
function isParseError(error: unknown): boolean {
  return error instanceof SyntaxError || (typeof error === "object" && error !== null && (error as { name?: unknown }).name === "SyntaxError");
}

const PARSE_ERROR_NOTE = "SyntaxError: response could not be parsed as JSON; the parser's message is not recorded because it quotes the body";

/** The single conversion from a thrown error to recorded text; every message passes through redactErrorText here. */
function errorMessage(error: unknown): string {
  if (isParseError(error)) return PARSE_ERROR_NOTE;
  return redactErrorText(error instanceof Error ? error.message : String(error));
}

/** HTTP status a failed read observed, or null when the failure was not an HTTP response. */
function errorStatus(error: unknown): number | null {
  return asNumber(asObject(error)?.status) ?? null;
}

/** Path a failed read requested when the error records one. */
function errorEndpoint(error: unknown): string | undefined {
  return asString(asObject(error)?.endpoint);
}

/**
 * In-memory placeholder for a collection whose read failed. It is never written to the bundle
 * (the core_data writer substitutes a not-collected marker) and every consumer checks the
 * snapshot's readable state before counting its items.
 */
function uncollected(): AnsibleCollection {
  return { items: [], complete: false, total: undefined, truncation: "not collected: the read failed" };
}

/** Failure fields of a snapshot: the scrubbed error, the observed status, and the path requested. */
function failedSnapshot(label: string, path: string, error: unknown): Pick<Snapshot<unknown>, "error" | "status" | "endpoint"> {
  return { error: `${label} (${path}): ${errorMessage(error)}`, status: errorStatus(error), endpoint: errorEndpoint(error) ?? requestPath(path) };
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
    return { data: uncollected(), ...failedSnapshot(label, path, error) };
  }
}

async function fetchObject(client: AnsibleClientSurface, label: string, path: string): Promise<Snapshot<JsonRecord | undefined>> {
  if (typeof client.get !== "function") {
    return { data: undefined, error: `${label} (${path}): client does not support object reads`, status: null, endpoint: requestPath(path) };
  }
  try {
    return { data: asObject(await client.get(path)) };
  } catch (error) {
    return { data: undefined, ...failedSnapshot(label, path, error) };
  }
}

interface InventoryView {
  label: string;
  items: JsonRecord[];
  error?: string;
  /** HTTP status the failed read observed; null for a non-HTTP failure; absent when the read succeeded. */
  status?: number | null;
  /** Path the failed read requested; absent when the read succeeded. */
  endpoint?: string;
  readable: boolean;
  empty: boolean;
  /** Items seen; null when the read failed, so an unreadable inventory never renders as zero. */
  seen: number | null;
  /** Server-reported total; null when the read failed, undefined when the server reported none. */
  total: number | null | undefined;
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
    items: readable ? collection.items : [],
    error: snapshot.error,
    status: readable ? undefined : snapshot.status ?? null,
    endpoint: readable ? undefined : snapshot.endpoint,
    readable,
    empty: readable && collection.items.length === 0,
    seen: readable ? collection.items.length : null,
    total: readable ? collection.total : null,
    partial,
  };
}

/** Renders a value derived from an inventory only when that inventory was read; null otherwise. */
function ifReadable<T>(view: InventoryView, value: () => T): T | null {
  return view.readable ? value() : null;
}

export interface AnsibleScope {
  username?: string;
  superuser?: boolean;
  systemAuditor?: boolean;
  /** Whether the audit account sees every object; null when the current user could not be read. */
  fullVisibility: boolean | null;
  note?: string;
}

/**
 * The current user from a `/api/v2/me/` body: the first entry of `results` (AAP) or the object itself, projected
 * to its documented fields in their documented types. A body without a string `username` or a numeric `id`
 * after projection is not a recognizable user and yields none.
 */
export function currentUserFromMe(value: unknown): JsonRecord | undefined {
  const object = asObject(value);
  if (!object) return undefined;
  const candidate = Array.isArray(object.results) ? asObject(object.results[0]) : object;
  if (!candidate) return undefined;
  const user = projectUser(candidate);
  return typeof user.username === "string" || typeof user.id === "number" ? user : undefined;
}

async function probeScope(client: AnsibleClientSurface): Promise<Snapshot<AnsibleScope>> {
  const me = await fetchObject(client, "current user", "/api/v2/me/");
  const user = currentUserFromMe(me.data);
  if (me.error || !user) {
    return {
      data: { fullVisibility: null, note: "current user could not be read, so the visibility of the audit account is unknown" },
      error: me.error ?? "current user (/api/v2/me/): no user returned",
      status: me.error ? me.status ?? null : null,
      endpoint: me.endpoint ?? "/api/v2/me/",
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
  return [
    ...scopeNotes(scope),
    ...views
      .map((view) => (view.readable ? view.partial : `${view.label}: unreadable (${view.error ?? "unknown error"})`))
      .filter((note): note is string => Boolean(note)),
  ];
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
      ? `${summary} Downgraded from pass to warn because the inventory is partial or unreadable: ${partialView.join("; ")}.`
      : summary,
    evidence: partialView.length > 0 ? { ...(evidence ?? {}), partial_view: partialView } : evidence,
    mappings: mappingsFor(definition),
  };
}

/** The read that failed, as evidence: the scrubbed error, the observed status, and the path requested; never a count. */
function unreadableEvidence(view: { error?: string; status?: number | null; endpoint?: string }): JsonRecord {
  return { error: view.error ?? null, http_status: view.status ?? null, endpoint: view.endpoint ?? null };
}

function manualForUnreadable(controlNumber: number, view: InventoryView | { label: string; error?: string; status?: number | null; endpoint?: string }, evidenceToCollect: string): AnsibleFinding {
  return finding(
    controlNumber,
    "manual",
    `${view.label} could not be read (${view.error ?? "unknown error"}), so this control cannot be verified from the API. Collect this evidence manually: ${evidenceToCollect}`,
    unreadableEvidence(view),
  );
}

/** Object-dataset snapshots (settings, survey specs) as the view manualForUnreadable expects. */
function objectView(label: string, snapshot: Snapshot<JsonRecord | undefined>): { label: string; error?: string; status?: number | null; endpoint?: string } {
  return { label, error: snapshot.error ?? "no settings object returned", status: snapshot.status ?? null, endpoint: snapshot.endpoint };
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
      endpoint: errorEndpoint(error) ?? endpoint,
      status: "not_readable",
      count: null,
      http_status: errorStatus(error),
      error: errorMessage(error),
    };
  }
}

export async function checkAnsibleAccess(client: AnsibleAapClient): Promise<AnsibleAccessCheckResult> {
  const me = await client.get("/api/v2/me/");
  const currentUser = currentUserFromMe(me);
  const ping = await client.get<unknown>("/api/v2/ping/").catch(() => undefined);

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
    currentUser: currentUser ? projectUser(currentUser) : undefined,
    ping: projectPing(ping),
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
    findings.push(manualForUnreadable(28, objectView("job settings", data.jobSettings), "Settings > Jobs (Maximum Scheduled Jobs, Maximum Forks) and each instance group's Max concurrent jobs and Max forks values"));
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
      jobs_total_reported: jobs.total ?? null,
      successful: ifReadable(jobs, () => jobs.items.filter((job) => isSuccessStatus(job.status)).length),
      failed: ifReadable(jobs, () => jobs.items.filter((job) => isFailureStatus(job.status)).length),
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
    const disabledRate = (disabled.length / hosts.items.length) * 100;
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
    const templatesUnreadableNote = templates.readable
      ? undefined
      : `the job templates list could not be read (${templates.error}), so last-run ages were not checked`;
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
        unknown.push({ ...entry, reason: templates.readable ? "owning template not in the sampled templates" : `owning template unknown: the job templates list could not be read (${templates.error})` });
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
      missed.length > 0 ? "fail" : unknown.length > 0 || templatesUnreadableNote ? "warn" : "pass",
      missed.length > 0
        ? `${missed.length}/${enabled.length} enabled schedules have a past or null next_run, or a last run older than ${MISSED_RUN_MULTIPLIER}x their interval.`
        : unknown.length > 0 || templatesUnreadableNote
          ? `No enabled schedule missed its window, but ${unknown.length}/${enabled.length} could not be fully evaluated (unparsed rrule, never-run or unsampled template)${templatesUnreadableNote ? `; ${templatesUnreadableNote}` : ""}.`
          : `All ${enabled.length} enabled schedules have a future next_run and a last run within ${MISSED_RUN_MULTIPLIER}x their interval.`,
      { enabled: enabled.length, missed: missed.slice(0, 10), unknown: unknown.slice(0, 10), job_templates_readable: templates.readable },
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
      hosts_total_reported: hosts.total ?? null,
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

export interface ProbeCoverage {
  /** Templates that qualified for the probe; null when the job templates list could not be read. */
  eligible: number | null;
  probed: number;
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
  probeCoverage?: {
    surveyTemplates: ProbeCoverage;
    criticalTemplates: ProbeCoverage;
  };
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
  // Labelled "credential records" rather than "credentials": the label opens the "<label>: <count> of <total> seen" and
  // "<label>: unreadable (...)" notes, and a value after a credential-named key is removed whatever its shape.
  const credentials = await collect(client, "credential records", "/api/v2/credentials/", {}, 500);
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
  let surveyTemplates = 0;
  let criticalTemplates = 0;
  for (const template of jobTemplates.data.items) {
    const id = asString(template.id);
    if (!id) continue;
    if (asBoolean(template.survey_enabled) === true) {
      surveyTemplates += 1;
      if (Object.keys(surveySpecs).length < DEFAULT_TEMPLATE_PROBE_LIMIT) {
        surveySpecs[id] = await fetchObject(client, `job template ${nameOf(template)} survey spec`, `/api/v2/job_templates/${id}/survey_spec/`);
      }
    }
    const isCritical = CRITICAL_TEMPLATE_PATTERN.test([template.name, template.playbook, template.description].map((value) => extractText(value)).join(" "));
    if (isCritical) {
      criticalTemplates += 1;
      if (Object.keys(templateErrorNotifications).length < DEFAULT_TEMPLATE_PROBE_LIMIT) {
        templateErrorNotifications[id] = await collect(client, `job template ${nameOf(template)} error notifications`, `/api/v2/job_templates/${id}/notification_templates_error/`, {}, 50);
      }
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
    probeCoverage: {
      surveyTemplates: { eligible: jobTemplates.error ? null : surveyTemplates, probed: Object.keys(surveySpecs).length },
      criticalTemplates: { eligible: jobTemplates.error ? null : criticalTemplates, probed: Object.keys(templateErrorNotifications).length },
    },
  };
}

function probeNote(label: string, coverage: ProbeCoverage | undefined): string | undefined {
  return coverage && coverage.eligible !== null && coverage.eligible > coverage.probed ? `${label}: ${coverage.probed} of ${coverage.eligible} probed` : undefined;
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
  const credentials = inventory("credential records", data.credentials);
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
      : ` Vault credential usage could not be read (${credentials.error}), so encrypted variable coverage was not checked.`;
    const launchNote = launchTimeVariableTemplates.length > 0
      ? ` ${launchTimeVariableTemplates.length} templates set ask_variables_on_launch; launch-time extra_vars are not scanned.`
      : "";
    const surveyProbeNote = probeNote("survey specs", data.probeCoverage?.surveyTemplates);
    findings.push(finding(
      18,
      hits.length > 0 ? "fail" : surveysUnreadable > 0 || variableSources.length > 0 ? "manual" : credentials.readable ? "pass" : "warn",
      hits.length > 0
        ? `${hits.length} templates, surveys, inventories, or groups carry plaintext values under secret-like variable names.${vaultNote}${launchNote}`
        : surveysUnreadable > 0 || variableSources.length > 0
          ? `No plaintext secret pattern matched, but ${surveysUnreadable} survey specs and ${variableSources.length} variable sources (${variableSources.map((view) => view.label).join(", ") || "none"}) could not be read; review them manually.${vaultNote}${launchNote}`
          : `No plaintext secret pattern matched across ${templates.seen} templates, ${Object.keys(data.surveySpecs).length} surveys, ${inventories.seen} inventories, and ${groups.seen} groups. Host variables are not scanned.${vaultNote}${launchNote}`,
      {
        hits: hits.slice(0, 20),
        surveys_scanned: Object.keys(data.surveySpecs).length,
        survey_templates_eligible: data.probeCoverage?.surveyTemplates.eligible ?? Object.keys(data.surveySpecs).length,
        surveys_unreadable: surveysUnreadable,
        inventories: inventories.seen,
        groups: groups.seen,
        ask_variables_on_launch_templates: launchTimeVariableTemplates.length,
        vault_credentials: ifReadable(credentials, () => vaultCredentials.map((credential) => ({ name: nameOf(credential), vault_id: vaultId(credential) ?? null }))),
      },
      [...partialNotes(data.scope, templates, inventories, groups), ...(surveyProbeNote ? [surveyProbeNote] : [])],
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
        // The organization stays in the list with its count null, so a denied admins read never
        // shrinks the inventory or reads as zero admins.
        counts.push({ id: org.id, name: nameOf(org), admin_count: null, complete: null, ...unreadableEvidence(snapshot ?? { error: "admins list was not read" }) });
        continue;
      }
      counts.push({ id: org.id, name: nameOf(org), admin_count: snapshot.data.items.length, complete: snapshot.data.complete });
    }
    const excessive = counts.filter((org) => (asNumber(org.admin_count) ?? 0) > maxOrgAdmins);
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
  const roleProbeNote = users.seen !== null && users.seen > probedUserIds.length ? `user roles: ${probedUserIds.length} of ${users.seen} users probed` : undefined;
  if (!teams.readable) {
    findings.push(manualForUnreadable(22, teams, "each team's Roles tab"));
  } else if (teams.empty) {
    findings.push(finding(22, "manual", "No teams were visible. Empty inventory is treated as manual for this control: confirm whether access is granted directly to users instead of teams, and review the Access tab of each organization.", { teams: 0 }));
  } else {
    const orgAdminTeams: JsonRecord[] = [];
    const inventoryAdminTeams: JsonRecord[] = [];
    const unreadable: string[] = [];
    const totalInventories = inventories.readable && typeof inventories.total === "number" ? inventories.total : undefined;
    const inventoryScopeNote = inventories.readable
      ? undefined
      : `the inventories list could not be read (${inventories.error}), so inventory-wide Admin roles were not checked`;
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
      orgAdminTeams.length + inventoryAdminTeams.length > 0 ? "fail" : unreadable.length > 0 ? "manual" : inventoryScopeNote ? "warn" : "pass",
      orgAdminTeams.length + inventoryAdminTeams.length > 0
        ? `${orgAdminTeams.length} teams hold the Admin role on an organization and ${inventoryAdminTeams.length} hold Admin on every visible inventory.`
        : unreadable.length > 0
          ? `No team holds organization-wide or inventory-wide Admin, but the roles of ${unreadable.length} teams could not be read; review them manually.`
          : inventoryScopeNote
            ? `None of the ${teams.seen} teams holds the Admin role on an organization, but ${inventoryScopeNote}.`
            : `None of the ${teams.seen} teams holds the Admin role on an organization or on every inventory.`,
      { org_admin_teams: orgAdminTeams, inventory_admin_teams: inventoryAdminTeams, unreadable, total_inventories: totalInventories ?? null, inventories_readable: inventories.readable },
      partialNotes(data.scope, users, teams, inventories),
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
      const roleSnapshots = [...Object.values(data.userRoles), ...Object.values(data.teamRoles)];
      const auditedOrgs = new Set<string>();
      for (const snapshot of roleSnapshots) {
        if (snapshot.error) continue;
        for (const role of snapshot.data.items) {
          if (roleName(role) === "auditor" && roleResourceType(role) === "organization") auditedOrgs.add(extractText(summaryFields(role).resource_name, String(summaryFields(role).resource_id)));
        }
      }
      const unreadableRoleLists = roleSnapshots.filter((snapshot) => snapshot.error).length;
      // An organization can only be called uncovered when every probed role list was read: the
      // Auditor that covers it may sit in a list that was denied.
      const roleCoverageKnown = teams.readable && unreadableRoleLists === 0;
      const unconfirmed = organizations.items.filter((org) => !auditedOrgs.has(nameOf(org)));
      const uncovered = roleCoverageKnown ? unconfirmed : null;
      // A confirmed Auditor in a readable list is positive evidence whatever else was denied, so the
      // control is covered when a system auditor exists or every organization has one confirmed.
      const covered = systemAuditors.length > 0 || unconfirmed.length === 0;
      const auditorGapNote = !teams.readable
        ? `the teams list could not be read (${teams.error}), so team-held Auditor roles were not checked`
        : unreadableRoleLists > 0
          ? `${unreadableRoleLists} user or team role lists could not be read, so their Auditor roles were not checked`
          : undefined;
      const coverageSentence = roleCoverageKnown
        ? `${auditedOrgs.size} organizations have an Auditor role holder among the probed users and teams`
        : unconfirmed.length === 0
          ? `an Auditor role holder was confirmed for every one of the ${organizations.seen} organizations, but ${auditorGapNote}`
          : `an Auditor role holder was confirmed for ${auditedOrgs.size} of ${organizations.seen} organizations and coverage is unknown for ${unconfirmed.length} organizations because ${auditorGapNote}`;
      findings.push(finding(
        24,
        covered ? (auditorGapNote ? "warn" : "pass") : roleCoverageKnown ? "warn" : "manual",
        covered
          ? `${systemAuditors.length} system auditors exist and ${coverageSentence}.`
          : roleCoverageKnown
            ? `No system auditor exists and ${unconfirmed.length}/${organizations.seen} organizations have no Auditor role holder among the probed users and teams.`
            : `No system auditor exists; ${coverageSentence}. Review the Access tab of those organizations for Auditor role holders manually.`,
        {
          system_auditors: sample(systemAuditors),
          audited_organizations: [...auditedOrgs],
          uncovered: uncovered === null ? null : sample(uncovered),
          coverage_unknown_organizations: roleCoverageKnown ? 0 : unconfirmed.length,
          teams_readable: teams.readable,
          unreadable_role_lists: unreadableRoleLists,
        },
        probePartial,
      ));
    }
  }

  const authSettings = data.authSettings.data;
  if (data.authSettings.error || !authSettings) {
    findings.push(manualForUnreadable(25, objectView("authentication settings", data.authSettings), "the LDAP, SAML, or OIDC authenticator configuration (Settings > Authentication, or the platform gateway Authentication page on AAP 2.5)"));
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
  // Flags stay null (never false) while the settings object they come from was not read.
  const auditEvidence = {
    activity_stream_enabled: activityEnabled ?? null,
    system_settings_readable: !data.systemSettings.error && systemSettings !== undefined,
    log_aggregator_enabled: logAggregatorEnabled ?? null,
    log_aggregator_type: (loggingSettings ? asString(loggingSettings.LOG_AGGREGATOR_TYPE) : undefined) ?? null,
    logging_settings_readable: !data.loggingSettings.error && loggingSettings !== undefined,
  };
  const settingsGapNotes = [
    data.systemSettings.error || !systemSettings
      ? `the system settings could not be read (${data.systemSettings.error ?? "no settings object returned"}), so ACTIVITY_STREAM_ENABLED was not confirmed`
      : activityEnabled === undefined
        ? "ACTIVITY_STREAM_ENABLED is not exposed by the system settings, so it was not confirmed"
        : undefined,
    data.loggingSettings.error || !loggingSettings
      ? `the logging settings could not be read (${data.loggingSettings.error ?? "no settings object returned"}), so external log aggregation was not confirmed`
      : undefined,
  ].filter((note): note is string => Boolean(note));
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
      !latest ? "warn" : latestAge !== undefined && latestAge > 1 ? "fail" : settingsGapNotes.length > 0 ? "warn" : "pass",
      !latest
        ? "The newest activity stream record has no timestamp, so freshness cannot be confirmed."
        : `Latest activity stream record is ${latestAge?.toFixed(1)} days old${logAggregatorEnabled === false ? "; external log aggregation is disabled" : ""}${settingsGapNotes.length > 0 ? `; ${settingsGapNotes.join("; ")}` : ""}.`,
      { ...auditEvidence, visible_activity_records: activity.seen, latest_activity_age_days: latestAge, settings_gaps: settingsGapNotes },
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
    const failedNotifications = ifReadable(notifications, () => notifications.items.filter((item) => String(item.status ?? "").toLowerCase() === "failed").length);
    const deliveryNote = notifications.readable
      ? undefined
      : `the notification delivery history could not be read (${notifications.error}), so failed deliveries were not checked`;
    const deliverySentence = deliveryNote ?? `${failedNotifications} of the last ${notifications.seen} notification deliveries failed`;
    const criticalProbeNote = probeNote("critical templates", data.probeCoverage?.criticalTemplates);
    findings.push(finding(
      27,
      critical.length === 0
        ? "manual"
        : covered === 0
          ? "warn"
          : (failedNotifications ?? 0) > 0
            ? "warn"
            : unreadable > 0
              ? "manual"
              : deliveryNote
                ? "warn"
                : "pass",
      critical.length === 0
        ? templates.readable
          ? `${notificationTemplates.seen} notification templates exist but no job template matched the critical keyword list; confirm failure notifications on the templates that matter manually.`
          : `${notificationTemplates.seen} notification templates exist but the job templates list could not be read (${templates.error}), so critical templates could not be identified; confirm failure notifications on the templates that matter manually.`
        : covered === 0
          ? `${notificationTemplates.seen} notification templates exist but none of the ${critical.length} critical job templates has an error notification attached.`
          : `${covered}/${critical.length} critical job templates have an error notification attached; ${deliverySentence}${unreadable > 0 ? `; ${unreadable} template notification lists could not be read` : ""}.`,
      {
        notification_template_count: notificationTemplates.seen,
        // Critical-template counts derive from the job templates list; they stay null when that list was not read.
        critical_templates: ifReadable(templates, () => critical.length),
        critical_templates_eligible: ifReadable(templates, () => data.probeCoverage?.criticalTemplates.eligible ?? critical.length),
        covered: ifReadable(templates, () => covered),
        unreadable: ifReadable(templates, () => unreadable),
        job_templates_readable: templates.readable,
        failed_notifications: failedNotifications,
        notifications_readable: notifications.readable,
      },
      [...partialNotes(data.scope, notificationTemplates, templates, notifications), ...(criticalProbeNote ? [criticalProbeNote] : [])],
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
      external_auth: authSettings ? hasExternalAuth(authSettings) : null,
      auth_settings_readable: !data.authSettings.error && authSettings !== undefined,
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
    surface.count === undefined || surface.count === null ? "-" : String(surface.count),
    // Error strings are already scrubbed and bounded (non-JSON bodies are described, not echoed), so the
    // full text is kept rather than sliced mid-path.
    surface.error ? surface.error.replace(/\s+/g, " ") : "",
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
    "- `core_data/` contains controller REST API responses projected to the fields the findings read; variables bodies, credential inputs, tokens, notification configurations, survey defaults, activity changes, task environment values, and URL userinfo are replaced by `[REDACTED]` (variables keep their names).",
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
    "See `QUICK_REFERENCE.md` for the layout. Secrets are not written to this bundle: credential-bearing fields are redacted at export time. AAP passwords must come from `AAP_PASSWORD` and are never accepted as tool arguments.",
  ].join("\n");
}

/** What a failed read leaves in core_data: the marker, never the empty collection it fell back to in memory. */
function notCollectedMarker(snapshot: Pick<Snapshot<unknown>, "error" | "status" | "endpoint">): AnsibleNotCollectedMarker {
  return { collected: false, status: snapshot.status ?? null, endpoint: snapshot.endpoint ?? "unknown", error: snapshot.error ?? "the read failed" };
}

type CoreDataSnapshot<T> = { data: T } | AnsibleNotCollectedMarker;

/**
 * A per-item file whose parent list failed was never probed, so it carries one marker naming the
 * parent read instead of an empty record that would read as "no items had anything to report".
 */
function notAttemptedRecord(parent: Snapshot<unknown>): AnsibleNotCollectedMarker {
  return notCollectedMarker({ ...parent, error: `not attempted: the parent list could not be read (${parent.error ?? "unknown error"})` });
}

function snapshotRecord<T>(snapshots: Record<string, Snapshot<T>>, parent?: Snapshot<unknown>): JsonRecord | AnsibleNotCollectedMarker {
  if (parent?.error && Object.keys(snapshots).length === 0) return notAttemptedRecord(parent);
  return Object.fromEntries(Object.entries(snapshots).map(([key, snapshot]) => [key, snapshot.error ? notCollectedMarker(snapshot) : { data: snapshot.data }]));
}

function projectCollectionSnapshot(snapshot: Snapshot<AnsibleCollection>, project: (item: JsonRecord) => JsonRecord): CoreDataSnapshot<AnsibleCollection> {
  if (snapshot.error) return notCollectedMarker(snapshot);
  return { data: { ...snapshot.data, items: snapshot.data.items.map(project) } };
}

function projectObjectSnapshot(snapshot: Snapshot<JsonRecord | undefined>, project: (value: JsonRecord | undefined) => JsonRecord | undefined): CoreDataSnapshot<JsonRecord | undefined> {
  if (snapshot.error) return notCollectedMarker(snapshot);
  return { data: project(snapshot.data) };
}

function projectCollectionRecord(snapshots: Record<string, Snapshot<AnsibleCollection>>, project: (item: JsonRecord) => JsonRecord, parent: Snapshot<unknown>): JsonRecord | AnsibleNotCollectedMarker {
  if (parent.error && Object.keys(snapshots).length === 0) return notAttemptedRecord(parent);
  return Object.fromEntries(Object.entries(snapshots).map(([key, snapshot]) => [key, projectCollectionSnapshot(snapshot, project)]));
}

/**
 * Builds the core_data files of the bundle from the collected snapshots. Every
 * dataset is projected to the fields the verdicts read; variables bodies,
 * credential inputs, tokens, notification configurations, survey defaults,
 * activity changes, environment dictionaries, and URL userinfo are redacted so
 * no credential-bearing value reaches the bundle or its zip.
 */
export function buildAnsibleCoreDataFiles(
  access: AnsibleAccessCheckResult,
  jobHealthData: JobHealthData,
  hostCoverageData: HostCoverageData,
  platformData: PlatformSecurityData,
): Array<[string, unknown]> {
  return [
    ["core_data/access.json", { ...access, currentUser: access.currentUser ? projectUser(access.currentUser) : undefined, ping: projectPing(access.ping) }],
    ["core_data/scope.json", jobHealthData.scope],
    ["core_data/jobs.json", projectCollectionSnapshot(jobHealthData.jobs, projectJob)],
    ["core_data/job_settings.json", projectObjectSnapshot(jobHealthData.jobSettings, projectJobSettings)],
    ["core_data/instance_groups.json", projectCollectionSnapshot(jobHealthData.instanceGroups, (item) => pick(item, INSTANCE_GROUP_FIELDS))],
    ["core_data/hosts.json", projectCollectionSnapshot(hostCoverageData.hosts, projectHost)],
    ["core_data/inventory_sources.json", projectCollectionSnapshot(hostCoverageData.inventorySources, projectInventorySource)],
    ["core_data/job_host_summaries.json", projectCollectionSnapshot(hostCoverageData.hostSummaries, (item) => pick(item, JOB_HOST_SUMMARY_FIELDS))],
    ["core_data/job_templates.json", projectCollectionSnapshot(hostCoverageData.jobTemplates, projectTemplate)],
    ["core_data/schedules.json", projectCollectionSnapshot(hostCoverageData.schedules, projectSchedule)],
    ["core_data/workflow_job_templates.json", projectCollectionSnapshot(hostCoverageData.workflowTemplates, projectTemplate)],
    ["core_data/organizations.json", projectCollectionSnapshot(platformData.organizations, (item) => pick(item, ORGANIZATION_FIELDS))],
    ["core_data/organization_admins.json", projectCollectionRecord(platformData.orgAdmins, projectUser, platformData.organizations)],
    ["core_data/users.json", projectCollectionSnapshot(platformData.users, projectUser)],
    ["core_data/user_roles.json", projectCollectionRecord(platformData.userRoles, projectRole, platformData.users)],
    ["core_data/teams.json", projectCollectionSnapshot(platformData.teams, (item) => pick(item, TEAM_FIELDS))],
    ["core_data/team_roles.json", projectCollectionRecord(platformData.teamRoles, projectRole, platformData.teams)],
    ["core_data/credentials.json", projectCollectionSnapshot(platformData.credentials, projectCredential)],
    ["core_data/tokens.json", projectCollectionSnapshot(platformData.tokens, projectToken)],
    ["core_data/projects.json", projectCollectionSnapshot(platformData.projects, projectProject)],
    ["core_data/survey_specs.json", snapshotRecord(Object.fromEntries(Object.entries(platformData.surveySpecs).map(([key, snapshot]) => [key, snapshot.error ? snapshot : { data: projectSurveySpec(snapshot.data) }])), platformData.jobTemplates)],
    ["core_data/template_error_notifications.json", projectCollectionRecord(platformData.templateErrorNotifications, projectNotificationTemplate, platformData.jobTemplates)],
    ["core_data/inventories.json", projectCollectionSnapshot(platformData.inventories, projectInventory)],
    ["core_data/groups.json", projectCollectionSnapshot(platformData.groups, projectGroup)],
    ["core_data/execution_environments.json", projectCollectionSnapshot(platformData.executionEnvironments, (item) => pick(item, EXECUTION_ENVIRONMENT_FIELDS))],
    ["core_data/notification_templates.json", projectCollectionSnapshot(platformData.notificationTemplates, projectNotificationTemplate)],
    ["core_data/notifications.json", projectCollectionSnapshot(platformData.notifications, projectNotification)],
    ["core_data/activity_stream.json", projectCollectionSnapshot(platformData.activity, projectActivity)],
    ["core_data/settings_authentication.json", projectObjectSnapshot(platformData.authSettings, projectSettings)],
    ["core_data/settings_system.json", projectObjectSnapshot(platformData.systemSettings, projectSettings)],
    ["core_data/settings_logging.json", projectObjectSnapshot(platformData.loggingSettings, projectSettings)],
  ];
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

  const coreDataFiles = buildAnsibleCoreDataFiles(access, jobHealthData, hostCoverageData, platformData);
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

/**
 * Every fixed-text message this integration emits around a refused, failed, or unparseable read, rendered
 * with representative observed values by the same constants and helpers the error sink uses (GWS note 1).
 * Each must survive redactErrorText unchanged, since every recorded string passes through it; the fixed-text
 * test holds this list to the scrub, and a message that does not survive is reworded rather than exempted.
 */
export function ansibleFixedTexts(): readonly string[] {
  const html = "<html><head><title>502 Bad Gateway</title></head><body>upstream unavailable</body></html>";
  const deniedBody = JSON.stringify({ detail: "You do not have permission to perform this action." });
  const inventoriesDenied = `AAP request failed: /api/v2/inventories/ (403 Forbidden)${responseDetail(deniedBody, "application/json")}`;
  const settingsDenied = `AAP request failed: /api/v2/settings/system/ (403 Forbidden)${responseDetail(deniedBody, "application/json")}`;
  const templatesDenied = `AAP request failed: /api/v2/job_templates/ (403 Forbidden)${responseDetail(deniedBody, "application/json")}`;
  const notificationsDenied = `AAP request failed: /api/v2/notifications/ (403 Forbidden)${responseDetail(deniedBody, "application/json")}`;
  const credentialsDenied = `credential records (/api/v2/credentials/): AAP request failed: /api/v2/credentials/ (403 Forbidden)${responseDetail(deniedBody, "application/json")}`;
  const parentFailed: Snapshot<AnsibleCollection> = { data: { items: [], complete: false }, error: inventoriesDenied, status: 403, endpoint: "/api/v2/inventories/" };
  const inventories = inventory("inventories", parentFailed);
  const unknownScope: Snapshot<AnsibleScope> = { data: { fullVisibility: null, note: "current user could not be read, so the visibility of the audit account is unknown" }, error: "current user (/api/v2/me/): no user returned", status: null, endpoint: "/api/v2/me/" };
  return Object.freeze([
    PARSE_ERROR_NOTE,
    describeNonJsonBody("text/html; charset=utf-8", html),
    describeNonJsonBody(null, "upstream unavailable"),
    inventoriesDenied,
    settingsDenied,
    `AAP request failed: /api/v2/hosts/ (502 Bad Gateway)${responseDetail(html, "text/html")}`,
    `AAP request failed: /api/v2/ping/ (200 OK): ${describeNonJsonBody("text/plain", "upstream unavailable")}`,
    "AAP request failed: /api/v2/ping/ (network error: fetch failed)",
    "AAP request failed: /api/v2/ping/ (network error: This operation was aborted)",
    "AAP session login failed (network error: fetch failed).",
    "AAP session login failed (401 Unauthorized).",
    "AAP session auth requires AAP_USERNAME and AAP_PASSWORD.",
    ...partialNotes(unknownScope, inventories, inventory("hosts", { data: { items: [{}], complete: false, total: 40, truncation: "page cap reached" } })),
    ...Object.values(NEXT_LINK_REFUSAL_NOTES),
    inventory("users", { data: { items: [{}], complete: false, total: 2, truncation: NEXT_LINK_REFUSAL_NOTES.foreign_origin } }).partial ?? "",
    REQUEST_REFUSED_NOTE,
    REFUSED_ENDPOINT,
    finding(22, "pass", "No team holds the Admin role on every inventory.", undefined, partialNotes(unknownScope, inventories)).summary,
    unknownScope.error ?? "",
    manualForUnreadable(22, inventories, "the Teams list with each team's roles and the inventories each Admin role covers").summary,
    manualForUnreadable(26, { label: "activity stream", error: `AAP request failed: /api/v2/activity_stream/ (403 Forbidden)${responseDetail(deniedBody, "application/json")}`, status: 403, endpoint: "/api/v2/activity_stream/" }, "the Activity Stream page showing entries from the last 24 hours and Settings > System (Enable Activity Stream)").summary,
    notCollectedMarker({}).error,
    notCollectedMarker({}).endpoint,
    notAttemptedRecord(parentFailed).error,
    `the system settings could not be read (${settingsDenied}), so ACTIVITY_STREAM_ENABLED was not confirmed`,
    "ACTIVITY_STREAM_ENABLED is not exposed by the system settings, so it was not confirmed",
    "ACTIVITY_STREAM_ENABLED is false, so platform changes are not being recorded.",
    `the logging settings could not be read (no settings object returned), so external log aggregation was not confirmed`,
    `the inventories list could not be read (${inventoriesDenied}), so inventory-wide Admin roles were not checked`,
    `the job templates list could not be read (${templatesDenied}), so last-run ages were not checked`,
    `owning template unknown: the job templates list could not be read (${templatesDenied})`,
    `the notification delivery history could not be read (${notificationsDenied}), so failed deliveries were not checked`,
    "No notification templates exist, so job failures cannot alert anyone. An empty notification inventory is treated as fail for this control.",
    "None of the 3 teams holds the Admin role on an organization or on every inventory.",
    `Vault credential usage could not be read (${credentialsDenied}), so encrypted variable coverage was not checked.`,
    `credential records could not be read (${credentialsDenied}), so this control cannot be verified from the API. Collect this evidence manually: the Credentials list with Last Modified and the Access tab of each credential`,
    "credential records: 12 of 40 seen (page cap reached)",
    `credential records: unreadable (${credentialsDenied})`,
    "3 credentials expose no owners summary and their owner_users/owner_teams endpoints could not be read; review their Access tab manually.",
  ]);
}
