/**
 * Slack Enterprise Grid audit tools for grclanker.
 *
 * This native TypeScript surface is grounded in the slack-sec-inspector spec
 * and starts with read-only Slack Web API, SCIM, and Audit Logs checks.
 */
import {
  createWriteStream,
  existsSync,
  lstatSync,
  mkdirSync,
  realpathSync,
} from "node:fs";
import { chmod, readdir, writeFile } from "node:fs/promises";
import { dirname, join, relative, resolve } from "node:path";
import archiver from "archiver";
import { Type } from "@sinclair/typebox";
import { errorResult, formatTable, textResult } from "./shared.js";

const DEFAULT_PAGE_LIMIT = 200;
const DEFAULT_TIMEOUT_MS = 30_000;
const DEFAULT_USER_LIMIT = 1000;
const DEFAULT_WORKSPACE_LIMIT = 50;
const DEFAULT_APP_LIMIT = 500;
const DEFAULT_AUDIT_LIMIT = 200;
const DEFAULT_LOOKBACK_DAYS = 30;
const DEFAULT_OUTPUT_DIR = "./export/slack";

type FetchImpl = typeof fetch;
type JsonRecord = Record<string, unknown>;

export interface SlackConfiguration {
  token: string;
  scimToken?: string;
  orgId?: string;
  webApiBaseUrl: string;
  scimBaseUrl: string;
  auditBaseUrl: string;
  timeoutMs: number;
  sourceChain: string[];
}

interface SlackApiClientOptions {
  fetchImpl?: FetchImpl;
  now?: () => Date;
}

export interface SlackAccessSurface {
  name: string;
  api: "web" | "scim" | "audit";
  endpoint: string;
  status: "readable" | "not_readable" | "not_configured";
  count?: number;
  error?: string;
}

export interface SlackAccessCheckResult {
  status: "healthy" | "limited";
  auth?: JsonRecord;
  enterprise?: JsonRecord;
  surfaces: SlackAccessSurface[];
  notes: string[];
  recommendedNextStep: string;
}

export interface SlackFinding {
  id: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  status: "pass" | "warn" | "fail";
  summary: string;
  evidence?: JsonRecord;
  mappings: string[];
}

export interface SlackAssessmentResult {
  title: string;
  summary: JsonRecord;
  findings: SlackFinding[];
}

export interface SlackAuditBundleResult {
  outputDir: string;
  zipPath: string;
  fileCount: number;
  findingCount: number;
}

type CheckAccessArgs = {
  token?: string;
  scim_token?: string;
  org_id?: string;
  web_api_base_url?: string;
  scim_base_url?: string;
  audit_base_url?: string;
  timeout_seconds?: number;
};

type IdentityArgs = CheckAccessArgs & {
  user_limit?: number;
  skip_scim?: boolean;
};

type AdminAccessArgs = CheckAccessArgs & {
  workspace_limit?: number;
  max_workspace_admins?: number;
  max_session_hours?: number;
  max_idle_minutes?: number;
};

type IntegrationsArgs = CheckAccessArgs & {
  app_limit?: number;
};

type MonitoringArgs = CheckAccessArgs & {
  days?: number;
  audit_limit?: number;
};

type ExportAuditBundleArgs = CheckAccessArgs & {
  output_dir?: string;
  user_limit?: number;
  workspace_limit?: number;
  app_limit?: number;
  audit_limit?: number;
  days?: number;
  max_workspace_admins?: number;
  max_session_hours?: number;
  max_idle_minutes?: number;
  skip_scim?: boolean;
};

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
    if (/^(true|1|yes)$/i.test(value.trim())) return true;
    if (/^(false|0|no)$/i.test(value.trim())) return false;
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
  return parsed.toString().replace(/\/+$/, "");
}

function parseTimeoutSeconds(value: number | undefined): number {
  return clampNumber(value, DEFAULT_TIMEOUT_MS / 1000, 1, 300) * 1000;
}

export function resolveSlackConfiguration(
  input: JsonRecord = {},
  env: NodeJS.ProcessEnv = process.env,
): SlackConfiguration {
  const sourceChain: string[] = [];
  const token = asString(input.token)
    ?? asString(input.user_token)
    ?? asString(env.SLACK_USER_TOKEN)
    ?? asString(env.SLACK_TOKEN);

  if (!token) {
    throw new Error("SLACK_USER_TOKEN or a token argument is required.");
  }
  sourceChain.push(asString(input.token) || asString(input.user_token) ? "arguments-token" : "environment-token");

  const scimToken = asString(input.scim_token)
    ?? asString(input.scimToken)
    ?? asString(env.SLACK_SCIM_TOKEN);
  if (scimToken) sourceChain.push(asString(input.scim_token) || asString(input.scimToken) ? "arguments-scim" : "environment-scim");

  const orgId = asString(input.org_id)
    ?? asString(input.enterprise_id)
    ?? asString(env.SLACK_ORG_ID)
    ?? asString(env.SLACK_ENTERPRISE_ID);
  if (orgId) sourceChain.push(asString(input.org_id) || asString(input.enterprise_id) ? "arguments-org" : "environment-org");

  return {
    token,
    scimToken,
    orgId,
    webApiBaseUrl: normalizeBaseUrl(
      asString(input.web_api_base_url) ?? asString(env.SLACK_WEB_API_BASE_URL) ?? "https://slack.com/api",
    ),
    scimBaseUrl: normalizeBaseUrl(
      asString(input.scim_base_url) ?? asString(env.SLACK_SCIM_BASE_URL) ?? "https://api.slack.com/scim/v2",
    ),
    auditBaseUrl: normalizeBaseUrl(
      asString(input.audit_base_url) ?? asString(env.SLACK_AUDIT_BASE_URL) ?? "https://api.slack.com/audit/v1",
    ),
    timeoutMs: parseTimeoutSeconds(asNumber(input.timeout_seconds) ?? asNumber(env.SLACK_TIMEOUT)),
    sourceChain: [...new Set(sourceChain)],
  };
}

function appendQuery(url: URL, query: JsonRecord): URL {
  for (const [key, value] of Object.entries(query)) {
    if (value === undefined || value === null || value === "") continue;
    url.searchParams.set(key, String(value));
  }
  return url;
}

function extractArray(value: unknown, keys: string[]): JsonRecord[] {
  const object = asObject(value);
  if (!object) return [];

  for (const key of keys) {
    const nested = object[key];
    if (Array.isArray(nested)) {
      return nested.filter((item): item is JsonRecord => Boolean(asObject(item)));
    }
  }

  const resources = object.Resources;
  if (Array.isArray(resources)) {
    return resources.filter((item): item is JsonRecord => Boolean(asObject(item)));
  }

  return [];
}

function extractCount(value: unknown, keys: string[]): number {
  const object = asObject(value);
  if (!object) return 0;
  for (const key of ["totalResults", "total_results", "count", "total"]) {
    const count = asNumber(object[key]);
    if (count !== undefined) return count;
  }
  for (const key of keys) {
    const value = object[key];
    if (Array.isArray(value)) return value.length;
  }
  return extractArray(value, keys).length;
}

function extractNestedObject(value: unknown, keys: string[]): JsonRecord | undefined {
  const object = asObject(value);
  if (!object) return undefined;
  for (const key of keys) {
    const nested = asObject(object[key]);
    if (nested) return nested;
  }
  return object;
}

function extractTimestamp(value: unknown): string | undefined {
  if (typeof value === "string" && !Number.isNaN(Date.parse(value))) return value;
  if (typeof value === "number" && Number.isFinite(value)) {
    const timestamp = value > 10_000_000_000 ? value : value * 1000;
    return new Date(timestamp).toISOString();
  }
  const object = asObject(value);
  if (!object) return undefined;
  return (
    extractTimestamp(object.date_create)
    ?? extractTimestamp(object.created)
    ?? extractTimestamp(object.timestamp)
    ?? extractTimestamp(object.date)
  );
}

function daysBetween(later: Date, earlierIso?: string): number | undefined {
  if (!earlierIso) return undefined;
  const earlier = new Date(earlierIso);
  if (Number.isNaN(earlier.getTime())) return undefined;
  return (later.getTime() - earlier.getTime()) / (24 * 60 * 60 * 1000);
}

function finding(
  id: string,
  title: string,
  severity: SlackFinding["severity"],
  status: SlackFinding["status"],
  summary: string,
  mappings: string[],
  evidence?: JsonRecord,
): SlackFinding {
  return { id, title, severity, status, summary, mappings, evidence };
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
  return normalized || "slack";
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

async function nextAvailableAuditDir(root: string, preferredName: string): Promise<string> {
  ensurePrivateDir(root);
  const suffixes = ["", "-2", "-3", "-4", "-5", "-6"];
  for (const suffix of suffixes) {
    const candidate = resolveSecureOutputPath(root, `${preferredName}${suffix}`);
    if (!existsSync(candidate)) {
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
    const output = createWriteStream(zipPath, { mode: 0o600 });
    const archive = archiver("zip", { zlib: { level: 9 } });

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

export class SlackApiClient {
  private readonly fetchImpl: FetchImpl;
  private readonly now: () => Date;

  constructor(
    private readonly config: SlackConfiguration,
    options: SlackApiClientOptions = {},
  ) {
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.now = options.now ?? (() => new Date());
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

  private async fetchJson(url: URL, init: RequestInit, label: string): Promise<JsonRecord> {
    const response = await this.fetchWithTimeout(url.toString(), init);
    const text = await response.text();
    if (!response.ok) {
      throw new Error(`${label} failed (${response.status} ${response.statusText}) ${text.slice(0, 200)}`);
    }
    const json = text.length > 0 ? JSON.parse(text) as JsonRecord : {};
    if (json.ok === false) {
      throw new Error(`${label} failed: ${asString(json.error) ?? "ok=false"}`);
    }
    return json;
  }

  async web(method: string, query: JsonRecord = {}): Promise<JsonRecord> {
    const url = appendQuery(new URL(`${this.config.webApiBaseUrl}/${method}`), query);
    return this.fetchJson(url, {
      method: "GET",
      headers: {
        accept: "application/json",
        authorization: `Bearer ${this.config.token}`,
      },
    }, `Slack Web API ${method}`);
  }

  async scim(path: string, query: JsonRecord = {}): Promise<JsonRecord> {
    if (!this.config.scimToken) {
      throw new Error("SLACK_SCIM_TOKEN is required for Slack SCIM checks.");
    }
    const normalizedPath = path.startsWith("/") ? path : `/${path}`;
    const url = appendQuery(new URL(`${this.config.scimBaseUrl}${normalizedPath}`), query);
    return this.fetchJson(url, {
      method: "GET",
      headers: {
        accept: "application/scim+json,application/json",
        authorization: `Bearer ${this.config.scimToken}`,
      },
    }, `Slack SCIM ${normalizedPath}`);
  }

  async audit(path: string, query: JsonRecord = {}): Promise<JsonRecord> {
    const normalizedPath = path.startsWith("/") ? path : `/${path}`;
    const url = appendQuery(new URL(`${this.config.auditBaseUrl}${normalizedPath}`), query);
    return this.fetchJson(url, {
      method: "GET",
      headers: {
        accept: "application/json",
        authorization: `Bearer ${this.config.token}`,
      },
    }, `Slack Audit Logs ${normalizedPath}`);
  }

  async paginateWeb(
    method: string,
    itemKeys: string[],
    query: JsonRecord = {},
    options: { limit?: number; pageLimit?: number } = {},
  ): Promise<JsonRecord[]> {
    const limit = options.limit ?? Number.POSITIVE_INFINITY;
    const pageLimit = clampNumber(options.pageLimit, DEFAULT_PAGE_LIMIT, 1, 1000);
    let cursor: string | undefined;
    const items: JsonRecord[] = [];

    do {
      const page = await this.web(method, { ...query, limit: pageLimit, cursor });
      items.push(...extractArray(page, itemKeys).slice(0, limit - items.length));
      const metadata = asObject(page.response_metadata);
      cursor = asString(metadata?.next_cursor);
    } while (cursor && items.length < limit);

    return items;
  }

  async paginateScim(
    path: string,
    query: JsonRecord = {},
    options: { limit?: number; pageLimit?: number } = {},
  ): Promise<JsonRecord[]> {
    const limit = options.limit ?? Number.POSITIVE_INFINITY;
    const pageLimit = clampNumber(options.pageLimit, DEFAULT_PAGE_LIMIT, 1, 1000);
    let startIndex = asNumber(query.startIndex) ?? 1;
    const items: JsonRecord[] = [];

    while (items.length < limit) {
      const page = await this.scim(path, { ...query, startIndex, count: pageLimit });
      const resources = extractArray(page, ["Resources"]);
      items.push(...resources.slice(0, limit - items.length));
      const total = asNumber(page.totalResults) ?? resources.length;
      if (resources.length === 0 || items.length >= total) break;
      startIndex += resources.length;
    }

    return items;
  }

  getNow(): Date {
    return this.now();
  }

  getOrgQuery(): JsonRecord {
    return this.config.orgId ? { enterprise_id: this.config.orgId } : {};
  }
}

function surfaceError(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

async function webSurface(
  client: Pick<SlackApiClient, "web" | "getOrgQuery">,
  name: string,
  method: string,
  itemKeys: string[] = [],
  query: JsonRecord = {},
): Promise<SlackAccessSurface> {
  try {
    const result = await client.web(method, { ...client.getOrgQuery(), ...query, limit: 1 });
    return {
      name,
      api: "web",
      endpoint: method,
      status: "readable",
      count: itemKeys.length > 0 ? extractCount(result, itemKeys) : 1,
    };
  } catch (error) {
    return { name, api: "web", endpoint: method, status: "not_readable", error: surfaceError(error) };
  }
}

async function scimSurface(
  client: Pick<SlackApiClient, "scim">,
  name: string,
  path: string,
): Promise<SlackAccessSurface> {
  try {
    const result = await client.scim(path, path === "/ServiceProviderConfig" ? {} : { count: 1 });
    return {
      name,
      api: "scim",
      endpoint: path,
      status: "readable",
      count: path === "/ServiceProviderConfig" ? 1 : extractCount(result, ["Resources"]),
    };
  } catch (error) {
    return { name, api: "scim", endpoint: path, status: "not_readable", error: surfaceError(error) };
  }
}

async function auditSurface(
  client: Pick<SlackApiClient, "audit">,
  name: string,
  path: string,
): Promise<SlackAccessSurface> {
  try {
    const result = await client.audit(path, path === "/logs" ? { limit: 1 } : {});
    return {
      name,
      api: "audit",
      endpoint: path,
      status: "readable",
      count: extractCount(result, ["entries", "schemas", "logs"]),
    };
  } catch (error) {
    return { name, api: "audit", endpoint: path, status: "not_readable", error: surfaceError(error) };
  }
}

export async function checkSlackAccess(client: SlackApiClient): Promise<SlackAccessCheckResult> {
  const auth = await client.web("auth.test");
  const enterprise = await client.web("admin.enterprise.info", client.getOrgQuery()).catch(() => undefined);
  const surfaces = await Promise.all([
    webSurface(client, "auth", "auth.test"),
    webSurface(client, "workspaces", "admin.teams.list", ["teams"]),
    webSurface(client, "users", "users.list", ["members"]),
    webSurface(client, "admin_users", "admin.users.list", ["users"]),
    webSurface(client, "approved_apps", "admin.apps.approved.list", ["apps"]),
    webSurface(client, "restricted_apps", "admin.apps.restricted.list", ["apps"]),
    webSurface(client, "information_barriers", "admin.barriers.list", ["barriers"]),
    webSurface(client, "discovery", "discovery.enterprise.info"),
    auditSurface(client, "audit_logs", "/logs"),
    auditSurface(client, "audit_schemas", "/schemas"),
    scimSurface(client, "scim_users", "/Users"),
    scimSurface(client, "scim_groups", "/Groups"),
    scimSurface(client, "scim_config", "/ServiceProviderConfig"),
  ]);

  const readableCount = surfaces.filter((surface) => surface.status === "readable").length;
  const status = readableCount >= 7 && surfaces.some((surface) => surface.name === "audit_logs" && surface.status === "readable")
    ? "healthy"
    : "limited";
  const team = asString(auth.team) ?? asString(auth.team_id) ?? "Slack tenant";
  const notes = [
    `Authenticated to ${team}${asString(auth.user) ? ` as ${auth.user}` : ""}.`,
    `${readableCount}/${surfaces.length} Slack audit surfaces are readable.`,
    surfaces.some((surface) => surface.api === "scim" && surface.status === "readable")
      ? "SCIM checks are available."
      : "SCIM checks are not available; set SLACK_SCIM_TOKEN to enable provisioning coverage.",
  ];

  return {
    status,
    auth,
    enterprise,
    surfaces,
    notes,
    recommendedNextStep:
      status === "healthy"
        ? "Run slack_assess_identity, slack_assess_admin_access, slack_assess_integrations, and slack_assess_monitoring."
        : "Grant a read-only Enterprise Grid admin token with admin.*, auditlogs:read, users:read, team:read, and optional SCIM read access.",
  };
}

function isHumanUser(user: JsonRecord): boolean {
  return user.is_bot !== true && user.is_app_user !== true;
}

function isActiveSlackUser(user: JsonRecord): boolean {
  return isHumanUser(user) && user.deleted !== true && user.is_deleted !== true;
}

function isGuestUser(user: JsonRecord): boolean {
  return user.is_restricted === true || user.is_ultra_restricted === true || asString(user.user_type) === "guest";
}

function userEmail(user: JsonRecord): string | undefined {
  const profile = asObject(user.profile);
  return asString(user.email) ?? asString(profile?.email);
}

function scimUserEmail(user: JsonRecord): string | undefined {
  const emails = Array.isArray(user.emails) ? user.emails : [];
  const primary = emails.map(asObject).find((email) => email?.primary === true);
  return asString(user.userName) ?? asString(primary?.value);
}

export async function assessSlackIdentity(
  client: Pick<SlackApiClient, "paginateWeb" | "paginateScim" | "scim">,
  options: { userLimit?: number; skipScim?: boolean } = {},
): Promise<SlackAssessmentResult> {
  const userLimit = clampNumber(options.userLimit, DEFAULT_USER_LIMIT, 1, 20_000);
  const users = await client.paginateWeb("users.list", ["members"], {}, { limit: userLimit });
  const humans = users.filter(isHumanUser);
  const activeHumans = humans.filter(isActiveSlackUser);
  const knownMfa = activeHumans.filter((user) => typeof user.has_2fa === "boolean");
  const withoutMfa = activeHumans.filter((user) => user.has_2fa === false);
  const guests = activeHumans.filter(isGuestUser);
  const deactivated = humans.filter((user) => user.deleted === true || user.is_deleted === true);

  const scimAvailable = !options.skipScim;
  const scimConfig = scimAvailable ? await client.scim("/ServiceProviderConfig").catch(() => undefined) : undefined;
  const scimUsers = scimAvailable
    ? await client.paginateScim("/Users", {}, { limit: userLimit }).catch(() => [])
    : [];
  const deletedSlackEmails = new Set(deactivated.map(userEmail).filter((email): email is string => Boolean(email)));
  const scimActiveDeletedInSlack = scimUsers.filter((user) => {
    if (user.active === false) return false;
    const email = scimUserEmail(user);
    return Boolean(email && deletedSlackEmails.has(email));
  });
  const mfaCoverage = activeHumans.length === 0 ? 0 : (knownMfa.length / activeHumans.length) * 100;

  const findings = [
    finding(
      "SLACK-ID-01",
      "MFA enrollment",
      "critical",
      knownMfa.length === 0 ? "warn" : withoutMfa.length > 0 ? "fail" : "pass",
      knownMfa.length === 0
        ? "Slack did not expose MFA enrollment on the sampled users."
        : withoutMfa.length > 0
          ? `${withoutMfa.length}/${activeHumans.length} active human users do not show MFA enrollment.`
          : "Every sampled active human user with MFA visibility is enrolled.",
      ["FedRAMP IA-2(6)", "CMMC 3.5.3", "SOC 2 CC6.1", "CIS 16.3"],
      {
        active_human_users: activeHumans.length,
        known_mfa_users: knownMfa.length,
        mfa_visibility_rate: mfaCoverage,
        users_without_mfa: withoutMfa.slice(0, 20).map((user) => user.name ?? user.id),
      },
    ),
    finding(
      "SLACK-ID-02",
      "Guest account inventory",
      "medium",
      guests.length > 0 ? "warn" : "pass",
      guests.length > 0
        ? `${guests.length}/${activeHumans.length} active human users are guests. Verify expiration and channel scope.`
        : "No active guest users were present in the sampled user inventory.",
      ["FedRAMP AC-2(2)", "CMMC 3.1.1", "SOC 2 CC6.2", "CIS 16.7"],
      { guest_count: guests.length, sample: guests.slice(0, 20).map((user) => user.name ?? user.id) },
    ),
    finding(
      "SLACK-ID-03",
      "SCIM provisioning coverage",
      "high",
      options.skipScim ? "warn" : scimConfig && scimUsers.length > 0 ? "pass" : "fail",
      options.skipScim
        ? "SCIM checks were skipped by request."
        : scimConfig && scimUsers.length > 0
          ? `SCIM is readable and returned ${scimUsers.length} provisioned users.`
          : "SCIM user provisioning data was not readable.",
      ["FedRAMP AC-2(1)", "CMMC 3.1.1", "SOC 2 CC6.2", "ISMAP CPS.AC-2"],
      { scim_users: scimUsers.length, service_provider_config_readable: Boolean(scimConfig) },
    ),
    finding(
      "SLACK-ID-04",
      "User lifecycle alignment",
      "high",
      !scimConfig ? "warn" : scimActiveDeletedInSlack.length > 0 ? "fail" : "pass",
      !scimConfig
        ? "SCIM lifecycle alignment could not be tested because SCIM was unreadable."
        : scimActiveDeletedInSlack.length > 0
          ? `${scimActiveDeletedInSlack.length} SCIM-active users appear deactivated in Slack.`
          : "No SCIM-active user matched a deactivated Slack user in the sample.",
      ["FedRAMP AC-2(3)", "CMMC 3.1.12", "SOC 2 CC6.2", "PCI-DSS 8.1.4"],
      { count: scimActiveDeletedInSlack.length },
    ),
    finding(
      "SLACK-ID-05",
      "Deactivated user visibility",
      "info",
      "pass",
      `${deactivated.length} deactivated human users are visible for lifecycle review.`,
      ["FedRAMP AC-2", "SOC 2 CC6.2"],
      { deactivated_users: deactivated.length },
    ),
  ];

  return {
    title: "Slack identity posture",
    summary: {
      users_sampled: users.length,
      active_human_users: activeHumans.length,
      guests: guests.length,
      users_without_mfa: withoutMfa.length,
      scim_users: scimUsers.length,
    },
    findings,
  };
}

async function listWorkspaces(
  client: Pick<SlackApiClient, "paginateWeb" | "web" | "getOrgQuery">,
  limit: number,
): Promise<JsonRecord[]> {
  const workspaces = await client.paginateWeb(
    "admin.teams.list",
    ["teams"],
    client.getOrgQuery(),
    { limit },
  ).catch(() => []);
  if (workspaces.length > 0) return workspaces;

  const auth = await client.web("auth.test").catch(() => undefined);
  const teamId = asString(auth?.team_id);
  return teamId ? [{ id: teamId, name: asString(auth?.team) ?? teamId }] : [];
}

function extractBoolSetting(settings: JsonRecord, keys: string[]): boolean | undefined {
  for (const key of keys) {
    const direct = asBoolean(settings[key]);
    if (direct !== undefined) return direct;
  }

  for (const value of Object.values(settings)) {
    const object = asObject(value);
    if (!object) continue;
    const nested = extractBoolSetting(object, keys);
    if (nested !== undefined) return nested;
  }

  return undefined;
}

function extractNumericSetting(settings: JsonRecord, keys: string[]): number | undefined {
  for (const key of keys) {
    const direct = asNumber(settings[key]);
    if (direct !== undefined) return direct;
  }

  for (const value of Object.values(settings)) {
    const object = asObject(value);
    if (!object) continue;
    const nested = extractNumericSetting(object, keys);
    if (nested !== undefined) return nested;
  }

  return undefined;
}

function extractDiscoverability(settings: JsonRecord): string | undefined {
  const direct = asString(settings.discoverability) ?? asString(settings.default_joinability);
  if (direct) return direct.toLowerCase();
  for (const value of Object.values(settings)) {
    const object = asObject(value);
    if (!object) continue;
    const nested = extractDiscoverability(object);
    if (nested) return nested;
  }
  return undefined;
}

export async function assessSlackAdminAccess(
  client: Pick<SlackApiClient, "paginateWeb" | "web" | "getOrgQuery">,
  options: {
    workspaceLimit?: number;
    maxWorkspaceAdmins?: number;
    maxSessionHours?: number;
    maxIdleMinutes?: number;
  } = {},
): Promise<SlackAssessmentResult> {
  const workspaceLimit = clampNumber(options.workspaceLimit, DEFAULT_WORKSPACE_LIMIT, 1, 500);
  const maxWorkspaceAdmins = clampNumber(options.maxWorkspaceAdmins, 5, 1, 100);
  const maxSessionHours = clampNumber(options.maxSessionHours, 24, 1, 720);
  const maxIdleMinutes = clampNumber(options.maxIdleMinutes, 30, 1, 1440);
  const workspaces = await listWorkspaces(client, workspaceLimit);
  const workspaceSettings: Array<{ id: string; name: string; settings: JsonRecord }> = [];
  const adminCounts: Array<{ id: string; name: string; count: number }> = [];

  for (const workspace of workspaces) {
    const id = asString(workspace.id) ?? asString(workspace.team_id);
    if (!id) continue;
    const name = asString(workspace.name) ?? id;
    const settings = await client.web("admin.teams.settings.info", { team_id: id }).catch(() => undefined);
    if (settings) {
      workspaceSettings.push({ id, name, settings: extractNestedObject(settings, ["team", "settings"]) ?? settings });
    }
    const admins = await client.web("admin.teams.admins.list", { team_id: id }).catch(() => undefined);
    adminCounts.push({ id, name, count: extractCount(admins, ["admins", "users"]) });
  }

  const excessiveAdmins = adminCounts.filter((item) => item.count > maxWorkspaceAdmins);
  const ssoSignals = workspaceSettings
    .map((item) => ({ ...item, required: extractBoolSetting(item.settings, [
      "sso_required",
      "require_sso",
      "requires_sso",
      "enterprise_login_required",
      "saml_required",
      "saml_enabled",
    ]) }))
    .filter((item) => item.required !== undefined);
  const missingSso = ssoSignals.filter((item) => item.required === false);

  const sessionSignals = workspaceSettings.map((item) => {
    const sessionMinutes = extractNumericSetting(item.settings, [
      "session_duration_minutes",
      "session_timeout_minutes",
      "session_duration",
      "max_session_duration_minutes",
    ]);
    const sessionHours = extractNumericSetting(item.settings, [
      "session_duration_hours",
      "session_timeout_hours",
      "max_session_duration_hours",
    ]);
    const idleMinutes = extractNumericSetting(item.settings, [
      "idle_timeout_minutes",
      "session_idle_timeout_minutes",
      "idle_session_timeout_minutes",
    ]);
    return {
      ...item,
      session_hours: sessionHours ?? (sessionMinutes === undefined ? undefined : sessionMinutes / 60),
      idle_minutes: idleMinutes,
    };
  });
  const sessionKnown = sessionSignals.filter((item) => item.session_hours !== undefined);
  const idleKnown = sessionSignals.filter((item) => item.idle_minutes !== undefined);
  const overlongSessions = sessionKnown.filter((item) => (item.session_hours ?? 0) > maxSessionHours);
  const overlongIdle = idleKnown.filter((item) => (item.idle_minutes ?? 0) > maxIdleMinutes);
  const openDiscoverability = workspaceSettings.filter((item) => {
    const discoverability = extractDiscoverability(item.settings);
    return discoverability === "open" || discoverability === "all" || discoverability === "public";
  });

  const findings = [
    finding(
      "SLACK-ADMIN-01",
      "Workspace admin inventory",
      "high",
      adminCounts.length === 0 ? "warn" : excessiveAdmins.length > 0 ? "fail" : "pass",
      adminCounts.length === 0
        ? "Workspace admin assignments were not readable."
        : excessiveAdmins.length > 0
          ? `${excessiveAdmins.length} workspaces exceed ${maxWorkspaceAdmins} admins.`
          : `No sampled workspace exceeded ${maxWorkspaceAdmins} admins.`,
      ["FedRAMP AC-6(5)", "CMMC 3.1.5", "SOC 2 CC6.3", "CIS 16.8"],
      { admin_counts: adminCounts, max_workspace_admins: maxWorkspaceAdmins },
    ),
    finding(
      "SLACK-ADMIN-02",
      "SSO enforcement",
      "critical",
      ssoSignals.length === 0 ? "warn" : missingSso.length > 0 ? "fail" : "pass",
      ssoSignals.length === 0
        ? "Workspace settings did not expose a recognizable SSO enforcement signal."
        : missingSso.length > 0
          ? `${missingSso.length}/${ssoSignals.length} workspaces do not show SSO enforcement.`
          : "Sampled workspaces show SSO enforcement.",
      ["FedRAMP IA-2(1)", "CMMC 3.5.3", "SOC 2 CC6.1", "CIS 16.2"],
      { signals: ssoSignals.map((item) => ({ id: item.id, name: item.name, required: item.required })) },
    ),
    finding(
      "SLACK-ADMIN-03",
      "Session duration limits",
      "high",
      sessionKnown.length === 0 ? "warn" : overlongSessions.length > 0 ? "fail" : "pass",
      sessionKnown.length === 0
        ? "Workspace settings did not expose a recognizable session-duration signal."
        : overlongSessions.length > 0
          ? `${overlongSessions.length}/${sessionKnown.length} workspaces exceed ${maxSessionHours} session hours.`
          : `Sampled workspaces are at or below ${maxSessionHours} session hours.`,
      ["FedRAMP AC-12", "CMMC 3.1.10", "SOC 2 CC6.1", "CIS 16.4"],
      { session_signals: sessionKnown.map((item) => ({ id: item.id, name: item.name, session_hours: item.session_hours })) },
    ),
    finding(
      "SLACK-ADMIN-04",
      "Idle timeout",
      "medium",
      idleKnown.length === 0 ? "warn" : overlongIdle.length > 0 ? "fail" : "pass",
      idleKnown.length === 0
        ? "Workspace settings did not expose a recognizable idle-timeout signal."
        : overlongIdle.length > 0
          ? `${overlongIdle.length}/${idleKnown.length} workspaces exceed ${maxIdleMinutes} idle minutes.`
          : `Sampled workspaces are at or below ${maxIdleMinutes} idle minutes.`,
      ["FedRAMP AC-11", "CMMC 3.1.11", "SOC 2 CC6.1", "CIS 16.5"],
      { idle_signals: idleKnown.map((item) => ({ id: item.id, name: item.name, idle_minutes: item.idle_minutes })) },
    ),
    finding(
      "SLACK-ADMIN-05",
      "Workspace discoverability",
      "medium",
      openDiscoverability.length > 0 ? "warn" : "pass",
      openDiscoverability.length > 0
        ? `${openDiscoverability.length} workspaces appear broadly discoverable.`
        : "No sampled workspace exposed an open discoverability setting.",
      ["FedRAMP AC-3", "CMMC 3.1.1", "SOC 2 CC6.1", "ISMAP CPS.AC-3"],
      { open_workspaces: openDiscoverability.map((item) => ({ id: item.id, name: item.name })) },
    ),
  ];

  return {
    title: "Slack admin access posture",
    summary: {
      workspaces: workspaces.length,
      workspace_settings_readable: workspaceSettings.length,
      admin_surfaces_readable: adminCounts.length,
      excessive_admin_workspaces: excessiveAdmins.length,
    },
    findings,
  };
}

function isCustomOrUnreviewedApp(app: JsonRecord): boolean {
  const type = asString(app.app_type) ?? asString(app.type);
  return app.is_custom === true
    || app.is_workflow_app === true
    || type === "custom"
    || app.is_app_directory_approved === false;
}

export async function assessSlackIntegrations(
  client: Pick<SlackApiClient, "paginateWeb" | "web" | "getOrgQuery">,
  options: { appLimit?: number } = {},
): Promise<SlackAssessmentResult> {
  const appLimit = clampNumber(options.appLimit, DEFAULT_APP_LIMIT, 1, 5000);
  const orgQuery = client.getOrgQuery();
  const approvedResult = await client.paginateWeb("admin.apps.approved.list", ["apps"], orgQuery, { limit: appLimit })
    .then((items) => ({ readable: true, items, error: undefined as string | undefined }))
    .catch((error) => ({ readable: false, items: [] as JsonRecord[], error: surfaceError(error) }));
  const restrictedResult = await client.paginateWeb("admin.apps.restricted.list", ["apps"], orgQuery, { limit: appLimit })
    .then((items) => ({ readable: true, items, error: undefined as string | undefined }))
    .catch((error) => ({ readable: false, items: [] as JsonRecord[], error: surfaceError(error) }));
  const barriersResult = await client.paginateWeb("admin.barriers.list", ["barriers"], orgQuery, { limit: 200 })
    .then((items) => ({ readable: true, items, error: undefined as string | undefined }))
    .catch((error) => ({ readable: false, items: [] as JsonRecord[], error: surfaceError(error) }));
  const discoveryResult = await client.web("discovery.enterprise.info", orgQuery)
    .then((value) => ({ readable: true, value, error: undefined as string | undefined }))
    .catch((error) => ({ readable: false, error: surfaceError(error) }));

  const approvedApps = approvedResult.items;
  const restrictedApps = restrictedResult.items;
  const customApps = approvedApps.filter(isCustomOrUnreviewedApp);
  const broadScopeApps = approvedApps.filter((app) => {
    const scopes = Array.isArray(app.scopes) ? app.scopes.map(String) : [];
    return scopes.some((scope) => /admin|files:read|channels:history|groups:history|users:read\.email/i.test(scope));
  });

  const findings = [
    finding(
      "SLACK-APP-01",
      "Approved app inventory",
      "high",
      approvedResult.readable ? "pass" : "fail",
      approvedResult.readable
        ? `${approvedApps.length} approved apps are visible for review.`
        : `Approved app inventory is not readable: ${approvedResult.error}`,
      ["FedRAMP CM-7", "CMMC 3.4.8", "SOC 2 CC6.8", "CIS 2.7"],
      { approved_app_count: approvedApps.length },
    ),
    finding(
      "SLACK-APP-02",
      "Restricted app policy",
      "medium",
      !restrictedResult.readable ? "warn" : restrictedApps.length === 0 ? "warn" : "pass",
      !restrictedResult.readable
        ? `Restricted app inventory is not readable: ${restrictedResult.error}`
        : restrictedApps.length === 0
          ? "No restricted apps were visible; confirm admin approval policy is active."
          : `${restrictedApps.length} restricted apps are visible.`,
      ["FedRAMP CM-7", "SOC 2 CC6.8", "PCI-DSS 6.3.2"],
      { restricted_app_count: restrictedApps.length },
    ),
    finding(
      "SLACK-APP-03",
      "Custom and broad-scope apps",
      customApps.length > 0 || broadScopeApps.length > 0 ? "high" : "medium",
      customApps.length > 0 || broadScopeApps.length > 0 ? "warn" : "pass",
      customApps.length > 0 || broadScopeApps.length > 0
        ? `${customApps.length} custom/unreviewed apps and ${broadScopeApps.length} broad-scope apps need review.`
        : "No custom/unreviewed or broad-scope approved apps were detected in the sample.",
      ["FedRAMP CM-7(4)", "CMMC 3.4.8", "SOC 2 CC6.8", "ISMAP CPS.CM-7"],
      {
        custom_apps: customApps.slice(0, 20).map((app) => app.name ?? app.id),
        broad_scope_apps: broadScopeApps.slice(0, 20).map((app) => app.name ?? app.id),
      },
    ),
    finding(
      "SLACK-APP-04",
      "Information barriers",
      "high",
      !barriersResult.readable ? "warn" : barriersResult.items.length === 0 ? "warn" : "pass",
      !barriersResult.readable
        ? `Information barriers are not readable: ${barriersResult.error}`
        : barriersResult.items.length === 0
          ? "No information barriers were visible."
          : `${barriersResult.items.length} information barriers are configured.`,
      ["FedRAMP AC-4", "CMMC 3.1.3", "SOC 2 CC6.6", "ISMAP CPS.AC-4"],
      { barrier_count: barriersResult.items.length },
    ),
    finding(
      "SLACK-APP-05",
      "DLP and Discovery visibility",
      "medium",
      discoveryResult.readable ? "pass" : "warn",
      discoveryResult.readable
        ? "Discovery API enterprise information is readable for DLP/eDiscovery posture review."
        : `Discovery API enterprise information is not readable: ${discoveryResult.error}`,
      ["FedRAMP SC-7(8)", "CMMC 3.13.6", "SOC 2 CC6.7", "IRAP ISM-0261"],
      { discovery_readable: discoveryResult.readable },
    ),
  ];

  return {
    title: "Slack integrations posture",
    summary: {
      approved_apps: approvedApps.length,
      restricted_apps: restrictedApps.length,
      custom_or_unreviewed_apps: customApps.length,
      broad_scope_apps: broadScopeApps.length,
      information_barriers: barriersResult.items.length,
      discovery_readable: discoveryResult.readable,
    },
    findings,
  };
}

function auditEntries(value: unknown): JsonRecord[] {
  return extractArray(value, ["entries", "logs"]);
}

function auditSchemas(value: unknown): JsonRecord[] {
  return extractArray(value, ["schemas"]);
}

function auditAction(entry: JsonRecord): string | undefined {
  return asString(entry.action) ?? asString(entry.event_type) ?? asString(entry.type);
}

export async function assessSlackMonitoring(
  client: Pick<SlackApiClient, "audit" | "getNow">,
  options: { days?: number; auditLimit?: number } = {},
): Promise<SlackAssessmentResult> {
  const now = client.getNow();
  const days = clampNumber(options.days, DEFAULT_LOOKBACK_DAYS, 1, 365);
  const auditLimit = clampNumber(options.auditLimit, DEFAULT_AUDIT_LIMIT, 1, 5000);
  const oldest = Math.floor((now.getTime() - days * 24 * 60 * 60 * 1000) / 1000);
  const logsResult = await client.audit("/logs", { limit: auditLimit, oldest })
    .then((value) => ({ readable: true, entries: auditEntries(value), error: undefined as string | undefined }))
    .catch((error) => ({ readable: false, entries: [] as JsonRecord[], error: surfaceError(error) }));
  const schemasResult = await client.audit("/schemas")
    .then((value) => ({ readable: true, schemas: auditSchemas(value), error: undefined as string | undefined }))
    .catch((error) => ({ readable: false, schemas: [] as JsonRecord[], error: surfaceError(error) }));

  const entries = logsResult.entries;
  const latestAge = entries
    .map((entry) => daysBetween(now, extractTimestamp(entry)))
    .filter((age): age is number => age !== undefined)
    .sort((left, right) => left - right)[0];
  const securityActions = new Set([
    "user_login",
    "user_logout",
    "app_installed",
    "app_approved",
    "app_restricted",
    "role_change_to_admin",
    "pref_sso_setting_changed",
    "pref_two_factor_auth_changed",
    "user_deactivated",
  ]);
  const externalActions = new Set([
    "channel_shared",
    "channel_unshared",
    "file_shared_externally",
    "slack_connect_channel_created",
    "user_joined_channel",
  ]);
  const visibleSecurityEvents = entries.filter((entry) => {
    const action = auditAction(entry);
    return Boolean(action && securityActions.has(action));
  });
  const visibleExternalEvents = entries.filter((entry) => {
    const action = auditAction(entry);
    return Boolean(action && externalActions.has(action));
  });

  const findings = [
    finding(
      "SLACK-MON-01",
      "Audit Logs API access",
      "critical",
      !logsResult.readable || entries.length === 0 ? "fail" : "pass",
      !logsResult.readable
        ? `Audit Logs API is not readable: ${logsResult.error}`
        : entries.length === 0
          ? `Audit Logs API returned no entries in the last ${days} days.`
          : `Audit Logs API returned ${entries.length} entries in the sampled window.`,
      ["FedRAMP AU-2", "FedRAMP AU-6", "SOC 2 CC7.2", "CIS 8.2"],
      { entries: entries.length, days },
    ),
    finding(
      "SLACK-MON-02",
      "Audit log recency",
      "high",
      latestAge === undefined ? "warn" : latestAge > 1 ? "fail" : "pass",
      latestAge === undefined
        ? "No parseable audit event timestamp was available."
        : `Latest parseable audit event is ${latestAge.toFixed(2)} days old.`,
      ["FedRAMP AU-6(3)", "CMMC 3.3.5", "SOC 2 CC7.2", "PCI-DSS 10.5.1"],
      { latest_event_age_days: latestAge },
    ),
    finding(
      "SLACK-MON-03",
      "Security event visibility",
      "medium",
      visibleSecurityEvents.length === 0 ? "warn" : "pass",
      visibleSecurityEvents.length === 0
        ? "No common security administration events were present in the sampled audit log entries."
        : `${visibleSecurityEvents.length} common security administration events were visible.`,
      ["FedRAMP SI-4", "FedRAMP AU-6", "SOC 2 CC7.2"],
      { security_event_count: visibleSecurityEvents.length },
    ),
    finding(
      "SLACK-MON-04",
      "Audit schema visibility",
      "low",
      schemasResult.readable ? "pass" : "warn",
      schemasResult.readable
        ? `${schemasResult.schemas.length} audit event schemas are readable.`
        : `Audit event schemas are not readable: ${schemasResult.error}`,
      ["FedRAMP AU-2", "SOC 2 CC7.2"],
      { schemas: schemasResult.schemas.length },
    ),
    finding(
      "SLACK-MON-05",
      "External sharing monitoring",
      "medium",
      visibleExternalEvents.length === 0 ? "warn" : "pass",
      visibleExternalEvents.length === 0
        ? "No Slack Connect or external sharing events appeared in the sampled audit logs."
        : `${visibleExternalEvents.length} external sharing events were visible.`,
      ["FedRAMP AC-21", "CMMC 3.1.20", "SOC 2 CC6.6", "IRAP ISM-0661"],
      { external_event_count: visibleExternalEvents.length },
    ),
  ];

  return {
    title: "Slack monitoring posture",
    summary: {
      days,
      audit_entries: entries.length,
      latest_event_age_days: latestAge,
      security_events: visibleSecurityEvents.length,
      external_sharing_events: visibleExternalEvents.length,
      schemas_readable: schemasResult.readable,
    },
    findings,
  };
}

function formatAccessCheckText(result: SlackAccessCheckResult): string {
  const rows = result.surfaces.map((surface) => [
    surface.name,
    surface.api,
    surface.status,
    surface.count === undefined ? "-" : String(surface.count),
    surface.error ? surface.error.replace(/\s+/g, " ").slice(0, 80) : "",
  ]);
  return [
    `Slack access check: ${result.status}`,
    "",
    ...result.notes,
    "",
    formatTable(["Surface", "API", "Status", "Count", "Note"], rows),
    "",
    `Next: ${result.recommendedNextStep}`,
  ].join("\n");
}

function formatAssessmentText(result: SlackAssessmentResult): string {
  const rows = result.findings.map((item) => [
    item.id,
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
    formatTable(["Control", "Severity", "Status", "Title", "Summary"], rows),
  ].join("\n");
}

function buildExecutiveSummary(
  config: SlackConfiguration,
  assessments: SlackAssessmentResult[],
): string {
  const findings = assessments.flatMap((assessment) => assessment.findings);
  const failCount = findings.filter((item) => item.status === "fail").length;
  const warnCount = findings.filter((item) => item.status === "warn").length;
  const passCount = findings.filter((item) => item.status === "pass").length;
  const criticalCount = findings.filter((item) => item.severity === "critical").length;
  const highCount = findings.filter((item) => item.severity === "high").length;

  return [
    "# Slack Audit Bundle",
    "",
    `Target: ${config.orgId ?? "Slack Enterprise Grid / workspace token"}`,
    `Generated: ${new Date().toISOString()}`,
    "",
    "## Result Counts",
    "",
    `- Failed controls: ${failCount}`,
    `- Warning controls: ${warnCount}`,
    `- Passing controls: ${passCount}`,
    `- Critical-severity controls: ${criticalCount}`,
    `- High-severity controls: ${highCount}`,
    "",
    "## Highest Priority Findings",
    "",
    ...findings
      .filter((item) => item.status !== "pass")
      .slice(0, 10)
      .map((item) => `- ${item.id} (${item.severity.toUpperCase()} / ${item.status.toUpperCase()}): ${item.summary}`),
  ].join("\n");
}

function buildControlMatrix(findings: SlackFinding[]): string {
  const rows = findings.map((item) => [
    item.id,
    item.severity.toUpperCase(),
    item.status.toUpperCase(),
    item.title,
    item.mappings.join(", "),
  ]);
  return [
    "# Slack Control Matrix",
    "",
    formatTable(["Control", "Severity", "Status", "Title", "Mappings"], rows),
  ].join("\n");
}

function buildBundleReadme(): string {
  return [
    "# Slack Evidence Bundle",
    "",
    "This bundle was generated by grclanker's native Slack Enterprise Grid tools.",
    "",
    "## Contents",
    "",
    "- `summary.md`: combined human-readable assessment output",
    "- `reports/executive-summary.md`: prioritized audit summary",
    "- `reports/control-matrix.md`: framework mapping matrix",
    "- `reports/*.md`: per-assessment markdown reports",
    "- `analysis/*.json`: normalized findings and assessment details",
    "- `core_data/access.json`: accessible Slack audit surface inventory",
    "- `metadata.json`: non-secret run metadata",
    "",
    "Slack tokens are not written to this bundle. Use environment variables for tenant credentials when possible.",
  ].join("\n");
}

export async function exportSlackAuditBundle(
  client: SlackApiClient,
  config: SlackConfiguration,
  outputRoot: string,
  options: ExportAuditBundleArgs = {},
): Promise<SlackAuditBundleResult> {
  const access = await checkSlackAccess(client);
  const identity = await assessSlackIdentity(client, {
    userLimit: options.user_limit,
    skipScim: options.skip_scim,
  });
  const adminAccess = await assessSlackAdminAccess(client, {
    workspaceLimit: options.workspace_limit,
    maxWorkspaceAdmins: options.max_workspace_admins,
    maxSessionHours: options.max_session_hours,
    maxIdleMinutes: options.max_idle_minutes,
  });
  const integrations = await assessSlackIntegrations(client, {
    appLimit: options.app_limit,
  });
  const monitoring = await assessSlackMonitoring(client, {
    days: options.days,
    auditLimit: options.audit_limit,
  });

  const assessments = [identity, adminAccess, integrations, monitoring];
  const findings = assessments.flatMap((assessment) => assessment.findings);
  const targetName = safeDirName(`${config.orgId ?? "slack"}-audit`);
  const outputDir = await nextAvailableAuditDir(outputRoot, targetName);

  await writeSecureTextFile(outputDir, "README.md", buildBundleReadme());
  await writeSecureTextFile(outputDir, "metadata.json", serializeJson({
    target: config.orgId ?? null,
    auth_mode: "bearer-token",
    scim_configured: Boolean(config.scimToken),
    source_chain: config.sourceChain,
    generated_at: new Date().toISOString(),
    options: {
      user_limit: options.user_limit ?? DEFAULT_USER_LIMIT,
      workspace_limit: options.workspace_limit ?? DEFAULT_WORKSPACE_LIMIT,
      app_limit: options.app_limit ?? DEFAULT_APP_LIMIT,
      audit_limit: options.audit_limit ?? DEFAULT_AUDIT_LIMIT,
      days: options.days ?? DEFAULT_LOOKBACK_DAYS,
      max_workspace_admins: options.max_workspace_admins ?? 5,
      max_session_hours: options.max_session_hours ?? 24,
      max_idle_minutes: options.max_idle_minutes ?? 30,
    },
  }));
  await writeSecureTextFile(outputDir, "summary.md", assessments.map(formatAssessmentText).join("\n\n"));
  await writeSecureTextFile(outputDir, "reports/executive-summary.md", buildExecutiveSummary(config, assessments));
  await writeSecureTextFile(outputDir, "reports/control-matrix.md", buildControlMatrix(findings));
  await writeSecureTextFile(outputDir, "reports/identity.md", formatAssessmentText(identity));
  await writeSecureTextFile(outputDir, "reports/admin-access.md", formatAssessmentText(adminAccess));
  await writeSecureTextFile(outputDir, "reports/integrations.md", formatAssessmentText(integrations));
  await writeSecureTextFile(outputDir, "reports/monitoring.md", formatAssessmentText(monitoring));
  await writeSecureTextFile(outputDir, "analysis/findings.json", serializeJson(findings));
  await writeSecureTextFile(outputDir, "analysis/identity.json", serializeJson(identity));
  await writeSecureTextFile(outputDir, "analysis/admin-access.json", serializeJson(adminAccess));
  await writeSecureTextFile(outputDir, "analysis/integrations.json", serializeJson(integrations));
  await writeSecureTextFile(outputDir, "analysis/monitoring.json", serializeJson(monitoring));
  await writeSecureTextFile(outputDir, "core_data/access.json", serializeJson(access));

  const zipPath = `${outputDir}.zip`;
  await createZipArchive(outputDir, zipPath);
  const fileCount = await countFilesRecursively(outputDir);

  return {
    outputDir,
    zipPath,
    fileCount,
    findingCount: findings.length,
  };
}

function normalizeCheckAccessArgs(args: unknown): CheckAccessArgs {
  const value = asObject(args) ?? {};
  return {
    token: asString(value.token) ?? asString(value.user_token),
    scim_token: asString(value.scim_token) ?? asString(value.scimToken),
    org_id: asString(value.org_id) ?? asString(value.enterprise_id),
    web_api_base_url: asString(value.web_api_base_url),
    scim_base_url: asString(value.scim_base_url),
    audit_base_url: asString(value.audit_base_url),
    timeout_seconds: asNumber(value.timeout_seconds),
  };
}

function normalizeIdentityArgs(args: unknown): IdentityArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeCheckAccessArgs(args),
    user_limit: asNumber(value.user_limit),
    skip_scim: asBoolean(value.skip_scim),
  };
}

function normalizeAdminAccessArgs(args: unknown): AdminAccessArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeCheckAccessArgs(args),
    workspace_limit: asNumber(value.workspace_limit),
    max_workspace_admins: asNumber(value.max_workspace_admins),
    max_session_hours: asNumber(value.max_session_hours),
    max_idle_minutes: asNumber(value.max_idle_minutes),
  };
}

function normalizeIntegrationsArgs(args: unknown): IntegrationsArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeCheckAccessArgs(args),
    app_limit: asNumber(value.app_limit),
  };
}

function normalizeMonitoringArgs(args: unknown): MonitoringArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeCheckAccessArgs(args),
    days: asNumber(value.days),
    audit_limit: asNumber(value.audit_limit),
  };
}

function normalizeExportAuditBundleArgs(args: unknown): ExportAuditBundleArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeCheckAccessArgs(args),
    output_dir: asString(value.output_dir) ?? asString(value.output),
    user_limit: asNumber(value.user_limit),
    workspace_limit: asNumber(value.workspace_limit),
    app_limit: asNumber(value.app_limit),
    audit_limit: asNumber(value.audit_limit),
    days: asNumber(value.days),
    max_workspace_admins: asNumber(value.max_workspace_admins),
    max_session_hours: asNumber(value.max_session_hours),
    max_idle_minutes: asNumber(value.max_idle_minutes),
    skip_scim: asBoolean(value.skip_scim),
  };
}

function createClient(args: CheckAccessArgs): SlackApiClient {
  return new SlackApiClient(resolveSlackConfiguration(args as JsonRecord));
}

const authParams = {
  token: Type.Optional(Type.String({ description: "Slack org-level user token. Defaults to SLACK_USER_TOKEN." })),
  scim_token: Type.Optional(Type.String({ description: "Slack SCIM bearer token. Defaults to SLACK_SCIM_TOKEN." })),
  org_id: Type.Optional(Type.String({ description: "Slack Enterprise Grid org ID. Defaults to SLACK_ORG_ID or SLACK_ENTERPRISE_ID." })),
  timeout_seconds: Type.Optional(Type.Number({ description: "Request timeout in seconds. Defaults to 30.", default: 30 })),
};

export function registerSlackTools(pi: any): void {
  pi.registerTool({
    name: "slack_check_access",
    label: "Check Slack audit access",
    description:
      "Validate read-only Slack Enterprise Grid API access and show which Web API, SCIM, Audit Logs, app, admin, and Discovery surfaces are readable.",
    parameters: Type.Object(authParams),
    prepareArguments: normalizeCheckAccessArgs,
    async execute(_toolCallId: string, args: CheckAccessArgs) {
      try {
        const result = await checkSlackAccess(createClient(args));
        return textResult(formatAccessCheckText(result), { tool: "slack_check_access", ...result });
      } catch (error) {
        return errorResult(
          `Slack access check failed: ${error instanceof Error ? error.message : String(error)}`,
          { tool: "slack_check_access" },
        );
      }
    },
  });

  pi.registerTool({
    name: "slack_assess_identity",
    label: "Assess Slack identity posture",
    description:
      "Assess Slack users, MFA enrollment visibility, guest inventory, SCIM provisioning coverage, and user lifecycle alignment.",
    parameters: Type.Object({
      ...authParams,
      user_limit: Type.Optional(Type.Number({ description: "Maximum users to sample. Defaults to 1000.", default: 1000 })),
      skip_scim: Type.Optional(Type.Boolean({ description: "Skip SCIM provisioning checks. Defaults to false.", default: false })),
    }),
    prepareArguments: normalizeIdentityArgs,
    async execute(_toolCallId: string, args: IdentityArgs) {
      try {
        const result = await assessSlackIdentity(createClient(args), {
          userLimit: args.user_limit,
          skipScim: args.skip_scim,
        });
        return textResult(formatAssessmentText(result), { tool: "slack_assess_identity", ...result });
      } catch (error) {
        return errorResult(
          `Slack identity assessment failed: ${error instanceof Error ? error.message : String(error)}`,
          { tool: "slack_assess_identity" },
        );
      }
    },
  });

  pi.registerTool({
    name: "slack_assess_admin_access",
    label: "Assess Slack admin access",
    description:
      "Assess Slack workspace admin inventory, SSO enforcement signals, session duration, idle timeout, and workspace discoverability.",
    parameters: Type.Object({
      ...authParams,
      workspace_limit: Type.Optional(Type.Number({ description: "Maximum workspaces to sample. Defaults to 50.", default: 50 })),
      max_workspace_admins: Type.Optional(Type.Number({ description: "Maximum expected admins per workspace. Defaults to 5.", default: 5 })),
      max_session_hours: Type.Optional(Type.Number({ description: "Maximum acceptable session duration in hours. Defaults to 24.", default: 24 })),
      max_idle_minutes: Type.Optional(Type.Number({ description: "Maximum acceptable idle timeout in minutes. Defaults to 30.", default: 30 })),
    }),
    prepareArguments: normalizeAdminAccessArgs,
    async execute(_toolCallId: string, args: AdminAccessArgs) {
      try {
        const result = await assessSlackAdminAccess(createClient(args), {
          workspaceLimit: args.workspace_limit,
          maxWorkspaceAdmins: args.max_workspace_admins,
          maxSessionHours: args.max_session_hours,
          maxIdleMinutes: args.max_idle_minutes,
        });
        return textResult(formatAssessmentText(result), { tool: "slack_assess_admin_access", ...result });
      } catch (error) {
        return errorResult(
          `Slack admin access assessment failed: ${error instanceof Error ? error.message : String(error)}`,
          { tool: "slack_assess_admin_access" },
        );
      }
    },
  });

  pi.registerTool({
    name: "slack_assess_integrations",
    label: "Assess Slack integrations",
    description:
      "Assess Slack approved/restricted app inventory, custom and broad-scope apps, information barriers, and Discovery API visibility.",
    parameters: Type.Object({
      ...authParams,
      app_limit: Type.Optional(Type.Number({ description: "Maximum approved/restricted apps to sample. Defaults to 500.", default: 500 })),
    }),
    prepareArguments: normalizeIntegrationsArgs,
    async execute(_toolCallId: string, args: IntegrationsArgs) {
      try {
        const result = await assessSlackIntegrations(createClient(args), {
          appLimit: args.app_limit,
        });
        return textResult(formatAssessmentText(result), { tool: "slack_assess_integrations", ...result });
      } catch (error) {
        return errorResult(
          `Slack integrations assessment failed: ${error instanceof Error ? error.message : String(error)}`,
          { tool: "slack_assess_integrations" },
        );
      }
    },
  });

  pi.registerTool({
    name: "slack_assess_monitoring",
    label: "Assess Slack monitoring",
    description:
      "Assess Slack Audit Logs API access, event recency, security administration events, schema visibility, and external sharing monitoring.",
    parameters: Type.Object({
      ...authParams,
      days: Type.Optional(Type.Number({ description: "Audit log lookback window in days. Defaults to 30.", default: 30 })),
      audit_limit: Type.Optional(Type.Number({ description: "Maximum audit events to sample. Defaults to 200.", default: 200 })),
    }),
    prepareArguments: normalizeMonitoringArgs,
    async execute(_toolCallId: string, args: MonitoringArgs) {
      try {
        const result = await assessSlackMonitoring(createClient(args), {
          days: args.days,
          auditLimit: args.audit_limit,
        });
        return textResult(formatAssessmentText(result), { tool: "slack_assess_monitoring", ...result });
      } catch (error) {
        return errorResult(
          `Slack monitoring assessment failed: ${error instanceof Error ? error.message : String(error)}`,
          { tool: "slack_assess_monitoring" },
        );
      }
    },
  });

  pi.registerTool({
    name: "slack_export_audit_bundle",
    label: "Export Slack audit bundle",
    description:
      "Export a Slack audit package with access checks, identity, admin-access, integrations, monitoring findings, markdown reports, JSON analysis, and a zip archive.",
    parameters: Type.Object({
      ...authParams,
      output_dir: Type.Optional(Type.String({ description: `Output root. Defaults to ${DEFAULT_OUTPUT_DIR}.` })),
      user_limit: Type.Optional(Type.Number({ description: "Maximum users to sample. Defaults to 1000.", default: 1000 })),
      workspace_limit: Type.Optional(Type.Number({ description: "Maximum workspaces to sample. Defaults to 50.", default: 50 })),
      app_limit: Type.Optional(Type.Number({ description: "Maximum approved/restricted apps to sample. Defaults to 500.", default: 500 })),
      audit_limit: Type.Optional(Type.Number({ description: "Maximum audit events to sample. Defaults to 200.", default: 200 })),
      days: Type.Optional(Type.Number({ description: "Audit log lookback window in days. Defaults to 30.", default: 30 })),
      max_workspace_admins: Type.Optional(Type.Number({ description: "Maximum expected admins per workspace. Defaults to 5.", default: 5 })),
      max_session_hours: Type.Optional(Type.Number({ description: "Maximum acceptable session duration in hours. Defaults to 24.", default: 24 })),
      max_idle_minutes: Type.Optional(Type.Number({ description: "Maximum acceptable idle timeout in minutes. Defaults to 30.", default: 30 })),
      skip_scim: Type.Optional(Type.Boolean({ description: "Skip SCIM provisioning checks. Defaults to false.", default: false })),
    }),
    prepareArguments: normalizeExportAuditBundleArgs,
    async execute(_toolCallId: string, args: ExportAuditBundleArgs) {
      try {
        const config = resolveSlackConfiguration(args as JsonRecord);
        const outputRoot = resolve(process.cwd(), args.output_dir?.trim() || DEFAULT_OUTPUT_DIR);
        const result = await exportSlackAuditBundle(new SlackApiClient(config), config, outputRoot, args);
        return textResult(
          [
            "Slack audit bundle exported.",
            `Output dir: ${result.outputDir}`,
            `Zip archive: ${result.zipPath}`,
            `Findings: ${result.findingCount}`,
            `Files: ${result.fileCount}`,
          ].join("\n"),
          {
            tool: "slack_export_audit_bundle",
            output_dir: result.outputDir,
            zip_path: result.zipPath,
            finding_count: result.findingCount,
            file_count: result.fileCount,
          },
        );
      } catch (error) {
        return errorResult(
          `Slack audit bundle export failed: ${error instanceof Error ? error.message : String(error)}`,
          { tool: "slack_export_audit_bundle" },
        );
      }
    },
  });
}
