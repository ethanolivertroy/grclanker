/**
 * Cisco Webex organization audit tools for grclanker.
 *
 * This native TypeScript surface starts with read-only token-backed Webex API
 * access across identity posture, collaboration governance, and meeting plus
 * hybrid security controls.
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

type FetchImpl = typeof fetch;
type JsonRecord = Record<string, unknown>;

const DEFAULT_OUTPUT_DIR = "./export/webex";
const DEFAULT_TIMEOUT_MS = 30_000;
const DEFAULT_PAGE_LIMIT = 200;
const DEFAULT_PEOPLE_LIMIT = 1000;
const DEFAULT_EVENT_LIMIT = 500;
const DEFAULT_LICENSE_LIMIT = 200;
const DEFAULT_RECORDING_LIMIT = 200;
const DEFAULT_MEETING_LIMIT = 200;
const DEFAULT_WEBHOOK_LIMIT = 200;
const DEFAULT_DEVICE_LIMIT = 500;
const DEFAULT_ROOM_LIMIT = 500;
const DEFAULT_MAX_ADMINS = 10;

export interface WebexResolvedConfig {
  token: string;
  orgId?: string;
  baseUrl: string;
  timeoutMs: number;
  sourceChain: string[];
}

export interface WebexAccessSurface {
  name: string;
  endpoint: string;
  status: "readable" | "not_readable" | "not_configured";
  count?: number;
  error?: string;
}

export interface WebexAccessCheckResult {
  status: "healthy" | "limited";
  orgId?: string;
  surfaces: WebexAccessSurface[];
  notes: string[];
  recommendedNextStep: string;
}

export interface WebexFinding {
  id: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  status: "pass" | "warn" | "fail";
  summary: string;
  evidence?: JsonRecord;
  mappings: string[];
}

export interface WebexAssessmentResult {
  title: string;
  summary: JsonRecord;
  findings: WebexFinding[];
}

export interface WebexAuditBundleResult {
  outputDir: string;
  zipPath: string;
  fileCount: number;
  findingCount: number;
}

type CheckAccessArgs = {
  token?: string;
  org_id?: string;
  base_url?: string;
  timeout_seconds?: number;
};

type IdentityArgs = CheckAccessArgs & {
  people_limit?: number;
  max_admins?: number;
};

type CollaborationArgs = CheckAccessArgs & {
  event_limit?: number;
  recording_limit?: number;
  webhook_limit?: number;
  license_limit?: number;
  room_limit?: number;
};

type MeetingHybridArgs = CheckAccessArgs & {
  meeting_limit?: number;
  device_limit?: number;
};

type ExportAuditBundleArgs = CheckAccessArgs & {
  output_dir?: string;
  people_limit?: number;
  max_admins?: number;
  event_limit?: number;
  recording_limit?: number;
  webhook_limit?: number;
  license_limit?: number;
  room_limit?: number;
  meeting_limit?: number;
  device_limit?: number;
};

function asObject(value: unknown): JsonRecord | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
  return value as JsonRecord;
}

function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function asString(value: unknown): string | undefined {
  if (typeof value === "string") {
    const trimmed = value.trim();
    return trimmed.length > 0 ? trimmed : undefined;
  }
  if (typeof value === "number" && Number.isFinite(value)) return String(value);
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
    if (/^(true|1|yes|enabled|on|active|required|strict)$/i.test(value.trim())) return true;
    if (/^(false|0|no|disabled|off|inactive|optional)$/i.test(value.trim())) return false;
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

function parseLinkHeaderNext(linkHeader: string | null): string | null {
  if (!linkHeader) return null;
  const match = linkHeader.match(/<([^>]+)>;\s*rel="next"/i);
  return match?.[1] ?? null;
}

function serializeJson(value: unknown): string {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function safeDirName(value: string): string {
  const normalized = value
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 80);
  return normalized || "webex";
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
  if (lstatSync(realParent).isSymbolicLink()) {
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
  await chmod(zipPath, 0o600);
}

async function countFilesRecursively(rootDir: string): Promise<number> {
  let total = 0;
  const entries = await readdir(rootDir, { withFileTypes: true });
  for (const entry of entries) {
    const pathname = join(rootDir, entry.name);
    if (entry.isDirectory()) {
      total += await countFilesRecursively(pathname);
    } else if (entry.isFile()) {
      total += 1;
    }
  }
  return total;
}

function getNestedValue(value: unknown, path: string[]): unknown {
  let current: unknown = value;
  for (const segment of path) {
    current = asObject(current)?.[segment];
    if (current === undefined) return undefined;
  }
  return current;
}

function firstDefined(value: unknown, paths: string[][]): unknown {
  for (const path of paths) {
    const candidate = getNestedValue(value, path);
    if (candidate !== undefined) return candidate;
  }
  return undefined;
}

function extractItems(payload: unknown): JsonRecord[] {
  const object = asObject(payload);
  if (!object) return [];
  if (Array.isArray(object.items)) {
    return object.items.map(asObject).filter((item): item is JsonRecord => Boolean(item));
  }
  if (Array.isArray(object.people)) {
    return object.people.map(asObject).filter((item): item is JsonRecord => Boolean(item));
  }
  if (Array.isArray(object.organizations)) {
    return object.organizations.map(asObject).filter((item): item is JsonRecord => Boolean(item));
  }
  if (Array.isArray(object.roles)) {
    return object.roles.map(asObject).filter((item): item is JsonRecord => Boolean(item));
  }
  return [];
}

function webexErrorSummary(payload: unknown): string | undefined {
  const object = asObject(payload);
  if (!object) return undefined;
  const messages = [
    ...asArray(object.errors).map((item) => asString(asObject(item)?.description) ?? asString(asObject(item)?.message)),
    asString(object.message),
    asString(object.error),
  ].filter((item): item is string => Boolean(item));
  return messages.length > 0 ? messages.join("; ") : undefined;
}

export function resolveWebexConfiguration(
  input: JsonRecord = {},
  env: NodeJS.ProcessEnv = process.env,
): WebexResolvedConfig {
  const sourceChain: string[] = [];
  const token = asString(input.token)
    ?? asString(env.WEBEX_TOKEN);
  if (!token) {
    throw new Error("WEBEX_TOKEN or a token argument is required.");
  }
  sourceChain.push(asString(input.token) ? "arguments-token" : "environment-token");

  const orgId = asString(input.org_id)
    ?? asString(env.WEBEX_ORG_ID);
  if (orgId) sourceChain.push(asString(input.org_id) ? "arguments-org" : "environment-org");

  return {
    token,
    orgId,
    baseUrl: normalizeBaseUrl(asString(input.base_url) ?? asString(env.WEBEX_API_BASE_URL) ?? "https://webexapis.com/v1"),
    timeoutMs: parseTimeoutSeconds(asNumber(input.timeout_seconds) ?? asNumber(env.WEBEX_TIMEOUT)),
    sourceChain: [...new Set(sourceChain)],
  };
}

export class WebexApiClient {
  private readonly config: WebexResolvedConfig;
  private readonly fetchImpl: FetchImpl;
  private readonly now: () => Date;

  constructor(
    config: WebexResolvedConfig,
    options: {
      fetchImpl?: FetchImpl;
      now?: () => Date;
    } = {},
  ) {
    this.config = config;
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.now = options.now ?? (() => new Date());
  }

  getResolvedConfig(): WebexResolvedConfig {
    return this.config;
  }

  getNow(): Date {
    return this.now();
  }

  getOrgQuery(): JsonRecord {
    return this.config.orgId ? { orgId: this.config.orgId } : {};
  }

  private buildUrl(pathOrUrl: string, query: JsonRecord = {}): string {
    const url = new URL(
      pathOrUrl.startsWith("http://") || pathOrUrl.startsWith("https://")
        ? pathOrUrl
        : `${this.config.baseUrl}${pathOrUrl.startsWith("/") ? pathOrUrl : `/${pathOrUrl}`}`,
    );
    for (const [key, value] of Object.entries(query)) {
      if (value === undefined || value === null || value === "") continue;
      url.searchParams.set(key, String(value));
    }
    return url.toString();
  }

  private async fetchJson(url: string): Promise<{ payload: JsonRecord; nextUrl: string | null }> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.config.timeoutMs);

    try {
      const response = await this.fetchImpl(url, {
        method: "GET",
        headers: {
          accept: "application/json",
          authorization: `Bearer ${this.config.token}`,
        },
        signal: controller.signal,
      });

      const rawText = await response.text();
      const payload = rawText.length > 0 ? JSON.parse(rawText) as JsonRecord : {};

      if (!response.ok) {
        const detail = webexErrorSummary(payload) ?? rawText.slice(0, 240);
        throw new Error(`Webex request failed (${response.status} ${response.statusText})${detail ? `: ${detail}` : ""}`);
      }

      return {
        payload,
        nextUrl: parseLinkHeaderNext(response.headers.get("link")),
      };
    } finally {
      clearTimeout(timeout);
    }
  }

  async get(path: string, query: JsonRecord = {}): Promise<JsonRecord> {
    const { payload } = await this.fetchJson(this.buildUrl(path, query));
    return payload;
  }

  async list(
    path: string,
    query: JsonRecord = {},
    options: { limit?: number; pageLimit?: number } = {},
  ): Promise<JsonRecord[]> {
    const limit = clampNumber(options.limit, DEFAULT_PAGE_LIMIT, 1, 5000);
    const pageLimit = clampNumber(options.pageLimit, DEFAULT_PAGE_LIMIT, 1, 1000);
    const items: JsonRecord[] = [];
    let nextUrl: string | null = this.buildUrl(path, { max: pageLimit, ...query });

    while (nextUrl && items.length < limit) {
      const response = await this.fetchJson(nextUrl);
      const pageItems = extractItems(response.payload);
      items.push(...pageItems.slice(0, limit - items.length));
      nextUrl = response.nextUrl;
      if (pageItems.length === 0) break;
    }

    return items;
  }

  async getMe(): Promise<JsonRecord> {
    return this.get("/people/me");
  }

  async listOrganizations(limit = DEFAULT_PAGE_LIMIT): Promise<JsonRecord[]> {
    return this.list("/organizations", {}, { limit });
  }

  async getOrganization(orgId: string): Promise<JsonRecord> {
    return this.get(`/organizations/${encodeURIComponent(orgId)}`);
  }

  async listPeople(limit = DEFAULT_PEOPLE_LIMIT): Promise<JsonRecord[]> {
    return this.list("/people", this.getOrgQuery(), { limit });
  }

  async listRoles(limit = DEFAULT_PAGE_LIMIT): Promise<JsonRecord[]> {
    return this.list("/roles", this.getOrgQuery(), { limit });
  }

  async listLicenses(limit = DEFAULT_LICENSE_LIMIT): Promise<JsonRecord[]> {
    return this.list("/licenses", this.getOrgQuery(), { limit });
  }

  async listEvents(limit = DEFAULT_EVENT_LIMIT): Promise<JsonRecord[]> {
    return this.list("/events", this.getOrgQuery(), { limit });
  }

  async listRecordings(limit = DEFAULT_RECORDING_LIMIT): Promise<JsonRecord[]> {
    return this.list("/recordings", this.getOrgQuery(), { limit });
  }

  async listMeetings(limit = DEFAULT_MEETING_LIMIT): Promise<JsonRecord[]> {
    return this.list("/meetings", this.getOrgQuery(), { limit });
  }

  async getMeetingPreferences(): Promise<JsonRecord> {
    return this.get("/meetingPreferences", this.getOrgQuery());
  }

  async listMeetingSites(limit = DEFAULT_PAGE_LIMIT): Promise<JsonRecord[]> {
    return this.list("/meetingPreferences/sites", this.getOrgQuery(), { limit });
  }

  async getAdminSettings(orgId: string): Promise<JsonRecord> {
    return this.get(`/admin/organizations/${encodeURIComponent(orgId)}/settings`);
  }

  async getSecuritySettings(orgId: string): Promise<JsonRecord> {
    return this.get(`/admin/organizations/${encodeURIComponent(orgId)}/security`);
  }

  async listHybridClusters(limit = DEFAULT_PAGE_LIMIT): Promise<JsonRecord[]> {
    return this.list("/hybrid/clusters", this.getOrgQuery(), { limit });
  }

  async listHybridConnectors(limit = DEFAULT_PAGE_LIMIT): Promise<JsonRecord[]> {
    return this.list("/hybrid/connectors", this.getOrgQuery(), { limit });
  }

  async listDevices(limit = DEFAULT_DEVICE_LIMIT): Promise<JsonRecord[]> {
    return this.list("/devices", this.getOrgQuery(), { limit });
  }

  async listWorkspaces(limit = DEFAULT_PAGE_LIMIT): Promise<JsonRecord[]> {
    return this.list("/workspaces", this.getOrgQuery(), { limit });
  }

  async listRooms(limit = DEFAULT_ROOM_LIMIT): Promise<JsonRecord[]> {
    return this.list("/rooms", this.getOrgQuery(), { limit });
  }

  async listWebhooks(limit = DEFAULT_WEBHOOK_LIMIT): Promise<JsonRecord[]> {
    return this.list("/webhooks", this.getOrgQuery(), { limit });
  }
}

function deriveOrgContext(
  config: WebexResolvedConfig,
  orgs: JsonRecord[],
): { orgId?: string; note: string } {
  if (config.orgId) {
    return { orgId: config.orgId, note: `Using configured Webex org ${config.orgId}.` };
  }

  const soleId = asString(orgs[0]?.id);
  if (orgs.length === 1 && soleId) {
    return { orgId: soleId, note: `Using the only visible Webex org ${soleId}.` };
  }

  if (orgs.length === 0) {
    return { orgId: undefined, note: "No Webex organizations were visible; org-scoped checks will stay limited." };
  }

  return {
    orgId: undefined,
    note: "Multiple Webex organizations were visible with no org_id selected; org-scoped checks will stay limited.",
  };
}

async function readableSurface(
  name: string,
  endpoint: string,
  load: () => Promise<unknown>,
  countResolver?: (value: unknown) => number | undefined,
): Promise<WebexAccessSurface> {
  try {
    const value = await load();
    return {
      name,
      endpoint,
      status: "readable",
      count: countResolver?.(value),
    };
  } catch (error) {
    return {
      name,
      endpoint,
      status: "not_readable",
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

function notConfiguredSurface(name: string, endpoint: string, error: string): WebexAccessSurface {
  return {
    name,
    endpoint,
    status: "not_configured",
    error,
  };
}

function finding(
  id: string,
  title: string,
  severity: WebexFinding["severity"],
  status: WebexFinding["status"],
  summary: string,
  mappings: string[],
  evidence?: JsonRecord,
): WebexFinding {
  return { id, title, severity, status, summary, evidence, mappings };
}

function personRoleIds(person: JsonRecord): string[] {
  return [
    ...asArray(person.roles).map((item) => asString(item)),
    ...asArray(person.adminRoles).map((item) => asString(asObject(item)?.id) ?? asString(item)),
  ].filter((item): item is string => Boolean(item));
}

function expandRoleNames(person: JsonRecord, roleMap: Map<string, string>): string[] {
  const values = [
    ...personRoleIds(person).map((id) => roleMap.get(id) ?? id),
    ...asArray(person.adminRoles).map((item) => asString(asObject(item)?.displayName) ?? asString(asObject(item)?.name)),
  ];
  return values.filter((item): item is string => Boolean(item));
}

function roleMapFromRoles(roles: JsonRecord[]): Map<string, string> {
  return new Map(
    roles
      .map((role) => {
        const id = asString(role.id);
        const name = asString(role.name) ?? asString(role.displayName);
        return id && name ? [id, name] as const : undefined;
      })
      .filter((item): item is readonly [string, string] => Boolean(item)),
  );
}

function objectHasAnyEnabledSignal(value: unknown): boolean {
  const object = asObject(value);
  if (!object) return false;
  for (const entry of Object.values(object)) {
    if (isExplicitlyEnabled(entry)) return true;
    if (asObject(entry) && objectHasAnyEnabledSignal(entry)) return true;
  }
  return false;
}

function isExplicitlyEnabled(value: unknown): boolean {
  return asBoolean(value) === true || /^(enabled|active|required|strict|e2ee|srtp)$/i.test(asString(value) ?? "");
}

function isExplicitlyDisabled(value: unknown): boolean {
  return asBoolean(value) === false || /^(disabled|inactive|off|none|optional|personal)$/i.test(asString(value) ?? "");
}

function roomName(room: JsonRecord): string {
  return asString(room.title) ?? asString(room.displayName) ?? asString(room.id) ?? "room";
}

function orgSignalsEnabled(value: unknown, candidatePaths: string[][]): boolean {
  return candidatePaths.some((path) => isExplicitlyEnabled(getNestedValue(value, path)));
}

function orgSignalsDisabled(value: unknown, candidatePaths: string[][]): boolean {
  return candidatePaths.some((path) => isExplicitlyDisabled(getNestedValue(value, path)));
}

export async function checkWebexAccess(
  client: Pick<
    WebexApiClient,
    | "getResolvedConfig"
    | "getMe"
    | "listOrganizations"
    | "listPeople"
    | "listRoles"
    | "listLicenses"
    | "listMeetings"
    | "listRecordings"
    | "listEvents"
    | "getAdminSettings"
    | "getSecuritySettings"
    | "listHybridClusters"
    | "listDevices"
    | "listWebhooks"
  >,
): Promise<WebexAccessCheckResult> {
  const config = client.getResolvedConfig();
  const [me, orgs] = await Promise.all([
    client.getMe(),
    client.listOrganizations(),
  ]);
  const { orgId, note } = deriveOrgContext(config, orgs);

  const surfaces: WebexAccessSurface[] = [
    await readableSurface("me", "/people/me", () => client.getMe(), () => 1),
    await readableSurface("organizations", "/organizations", () => client.listOrganizations(), (value) => Array.isArray(value) ? value.length : undefined),
    await readableSurface("people", "/people", () => client.listPeople(), (value) => Array.isArray(value) ? value.length : undefined),
    await readableSurface("roles", "/roles", () => client.listRoles(), (value) => Array.isArray(value) ? value.length : undefined),
    await readableSurface("licenses", "/licenses", () => client.listLicenses(), (value) => Array.isArray(value) ? value.length : undefined),
    await readableSurface("meetings", "/meetings", () => client.listMeetings(), (value) => Array.isArray(value) ? value.length : undefined),
    await readableSurface("recordings", "/recordings", () => client.listRecordings(), (value) => Array.isArray(value) ? value.length : undefined),
    await readableSurface("events", "/events", () => client.listEvents(), (value) => Array.isArray(value) ? value.length : undefined),
    await readableSurface("hybrid_clusters", "/hybrid/clusters", () => client.listHybridClusters(), (value) => Array.isArray(value) ? value.length : undefined),
    await readableSurface("devices", "/devices", () => client.listDevices(), (value) => Array.isArray(value) ? value.length : undefined),
    await readableSurface("webhooks", "/webhooks", () => client.listWebhooks(), (value) => Array.isArray(value) ? value.length : undefined),
  ];

  if (orgId) {
    surfaces.push(
      await readableSurface("admin_settings", `/admin/organizations/${orgId}/settings`, () => client.getAdminSettings(orgId), () => 1),
      await readableSurface("security_settings", `/admin/organizations/${orgId}/security`, () => client.getSecuritySettings(orgId), () => 1),
    );
  } else {
    surfaces.push(
      notConfiguredSurface("admin_settings", "/admin/organizations/{orgId}/settings", note),
      notConfiguredSurface("security_settings", "/admin/organizations/{orgId}/security", note),
    );
  }

  const readableCount = surfaces.filter((surfaceItem) => surfaceItem.status === "readable").length;
  const status = readableCount >= 7 ? "healthy" : "limited";

  return {
    status,
    orgId,
    surfaces,
    notes: [
      `Authenticated as ${asString(me.displayName) ?? asString(asArray(me.emails)[0]) ?? asString(me.id) ?? "current Webex user"}.`,
      note,
      `${readableCount}/${surfaces.length} Webex audit surfaces are readable.`,
    ],
    recommendedNextStep:
      status === "healthy"
        ? "Run webex_assess_identity, webex_assess_collaboration_governance, webex_assess_meeting_hybrid_security, or webex_export_audit_bundle."
        : "Provide a read-only Webex token with people, org, meetings, recordings, events, and Control Hub admin read scopes.",
  };
}

export async function assessWebexIdentity(
  client: Pick<
    WebexApiClient,
    "getResolvedConfig" | "listOrganizations" | "listPeople" | "listRoles" | "getAdminSettings"
  >,
  options: {
    peopleLimit?: number;
    maxAdmins?: number;
  } = {},
): Promise<WebexAssessmentResult> {
  const config = client.getResolvedConfig();
  const peopleLimit = clampNumber(options.peopleLimit, DEFAULT_PEOPLE_LIMIT, 1, 10000);
  const maxAdmins = clampNumber(options.maxAdmins, DEFAULT_MAX_ADMINS, 0, 5000);

  const orgs = await client.listOrganizations();
  const { orgId, note } = deriveOrgContext(config, orgs);
  const [people, roles, adminSettings] = await Promise.all([
    client.listPeople(peopleLimit),
    client.listRoles(),
    orgId ? client.getAdminSettings(orgId).catch(() => ({})) : Promise.resolve({}),
  ]);

  const roleMap = roleMapFromRoles(roles);
  const adminUsers = people.filter((person) => expandRoleNames(person, roleMap).some((role) => /admin/i.test(role)));
  const complianceOfficers = people.filter((person) => expandRoleNames(person, roleMap).some((role) => /compliance/i.test(role)));
  const adminsWithoutMfa = adminUsers.filter((person) => !isExplicitlyEnabled(firstDefined(person, [
    ["mfaEnabled"],
    ["mfaRequired"],
    ["security", "mfaEnabled"],
    ["status", "mfaEnabled"],
  ])));

  const ssoEnabled = orgSignalsEnabled(adminSettings, [
    ["ssoEnabled"],
    ["security", "ssoEnabled"],
    ["authentication", "ssoEnabled"],
    ["authentication", "sso", "enabled"],
    ["idp", "enabled"],
  ]);
  const adminMfaRequired = orgSignalsEnabled(adminSettings, [
    ["adminMfaRequired"],
    ["security", "adminMfaRequired"],
    ["security", "mfa", "requiredForAdmins"],
    ["authentication", "mfa", "requiredForAdmins"],
  ]);

  const findings = [
    finding(
      "WEBEX-ID-01",
      "Organization SSO enforcement",
      "critical",
      orgId ? (ssoEnabled ? "pass" : "fail") : "warn",
      orgId
        ? (ssoEnabled
          ? "Webex org settings exposed SSO as enabled."
          : "Webex org settings did not expose SSO as enabled.")
        : note,
      ["FedRAMP IA-2(1)", "SOC 2 CC6.1", "PCI-DSS 8.4.1", "CIS 16.2"],
      { org_id: orgId ?? null, sso_enabled: ssoEnabled },
    ),
    finding(
      "WEBEX-ID-02",
      "Admin MFA enforcement",
      "critical",
      orgId ? (adminMfaRequired && adminsWithoutMfa.length === 0 ? "pass" : "fail") : "warn",
      orgId
        ? (adminMfaRequired && adminsWithoutMfa.length === 0
          ? "Org policy required MFA for admins and no sampled admins were missing it."
          : `${adminsWithoutMfa.length}/${adminUsers.length} sampled admins appeared to lack MFA or org MFA enforcement was not visible.`)
        : note,
      ["FedRAMP IA-2(2)", "SOC 2 CC6.1", "PCI-DSS 8.4.2", "CIS 16.3"],
      { admin_users: adminUsers.length, admins_without_mfa: adminsWithoutMfa.length, admin_mfa_required: adminMfaRequired },
    ),
    finding(
      "WEBEX-ID-03",
      "Compliance Officer assignment",
      "high",
      complianceOfficers.length > 0 ? "pass" : "warn",
      complianceOfficers.length > 0
        ? `${complianceOfficers.length} sampled users carried a compliance-oriented role.`
        : "No sampled users carried a Compliance Officer style role.",
      ["FedRAMP AU-1", "SOC 2 CC7.2", "PCI-DSS 12.5.2", "CIS 8.1"],
      { compliance_officers: complianceOfficers.length },
    ),
    finding(
      "WEBEX-ID-04",
      "Administrative privilege concentration",
      "medium",
      adminUsers.length <= maxAdmins ? "pass" : "warn",
      adminUsers.length <= maxAdmins
        ? `${adminUsers.length} sampled users had admin roles, within the configured threshold of ${maxAdmins}.`
        : `${adminUsers.length} sampled users had admin roles, exceeding the configured threshold of ${maxAdmins}.`,
      ["FedRAMP AC-2", "FedRAMP AC-6", "SOC 2 CC6.3", "PCI-DSS 7.2.2"],
      { admin_users: adminUsers.length, max_admins: maxAdmins, sampled_people: people.length },
    ),
  ];

  return {
    title: "Webex identity posture",
    summary: {
      org_id: orgId ?? null,
      sampled_people: people.length,
      admin_users: adminUsers.length,
      admins_without_mfa: adminsWithoutMfa.length,
      compliance_officers: complianceOfficers.length,
      sso_enabled: ssoEnabled,
      admin_mfa_required: adminMfaRequired,
    },
    findings,
  };
}

export async function assessWebexCollaborationGovernance(
  client: Pick<
    WebexApiClient,
    "getResolvedConfig" | "listOrganizations" | "getSecuritySettings" | "getAdminSettings" | "listEvents" | "listRecordings" | "listRooms" | "listWebhooks" | "listLicenses"
  >,
  options: {
    eventLimit?: number;
    recordingLimit?: number;
    webhookLimit?: number;
    licenseLimit?: number;
    roomLimit?: number;
  } = {},
): Promise<WebexAssessmentResult> {
  const config = client.getResolvedConfig();
  const eventLimit = clampNumber(options.eventLimit, DEFAULT_EVENT_LIMIT, 1, 10000);
  const recordingLimit = clampNumber(options.recordingLimit, DEFAULT_RECORDING_LIMIT, 1, 10000);
  const webhookLimit = clampNumber(options.webhookLimit, DEFAULT_WEBHOOK_LIMIT, 1, 10000);
  const licenseLimit = clampNumber(options.licenseLimit, DEFAULT_LICENSE_LIMIT, 1, 10000);
  const roomLimit = clampNumber(options.roomLimit, DEFAULT_ROOM_LIMIT, 1, 10000);

  const orgs = await client.listOrganizations();
  const { orgId, note } = deriveOrgContext(config, orgs);
  const [securitySettings, adminSettings, events, recordings, rooms, webhooks, licenses] = await Promise.all([
    orgId ? client.getSecuritySettings(orgId).catch(() => ({})) : Promise.resolve({}),
    orgId ? client.getAdminSettings(orgId).catch(() => ({})) : Promise.resolve({}),
    client.listEvents(eventLimit).catch(() => []),
    client.listRecordings(recordingLimit).catch(() => []),
    client.listRooms(roomLimit).catch(() => []),
    client.listWebhooks(webhookLimit).catch(() => []),
    client.listLicenses(licenseLimit).catch(() => []),
  ]);

  const externalRestricted = orgSignalsEnabled(securitySettings, [
    ["externalCommunicationsRestricted"],
    ["externalMessagingRestricted"],
    ["messaging", "external", "restricted"],
    ["externalCommunicationPolicy", "approvedDomainsOnly"],
    ["allowedDomainsOnly"],
  ]);
  const fileControlsEnabled = orgSignalsEnabled(securitySettings, [
    ["fileSharingRestricted"],
    ["fileSharing", "restricted"],
    ["messagingDlpEnabled"],
    ["dlp", "enabled"],
    ["fileTypeFilteringEnabled"],
  ]);
  const guestRestricted = orgSignalsDisabled(securitySettings, [
    ["guestAccessEnabled"],
    ["guestsAllowed"],
    ["messaging", "guestAccessEnabled"],
  ]) || orgSignalsEnabled(securitySettings, [
    ["guestAccessRestricted"],
    ["messaging", "guestAccessRestricted"],
  ]);

  const riskyRecordings = recordings.filter((recording) =>
    isExplicitlyDisabled(firstDefined(recording, [
      ["organizationOwned"],
      ["orgControlledStorage"],
      ["storage", "organizationControlled"],
    ])),
  );
  const retentionConfigured = orgSignalsEnabled(adminSettings, [
    ["recordingRetentionEnabled"],
    ["recordings", "autoDeleteEnabled"],
    ["retention", "configured"],
    ["dataRetentionPolicyEnabled"],
  ]) || asNumber(firstDefined(adminSettings, [
    ["recordingRetentionDays"],
    ["recordings", "autoDeleteDays"],
    ["retention", "days"],
  ])) !== undefined;

  const roomsWithoutClassification = rooms.filter((room) => {
    const value = firstDefined(room, [
      ["classification"],
      ["classificationLabel"],
      ["retention", "classification"],
    ]);
    return !asString(value);
  });
  const insecureWebhooks = webhooks.filter((webhook) => {
    const targetUrl = asString(webhook.targetUrl) ?? asString(webhook.url) ?? "";
    const secret = asString(webhook.secret);
    return !targetUrl.startsWith("https://") || !secret;
  });
  const adminAuditEvents = events.filter((event) => {
    const text = JSON.stringify(event).toLowerCase();
    return text.includes("admin") || text.includes("role") || text.includes("compliance");
  });

  const totalAssignedLicenses = licenses.reduce((count, license) => count + (asNumber(firstDefined(license, [
    ["consumedUnits"],
    ["assigned"],
    ["consumed"],
  ])) ?? 0), 0);
  const totalAvailableLicenses = licenses.reduce((count, license) => count + (asNumber(firstDefined(license, [
    ["totalUnits"],
    ["capacity"],
    ["total"],
  ])) ?? 0), 0);
  const unassignedLicenses = Math.max(totalAvailableLicenses - totalAssignedLicenses, 0);
  const unassignedRatio = totalAvailableLicenses > 0 ? unassignedLicenses / totalAvailableLicenses : 0;

  const findings = [
    finding(
      "WEBEX-COLLAB-01",
      "External communications restrictions",
      "high",
      orgId ? (externalRestricted && guestRestricted ? "pass" : "warn") : "warn",
      orgId
        ? (externalRestricted && guestRestricted
          ? "External communications and guest access controls appeared restricted."
          : "External communications or guest access controls did not appear tightly restricted.")
        : note,
      ["FedRAMP AC-4", "SOC 2 CC6.6", "PCI-DSS 1.3.7", "CIS 13.4"],
      { org_id: orgId ?? null, external_restricted: externalRestricted, guest_restricted: guestRestricted },
    ),
    finding(
      "WEBEX-COLLAB-02",
      "File sharing and DLP controls",
      "high",
      orgId ? (fileControlsEnabled ? "pass" : "warn") : "warn",
      orgId
        ? (fileControlsEnabled
          ? "File sharing restrictions or DLP-style controls were visible."
          : "File sharing restrictions or DLP-style controls were not clearly visible.")
        : note,
      ["FedRAMP AC-4(1)", "SOC 2 CC6.7", "PCI-DSS 1.3.7", "CIS 13.4"],
      { org_id: orgId ?? null, file_controls_enabled: fileControlsEnabled },
    ),
    finding(
      "WEBEX-COLLAB-03",
      "Recording storage and retention governance",
      "medium",
      riskyRecordings.length === 0 && retentionConfigured ? "pass" : riskyRecordings.length > 0 ? "fail" : "warn",
      riskyRecordings.length === 0 && retentionConfigured
        ? "Sampled recordings appeared organization-controlled and retention settings were visible."
        : `${riskyRecordings.length} sampled recordings appeared outside org-controlled storage or retention settings were not clearly visible.`,
      ["FedRAMP SC-28", "FedRAMP SI-12", "SOC 2 CC6.7", "PCI-DSS 3.4.1"],
      { risky_recordings: riskyRecordings.slice(0, 25).map((item) => asString(item.id)), retention_configured: retentionConfigured },
    ),
    finding(
      "WEBEX-COLLAB-04",
      "Room classification and retention coverage",
      "medium",
      rooms.length === 0 || roomsWithoutClassification.length === 0 ? "pass" : "warn",
      rooms.length === 0 || roomsWithoutClassification.length === 0
        ? "Sampled rooms exposed classification coverage or there were no rooms in scope."
        : `${roomsWithoutClassification.length}/${rooms.length} sampled rooms lacked visible classification labels.`,
      ["FedRAMP AC-16", "SOC 2 CC6.7", "PCI-DSS 9.6.1", "CIS 14.1"],
      { sampled_rooms: rooms.length, rooms_without_classification: roomsWithoutClassification.slice(0, 25).map(roomName) },
    ),
    finding(
      "WEBEX-COLLAB-05",
      "Webhook transport and admin audit visibility",
      "high",
      insecureWebhooks.length === 0 && adminAuditEvents.length > 0 ? "pass" : insecureWebhooks.length > 0 ? "fail" : "warn",
      insecureWebhooks.length === 0 && adminAuditEvents.length > 0
        ? "All sampled webhooks used HTTPS with secrets and admin activity events were visible."
        : `${insecureWebhooks.length} sampled webhooks were missing HTTPS or a secret, or admin audit events were not visible.`,
      ["FedRAMP AU-12", "FedRAMP SC-8(1)", "SOC 2 CC7.2", "PCI-DSS 10.2.2"],
      { insecure_webhooks: insecureWebhooks.slice(0, 25).map((item) => asString(item.id)), admin_audit_events: adminAuditEvents.length },
    ),
    finding(
      "WEBEX-COLLAB-06",
      "License utilization review",
      "low",
      totalAvailableLicenses === 0 || unassignedRatio <= 0.2 ? "pass" : "warn",
      totalAvailableLicenses === 0 || unassignedRatio <= 0.2
        ? "License assignment looked reasonably utilized in the sampled inventory."
        : `${unassignedLicenses}/${totalAvailableLicenses} sampled licenses were unassigned, above the 20% review threshold.`,
      ["FedRAMP CM-8", "SOC 2 CC6.8", "PCI-DSS 2.4", "CIS 1.1"],
      { total_available_licenses: totalAvailableLicenses, total_assigned_licenses: totalAssignedLicenses, unassigned_licenses: unassignedLicenses },
    ),
  ];

  return {
    title: "Webex collaboration governance",
    summary: {
      org_id: orgId ?? null,
      external_restricted: externalRestricted,
      file_controls_enabled: fileControlsEnabled,
      guest_restricted: guestRestricted,
      risky_recordings: riskyRecordings.length,
      retention_configured: retentionConfigured,
      sampled_rooms: rooms.length,
      rooms_without_classification: roomsWithoutClassification.length,
      insecure_webhooks: insecureWebhooks.length,
      admin_audit_events: adminAuditEvents.length,
      unassigned_licenses: unassignedLicenses,
      total_available_licenses: totalAvailableLicenses,
    },
    findings,
  };
}

export async function assessWebexMeetingHybridSecurity(
  client: Pick<
    WebexApiClient,
    "getResolvedConfig" | "listOrganizations" | "getAdminSettings" | "getMeetingPreferences" | "listMeetingSites" | "listMeetings" | "listHybridClusters" | "listHybridConnectors" | "listDevices" | "listWorkspaces"
  >,
  options: {
    meetingLimit?: number;
    deviceLimit?: number;
  } = {},
): Promise<WebexAssessmentResult> {
  const config = client.getResolvedConfig();
  const meetingLimit = clampNumber(options.meetingLimit, DEFAULT_MEETING_LIMIT, 1, 10000);
  const deviceLimit = clampNumber(options.deviceLimit, DEFAULT_DEVICE_LIMIT, 1, 10000);

  const orgs = await client.listOrganizations();
  const { orgId, note } = deriveOrgContext(config, orgs);
  const [adminSettings, meetingPreferences, meetingSites, meetings, hybridClusters, hybridConnectors, devices, workspaces] = await Promise.all([
    orgId ? client.getAdminSettings(orgId).catch(() => ({})) : Promise.resolve({}),
    client.getMeetingPreferences().catch(() => ({})),
    client.listMeetingSites().catch(() => []),
    client.listMeetings(meetingLimit).catch(() => []),
    client.listHybridClusters().catch(() => []),
    client.listHybridConnectors().catch(() => []),
    client.listDevices(deviceLimit).catch(() => []),
    client.listWorkspaces().catch(() => []),
  ]);

  const encryptionEnabled = orgSignalsEnabled(meetingPreferences, [
    ["e2eeEnabled"],
    ["encryption", "e2eeEnabled"],
    ["meetingSecurity", "e2eeEnabled"],
  ]) || orgSignalsEnabled(adminSettings, [
    ["calling", "srtpRequired"],
    ["calling", "encryptionRequired"],
  ]);

  const lobbyEnabled = orgSignalsEnabled(meetingPreferences, [
    ["lobbyEnabled"],
    ["meetingSecurity", "lobbyEnabled"],
    ["join", "lobbyEnabled"],
  ]) || meetingSites.some((site) => orgSignalsEnabled(site, [
    ["lobbyEnabled"],
    ["meetingSecurity", "lobbyEnabled"],
  ]));
  const passwordRequired = orgSignalsEnabled(meetingPreferences, [
    ["passwordRequired"],
    ["meetingSecurity", "passwordRequired"],
    ["join", "passwordRequired"],
  ]) || meetingSites.some((site) => orgSignalsEnabled(site, [
    ["passwordRequired"],
    ["meetingSecurity", "passwordRequired"],
  ]));

  const guestRestricted = orgSignalsDisabled(adminSettings, [
    ["guestAccessEnabled"],
    ["meetings", "guestAccessEnabled"],
  ]) || orgSignalsEnabled(adminSettings, [
    ["guestAccessRestricted"],
    ["meetings", "guestAccessRestricted"],
  ]);
  const virtualBackgroundEnforced = orgSignalsEnabled(meetingPreferences, [
    ["virtualBackgroundEnforced"],
    ["video", "virtualBackgroundEnforced"],
  ]);

  const unhealthyClusters = hybridClusters.filter((cluster) => !/active|healthy|online/i.test(asString(firstDefined(cluster, [
    ["status"],
    ["state"],
    ["health", "status"],
  ])) ?? ""));
  const inactiveConnectors = hybridConnectors.filter((connector) => !/active|connected|healthy/i.test(asString(firstDefined(connector, [
    ["status"],
    ["state"],
    ["connectionStatus"],
  ])) ?? ""));

  const outdatedDevices = devices.filter((device) => /eol|unsupported|outdated/i.test(asString(firstDefined(device, [
    ["firmwareStatus"],
    ["status", "firmware"],
    ["software", "status"],
  ])) ?? ""));
  const unmanagedDevices = devices.filter((device) => {
    const managedValue = firstDefined(device, [
      ["managed"],
      ["management", "managed"],
      ["isManaged"],
    ]);
    return managedValue !== undefined && asBoolean(managedValue) === false;
  });

  const meetingsWithoutGuards = meetings.filter((meeting) =>
    !orgSignalsEnabled(meeting, [["lobbyEnabled"], ["security", "lobbyEnabled"]])
    || !orgSignalsEnabled(meeting, [["passwordRequired"], ["security", "passwordRequired"]]),
  );

  const findings = [
    finding(
      "WEBEX-MTG-01",
      "Meeting and calling encryption defaults",
      "high",
      encryptionEnabled ? "pass" : "warn",
      encryptionEnabled
        ? "Meeting or calling encryption controls appeared enabled by default."
        : "Meeting or calling encryption controls were not clearly visible as enabled by default.",
      ["FedRAMP SC-8(1)", "SOC 2 CC6.7", "PCI-DSS 4.1", "CIS 14.4"],
      { encryption_enabled: encryptionEnabled },
    ),
    finding(
      "WEBEX-MTG-02",
      "Lobby and password defaults",
      "high",
      lobbyEnabled && passwordRequired ? "pass" : "fail",
      lobbyEnabled && passwordRequired
        ? "Meeting preferences exposed both lobby and password defaults."
        : "Meeting preferences did not clearly expose both lobby and password defaults as enabled.",
      ["FedRAMP AC-3", "FedRAMP IA-5", "SOC 2 CC6.1", "PCI-DSS 8.2.3"],
      { lobby_enabled: lobbyEnabled, password_required: passwordRequired, sampled_meetings_without_guards: meetingsWithoutGuards.length },
    ),
    finding(
      "WEBEX-MTG-03",
      "Guest and virtual background governance",
      "medium",
      guestRestricted && virtualBackgroundEnforced ? "pass" : guestRestricted ? "warn" : "fail",
      guestRestricted && virtualBackgroundEnforced
        ? "Guest meeting access appeared restricted and virtual backgrounds were enforced."
        : "Guest meeting access or virtual background governance was not fully visible.",
      ["FedRAMP AC-14", "SOC 2 CC6.1", "PCI-DSS 7.1.3", "CIS 16.7"],
      { guest_restricted: guestRestricted, virtual_background_enforced: virtualBackgroundEnforced },
    ),
    finding(
      "WEBEX-MTG-04",
      "Hybrid cluster and connector health",
      "high",
      unhealthyClusters.length === 0 && inactiveConnectors.length === 0 ? "pass" : unhealthyClusters.length > 0 ? "fail" : "warn",
      unhealthyClusters.length === 0 && inactiveConnectors.length === 0
        ? "All sampled hybrid clusters and connectors appeared healthy."
        : `${unhealthyClusters.length} clusters or ${inactiveConnectors.length} connectors appeared unhealthy or inactive.`,
      ["FedRAMP CM-8", "FedRAMP SI-4", "SOC 2 CC7.1", "PCI-DSS 10.6"],
      { unhealthy_clusters: unhealthyClusters.slice(0, 25).map((item) => asString(item.id)), inactive_connectors: inactiveConnectors.slice(0, 25).map((item) => asString(item.id)) },
    ),
    finding(
      "WEBEX-MTG-05",
      "Device firmware and management posture",
      "high",
      outdatedDevices.length === 0 && unmanagedDevices.length === 0 ? "pass" : outdatedDevices.length > 0 ? "fail" : "warn",
      outdatedDevices.length === 0 && unmanagedDevices.length === 0
        ? `Sampled devices and ${workspaces.length} workspaces did not expose firmware or management issues.`
        : `${outdatedDevices.length} devices appeared outdated and ${unmanagedDevices.length} devices appeared unmanaged.`,
      ["FedRAMP SI-2", "FedRAMP CM-8(3)", "SOC 2 CC6.8", "PCI-DSS 6.2"],
      { outdated_devices: outdatedDevices.slice(0, 25).map((item) => asString(item.id)), unmanaged_devices: unmanagedDevices.slice(0, 25).map((item) => asString(item.id)), workspaces: workspaces.length },
    ),
  ];

  return {
    title: "Webex meeting and hybrid security",
    summary: {
      org_id: orgId ?? null,
      encryption_enabled: encryptionEnabled,
      lobby_enabled: lobbyEnabled,
      password_required: passwordRequired,
      guest_restricted: guestRestricted,
      virtual_background_enforced: virtualBackgroundEnforced,
      unhealthy_clusters: unhealthyClusters.length,
      inactive_connectors: inactiveConnectors.length,
      outdated_devices: outdatedDevices.length,
      unmanaged_devices: unmanagedDevices.length,
      sampled_meetings_without_guards: meetingsWithoutGuards.length,
      workspaces: workspaces.length,
    },
    findings,
  };
}

function formatAccessCheckText(result: WebexAccessCheckResult): string {
  const rows = result.surfaces.map((surfaceItem) => [
    surfaceItem.name,
    surfaceItem.status,
    surfaceItem.count === undefined ? "-" : String(surfaceItem.count),
    surfaceItem.error ? surfaceItem.error.replace(/\s+/g, " ").slice(0, 80) : "",
  ]);

  return [
    `Webex access check: ${result.status}`,
    "",
    ...result.notes,
    "",
    formatTable(["Surface", "Status", "Count", "Note"], rows),
    "",
    `Next: ${result.recommendedNextStep}`,
  ].join("\n");
}

function formatAssessmentText(result: WebexAssessmentResult): string {
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

function buildExecutiveSummary(config: WebexResolvedConfig, assessments: WebexAssessmentResult[]): string {
  const findings = assessments.flatMap((assessment) => assessment.findings);
  const failCount = findings.filter((item) => item.status === "fail").length;
  const warnCount = findings.filter((item) => item.status === "warn").length;
  const passCount = findings.filter((item) => item.status === "pass").length;

  return [
    "# Webex Audit Bundle",
    "",
    `Org: ${config.orgId ?? "auto / unspecified"}`,
    `Generated: ${new Date().toISOString()}`,
    "",
    "## Result Counts",
    "",
    `- Failed controls: ${failCount}`,
    `- Warning controls: ${warnCount}`,
    `- Passing controls: ${passCount}`,
    "",
    "## Highest Priority Findings",
    "",
    ...findings
      .filter((item) => item.status !== "pass")
      .slice(0, 10)
      .map((item) => `- ${item.id} (${item.severity.toUpperCase()} / ${item.status.toUpperCase()}): ${item.summary}`),
  ].join("\n");
}

function buildControlMatrix(findings: WebexFinding[]): string {
  const rows = findings.map((item) => [
    item.id,
    item.severity.toUpperCase(),
    item.status.toUpperCase(),
    item.title,
    item.mappings.join(", "),
  ]);
  return [
    "# Webex Control Matrix",
    "",
    formatTable(["Control", "Severity", "Status", "Title", "Mappings"], rows),
  ].join("\n");
}

function buildBundleReadme(): string {
  return [
    "# Webex Evidence Bundle",
    "",
    "This bundle was generated by grclanker's native Webex tools.",
    "",
    "## Contents",
    "",
    "- `summary.md`: combined human-readable assessment output",
    "- `reports/executive-summary.md`: prioritized audit summary",
    "- `reports/control-matrix.md`: framework mapping matrix",
    "- `reports/*.md`: per-assessment markdown reports",
    "- `analysis/*.json`: normalized findings and assessment details",
    "- `core_data/access.json`: accessible Webex audit surface inventory",
    "- `metadata.json`: non-secret run metadata",
    "",
    "Credentials are never written into the bundle.",
  ].join("\n");
}

export async function exportWebexAuditBundle(
  client: Pick<
    WebexApiClient,
    | "getResolvedConfig"
    | "getMe"
    | "listOrganizations"
    | "listPeople"
    | "listRoles"
    | "getAdminSettings"
    | "getSecuritySettings"
    | "listEvents"
    | "listRecordings"
    | "listRooms"
    | "listWebhooks"
    | "listLicenses"
    | "getMeetingPreferences"
    | "listMeetingSites"
    | "listMeetings"
    | "listHybridClusters"
    | "listHybridConnectors"
    | "listDevices"
    | "listWorkspaces"
  >,
  config: WebexResolvedConfig,
  outputRoot: string,
  options: {
    peopleLimit?: number;
    maxAdmins?: number;
    eventLimit?: number;
    recordingLimit?: number;
    webhookLimit?: number;
    licenseLimit?: number;
    roomLimit?: number;
    meetingLimit?: number;
    deviceLimit?: number;
  } = {},
): Promise<WebexAuditBundleResult> {
  const access = await checkWebexAccess(client);
  const identity = await assessWebexIdentity(client, options);
  const collaboration = await assessWebexCollaborationGovernance(client, options);
  const meetingHybrid = await assessWebexMeetingHybridSecurity(client, options);
  const assessments = [identity, collaboration, meetingHybrid];
  const findings = assessments.flatMap((assessment) => assessment.findings);

  ensurePrivateDir(outputRoot);
  const outputDir = await nextAvailableAuditDir(
    outputRoot,
    `${safeDirName(config.orgId ?? "webex-org")}-audit-bundle`,
  );

  await writeSecureTextFile(outputDir, "README.md", `${buildBundleReadme()}\n`);
  await writeSecureTextFile(outputDir, "metadata.json", serializeJson({
    generated_at: new Date().toISOString(),
    org_id: config.orgId ?? null,
    source_chain: config.sourceChain,
  }));
  await writeSecureTextFile(
    outputDir,
    "summary.md",
    [
      formatAccessCheckText(access),
      "",
      formatAssessmentText(identity),
      "",
      formatAssessmentText(collaboration),
      "",
      formatAssessmentText(meetingHybrid),
    ].join("\n"),
  );
  await writeSecureTextFile(outputDir, "reports/executive-summary.md", `${buildExecutiveSummary(config, assessments)}\n`);
  await writeSecureTextFile(outputDir, "reports/control-matrix.md", `${buildControlMatrix(findings)}\n`);
  await writeSecureTextFile(outputDir, "reports/identity.md", `${formatAssessmentText(identity)}\n`);
  await writeSecureTextFile(outputDir, "reports/collaboration-governance.md", `${formatAssessmentText(collaboration)}\n`);
  await writeSecureTextFile(outputDir, "reports/meeting-hybrid-security.md", `${formatAssessmentText(meetingHybrid)}\n`);
  await writeSecureTextFile(outputDir, "analysis/findings.json", serializeJson(findings));
  await writeSecureTextFile(outputDir, "analysis/identity.json", serializeJson(identity));
  await writeSecureTextFile(outputDir, "analysis/collaboration-governance.json", serializeJson(collaboration));
  await writeSecureTextFile(outputDir, "analysis/meeting-hybrid-security.json", serializeJson(meetingHybrid));
  await writeSecureTextFile(outputDir, "core_data/access.json", serializeJson(access));

  const zipPath = resolveSecureOutputPath(outputRoot, `${safeDirName(config.orgId ?? "webex-org")}-audit-bundle.zip`);
  await createZipArchive(outputDir, zipPath);

  return {
    outputDir,
    zipPath,
    fileCount: await countFilesRecursively(outputDir),
    findingCount: findings.length,
  };
}

function normalizeCheckAccessArgs(args: unknown): CheckAccessArgs {
  const value = asObject(args) ?? {};
  return {
    token: asString(value.token),
    org_id: asString(value.org_id),
    base_url: asString(value.base_url),
    timeout_seconds: asNumber(value.timeout_seconds),
  };
}

function normalizeIdentityArgs(args: unknown): IdentityArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeCheckAccessArgs(args),
    people_limit: asNumber(value.people_limit),
    max_admins: asNumber(value.max_admins),
  };
}

function normalizeCollaborationArgs(args: unknown): CollaborationArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeCheckAccessArgs(args),
    event_limit: asNumber(value.event_limit),
    recording_limit: asNumber(value.recording_limit),
    webhook_limit: asNumber(value.webhook_limit),
    license_limit: asNumber(value.license_limit),
    room_limit: asNumber(value.room_limit),
  };
}

function normalizeMeetingHybridArgs(args: unknown): MeetingHybridArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeCheckAccessArgs(args),
    meeting_limit: asNumber(value.meeting_limit),
    device_limit: asNumber(value.device_limit),
  };
}

function normalizeExportAuditBundleArgs(args: unknown): ExportAuditBundleArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeIdentityArgs(args),
    event_limit: asNumber(value.event_limit),
    recording_limit: asNumber(value.recording_limit),
    webhook_limit: asNumber(value.webhook_limit),
    license_limit: asNumber(value.license_limit),
    room_limit: asNumber(value.room_limit),
    meeting_limit: asNumber(value.meeting_limit),
    device_limit: asNumber(value.device_limit),
    output_dir: asString(value.output_dir) ?? asString(value.output),
  };
}

function createClient(args: CheckAccessArgs): WebexApiClient {
  return new WebexApiClient(resolveWebexConfiguration(args));
}

const authParams = {
  token: Type.Optional(Type.String({ description: "Webex access token. Defaults to WEBEX_TOKEN." })),
  org_id: Type.Optional(Type.String({ description: "Webex organization ID. Defaults to WEBEX_ORG_ID or auto-detect when only one org is visible." })),
  base_url: Type.Optional(Type.String({ description: "Webex API base URL. Defaults to https://webexapis.com/v1." })),
  timeout_seconds: Type.Optional(Type.Number({ description: "HTTP timeout in seconds. Defaults to 30.", default: 30 })),
};

export function registerWebexTools(pi: any): void {
  pi.registerTool({
    name: "webex_check_access",
    label: "Check Webex audit access",
    description:
      "Validate read-only Webex access across people, organizations, meetings, recordings, events, admin settings, hybrid, devices, and webhooks.",
    parameters: Type.Object(authParams),
    prepareArguments: normalizeCheckAccessArgs,
    async execute(_toolCallId: string, args: CheckAccessArgs) {
      try {
        const result = await checkWebexAccess(createClient(args));
        return textResult(formatAccessCheckText(result), { tool: "webex_check_access", ...result });
      } catch (error) {
        return errorResult(
          `Webex access check failed: ${error instanceof Error ? error.message : String(error)}`,
          { tool: "webex_check_access" },
        );
      }
    },
  });

  pi.registerTool({
    name: "webex_assess_identity",
    label: "Assess Webex identity posture",
    description:
      "Assess Webex identity posture across SSO enforcement, admin MFA coverage, compliance-role assignment, and administrative privilege concentration.",
    parameters: Type.Object({
      ...authParams,
      people_limit: Type.Optional(Type.Number({ description: "Maximum people to inspect. Defaults to 1000.", default: 1000 })),
      max_admins: Type.Optional(Type.Number({ description: "Maximum acceptable admin users before warning. Defaults to 10.", default: 10 })),
    }),
    prepareArguments: normalizeIdentityArgs,
    async execute(_toolCallId: string, args: IdentityArgs) {
      try {
        const result = await assessWebexIdentity(createClient(args), {
          peopleLimit: args.people_limit,
          maxAdmins: args.max_admins,
        });
        return textResult(formatAssessmentText(result), { tool: "webex_assess_identity", ...result });
      } catch (error) {
        return errorResult(
          `Webex identity assessment failed: ${error instanceof Error ? error.message : String(error)}`,
          { tool: "webex_assess_identity" },
        );
      }
    },
  });

  pi.registerTool({
    name: "webex_assess_collaboration_governance",
    label: "Assess Webex collaboration governance",
    description:
      "Assess Webex collaboration governance across external communications, file sharing and DLP, recording retention, room classification, webhook security, admin audit visibility, and license utilization.",
    parameters: Type.Object({
      ...authParams,
      event_limit: Type.Optional(Type.Number({ description: "Maximum events to inspect. Defaults to 500.", default: 500 })),
      recording_limit: Type.Optional(Type.Number({ description: "Maximum recordings to inspect. Defaults to 200.", default: 200 })),
      webhook_limit: Type.Optional(Type.Number({ description: "Maximum webhooks to inspect. Defaults to 200.", default: 200 })),
      license_limit: Type.Optional(Type.Number({ description: "Maximum licenses to inspect. Defaults to 200.", default: 200 })),
      room_limit: Type.Optional(Type.Number({ description: "Maximum rooms to inspect. Defaults to 500.", default: 500 })),
    }),
    prepareArguments: normalizeCollaborationArgs,
    async execute(_toolCallId: string, args: CollaborationArgs) {
      try {
        const result = await assessWebexCollaborationGovernance(createClient(args), {
          eventLimit: args.event_limit,
          recordingLimit: args.recording_limit,
          webhookLimit: args.webhook_limit,
          licenseLimit: args.license_limit,
          roomLimit: args.room_limit,
        });
        return textResult(formatAssessmentText(result), { tool: "webex_assess_collaboration_governance", ...result });
      } catch (error) {
        return errorResult(
          `Webex collaboration governance assessment failed: ${error instanceof Error ? error.message : String(error)}`,
          { tool: "webex_assess_collaboration_governance" },
        );
      }
    },
  });

  pi.registerTool({
    name: "webex_assess_meeting_hybrid_security",
    label: "Assess Webex meeting and hybrid security",
    description:
      "Assess Webex meeting and hybrid security across encryption defaults, lobby and password controls, guest governance, hybrid cluster health, and device management posture.",
    parameters: Type.Object({
      ...authParams,
      meeting_limit: Type.Optional(Type.Number({ description: "Maximum meetings to inspect. Defaults to 200.", default: 200 })),
      device_limit: Type.Optional(Type.Number({ description: "Maximum devices to inspect. Defaults to 500.", default: 500 })),
    }),
    prepareArguments: normalizeMeetingHybridArgs,
    async execute(_toolCallId: string, args: MeetingHybridArgs) {
      try {
        const result = await assessWebexMeetingHybridSecurity(createClient(args), {
          meetingLimit: args.meeting_limit,
          deviceLimit: args.device_limit,
        });
        return textResult(formatAssessmentText(result), { tool: "webex_assess_meeting_hybrid_security", ...result });
      } catch (error) {
        return errorResult(
          `Webex meeting and hybrid assessment failed: ${error instanceof Error ? error.message : String(error)}`,
          { tool: "webex_assess_meeting_hybrid_security" },
        );
      }
    },
  });

  pi.registerTool({
    name: "webex_export_audit_bundle",
    label: "Export Webex audit bundle",
    description:
      "Export a Webex audit package with access checks, identity findings, collaboration governance, meeting and hybrid security findings, markdown reports, JSON analysis, and a zip archive.",
    parameters: Type.Object({
      ...authParams,
      output_dir: Type.Optional(Type.String({ description: `Output root. Defaults to ${DEFAULT_OUTPUT_DIR}.` })),
      people_limit: Type.Optional(Type.Number({ description: "Maximum people to inspect. Defaults to 1000.", default: 1000 })),
      max_admins: Type.Optional(Type.Number({ description: "Maximum acceptable admin users before warning. Defaults to 10.", default: 10 })),
      event_limit: Type.Optional(Type.Number({ description: "Maximum events to inspect. Defaults to 500.", default: 500 })),
      recording_limit: Type.Optional(Type.Number({ description: "Maximum recordings to inspect. Defaults to 200.", default: 200 })),
      webhook_limit: Type.Optional(Type.Number({ description: "Maximum webhooks to inspect. Defaults to 200.", default: 200 })),
      license_limit: Type.Optional(Type.Number({ description: "Maximum licenses to inspect. Defaults to 200.", default: 200 })),
      room_limit: Type.Optional(Type.Number({ description: "Maximum rooms to inspect. Defaults to 500.", default: 500 })),
      meeting_limit: Type.Optional(Type.Number({ description: "Maximum meetings to inspect. Defaults to 200.", default: 200 })),
      device_limit: Type.Optional(Type.Number({ description: "Maximum devices to inspect. Defaults to 500.", default: 500 })),
    }),
    prepareArguments: normalizeExportAuditBundleArgs,
    async execute(_toolCallId: string, args: ExportAuditBundleArgs) {
      try {
        const config = resolveWebexConfiguration(args);
        const outputRoot = resolve(process.cwd(), args.output_dir?.trim() || DEFAULT_OUTPUT_DIR);
        const result = await exportWebexAuditBundle(new WebexApiClient(config), config, outputRoot, {
          peopleLimit: args.people_limit,
          maxAdmins: args.max_admins,
          eventLimit: args.event_limit,
          recordingLimit: args.recording_limit,
          webhookLimit: args.webhook_limit,
          licenseLimit: args.license_limit,
          roomLimit: args.room_limit,
          meetingLimit: args.meeting_limit,
          deviceLimit: args.device_limit,
        });
        return textResult(
          [
            "Webex audit bundle exported.",
            `Output dir: ${result.outputDir}`,
            `Zip archive: ${result.zipPath}`,
            `Findings: ${result.findingCount}`,
            `Files: ${result.fileCount}`,
          ].join("\n"),
          {
            tool: "webex_export_audit_bundle",
            output_dir: result.outputDir,
            zip_path: result.zipPath,
            finding_count: result.findingCount,
            file_count: result.fileCount,
          },
        );
      } catch (error) {
        return errorResult(
          `Webex audit bundle export failed: ${error instanceof Error ? error.message : String(error)}`,
          { tool: "webex_export_audit_bundle" },
        );
      }
    },
  });
}
