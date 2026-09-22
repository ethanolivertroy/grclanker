/**
 * Cloudflare security posture tools for grclanker.
 *
 * Read-only inspection of Cloudflare accounts and zones through the v4 API:
 * token and member posture, Zero Trust Access, WAF and DDoS rulesets, TLS,
 * DNS, security headers, traffic controls, and exportable evidence bundles.
 *
 * Every endpoint, phase, setting id, and response field read here is
 * traceable to the page listed in CLOUDFLARE_API_DOCS.
 */
import {
  createWriteStream,
  existsSync,
  lstatSync,
  mkdirSync,
  realpathSync,
} from "node:fs";
import { chmod, readdir, writeFile } from "node:fs/promises";
import { basename, dirname, join, relative, resolve } from "node:path";
import { ZipArchive } from "archiver";
import { Type } from "@sinclair/typebox";
import { errorResult, formatTable, textResult } from "./shared.js";

type FetchImpl = typeof fetch;
type JsonRecord = Record<string, unknown>;

const DEFAULT_OUTPUT_DIR = "./export/cloudflare";
const DEFAULT_TIMEOUT_MS = 30_000;
const DEFAULT_ZONE_LIMIT = 20;
const DEFAULT_MEMBER_LIMIT = 200;
const DEFAULT_TOKEN_LIMIT = 200;
const DEFAULT_AUDIT_LIMIT = 200;
const DEFAULT_HOSTNAME_ASSOCIATION_LIMIT = 5000;
const DEFAULT_DNS_RECORD_LIMIT = 500;
const DEFAULT_MAX_SUPER_ADMINS = 2;
const HSTS_MIN_MAX_AGE_SECONDS = 15_552_000;
const STALE_IP_RULE_DAYS = 365;
const CERTIFICATE_EXPIRY_WARNING_DAYS = 30;
const AUDIT_LOG_LOOKBACK_DAYS = 30;
const CURSOR_PAGE_BUDGET = 100;

/**
 * Documentation pages on developers.cloudflare.com/api that every request and
 * response field in this module is traced to.
 */
export const CLOUDFLARE_API_DOCS = {
  accountsList: "https://developers.cloudflare.com/api/resources/accounts/methods/list/",
  zonesList: "https://developers.cloudflare.com/api/resources/zones/methods/list/",
  zoneSettingGet: "https://developers.cloudflare.com/api/resources/zones/subresources/settings/methods/get/",
  rulesetsList: "https://developers.cloudflare.com/api/resources/rulesets/methods/list/",
  rulesetPhaseEntrypoint: "https://developers.cloudflare.com/api/resources/rulesets/subresources/phases/methods/get/",
  dnsRecordsList: "https://developers.cloudflare.com/api/resources/dns/subresources/records/methods/list/",
  dnssecGet: "https://developers.cloudflare.com/api/resources/dns/subresources/dnssec/methods/get/",
  certificatePacksList: "https://developers.cloudflare.com/api/resources/ssl/subresources/certificate_packs/methods/list/",
  universalSslSettings: "https://developers.cloudflare.com/api/resources/ssl/subresources/universal/subresources/settings/methods/get/",
  originTlsClientAuthSettings: "https://developers.cloudflare.com/api/resources/origin_tls_client_auth/subresources/settings/methods/get/",
  originTlsClientAuthHostname: "https://developers.cloudflare.com/api/resources/origin_tls_client_auth/subresources/hostnames/methods/get/",
  originTlsClientAuthHostnamesList: "https://github.com/cloudflare/api-schemas/blob/main/openapi.json#per-hostname-authenticated-origin-pull-list-hostname-associations",
  zeroTrustAccountGet: "https://developers.cloudflare.com/api/resources/zero_trust/subresources/gateway/methods/list/",
  zoneSubscriptionGet: "https://developers.cloudflare.com/api/resources/zones/subresources/subscriptions/methods/get/",
  botManagementGet: "https://developers.cloudflare.com/api/resources/bot_management/methods/get/",
  rateLimitsListLegacy: "https://developers.cloudflare.com/api/resources/rate_limits/methods/list/",
  pageRulesList: "https://developers.cloudflare.com/api/resources/page_rules/methods/list/",
  firewallRulesListLegacy: "https://developers.cloudflare.com/api/resources/firewall/subresources/rules/methods/list/",
  accessApplicationsList: "https://developers.cloudflare.com/api/resources/zero_trust/subresources/access/subresources/applications/methods/list/",
  accessPoliciesList: "https://developers.cloudflare.com/api/resources/zero_trust/subresources/access/subresources/policies/methods/list/",
  identityProvidersList: "https://developers.cloudflare.com/api/resources/zero_trust/subresources/identity_providers/methods/list/",
  gatewayRulesList: "https://developers.cloudflare.com/api/resources/zero_trust/subresources/gateway/subresources/rules/methods/list/",
  auditLogsList: "https://developers.cloudflare.com/api/resources/audit_logs/methods/list/",
  membersList: "https://developers.cloudflare.com/api/resources/accounts/subresources/members/methods/list/",
  userTokensList: "https://developers.cloudflare.com/api/resources/user/subresources/tokens/methods/list/",
  userTokenVerify: "https://developers.cloudflare.com/api/resources/user/subresources/tokens/methods/verify/",
  userTokenGet: "https://developers.cloudflare.com/api/resources/user/subresources/tokens/methods/get/",
  accountTokensList: "https://developers.cloudflare.com/api/resources/accounts/subresources/tokens/methods/list/",
  ipAccessRulesList: "https://developers.cloudflare.com/api/resources/firewall/subresources/access_rules/methods/list/",
} as const;

export const CLOUDFLARE_RULESET_PHASES = {
  ddosL7: "ddos_l7",
  firewallManaged: "http_request_firewall_managed",
  firewallCustom: "http_request_firewall_custom",
  rateLimit: "http_ratelimit",
  responseHeadersTransform: "http_response_headers_transform",
} as const;

export const CLOUDFLARE_ZONE_SETTING_IDS = [
  "ssl",
  "min_tls_version",
  "always_use_https",
  "automatic_https_rewrites",
  "security_header",
  "browser_check",
  "email_obfuscation",
  "tls_client_auth",
] as const;

const REQUIRED_SECURITY_HEADERS = [
  "content-security-policy",
  "x-frame-options",
  "x-content-type-options",
  "referrer-policy",
] as const;

export interface CloudflareResolvedConfig {
  apiToken?: string;
  apiKey?: string;
  email?: string;
  accountId?: string;
  baseUrl: string;
  timeoutMs: number;
  authMethod: "token" | "global_key";
  sourceChain: string[];
}

export interface CloudflareAccessSurface {
  name: string;
  scope: "user" | "account" | "zone";
  endpoint: string;
  /**
   * readable: the probe completed; not_readable: the probe itself failed; not_configured: the probe has no
   * target because a readable parent inventory was empty or no account id is set; not_attempted: the probe
   * was never sent because its parent inventory could not be read (the error names the parent).
   */
  status: "readable" | "not_readable" | "not_configured" | "not_attempted";
  /** Items the probe saw; null when the probe never completed, so a denial is never mistaken for an empty inventory. */
  count?: number | null;
  /** HTTP status the failing probe observed; null when the failure was not an HTTP response. */
  http_status?: number | null;
  error?: string;
}

export interface CloudflareAccessCheckResult {
  status: "healthy" | "limited";
  authMethod: CloudflareResolvedConfig["authMethod"];
  accountId?: string;
  surfaces: CloudflareAccessSurface[];
  notes: string[];
  recommendedNextStep: string;
}

export type CloudflareFindingStatus = "pass" | "warn" | "fail" | "manual";

export interface CloudflareFinding {
  id: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  status: CloudflareFindingStatus;
  summary: string;
  evidence?: JsonRecord;
  mappings: string[];
  specControl?: number;
}

export interface CloudflareAssessmentResult {
  title: string;
  summary: JsonRecord;
  findings: CloudflareFinding[];
  errors: string[];
}

export interface CloudflareAuditBundleResult {
  outputDir: string;
  zipPath: string;
  fileCount: number;
  findingCount: number;
  errorCount: number;
}

export interface CloudflarePagedList {
  items: JsonRecord[];
  totalCount?: number;
  truncated: boolean;
}

type ListResult = JsonRecord[] | CloudflarePagedList;

export interface CloudflareReader {
  getResolvedConfig(): CloudflareResolvedConfig;
  verifyCurrentToken(): Promise<JsonRecord | null>;
  getUserToken(tokenId: string): Promise<JsonRecord | null>;
  listAccounts(limit?: number): Promise<ListResult>;
  listZones(limit?: number): Promise<ListResult>;
  listUserTokens(limit?: number): Promise<ListResult>;
  listAccountTokens(accountId: string, limit?: number): Promise<ListResult>;
  getZoneSettings(zoneId: string): Promise<JsonRecord[]>;
  listFirewallRules(zoneId: string): Promise<ListResult>;
  listZoneRulesets(zoneId: string): Promise<ListResult>;
  getZoneEntrypointRuleset(zoneId: string, phase: string): Promise<JsonRecord | null>;
  listDnsRecords(zoneId: string, limit?: number): Promise<ListResult>;
  getDnssec(zoneId: string): Promise<JsonRecord | null>;
  listCertificatePacks(zoneId: string): Promise<ListResult>;
  getUniversalSslSettings(zoneId: string): Promise<JsonRecord | null>;
  getOriginTlsClientAuthSettings(zoneId: string): Promise<JsonRecord | null>;
  listOriginTlsClientAuthHostnames(zoneId: string, limit?: number): Promise<ListResult>;
  getZoneSubscription(zoneId: string): Promise<JsonRecord | null>;
  getZeroTrustAccount(accountId: string): Promise<JsonRecord | null>;
  listRateLimits(zoneId: string): Promise<ListResult>;
  listPageRules(zoneId: string): Promise<ListResult>;
  getBotManagement(zoneId: string): Promise<JsonRecord | null>;
  listAccessApplications(accountId: string): Promise<ListResult>;
  listAccessPolicies(accountId: string): Promise<ListResult>;
  listIdentityProviders(accountId: string): Promise<ListResult>;
  listGatewayRules(accountId: string): Promise<ListResult>;
  listAuditLogs(accountId: string, limit?: number): Promise<ListResult>;
  listMembers(accountId: string, limit?: number): Promise<ListResult>;
  listIpAccessRules(accountId: string): Promise<ListResult>;
}

type CheckAccessArgs = {
  api_token?: string;
  api_key?: string;
  email?: string;
  account_id?: string;
  base_url?: string;
  timeout_seconds?: number;
};

type IdentityArgs = CheckAccessArgs & {
  max_super_admins?: number;
  member_limit?: number;
  token_limit?: number;
  zone_limit?: number;
};

type ZoneSecurityArgs = CheckAccessArgs & {
  zone_limit?: number;
};

type TrafficArgs = CheckAccessArgs & {
  zone_limit?: number;
  audit_limit?: number;
};

type ExportAuditBundleArgs = CheckAccessArgs & {
  output_dir?: string;
  max_super_admins?: number;
  member_limit?: number;
  token_limit?: number;
  zone_limit?: number;
  audit_limit?: number;
};

type AssessmentOptions = {
  maxSuperAdmins?: number;
  memberLimit?: number;
  tokenLimit?: number;
  zoneLimit?: number;
  auditLimit?: number;
};

function asObject(value: unknown): JsonRecord | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
  return value as JsonRecord;
}

function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function asRecordArray(value: unknown): JsonRecord[] {
  return asArray(value).map(asObject).filter((item): item is JsonRecord => Boolean(item));
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
  return typeof value === "boolean" ? value : undefined;
}

function asDate(value: unknown): Date | undefined {
  const text = asString(value);
  if (!text) return undefined;
  const parsed = new Date(text);
  return Number.isNaN(parsed.getTime()) ? undefined : parsed;
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

/** Every JSON file the bundle writes goes through the snapshot walk first (rule 9 at every depth, with the cap). */
function serializeJson(value: unknown): string {
  return `${JSON.stringify(scrubSnapshotValue(value), null, 2)}\n`;
}

function safeDirName(value: string): string {
  const normalized = value
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 80);
  return normalized || "cloudflare";
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
  for (let attempt = 1; attempt <= 50; attempt += 1) {
    const suffix = attempt === 1 ? "" : `-${attempt}`;
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

export function resolveCloudflareConfiguration(
  input: JsonRecord = {},
  env: NodeJS.ProcessEnv = process.env,
): CloudflareResolvedConfig {
  const sourceChain: string[] = [];
  const apiToken = asString(input.api_token)
    ?? asString(input.token)
    ?? asString(env.CLOUDFLARE_API_TOKEN);
  if (apiToken) {
    sourceChain.push(asString(input.api_token) || asString(input.token) ? "arguments-api-token" : "environment-api-token");
  }

  const apiKey = asString(input.api_key)
    ?? asString(env.CLOUDFLARE_API_KEY);
  const email = asString(input.email)
    ?? asString(env.CLOUDFLARE_EMAIL);

  if (!apiToken && !(apiKey && email)) {
    throw new Error("Provide CLOUDFLARE_API_TOKEN or the CLOUDFLARE_EMAIL + CLOUDFLARE_API_KEY pair.");
  }

  if (!apiToken) {
    sourceChain.push(asString(input.api_key) ? "arguments-api-key" : "environment-api-key");
    sourceChain.push(asString(input.email) ? "arguments-email" : "environment-email");
  }

  const accountId = asString(input.account_id)
    ?? asString(env.CLOUDFLARE_ACCOUNT_ID);
  if (accountId) sourceChain.push(asString(input.account_id) ? "arguments-account-id" : "environment-account-id");

  const baseUrl = normalizeBaseUrl(
    asString(input.base_url) ?? asString(env.CLOUDFLARE_API_BASE_URL) ?? "https://api.cloudflare.com/client/v4",
  );
  if (asString(input.base_url)) sourceChain.push("arguments-base-url");
  else if (asString(env.CLOUDFLARE_API_BASE_URL)) sourceChain.push("environment-base-url");
  else sourceChain.push("default-base-url");

  return {
    apiToken,
    apiKey,
    email,
    accountId,
    baseUrl,
    timeoutMs: parseTimeoutSeconds(asNumber(input.timeout_seconds) ?? asNumber(env.CLOUDFLARE_TIMEOUT)),
    authMethod: apiToken ? "token" : "global_key",
    sourceChain: [...new Set(sourceChain)],
  };
}

function buildHeaders(config: CloudflareResolvedConfig): Record<string, string> {
  if (config.authMethod === "token" && config.apiToken) {
    return {
      accept: "application/json",
      authorization: `Bearer ${config.apiToken}`,
    };
  }

  return {
    accept: "application/json",
    "x-auth-email": config.email ?? "",
    "x-auth-key": config.apiKey ?? "",
  };
}

function extractResultArray(payload: unknown): JsonRecord[] {
  const object = asObject(payload);
  return Array.isArray(object?.result) ? asRecordArray(object.result) : [];
}

function extractResultObject(payload: unknown): JsonRecord | undefined {
  const object = asObject(payload);
  return asObject(object?.result);
}

function cloudflareErrorSummary(payload: unknown): string | undefined {
  const object = asObject(payload);
  const errors = asRecordArray(object?.errors)
    .map((record) => asString(record.message))
    .filter((item): item is string => Boolean(item));
  return errors.length > 0 ? errors.join("; ") : undefined;
}

/**
 * Describes a non-JSON body by content type and byte length only. Proxy and
 * WAF pages can echo request headers, so the body text itself is never kept.
 */
function describeNonJsonBody(contentType: string | null, rawText: string): string | undefined {
  if (rawText.length === 0) return undefined;
  return `non-JSON body (${contentType?.split(";")[0]?.trim() || "unknown content type"}, ${Buffer.byteLength(rawText, "utf8")} bytes)`;
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
// identifiers. The bearer ids are the one override to that identifier suffix (CodeRabbit r4077259415 on #78): a key
// ending in `secret_id` (a Vault AppRole secret id: `secret_id`, `VAULT_SECRET_ID`, `role_secret_id`, `roleSecretId`)
// or in a session id (`session_id`, `sid`, `sessid`, `jsessionid`, `PHPSESSID`) authenticates rather than identifies,
// so it is a credential key despite ending in `id` and its value goes whatever its shape, UUID included, while
// `client_id`, `tenant_id`, `access_key_id`, `key_id`, and `secret_name` keep theirs unless the value's own shape goes.
const ERROR_CREDENTIAL_WORDS =
  "token|secret[_-]?id|secret|passw(?:or)?d|pwd|api[_-]?key|apikey|auth[_-]?key|auth[_-]?email|session(?:[_-]?id)?|sessid|sid|cookie|csrftoken|authorization|auth|signature|sig|nonce|credentials?|access[_-]?key|private[_-]?key|skey|ikey";
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
/**
 * A quoted phrase that is a scheme word and one value (`"Bearer prod-token"`, `\"Token prod-key\"`, `'Basic abc'`):
 * the quotes delimit a header value being quoted, so the value goes whatever its shape (reviewer D round 5 depth
 * control, the quoted name-shaped bearer), where the same phrase bare in prose (`sent as Bearer prod-token`) is
 * judged by the scheme rule's shape test. A quoted phrase of several words after the scheme is prose and stays.
 */
const ERROR_QUOTED_SCHEME_PHRASE_PATTERN = new RegExp(String.raw`(\\?(["']))(${ERROR_SCHEME_PATTERN})(\s+)((?:(?!\\?\2)[^\s"'\\])+)(\\?\2)`, "gi");
const QUOTED_SCHEME_PHRASE_REPLACEMENT = `$1$3$4${REDACTED_ERROR_VALUE}$6`;

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
 * never ends in a credential word, so its value is judged by its own shape alone; the bearer ids (`secret_id` and
 * the session ids, see ERROR_CREDENTIAL_WORDS) are credential words, so that suffix test never reaches them.
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

/**
 * Carrier rules: a value is removed because of what carries it (a quoted header or pair value, an authorization
 * scheme, a JWT or PEM shape), not because of its own shape. The free-form header carriers (Cookie, Set-Cookie,
 * X-Auth-Key, X-Auth-Email) run first in scrubHeaderCarriers, so these only ever see the marker.
 */
const CARRIER_TEXT_PATTERNS: ReadonlyArray<readonly [RegExp, string]> = [
  // Quoted header and pair values first, whatever their shape, so the scheme and pair rules see the marker.
  [ERROR_QUOTED_CREDENTIAL_PATTERN, QUOTED_VALUE_REPLACEMENT],
  [ERROR_QUOTED_SCHEME_PATTERN, QUOTED_VALUE_REPLACEMENT],
  [ERROR_QUOTED_SCHEME_PHRASE_PATTERN, QUOTED_SCHEME_PHRASE_REPLACEMENT],
  // Authorization scheme values wherever they appear (headers, cookies, HTML, JSON messages); the value must be
  // long, carry a digit or base64 symbol, or change case inside the word, so prose such as "Basic authentication"
  // and "Bearer Token" stays.
  // Case-sensitive so the inner-case-change test means what it says (under /i, [a-z][A-Z] is any two letters).
  [/\b(Bearer|bearer|BEARER|Basic|basic|BASIC|Digest|digest|Negotiate|negotiate|SSWS|Token|token|TOKEN|ApiKey|apikey|APIKEY|Api-Key|api-key)\s+(?=[A-Za-z0-9\-._~+/=:]{16,}|[A-Za-z0-9\-._~+/=:]*[\d+/=]|[A-Za-z0-9\-._~+/=:]*[a-z][A-Z])[A-Za-z0-9\-._~+/=:]{6,}/g, `$1 ${REDACTED_ERROR_VALUE}`],
  // JWT-shaped strings.
  [/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g, REDACTED_ERROR_VALUE],
  // PEM blocks, whole or cut off.
  [/-----BEGIN [A-Z0-9 ]+-----[\s\S]*?(?:-----END [A-Z0-9 ]+-----|$)/g, REDACTED_ERROR_VALUE],
];

/** Bare-shape rules: a value is removed for its own shape, wherever it stands. Error text only; a snapshot keeps its identifiers. */
const BARE_SHAPE_PATTERNS: ReadonlyArray<readonly [RegExp, string]> = [
  // AWS access key ids, 40-character secret access keys, long secret-shaped blobs, and hex digests.
  [/\b(?:AKIA|ASIA|AROA|AIDA|AGPA|ANPA|ANVA|APKA|ABIA|ACCA)[A-Z0-9]{16}\b/g, REDACTED_ERROR_VALUE],
  [/(?<![A-Za-z0-9/+=])[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+=])/g, REDACTED_ERROR_VALUE],
  // Long blobs must carry a digit so camelCase identifiers survive.
  [/(?<![A-Za-z0-9+_=-])(?=[A-Za-z0-9+_-]*\d)[A-Za-z0-9+_-]{40,}={0,2}(?![A-Za-z0-9+_=-])/g, REDACTED_ERROR_VALUE],
  [/\b[a-f0-9]{32,}\b/gi, REDACTED_ERROR_VALUE],
];

const ERROR_TEXT_PATTERNS: ReadonlyArray<readonly [RegExp, string]> = [...CARRIER_TEXT_PATTERNS, ...BARE_SHAPE_PATTERNS];

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
 * Rule 9 sink for error text. CloudflareApiError scrubs its own message and errorMessage(), the only
 * conversion from a thrown error to recorded text (read outcomes, access surfaces, zone setting reads,
 * tool results), runs the same pass, so no path can carry a credential echoed by an upstream error
 * body, a transport error, or a URL into the audit output.
 */
export function redactErrorText(text: string): string {
  let scrubbed = scrubCarriers(text);
  for (const [pattern, replacement] of BARE_SHAPE_PATTERNS) {
    scrubbed = scrubbed.replace(pattern, replacement);
  }
  scrubbed = scrubCredentialPairs(scrubbed);
  return scrubLongTokens(scrubbed);
}

/** The carrier passes shared by error text and snapshot strings: configured secrets, URL userinfo and query, header carriers, quoted values, schemes, JWT and PEM shapes. */
function scrubCarriers(text: string): string {
  let scrubbed = scrubConfiguredSecrets(text);
  scrubbed = scrubbed.replace(ERROR_URL_PATTERN, (_match, scheme: string, hostPath: string, query?: string) =>
    `${scheme}${hostPath}${query ? `?${REDACTED_ERROR_VALUE}` : ""}`,
  );
  scrubbed = scrubHeaderCarriers(scrubbed);
  for (const [pattern, replacement] of CARRIER_TEXT_PATTERNS) {
    scrubbed = scrubbed.replace(pattern, replacement);
  }
  return scrubbed;
}

/**
 * Rule 9 data-side scrub for a string kept in a snapshot (reviewer D round 5 depth control): the carrier rules of
 * redactErrorText (the configured secrets in every encoded form, URL userinfo and query strings, the free-form
 * header carriers, quoted header and pair values, authorization schemes, JWT and PEM shapes, and credential-named
 * pairs) without its bare-shape rules, so a value is removed for what carries it and an identifier, a digest, or a
 * key id that is data stays data.
 */
export function redactCarrierText(text: string): string {
  return scrubCredentialPairs(scrubCarriers(text));
}

/** Nesting past which an object or array in a snapshot is replaced by the marker; the value handed to the walker is depth 1. */
const SNAPSHOT_DEPTH_CAP = 32;
/**
 * Field names whose value in API data is a secret whatever its shape. Exact names, not the suffix rule of the error
 * text pair rule: a snapshot's own keys name collections about credentials (`tokens`, `credentials`,
 * `passwordCredentials`, `webauthncredentials`, `hardtoken`) that carry metadata, and those stay.
 */
const SNAPSHOT_SECRET_KEY_PATTERN =
  /^(?:secret[_-]?key|skey|secret|client[_-]?secret|api[_-]?secret|password|passwd|passphrase|private[_-]?key|access[_-]?token|refresh[_-]?token|id[_-]?token|authorization|cookie|set-cookie|x-auth-key|api[_-]?key|x-api-key)$/i;
/**
 * The bearer-id override for snapshot keys (CodeRabbit r4077259415 on #78): a key ending in `secret_id`, any prefix,
 * casing, and separator (`secret_id`, `VAULT_SECRET_ID`, `role_secret_id`, `roleSecretId`), holds a Vault AppRole
 * secret id, which authenticates rather than identifies, so its value is the marker whatever its shape; an `_id` key
 * that identifies (`client_id`, `tenant_id`, `key_id`, `user_id`) is data and stays.
 */
const SNAPSHOT_BEARER_ID_KEY_PATTERN = /secret[_-]?id$/i;

/** The snapshot walk behind scrubSnapshotValue and the integration's own data walkers: one key rule, one string rule, one cap. */
function scrubSnapshotTree(value: unknown, isSecretKey: (key: string) => boolean, depth: number): unknown {
  if (typeof value === "string") return redactCarrierText(value);
  if (value === null || typeof value !== "object") return value;
  if (value instanceof Date) return value;
  if (depth > SNAPSHOT_DEPTH_CAP) return REDACTED_ERROR_VALUE;
  if (Array.isArray(value)) return value.map((entry) => scrubSnapshotTree(entry, isSecretKey, depth + 1));
  const output: Record<string, unknown> = {};
  for (const [key, entry] of Object.entries(value as Record<string, unknown>)) {
    output[key] = isSecretKey(key) ? snapshotMarkerFor(entry) : scrubSnapshotTree(entry, isSecretKey, depth + 1);
  }
  return output;
}

/** An absent or empty secret stays as it is (it reports that nothing was set); anything else is the marker. */
function snapshotMarkerFor(entry: unknown): unknown {
  return entry === undefined || entry === null || entry === "" ? entry : REDACTED_ERROR_VALUE;
}

/**
 * Rule 9 walk over a value about to be written to a bundle file or returned as data (reviewer D round 5 depth
 * control). Every string at every depth goes through redactCarrierText, so a carrier inside a benign-keyed string
 * (`detail: "Authorization: Bearer ..."`) is scrubbed in place with its siblings kept; a value under a secret
 * field name is the marker; an object or array nested past SNAPSHOT_DEPTH_CAP is the marker, so the depth of a
 * server-supplied tree bounds the work and nothing deeper than the cap is copied.
 */
export function scrubSnapshotValue(value: unknown): unknown {
  return scrubSnapshotTree(value, (key) => SNAPSHOT_SECRET_KEY_PATTERN.test(key) || SNAPSHOT_BEARER_ID_KEY_PATTERN.test(key), 1);
}

/** Keeps only the first and last four characters of an identifier, the way access key ids are masked elsewhere. */
export function maskIdentifier(id: string): string {
  if (id.length <= 8) return "****";
  return `${id.slice(0, 4)}****${id.slice(-4)}`;
}

/**
 * A server-assigned identifier for a sentence, kept whole when the error-text scrub keeps it and otherwise
 * masked. A Cloudflare account, zone, or token id is 32 hex characters, a hex digest to the scrub, and would
 * render as [REDACTED] in a summary or an access note, which loses the resource and reads as though a secret
 * had been recorded; the masked form still names it. Structured fields (accountId, endpoint, account_id,
 * record ids) carry the id whole and are never passed through this.
 */
export function labelIdentifier(id: string): string {
  return redactErrorText(id) === id ? id : maskIdentifier(id);
}

/** A request path for a sentence: each segment goes through labelIdentifier, so `/accounts/<32 hex>/members` names the account by its masked id. */
export function displayPath(path: string): string {
  return path.split("/").map((segment) => (segment.length === 0 ? segment : labelIdentifier(segment))).join("/");
}

export class CloudflareApiError extends Error {
  /** HTTP status the request observed; undefined for transport failures (timeouts, connection errors). */
  readonly status: number | undefined;
  readonly path: string;

  constructor(message: string, status: number | undefined, path: string) {
    super(redactErrorText(message));
    this.name = "CloudflareApiError";
    this.status = status;
    this.path = path;
  }
}

function errorStatus(error: unknown): number | undefined {
  const record = asObject(error);
  return asNumber(record?.status) ?? asNumber(record?.statusCode);
}

/** Path of the request that failed, taken from the observed request rather than a caller's constant. */
function errorEndpoint(error: unknown): string | undefined {
  return error instanceof CloudflareApiError ? error.path : undefined;
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

/** The only way a thrown error becomes recorded text. */
function errorMessage(error: unknown): string {
  if (isParseError(error)) return PARSE_ERROR_NOTE;
  return redactErrorText(error instanceof Error ? error.message : String(error));
}

export class CloudflareApiClient implements CloudflareReader {
  private readonly config: CloudflareResolvedConfig;
  private readonly fetchImpl: FetchImpl;
  private readonly now: () => Date;

  constructor(
    config: CloudflareResolvedConfig,
    options: {
      fetchImpl?: FetchImpl;
      now?: () => Date;
    } = {},
  ) {
    this.config = config;
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.now = options.now ?? (() => new Date());
    registerConfiguredSecrets(config.apiToken, config.apiKey);
  }

  getResolvedConfig(): CloudflareResolvedConfig {
    return this.config;
  }

  getNow(): Date {
    return this.now();
  }

  private buildUrl(path: string, query: JsonRecord = {}): string {
    const normalizedPath = path.startsWith("/") ? path : `/${path}`;
    const url = new URL(`${this.config.baseUrl}${normalizedPath}`);
    for (const [key, value] of Object.entries(query)) {
      if (value === undefined || value === null || value === "") continue;
      url.searchParams.set(key, String(value));
    }
    return url.toString();
  }

  private async requestJson(
    path: string,
    options: {
      query?: JsonRecord;
      allow404?: boolean;
    } = {},
  ): Promise<JsonRecord | null> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.config.timeoutMs);

    try {
      let response: Response;
      let rawText: string;
      try {
        response = await this.fetchImpl(this.buildUrl(path, options.query), {
          method: "GET",
          headers: buildHeaders(this.config),
          signal: controller.signal,
        });
        rawText = await response.text();
      } catch (error) {
        // Transport failures carry no HTTP status; the message names the path and the timeout budget, never a body.
        const reason = controller.signal.aborted
          ? `timed out after ${this.config.timeoutMs} ms`
          : `network error: ${errorMessage(error)}`;
        throw new CloudflareApiError(`Cloudflare request failed for ${displayPath(path)} (${reason})`, undefined, path);
      }

      let payload: JsonRecord = {};
      let parsed = rawText.length === 0;
      if (rawText.length > 0) {
        try {
          payload = asObject(JSON.parse(rawText)) ?? {};
          parsed = true;
        } catch {
          payload = {};
        }
      }
      const contentType = response.headers?.get?.("content-type") ?? null;

      if (response.status === 404 && options.allow404) {
        return null;
      }

      if (!response.ok) {
        const detail = (parsed ? cloudflareErrorSummary(payload) : undefined) ?? describeNonJsonBody(contentType, rawText);
        throw new CloudflareApiError(
          `Cloudflare request failed for ${displayPath(path)} (${response.status} ${response.statusText})${detail ? `: ${detail}` : ""}`,
          response.status,
          path,
        );
      }

      // A 2xx answer that is not JSON (a proxy login page, an HTML error) is a failed read, not an empty inventory.
      if (!parsed) {
        throw new CloudflareApiError(
          `Cloudflare request returned a non-JSON payload for ${displayPath(path)} (${response.status} ${response.statusText}): ${describeNonJsonBody(contentType, rawText)}`,
          response.status,
          path,
        );
      }

      if (payload.success === false) {
        throw new CloudflareApiError(cloudflareErrorSummary(payload) ?? `Cloudflare API reported failure for ${displayPath(path)}.`, response.status, path);
      }

      return payload;
    } finally {
      clearTimeout(timeout);
    }
  }

  private async getObject(path: string, allow404 = true): Promise<JsonRecord | null> {
    const payload = await this.requestJson(path, { allow404 });
    if (payload === null) return null;
    return extractResultObject(payload) ?? null;
  }

  private async getUnpaginatedList(path: string, query: JsonRecord = {}): Promise<CloudflarePagedList> {
    const payload = await this.requestJson(path, { query, allow404: true });
    if (payload === null) return { items: [], truncated: false, totalCount: 0 };
    const items = extractResultArray(payload);
    return { items, truncated: false, totalCount: items.length };
  }

  private async listPaginated(
    path: string,
    options: {
      query?: JsonRecord;
      allow404?: boolean;
      limit: number;
      perPage: number;
    },
  ): Promise<CloudflarePagedList> {
    const limit = clampNumber(options.limit, 50, 1, 100_000);
    const perPage = options.perPage;
    const items: JsonRecord[] = [];
    let totalCount: number | undefined;
    let truncated = false;

    for (let page = 1; ; page += 1) {
      const payload = await this.requestJson(path, {
        query: { ...options.query, page, per_page: perPage },
        allow404: options.allow404,
      });
      if (payload === null) {
        // A 404 on the first page means the product is not provisioned; a 404
        // after items were collected means the listing stopped early, so the
        // collected items are kept and reported as truncated.
        if (page === 1) return { items: [], truncated: false, totalCount: 0 };
        return { items, truncated: true, totalCount: undefined };
      }

      const pageItems = extractResultArray(payload);
      const resultInfo = asObject(payload.result_info);
      totalCount = asNumber(resultInfo?.total_count) ?? totalCount;
      const totalPages = asNumber(resultInfo?.total_pages);

      const remaining = limit - items.length;
      items.push(...pageItems.slice(0, remaining));
      if (pageItems.length > remaining) {
        truncated = true;
        break;
      }

      const lastPage = pageItems.length === 0
        || pageItems.length < perPage
        || (totalPages !== undefined && page >= totalPages);
      if (lastPage) break;
      if (items.length >= limit) {
        truncated = true;
        break;
      }
    }

    if (totalCount !== undefined && totalCount > items.length) truncated = true;
    return { items, totalCount: totalCount ?? (truncated ? undefined : items.length), truncated };
  }

  private async listCursorPaginated(path: string, limit: number, perPage: number): Promise<CloudflarePagedList> {
    const items: JsonRecord[] = [];
    let cursor: string | undefined;
    for (let iteration = 0; iteration < CURSOR_PAGE_BUDGET; iteration += 1) {
      const payload = await this.requestJson(path, {
        query: { per_page: perPage, cursor },
        allow404: true,
      });
      if (payload === null) {
        if (iteration === 0) return { items: [], truncated: false, totalCount: 0 };
        return { items, truncated: true, totalCount: undefined };
      }
      const pageItems = extractResultArray(payload);
      const remaining = limit - items.length;
      items.push(...pageItems.slice(0, remaining));
      if (pageItems.length > remaining) return { items, truncated: true };

      const cursors = asObject(asObject(payload.result_info)?.cursors);
      const nextCursor = asString(cursors?.after);
      if (!nextCursor) return { items, truncated: false, totalCount: items.length };
      // A cursor that arrives with an empty page or repeats the one just used
      // cannot be followed safely; the listing is reported as incomplete.
      if (pageItems.length === 0 || nextCursor === cursor) return { items, truncated: true, totalCount: undefined };
      cursor = nextCursor;
      if (items.length >= limit) return { items, truncated: true };
    }
    return { items, truncated: true, totalCount: undefined };
  }

  private zonePath(zoneId: string, suffix: string): string {
    return `/zones/${encodeURIComponent(zoneId)}${suffix}`;
  }

  private accountPath(accountId: string, suffix: string): string {
    return `/accounts/${encodeURIComponent(accountId)}${suffix}`;
  }

  async verifyCurrentToken(): Promise<JsonRecord | null> {
    return this.getObject("/user/tokens/verify");
  }

  async getUserToken(tokenId: string): Promise<JsonRecord | null> {
    return this.getObject(`/user/tokens/${encodeURIComponent(tokenId)}`);
  }

  async listAccounts(limit = 50): Promise<CloudflarePagedList> {
    return this.listPaginated("/accounts", { limit, perPage: 50 });
  }

  async listZones(limit = DEFAULT_ZONE_LIMIT): Promise<CloudflarePagedList> {
    return this.listPaginated("/zones", {
      limit,
      perPage: 50,
      query: this.config.accountId ? { "account.id": this.config.accountId } : {},
    });
  }

  async listUserTokens(limit = DEFAULT_TOKEN_LIMIT): Promise<CloudflarePagedList> {
    return this.listPaginated("/user/tokens", { limit, perPage: 50, allow404: true, query: { include_expired: true } });
  }

  async listAccountTokens(accountId: string, limit = DEFAULT_TOKEN_LIMIT): Promise<CloudflarePagedList> {
    return this.listPaginated(this.accountPath(accountId, "/tokens"), { limit, perPage: 50, allow404: true, query: { include_expired: true } });
  }

  async getZoneSettings(zoneId: string): Promise<JsonRecord[]> {
    return Promise.all(CLOUDFLARE_ZONE_SETTING_IDS.map(async (settingId) => {
      try {
        const setting = await this.getObject(this.zonePath(zoneId, `/settings/${settingId}`), false);
        return { id: settingId, value: setting?.value };
      } catch (error) {
        return { id: settingId, error: errorMessage(error), status: errorStatus(error) ?? null };
      }
    }));
  }

  async listFirewallRules(zoneId: string): Promise<CloudflarePagedList> {
    return this.listPaginated(this.zonePath(zoneId, "/firewall/rules"), { allow404: true, limit: 500, perPage: 100 });
  }

  async listZoneRulesets(zoneId: string): Promise<CloudflarePagedList> {
    return this.listCursorPaginated(this.zonePath(zoneId, "/rulesets"), 500, 50);
  }

  async getZoneEntrypointRuleset(zoneId: string, phase: string): Promise<JsonRecord | null> {
    return this.getObject(this.zonePath(zoneId, `/rulesets/phases/${encodeURIComponent(phase)}/entrypoint`));
  }

  async listDnsRecords(zoneId: string, limit = DEFAULT_DNS_RECORD_LIMIT): Promise<CloudflarePagedList> {
    return this.listPaginated(this.zonePath(zoneId, "/dns_records"), { limit, perPage: 100 });
  }

  async getDnssec(zoneId: string): Promise<JsonRecord | null> {
    return this.getObject(this.zonePath(zoneId, "/dnssec"));
  }

  async listCertificatePacks(zoneId: string): Promise<CloudflarePagedList> {
    return this.listPaginated(this.zonePath(zoneId, "/ssl/certificate_packs"), { allow404: true, limit: 500, perPage: 50, query: { status: "all" } });
  }

  async getUniversalSslSettings(zoneId: string): Promise<JsonRecord | null> {
    return this.getObject(this.zonePath(zoneId, "/ssl/universal/settings"));
  }

  async getOriginTlsClientAuthSettings(zoneId: string): Promise<JsonRecord | null> {
    return this.getObject(this.zonePath(zoneId, "/origin_tls_client_auth/settings"));
  }

  async listOriginTlsClientAuthHostnames(zoneId: string, limit = DEFAULT_HOSTNAME_ASSOCIATION_LIMIT): Promise<CloudflarePagedList> {
    return this.listPaginated(this.zonePath(zoneId, "/origin_tls_client_auth/hostnames"), { allow404: true, limit, perPage: 1000, query: { status: "all" } });
  }

  async getZoneSubscription(zoneId: string): Promise<JsonRecord | null> {
    return this.getObject(this.zonePath(zoneId, "/subscription"));
  }

  async getZeroTrustAccount(accountId: string): Promise<JsonRecord | null> {
    return this.getObject(this.accountPath(accountId, "/gateway"));
  }

  async listRateLimits(zoneId: string): Promise<CloudflarePagedList> {
    return this.listPaginated(this.zonePath(zoneId, "/rate_limits"), { allow404: true, limit: 1000, perPage: 100 });
  }

  async listPageRules(zoneId: string): Promise<CloudflarePagedList> {
    return this.getUnpaginatedList(this.zonePath(zoneId, "/pagerules"), { status: "active" });
  }

  async getBotManagement(zoneId: string): Promise<JsonRecord | null> {
    return this.getObject(this.zonePath(zoneId, "/bot_management"));
  }

  async listAccessApplications(accountId: string): Promise<CloudflarePagedList> {
    return this.listPaginated(this.accountPath(accountId, "/access/apps"), { allow404: true, limit: 500, perPage: 50 });
  }

  async listAccessPolicies(accountId: string): Promise<CloudflarePagedList> {
    return this.listPaginated(this.accountPath(accountId, "/access/policies"), { allow404: true, limit: 1000, perPage: 100 });
  }

  async listIdentityProviders(accountId: string): Promise<CloudflarePagedList> {
    return this.listPaginated(this.accountPath(accountId, "/access/identity_providers"), { allow404: true, limit: 200, perPage: 100 });
  }

  async listGatewayRules(accountId: string): Promise<CloudflarePagedList> {
    return this.getUnpaginatedList(this.accountPath(accountId, "/gateway/rules"));
  }

  async listAuditLogs(accountId: string, limit = DEFAULT_AUDIT_LIMIT): Promise<CloudflarePagedList> {
    const since = new Date(this.now().getTime() - AUDIT_LOG_LOOKBACK_DAYS * 86_400_000).toISOString();
    return this.listPaginated(this.accountPath(accountId, "/audit_logs"), { allow404: true, limit, perPage: 100, query: { since, direction: "desc" } });
  }

  async listMembers(accountId: string, limit = DEFAULT_MEMBER_LIMIT): Promise<CloudflarePagedList> {
    return this.listPaginated(this.accountPath(accountId, "/members"), { allow404: true, limit, perPage: 50 });
  }

  async listIpAccessRules(accountId: string): Promise<CloudflarePagedList> {
    return this.listPaginated(this.accountPath(accountId, "/firewall/access_rules/rules"), { allow404: true, limit: 1000, perPage: 50 });
  }
}

/** A failed read: the scrubbed error plus the HTTP status and path the failing request observed, when it was one. */
type ReadFailure = { ok: false; error: string; status?: number; endpoint?: string };

type ReadOutcome<T> =
  | { ok: true; value: T }
  | ReadFailure;

async function attempt<T>(load: () => Promise<T>): Promise<ReadOutcome<T>> {
  try {
    return { ok: true, value: await load() };
  } catch (error) {
    return { ok: false, error: errorMessage(error), status: errorStatus(error), endpoint: errorEndpoint(error) };
  }
}

/**
 * Outcome for a read the client cannot perform. It states that no request was made so the
 * consumer never mistakes the missing reader for a denied or failed endpoint.
 */
function notAttempted(method: keyof CloudflareReader): ReadFailure {
  return { ok: false, error: `not attempted: this client does not expose ${method}, so no request was made` };
}

/** The list behind a readable outcome; undefined when the read failed or was never attempted, never an empty fallback. */
function readList(outcome: ReadOutcome<CloudflarePagedList> | undefined): CloudflarePagedList | undefined {
  return outcome?.ok ? outcome.value : undefined;
}

/**
 * Written in place of a list that was denied, errored, or never collected so that `[]` in
 * core_data always means "read and empty". status and endpoint come from the observed request.
 */
export interface CloudflareUncollectedMarker {
  collected: false;
  status: number | null;
  endpoint: string | null;
  error: string;
}

function uncollectedMarker(outcome: { error: string; status?: number; endpoint?: string } | undefined, fallbackError: string): CloudflareUncollectedMarker {
  return { collected: false, status: outcome?.status ?? null, endpoint: outcome?.endpoint ?? null, error: outcome?.error ?? fallbackError };
}

function asPaged(value: unknown): CloudflarePagedList {
  if (Array.isArray(value)) return { items: asRecordArray(value), truncated: false, totalCount: value.length };
  const record = asObject(value);
  if (record && Array.isArray(record.items)) {
    return {
      items: asRecordArray(record.items),
      totalCount: asNumber(record.totalCount) ?? asNumber(record.total_count),
      truncated: asBoolean(record.truncated) ?? false,
    };
  }
  return { items: [], truncated: false, totalCount: 0 };
}

async function attemptList(load: () => Promise<unknown>): Promise<ReadOutcome<CloudflarePagedList>> {
  const outcome = await attempt(load);
  return outcome.ok ? { ok: true, value: asPaged(outcome.value) } : outcome;
}

const STATUS_RANK: Record<CloudflareFindingStatus, number> = { pass: 0, warn: 1, manual: 2, fail: 3 };

function worstStatus(statuses: CloudflareFindingStatus[]): CloudflareFindingStatus {
  return statuses.reduce<CloudflareFindingStatus>((worst, current) => (STATUS_RANK[current] > STATUS_RANK[worst] ? current : worst), "pass");
}

function capStatus(status: CloudflareFindingStatus, cap: CloudflareFindingStatus): CloudflareFindingStatus {
  return STATUS_RANK[status] < STATUS_RANK[cap] ? cap : status;
}

function manualReason(endpoint: string, permission: string, evidence: string, error?: string): string {
  return `Manual review required: ${displayPath(endpoint)} could not be read${error ? ` (${error})` : ""}. Grant ${permission} to the audit token, or collect ${evidence} manually.`;
}

function partialInventoryNote(label: string, list: CloudflarePagedList): string | undefined {
  if (!list.truncated) return undefined;
  const total = list.totalCount === undefined ? "an unknown total" : `${list.totalCount} total`;
  return `Partial ${label} inventory: ${list.items.length} seen of ${total}; unseen items were not assessed.`;
}

interface ControlMapping {
  fedramp: string;
  cmmc: string;
  soc2: string;
  cis: string;
  pci: string;
  stig: string;
  irap: string;
  ismap: string;
}

export const CLOUDFLARE_FRAMEWORKS: Array<{ key: keyof ControlMapping; label: string; slug: string }> = [
  { key: "fedramp", label: "FedRAMP", slug: "fedramp" },
  { key: "cmmc", label: "CMMC", slug: "cmmc" },
  { key: "soc2", label: "SOC 2", slug: "soc2" },
  { key: "cis", label: "CIS", slug: "cis" },
  { key: "pci", label: "PCI-DSS", slug: "pci_dss" },
  { key: "stig", label: "STIG", slug: "disa_stig" },
  { key: "irap", label: "IRAP", slug: "irap" },
  { key: "ismap", label: "ISMAP", slug: "ismap" },
];

const SPEC_CONTROL_MAPPINGS: Record<number, ControlMapping> = {
  1: { fedramp: "SC-7", cmmc: "SC.L2-3.13.1", soc2: "CC6.6", cis: "9.1", pci: "6.6", stig: "SRG-APP-000383", irap: "ISM-1148", ismap: "CPS-11" },
  2: { fedramp: "SC-7", cmmc: "SC.L2-3.13.1", soc2: "CC6.6", cis: "9.2", pci: "6.6", stig: "SRG-APP-000383", irap: "ISM-1148", ismap: "CPS-11" },
  3: { fedramp: "SC-5", cmmc: "SC.L2-3.13.6", soc2: "CC6.6", cis: "9.3", pci: "6.5.10", stig: "SRG-APP-000246", irap: "ISM-1020", ismap: "CPS-11" },
  4: { fedramp: "SC-7", cmmc: "SC.L2-3.13.1", soc2: "CC6.6", cis: "9.4", pci: "6.6", stig: "SRG-APP-000383", irap: "ISM-1148", ismap: "CPS-11" },
  5: { fedramp: "SC-8", cmmc: "SC.L2-3.13.8", soc2: "CC6.7", cis: "3.1", pci: "4.1", stig: "SRG-APP-000219", irap: "ISM-0490", ismap: "CPS-09" },
  6: { fedramp: "SC-8(1)", cmmc: "SC.L2-3.13.8", soc2: "CC6.7", cis: "3.2", pci: "4.1", stig: "SRG-APP-000219", irap: "ISM-1369", ismap: "CPS-09" },
  7: { fedramp: "SC-8", cmmc: "SC.L2-3.13.8", soc2: "CC6.7", cis: "3.3", pci: "4.1", stig: "SRG-APP-000219", irap: "ISM-0490", ismap: "CPS-09" },
  8: { fedramp: "SC-20", cmmc: "SC.L2-3.13.15", soc2: "CC6.7", cis: "3.4", pci: "n/a", stig: "SRG-APP-000516", irap: "ISM-1183", ismap: "CPS-09" },
  9: { fedramp: "AC-3", cmmc: "AC.L2-3.1.2", soc2: "CC6.1", cis: "1.1", pci: "7.2.1", stig: "SRG-APP-000033", irap: "ISM-0432", ismap: "CPS-07" },
  10: { fedramp: "IA-2", cmmc: "AC.L2-3.1.1", soc2: "CC6.1", cis: "1.2", pci: "8.3.1", stig: "SRG-APP-000148", irap: "ISM-1557", ismap: "CPS-04" },
  11: { fedramp: "AU-2", cmmc: "AU.L2-3.3.1", soc2: "CC7.2", cis: "8.1", pci: "10.2.1", stig: "SRG-APP-000089", irap: "ISM-0580", ismap: "CPS-10" },
  12: { fedramp: "AC-6", cmmc: "AC.L2-3.1.5", soc2: "CC6.3", cis: "5.1", pci: "7.2.1", stig: "SRG-APP-000340", irap: "ISM-0432", ismap: "CPS-07" },
  13: { fedramp: "IA-5(1)", cmmc: "IA.L2-3.5.8", soc2: "CC6.1", cis: "5.2", pci: "8.6.3", stig: "SRG-APP-000175", irap: "ISM-1590", ismap: "CPS-05" },
  14: { fedramp: "AC-2", cmmc: "AC.L2-3.1.1", soc2: "CC6.3", cis: "6.1", pci: "7.2.2", stig: "SRG-APP-000033", irap: "ISM-0432", ismap: "CPS-07" },
  15: { fedramp: "CM-6", cmmc: "CM.L2-3.4.2", soc2: "CC8.1", cis: "10.1", pci: "2.2", stig: "SRG-APP-000386", irap: "ISM-0380", ismap: "CPS-12" },
  16: { fedramp: "SC-5", cmmc: "SC.L2-3.13.6", soc2: "CC6.6", cis: "9.5", pci: "6.5.10", stig: "SRG-APP-000246", irap: "ISM-1020", ismap: "CPS-11" },
  17: { fedramp: "SC-7(5)", cmmc: "SC.L2-3.13.1", soc2: "CC6.6", cis: "9.6", pci: "1.3.2", stig: "SRG-APP-000383", irap: "ISM-1148", ismap: "CPS-11" },
  18: { fedramp: "SC-8", cmmc: "SC.L2-3.13.8", soc2: "CC6.7", cis: "3.5", pci: "4.1", stig: "SRG-APP-000219", irap: "ISM-0490", ismap: "CPS-09" },
  19: { fedramp: "SC-7", cmmc: "SC.L2-3.13.1", soc2: "CC6.6", cis: "9.7", pci: "6.6", stig: "SRG-APP-000383", irap: "ISM-1148", ismap: "CPS-11" },
  20: { fedramp: "SC-7", cmmc: "SC.L2-3.13.1", soc2: "CC6.7", cis: "3.6", pci: "n/a", stig: "SRG-APP-000383", irap: "ISM-1148", ismap: "CPS-11" },
  21: { fedramp: "SC-8", cmmc: "SC.L2-3.13.8", soc2: "CC6.7", cis: "3.7", pci: "4.1", stig: "SRG-APP-000219", irap: "ISM-0490", ismap: "CPS-09" },
  22: { fedramp: "SC-8", cmmc: "SC.L2-3.13.8", soc2: "CC6.7", cis: "3.8", pci: "4.1", stig: "SRG-APP-000219", irap: "ISM-0490", ismap: "CPS-09" },
  23: { fedramp: "SC-7", cmmc: "SC.L2-3.13.1", soc2: "CC6.7", cis: "9.8", pci: "6.5.10", stig: "SRG-APP-000383", irap: "ISM-1148", ismap: "CPS-11" },
  24: { fedramp: "SC-7", cmmc: "SC.L2-3.13.1", soc2: "CC6.6", cis: "9.9", pci: "1.3.1", stig: "SRG-APP-000383", irap: "ISM-1148", ismap: "CPS-11" },
  25: { fedramp: "SC-8", cmmc: "SC.L2-3.13.8", soc2: "CC6.7", cis: "3.9", pci: "4.1", stig: "SRG-APP-000219", irap: "ISM-0490", ismap: "CPS-09" },
};

function mappingsForControl(specControl: number): string[] {
  const mapping = SPEC_CONTROL_MAPPINGS[specControl];
  if (!mapping) return [];
  return CLOUDFLARE_FRAMEWORKS
    .filter((framework) => mapping[framework.key] !== "n/a")
    .map((framework) => `${framework.label} ${mapping[framework.key]}`);
}

export function frameworkControlFor(finding: CloudflareFinding, frameworkKey: keyof ControlMapping): string {
  const mapping = finding.specControl ? SPEC_CONTROL_MAPPINGS[finding.specControl] : undefined;
  return mapping ? mapping[frameworkKey] : "n/a";
}

function finding(
  id: string,
  title: string,
  severity: CloudflareFinding["severity"],
  status: CloudflareFindingStatus,
  summary: string,
  specControl: number | undefined,
  evidence?: JsonRecord,
): CloudflareFinding {
  return {
    id,
    title,
    severity,
    status,
    summary,
    evidence,
    mappings: specControl ? mappingsForControl(specControl) : [],
    specControl,
  };
}

function deriveAccountContext(
  config: CloudflareResolvedConfig,
  accountsOutcome: ReadOutcome<CloudflarePagedList>,
): { accountId?: string; note: string } {
  if (config.accountId) {
    return { accountId: config.accountId, note: `Using configured account ${labelIdentifier(config.accountId)}.` };
  }

  // A denied or failed account list is named as such; it is never reported as "no accounts were visible".
  if (!accountsOutcome.ok) {
    return { accountId: undefined, note: `The account list could not be read (${displayPath(accountsOutcome.endpoint ?? "/accounts")}: ${accountsOutcome.error}); account-scoped checks stay manual until account_id is set.` };
  }

  const accounts = accountsOutcome.value.items;
  const soleId = asString(accounts[0]?.id);
  if (accounts.length === 1 && soleId) {
    return { accountId: soleId, note: `Using the only visible Cloudflare account ${labelIdentifier(soleId)}.` };
  }

  if (accounts.length === 0) {
    return { accountId: undefined, note: "No Cloudflare account context was visible; account-scoped checks stay manual until account_id is set." };
  }

  return {
    accountId: undefined,
    note: "Multiple Cloudflare accounts were visible with no account_id selected; account-scoped checks stay manual until account_id is set.",
  };
}

const ACCOUNT_RECORD_FIELDS = ["id", "name", "type", "created_on"] as const;
const ACCOUNT_SETTING_FIELDS = ["enforce_twofactor", "api_access_enabled", "access_approval_expiry", "use_account_custom_ns_by_default"] as const;
const ZONE_RECORD_FIELDS = ["id", "name", "status", "paused", "type", "development_mode", "created_on", "modified_on", "activated_on", "name_servers", "original_name_servers", "original_registrar", "original_dnshost"] as const;

function pickFields(record: JsonRecord, fields: readonly string[]): JsonRecord {
  const projected: JsonRecord = {};
  for (const field of fields) {
    if (field in record) projected[field] = record[field];
  }
  return projected;
}

/**
 * Projects a GET /accounts record to the fields the verdicts and the account
 * context read; contact emails and free-form settings are dropped.
 */
function projectAccountRecord(account: JsonRecord): JsonRecord {
  const settings = asObject(account.settings);
  return {
    ...pickFields(account, ACCOUNT_RECORD_FIELDS),
    ...(settings ? { settings: { ...pickFields(settings, ACCOUNT_SETTING_FIELDS), abuse_contact_email_configured: Boolean(asString(settings.abuse_contact_email)) } } : {}),
  };
}

/**
 * Projects a GET /zones record to identity, status, plan, and account
 * references; the owner email and other contact details are dropped.
 */
function projectZoneRecord(zone: JsonRecord): JsonRecord {
  const plan = asObject(zone.plan);
  const owner = asObject(zone.owner);
  const account = asObject(zone.account);
  return {
    ...pickFields(zone, ZONE_RECORD_FIELDS),
    ...(plan ? { plan: pickFields(plan, ["id", "name", "legacy_id", "is_subscribed"]) } : {}),
    ...(owner ? { owner: pickFields(owner, ["id", "type"]) } : {}),
    ...(account ? { account: pickFields(account, ["id", "name"]) } : {}),
  };
}

function projectPagedList(list: CloudflarePagedList, project: (record: JsonRecord) => JsonRecord): CloudflarePagedList {
  return { ...list, items: list.items.map((record) => project(record)) };
}

async function readableSurface(
  name: string,
  scope: CloudflareAccessSurface["scope"],
  endpoint: string,
  load: () => Promise<unknown>,
): Promise<CloudflareAccessSurface> {
  try {
    const value = await load();
    const count = Array.isArray(value) || asObject(value)?.items !== undefined
      ? asPaged(value).items.length
      : value === null ? 0 : 1;
    return { name, scope, endpoint, status: "readable", count };
  } catch (error) {
    return { name, scope, endpoint: errorEndpoint(error) ?? endpoint, status: "not_readable", count: null, http_status: errorStatus(error) ?? null, error: errorMessage(error) };
  }
}

function notConfiguredSurface(
  name: string,
  scope: CloudflareAccessSurface["scope"],
  endpoint: string,
  error: string,
): CloudflareAccessSurface {
  return { name, scope, endpoint, status: "not_configured", count: null, error };
}

/** A probe that was never sent because the inventory it depends on could not be read; carries the parent's status and error. */
function notAttemptedSurface(
  name: string,
  scope: CloudflareAccessSurface["scope"],
  endpoint: string,
  parent: { endpoint: string; status?: number; error: string },
): CloudflareAccessSurface {
  return {
    name,
    scope,
    endpoint,
    status: "not_attempted",
    count: null,
    http_status: parent.status ?? null,
    error: `Not attempted: ${displayPath(parent.endpoint)} could not be read (${parent.error})`,
  };
}

function zoneName(zone: JsonRecord): string {
  return asString(zone.name) ?? asString(zone.id) ?? "unknown-zone";
}

interface ZoneSettingRead {
  value?: unknown;
  error?: string;
}

function settingMap(settings: JsonRecord[]): Map<string, ZoneSettingRead> {
  const map = new Map<string, ZoneSettingRead>();
  for (const item of settings) {
    const id = asString(item.id);
    if (!id) continue;
    const error = asString(item.error);
    map.set(id, error ? { error } : { value: item.value });
  }
  return map;
}

interface ZoneVerdict {
  zone: string;
  status: CloudflareFindingStatus;
  detail: string;
}

function verdict(zone: string, status: CloudflareFindingStatus, detail: string): ZoneVerdict {
  return { zone, status, detail };
}

function judgeOriginPulls(
  zone: string,
  tlsClientAuth: ZoneSettingRead | undefined,
  originOutcome: ReadOutcome<JsonRecord | null>,
  hostnamesOutcome: ReadOutcome<CloudflarePagedList>,
): ZoneVerdict {
  const settingReadable = Boolean(tlsClientAuth && !tlsClientAuth.error);
  if (!originOutcome.ok && !settingReadable) {
    return verdict(zone, "manual", manualReason("/zones/{zone_id}/origin_tls_client_auth/settings and /zones/{zone_id}/settings/tls_client_auth", "SSL and Certificates: Read plus Zone Settings: Read", "the Authenticated Origin Pulls status", originOutcome.error));
  }
  const zoneLevelEnabled = originOutcome.ok ? asBoolean(originOutcome.value?.enabled) : undefined;
  const settingOn = settingReadable ? asString(tlsClientAuth!.value) : undefined;
  const zoneLevelOn = zoneLevelEnabled === true || settingOn === "on";
  const zoneLevelOff = !zoneLevelOn && (zoneLevelEnabled === false || settingOn === "off");
  const zoneSummary = `zone-level enabled ${String(zoneLevelEnabled ?? "unread")}, tls_client_auth ${settingOn ?? "unread"}`;
  if (!zoneLevelOn && !zoneLevelOff) {
    return verdict(zone, "manual", "Authenticated Origin Pulls status returned undocumented values; confirm under SSL/TLS > Origin Server.");
  }
  if (!hostnamesOutcome.ok) {
    return verdict(zone, "manual", `Zone-level Authenticated Origin Pulls is ${zoneLevelOn ? "enabled" : "disabled"} (${zoneSummary}), but ${manualReason("/zones/{zone_id}/origin_tls_client_auth/hostnames", "SSL and Certificates: Read", "the per-hostname certificate associations", hostnamesOutcome.error)}`);
  }
  const associations = hostnamesOutcome.value.items.filter((item) => asString(item.status) !== "deleted");
  const active = associations.filter((item) => asBoolean(item.enabled) === true && asString(item.status) === "active");
  const inactive = associations.filter((item) => !(asBoolean(item.enabled) === true && asString(item.status) === "active"));
  const undated = active.filter((item) => !asString(item.updated_at) && !asString(item.created_at));
  const partial = partialInventoryNote("hostname association", hostnamesOutcome.value);
  const hostnameSummary = associations.length === 0
    ? "no per-hostname certificate associations"
    : `${active.length} of ${associations.length} per-hostname associations active and enabled${inactive.length > 0 ? ` (${inactive.map((item) => `${asString(item.hostname) ?? "unknown-hostname"}: enabled ${String(asBoolean(item.enabled) ?? "unread")}, status ${asString(item.status) ?? "unread"}`).join("; ")})` : ""}`;
  if (zoneLevelOff && active.length === 0) {
    return verdict(zone, "fail", `Authenticated Origin Pulls disabled (${zoneSummary}) and ${hostnameSummary}.`);
  }
  if (zoneLevelOff) {
    return verdict(zone, "warn", `Zone-level Authenticated Origin Pulls is disabled (${zoneSummary}); only ${hostnameSummary} enforce origin authentication.${partial ? ` ${partial}` : ""}`);
  }
  if (inactive.length > 0 || undated.length > 0 || partial) {
    const reasons = [
      inactive.length > 0 ? `${inactive.length} associations are disabled or not active` : undefined,
      undated.length > 0 ? `${undated.length} active associations have no created_at or updated_at` : undefined,
      partial,
    ].filter((reason): reason is string => Boolean(reason));
    return verdict(zone, "warn", `Zone-level Authenticated Origin Pulls enabled (${zoneSummary}); ${hostnameSummary}. ${reasons.join("; ")}.`);
  }
  return verdict(zone, "pass", `Authenticated Origin Pulls enabled (${zoneSummary}); ${hostnameSummary}.`);
}

function settingVerdict(
  zone: string,
  settings: Map<string, ZoneSettingRead>,
  settingId: string,
  judge: (value: unknown) => { status: CloudflareFindingStatus; detail: string },
  permission = "Zone Settings: Read",
): ZoneVerdict {
  const read = settings.get(settingId);
  if (!read) {
    return verdict(zone, "manual", manualReason(`/zones/{zone_id}/settings/${settingId}`, permission, `the ${settingId} zone setting`, "setting not returned"));
  }
  if (read.error) {
    return verdict(zone, "manual", manualReason(`/zones/{zone_id}/settings/${settingId}`, permission, `the ${settingId} zone setting`, read.error));
  }
  const judged = judge(read.value);
  return verdict(zone, judged.status, judged.detail);
}

function onOffJudge(label: string): (value: unknown) => { status: CloudflareFindingStatus; detail: string } {
  return (value) => {
    const text = asString(value);
    if (text === "on") return { status: "pass", detail: `${label} is on.` };
    if (text === "off") return { status: "fail", detail: `${label} is off.` };
    return { status: "manual", detail: `${label} returned an undocumented value (${String(text ?? "null")}); confirm in the dashboard.` };
  };
}

function aggregateZoneVerdicts(
  id: string,
  title: string,
  severity: CloudflareFinding["severity"],
  specControl: number | undefined,
  zonesOutcome: ReadOutcome<CloudflarePagedList>,
  verdicts: ZoneVerdict[],
  options: {
    emptyStatus: CloudflareFindingStatus;
    emptyDetail: string;
    passDetail: string;
    extraEvidence?: JsonRecord;
  },
): CloudflareFinding {
  if (!zonesOutcome.ok) {
    // A denied or failed zone list is not an empty one: the finding names the read that failed and
    // carries no zone count, total, or truncation flag.
    return finding(id, title, severity, "manual", manualReason(zonesOutcome.endpoint ?? "/zones", "Zone: Read", "the zone list", zonesOutcome.error), specControl, {
      zones_seen: null,
      zones_total: null,
      zone_inventory_truncated: null,
      zones_http_status: zonesOutcome.status ?? null,
      zones_error: zonesOutcome.error,
      ...options.extraEvidence,
    });
  }
  const zones = zonesOutcome.value;
  const partialNote = partialInventoryNote("zone", zones);
  if (zones.items.length === 0) {
    return finding(id, title, severity, options.emptyStatus, `${options.emptyDetail}${partialNote ? ` ${partialNote}` : ""}`, specControl, {
      zones_seen: 0,
      zones_total: zones.totalCount ?? null,
      zone_inventory_truncated: zones.truncated,
      ...options.extraEvidence,
    });
  }

  const nonPassing = verdicts.filter((item) => item.status !== "pass");
  let status = worstStatus(verdicts.map((item) => item.status));
  if (partialNote) status = capStatus(status, "warn");

  const counts = {
    pass: verdicts.filter((item) => item.status === "pass").length,
    warn: verdicts.filter((item) => item.status === "warn").length,
    fail: verdicts.filter((item) => item.status === "fail").length,
    manual: verdicts.filter((item) => item.status === "manual").length,
  };
  const summary = nonPassing.length === 0
    ? `${options.passDetail} (${verdicts.length} zones).${partialNote ? ` ${partialNote}` : ""}`
    : `${counts.fail} zones failed, ${counts.warn} warned, ${counts.manual} need manual review out of ${verdicts.length} sampled. ${nonPassing.slice(0, 3).map((item) => `${item.zone}: ${item.detail}`).join(" ")}${partialNote ? ` ${partialNote}` : ""}`;

  return finding(id, title, severity, status, summary, specControl, {
    zones_seen: zones.items.length,
    zones_total: zones.totalCount ?? null,
    zone_inventory_truncated: zones.truncated,
    counts,
    zones: verdicts.slice(0, 50).map((item) => ({ zone: item.zone, status: item.status, detail: item.detail })),
    ...options.extraEvidence,
  });
}

function enabledRules(ruleset: JsonRecord | null): JsonRecord[] {
  return asRecordArray(ruleset?.rules).filter((rule) => asBoolean(rule.enabled) !== false);
}

function ruleAction(rule: JsonRecord): string {
  return asString(rule.action)?.toLowerCase() ?? "";
}

function entrypointVerdict(
  zone: string,
  phase: string,
  outcome: ReadOutcome<JsonRecord | null>,
  judge: (ruleset: JsonRecord | null) => { status: CloudflareFindingStatus; detail: string },
  permission: string,
): ZoneVerdict {
  if (!outcome.ok) {
    return verdict(zone, "manual", manualReason(`/zones/{zone_id}/rulesets/phases/${phase}/entrypoint`, permission, `the ${phase} entry point ruleset`, outcome.error));
  }
  const judged = judge(outcome.value);
  return verdict(zone, judged.status, judged.detail);
}

function judgeManagedWaf(ruleset: JsonRecord | null): { status: CloudflareFindingStatus; detail: string } {
  if (!ruleset) return { status: "fail", detail: "No http_request_firewall_managed entry point ruleset exists, so no WAF managed ruleset is deployed." };
  const executes = enabledRules(ruleset).filter((rule) => ruleAction(rule) === "execute");
  if (executes.length === 0) {
    return { status: "fail", detail: "The http_request_firewall_managed entry point has no enabled execute rule deploying a managed ruleset." };
  }
  const disabledOverride = executes.some((rule) => asBoolean(asObject(asObject(rule.action_parameters)?.overrides)?.enabled) === false);
  if (disabledOverride) return { status: "fail", detail: "A managed ruleset execute rule has overrides.enabled false, disabling the managed rules." };
  const ids = executes.map((rule) => asString(asObject(rule.action_parameters)?.id) ?? "unknown");
  return { status: "pass", detail: `${executes.length} enabled managed ruleset execute rules (${ids.join(", ")}).` };
}

function judgeCustomWaf(ruleset: JsonRecord | null): { status: CloudflareFindingStatus; detail: string } {
  if (!ruleset) return { status: "fail", detail: "No http_request_firewall_custom entry point ruleset exists, so no custom WAF rules are deployed." };
  const rules = enabledRules(ruleset);
  const mitigating = rules.filter((rule) => ["block", "managed_challenge", "js_challenge", "challenge"].includes(ruleAction(rule)));
  if (rules.length === 0) return { status: "fail", detail: "The http_request_firewall_custom entry point has no enabled rules." };
  if (mitigating.length === 0) return { status: "warn", detail: `${rules.length} enabled custom rules, none with a block or challenge action.` };
  return { status: "pass", detail: `${mitigating.length} of ${rules.length} enabled custom rules block or challenge.` };
}

function managedDdosL7Listed(rulesets: ReadOutcome<CloudflarePagedList>): boolean | undefined {
  if (!rulesets.ok) return undefined;
  return rulesets.value.items.some((ruleset) => asString(ruleset.kind) === "managed" && asString(ruleset.phase) === CLOUDFLARE_RULESET_PHASES.ddosL7);
}

function judgeDdosL7(ruleset: JsonRecord | null, managedListed: boolean | undefined): { status: CloudflareFindingStatus; detail: string } {
  if (!ruleset) {
    if (managedListed === true) {
      return {
        status: "pass",
        detail: "The managed ddos_l7 ruleset is listed for the zone and no override ruleset lowers its sensitivity, so HTTP DDoS Attack Protection runs at Cloudflare's default (high) sensitivity.",
      };
    }
    return {
      status: "manual",
      detail: managedListed === false
        ? "No ddos_l7 override exists and the zone ruleset list does not show a managed ddos_l7 ruleset; confirm HTTP DDoS Attack Protection under Security > DDoS."
        : "No ddos_l7 override exists and the zone ruleset list could not be read (Zone WAF: Read); confirm HTTP DDoS Attack Protection under Security > DDoS. Per-rule overrides need an Enterprise plan with Advanced DDoS Protection.",
    };
  }
  const executes = asRecordArray(ruleset.rules).filter((rule) => ruleAction(rule) === "execute");
  if (executes.length === 0) return { status: "manual", detail: "The ddos_l7 entry point has no execute rule; confirm DDoS overrides in the dashboard." };
  const disabled = executes.filter((rule) => asBoolean(rule.enabled) === false);
  if (disabled.length === executes.length) return { status: "fail", detail: "Every ddos_l7 override rule is disabled." };
  const levels = executes
    .filter((rule) => asBoolean(rule.enabled) !== false)
    .map((rule) => asString(asObject(asObject(rule.action_parameters)?.overrides)?.sensitivity_level)?.toLowerCase() ?? "default");
  if (levels.includes("eoff")) return { status: "fail", detail: "HTTP DDoS sensitivity override is essentially off (eoff)." };
  if (levels.includes("low")) return { status: "warn", detail: "HTTP DDoS sensitivity override is low." };
  return { status: "pass", detail: `HTTP DDoS override sensitivity is ${[...new Set(levels)].join(", ")}.` };
}

function judgeSecurityHeaders(ruleset: JsonRecord | null): { status: CloudflareFindingStatus; detail: string } {
  if (!ruleset) return { status: "fail", detail: "No http_response_headers_transform entry point ruleset exists, so no security headers are set at the edge." };
  const setHeaders = new Set<string>();
  for (const rule of enabledRules(ruleset).filter((item) => ruleAction(item) === "rewrite")) {
    const headers = asObject(asObject(rule.action_parameters)?.headers) ?? {};
    for (const [name, spec] of Object.entries(headers)) {
      const operation = asString(asObject(spec)?.operation)?.toLowerCase();
      if (operation === "remove") continue;
      setHeaders.add(name.toLowerCase());
    }
  }
  const missing = REQUIRED_SECURITY_HEADERS.filter((header) => !setHeaders.has(header));
  if (missing.length === 0) return { status: "pass", detail: "Transform rules set Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, and Referrer-Policy." };
  if (missing.length === REQUIRED_SECURITY_HEADERS.length) return { status: "fail", detail: "No enabled response header transform rule sets any required security header." };
  return { status: "warn", detail: `Missing security headers: ${missing.join(", ")}.` };
}

function judgeRateLimitRuleset(ruleset: JsonRecord | null): { status: CloudflareFindingStatus; detail: string } {
  if (!ruleset) return { status: "fail", detail: "No http_ratelimit entry point ruleset exists, so no rate limiting rules protect the zone." };
  const rules = enabledRules(ruleset).filter((rule) => asObject(rule.ratelimit) !== undefined);
  if (rules.length === 0) return { status: "fail", detail: "The http_ratelimit entry point has no enabled rules with a ratelimit block." };
  return { status: "pass", detail: `${rules.length} enabled http_ratelimit rules.` };
}

function pageRuleIsRisky(rule: JsonRecord): boolean {
  if (asString(rule.status) === "disabled") return false;
  const targets = asRecordArray(rule.targets)
    .map((target) => asString(asObject(target.constraint)?.value)?.toLowerCase() ?? "")
    .join(" ");
  const actions = asRecordArray(rule.actions).map((action) => ({
    id: asString(action.id)?.toLowerCase() ?? "",
    value: asString(action.value)?.toLowerCase() ?? "",
  }));

  return actions.some((action) =>
    action.id === "disable_security"
    || (action.id === "security_level" && action.value === "essentially_off")
    || (action.id === "ssl" && (action.value === "off" || action.value === "flexible"))
    || (action.id === "browser_check" && action.value === "off")
    || (action.id === "email_obfuscation" && action.value === "off")
    || (action.id === "cache_level" && action.value === "cache_everything"
      && /(login|auth|admin|api|account|checkout)/.test(targets)),
  );
}

function botManagementJudgement(config: JsonRecord | null): { status: CloudflareFindingStatus; detail: string } {
  if (!config) {
    return { status: "manual", detail: "No bot management configuration was returned; confirm the zone plan includes Bot Fight Mode, Super Bot Fight Mode, or Bot Management." };
  }
  const fightMode = asBoolean(config.fight_mode);
  const definitely = asString(config.sbfm_definitely_automated);
  const likely = asString(config.sbfm_likely_automated);
  const enterpriseShape = config.auto_update_model !== undefined || config.suppress_session_score !== undefined;

  if (fightMode === true) return { status: "pass", detail: "Bot Fight Mode is enabled." };
  if (definitely === "block" || definitely === "managed_challenge") {
    return { status: "pass", detail: `Super Bot Fight Mode acts on definitely automated traffic (${definitely}${likely ? `, likely automated ${likely}` : ""}).` };
  }
  if (definitely === "allow") return { status: "fail", detail: "Super Bot Fight Mode allows definitely automated traffic." };
  if (fightMode === false) return { status: "fail", detail: "Bot Fight Mode is disabled and no Super Bot Fight Mode action is configured." };
  if (enterpriseShape) {
    return { status: "manual", detail: "Enterprise Bot Management is provisioned; enforcement lives in WAF custom rules using cf.bot_management.score, so confirm those rules manually." };
  }
  return { status: "manual", detail: "Bot management fields fight_mode and sbfm_definitely_automated were absent; confirm the plan includes Bot Fight Mode, Super Bot Fight Mode (Pro or Business), or Bot Management (Enterprise)." };
}

async function zonePlanNote(client: Partial<Pick<CloudflareReader, "getZoneSubscription">>, zoneId: string): Promise<string> {
  if (!client.getZoneSubscription) return "";
  const subscription = await attempt(() => client.getZoneSubscription!(zoneId));
  if (!subscription.ok) return ` ${zonePlanNoteText(subscription.error)}`;
  const planName = asString(asObject(subscription.value?.rate_plan)?.public_name);
  const state = asString(subscription.value?.state);
  if (!planName) return " The zone subscription returned no rate_plan.public_name, so the plan is not named here.";
  return ` Current zone plan: ${planName}${state ? ` (subscription ${state})` : ""}.`;
}

function collectMemberRoleNames(member: JsonRecord): string[] {
  return asRecordArray(member.roles)
    .map((role) => asString(role.name))
    .filter((item): item is string => Boolean(item));
}

function daysBetween(from: Date, to: Date): number {
  return (to.getTime() - from.getTime()) / 86_400_000;
}

export async function checkCloudflareAccess(
  client: Pick<
    CloudflareReader,
    "getResolvedConfig" | "verifyCurrentToken" | "listAccounts" | "listZones" | "getZoneSettings" | "getDnssec" | "listMembers" | "listAccessApplications" | "listAuditLogs"
  > & Partial<Pick<CloudflareReader, "listZoneRulesets">>,
): Promise<CloudflareAccessCheckResult> {
  const config = client.getResolvedConfig();
  const [verify, accounts, zones] = await Promise.all([
    attempt(() => client.verifyCurrentToken()),
    attemptList(() => client.listAccounts()),
    attemptList(() => client.listZones()),
  ]);
  const accountItems = readList(accounts)?.items ?? [];
  const zoneItems = readList(zones)?.items ?? [];
  const { accountId, note } = deriveAccountContext(config, accounts);
  const firstZoneId = asString(zoneItems[0]?.id);

  const failedSurface = (name: string, scope: CloudflareAccessSurface["scope"], endpoint: string, outcome: { error: string; status?: number; endpoint?: string }): CloudflareAccessSurface =>
    ({ name, scope, endpoint: outcome.endpoint ?? endpoint, status: "not_readable", count: null, http_status: outcome.status ?? null, error: outcome.error });
  const surfaces: CloudflareAccessSurface[] = [
    verify.ok
      ? { name: "token_verify", scope: "user", endpoint: "/user/tokens/verify", status: "readable", count: verify.value ? 1 : 0 }
      : failedSurface("token_verify", "user", "/user/tokens/verify", verify),
    accounts.ok
      ? { name: "accounts", scope: "account", endpoint: "/accounts", status: "readable", count: accountItems.length }
      : failedSurface("accounts", "account", "/accounts", accounts),
    zones.ok
      ? { name: "zones", scope: "zone", endpoint: "/zones", status: "readable", count: zoneItems.length }
      : failedSurface("zones", "zone", "/zones", zones),
  ];

  if (firstZoneId) {
    const settings = await attempt(() => client.getZoneSettings(firstZoneId));
    const settingErrors = settings.ok ? settings.value.filter((item) => asString(item.error)).length : 0;
    surfaces.push(
      settings.ok && settingErrors === 0
        ? { name: "zone_settings", scope: "zone", endpoint: `/zones/${firstZoneId}/settings/{setting_id}`, status: "readable", count: settings.value.length }
        : {
          name: "zone_settings",
          scope: "zone",
          endpoint: `/zones/${firstZoneId}/settings/{setting_id}`,
          status: "not_readable",
          count: null,
          http_status: settings.ok ? asNumber(settings.value.find((item) => asString(item.error))?.status) ?? null : settings.status ?? null,
          error: settings.ok
            ? `${settingErrors} of ${settings.value.length} zone settings could not be read: ${settings.value.filter((item) => asString(item.error)).map((item) => `${asString(item.id)}: ${asString(item.error)}`).join("; ")}`
            : settings.error,
        },
      await readableSurface("dnssec", "zone", `/zones/${firstZoneId}/dnssec`, () => client.getDnssec(firstZoneId)),
    );
    if (client.listZoneRulesets) {
      const listZoneRulesets = client.listZoneRulesets.bind(client);
      surfaces.push(await readableSurface("rulesets", "zone", `/zones/${firstZoneId}/rulesets`, () => listZoneRulesets(firstZoneId)));
    }
  } else if (!zones.ok) {
    // The zone list itself failed, so nothing zone-scoped was sent: the rows name the parent read and its
    // status rather than the not_configured rendering a readable-but-empty zone list earns.
    const parent = { endpoint: zones.endpoint ?? "/zones", status: zones.status, error: zones.error };
    surfaces.push(
      notAttemptedSurface("zone_settings", "zone", "/zones/{zone_id}/settings/{setting_id}", parent),
      notAttemptedSurface("dnssec", "zone", "/zones/{zone_id}/dnssec", parent),
    );
    if (client.listZoneRulesets) surfaces.push(notAttemptedSurface("rulesets", "zone", "/zones/{zone_id}/rulesets", parent));
  } else {
    surfaces.push(
      notConfiguredSurface("zone_settings", "zone", "/zones/{zone_id}/settings/{setting_id}", "No visible zones were available."),
      notConfiguredSurface("dnssec", "zone", "/zones/{zone_id}/dnssec", "No visible zones were available."),
    );
    if (client.listZoneRulesets) surfaces.push(notConfiguredSurface("rulesets", "zone", "/zones/{zone_id}/rulesets", "No visible zones were available."));
  }

  if (accountId) {
    surfaces.push(
      await readableSurface("members", "account", `/accounts/${accountId}/members`, () => client.listMembers(accountId)),
      await readableSurface("zero_trust_apps", "account", `/accounts/${accountId}/access/apps`, () => client.listAccessApplications(accountId)),
      await readableSurface("audit_logs", "account", `/accounts/${accountId}/audit_logs`, () => client.listAuditLogs(accountId)),
    );
  } else {
    surfaces.push(
      notConfiguredSurface("members", "account", "/accounts/{account_id}/members", note),
      notConfiguredSurface("zero_trust_apps", "account", "/accounts/{account_id}/access/apps", note),
      notConfiguredSurface("audit_logs", "account", "/accounts/{account_id}/audit_logs", note),
    );
  }

  const readableCount = surfaces.filter((surfaceItem) => surfaceItem.status === "readable").length;
  const notAttempted = surfaces.filter((surfaceItem) => surfaceItem.status === "not_attempted");
  const failedCount = surfaces.filter((surfaceItem) => surfaceItem.status === "not_readable").length;
  // A probe that failed or was never sent keeps the check at limited: not_configured rows (no account id,
  // readable-but-empty zone list) are the only non-readable rows a healthy check may carry.
  const status = readableCount >= 5 && failedCount === 0 && notAttempted.length === 0 ? "healthy" : "limited";

  return {
    status,
    authMethod: config.authMethod,
    accountId,
    surfaces,
    notes: [
      `Authenticated with ${config.authMethod === "token" ? "an API token" : "a Global API Key"}.`,
      note,
      `${readableCount}/${surfaces.length} Cloudflare audit surfaces are readable.`,
      ...(!zones.ok && notAttempted.length > 0
        ? [`${notAttempted.length} zone-scoped surfaces were not attempted because ${displayPath(zones.endpoint ?? "/zones")} could not be read (${zones.status ?? "no HTTP status"}).`]
        : []),
    ],
    recommendedNextStep:
      status === "healthy"
        ? "Run cloudflare_assess_identity, cloudflare_assess_zone_security, cloudflare_assess_traffic_controls, or cloudflare_export_audit_bundle."
        : "Provide a read-only API token and, when multiple accounts exist, set account_id to unlock account-scoped Cloudflare checks.",
  };
}

export async function assessCloudflareIdentity(
  client: Pick<
    CloudflareReader,
    "getResolvedConfig" | "verifyCurrentToken" | "listAccounts" | "listMembers" | "listAccessApplications" | "listAccessPolicies" | "listIdentityProviders" | "listUserTokens" | "listZones"
  > & Partial<Pick<CloudflareReader, "getUserToken" | "listAccountTokens">>,
  options: AssessmentOptions = {},
): Promise<CloudflareAssessmentResult> {
  const config = client.getResolvedConfig();
  const now = new Date();
  const maxSuperAdmins = clampNumber(options.maxSuperAdmins, DEFAULT_MAX_SUPER_ADMINS, 0, 100);
  const memberLimit = clampNumber(options.memberLimit, DEFAULT_MEMBER_LIMIT, 1, 5000);
  const tokenLimit = clampNumber(options.tokenLimit, DEFAULT_TOKEN_LIMIT, 1, 5000);
  const zoneLimit = clampNumber(options.zoneLimit, DEFAULT_ZONE_LIMIT, 1, 500);
  const errors: string[] = [];
  const recordError = <T>(label: string, outcome: ReadOutcome<T>): void => {
    if (!outcome.ok) errors.push(`${displayPath(label)}: ${outcome.error}`);
  };

  const [verify, accounts, zones, userTokens] = await Promise.all([
    attempt(() => client.verifyCurrentToken()),
    attemptList(() => client.listAccounts()),
    attemptList(() => client.listZones(zoneLimit)),
    attemptList(() => client.listUserTokens(tokenLimit)),
  ]);
  recordError("/user/tokens/verify", verify);
  recordError("/accounts", accounts);
  recordError("/zones", zones);
  recordError("/user/tokens", userTokens);
  const { accountId, note } = deriveAccountContext(config, accounts);

  const [members, accessApps, accessPolicies, identityProviders, accountTokens] = accountId
    ? await Promise.all([
      attemptList(() => client.listMembers(accountId, memberLimit)),
      attemptList(() => client.listAccessApplications(accountId)),
      attemptList(() => client.listAccessPolicies(accountId)),
      attemptList(() => client.listIdentityProviders(accountId)),
      // A client without the account token reader never attempted the read; that is an absent
      // outcome, not a readable empty list.
      client.listAccountTokens
        ? attemptList(() => client.listAccountTokens!(accountId, tokenLimit))
        : Promise.resolve<ReadOutcome<CloudflarePagedList> | undefined>(undefined),
    ])
    : [undefined, undefined, undefined, undefined, undefined];
  if (accountId) {
    recordError(`/accounts/${accountId}/members`, members!);
    recordError(`/accounts/${accountId}/access/apps`, accessApps!);
    recordError(`/accounts/${accountId}/access/policies`, accessPolicies!);
    recordError(`/accounts/${accountId}/access/identity_providers`, identityProviders!);
    if (accountTokens) recordError(`/accounts/${accountId}/tokens`, accountTokens);
  }

  const verified = verify.ok ? verify.value : null;
  const verifiedStatus = asString(verified?.status)?.toLowerCase();
  const verifiedId = asString(verified?.id);
  const tokenDetails = verifiedId && client.getUserToken
    ? await attempt(() => client.getUserToken!(verifiedId))
    : undefined;
  if (tokenDetails) recordError(`/user/tokens/${verifiedId}`, tokenDetails);
  const policies = tokenDetails?.ok ? asRecordArray(tokenDetails.value?.policies) : [];

  const findings: CloudflareFinding[] = [];

  findings.push(finding(
    "CF-IAM-01",
    "API credential type",
    "high",
    config.authMethod === "token" ? "pass" : "fail",
    config.authMethod === "token"
      ? "Cloudflare access is using an API token rather than a legacy Global API Key."
      : "Cloudflare access is using a legacy Global API Key; move to a scoped API token.",
    12,
    { auth_method: config.authMethod },
  ));

  if (config.authMethod !== "token") {
    findings.push(finding("CF-IAM-02", "Current token verification and scoping", "high", "manual",
      "Global API Key auth has no token to verify; create a scoped read-only API token and record its permission groups manually.", 12,
      { auth_method: config.authMethod }));
  } else if (!verify.ok) {
    findings.push(finding("CF-IAM-02", "Current token verification and scoping", "high", "manual",
      manualReason("/user/tokens/verify", "any valid API token (verify needs no extra permission)", "the token status and permission groups from the dashboard", verify.error), 12,
      { error: verify.error }));
  } else if (verifiedStatus !== "active") {
    findings.push(finding("CF-IAM-02", "Current token verification and scoping", "high", "fail",
      `The active API token reported status ${verifiedStatus ?? "unknown"} instead of active.`, 12,
      { verified_status: verifiedStatus ?? null }));
  } else if (!tokenDetails || !tokenDetails.ok) {
    findings.push(finding("CF-IAM-02", "Current token verification and scoping", "high", "manual",
      manualReason(
        tokenDetails && !tokenDetails.ok ? tokenDetails.endpoint ?? `/user/tokens/${verifiedId}` : `/user/tokens/${verifiedId ?? "{token_id}"}`,
        "User API Tokens: Read",
        "the token permission groups and resource scope",
        tokenDetails && !tokenDetails.ok ? tokenDetails.error : notAttempted("getUserToken").error,
      ), 12,
      { verified_status: verifiedStatus, token_id: verifiedId ?? null, ...(tokenDetails && !tokenDetails.ok ? { http_status: tokenDetails.status ?? null } : {}) }));
  } else {
    const broadPolicies = policies.filter((policy) => {
      const resources = asObject(policy.resources) ?? {};
      return Object.keys(resources).some((key) => /^com\.cloudflare\.api\.account\.zone\.\*$|^com\.cloudflare\.api\.account\.\*$|^com\.cloudflare\.api\.user\.\*$/.test(key));
    });
    const permissionGroups = policies.flatMap((policy) => asRecordArray(policy.permission_groups).map((group) => asString(group.name) ?? asString(group.id) ?? "unknown"));
    const writeGroups = permissionGroups.filter((name) => /write|edit|admin/i.test(name));
    const status: CloudflareFindingStatus = policies.length === 0 ? "fail" : writeGroups.length > 0 ? "warn" : "pass";
    findings.push(finding("CF-IAM-02", "Current token verification and scoping", "high", status,
      policies.length === 0
        ? "The active token verified as active but exposes no policies; confirm its scope manually."
        : writeGroups.length > 0
          ? `The active token is active but carries ${writeGroups.length} write-capable permission groups (${writeGroups.slice(0, 5).join(", ")}); audit tokens should be read-only.`
          : `The active token is active with ${permissionGroups.length} read-only permission groups across ${policies.length} policies.`,
      12,
      { verified_status: verifiedStatus, policies: policies.length, permission_groups: permissionGroups.slice(0, 50), write_capable_groups: writeGroups.slice(0, 50), broad_resource_policies: broadPolicies.length, expires_on: asString(verified?.expires_on) ?? null }));
  }

  const tokenSources: Array<{ label: string; outcome: ReadOutcome<CloudflarePagedList> | undefined }> = [
    { label: "/user/tokens", outcome: userTokens },
    { label: `/accounts/${accountId ?? "{account_id}"}/tokens`, outcome: accountTokens },
  ];
  const readableTokenLists = tokenSources.filter((source) => source.outcome?.ok);
  const failedTokenLists = tokenSources.filter((source) => source.outcome && !source.outcome.ok);
  const tokensReadable = readableTokenLists.length > 0;
  const allTokens = readableTokenLists.flatMap((source) => readList(source.outcome)?.items ?? []);
  const truncatedTokenLists = readableTokenLists.filter((source) => readList(source.outcome)?.truncated);
  const activeTokens = allTokens.filter((token) => asString(token.status) === "active");
  const tokensWithoutExpiry = activeTokens.filter((token) => !asDate(token.expires_on));
  const expiredButActive = activeTokens.filter((token) => {
    const expires = asDate(token.expires_on);
    return expires !== undefined && expires.getTime() < now.getTime();
  });
  const unknownStatusTokens = allTokens.filter((token) => !["active", "disabled", "expired"].includes(asString(token.status) ?? ""));
  const neverUsedTokens = activeTokens.filter((token) => !asDate(token.last_used_on));

  let tokenExpiryStatus: CloudflareFindingStatus;
  let tokenExpirySummary: string;
  if (readableTokenLists.length === 0) {
    tokenExpiryStatus = "manual";
    // Only the endpoints this run actually requested are named; an account token list that was never
    // attempted (no account context) is not reported as unreadable.
    const attemptedEndpoints = failedTokenLists.map((source) => (source.outcome && !source.outcome.ok ? source.outcome.endpoint : undefined) ?? source.label);
    tokenExpirySummary = manualReason(
      attemptedEndpoints.join(" and ") || "/user/tokens",
      "User API Tokens: Read and Account API Tokens: Read",
      "the API token inventory with expiry dates",
      failedTokenLists.map((source) => source.outcome && !source.outcome.ok ? source.outcome.error : "").filter(Boolean).join("; ") || "no token list readable",
    );
  } else if (allTokens.length === 0) {
    tokenExpiryStatus = "manual";
    tokenExpirySummary = "No API tokens were visible to this principal even though it authenticates with one; the inventory is scoped to other users or accounts. Manual review: export the token list from the dashboard (My Profile > API Tokens and Manage Account > API Tokens).";
  } else if (tokensWithoutExpiry.length > 0 || expiredButActive.length > 0) {
    tokenExpiryStatus = "fail";
    tokenExpirySummary = `${tokensWithoutExpiry.length} of ${activeTokens.length} active API tokens have no expires_on date${expiredButActive.length > 0 ? ` and ${expiredButActive.length} report active past their expiry` : ""}.`;
  } else if (unknownStatusTokens.length > 0 || truncatedTokenLists.length > 0 || failedTokenLists.length > 0) {
    tokenExpiryStatus = "warn";
    // Counts are scoped to the sources this run could read; a denied or truncated source is named as the
    // reason the verdict is capped rather than folded into the tally as zero.
    const scope = failedTokenLists.length > 0 || truncatedTokenLists.length > 0
      ? `the ${allTokens.length} readable ${allTokens.length === 1 ? "token" : "tokens"} (${readableTokenLists.map((source) => source.label).join(", ")})`
      : `all ${allTokens.length} inventoried tokens`;
    const caveats = [
      unknownStatusTokens.length > 0 ? `${unknownStatusTokens.length} ${unknownStatusTokens.length === 1 ? "has" : "have"} an undocumented status` : "",
      truncatedTokenLists.length > 0 ? `the token list was truncated (${truncatedTokenLists.map((source) => `${source.label}: ${readList(source.outcome)?.items.length ?? "unknown"} seen of ${readList(source.outcome)?.totalCount ?? "unknown"}`).join("; ")})` : "",
      failedTokenLists.length > 0 ? `${failedTokenLists.map((source) => source.label).join(", ")} could not be read, so tokens listed there were not assessed` : "",
    ].filter(Boolean);
    tokenExpirySummary = `${activeTokens.length} of ${scope} ${activeTokens.length === 1 ? "is" : "are"} active and every active one carries an expiry date, but ${caveats.join(", and ")}.`;
  } else {
    tokenExpiryStatus = "pass";
    tokenExpirySummary = `All ${activeTokens.length} active API tokens carry an expires_on date (${allTokens.length} tokens inventoried).`;
  }
  // Every count derived from the token inventory renders null, never zero, when no token list was readable.
  findings.push(finding("CF-IAM-06", "API token expiration", "medium", tokenExpiryStatus, tokenExpirySummary, 13, {
    tokens_seen: tokensReadable ? allTokens.length : null,
    active_tokens: tokensReadable ? activeTokens.length : null,
    tokens_without_expiry: tokensReadable ? tokensWithoutExpiry.slice(0, 50).map((token) => asString(token.name) ?? asString(token.id) ?? "unknown") : null,
    active_past_expiry: tokensReadable ? expiredButActive.length : null,
    never_used_active_tokens: tokensReadable ? neverUsedTokens.length : null,
    sources: tokenSources.map((source) => ({
      endpoint: source.outcome && !source.outcome.ok ? source.outcome.endpoint ?? source.label : source.label,
      readable: source.outcome ? source.outcome.ok : null,
      attempted: source.outcome !== undefined,
      seen: source.outcome?.ok ? source.outcome.value.items.length : null,
      total: source.outcome?.ok ? source.outcome.value.totalCount ?? null : null,
      truncated: source.outcome?.ok ? source.outcome.value.truncated : null,
      http_status: source.outcome && !source.outcome.ok ? source.outcome.status ?? null : null,
      error: source.outcome && !source.outcome.ok ? source.outcome.error : null,
    })),
  }));

  const memberList = readList(members);
  const superAdmins = (memberList?.items ?? []).filter((member) =>
    collectMemberRoleNames(member).some((role) => /super/i.test(role) && /admin/i.test(role)),
  );
  const membersWithout2fa = (memberList?.items ?? []).filter((member) => asBoolean(asObject(member.user)?.two_factor_authentication_enabled) === false);
  const membersPartial = memberList ? partialInventoryNote("member", memberList) : undefined;
  let memberStatus: CloudflareFindingStatus;
  let memberSummary: string;
  if (!accountId) {
    memberStatus = "manual";
    memberSummary = `${note} Collect the member list from Manage Account > Members.`;
  } else if (!members || !members.ok) {
    memberStatus = "manual";
    memberSummary = manualReason(`/accounts/${accountId}/members`, "Account Settings: Read", "the account member and role list", members && !members.ok ? members.error : undefined);
  } else if (memberList!.items.length === 0) {
    memberStatus = "manual";
    memberSummary = "The member list returned zero members, which cannot be right for an account with an authenticated principal; confirm the token can list members and review roles manually.";
  } else if (superAdmins.length > maxSuperAdmins) {
    memberStatus = "fail";
    memberSummary = `${superAdmins.length} Super Administrator assignments exceeded the configured threshold of ${maxSuperAdmins}.${membersPartial ? ` ${membersPartial}` : ""}`;
  } else {
    memberStatus = membersPartial || membersWithout2fa.length > 0 ? "warn" : "pass";
    memberSummary = `${superAdmins.length} Super Administrator assignments across ${memberList!.items.length} members, within the threshold of ${maxSuperAdmins}.${membersWithout2fa.length > 0 ? ` ${membersWithout2fa.length} members have two_factor_authentication_enabled false.` : ""}${membersPartial ? ` ${membersPartial}` : ""}`;
  }
  findings.push(finding("CF-IAM-03", "Account member privilege concentration", "medium", memberStatus, memberSummary, 14, {
    account_id: accountId ?? null,
    super_admins: memberList ? superAdmins.length : null,
    members_seen: memberList?.items.length ?? null,
    members_total: memberList?.totalCount ?? null,
    members_truncated: memberList?.truncated ?? null,
    members_without_2fa: memberList ? membersWithout2fa.length : null,
    ...(members && !members.ok ? { members_http_status: members.status ?? null, members_error: members.error } : {}),
  }));

  const apps = readList(accessApps);
  const reusablePolicies = readList(accessPolicies);
  const inlinePolicies = (apps?.items ?? []).flatMap((app) => asRecordArray(app.policies));
  const allPolicies = [...inlinePolicies, ...(reusablePolicies?.items ?? [])];
  const bypassPolicies = allPolicies.filter((policy) => asString(policy.decision) === "bypass");
  const appsWithoutPolicies = (apps?.items ?? []).filter((app) => {
    const type = asString(app.type);
    return asRecordArray(app.policies).length === 0 && type !== "app_launcher" && type !== "warp" && type !== "biso";
  });
  let accessStatus: CloudflareFindingStatus;
  let accessSummary: string;
  if (!accountId) {
    accessStatus = "manual";
    accessSummary = `${note} Review Zero Trust > Access > Applications manually.`;
  } else if (!accessApps || !accessApps.ok) {
    accessStatus = "manual";
    accessSummary = manualReason(`/accounts/${accountId}/access/apps`, "Access: Apps and Policies: Read", "the Access application and policy inventory", accessApps && !accessApps.ok ? accessApps.error : undefined);
  } else if (apps!.items.length === 0) {
    accessStatus = "manual";
    accessSummary = "No Access applications exist; if the account uses Zero Trust, confirm the Access subscription and app inventory manually. Zero apps cannot be judged compliant by default.";
  } else if (bypassPolicies.length > 0 || appsWithoutPolicies.length > 0) {
    accessStatus = "fail";
    accessSummary = `${bypassPolicies.length} Access policies use decision bypass and ${appsWithoutPolicies.length} applications have no attached policy.`;
  } else if (accessPolicies && !accessPolicies.ok) {
    // Reusable policies are where a bypass decision can hide outside any app's
    // inline list, so an unreadable policies endpoint blocks the pass.
    accessStatus = "manual";
    accessSummary = `${apps!.items.length} Access applications carry ${inlinePolicies.length} inline policies, none with bypass, but the reusable policy list could not be checked. ${manualReason(`/accounts/${accountId}/access/policies`, "Access: Apps and Policies: Read", "the reusable Access policy list and each policy's decision", accessPolicies.error)}`;
  } else {
    const partials = [partialInventoryNote("Access application", apps!), partialInventoryNote("reusable Access policy", reusablePolicies!)]
      .filter((entry): entry is string => Boolean(entry));
    accessStatus = partials.length > 0 ? "warn" : "pass";
    accessSummary = `${apps!.items.length} Access applications carry ${allPolicies.length} policies (${inlinePolicies.length} inline, ${reusablePolicies!.items.length} reusable; allow, deny, or non_identity), none with bypass.${partials.length > 0 ? ` ${partials.join(" ")}` : ""}`;
  }
  findings.push(finding("CF-IAM-04", "Zero Trust Access app and policy coverage", "high", accessStatus, accessSummary, 9, {
    access_apps: apps?.items.length ?? null,
    access_apps_total: apps?.totalCount ?? null,
    access_apps_truncated: apps?.truncated ?? null,
    inline_policies: apps ? inlinePolicies.length : null,
    reusable_policies: reusablePolicies?.items.length ?? null,
    reusable_policies_total: reusablePolicies?.totalCount ?? null,
    reusable_policies_readable: accessPolicies ? accessPolicies.ok : null,
    reusable_policies_truncated: reusablePolicies?.truncated ?? null,
    // Counted over the inline policies plus the reusable list when it was readable; null when no app list was read.
    bypass_policies: apps ? bypassPolicies.length : null,
    apps_without_policies: apps ? appsWithoutPolicies.slice(0, 25).map((app) => asString(app.name) ?? asString(app.id) ?? "unknown") : null,
    ...(accessApps && !accessApps.ok ? { access_apps_http_status: accessApps.status ?? null, access_apps_error: accessApps.error } : {}),
    ...(accessPolicies && !accessPolicies.ok ? { reusable_policies_http_status: accessPolicies.status ?? null, reusable_policies_error: accessPolicies.error } : {}),
  }));

  const idps = readList(identityProviders);
  const idpTypes = (idps?.items ?? []).map((idp) => asString(idp.type) ?? "unknown");
  const weakIdpTypes = idpTypes.filter((type) => type === "onetimepin");
  let idpStatus: CloudflareFindingStatus;
  let idpSummary: string;
  if (!accountId) {
    idpStatus = "manual";
    idpSummary = `${note} Review Zero Trust > Settings > Authentication manually.`;
  } else if (!identityProviders || !identityProviders.ok) {
    idpStatus = "manual";
    idpSummary = manualReason(`/accounts/${accountId}/access/identity_providers`, "Access: Organizations, Identity Providers, and Groups: Read", "the identity provider list", identityProviders && !identityProviders.ok ? identityProviders.error : undefined);
  } else if (idps!.items.length === 0) {
    idpStatus = "fail";
    idpSummary = "No Zero Trust identity providers are configured, so Access cannot enforce SSO or MFA-backed identity.";
  } else if (weakIdpTypes.length === idpTypes.length) {
    idpStatus = "fail";
    idpSummary = "Only the One-time PIN identity provider is configured; add an SSO or MFA-capable provider.";
  } else {
    const partial = partialInventoryNote("identity provider", idps!);
    idpStatus = weakIdpTypes.length > 0 || partial ? "warn" : "pass";
    idpSummary = `${idpTypes.length} identity providers configured (${[...new Set(idpTypes)].join(", ")})${weakIdpTypes.length > 0 ? "; One-time PIN remains enabled alongside SSO providers" : ""}.${partial ? ` ${partial}` : ""}`;
  }
  findings.push(finding("CF-IAM-05", "Zero Trust identity provider coverage", "medium", idpStatus, idpSummary, 10, {
    identity_providers: idps ? idpTypes.length : null,
    identity_provider_types: idps ? [...new Set(idpTypes)] : null,
    identity_providers_truncated: idps?.truncated ?? null,
    ...(identityProviders && !identityProviders.ok ? { identity_providers_http_status: identityProviders.status ?? null, identity_providers_error: identityProviders.error } : {}),
  }));

  // Summary counts render null, never the zero of an empty fallback, for every inventory whose read failed or never ran.
  return {
    title: "Cloudflare identity posture",
    summary: {
      auth_method: config.authMethod,
      account_id: accountId ?? null,
      visible_accounts: readList(accounts)?.items.length ?? null,
      sampled_zones: readList(zones)?.items.length ?? null,
      super_admins: memberList ? superAdmins.length : null,
      access_apps: apps?.items.length ?? null,
      access_policies: apps && reusablePolicies ? allPolicies.length : null,
      identity_providers: idps ? idpTypes.length : null,
      tokens_seen: tokensReadable ? allTokens.length : null,
      tokens_without_expiry: tokensReadable ? tokensWithoutExpiry.length : null,
      manual_findings: findings.filter((item) => item.status === "manual").length,
    },
    findings,
    errors,
  };
}

export async function assessCloudflareZoneSecurity(
  client: Pick<
    CloudflareReader,
    "listZones" | "getZoneSettings" | "getDnssec" | "listFirewallRules" | "listZoneRulesets" | "getUniversalSslSettings"
  > & Partial<Pick<CloudflareReader, "getZoneEntrypointRuleset" | "listDnsRecords" | "listCertificatePacks" | "getOriginTlsClientAuthSettings" | "listOriginTlsClientAuthHostnames">>,
  options: AssessmentOptions = {},
): Promise<CloudflareAssessmentResult> {
  const zoneLimit = clampNumber(options.zoneLimit, DEFAULT_ZONE_LIMIT, 1, 500);
  const now = new Date();
  const errors: string[] = [];
  const zonesOutcome = await attemptList(() => client.listZones(zoneLimit));
  if (!zonesOutcome.ok) errors.push(`/zones: ${zonesOutcome.error}`);
  const zones = readList(zonesOutcome);

  const managedWaf: ZoneVerdict[] = [];
  const customWaf: ZoneVerdict[] = [];
  const ddos: ZoneVerdict[] = [];
  const strictSsl: ZoneVerdict[] = [];
  const minTls: ZoneVerdict[] = [];
  const hsts: ZoneVerdict[] = [];
  const alwaysHttps: ZoneVerdict[] = [];
  const httpsRewrites: ZoneVerdict[] = [];
  const dnssec: ZoneVerdict[] = [];
  const universalSsl: ZoneVerdict[] = [];
  const originPulls: ZoneVerdict[] = [];
  const browserCheck: ZoneVerdict[] = [];
  const emailObfuscation: ZoneVerdict[] = [];
  const securityHeaders: ZoneVerdict[] = [];
  const dnsExposure: ZoneVerdict[] = [];
  // The deprecated firewall rules API is consulted only when a managed ruleset read fails; until then its count is unknown.
  let legacyFirewallRulesSeen: number | null = null;

  const entrypoint = (zoneId: string, phase: string): Promise<ReadOutcome<JsonRecord | null>> =>
    client.getZoneEntrypointRuleset
      ? attempt(() => client.getZoneEntrypointRuleset!(zoneId, phase))
      : Promise.resolve(notAttempted("getZoneEntrypointRuleset"));
  // The per-hostname association endpoint is documented in CF-ZONE-11 only on a run that requested it.
  const hostnameAssociationsRequested = Boolean(client.listOriginTlsClientAuthHostnames) && (zones?.items.length ?? 0) > 0;

  for (const zone of zones?.items ?? []) {
    const zoneId = asString(zone.id);
    if (!zoneId) continue;
    const name = zoneName(zone);
    const zoneErrors = (label: string, outcome: ReadOutcome<unknown>): void => {
      if (!outcome.ok) errors.push(`${name} ${label}: ${outcome.error}`);
    };

    const [settingsOutcome, dnssecOutcome, managedOutcome, customOutcome, ddosOutcome, headersOutcome, universalOutcome, originOutcome, originHostnamesOutcome, rulesetListOutcome, certPacksOutcome, dnsOutcome] = await Promise.all([
      attempt(() => client.getZoneSettings(zoneId)),
      attempt(() => client.getDnssec(zoneId)),
      entrypoint(zoneId, CLOUDFLARE_RULESET_PHASES.firewallManaged),
      entrypoint(zoneId, CLOUDFLARE_RULESET_PHASES.firewallCustom),
      entrypoint(zoneId, CLOUDFLARE_RULESET_PHASES.ddosL7),
      entrypoint(zoneId, CLOUDFLARE_RULESET_PHASES.responseHeadersTransform),
      attempt(() => client.getUniversalSslSettings(zoneId)),
      client.getOriginTlsClientAuthSettings
        ? attempt(() => client.getOriginTlsClientAuthSettings!(zoneId))
        : Promise.resolve(notAttempted("getOriginTlsClientAuthSettings")),
      client.listOriginTlsClientAuthHostnames
        ? attemptList(() => client.listOriginTlsClientAuthHostnames!(zoneId))
        : Promise.resolve(notAttempted("listOriginTlsClientAuthHostnames")),
      attemptList(() => client.listZoneRulesets(zoneId)),
      client.listCertificatePacks
        ? attemptList(() => client.listCertificatePacks!(zoneId))
        : Promise.resolve(notAttempted("listCertificatePacks")),
      client.listDnsRecords
        ? attemptList(() => client.listDnsRecords!(zoneId))
        : Promise.resolve(notAttempted("listDnsRecords")),
    ]);
    zoneErrors("zone settings", settingsOutcome);
    zoneErrors("/dnssec", dnssecOutcome);
    zoneErrors(`/rulesets/phases/${CLOUDFLARE_RULESET_PHASES.firewallManaged}/entrypoint`, managedOutcome);
    zoneErrors(`/rulesets/phases/${CLOUDFLARE_RULESET_PHASES.firewallCustom}/entrypoint`, customOutcome);
    zoneErrors(`/rulesets/phases/${CLOUDFLARE_RULESET_PHASES.ddosL7}/entrypoint`, ddosOutcome);
    zoneErrors(`/rulesets/phases/${CLOUDFLARE_RULESET_PHASES.responseHeadersTransform}/entrypoint`, headersOutcome);
    zoneErrors("/ssl/universal/settings", universalOutcome);
    zoneErrors("/origin_tls_client_auth/settings", originOutcome);
    zoneErrors("/origin_tls_client_auth/hostnames", originHostnamesOutcome);
    zoneErrors("/rulesets", rulesetListOutcome);
    zoneErrors("/ssl/certificate_packs", certPacksOutcome);
    zoneErrors("/dns_records", dnsOutcome);

    const settings = settingMap(settingsOutcome.ok ? settingsOutcome.value : []);
    if (!settingsOutcome.ok) {
      for (const settingId of CLOUDFLARE_ZONE_SETTING_IDS) settings.set(settingId, { error: settingsOutcome.error });
    } else {
      // getZoneSettings reports each failed per-setting read inline instead of throwing; every one is recorded.
      for (const [settingId, read] of settings) {
        if (read.error) errors.push(`${name} /settings/${settingId}: ${read.error}`);
      }
    }

    if (!managedOutcome.ok) {
      const legacy = await attemptList(() => client.listFirewallRules(zoneId));
      if (legacy.ok) legacyFirewallRulesSeen = (legacyFirewallRulesSeen ?? 0) + legacy.value.items.length;
    }
    managedWaf.push(entrypointVerdict(name, CLOUDFLARE_RULESET_PHASES.firewallManaged, managedOutcome, judgeManagedWaf, "Zone WAF: Read"));
    customWaf.push(entrypointVerdict(name, CLOUDFLARE_RULESET_PHASES.firewallCustom, customOutcome, judgeCustomWaf, "Zone WAF: Read"));
    const managedDdosListed = managedDdosL7Listed(rulesetListOutcome);
    ddos.push(entrypointVerdict(name, CLOUDFLARE_RULESET_PHASES.ddosL7, ddosOutcome, (ruleset) => judgeDdosL7(ruleset, managedDdosListed), "Zone WAF: Read"));
    securityHeaders.push(entrypointVerdict(name, CLOUDFLARE_RULESET_PHASES.responseHeadersTransform, headersOutcome, judgeSecurityHeaders, "Transform Rules: Read"));

    strictSsl.push(settingVerdict(name, settings, "ssl", (value) => {
      const mode = asString(value);
      if (mode === "strict") return { status: "pass", detail: "SSL mode is Full (Strict)." };
      if (mode === "full" || mode === "origin_pull") return { status: "warn", detail: `SSL mode is ${mode}, which does not validate the origin certificate chain.` };
      if (mode === "flexible" || mode === "off") return { status: "fail", detail: `SSL mode is ${mode}.` };
      return { status: "manual", detail: `SSL mode returned an undocumented value (${String(mode ?? "null")}).` };
    }));
    minTls.push(settingVerdict(name, settings, "min_tls_version", (value) => {
      const version = asString(value);
      if (version === "1.2" || version === "1.3") return { status: "pass", detail: `Minimum TLS version is ${version}.` };
      if (version === "1.0" || version === "1.1") return { status: "fail", detail: `Minimum TLS version is ${version}.` };
      return { status: "manual", detail: `min_tls_version returned an undocumented value (${String(version ?? "null")}).` };
    }));
    hsts.push(settingVerdict(name, settings, "security_header", (value) => {
      const sts = asObject(asObject(value)?.strict_transport_security);
      if (!sts) return { status: "manual", detail: "security_header did not include strict_transport_security; confirm HSTS in SSL/TLS > Edge Certificates." };
      const enabled = asBoolean(sts.enabled);
      const maxAge = asNumber(sts.max_age);
      if (enabled !== true) return { status: "fail", detail: "HSTS is not enabled." };
      if (maxAge === undefined || maxAge < HSTS_MIN_MAX_AGE_SECONDS) return { status: "fail", detail: `HSTS max_age is ${maxAge ?? "unset"}, below ${HSTS_MIN_MAX_AGE_SECONDS} seconds.` };
      if (asBoolean(sts.include_subdomains) !== true) return { status: "warn", detail: "HSTS is enabled without include_subdomains." };
      if (asBoolean(sts.preload) !== true) return { status: "warn", detail: "HSTS is enabled with include_subdomains but without preload." };
      return { status: "pass", detail: `HSTS enabled with max_age ${maxAge}, include_subdomains, and preload.` };
    }));
    alwaysHttps.push(settingVerdict(name, settings, "always_use_https", onOffJudge("Always Use HTTPS")));
    httpsRewrites.push(settingVerdict(name, settings, "automatic_https_rewrites", onOffJudge("Automatic HTTPS Rewrites")));
    browserCheck.push(settingVerdict(name, settings, "browser_check", onOffJudge("Browser Integrity Check")));
    emailObfuscation.push(settingVerdict(name, settings, "email_obfuscation", onOffJudge("Email Address Obfuscation")));

    if (!dnssecOutcome.ok) {
      dnssec.push(verdict(name, "manual", manualReason("/zones/{zone_id}/dnssec", "DNS: Read", "the DNSSEC status", dnssecOutcome.error)));
    } else {
      const status = asString(dnssecOutcome.value?.status);
      if (status === "active") dnssec.push(verdict(name, "pass", "DNSSEC status is active."));
      else if (status === "pending" || status === "pending-disabled") dnssec.push(verdict(name, "warn", `DNSSEC status is ${status}; the DS record is not yet live at the registrar.`));
      else if (status === "disabled" || status === "error") dnssec.push(verdict(name, "fail", `DNSSEC status is ${status}.`));
      else dnssec.push(verdict(name, "manual", `DNSSEC status returned an undocumented value (${String(status ?? "null")}).`));
    }

    if (!universalOutcome.ok) {
      universalSsl.push(verdict(name, "manual", manualReason("/zones/{zone_id}/ssl/universal/settings", "SSL and Certificates: Read", "the Universal SSL status and edge certificate list", universalOutcome.error)));
    } else if (asBoolean(universalOutcome.value?.enabled) !== true) {
      universalSsl.push(verdict(name, "fail", "Universal SSL is disabled for the zone."));
    } else if (!certPacksOutcome.ok) {
      universalSsl.push(verdict(name, "manual", manualReason("/zones/{zone_id}/ssl/certificate_packs", "SSL and Certificates: Read", "the certificate pack status and expiry dates", certPacksOutcome.error)));
    } else {
      const packs = certPacksOutcome.value.items;
      const activePacks = packs.filter((pack) => asString(pack.status) === "active");
      const certificates = activePacks.flatMap((pack) => asRecordArray(pack.certificates));
      const undatedCertificates = certificates.filter((certificate) => !asDate(certificate.expires_on));
      const expiredCertificates = certificates.filter((certificate) => {
        const expires = asDate(certificate.expires_on);
        return expires !== undefined && expires.getTime() < now.getTime();
      });
      const expiringSoon = certificates.filter((certificate) => {
        const expires = asDate(certificate.expires_on);
        return expires !== undefined && expires.getTime() >= now.getTime() && daysBetween(now, expires) <= CERTIFICATE_EXPIRY_WARNING_DAYS;
      });
      if (packs.length === 0) universalSsl.push(verdict(name, "fail", "Universal SSL is enabled but no certificate packs exist for the zone."));
      else if (activePacks.length === 0) universalSsl.push(verdict(name, "fail", `No certificate pack is active (statuses: ${[...new Set(packs.map((pack) => asString(pack.status) ?? "unknown"))].join(", ")}).`));
      else if (expiredCertificates.length > 0) universalSsl.push(verdict(name, "fail", `${expiredCertificates.length} certificates in active packs are past expires_on.`));
      else if (undatedCertificates.length > 0 || certificates.length === 0) universalSsl.push(verdict(name, "warn", `${activePacks.length} active certificate packs, but ${certificates.length === 0 ? "no certificate entries" : `${undatedCertificates.length} certificates without expires_on`} were returned, so validity cannot be confirmed.`));
      else if (expiringSoon.length > 0) universalSsl.push(verdict(name, "warn", `${expiringSoon.length} certificates expire within ${CERTIFICATE_EXPIRY_WARNING_DAYS} days.`));
      else if (certPacksOutcome.value.truncated) universalSsl.push(verdict(name, "warn", partialInventoryNote("certificate pack", certPacksOutcome.value) ?? "Certificate pack inventory was truncated."));
      else universalSsl.push(verdict(name, "pass", `${activePacks.length} active certificate packs with ${certificates.length} valid certificates.`));
    }

    originPulls.push(judgeOriginPulls(name, settings.get("tls_client_auth"), originOutcome, originHostnamesOutcome));

    if (!dnsOutcome.ok) {
      dnsExposure.push(verdict(name, "manual", manualReason("/zones/{zone_id}/dns_records", "DNS: Read", "the DNS record export", dnsOutcome.error)));
    } else {
      const records = dnsOutcome.value.items;
      const exposed = records.filter((record) => ["A", "AAAA", "CNAME"].includes(asString(record.type) ?? "") && asBoolean(record.proxied) === false && asBoolean(record.proxiable) !== false);
      const partial = partialInventoryNote("DNS record", dnsOutcome.value);
      if (records.length === 0) dnsExposure.push(verdict(name, "manual", "No DNS records were returned for the zone; confirm the zone is active and the token has DNS: Read."));
      else if (exposed.length > 0) dnsExposure.push(verdict(name, "warn", `${exposed.length} of ${records.length} A/AAAA/CNAME records are unproxied and expose origin addresses (${exposed.slice(0, 5).map((record) => asString(record.name) ?? "?").join(", ")}).${partial ? ` ${partial}` : ""}`));
      else if (partial) dnsExposure.push(verdict(name, "warn", partial));
      else dnsExposure.push(verdict(name, "pass", `All ${records.length} proxiable records are proxied through Cloudflare.`));
    }
  }

  const emptyZones = { emptyStatus: "manual" as CloudflareFindingStatus, emptyDetail: "No zones were visible to this token, so zone controls cannot be judged; grant Zone: Read or set account_id." };
  const findings = [
    aggregateZoneVerdicts("CF-ZONE-01", "WAF managed rulesets deployed", "high", 1, zonesOutcome, managedWaf, {
      ...emptyZones,
      passDetail: "Every sampled zone executes an enabled WAF managed ruleset in http_request_firewall_managed",
      extraEvidence: {
        legacy_firewall_rules_seen: legacyFirewallRulesSeen,
        // The deprecated endpoint is named only on a run that actually requested it.
        ...(legacyFirewallRulesSeen !== null ? { legacy_fallback: "GET /zones/{zone_id}/firewall/rules is deprecated and was consulted for evidence only because the rulesets API was unreadable." } : {}),
      },
    }),
    aggregateZoneVerdicts("CF-ZONE-06", "WAF custom rules with blocking actions", "medium", 2, zonesOutcome, customWaf, {
      ...emptyZones,
      passDetail: "Every sampled zone has enabled custom WAF rules with block or challenge actions",
    }),
    aggregateZoneVerdicts("CF-ZONE-07", "HTTP DDoS protection sensitivity", "high", 3, zonesOutcome, ddos, {
      ...emptyZones,
      passDetail: "Every sampled zone keeps HTTP DDoS override sensitivity at default or medium",
    }),
    aggregateZoneVerdicts("CF-ZONE-02", "SSL mode Full (Strict)", "high", 5, zonesOutcome, strictSsl, {
      ...emptyZones,
      passDetail: "Every sampled zone enforces Full (Strict) SSL mode",
    }),
    aggregateZoneVerdicts("CF-ZONE-03", "Minimum TLS version", "medium", 6, zonesOutcome, minTls, {
      ...emptyZones,
      passDetail: "Every sampled zone requires TLS 1.2 or newer",
    }),
    aggregateZoneVerdicts("CF-ZONE-04", "HSTS enforcement", "medium", 7, zonesOutcome, hsts, {
      ...emptyZones,
      passDetail: "Every sampled zone enables HSTS with max_age of at least six months, include_subdomains, and preload",
    }),
    aggregateZoneVerdicts("CF-ZONE-08", "Always Use HTTPS", "medium", 21, zonesOutcome, alwaysHttps, {
      ...emptyZones,
      passDetail: "Every sampled zone has Always Use HTTPS on",
    }),
    aggregateZoneVerdicts("CF-ZONE-09", "Automatic HTTPS Rewrites", "low", 22, zonesOutcome, httpsRewrites, {
      ...emptyZones,
      passDetail: "Every sampled zone has Automatic HTTPS Rewrites on",
    }),
    aggregateZoneVerdicts("CF-ZONE-05", "DNSSEC enabled", "medium", 8, zonesOutcome, dnssec, {
      ...emptyZones,
      passDetail: "Every sampled zone has DNSSEC status active",
    }),
    aggregateZoneVerdicts("CF-ZONE-10", "Universal SSL and certificate validity", "medium", 25, zonesOutcome, universalSsl, {
      ...emptyZones,
      passDetail: "Every sampled zone has Universal SSL enabled with active, unexpired certificate packs",
    }),
    aggregateZoneVerdicts("CF-ZONE-11", "Authenticated Origin Pulls", "medium", 18, zonesOutcome, originPulls, {
      ...emptyZones,
      passDetail: "Every sampled zone enables Authenticated Origin Pulls at the zone level and every per-hostname certificate association is active and enabled",
      extraEvidence: hostnameAssociationsRequested
        ? { per_hostname_source: `GET /zones/{zone_id}/origin_tls_client_auth/hostnames (OpenAPI operation per-hostname-authenticated-origin-pull-list-hostname-associations, per_page 1000, status=all): ${CLOUDFLARE_API_DOCS.originTlsClientAuthHostnamesList}` }
        : {},
    }),
    aggregateZoneVerdicts("CF-ZONE-12", "Browser Integrity Check", "low", 19, zonesOutcome, browserCheck, {
      ...emptyZones,
      passDetail: "Every sampled zone has Browser Integrity Check on",
    }),
    aggregateZoneVerdicts("CF-ZONE-13", "Email Address Obfuscation", "low", 20, zonesOutcome, emailObfuscation, {
      ...emptyZones,
      passDetail: "Every sampled zone has Email Address Obfuscation on",
    }),
    aggregateZoneVerdicts("CF-ZONE-14", "Security headers via transform rules", "medium", 23, zonesOutcome, securityHeaders, {
      ...emptyZones,
      passDetail: "Every sampled zone sets CSP, X-Frame-Options, X-Content-Type-Options, and Referrer-Policy through http_response_headers_transform rules",
    }),
    aggregateZoneVerdicts("CF-ZONE-15", "DNS record origin exposure", "low", undefined, zonesOutcome, dnsExposure, {
      ...emptyZones,
      passDetail: "Every sampled zone proxies all proxiable A/AAAA/CNAME records",
    }),
  ];

  return {
    title: "Cloudflare zone security posture",
    summary: {
      sampled_zones: zones?.items.length ?? null,
      zones_total: zones?.totalCount ?? null,
      zone_inventory_truncated: zones?.truncated ?? null,
      ...(zonesOutcome.ok ? {} : { zones_http_status: zonesOutcome.status ?? null, zones_error: zonesOutcome.error }),
      failing_findings: findings.filter((item) => item.status === "fail").length,
      warning_findings: findings.filter((item) => item.status === "warn").length,
      manual_findings: findings.filter((item) => item.status === "manual").length,
      passing_findings: findings.filter((item) => item.status === "pass").length,
    },
    findings,
    errors,
  };
}

export async function assessCloudflareTrafficControls(
  client: Pick<
    CloudflareReader,
    "getResolvedConfig" | "listAccounts" | "listZones" | "listRateLimits" | "listPageRules" | "getBotManagement" | "listAuditLogs" | "listGatewayRules" | "listIpAccessRules"
  > & Partial<Pick<CloudflareReader, "getZoneEntrypointRuleset" | "getZoneSubscription" | "getZeroTrustAccount">>,
  options: AssessmentOptions = {},
): Promise<CloudflareAssessmentResult> {
  const config = client.getResolvedConfig();
  const now = new Date();
  const zoneLimit = clampNumber(options.zoneLimit, DEFAULT_ZONE_LIMIT, 1, 500);
  const auditLimit = clampNumber(options.auditLimit, DEFAULT_AUDIT_LIMIT, 1, 5000);
  const errors: string[] = [];

  const [accountsOutcome, zonesOutcome] = await Promise.all([
    attemptList(() => client.listAccounts()),
    attemptList(() => client.listZones(zoneLimit)),
  ]);
  if (!accountsOutcome.ok) errors.push(`/accounts: ${accountsOutcome.error}`);
  if (!zonesOutcome.ok) errors.push(`/zones: ${zonesOutcome.error}`);
  const zones = readList(zonesOutcome);
  const { accountId, note } = deriveAccountContext(config, accountsOutcome);

  const rateLimiting: ZoneVerdict[] = [];
  const pageRules: ZoneVerdict[] = [];
  const botControls: ZoneVerdict[] = [];

  for (const zone of zones?.items ?? []) {
    const zoneId = asString(zone.id);
    if (!zoneId) continue;
    const name = zoneName(zone);
    const [rateLimitRuleset, pageRuleOutcome, botOutcome] = await Promise.all([
      client.getZoneEntrypointRuleset
        ? attempt(() => client.getZoneEntrypointRuleset!(zoneId, CLOUDFLARE_RULESET_PHASES.rateLimit))
        : Promise.resolve(notAttempted("getZoneEntrypointRuleset")),
      attemptList(() => client.listPageRules(zoneId)),
      attempt(() => client.getBotManagement(zoneId)),
    ]);
    if (!rateLimitRuleset.ok) errors.push(`${name} /rulesets/phases/${CLOUDFLARE_RULESET_PHASES.rateLimit}/entrypoint: ${rateLimitRuleset.error}`);
    if (!pageRuleOutcome.ok) errors.push(`${name} /pagerules: ${pageRuleOutcome.error}`);
    if (!botOutcome.ok) errors.push(`${name} /bot_management: ${botOutcome.error}`);

    if (rateLimitRuleset.ok) {
      const rulesetJudgement = judgeRateLimitRuleset(rateLimitRuleset.value);
      rateLimiting.push(verdict(name, rulesetJudgement.status, rulesetJudgement.detail));
    } else {
      const legacyRateLimits = await attemptList(() => client.listRateLimits(zoneId));
      if (!legacyRateLimits.ok) errors.push(`${name} /rate_limits: ${legacyRateLimits.error}`);
      const legacyEnabled = legacyRateLimits.ok ? legacyRateLimits.value.items.filter((rule) => asBoolean(rule.disabled) !== true) : [];
      const manualDetail = manualReason(`/zones/{zone_id}/rulesets/phases/${CLOUDFLARE_RULESET_PHASES.rateLimit}/entrypoint`, "Zone WAF: Read", "the rate limiting rule list", rateLimitRuleset.error);
      if (legacyEnabled.length > 0) rateLimiting.push(verdict(name, "warn", `The http_ratelimit entry point could not be read (${rateLimitRuleset.error}); the deprecated /rate_limits API shows ${legacyEnabled.length} enabled legacy rate limits as evidence only. Grant Zone WAF: Read and migrate them to http_ratelimit rules.`));
      else rateLimiting.push(verdict(name, "manual", `${manualDetail}${legacyRateLimits.ok ? " The deprecated /rate_limits API returned no enabled legacy rate limits." : ""}`));
    }

    if (!pageRuleOutcome.ok) pageRules.push(verdict(name, "manual", manualReason("/zones/{zone_id}/pagerules", "Page Rules: Read", "the page rule list", pageRuleOutcome.error)));
    else {
      const risky = pageRuleOutcome.value.items.filter(pageRuleIsRisky);
      if (risky.length > 0) pageRules.push(verdict(name, "fail", `${risky.length} active page rules weaken security (disable_security, security_level essentially_off, ssl off/flexible, or cache_everything on sensitive paths).`));
      else if (pageRuleOutcome.value.items.length === 0) pageRules.push(verdict(name, "pass", "No active page rules exist (status=active); emptiness is compliant because no active rule can weaken security."));
      else pageRules.push(verdict(name, "pass", `${pageRuleOutcome.value.items.length} active page rules, none security-degrading.`));
    }

    if (!botOutcome.ok) botControls.push(verdict(name, "manual", manualReason("/zones/{zone_id}/bot_management", "Bot Management: Read", "the Bot Fight Mode or Bot Management settings", botOutcome.error)));
    else {
      const judged = botManagementJudgement(botOutcome.value);
      const planNote = judged.status === "manual" ? await zonePlanNote(client, zoneId) : "";
      botControls.push(verdict(name, judged.status, `${judged.detail}${planNote}`));
    }
  }

  const [auditOutcome, gatewayOutcome, ipRulesOutcome, gatewayAccountOutcome] = accountId
    ? await Promise.all([
      attemptList(() => client.listAuditLogs(accountId, auditLimit)),
      attemptList(() => client.listGatewayRules(accountId)),
      attemptList(() => client.listIpAccessRules(accountId)),
      client.getZeroTrustAccount
        ? attempt(() => client.getZeroTrustAccount!(accountId))
        : Promise.resolve(notAttempted("getZeroTrustAccount")),
    ])
    : [undefined, undefined, undefined, undefined];
  if (accountId) {
    const accountLabel = displayPath(`/accounts/${accountId}`);
    if (!auditOutcome!.ok) errors.push(`${accountLabel}/audit_logs: ${auditOutcome!.error}`);
    if (!gatewayOutcome!.ok) errors.push(`${accountLabel}/gateway/rules: ${gatewayOutcome!.error}`);
    if (!gatewayAccountOutcome!.ok) errors.push(`${accountLabel}/gateway: ${gatewayAccountOutcome!.error}`);
    if (!ipRulesOutcome!.ok) errors.push(`${accountLabel}/firewall/access_rules/rules: ${ipRulesOutcome!.error}`);
  }

  const emptyZones = { emptyStatus: "manual" as CloudflareFindingStatus, emptyDetail: "No zones were visible to this token, so zone traffic controls cannot be judged; grant Zone: Read or set account_id." };
  const findings: CloudflareFinding[] = [
    aggregateZoneVerdicts("CF-TRF-01", "Rate limiting coverage", "medium", 16, zonesOutcome, rateLimiting, {
      ...emptyZones,
      passDetail: "Every sampled zone has enabled rate limiting rules",
    }),
    aggregateZoneVerdicts("CF-TRF-02", "Page rule security regressions", "medium", 15, zonesOutcome, pageRules, {
      ...emptyZones,
      passDetail: "No sampled zone has page rules that weaken security",
    }),
    aggregateZoneVerdicts("CF-TRF-03", "Bot and automated traffic controls", "medium", 4, zonesOutcome, botControls, {
      ...emptyZones,
      passDetail: "Every sampled zone enforces Bot Fight Mode or Super Bot Fight Mode",
    }),
  ];

  const auditLogs = readList(auditOutcome);
  if (!accountId) {
    findings.push(finding("CF-TRF-04", "Account audit log visibility", "high", "manual", `${note} Export the audit log from Manage Account > Audit Log.`, 11, { account_id: null }));
  } else if (!auditOutcome!.ok) {
    findings.push(finding("CF-TRF-04", "Account audit log visibility", "high", "manual", manualReason(auditOutcome!.endpoint ?? `/accounts/${accountId}/audit_logs`, "Account Settings: Read", `the last ${AUDIT_LOG_LOOKBACK_DAYS} days of audit log events`, auditOutcome!.error), 11, { account_id: accountId, audit_events: null, http_status: auditOutcome!.status ?? null }));
  } else if (auditLogs!.items.length === 0) {
    findings.push(finding("CF-TRF-04", "Account audit log visibility", "high", "manual", `No audit log events were returned for the last ${AUDIT_LOG_LOOKBACK_DAYS} days; Cloudflare always records account changes, so confirm visibility in Manage Account > Audit Log and check the token scope.`, 11, { account_id: accountId, audit_events: 0 }));
  } else {
    const newest = auditLogs!.items.map((event) => asDate(event.when)).filter((item): item is Date => Boolean(item)).sort((a, b) => b.getTime() - a.getTime())[0];
    const failedActions = auditLogs!.items.filter((event) => asBoolean(asObject(event.action)?.result) === false).length;
    const partial = partialInventoryNote("audit event", auditLogs!);
    findings.push(finding("CF-TRF-04", "Account audit log visibility", "high", partial ? "warn" : "pass", `${auditLogs!.items.length} audit log events were readable for the last ${AUDIT_LOG_LOOKBACK_DAYS} days${newest ? ` (newest ${newest.toISOString()})` : ""}; ${failedActions} recorded failed actions. Retention beyond the API window is a manual check.${partial ? ` ${partial}` : ""}`, 11, {
      account_id: accountId,
      audit_events: auditLogs!.items.length,
      newest_event: newest?.toISOString() ?? null,
      failed_actions: failedActions,
      truncated: auditLogs!.truncated,
    }));
  }

  const ipRules = readList(ipRulesOutcome);
  if (!accountId) {
    findings.push(finding("CF-TRF-05", "IP access rules", "medium", "manual", `${note} Review Security > WAF > Tools manually.`, 17, { account_id: null }));
  } else if (!ipRulesOutcome!.ok) {
    findings.push(finding("CF-TRF-05", "IP access rules", "medium", "manual", manualReason(ipRulesOutcome!.endpoint ?? `/accounts/${accountId}/firewall/access_rules/rules`, "Account Firewall Access Rules: Read", "the IP access rule list with notes and modified dates", ipRulesOutcome!.error), 17, { account_id: accountId, ip_access_rules: null, http_status: ipRulesOutcome!.status ?? null }));
  } else {
    const stale = ipRules!.items.filter((rule) => {
      const modified = asDate(rule.modified_on);
      return modified === undefined || daysBetween(modified, now) > STALE_IP_RULE_DAYS;
    });
    const allowRules = ipRules!.items.filter((rule) => asString(rule.mode) === "whitelist");
    const undocumented = ipRules!.items.filter((rule) => !asString(rule.notes));
    const partial = partialInventoryNote("IP access rule", ipRules!);
    const status: CloudflareFindingStatus = ipRules!.items.length === 0
      ? "pass"
      : stale.length > 0 || undocumented.length > 0 || partial
        ? "warn"
        : "pass";
    findings.push(finding("CF-TRF-05", "IP access rules", "medium", status,
      ipRules!.items.length === 0
        ? "No account-level IP access rules exist; emptiness is compliant because there are no allowlist entries to go stale."
        : `${ipRules!.items.length} IP access rules (${allowRules.length} allow, ${stale.length} unmodified for over ${STALE_IP_RULE_DAYS} days or undated, ${undocumented.length} without notes).${partial ? ` ${partial}` : ""}`,
      17,
      { account_id: accountId, ip_access_rules: ipRules!.items.length, allow_rules: allowRules.length, stale_rules: stale.length, rules_without_notes: undocumented.length, truncated: ipRules!.truncated }));
  }

  const gatewayRules = readList(gatewayOutcome);
  if (!accountId) {
    findings.push(finding("CF-TRF-06", "Gateway SWG policies", "medium", "manual", `${note} Review Zero Trust > Gateway > Firewall policies manually.`, 24, { account_id: null }));
  } else if (!gatewayOutcome!.ok) {
    findings.push(finding("CF-TRF-06", "Gateway SWG policies", "medium", "manual", manualReason(gatewayOutcome!.endpoint ?? `/accounts/${accountId}/gateway/rules`, "Zero Trust: Read", "the Gateway DNS and HTTP policy list", gatewayOutcome!.error), 24, { account_id: accountId, gateway_rules: null, http_status: gatewayOutcome!.status ?? null }));
  } else {
    const enabled = gatewayRules!.items.filter((rule) => asBoolean(rule.enabled) !== false);
    const filters = new Set(enabled.flatMap((rule) => asArray(rule.filters).map((item) => asString(item) ?? "")));
    const blocking = enabled.filter((rule) => ["block", "isolate", "override", "quarantine"].includes(asString(rule.action) ?? ""));
    if (gatewayRules!.items.length === 0) {
      const gatewayTag = gatewayAccountOutcome!.ok ? asString(gatewayAccountOutcome!.value?.gateway_tag) : undefined;
      if (gatewayTag) {
        findings.push(finding("CF-TRF-06", "Gateway SWG policies", "medium", "fail", `Zero Trust Gateway is provisioned for this account (gateway_tag ${gatewayTag} from /accounts/{account_id}/gateway) but no Gateway DNS or HTTP policies exist.`, 24, { account_id: accountId, gateway_rules: 0, gateway_tag: gatewayTag }));
      } else {
        findings.push(finding("CF-TRF-06", "Gateway SWG policies", "medium", "manual", `No Gateway rules exist and ${gatewayAccountOutcome!.ok ? "/accounts/{account_id}/gateway returned no gateway_tag" : `/accounts/{account_id}/gateway could not be read (${gatewayAccountOutcome!.error})`}. Zero Trust Gateway requires a Zero Trust subscription with the Gateway product; confirm whether Gateway is licensed and, if so, define DNS and HTTP filtering policies.`, 24, { account_id: accountId, gateway_rules: 0, gateway_tag: null }));
      }
    } else if (blocking.length === 0 || !(filters.has("dns") || filters.has("http"))) {
      findings.push(finding("CF-TRF-06", "Gateway SWG policies", "medium", "fail", `${enabled.length} enabled Gateway rules, but none block, isolate, or override on DNS or HTTP filters.`, 24, { account_id: accountId, gateway_rules: gatewayRules!.items.length, enabled_rules: enabled.length, filters: [...filters] }));
    } else {
      const partial = partialInventoryNote("Gateway rule", gatewayRules!);
      findings.push(finding("CF-TRF-06", "Gateway SWG policies", "medium", partial ? "warn" : "pass", `${enabled.length} enabled Gateway rules (${blocking.length} blocking or isolating) across filters ${[...filters].join(", ")}.${partial ? ` ${partial}` : ""}`, 24, { account_id: accountId, gateway_rules: gatewayRules!.items.length, enabled_rules: enabled.length, blocking_rules: blocking.length, filters: [...filters] }));
    }
  }

  return {
    title: "Cloudflare traffic controls posture",
    summary: {
      account_id: accountId ?? null,
      sampled_zones: zones?.items.length ?? null,
      zones_total: zones?.totalCount ?? null,
      zone_inventory_truncated: zones?.truncated ?? null,
      ...(zonesOutcome.ok ? {} : { zones_http_status: zonesOutcome.status ?? null, zones_error: zonesOutcome.error }),
      audit_events: auditLogs?.items.length ?? null,
      gateway_rules: gatewayRules?.items.length ?? null,
      ip_access_rules: ipRules?.items.length ?? null,
      failing_findings: findings.filter((item) => item.status === "fail").length,
      warning_findings: findings.filter((item) => item.status === "warn").length,
      manual_findings: findings.filter((item) => item.status === "manual").length,
      passing_findings: findings.filter((item) => item.status === "pass").length,
    },
    findings,
    errors,
  };
}

function formatAccessCheckText(result: CloudflareAccessCheckResult): string {
  const rows = result.surfaces.map((surfaceItem) => [
    surfaceItem.name,
    surfaceItem.scope,
    surfaceItem.status,
    surfaceItem.count === undefined || surfaceItem.count === null ? "-" : String(surfaceItem.count),
    // Error strings are already scrubbed and bounded (non-JSON bodies are described, not echoed), so the
    // full text is kept rather than sliced mid-path.
    surfaceItem.error ? surfaceItem.error.replace(/\s+/g, " ") : "",
  ]);
  return [
    `Cloudflare access check: ${result.status}`,
    "",
    ...result.notes,
    "",
    formatTable(["Surface", "Scope", "Status", "Count", "Note"], rows),
    "",
    `Next: ${result.recommendedNextStep}`,
  ].join("\n");
}

function formatAssessmentText(result: CloudflareAssessmentResult): string {
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
    ...(result.errors.length > 0 ? ["", `Read errors (${result.errors.length}): see _errors.log in exported bundles.`] : []),
  ].join("\n");
}

function statusCounts(findings: CloudflareFinding[]): Record<CloudflareFindingStatus, number> {
  return {
    pass: findings.filter((item) => item.status === "pass").length,
    warn: findings.filter((item) => item.status === "warn").length,
    fail: findings.filter((item) => item.status === "fail").length,
    manual: findings.filter((item) => item.status === "manual").length,
  };
}

function buildExecutiveSummary(config: CloudflareResolvedConfig, assessments: CloudflareAssessmentResult[], generatedAt: string): string {
  const findings = assessments.flatMap((assessment) => assessment.findings);
  const counts = statusCounts(findings);

  return [
    "# Cloudflare Executive Summary",
    "",
    `Auth method: ${config.authMethod}`,
    `Account: ${config.accountId ?? "auto / unspecified"}`,
    `Generated: ${generatedAt}`,
    "",
    "## Result Counts",
    "",
    `- Failed controls: ${counts.fail}`,
    `- Warning controls: ${counts.warn}`,
    `- Manual review controls: ${counts.manual}`,
    `- Passing controls: ${counts.pass}`,
    "",
    "## Status Semantics",
    "",
    "- pass: every sampled item met the control with documented evidence",
    "- warn: partially met, or the inventory was partial so unseen items were not judged",
    "- fail: at least one sampled item violates the control",
    "- manual: the API could not prove the control (permission denied, plan not present, or no automatable signal); the summary names the evidence to collect",
    "",
    "## Highest Priority Findings",
    "",
    ...findings
      .filter((item) => item.status === "fail" || item.status === "warn")
      .sort((a, b) => STATUS_RANK[b.status] - STATUS_RANK[a.status])
      .slice(0, 10)
      .map((item) => `- ${item.id} (${item.severity.toUpperCase()} / ${item.status.toUpperCase()}): ${item.summary}`),
    "",
    "## Manual Review Queue",
    "",
    ...findings
      .filter((item) => item.status === "manual")
      .map((item) => `- ${item.id}: ${item.summary}`),
  ].join("\n");
}

function buildUnifiedMatrix(findings: CloudflareFinding[]): string {
  const rows = findings.map((item) => [
    item.id,
    item.specControl ? String(item.specControl) : "-",
    item.status.toUpperCase(),
    item.title,
    ...CLOUDFLARE_FRAMEWORKS.map((framework) => frameworkControlFor(item, framework.key)),
  ]);
  return [
    "# Cloudflare Unified Compliance Matrix",
    "",
    formatTable(["Finding", "Spec", "Status", "Title", ...CLOUDFLARE_FRAMEWORKS.map((framework) => framework.label)], rows),
  ].join("\n");
}

/**
 * Shortens report cells without splitting a token, so a cut summary never leaves a partial endpoint
 * path or status behind; the ellipsis marks that the full text lives in analysis/findings.json.
 */
function truncateAtWordBoundary(text: string, maxLength: number): string {
  if (text.length <= maxLength) return text;
  const head = text.slice(0, maxLength);
  const boundary = head.lastIndexOf(" ");
  if (boundary <= 0) return text;
  return `${head.slice(0, boundary).replace(/[\s(,;:]+$/, "")} …`;
}

function buildFrameworkReport(framework: { key: keyof ControlMapping; label: string }, findings: CloudflareFinding[], generatedAt: string): string {
  const mapped = findings.filter((item) => frameworkControlFor(item, framework.key) !== "n/a");
  const counts = statusCounts(mapped);
  const rows = mapped.map((item) => [
    frameworkControlFor(item, framework.key),
    item.id,
    item.status.toUpperCase(),
    item.title,
    truncateAtWordBoundary(item.summary, 160),
  ]);
  return [
    `# ${framework.label} Compliance Report (Cloudflare)`,
    "",
    `Generated: ${generatedAt}`,
    "",
    `Mapped findings: ${mapped.length} (pass ${counts.pass}, warn ${counts.warn}, fail ${counts.fail}, manual ${counts.manual})`,
    "",
    formatTable([`${framework.label} control`, "Finding", "Status", "Title", "Summary"], rows),
  ].join("\n");
}

function buildQuickReference(result: { outputDirName: string; findings: CloudflareFinding[]; errorCount: number }): string {
  const counts = statusCounts(result.findings);
  return [
    "# Quick Reference",
    "",
    `Bundle: ${result.outputDirName}`,
    `Findings: ${result.findings.length} (pass ${counts.pass}, warn ${counts.warn}, fail ${counts.fail}, manual ${counts.manual})`,
    `Read errors: ${result.errorCount}${result.errorCount > 0 ? " (see _errors.log)" : ""}`,
    "",
    "## Start Here",
    "",
    "1. `compliance/executive_summary.md` for prioritized failures and the manual review queue",
    "2. `compliance/unified_compliance_matrix.md` for every finding mapped across frameworks",
    "3. `compliance/<framework>/` for one report per framework",
    "4. `analysis/*.json` for the evidence behind each finding",
    "5. `core_data/*.json` for the raw inventories the findings were judged from",
    "",
    "## Tools",
    "",
    "- cloudflare_check_access",
    "- cloudflare_assess_identity",
    "- cloudflare_assess_zone_security",
    "- cloudflare_assess_traffic_controls",
    "- cloudflare_export_audit_bundle",
  ].join("\n");
}

function buildBundleReadme(): string {
  return [
    "# Cloudflare Evidence Bundle",
    "",
    "This bundle was generated by grclanker's native Cloudflare tools.",
    "",
    "## Contents",
    "",
    "- `QUICK_REFERENCE.md`: where to start",
    "- `summary.md`: combined human-readable assessment output",
    "- `compliance/executive_summary.md`: prioritized audit summary and manual review queue",
    "- `compliance/unified_compliance_matrix.md`: every finding mapped across FedRAMP, CMMC, SOC 2, CIS, PCI-DSS, STIG, IRAP, and ISMAP",
    "- `compliance/<framework>/*_compliance_report.md`: one report per framework",
    "- `analysis/*.json`: normalized findings and assessment details",
    "- `core_data/*.json`: raw inventories (access surfaces, accounts, zones)",
    "- `metadata.json`: non-secret run metadata",
    "- `_errors.log`: present only when some reads failed but the bundle still completed",
    "",
    "Credentials are never written into the bundle. Re-running the export allocates a new directory and zip instead of overwriting.",
  ].join("\n");
}

export async function exportCloudflareAuditBundle(
  client: Pick<
    CloudflareReader,
    | "getResolvedConfig"
    | "verifyCurrentToken"
    | "listAccounts"
    | "listZones"
    | "getZoneSettings"
    | "getDnssec"
    | "listMembers"
    | "listAccessApplications"
    | "listAuditLogs"
    | "listAccessPolicies"
    | "listIdentityProviders"
    | "listUserTokens"
    | "listFirewallRules"
    | "listZoneRulesets"
    | "getUniversalSslSettings"
    | "listRateLimits"
    | "listPageRules"
    | "getBotManagement"
    | "listGatewayRules"
    | "listIpAccessRules"
  > & Partial<CloudflareReader>,
  config: CloudflareResolvedConfig,
  outputRoot: string,
  options: AssessmentOptions = {},
): Promise<CloudflareAuditBundleResult> {
  const generatedAt = new Date().toISOString();
  const access = await checkCloudflareAccess(client);
  const identity = await assessCloudflareIdentity(client, options);
  const zoneSecurity = await assessCloudflareZoneSecurity(client, options);
  const trafficControls = await assessCloudflareTrafficControls(client, options);
  const assessments = [identity, zoneSecurity, trafficControls];
  const findings = assessments.flatMap((assessment) => assessment.findings);
  const errors = assessments.flatMap((assessment) => assessment.errors.map((item) => `${assessment.title}: ${item}`));
  const [accounts, zones] = await Promise.all([
    attemptList(() => client.listAccounts()),
    attemptList(() => client.listZones(options.zoneLimit)),
  ]);

  ensurePrivateDir(outputRoot);
  const outputDir = await nextAvailableAuditDir(
    outputRoot,
    `${safeDirName(config.accountId ?? "cloudflare-account")}-audit-bundle`,
  );
  const outputDirName = basename(outputDir);

  await writeSecureTextFile(outputDir, "README.md", `${buildBundleReadme()}\n`);
  await writeSecureTextFile(outputDir, "QUICK_REFERENCE.md", `${buildQuickReference({ outputDirName, findings, errorCount: errors.length })}\n`);
  await writeSecureTextFile(outputDir, "metadata.json", serializeJson({
    generated_at: generatedAt,
    auth_method: config.authMethod,
    account_id: config.accountId ?? null,
    source_chain: config.sourceChain,
    finding_count: findings.length,
    error_count: errors.length,
    status_counts: statusCounts(findings),
  }));
  await writeSecureTextFile(
    outputDir,
    "summary.md",
    [
      formatAccessCheckText(access),
      "",
      formatAssessmentText(identity),
      "",
      formatAssessmentText(zoneSecurity),
      "",
      formatAssessmentText(trafficControls),
    ].join("\n"),
  );
  await writeSecureTextFile(outputDir, "compliance/executive_summary.md", `${buildExecutiveSummary(config, assessments, generatedAt)}\n`);
  await writeSecureTextFile(outputDir, "compliance/unified_compliance_matrix.md", `${buildUnifiedMatrix(findings)}\n`);
  for (const framework of CLOUDFLARE_FRAMEWORKS) {
    await writeSecureTextFile(outputDir, `compliance/${framework.slug}/${framework.slug}_compliance_report.md`, `${buildFrameworkReport(framework, findings, generatedAt)}\n`);
  }
  await writeSecureTextFile(outputDir, "analysis/findings.json", serializeJson(findings));
  await writeSecureTextFile(outputDir, "analysis/identity.json", serializeJson(identity));
  await writeSecureTextFile(outputDir, "analysis/zone-security.json", serializeJson(zoneSecurity));
  await writeSecureTextFile(outputDir, "analysis/traffic-controls.json", serializeJson(trafficControls));
  await writeSecureTextFile(outputDir, "core_data/access.json", serializeJson(access));
  // A denied or failed list is written as a not-collected marker carrying the observed status and path, never as an empty list.
  await writeSecureTextFile(outputDir, "core_data/accounts.json", serializeJson(accounts.ok ? projectPagedList(accounts.value, projectAccountRecord) : uncollectedMarker(accounts, "not collected")));
  await writeSecureTextFile(outputDir, "core_data/zones.json", serializeJson(zones.ok ? projectPagedList(zones.value, projectZoneRecord) : uncollectedMarker(zones, "not collected")));
  if (errors.length > 0) {
    await writeSecureTextFile(outputDir, "_errors.log", `${errors.map((item) => `${generatedAt} ${item}`).join("\n")}\n`);
  }

  const zipPath = resolveSecureOutputPath(outputRoot, `${outputDirName}.zip`);
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
    api_token: asString(value.api_token) ?? asString(value.token),
    api_key: asString(value.api_key),
    email: asString(value.email),
    account_id: asString(value.account_id),
    base_url: asString(value.base_url),
    timeout_seconds: asNumber(value.timeout_seconds),
  };
}

function normalizeIdentityArgs(args: unknown): IdentityArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeCheckAccessArgs(args),
    max_super_admins: asNumber(value.max_super_admins),
    member_limit: asNumber(value.member_limit),
    token_limit: asNumber(value.token_limit),
    zone_limit: asNumber(value.zone_limit),
  };
}

function normalizeZoneSecurityArgs(args: unknown): ZoneSecurityArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeCheckAccessArgs(args),
    zone_limit: asNumber(value.zone_limit),
  };
}

function normalizeTrafficArgs(args: unknown): TrafficArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeCheckAccessArgs(args),
    zone_limit: asNumber(value.zone_limit),
    audit_limit: asNumber(value.audit_limit),
  };
}

function normalizeExportAuditBundleArgs(args: unknown): ExportAuditBundleArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeIdentityArgs(args),
    audit_limit: asNumber(value.audit_limit),
    output_dir: asString(value.output_dir) ?? asString(value.output),
  };
}

function createClient(args: CheckAccessArgs): CloudflareApiClient {
  return new CloudflareApiClient(resolveCloudflareConfiguration(args));
}

const authParams = {
  api_token: Type.Optional(Type.String({ description: "Cloudflare API token. Defaults to CLOUDFLARE_API_TOKEN." })),
  api_key: Type.Optional(Type.String({ description: "Legacy Cloudflare Global API Key. Defaults to CLOUDFLARE_API_KEY." })),
  email: Type.Optional(Type.String({ description: "Cloudflare account email for Global API Key auth. Defaults to CLOUDFLARE_EMAIL." })),
  account_id: Type.Optional(Type.String({ description: "Cloudflare account ID for account-scoped checks. Defaults to CLOUDFLARE_ACCOUNT_ID." })),
  base_url: Type.Optional(Type.String({ description: "Cloudflare API base URL. Defaults to https://api.cloudflare.com/client/v4." })),
  timeout_seconds: Type.Optional(Type.Number({ description: "HTTP timeout in seconds. Defaults to 30.", default: 30 })),
};

export function registerCloudflareTools(pi: any): void {
  pi.registerTool({
    name: "cloudflare_check_access",
    label: "Check Cloudflare audit access",
    description:
      "Validate read-only Cloudflare access across token verification, accounts, zones, zone settings, DNSSEC, rulesets, members, Zero Trust apps, and audit logs.",
    parameters: Type.Object(authParams),
    prepareArguments: normalizeCheckAccessArgs,
    async execute(_toolCallId: string, args: CheckAccessArgs) {
      try {
        const result = await checkCloudflareAccess(createClient(args));
        return textResult(formatAccessCheckText(result), { tool: "cloudflare_check_access", ...result });
      } catch (error) {
        return errorResult(
          `Cloudflare access check failed: ${errorMessage(error)}`,
          { tool: "cloudflare_check_access" },
        );
      }
    },
  });

  pi.registerTool({
    name: "cloudflare_assess_identity",
    label: "Assess Cloudflare identity posture",
    description:
      "Assess Cloudflare authentication method, token verification and scoping, API token expiration, member privilege concentration, Zero Trust Access coverage, and identity provider posture.",
    parameters: Type.Object({
      ...authParams,
      max_super_admins: Type.Optional(Type.Number({ description: "Maximum acceptable Super Administrator assignments before failing. Defaults to 2.", default: 2 })),
      member_limit: Type.Optional(Type.Number({ description: "Maximum account members to inspect. Defaults to 200.", default: 200 })),
      token_limit: Type.Optional(Type.Number({ description: "Maximum API tokens to inspect. Defaults to 200.", default: 200 })),
      zone_limit: Type.Optional(Type.Number({ description: "Maximum zones to sample. Defaults to 20.", default: 20 })),
    }),
    prepareArguments: normalizeIdentityArgs,
    async execute(_toolCallId: string, args: IdentityArgs) {
      try {
        const result = await assessCloudflareIdentity(createClient(args), {
          maxSuperAdmins: args.max_super_admins,
          memberLimit: args.member_limit,
          tokenLimit: args.token_limit,
          zoneLimit: args.zone_limit,
        });
        return textResult(formatAssessmentText(result), { tool: "cloudflare_assess_identity", ...result });
      } catch (error) {
        return errorResult(
          `Cloudflare identity assessment failed: ${errorMessage(error)}`,
          { tool: "cloudflare_assess_identity" },
        );
      }
    },
  });

  pi.registerTool({
    name: "cloudflare_assess_zone_security",
    label: "Assess Cloudflare zone security",
    description:
      "Assess Cloudflare zone security across WAF managed and custom rulesets, HTTP DDoS sensitivity, strict SSL, minimum TLS, HSTS, HTTPS enforcement, DNSSEC, Universal SSL certificates, Authenticated Origin Pulls, Browser Integrity Check, email obfuscation, security header transform rules, and DNS origin exposure.",
    parameters: Type.Object({
      ...authParams,
      zone_limit: Type.Optional(Type.Number({ description: "Maximum zones to sample. Defaults to 20.", default: 20 })),
    }),
    prepareArguments: normalizeZoneSecurityArgs,
    async execute(_toolCallId: string, args: ZoneSecurityArgs) {
      try {
        const result = await assessCloudflareZoneSecurity(createClient(args), {
          zoneLimit: args.zone_limit,
        });
        return textResult(formatAssessmentText(result), { tool: "cloudflare_assess_zone_security", ...result });
      } catch (error) {
        return errorResult(
          `Cloudflare zone security assessment failed: ${errorMessage(error)}`,
          { tool: "cloudflare_assess_zone_security" },
        );
      }
    },
  });

  pi.registerTool({
    name: "cloudflare_assess_traffic_controls",
    label: "Assess Cloudflare traffic controls",
    description:
      "Assess Cloudflare traffic and edge control posture across rate limiting rulesets, page rules, bot management, account audit logs, IP access rules, and Gateway policies.",
    parameters: Type.Object({
      ...authParams,
      zone_limit: Type.Optional(Type.Number({ description: "Maximum zones to sample. Defaults to 20.", default: 20 })),
      audit_limit: Type.Optional(Type.Number({ description: "Maximum audit log entries to inspect. Defaults to 200.", default: 200 })),
    }),
    prepareArguments: normalizeTrafficArgs,
    async execute(_toolCallId: string, args: TrafficArgs) {
      try {
        const result = await assessCloudflareTrafficControls(createClient(args), {
          zoneLimit: args.zone_limit,
          auditLimit: args.audit_limit,
        });
        return textResult(formatAssessmentText(result), { tool: "cloudflare_assess_traffic_controls", ...result });
      } catch (error) {
        return errorResult(
          `Cloudflare traffic control assessment failed: ${errorMessage(error)}`,
          { tool: "cloudflare_assess_traffic_controls" },
        );
      }
    },
  });

  pi.registerTool({
    name: "cloudflare_export_audit_bundle",
    label: "Export Cloudflare audit bundle",
    description:
      "Export a Cloudflare audit package with access checks, identity, zone security, and traffic-control findings, per-framework compliance reports, JSON analysis, raw core data, an errors log on partial failure, and a zip archive.",
    parameters: Type.Object({
      ...authParams,
      output_dir: Type.Optional(Type.String({ description: `Output root. Defaults to ${DEFAULT_OUTPUT_DIR}.` })),
      max_super_admins: Type.Optional(Type.Number({ description: "Maximum acceptable Super Administrator assignments before failing. Defaults to 2.", default: 2 })),
      member_limit: Type.Optional(Type.Number({ description: "Maximum account members to inspect. Defaults to 200.", default: 200 })),
      token_limit: Type.Optional(Type.Number({ description: "Maximum API tokens to inspect. Defaults to 200.", default: 200 })),
      zone_limit: Type.Optional(Type.Number({ description: "Maximum zones to sample. Defaults to 20.", default: 20 })),
      audit_limit: Type.Optional(Type.Number({ description: "Maximum audit log entries to inspect. Defaults to 200.", default: 200 })),
    }),
    prepareArguments: normalizeExportAuditBundleArgs,
    async execute(_toolCallId: string, args: ExportAuditBundleArgs) {
      try {
        const config = resolveCloudflareConfiguration(args);
        const outputRoot = resolve(process.cwd(), args.output_dir?.trim() || DEFAULT_OUTPUT_DIR);
        const result = await exportCloudflareAuditBundle(new CloudflareApiClient(config), config, outputRoot, {
          maxSuperAdmins: args.max_super_admins,
          memberLimit: args.member_limit,
          tokenLimit: args.token_limit,
          zoneLimit: args.zone_limit,
          auditLimit: args.audit_limit,
        });
        return textResult(
          [
            "Cloudflare audit bundle exported.",
            `Output dir: ${result.outputDir}`,
            `Zip archive: ${result.zipPath}`,
            `Findings: ${result.findingCount}`,
            `Files: ${result.fileCount}`,
            `Read errors: ${result.errorCount}`,
          ].join("\n"),
          {
            tool: "cloudflare_export_audit_bundle",
            output_dir: result.outputDir,
            zip_path: result.zipPath,
            finding_count: result.findingCount,
            file_count: result.fileCount,
            error_count: result.errorCount,
          },
        );
      } catch (error) {
        return errorResult(
          `Cloudflare audit bundle export failed: ${errorMessage(error)}`,
          { tool: "cloudflare_export_audit_bundle" },
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
export function cloudflareFixedTexts(): readonly string[] {
  const html = "<html><head><title>502 Bad Gateway</title></head><body>upstream unavailable</body></html>";
  const denied = cloudflareErrorSummary({ success: false, errors: [{ code: 10000, message: "Authentication error" }] }) ?? "";
  const policiesPath = "/accounts/acc-123/access/policies";
  const zonesDenied = `Cloudflare request failed for /zones (403 Forbidden): ${denied}`;
  const policiesDenied = `Cloudflare request failed for ${policiesPath} (403 Forbidden): ${denied}`;
  const subscriptionDenied = `Cloudflare request failed for /zones/zone-1/subscription (403 Forbidden): ${denied}`;
  const notAttemptedZoneSurface = notAttemptedSurface("zone_dnssec", "zone", "/zones/{zone_id}/dnssec", { endpoint: "/zones", status: 403, error: zonesDenied });
  return Object.freeze([
    PARSE_ERROR_NOTE,
    describeNonJsonBody("text/html; charset=utf-8", html) ?? "",
    describeNonJsonBody(null, "upstream unavailable") ?? "",
    denied,
    zonesDenied,
    policiesDenied,
    `Cloudflare request failed for /zones/zone-1/settings/always_use_https (502 Bad Gateway): ${describeNonJsonBody("text/html", html)}`,
    "Cloudflare request failed for /zones (timed out after 30000 ms)",
    "Cloudflare request failed for /zones (network error: fetch failed)",
    `Cloudflare request returned a non-JSON payload for /zones (200 OK): ${describeNonJsonBody("text/html", html)}`,
    "Cloudflare API reported failure for /zones.",
    notAttempted("listAccessPolicies").error,
    notAttemptedZoneSurface.error ?? "",
    "3 zone-scoped surfaces were not attempted because /zones could not be read (403).",
    "3 zone-scoped surfaces were not attempted because /zones could not be read (no HTTP status).",
    "5/7 Cloudflare audit surfaces are readable.",
    "Provide a read-only API token and, when multiple accounts exist, set account_id to unlock account-scoped Cloudflare checks.",
    manualReason("/user/tokens/verify", "any valid API token (verify needs no extra permission)", "the token status and permission groups from the dashboard", `Cloudflare request failed for /user/tokens/verify (403 Forbidden): ${denied}`),
    manualReason(policiesPath, "Access: Apps and Policies: Read", "the reusable Access policy list and each policy's decision", policiesDenied),
    `2 Access applications carry 3 inline policies, none with bypass, but the reusable policy list could not be checked. ${manualReason(policiesPath, "Access: Apps and Policies: Read", "the reusable Access policy list and each policy's decision", policiesDenied)}`,
    "The active API token reported status expired instead of active.",
    "Global API Key auth has no token to verify; create a scoped read-only API token and record its permission groups manually.",
    partialInventoryNote("Access application", { items: [{}], truncated: true, totalCount: 40 }) ?? "",
    partialInventoryNote("reusable Access policy", { items: [{}], truncated: true }) ?? "",
    zonePlanNoteText(subscriptionDenied),
    "The zone subscription returned no rate_plan.public_name, so the plan is not named here.",
    "GET /zones/{zone_id}/firewall/rules is deprecated and was consulted for evidence only because the rulesets API was unreadable.",
    `/user/tokens/verify: ${zonesDenied.replace("/zones", "/user/tokens/verify")}`,
  ]);
}

/** The zone-plan note for an unreadable subscription read, as zonePlanNote renders it (without its leading space). */
function zonePlanNoteText(error: string): string {
  return `The zone plan could not be named because /zones/{zone_id}/subscription was not readable (${error}); zones[].plan is deprecated and is not read.`;
}
