/**
 * Palo Alto Networks security inspector tools for grclanker.
 *
 * Read-only audit surface across Prisma Cloud CSPM (REST API with JWT login)
 * and PAN-OS firewalls or Panorama (XML API). Nothing here mutates a tenant
 * or a device: every request is a GET, a config "show", or an operational
 * "show" command.
 */
import {
  createWriteStream,
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  realpathSync,
} from "node:fs";
import { chmod, readdir, writeFile } from "node:fs/promises";
import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { homedir } from "node:os";
import { basename, dirname, join, relative, resolve } from "node:path";
import { ZipArchive } from "archiver";
import { Type } from "@sinclair/typebox";
import { REDACTED_VALUE, scrubSensitiveValues } from "../../flue/redact.js";
import { errorResult, formatTable, textResult } from "./shared.js";

type FetchImpl = typeof fetch;
type JsonRecord = Record<string, unknown>;

const DEFAULT_OUTPUT_DIR = "./export/paloalto";
const DEFAULT_TIMEOUT_MS = 30_000;
const DEFAULT_RETRY_ATTEMPTS = 3;
const DEFAULT_ALERT_LIMIT = 500;
const DEFAULT_ALERT_PAGE_SIZE = 100;
const DEFAULT_COMPUTE_PAGE_SIZE = 50;
const DEFAULT_COMPUTE_LIMIT = 500;
const DEFAULT_MAX_CRITICAL_CVES = 0;
const DEFAULT_MIN_HOST_COMPLIANCE_RATE = 90;
const DEFAULT_MAX_SUPERUSERS = 3;
const DEFAULT_MIN_COMPLIANCE_PASS_RATE = 90;
const PRISMA_TOKEN_TTL_MS = 9 * 60 * 1000;
const DEFAULT_PRISMA_API_URL = "https://api.prismacloud.io";
const DEFAULT_CONFIG_FILE = join(homedir(), ".grclanker", "paloalto.json");

export type PaloaltoSeverity = "critical" | "high" | "medium" | "low" | "info";
export type PaloaltoStatus = "pass" | "warn" | "fail" | "manual";
export type PaloaltoFramework =
  | "FedRAMP"
  | "CMMC 2.0"
  | "SOC 2"
  | "CIS"
  | "PCI-DSS 4.0"
  | "DISA STIG"
  | "IRAP"
  | "ISMAP";

export interface PaloaltoPrismaConfig {
  apiUrl: string;
  accessKeyId: string;
  secretKey: string;
}

export interface PaloaltoPanosHostConfig {
  host: string;
  baseUrl: string;
  apiKey?: string;
  username?: string;
  password?: string;
}

export interface PaloaltoResolvedConfig {
  prisma?: PaloaltoPrismaConfig;
  computeUrl?: string;
  panos: PaloaltoPanosHostConfig[];
  verifyTls: boolean;
  timeoutMs: number;
  retryAttempts: number;
  sourceChain: string[];
}

export interface PaloaltoAccessSurface {
  product: "prisma-cloud" | "prisma-compute" | "pan-os";
  target: string;
  name: string;
  /** The probe's documented request; for a failed probe, the request that actually failed. */
  endpoint: string;
  status: "readable" | "not_readable" | "not_configured";
  /** Items the probe read; null when it read nothing, so a refusal is never an empty count. */
  count: number | null;
  /** True when a readable probe stopped at its page cap (count is a lower bound); null when the probe failed; absent otherwise. */
  partial?: boolean | null;
  /** The HTTP status a failed probe observed; null when it was readable or no response arrived. */
  httpStatus: number | null;
  error?: string;
}

/** How a surface read failed: the request that failed and the HTTP status it observed (null when no response arrived). */
export interface PaloaltoSurfaceFailure {
  endpoint: string | null;
  status: number | null;
  error: string;
}

export interface PaloaltoAccessCheckResult {
  status: "healthy" | "degraded" | "unconfigured";
  products: string[];
  surfaces: PaloaltoAccessSurface[];
  notes: string[];
  recommendedNextStep: string;
}

export interface PaloaltoFinding {
  id: string;
  control: number;
  title: string;
  severity: PaloaltoSeverity;
  status: PaloaltoStatus;
  summary: string;
  evidence?: JsonRecord;
  mappings: string[];
}

export interface PaloaltoAssessmentResult {
  title: string;
  summary: JsonRecord;
  findings: PaloaltoFinding[];
  errors: string[];
}

export interface PaloaltoAuditBundleResult {
  outputDir: string;
  zipPath: string;
  fileCount: number;
  findingCount: number;
  errorCount: number;
}

export interface XmlNode {
  name: string;
  attributes: Record<string, string>;
  children: XmlNode[];
  text: string;
}

export interface PanosDeviceSnapshot {
  host: string;
  platform: "firewall" | "panorama";
  reachable: boolean;
  systemInfo: JsonRecord;
  haState?: XmlNode;
  haStateFailed: boolean;
  config: XmlNode[];
  /** The xpath each entry of config was read from, in the same order; absent only in hand-built snapshots. */
  configXpaths?: string[];
  failedXpaths: string[];
  /** Failure detail per read ("show system info", "show high-availability state", or an xpath); absent only in hand-built snapshots. */
  failures?: Record<string, PaloaltoSurfaceFailure>;
  errors: string[];
}

export interface ComputeSnapshot {
  consoleUrl: string;
  defenders: JsonRecord[];
  runtimeContainerPolicy: JsonRecord;
  complianceContainerPolicy: JsonRecord;
  complianceHostPolicy: JsonRecord;
  vulnerabilityImagePolicy: JsonRecord;
  registrySettings: JsonRecord;
  registryScans: JsonRecord[];
  images: JsonRecord[];
  vulnerabilityStats: JsonRecord[];
  complianceStats: JsonRecord;
  cloudDiscovery: JsonRecord[];
  ciScans: JsonRecord[];
  failed: string[];
  /** Failure detail per entry of failed; absent only in hand-built snapshots. */
  failures?: Record<string, PaloaltoSurfaceFailure>;
  truncated: string[];
  /** Why each entry of truncated stopped early (page cap, stuck offset). */
  truncationReasons?: Record<string, string>;
  /** Per surface, how many collected records carried none of the documented members and were kept out of the inventory; absent only in hand-built snapshots. */
  unevaluable?: Record<string, number>;
  errors: string[];
}

/** A paged collection; truncated is true whenever the loop exited before the cursor ended. */
export interface PagedResult {
  items: JsonRecord[];
  truncated: boolean;
  truncationReason?: string;
}

export interface AlertPage extends PagedResult {
  totalRows?: number;
}

export interface PrismaSnapshot {
  posture?: JsonRecord;
  alertRules: JsonRecord[];
  alerts: JsonRecord[];
  /** Whether the alert walk stopped early; null when the alert read failed (no walk happened). */
  alertsTruncated: boolean | null;
  alertsTruncationReason?: string;
  alertsTotal?: number;
  policies: JsonRecord[];
  cloudAccounts: JsonRecord[];
  accountGroups: JsonRecord[];
  userRoles: JsonRecord[];
  integrations: JsonRecord[];
  failed: string[];
  /** Failure detail per entry of failed; absent only in hand-built snapshots. */
  failures?: Record<string, PaloaltoSurfaceFailure>;
  /** The request the client issued for each surface, where it differs from the documented default (integrations is tenant-scoped once login returns a prismaId). */
  readEndpoints?: Record<string, string>;
  /** Per surface, how many collected records carried none of the documented members and were kept out of the inventory; absent only in hand-built snapshots. */
  unevaluable?: Record<string, number>;
  compute?: ComputeSnapshot;
  computeUnavailableReason?: string;
  /** The request that made the Compute console unreachable (CSPM /meta_info), when one was made. */
  computeUnavailableFailure?: PaloaltoSurfaceFailure;
  errors: string[];
}

type AuthArgs = {
  prisma_api_url?: string;
  prisma_access_key_id?: string;
  prisma_secret_key?: string;
  prisma_compute_url?: string;
  panos_hosts?: string;
  panos_api_key?: string;
  panos_username?: string;
  panos_password?: string;
  config_file?: string;
  verify_tls?: boolean;
  timeout_seconds?: number;
};

type CloudPostureArgs = AuthArgs & {
  alert_limit?: number;
  min_compliance_pass_rate?: number;
};

type DeviceHardeningArgs = AuthArgs & {
  max_superusers?: number;
};

type ExportAuditBundleArgs = CloudPostureArgs & DeviceHardeningArgs & {
  output_dir?: string;
};

interface ControlDefinition {
  control: number;
  id: string;
  title: string;
  mappings: Record<PaloaltoFramework, string[]>;
}

const FRAMEWORK_ORDER: PaloaltoFramework[] = [
  "FedRAMP",
  "CMMC 2.0",
  "SOC 2",
  "CIS",
  "PCI-DSS 4.0",
  "DISA STIG",
  "IRAP",
  "ISMAP",
];

const FRAMEWORK_FILES: Record<PaloaltoFramework, string> = {
  FedRAMP: "fedramp.md",
  "CMMC 2.0": "cmmc.md",
  "SOC 2": "soc2.md",
  CIS: "cis.md",
  "PCI-DSS 4.0": "pci-dss.md",
  "DISA STIG": "disa-stig.md",
  IRAP: "irap.md",
  ISMAP: "ismap.md",
};

function mappingRow(
  fedramp: string,
  cmmc: string,
  soc2: string,
  cis: string,
  pci: string,
  stig: string,
  irap: string,
  ismap: string,
): Record<PaloaltoFramework, string[]> {
  const split = (value: string) => value.split(",").map((item) => item.trim()).filter(Boolean);
  return {
    FedRAMP: split(fedramp),
    "CMMC 2.0": split(cmmc),
    "SOC 2": split(soc2),
    CIS: split(cis),
    "PCI-DSS 4.0": split(pci),
    "DISA STIG": split(stig),
    IRAP: split(irap),
    ISMAP: split(ismap),
  };
}

export const PALOALTO_CONTROLS: ControlDefinition[] = [
  { control: 1, id: "PA-01", title: "CSPM compliance posture", mappings: mappingRow("CA-7, RA-5", "C.2.4, C.3.4", "CC7.1", "CIS CSC 4", "6.3, 11.3", "V-XXXXX", "ISM-1526", "8.1.1") },
  { control: 2, id: "PA-02", title: "Alert policy coverage", mappings: mappingRow("SI-4, IR-5", "C.2.1, C.5.3", "CC7.2, CC7.3", "CIS CSC 6", "10.4, 12.10", "V-XXXXX", "ISM-0120", "8.2.1") },
  { control: 3, id: "PA-03", title: "IAM overprivileged access", mappings: mappingRow("AC-6, AC-2", "C.1.1, C.1.4", "CC6.1, CC6.3", "CIS CSC 5, CIS CSC 6", "7.1, 7.2", "V-XXXXX", "ISM-1506", "6.1.1") },
  { control: 4, id: "PA-04", title: "Cloud account governance", mappings: mappingRow("CA-2, CM-8", "C.2.2, C.4.1", "CC6.6, CC8.1", "CIS CSC 1", "2.4, 12.5", "V-XXXXX", "ISM-1555", "4.1.1") },
  { control: 5, id: "PA-05", title: "Network exposure analysis", mappings: mappingRow("SC-7, AC-4", "C.3.13, C.4.6", "CC6.1, CC6.6", "CIS CSC 9, CIS CSC 12", "1.2, 1.3", "V-XXXXX", "ISM-1416", "7.1.1") },
  { control: 6, id: "PA-06", title: "Encryption at rest verification", mappings: mappingRow("SC-28, SC-12", "C.3.8, C.3.10", "CC6.1, CC6.7", "CIS CSC 3", "3.4, 3.5", "V-XXXXX", "ISM-0457", "7.2.1") },
  { control: 7, id: "PA-07", title: "Container image vulnerability", mappings: mappingRow("RA-5, SI-2", "C.3.4, C.5.2", "CC7.1", "CIS CSC 7", "6.3, 11.3", "V-XXXXX", "ISM-1143", "8.1.2") },
  { control: 8, id: "PA-08", title: "Host compliance posture", mappings: mappingRow("CM-6, CM-2", "C.2.3, C.3.1", "CC6.1, CC8.1", "CIS CSC 4", "2.2, 2.3", "V-XXXXX", "ISM-1407", "5.1.1") },
  { control: 9, id: "PA-09", title: "Runtime protection policies", mappings: mappingRow("SI-4, SI-7", "C.5.3, C.5.2", "CC7.2", "CIS CSC 8", "11.5", "V-XXXXX", "ISM-1233", "8.3.1") },
  { control: 10, id: "PA-10", title: "Defender deployment coverage", mappings: mappingRow("SI-4, CM-8", "C.2.4, C.5.1", "CC6.1, CC7.1", "CIS CSC 1, CIS CSC 2", "11.4", "V-XXXXX", "ISM-1034", "8.1.3") },
  { control: 11, id: "PA-11", title: "Registry scanning configuration", mappings: mappingRow("RA-5, CM-3", "C.3.4, C.5.2", "CC7.1, CC8.1", "CIS CSC 7", "6.3", "V-XXXXX", "ISM-1143", "8.1.4") },
  { control: 12, id: "PA-12", title: "Firewall security rule audit", mappings: mappingRow("AC-4, SC-7", "C.3.13, C.4.6", "CC6.1, CC6.6", "CIS CSC 9", "1.2, 1.3", "V-207184", "ISM-1416", "7.1.2") },
  { control: 13, id: "PA-13", title: "Zone segmentation verification", mappings: mappingRow("SC-7, AC-4", "C.3.12, C.3.13", "CC6.1, CC6.6", "CIS CSC 12", "1.2, 1.4", "V-207187", "ISM-1181", "7.1.3") },
  { control: 14, id: "PA-14", title: "SSL/TLS decryption coverage", mappings: mappingRow("SC-8, SI-4", "C.3.8, C.5.3", "CC6.1, CC6.7", "CIS CSC 9", "4.1, 4.2", "V-207190", "ISM-0490", "7.2.2") },
  { control: 15, id: "PA-15", title: "GlobalProtect VPN configuration", mappings: mappingRow("IA-2, AC-17", "C.1.1, C.3.7", "CC6.1, CC6.2", "CIS CSC 13", "8.3, 8.4", "V-207193", "ISM-1504", "6.2.1") },
  { control: 16, id: "PA-16", title: "Threat prevention profiles", mappings: mappingRow("SI-3, SI-4", "C.5.2, C.5.3", "CC6.8, CC7.1", "CIS CSC 8, CIS CSC 10", "5.2, 5.3", "V-207196", "ISM-1288", "8.2.2") },
  { control: 17, id: "PA-17", title: "WildFire analysis configuration", mappings: mappingRow("SI-3, SI-4", "C.5.2, C.5.3", "CC6.8, CC7.1", "CIS CSC 8, CIS CSC 10", "5.2", "V-207199", "ISM-1288", "8.2.3") },
  { control: 18, id: "PA-18", title: "URL filtering enforcement", mappings: mappingRow("SC-7, SI-4", "C.3.13, C.5.3", "CC6.1, CC6.8", "CIS CSC 9", "1.2, 6.2", "V-207202", "ISM-0261", "7.3.1") },
  { control: 19, id: "PA-19", title: "Admin role and access audit", mappings: mappingRow("AC-2, AC-6", "C.1.1, C.1.4", "CC6.1, CC6.3", "CIS CSC 5, CIS CSC 6", "7.1, 8.2", "V-207205", "ISM-1506", "6.1.2") },
  { control: 20, id: "PA-20", title: "Logging and SIEM integration", mappings: mappingRow("AU-2, AU-6", "C.3.1, C.3.3", "CC7.2, CC7.3", "CIS CSC 6, CIS CSC 8", "10.1, 10.2", "V-207208", "ISM-0580", "8.4.1") },
  { control: 21, id: "PA-21", title: "Data loss prevention", mappings: mappingRow("SC-28, SI-4", "C.3.8, C.5.3", "CC6.1, CC6.7", "CIS CSC 3", "3.4, 3.5", "V-XXXXX", "ISM-0457", "7.2.3") },
  { control: 22, id: "PA-22", title: "File blocking policies", mappings: mappingRow("SI-3, SC-7", "C.5.2, C.5.3", "CC6.8", "CIS CSC 8, CIS CSC 10", "5.2", "V-XXXXX", "ISM-1288", "8.2.4") },
  { control: 23, id: "PA-23", title: "System hardening", mappings: mappingRow("CM-6, CM-7", "C.2.3, C.3.1", "CC6.1, CC8.1", "CIS CSC 4", "2.2, 2.3", "V-207211", "ISM-0380", "5.1.2") },
  { control: 24, id: "PA-24", title: "Cloud discovery and shadow IT", mappings: mappingRow("CM-8, RA-5", "C.2.2, C.2.4", "CC6.1, CC7.1", "CIS CSC 1", "11.2", "V-XXXXX", "ISM-1034", "4.1.2") },
  { control: 25, id: "PA-25", title: "CI/CD pipeline security", mappings: mappingRow("SA-11, CM-3", "C.3.4, C.5.2", "CC8.1", "CIS CSC 7", "6.3, 6.5", "V-XXXXX", "ISM-1143", "9.1.1") },
];

const CONTROLS_BY_NUMBER = new Map(PALOALTO_CONTROLS.map((item) => [item.control, item]));

function controlMappings(control: number): string[] {
  const definition = CONTROLS_BY_NUMBER.get(control);
  if (!definition) return [];
  return FRAMEWORK_ORDER.flatMap((framework) =>
    definition.mappings[framework].map((reference) => `${framework} ${reference}`),
  );
}

function asObject(value: unknown): JsonRecord | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
  return value as JsonRecord;
}

function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function asRecords(value: unknown): JsonRecord[] {
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
  if (typeof value === "boolean") return value;
  if (typeof value === "string") {
    if (/^(true|1|yes|enabled|on)$/i.test(value.trim())) return true;
    if (/^(false|0|no|disabled|off)$/i.test(value.trim())) return false;
  }
  return undefined;
}

function clampNumber(value: number | undefined, fallback: number, min: number, max: number): number {
  const parsed = Math.trunc(value ?? fallback);
  return Math.min(Math.max(parsed, min), max);
}

function normalizeBaseUrl(rawUrl: string): string {
  const withScheme = /^https?:\/\//i.test(rawUrl.trim()) ? rawUrl.trim() : `https://${rawUrl.trim()}`;
  const parsed = new URL(withScheme);
  parsed.hash = "";
  parsed.search = "";
  parsed.pathname = parsed.pathname.replace(/\/+$/, "");
  return parsed.toString().replace(/\/+$/, "");
}

function parseTimeoutSeconds(value: number | undefined): number {
  return clampNumber(value, DEFAULT_TIMEOUT_MS / 1000, 1, 300) * 1000;
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
  return normalized || "paloalto";
}

export const REDACTION_MARKER = "[REDACTED]";

/**
 * Scrub boundary. A bare value shaped like a name (words joined by hyphens or
 * underscores with at most one digit group per segment: prod-us-east-2026,
 * fw-dc1-01, sess-canary-COOKIE-31415926535897) standing alone in prose is
 * indistinguishable from a resource name and stays, because a summary that names
 * the unread inventory is itself a verdict-safety requirement. Two guards make
 * that safe and both hold by construction:
 *
 * 1. A value inside a carrier is removed whatever its shape: the Authorization,
 *    Proxy-Authorization, Cookie, Set-Cookie, X-Api-Key, X-PAN-KEY, x-redlock-auth
 *    and similar header lines to the end of the line; the userinfo of every
 *    embedded URL; credential-named query and fragment pairs of every URL and bare
 *    query string (the PAN-OS key= parameter included) and any query value shaped
 *    like a token; the schemes Bearer, Basic, Digest, Token, Negotiate, NTLM, SSWS,
 *    and ApiKey (only a listed prose word after the scheme, "Basic authentication",
 *    stays; after the noun "Token" any short plain lowercase word does); credential-named key=value pairs (to the next
 *    delimiter), key: value pairs (to the end of the line), "key":"value" pairs,
 *    and key="value" XML or HTML attributes; and webhook services whose URL path is
 *    the secret. Nothing this module renders puts a credential word in front of a
 *    colon or an equals sign, so every fixed text survives the scrub.
 * 2. A configured secret (the Prisma Cloud access key ID and secret key, the PAN-OS
 *    API key, the keygen password, and the key keygen returns) is removed whatever
 *    its shape and in every encoded form (JSON-escaped, URL-encoded, form-encoded,
 *    base64, base64url, re-flowed PEM lines), down to MIN_CONFIGURED_SECRET_LENGTH
 *    (cli/flue/redact.ts owns the forms). redactSecrets applies it at every client
 *    throw site; the tool boundary and the bundle writer apply it to the whole
 *    payload and every written file.
 *
 * Real token shapes are still removed bare: PEM blocks, JWTs, LUFRPT-prefixed
 * PAN-OS keys, AWS access key ids, and (in error text) any run of
 * LONG_TOKEN_MIN_LENGTH or more token characters that carries base64 symbols,
 * digits scattered through its letters (0f9e8d7c6b5a4938), or token casing
 * (Kq7Zx2Vw9Lm4Tp8R). The rule is path-safe: "/", ".", ":", "@", "=", and
 * whitespace end a run, so URL path segments, dotted hostnames, colon-separated
 * ARNs, and the two sides of a key=value pair are judged piece by piece, while
 * "-" and "_" split a run into name segments; uppercase codes (ENOENT, PCI-DSS-4),
 * digit strings, and canonical UUIDs are names outright. Data values and bundle
 * content go through redactCredentialValueText, every carrier rule without the
 * long-token one (an opaque identifier in evidence is not a secret) and with
 * public PEM blocks (certificates, public keys, CSRs) kept as evidence. Every rule
 * is unanchored and idempotent.
 */
export const MIN_CONFIGURED_SECRET_LENGTH = 4;
export const LONG_TOKEN_MIN_LENGTH = 16;

// Which PEM blocks a scrub removes: every block in error text, where a block is never
// evidence; only non-public blocks in data values, where a certificate is.
type PemScope = "all" | "private";

const PEM_BLOCK_PATTERN = /-----BEGIN ([A-Z0-9 ]+)-----[\s\S]*?-----END [A-Z0-9 ]+-----/g;
// A block whose END was cut off (a truncated message) runs to the end of the text.
const PEM_OPEN_PATTERN = /-----BEGIN ([A-Z0-9 ]+)-----(?:(?!-----END )[\s\S])*$/;
// Labels of PEM blocks that carry public material only; every other label (PRIVATE KEY,
// ENCRYPTED PRIVATE KEY, RSA/EC/DSA/OPENSSH PRIVATE KEY, PGP PRIVATE KEY BLOCK) is a secret.
const PUBLIC_PEM_LABELS = new Set(["CERTIFICATE", "TRUSTED CERTIFICATE", "X509 CRL", "CERTIFICATE REQUEST", "NEW CERTIFICATE REQUEST", "PUBLIC KEY", "RSA PUBLIC KEY", "PKCS7", "CMS"]);
// Any scheme-prefixed URL: the userinfo is dropped; its query and fragment pairs are
// judged by the pair rule below, so the scheme, host, path, and ordinary pairs stay.
const EMBEDDED_URL_PATTERN = /\b[a-z][a-z0-9+.-]*:\/\/[^\s"'<>()[\]{}]+/gi;
const URL_USERINFO_PATTERN = /^([a-z][a-z0-9+.-]*:\/\/)[^\s/@"'<>]+@/i;
// A query or fragment pair, in a URL or a bare query string: a credential-named pair or a
// token-shaped value loses the value. A value ends at "&", "#", whitespace, a quote, or the
// ";" and "," that end a URL inside a sentence (no token carries either).
const QUERY_PAIR_PATTERN = /([?&#])([A-Za-z0-9_.[\]-]+)=((?!\[REDACTED\])[^&#\s"'<>;,]+)/g;
// A credential-bearing header line: the whole value goes, whatever its shape. The name and
// separator are matched here and the value is consumed by headerValueEnd, which carries a
// quoted value (double, single, or JSON-escaped quotes) through its closing quote, so
// Cookie: sid="value" loses value and quotes together instead of stopping at the first
// quote. A value that already opens with a marker is left alone so the rule is idempotent.
const HEADER_LINE_PATTERN = /\b(authorization|proxy-authorization|cookie|set-cookie|x-api-key|api-key|apikey|x-pan-key|x-redlock-auth|x-auth-token|x-access-token|x-amz-security-token|x-vault-token|private-token|x-goog-api-key|x-csrf-token|x-xsrf-token)(["']?\s*:\s*)/gi;
// Inside a header value a quote opens a quoted segment only where a value can start: at the
// start of the value or after "=", ":", ",", ";", "(", or whitespace. Anywhere else it is the
// quote that closes the text the header line was quoted in.
const HEADER_VALUE_OPENER_PATTERN = /[=:,;(\s]/;
const HEADER_VALUE_TERMINATOR_PATTERN = /[\r\n<>]/;
// A scheme and its credentials: the value is removed whatever its shape, except the
// prose words that follow a scheme name in a sentence ("Basic authentication is
// required", "Bearer token") and a Titlecase word, which makes the scheme name an
// adjective in a title ("Basic Network Scan", "Bearer Token", "Token Hygiene"): a Basic
// credential is base64 and a bearer token or API key carries digits, symbols, or token
// casing, so neither is ever one capitalized word of letters. "Token" is also this
// module's own noun ("Token hygiene", "token inventory"), so after it any plain
// lowercase word shorter than LONG_TOKEN_MIN_LENGTH is prose. OAuth 1.0 carries its
// credentials as key="value" attributes, which the attribute rule removes, so OAuth is
// not a scheme here and "OAuth clients" stays.
const SCHEME_VALUE_PATTERN = /\b(Bearer|Basic|Digest|Token|Negotiate|NTLM|SSWS|ApiKey|Api-Key)\s+((?!\[REDACTED\])[A-Za-z0-9._~+/=-]{4,})/gi;
const PLAIN_WORD_PATTERN = /^[a-z]+$/;
const TITLE_WORD_PATTERN = /^[A-Z][a-z]{1,19}$/;
const SCHEME_PROSE_WORDS = new Set([
  "authentication", "authorization", "auth", "token", "tokens", "credential", "credentials", "scheme", "schemes", "header", "headers",
  "realm", "challenge", "access", "mode", "method", "login", "flow", "grant", "type", "string", "value", "values", "user", "users",
  "account", "client", "clients", "error", "request", "requests", "response", "with", "without", "and", "or", "is", "was", "are",
  "not", "the", "this", "that", "these", "those", "to", "in", "for", "from", "on", "of", "by", "as", "at", "if", "then", "but", "so",
  "than", "when", "where", "over", "via", "per", "only", "still", "also", "use", "used", "using", "required", "requires", "failed",
  "rejected", "expired", "invalid", "missing", "unsupported", "supported", "unauthorized", "forbidden", "denied", "allowed", "enabled",
  "disabled", "preferred", "deprecated", "retired", "retiring", "must", "should", "can", "cannot", "could", "will", "would", "may",
  "has", "have", "does", "did", "do", "be", "been",
]);
// "key":"value" and key="value" carriers keep the whole quoted value together so a
// value with spaces is removed as one; the unquoted pair rule below takes the rest.
// Keys may start with "_" (_upstream_session, _token), so a key begins wherever no key
// character precedes it rather than at a word boundary.
const JSON_QUOTED_PAIR_PATTERN = /"([A-Za-z_][A-Za-z0-9_.-]{0,63})"(\s*:\s*)"((?!\[REDACTED\])[^"\r\n]+)"/g;
const QUOTED_ATTRIBUTE_PATTERN = /(?<![A-Za-z0-9_.:-])([A-Za-z_][A-Za-z0-9_.:-]{0,63})\s*=\s*(["'])((?!\[REDACTED\])[^"'\r\n]+)\2/g;
// An unquoted pair: key=value runs to the next delimiter, key: value (a header or
// YAML-style line) to the end of the line, where a brace or bracket ends it so a JSON
// structure after a credential-named key (compact "password":{...}, "auth":null}) is
// never taken for a value.
const ASSIGNMENT_KEY_PATTERN = /(?<![A-Za-z0-9_.-])(["']?)([A-Za-z_][A-Za-z0-9_.-]{0,63})(["']?\s*([:=])\s*["']?)/g;
const DELIMITED_VALUE_PATTERN = /(?!\[REDACTED\])[^\s"'<>;,&]+/y;
const LINE_VALUE_PATTERN = /(?!\[REDACTED\])[^\r\n<>"',;{}[\]]*[^\s\r\n<>"',;{}[\]]/y;
const TOKEN_IN_PATH_WEBHOOK_PATTERN = /(https?:\/\/(?:hooks\.slack\.com\/services|discord(?:app)?\.com\/api\/webhooks|[a-z0-9.-]*webhook\.office\.com\/webhookb2)\/)(?!\[REDACTED\])[^\s"'<>]+/gi;
const JWT_PATTERN = /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]+)*/g;
const PANOS_API_KEY_PATTERN = /\bLUFRPT[A-Za-z0-9+/=_-]{16,}/g;
const AWS_ACCESS_KEY_ID_PATTERN = /\b(?:AKIA|ASIA|AROA|AIDA|AGPA|ANPA|ANVA|APKA|ABIA|ACCA)[A-Z0-9]{16}\b/g;
const LONG_TOKEN_RUN_PATTERN = /[A-Za-z0-9+_-]{16,}(?:={1,2}(?![A-Za-z0-9&]))?/g;
const TOKEN_VALUE_PATTERN = /^[A-Za-z0-9+_-]{16,}={0,2}$/;
const UPPERCASE_CODE_PATTERN = /^[A-Z][A-Z_]*$|^[A-Z][A-Z0-9]*(?:[_-][A-Z0-9]+)+$/;
const DIGITS_ONLY_PATTERN = /^\d+$/;
const DIGIT_GROUP_PATTERN = /\d+/g;
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
// Below this many letters a segment's casing is not judged: eBay, iOS, McD are names.
const MIN_LETTERS_FOR_CASING = 6;
// A segment this long that is not name-shaped makes the whole run a token on its own.
const MIN_TOKEN_SEGMENT_LENGTH = 8;
// A carrier is named by its last word: api_key, access_token, client_secret, X-PAN-KEY,
// _upstream_session, oauth_signature, Set-Cookie, password1. A key whose last word names
// something else (credentialID, keyId, tokenCount, auth_mode, credentials_file,
// passwordPolicy, password_complexity_by_device, credential-enforcement) is not one, nor is
// a max/min bound; a session id (session_id, PHPSESSID, JSESSIONID) is, whatever its tail.
const CREDENTIAL_KEY_WORDS = new Set([
  "token", "tokens", "secret", "secrets", "password", "passwords", "passwd", "pwd", "passphrase", "passcode", "phash",
  "apikey", "authorization", "credential", "credentials", "key", "keys", "cookie", "cookies", "sid", "sig", "signature",
  "auth", "nonce", "sas", "community", "authpwd", "privpwd", "pin", "otp", "totp", "jwt", "assertion", "bearer", "hmac",
  "session", "sessid", "kubeconfig", "dsn", "pem", "ikey", "skey",
]);
// Concatenated spellings the segment split cannot see (authtoken, sharedsecret, privatekey).
const CREDENTIAL_KEY_SUFFIX_PATTERN = /(?:token|secret|passw(?:or)?d|passphrase|passcode|phash|authorization|credential|signature|nonce|community|assertion|session|sessid|authpwd|privpwd|(?:api|private|secret|access|signing|encryption|master|shared|account|client|service|session|license|ssh|hmac)keys?)$/;
// A key whose last word names the form of a value (password_hash, token_value,
// authorization_header, secret_plain) carries a credential when an earlier word names one.
const CREDENTIAL_VALUE_FORM_WORDS = new Set(["value", "values", "plain", "plaintext", "data", "string", "text", "header", "raw", "encrypted", "hash", "digest", "blob", "content"]);
const SESSION_ID_PATTERN = /sess(?:ion)?[_.-]?id$/i;
const BOUND_KEY_SEGMENTS = new Set(["max", "min"]);
const EXTRA_CREDENTIAL_KEYS = new Set(["x-pan-key", "x-redlock-auth", "proxy-authorization", "x-amz-signature", "x-amz-credential", "x-amz-security-token", "oauth_signature", "oauth_token", "oauth_verifier"]);
// "pass" names a credential in a query string or an = assignment (user=a&pass=b), while a
// "pass" count or verdict in a key: value pair is this module's own vocabulary.
const ASSIGNMENT_ONLY_CREDENTIAL_WORDS = new Set(["pass"]);
// JSON structure and literals after a key are never a credential value.
const STRUCTURAL_VALUE_PATTERN = /^(?:[{[]|\{\}|\[\]|true|false|null)$/;
// A bare integer under a plural credential word ("oauth_tokens": 1, keys=3, secrets: 0) is
// a count, this module's own summary vocabulary, not a credential.
const PLURAL_CREDENTIAL_WORDS = new Set(["tokens", "secrets", "keys", "cookies", "passwords", "credentials"]);
const COUNT_VALUE_PATTERN = /^\d+(?:\s|$)/;
// "code" names a credential only behind one of these words (registration_code,
// activation_code, authorization_code, recovery_code); status_code, error_code, and
// country_code stay evidence.
const CREDENTIAL_CODE_QUALIFIERS = new Set(["registration", "activation", "linking", "auth", "authorization", "access", "verification", "recovery", "backup", "security", "mfa", "otp", "pairing", "enrollment", "license"]);

function credentialKeyWord(segment: string): boolean {
  return CREDENTIAL_KEY_WORDS.has(segment) || CREDENTIAL_KEY_SUFFIX_PATTERN.test(segment);
}

// The words of a key with trailing digits removed from each (password1, key2).
function keyWords(key: string): string[] {
  return propertyNameSegments(key).map((segment) => segment.replace(/\d+$/, "")).filter((segment) => segment.length > 0);
}

/** True when a name in a query string, header, attribute, or name-value pair carries a credential. */
export function isCredentialKey(key: string): boolean {
  if (SESSION_ID_PATTERN.test(key) || EXTRA_CREDENTIAL_KEYS.has(key.toLowerCase())) return true;
  const words = keyWords(key);
  const last = words[words.length - 1];
  if (last === undefined || BOUND_KEY_SEGMENTS.has(words[0])) return false;
  if ((last === "key" || last === "keys") && words.length > 1 && NON_CREDENTIAL_KEY_QUALIFIERS.has(words[words.length - 2])) return false;
  if (last === "code" || last === "codes") return words.length > 1 && CREDENTIAL_CODE_QUALIFIERS.has(words[words.length - 2]);
  if (credentialKeyWord(last)) return true;
  return CREDENTIAL_VALUE_FORM_WORDS.has(last) && words.slice(0, -1).some(credentialKeyWord);
}

// True for a value that opens with a bare integer under a plural credential word: a count,
// not a carrier (the rest of a key: value line is rescanned for pairs of its own).
function isCountValue(key: string, value: string): boolean {
  if (!COUNT_VALUE_PATTERN.test(value)) return false;
  const words = keyWords(key);
  return words.length > 0 && PLURAL_CREDENTIAL_WORDS.has(words[words.length - 1]);
}

/** isCredentialKey plus the words that name a credential only in a query string or = assignment. */
function isCredentialAssignmentKey(key: string): boolean {
  if (isCredentialKey(key)) return true;
  const words = keyWords(key);
  return words.length > 0 && ASSIGNMENT_ONLY_CREDENTIAL_WORDS.has(words[words.length - 1]);
}

// Token-shaped casing: the case changes more often than once every three letters
// (bPxRfiCYcanaryKEY); words, acronyms, camelCase, and PascalCase change case at word
// boundaries only (AWSLambdaBasicExecutionRole).
function hasTokenCasing(letters: string): boolean {
  if (letters.length < MIN_LETTERS_FOR_CASING) return false;
  let changes = 0;
  for (let index = 1; index < letters.length; index += 1) {
    const previousLower = letters[index - 1] >= "a" && letters[index - 1] <= "z";
    const currentLower = letters[index] >= "a" && letters[index] <= "z";
    if (previousLower !== currentLower) changes += 1;
  }
  return changes * 3 > letters.length;
}

// A "-" or "_" separated segment shaped like part of a name: empty, digits alone, or letters
// with at most one digit group (west2, sha256, vsys1, ethernet1) whose casing is not token-shaped.
function isNameSegment(segment: string): boolean {
  if (segment.length === 0 || DIGITS_ONLY_PATTERN.test(segment)) return true;
  const digitGroups = segment.match(DIGIT_GROUP_PATTERN) ?? [];
  if (digitGroups.length > 1) return false;
  return !hasTokenCasing(segment.replace(DIGIT_GROUP_PATTERN, ""));
}

// A run is a token when it carries base64 symbols ("+" anywhere; "=" padding only where the
// run is base64-shaped: a multiple of four characters with no "-" or "_", so "key=" left
// in front of a marker is never padding and the rule stays idempotent), or when a
// segment of MIN_TOKEN_SEGMENT_LENGTH or more is not name-shaped, or when at least half
// of its segments are not. One short random-looking segment beside several names (the
// six-character mkdtemp suffix of a temp path, a build id) does not make a token.
function looksLikeToken(run: string): boolean {
  const padding = /=+$/.exec(run)?.[0] ?? "";
  const body = run.slice(0, run.length - padding.length);
  if (UPPERCASE_CODE_PATTERN.test(body) || DIGITS_ONLY_PATTERN.test(body) || UUID_PATTERN.test(body)) return false;
  if (body.includes("+")) return true;
  if (padding.length > 0) return run.length % 4 === 0 && !/[-_]/.test(body);
  const segments = body.split(/[-_]/).filter((segment) => segment.length > 0);
  const tokenSegments = segments.filter((segment) => !isNameSegment(segment));
  if (tokenSegments.length === 0) return false;
  return tokenSegments.some((segment) => segment.length >= MIN_TOKEN_SEGMENT_LENGTH) || tokenSegments.length * 2 >= segments.length;
}

// A whole query value that is one token-shaped run (no path, dot, or percent escape inside).
function isTokenShapedValue(value: string): boolean {
  return TOKEN_VALUE_PATTERN.test(value) && looksLikeToken(value);
}

// The word after a scheme name is prose when it is a Titlecase word, a plain lowercase
// word from the list above, or, after "Token", any plain lowercase word too short to be
// a real token.
function isSchemeProse(scheme: string, value: string): boolean {
  if (TITLE_WORD_PATTERN.test(value)) return true;
  if (!PLAIN_WORD_PATTERN.test(value)) return false;
  if (SCHEME_PROSE_WORDS.has(value)) return true;
  return scheme.toLowerCase() === "token" && value.length < LONG_TOKEN_MIN_LENGTH;
}

function isPublicPemLabel(label: string): boolean {
  return PUBLIC_PEM_LABELS.has(label.trim());
}

function scrubPem(text: string, scope: PemScope): string {
  const keeps = (label: string): boolean => {
    switch (scope) {
      case "all":
        return false;
      case "private":
        return isPublicPemLabel(label);
      default: {
        const exhaustive: never = scope;
        return exhaustive;
      }
    }
  };
  return text
    .replace(PEM_BLOCK_PATTERN, (match, label: string) => (keeps(label) ? match : REDACTION_MARKER))
    .replace(PEM_OPEN_PATTERN, (match, label: string) => (keeps(label) ? match : REDACTION_MARKER));
}

function scrubUrlUserinfo(url: string): string {
  return url.replace(URL_USERINFO_PATTERN, `$1${REDACTION_MARKER}@`);
}

// Where the value of a header line that starts at start ends: at the end of the line, at an
// HTML tag, or at the quote that closes the text the line sits in. A quoted segment
// ("value", 'value') is carried through its closing quote on the same line; a JSON-escaped
// quote (\") is content, and once one has been seen the next unescaped quote closes the JSON
// string the header line is embedded in. Trailing whitespace is not part of the value.
function headerValueEnd(text: string, start: number): number {
  let index = start;
  let escapedQuotes = false;
  while (index < text.length) {
    const char = text[index];
    if (HEADER_VALUE_TERMINATOR_PATTERN.test(char)) break;
    if (char === "\\" && (text[index + 1] === '"' || text[index + 1] === "'")) {
      escapedQuotes = true;
      index += 2;
      continue;
    }
    if (char === '"' || char === "'") {
      if (escapedQuotes || (index > start && !HEADER_VALUE_OPENER_PATTERN.test(text[index - 1]))) break;
      const close = text.indexOf(char, index + 1);
      const segment = text.slice(index + 1, close === -1 ? text.length : close);
      if (close !== -1 && !HEADER_VALUE_TERMINATOR_PATTERN.test(segment)) {
        index = close + 1;
        // A value that is one quoted string ends with its closing quote.
        if (index - segment.length - 2 === start) return index;
        continue;
      }
    }
    index += 1;
  }
  while (index > start && /\s/.test(text[index - 1])) index -= 1;
  return index;
}

// The quote a header value is wrapped in as a whole, or "" when it is not one quoted string.
// JSON-escaped quotes are content of the string the line sits in and go with the value.
function enclosingQuote(value: string): string {
  return value.length >= 2 && (value[0] === '"' || value[0] === "'") && value[value.length - 1] === value[0] ? value[0] : "";
}

// Every credential-bearing header line loses its value whatever the value's shape; a value
// that is one quoted string keeps its quotes around the marker so quoted text stays quoted.
function scrubHeaderLines(text: string): string {
  HEADER_LINE_PATTERN.lastIndex = 0;
  let out = "";
  let last = 0;
  let match: RegExpExecArray | null;
  while ((match = HEADER_LINE_PATTERN.exec(text)) !== null) {
    const start = match.index + match[0].length;
    const end = headerValueEnd(text, start);
    const value = text.slice(start, end);
    if (value.length === 0 || value.startsWith(REDACTION_MARKER)) continue;
    const quote = enclosingQuote(value);
    if (value.slice(quote.length).startsWith(REDACTION_MARKER)) continue;
    out += `${text.slice(last, start)}${quote}${REDACTION_MARKER}${quote}`;
    last = end;
    HEADER_LINE_PATTERN.lastIndex = end;
  }
  return last === 0 ? text : `${out}${text.slice(last)}`;
}

// The key and separator are matched on their own and the value is consumed only when the
// key names a credential, so the value of an ordinary pair is rescanned and a credential
// pair nested inside it (data=token=...) is still caught.
function replaceCredentialAssignments(text: string): string {
  ASSIGNMENT_KEY_PATTERN.lastIndex = 0;
  let out = "";
  let last = 0;
  let match: RegExpExecArray | null;
  while ((match = ASSIGNMENT_KEY_PATTERN.exec(text)) !== null) {
    const [whole, openingQuote, key, separator, operator] = match;
    if (!(operator === "=" ? isCredentialAssignmentKey(key) : isCredentialKey(key))) continue;
    const valuePattern = operator === ":" ? LINE_VALUE_PATTERN : DELIMITED_VALUE_PATTERN;
    valuePattern.lastIndex = match.index + whole.length;
    const value = valuePattern.exec(text)?.[0];
    if (value === undefined || STRUCTURAL_VALUE_PATTERN.test(value) || isCountValue(key, value)) continue;
    out += `${text.slice(last, match.index)}${openingQuote}${key}${separator}${REDACTION_MARKER}`;
    last = match.index + whole.length + value.length;
    ASSIGNMENT_KEY_PATTERN.lastIndex = last;
  }
  return last === 0 ? text : `${out}${text.slice(last)}`;
}

/** Every carrier rule (guard 1) plus the token shapes a prefix identifies on its own; the long-token rule is left to redactErrorText. */
function scrubCarriers(text: string, pemScope: PemScope): string {
  const scrubbed = scrubHeaderLines(scrubPem(text, pemScope)
    .replace(TOKEN_IN_PATH_WEBHOOK_PATTERN, `$1${REDACTION_MARKER}`)
    .replace(EMBEDDED_URL_PATTERN, scrubUrlUserinfo)
    .replace(QUERY_PAIR_PATTERN, (match, separator: string, key: string, value: string) => (isCredentialAssignmentKey(key) || isTokenShapedValue(value) ? `${separator}${key}=${REDACTION_MARKER}` : match)))
    .replace(SCHEME_VALUE_PATTERN, (match, scheme: string, value: string) => (isSchemeProse(scheme, value) ? match : `${scheme} ${REDACTION_MARKER}`))
    .replace(JSON_QUOTED_PAIR_PATTERN, (match, key: string, separator: string, value: string) => (isCredentialKey(key) && !isCountValue(key, value) ? `"${key}"${separator}"${REDACTION_MARKER}"` : match))
    .replace(QUOTED_ATTRIBUTE_PATTERN, (match, key: string, quote: string) => (isCredentialKey(key) ? `${key}=${quote}${REDACTION_MARKER}${quote}` : match));
  return replaceCredentialAssignments(scrubbed)
    .replace(JWT_PATTERN, REDACTION_MARKER)
    .replace(PANOS_API_KEY_PATTERN, REDACTION_MARKER)
    .replace(AWS_ACCESS_KEY_ID_PATTERN, REDACTION_MARKER);
}

/** The general scrub for error text: every carrier rule, every PEM block, and the long-token rule. Idempotent. */
export function redactErrorText(text: string): string {
  return scrubCarriers(text, "all").replace(LONG_TOKEN_RUN_PATTERN, (run) => (looksLikeToken(run) ? REDACTION_MARKER : run));
}

/** Guard 2 on its own: every configured secret in every encoded form, for whole payloads and bundle files where the general scrub would remove evidence. */
export function redactConfiguredSecrets(text: string, secrets: ReadonlyArray<string | undefined>): string {
  const values = secrets.filter((value): value is string => typeof value === "string" && value.length >= MIN_CONFIGURED_SECRET_LENGTH);
  if (values.length === 0) return text;
  return scrubSensitiveValues(text, values).split(REDACTED_VALUE).join(REDACTION_MARKER);
}

/**
 * Every string inside a tool result or other plain value, with the configured secrets
 * removed; a number whose decimal form is a configured secret becomes the marker too.
 * Structure is never touched, so a short secret that matches a whole token (a PIN, a
 * word) cannot break the JSON the value is serialized to.
 */
function sealValue<T>(value: T, secrets: ReadonlyArray<string | undefined>): T {
  if (typeof value === "string") return redactConfiguredSecrets(value, secrets) as T;
  if (typeof value === "number") return (secrets.includes(String(value)) ? REDACTION_MARKER : value) as T;
  if (Array.isArray(value)) return value.map((item) => sealValue(item, secrets)) as T;
  if (value && typeof value === "object" && Object.getPrototypeOf(value) === Object.prototype) {
    const output: JsonRecord = {};
    for (const [key, entry] of Object.entries(value as JsonRecord)) output[key] = sealValue(entry, secrets);
    return output as T;
  }
  return value;
}

/** The single sink every persisted or returned error string passes through. */
function errorMessage(error: unknown): string {
  return redactErrorText(error instanceof Error ? error.message : String(error));
}

/**
 * Every failed Prisma Cloud, Compute, or PAN-OS request is thrown as this
 * class. status is the HTTP status the request observed (null when no response
 * arrived: timeout, DNS, TLS, or connection failure) and endpoint names the
 * request that actually failed ("GET /v2/policy", "POST /login",
 * "GET /api/v1/defenders", "GET /api/?type=config&action=show&xpath=..."), so
 * a marker, probe, or finding built from the error never names a request the
 * run did not make. The message is scrubbed on construction and again at every
 * sink; it carries the status-and-length note for any non-JSON or non-XML body.
 */
export class PaloaltoApiError extends Error {
  readonly status: number | null;
  readonly endpoint: string;

  constructor(message: string, status: number | null, endpoint: string) {
    super(redactErrorText(message));
    this.name = "PaloaltoApiError";
    this.status = status;
    this.endpoint = endpoint;
  }
}

/** The failure detail recorded for a surface: the request that failed, the status it observed, and the scrubbed message. */
function describeFailure(error: unknown): PaloaltoSurfaceFailure {
  return {
    endpoint: error instanceof PaloaltoApiError ? error.endpoint : null,
    status: error instanceof PaloaltoApiError ? error.status : null,
    error: errorMessage(error),
  };
}

/** A hand-built snapshot records which reads failed but not how; the marker then carries no request or status it cannot vouch for. */
function failureOf(failures: Record<string, PaloaltoSurfaceFailure> | undefined, label: string): PaloaltoSurfaceFailure {
  return failures?.[label] ?? { endpoint: null, status: null, error: `${label} was not read.` };
}

type PaloaltoDatasetStatus = "ok" | "forbidden" | "not_found" | "error" | "unavailable";

function datasetStatusOf(status: number | null): PaloaltoDatasetStatus {
  if (status === 401 || status === 403) return "forbidden";
  if (status === 404) return "not_found";
  return "error";
}

/**
 * The object written in place of a dataset that was not read, so a refusal is
 * never an empty array or null: status is the HTTP status the failed request
 * observed (null when no response arrived) and endpoint the request that failed.
 */
function notCollectedMarker(failure: PaloaltoSurfaceFailure, datasetStatus: PaloaltoDatasetStatus = datasetStatusOf(failure.status)): JsonRecord {
  return {
    collected: false,
    status: failure.status,
    dataset_status: datasetStatus,
    endpoint: failure.endpoint,
    error: failure.error,
  };
}

/**
 * Collection status of one surface for assessment summaries; a surface that was not read
 * reports null counts, never 0 or false. unevaluable_records counts the collected records
 * that carried none of the documented members and were kept out of the inventory.
 */
function surfaceCollectionStatus(endpoint: string | null, failure: PaloaltoSurfaceFailure | undefined, seen: number | null, truncated: boolean | null, unevaluable = 0): JsonRecord {
  return {
    status: failure ? datasetStatusOf(failure.status) : "ok",
    endpoint: failure ? failure.endpoint : endpoint,
    http_status: failure ? failure.status : null,
    seen: failure ? null : seen,
    truncated: failure ? null : truncated,
    unevaluable_records: failure ? null : unevaluable,
    error: failure ? failure.error : null,
  };
}

function splitList(value: string | undefined): string[] {
  return (value ?? "")
    .split(/[\s,;]+/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolvePromise) => setTimeout(resolvePromise, ms));
}

/** The client-side scrub for a thrown message: the configured secrets in every form (guard 2), then the general scrub. */
export function redactSecrets(message: string, secrets: ReadonlyArray<string | undefined>): string {
  return redactErrorText(redactConfiguredSecrets(message, secrets));
}

// A JSON property name is split into lower-case segments on underscores, hyphens,
// dots, spaces, and camelCase boundaries, so api_key, apiKey, APIKey, and the header
// name X-Api-Key all end in ["api", "key"]. The value is a credential when the last
// segment is one of these words (authToken, integrationKey, password, clientSecret,
// secrets, credential) or a qualified key such as api_key, private_key, or secret_key.
// A bare key (Prisma header pairs use key as the header name), public_key, and every
// id, url, name, type, or flag are kept: credentialID, hostUrl, and login never match.
const CREDENTIAL_LAST_SEGMENTS = new Set([
  "token", "tokens", "secret", "secrets", "password", "passwords", "passwd", "pwd", "passphrase", "phash",
  "apikey", "authorization", "credential", "credentials",
]);
const NON_CREDENTIAL_KEY_QUALIFIERS = new Set(["public"]);
// Header pairs ({key, value, secure} in Prisma Cloud webhook integrations) are credential
// pairs when flagged secure: true or when the label names a credential (Authorization,
// X-Api-Key); only the value is replaced so the label and flags stay readable.
const CREDENTIAL_PAIR_LABEL_KEYS = ["key", "name", "header"];
const CREDENTIAL_PAIR_VALUE_KEYS = new Set(["value", "default", "default_value"]);

/**
 * The scrub for credentials carried inside string values rather than under a
 * credential-named key: every carrier rule of redactErrorText (URL userinfo and
 * credential query pairs; webhook services whose URL path is the secret; header,
 * cookie, scheme, and credential-pair carriers; JSON encoded as a string; private
 * PEM blocks) without the long-token rule, because a policy id, resource id, or hash
 * in evidence is not a secret, and with public PEM blocks kept because a certificate
 * is evidence. Applied to every string kept in a snapshot.
 */
export function redactCredentialValueText(text: string): string {
  return scrubCarriers(text, "private");
}

function propertyNameSegments(name: string): string[] {
  return name
    .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
    .replace(/([A-Z]+)([A-Z][a-z])/g, "$1_$2")
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter((segment) => segment.length > 0);
}

export function isCredentialPropertyName(name: string): boolean {
  const segments = propertyNameSegments(name);
  const last = segments[segments.length - 1];
  if (last === undefined) return false;
  if (CREDENTIAL_LAST_SEGMENTS.has(last)) return true;
  if (last === "key" && segments.length > 1) return !NON_CREDENTIAL_KEY_QUALIFIERS.has(segments[segments.length - 2]);
  return false;
}

function isCredentialJsonPair(record: JsonRecord): boolean {
  if (record.secure === true) return true;
  const label = CREDENTIAL_PAIR_LABEL_KEYS.map((key) => record[key]).find((value): value is string => typeof value === "string");
  return label !== undefined
    && isCredentialPropertyName(label)
    && [...CREDENTIAL_PAIR_VALUE_KEYS].some((key) => key in record);
}

function carriesValue(value: unknown): boolean {
  if (typeof value === "string") return value.length > 0;
  if (typeof value === "number") return true;
  if (Array.isArray(value)) return value.length > 0;
  const record = asObject(value);
  return record !== undefined && Object.keys(record).length > 0;
}

function redactCredentialNode(value: unknown): unknown {
  if (typeof value === "string") return redactCredentialValueText(value);
  if (Array.isArray(value)) return value.map(redactCredentialNode);
  const record = asObject(value);
  if (!record) return value;
  const credentialPair = isCredentialJsonPair(record);
  const output: JsonRecord = {};
  for (const [key, entry] of Object.entries(record)) {
    const credentialName = isCredentialPropertyName(key) || (credentialPair && CREDENTIAL_PAIR_VALUE_KEYS.has(key));
    // The whole value collapses, so a credential container (Compute registry
    // credential: {secret: {plain}}, image secrets[]) never leaks a nested child.
    output[key] = credentialName && carriesValue(entry) ? REDACTION_MARKER : redactCredentialNode(entry);
  }
  return output;
}

/**
 * Returns a deep copy of a Prisma Cloud or Compute payload with every
 * credential-bearing property (string, number, array, or object) replaced by
 * REDACTION_MARKER and every remaining string scrubbed of URL query credentials,
 * URL userinfo, token-in-path webhook URLs, and JSON-encoded credential fields.
 * Identifiers, credential references (credentialID), hosts, names, types, flags,
 * and counts are kept, so the assessments read the redacted copy unchanged.
 */
export function redactCredentialProperties<T>(value: T): T {
  return redactCredentialNode(value) as T;
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
  if (relativeTarget === ".." || relativeTarget.startsWith("..")) {
    throw new Error(`Refusing to write outside ${realBase}: ${targetDir}`);
  }

  const pathSegments = relativeTarget.split(/[\\/]+/).filter(Boolean);
  let currentPath = realBase;
  for (const segment of pathSegments) {
    currentPath = join(currentPath, segment);
    if (!existsSync(currentPath)) break;
    if (lstatSync(currentPath).isSymbolicLink()) {
      throw new Error(`Refusing to use symlinked parent directory: ${currentPath}`);
    }
  }

  const parent = dirname(resolvedTarget);
  ensurePrivateDir(parent);
  if (lstatSync(realpathSync(parent)).isSymbolicLink()) {
    throw new Error(`Refusing to use symlinked parent directory: ${parent}`);
  }
  return resolvedTarget;
}

async function nextAvailableAuditDir(root: string, preferredName: string): Promise<string> {
  ensurePrivateDir(root);
  for (const suffix of ["", "-2", "-3", "-4", "-5", "-6"]) {
    const candidate = resolveSecureOutputPath(root, `${preferredName}${suffix}`);
    if (!existsSync(candidate)) {
      mkdirSync(candidate, { recursive: true, mode: 0o700 });
      await chmod(candidate, 0o700);
      return candidate;
    }
  }
  throw new Error(`Unable to allocate output directory under ${root}`);
}

/** Writes one bundle file; every configured secret is removed from the content first, in every encoded form (guard 2). */
async function writeSecureTextFile(rootDir: string, relativePathname: string, content: string, secrets: ReadonlyArray<string | undefined> = []): Promise<void> {
  const destination = resolveSecureOutputPath(rootDir, relativePathname);
  ensurePrivateDir(dirname(destination));
  await writeFile(destination, redactConfiguredSecrets(content, secrets), { encoding: "utf8", mode: 0o600 });
}

/** Writes one JSON bundle file; the configured secrets are removed value by value before serialization so the file stays valid JSON. */
async function writeSecureJsonFile(rootDir: string, relativePathname: string, value: unknown, secrets: ReadonlyArray<string | undefined>): Promise<void> {
  const plain: unknown = JSON.parse(JSON.stringify(value));
  await writeSecureTextFile(rootDir, relativePathname, serializeJson(sealValue(plain, secrets)));
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
  await chmod(zipPath, 0o600);
}

async function countFilesRecursively(rootDir: string): Promise<number> {
  let total = 0;
  for (const entry of await readdir(rootDir, { withFileTypes: true })) {
    const pathname = join(rootDir, entry.name);
    if (entry.isDirectory()) total += await countFilesRecursively(pathname);
    else if (entry.isFile()) total += 1;
  }
  return total;
}

const XML_ENTITIES: Record<string, string> = {
  amp: "&",
  lt: "<",
  gt: ">",
  quot: "\"",
  apos: "'",
};

function decodeXmlText(value: string): string {
  return value.replace(/&(#x[0-9a-f]+|#[0-9]+|[a-z]+);/gi, (match, entity: string) => {
    if (entity.startsWith("#x") || entity.startsWith("#X")) return String.fromCodePoint(Number.parseInt(entity.slice(2), 16));
    if (entity.startsWith("#")) return String.fromCodePoint(Number.parseInt(entity.slice(1), 10));
    return XML_ENTITIES[entity.toLowerCase()] ?? match;
  });
}

function parseXmlAttributes(source: string): Record<string, string> {
  const attributes: Record<string, string> = {};
  const pattern = /([^\s=\/]+)\s*=\s*(?:"([^"]*)"|'([^']*)')/g;
  let match: RegExpExecArray | null;
  while ((match = pattern.exec(source)) !== null) {
    attributes[match[1]] = decodeXmlText(match[2] ?? match[3] ?? "");
  }
  return attributes;
}

export function parseXml(source: string): XmlNode {
  const root: XmlNode = { name: "#document", attributes: {}, children: [], text: "" };
  const stack: XmlNode[] = [root];
  let index = 0;

  while (index < source.length) {
    const next = source.indexOf("<", index);
    if (next === -1) {
      stack[stack.length - 1].text += decodeXmlText(source.slice(index));
      break;
    }
    if (next > index) {
      stack[stack.length - 1].text += decodeXmlText(source.slice(index, next));
    }

    if (source.startsWith("<!--", next)) {
      const end = source.indexOf("-->", next);
      index = end === -1 ? source.length : end + 3;
      continue;
    }
    if (source.startsWith("<![CDATA[", next)) {
      const end = source.indexOf("]]>", next);
      stack[stack.length - 1].text += source.slice(next + 9, end === -1 ? source.length : end);
      index = end === -1 ? source.length : end + 3;
      continue;
    }
    if (source.startsWith("<?", next) || source.startsWith("<!", next)) {
      const end = source.indexOf(">", next);
      index = end === -1 ? source.length : end + 1;
      continue;
    }

    const end = source.indexOf(">", next);
    if (end === -1) break;
    const rawTag = source.slice(next + 1, end).trim();
    index = end + 1;

    if (rawTag.startsWith("/")) {
      if (stack.length > 1) stack.pop();
      continue;
    }

    const selfClosing = rawTag.endsWith("/");
    const body = selfClosing ? rawTag.slice(0, -1).trim() : rawTag;
    const nameMatch = /^[^\s\/>]+/.exec(body);
    if (!nameMatch) continue;
    const node: XmlNode = {
      name: nameMatch[0],
      attributes: parseXmlAttributes(body.slice(nameMatch[0].length)),
      children: [],
      text: "",
    };
    stack[stack.length - 1].children.push(node);
    if (!selfClosing) stack.push(node);
  }

  return root;
}

export function xmlChild(node: XmlNode | undefined, name: string): XmlNode | undefined {
  return node?.children.find((child) => child.name === name);
}

export function xmlChildren(node: XmlNode | undefined, name: string): XmlNode[] {
  return node?.children.filter((child) => child.name === name) ?? [];
}

export function xmlText(node: XmlNode | undefined): string | undefined {
  const text = node?.text.trim();
  return text && text.length > 0 ? text : undefined;
}

export function xmlPath(node: XmlNode | undefined, path: string[]): XmlNode | undefined {
  let current = node;
  for (const segment of path) {
    current = xmlChild(current, segment);
    if (!current) return undefined;
  }
  return current;
}

export function xmlFindAll(node: XmlNode | undefined, name: string, results: XmlNode[] = []): XmlNode[] {
  if (!node) return results;
  for (const child of node.children) {
    if (child.name === name) results.push(child);
    xmlFindAll(child, name, results);
  }
  return results;
}

export function xmlMembers(node: XmlNode | undefined): string[] {
  return xmlChildren(node, "member").map(xmlText).filter((item): item is string => Boolean(item));
}

function xmlEntryName(node: XmlNode): string {
  return node.attributes.name ?? xmlText(node) ?? "unnamed";
}

function xmlEntries(node: XmlNode | undefined): XmlNode[] {
  return xmlChildren(node, "entry");
}

export function xmlToJson(node: XmlNode): unknown {
  if (node.children.length === 0 && Object.keys(node.attributes).length === 0) {
    return node.text.trim();
  }
  const output: JsonRecord = {};
  for (const [key, value] of Object.entries(node.attributes)) output[`@${key}`] = value;
  const text = node.text.trim();
  if (text) output["#text"] = text;
  for (const child of node.children) {
    const value = xmlToJson(child);
    const existing = output[child.name];
    if (existing === undefined) output[child.name] = value;
    else if (Array.isArray(existing)) existing.push(value);
    else output[child.name] = [existing, value];
  }
  return output;
}

export const XML_REDACTION_MARKER = REDACTION_MARKER;

// PAN-OS stores secrets as leaf elements whose names end in one of these words:
// phash (admin password hashes), bind-password, secret and shared-secret (RADIUS,
// TACACS+, LDAP), pre-shared-key and key (IKE, IPSec, HA encryption), private-key
// (certificates), passphrase, authpwd and privpwd (SNMPv3), snmp-community-string,
// api-key and token (integrations), plus plural containers (keys, secrets, tokens,
// passwords) and one-time codes (pin, otp). Names are matched on their last
// segment after underscores and camelCase boundaries are normalized to hyphens
// (apiKey, preSharedKey, and bind_password all match), so password-complexity,
// key-usage, and credential-enforcement are kept.
const CREDENTIAL_XML_NAME_PATTERN = /(?:^|-)(?:password|passwords|passwd|pwd|passphrase|phash|hash|secret|secrets|key|keys|token|tokens|community|community-string|credential|credentials|authpwd|privpwd|pin|otp)$/;
const NON_CREDENTIAL_XML_NAMES = new Set(["public-key", "public-keys"]);

export function isCredentialXmlName(name: string): boolean {
  const normalized = name
    .trim()
    .replace(/([a-z0-9])([A-Z])/g, "$1-$2")
    .toLowerCase()
    .replace(/_/g, "-");
  if (NON_CREDENTIAL_XML_NAMES.has(normalized)) return false;
  return CREDENTIAL_XML_NAME_PATTERN.test(normalized);
}

function redactXmlAttributes(attributes: Record<string, string>): Record<string, string> {
  const output: Record<string, string> = {};
  for (const [key, value] of Object.entries(attributes)) {
    output[key] = isCredentialXmlName(key) && value.length > 0 ? XML_REDACTION_MARKER : redactCredentialValueText(value);
  }
  return output;
}

/**
 * Returns a deep copy of an XML tree with every credential-bearing node
 * collapsed to XML_REDACTION_MARKER (the whole subtree, so a container such as
 * pre-shared-key never leaks a differently named child) and every remaining
 * text or attribute value scrubbed of URL query credentials and userinfo. The
 * source tree is not mutated: assessments keep reading raw values in memory,
 * only what is written to disk is redacted.
 */
export function redactXmlCredentials(node: XmlNode): XmlNode {
  if (isCredentialXmlName(node.name)) {
    const hasValue = node.text.trim().length > 0 || node.children.length > 0;
    return { name: node.name, attributes: redactXmlAttributes(node.attributes), children: [], text: hasValue ? XML_REDACTION_MARKER : "" };
  }
  return {
    name: node.name,
    attributes: redactXmlAttributes(node.attributes),
    children: node.children.map(redactXmlCredentials),
    text: redactCredentialValueText(node.text),
  };
}

/** The xpath behind each entry of config: recorded by the collector, inferred in platform order for a hand-built snapshot. */
function panosConfigXpaths(snapshot: PanosDeviceSnapshot): string[] {
  return snapshot.configXpaths ?? platformXpaths(snapshot.platform).filter((xpath) => !snapshot.failedXpaths.includes(xpath));
}

/** Per-read collection status of a PAN-OS device: the two operational reads plus every config xpath the platform requires. */
function panosCollectionStatus(snapshot: PanosDeviceSnapshot): JsonRecord {
  const xpaths = panosConfigXpaths(snapshot);
  const status: JsonRecord = {
    system_info: surfaceCollectionStatus(
      PANOS_READ_ENDPOINTS[PANOS_SYSTEM_INFO_READ],
      snapshot.reachable ? undefined : failureOf(snapshot.failures, PANOS_SYSTEM_INFO_READ),
      Object.keys(snapshot.systemInfo).length,
      false,
    ),
    ha_state: surfaceCollectionStatus(
      PANOS_READ_ENDPOINTS[PANOS_HA_STATE_READ],
      snapshot.haStateFailed ? failureOf(snapshot.failures, PANOS_HA_STATE_READ) : undefined,
      snapshot.haState ? 1 : 0,
      false,
    ),
  };
  snapshot.config.forEach((tree, index) => {
    const xpath = xpaths[index] ?? `#${index}`;
    status[xpath] = surfaceCollectionStatus(panosConfigEndpoint(xpath), undefined, tree.children.length, false);
  });
  for (const xpath of snapshot.failedXpaths) {
    status[xpath] = surfaceCollectionStatus(panosConfigEndpoint(xpath), failureOf(snapshot.failures, xpath), null, null);
  }
  return status;
}

/**
 * The core_data/ representation of a PAN-OS device snapshot, with credentials
 * redacted. config is keyed by xpath, and every read that failed (system info,
 * HA state, or a config subtree) is written as a not-collected marker naming
 * the request that failed and the status it observed, never as null, an empty
 * object, or a missing entry.
 */
export function panosSnapshotToJson(snapshot: PanosDeviceSnapshot): JsonRecord {
  const xpaths = panosConfigXpaths(snapshot);
  const config: JsonRecord = {};
  snapshot.config.forEach((tree, index) => {
    config[xpaths[index] ?? `#${index}`] = xmlToJson(redactXmlCredentials(tree));
  });
  for (const xpath of snapshot.failedXpaths) {
    config[xpath] = notCollectedMarker(failureOf(snapshot.failures, xpath));
  }
  return {
    host: snapshot.host,
    platform: snapshot.platform,
    system_info: snapshot.reachable ? redactCredentialProperties(snapshot.systemInfo) : notCollectedMarker(failureOf(snapshot.failures, PANOS_SYSTEM_INFO_READ)),
    ha_state: snapshot.haStateFailed
      ? notCollectedMarker(failureOf(snapshot.failures, PANOS_HA_STATE_READ))
      : snapshot.haState ? xmlToJson(redactXmlCredentials(snapshot.haState)) : null,
    config,
    collection: panosCollectionStatus(snapshot),
  };
}

/** The integrations request the client issues: tenant-scoped once login has returned a prismaId, the legacy path otherwise. */
function prismaIntegrationsEndpoint(prismaId: string | undefined): string {
  return prismaId ? `GET /api/v1/tenant/${encodeURIComponent(prismaId)}/integration` : "GET /integration";
}

/** The request behind each CSPM read, keyed by the collector's surface label, as issued when login returned no prismaId. */
const PRISMA_READ_ENDPOINTS: Record<string, string> = {
  "compliance posture": "GET /v2/compliance/posture",
  "alert rules": "GET /v2/alert/rule",
  "open alerts": "GET /v2/alert",
  policies: "GET /v2/policy",
  "cloud accounts": "GET /cloud",
  "account groups": "GET /cloud/group",
  "user roles": "GET /user/role",
  integrations: prismaIntegrationsEndpoint(undefined),
};

/** The documented request behind each Compute read, keyed by the collector's surface label. */
const COMPUTE_READ_ENDPOINTS: Record<string, string> = {
  defenders: "GET /api/v1/defenders",
  "runtime container policy": "GET /api/v1/policies/runtime/container",
  "compliance container policy": "GET /api/v1/policies/compliance/container",
  "compliance host policy": "GET /api/v1/policies/compliance/host",
  "vulnerability image policy": "GET /api/v1/policies/vulnerability/images",
  "registry settings": "GET /api/v1/settings/registry",
  "registry scans": "GET /api/v1/registry",
  images: "GET /api/v1/images",
  "vulnerability stats": "GET /api/v1/stats/vulnerabilities",
  "compliance stats": "GET /api/v1/stats/compliance",
  "cloud discovery": "GET /api/v1/cloud/discovery",
  "ci scans": "GET /api/v1/scans",
};

/**
 * The members that identify a documented record of each list surface: the identity
 * and status fields the verdicts read, keyed by the collector's surface label. A 2xx
 * array whose records carry none of them is a foreign document (a portal's JSON, another
 * API's list) and is recorded as an unreadable surface, never as an inventory; a record
 * carrying none of them inside an otherwise documented array is unevaluable and is kept
 * out of the inventory with its count recorded, which caps every dependent verdict.
 */
const DOCUMENTED_RECORD_MEMBERS: Record<string, string[]> = {
  "alert rules": ["policyScanConfigId", "name", "enabled", "alertRuleNotificationConfig", "policies"],
  "open alerts": ["id", "status", "policy", "alertTime", "resource"],
  policies: ["policyId", "name", "policyType", "severity", "enabled"],
  "cloud accounts": ["accountId", "name", "cloudType", "enabled", "status"],
  "account groups": ["id", "name", "accountIds", "accounts"],
  "user roles": ["id", "name", "roleType", "associatedUsers"],
  integrations: ["id", "name", "integrationType", "enabled", "integrationConfig"],
  defenders: ["hostname", "version", "connected", "type", "lastModified"],
  "registry scans": ["_id", "repoTag", "scanTime", "type"],
  images: ["_id", "repoTag", "scanTime", "vulnerabilityDistribution", "tags"],
  "vulnerability stats": ["_id", "images", "registryImages", "containers", "hosts", "functions"],
  "cloud discovery": ["provider", "serviceType", "total", "defended", "err"],
  "ci scans": ["_id", "time", "pass", "type", "entityInfo"],
};

function documentedMembersOf(label: string): string[] {
  const members = DOCUMENTED_RECORD_MEMBERS[label];
  if (!members) throw new Error(`No documented record members are registered for the ${label} surface`);
  return members;
}

/** Whether a record carries at least one of the members that identify a documented record of the surface. */
function isDocumentedRecord(record: JsonRecord, members: string[]): boolean {
  return members.some((member) => member in record);
}

/**
 * Splits a collected list into the documented records the verdicts evaluate and the
 * count of records that carry none of the surface's documented members.
 */
function partitionDocumentedRecords(label: string, records: JsonRecord[]): { records: JsonRecord[]; unevaluable: number } {
  const members = documentedMembersOf(label);
  const documented = records.filter((record) => isDocumentedRecord(record, members));
  return { records: documented, unevaluable: records.length - documented.length };
}

/** The note a gate appends for records of a list surface that carry none of the documented members. */
function unevaluableRecordsNote(product: string, label: string, unevaluable: number, evaluated: number): string {
  return `${product} ${label}: ${unevaluable} of ${unevaluable + evaluated} records carry none of the documented members (${documentedMembersOf(label).join(", ")}) and were not evaluated`;
}

function seenCount(value: unknown): number {
  if (Array.isArray(value)) return value.length;
  if (value === undefined || value === null) return 0;
  return 1;
}

function snakeCase(label: string): string {
  return label.replace(/\s+/g, "_");
}

/** Per-surface collection status of a Compute snapshot, keyed by snake_case surface name. */
function computeCollectionStatus(snapshot: ComputeSnapshot): JsonRecord {
  const values: Record<string, unknown> = {
    defenders: snapshot.defenders,
    "runtime container policy": snapshot.runtimeContainerPolicy,
    "compliance container policy": snapshot.complianceContainerPolicy,
    "compliance host policy": snapshot.complianceHostPolicy,
    "vulnerability image policy": snapshot.vulnerabilityImagePolicy,
    "registry settings": snapshot.registrySettings,
    "registry scans": snapshot.registryScans,
    images: snapshot.images,
    "vulnerability stats": snapshot.vulnerabilityStats,
    "compliance stats": snapshot.complianceStats,
    "cloud discovery": snapshot.cloudDiscovery,
    "ci scans": snapshot.ciScans,
  };
  return Object.fromEntries(Object.entries(values).map(([label, value]) => [
    snakeCase(label),
    surfaceCollectionStatus(
      COMPUTE_READ_ENDPOINTS[label] ?? null,
      snapshot.failed.includes(label) ? failureOf(snapshot.failures, label) : undefined,
      seenCount(value),
      snapshot.truncated.includes(label),
      snapshot.unevaluable?.[label] ?? 0,
    ),
  ]));
}

/** The marker written for the whole Compute half when the console could not be reached, naming the /meta_info request when one failed. */
function computeUnavailableMarker(snapshot: PrismaSnapshot): JsonRecord {
  const failure = snapshot.computeUnavailableFailure;
  return notCollectedMarker({
    endpoint: failure?.endpoint ?? null,
    status: failure?.status ?? null,
    error: snapshot.computeUnavailableReason ?? "Prisma Cloud Compute console was not reached.",
  }, "unavailable");
}

/**
 * The core_data/ representation of a Compute snapshot: every surface that was
 * not read is written as a not-collected marker in place of its fallback value.
 */
export function computeSnapshotToJson(snapshot: ComputeSnapshot): JsonRecord {
  const surface = (label: string, value: unknown): unknown => (snapshot.failed.includes(label) ? notCollectedMarker(failureOf(snapshot.failures, label)) : value);
  return {
    console_url: snapshot.consoleUrl,
    defenders: surface("defenders", snapshot.defenders),
    runtime_container_policy: surface("runtime container policy", snapshot.runtimeContainerPolicy),
    compliance_container_policy: surface("compliance container policy", snapshot.complianceContainerPolicy),
    compliance_host_policy: surface("compliance host policy", snapshot.complianceHostPolicy),
    vulnerability_image_policy: surface("vulnerability image policy", snapshot.vulnerabilityImagePolicy),
    registry_settings: surface("registry settings", snapshot.registrySettings),
    registry_scans: surface("registry scans", snapshot.registryScans),
    images: surface("images", snapshot.images),
    vulnerability_stats: surface("vulnerability stats", snapshot.vulnerabilityStats),
    compliance_stats: surface("compliance stats", snapshot.complianceStats),
    cloud_discovery: surface("cloud discovery", snapshot.cloudDiscovery),
    ci_scans: surface("ci scans", snapshot.ciScans),
    truncated: snapshot.truncated.map(snakeCase),
    truncation_reasons: Object.fromEntries(Object.entries(snapshot.truncationReasons ?? {}).map(([label, reason]) => [snakeCase(label), reason])),
    collection: computeCollectionStatus(snapshot),
  };
}

/** Per-surface collection status of the CSPM half of a Prisma snapshot, keyed by snake_case surface name. */
function prismaCollectionStatus(snapshot: PrismaSnapshot): JsonRecord {
  const values: Record<string, unknown> = {
    "compliance posture": snapshot.posture,
    "alert rules": snapshot.alertRules,
    "open alerts": snapshot.alerts,
    policies: snapshot.policies,
    "cloud accounts": snapshot.cloudAccounts,
    "account groups": snapshot.accountGroups,
    "user roles": snapshot.userRoles,
    integrations: snapshot.integrations,
  };
  return Object.fromEntries(Object.entries(values).map(([label, value]) => [
    snakeCase(label),
    surfaceCollectionStatus(
      snapshot.readEndpoints?.[label] ?? PRISMA_READ_ENDPOINTS[label] ?? null,
      snapshot.failed.includes(label) ? failureOf(snapshot.failures, label) : undefined,
      seenCount(value),
      label === "open alerts" ? snapshot.alertsTruncated : false,
      snapshot.unevaluable?.[label] ?? 0,
    ),
  ]));
}

/**
 * The core_data/ representation of a Prisma Cloud snapshot. Every CSPM surface
 * the collector could not read is written as a not-collected marker (never an
 * empty array), the alert truncation flags render null when the alert walk never
 * happened, and the Compute half is either its own projection or an unavailable
 * marker naming the /meta_info request that failed.
 */
export function prismaSnapshotToJson(snapshot: PrismaSnapshot): JsonRecord {
  const surface = (label: string, value: unknown): unknown => (snapshot.failed.includes(label) ? notCollectedMarker(failureOf(snapshot.failures, label)) : value);
  const alertsRead = !snapshot.failed.includes("open alerts");
  return {
    compliance_posture: surface("compliance posture", snapshot.posture ?? null),
    alert_rules: surface("alert rules", snapshot.alertRules),
    open_alerts: surface("open alerts", snapshot.alerts),
    open_alerts_truncated: alertsRead ? snapshot.alertsTruncated : null,
    open_alerts_truncation_reason: alertsRead ? snapshot.alertsTruncationReason ?? null : null,
    open_alerts_total: alertsRead ? snapshot.alertsTotal ?? null : null,
    policies: surface("policies", snapshot.policies),
    cloud_accounts: surface("cloud accounts", snapshot.cloudAccounts),
    account_groups: surface("account groups", snapshot.accountGroups),
    user_roles: surface("user roles", snapshot.userRoles),
    integrations: surface("integrations", snapshot.integrations),
    compute: snapshot.compute ? computeSnapshotToJson(snapshot.compute) : computeUnavailableMarker(snapshot),
    collection: prismaCollectionStatus(snapshot),
  };
}

const ERRNO_CODE_PATTERN = /^E[A-Z0-9_]{1,30}$/;
const JSON_POSITION_PATTERN = /at position (\d+)/;

/**
 * Two-step config loader guard with fixed text per step. Neither the filesystem
 * message (which echoes the path and the operation) nor the JSON.parse message
 * (which quotes a window of the source around the failure, or the whole source
 * of a short file) is ever interpolated: the read step carries the path and a
 * validated errno code, the parse step carries the path and a line number taken
 * only through a strict position regex.
 */
function readConfigText(pathname: string): string {
  try {
    return readFileSync(pathname, "utf8");
  } catch (error) {
    const code = asString(asObject(error)?.code);
    const suffix = code !== undefined && ERRNO_CODE_PATTERN.test(code) ? ` (${code})` : "";
    throw new Error(`Unable to read Palo Alto config file ${pathname}${suffix}`);
  }
}

function parseConfigJson(pathname: string, raw: string): unknown {
  try {
    return JSON.parse(raw) as unknown;
  } catch (error) {
    const position = error instanceof Error ? JSON_POSITION_PATTERN.exec(error.message) : null;
    const line = position ? raw.slice(0, Number(position[1])).split("\n").length : undefined;
    throw new Error(`Unable to parse Palo Alto config file: invalid JSON in ${pathname}${line === undefined ? "" : ` at line ${line}`} (INVALID_JSON)`);
  }
}

function readConfigFile(pathname: string | undefined): JsonRecord {
  if (!pathname && !existsSync(DEFAULT_CONFIG_FILE)) return {};
  const candidate = pathname ?? DEFAULT_CONFIG_FILE;
  const parsed = parseConfigJson(candidate, readConfigText(candidate));
  const values = asObject(parsed);
  if (!values) {
    throw new Error(`Unable to parse Palo Alto config file: ${candidate} must contain a JSON object (INVALID_CONFIG_SHAPE)`);
  }
  return values;
}

export function resolvePaloaltoConfiguration(
  input: JsonRecord = {},
  env: NodeJS.ProcessEnv = process.env,
): PaloaltoResolvedConfig {
  const sourceChain: string[] = [];
  const configFile = readConfigFile(asString(input.config_file) ?? asString(env.PALOALTO_CONFIG_FILE));

  const ranks = new Map<string, number>();
  const pick = (argKey: string, envKey: string, label: string): string | undefined => {
    const fromArgs = asString(input[argKey]);
    if (fromArgs) {
      sourceChain.push(`arguments-${label}`);
      ranks.set(argKey, 3);
      return fromArgs;
    }
    const fromEnv = asString(env[envKey]);
    if (fromEnv) {
      sourceChain.push(`environment-${label}`);
      ranks.set(argKey, 2);
      return fromEnv;
    }
    const fromFile = asString(configFile[envKey]) ?? asString(configFile[argKey]);
    if (fromFile) {
      sourceChain.push(`config-file-${label}`);
      ranks.set(argKey, 1);
      return fromFile;
    }
    return undefined;
  };

  const prismaAccessKeyId = pick("prisma_access_key_id", "PRISMA_ACCESS_KEY_ID", "prisma-access-key");
  const prismaSecretKey = pick("prisma_secret_key", "PRISMA_SECRET_KEY", "prisma-secret-key");
  const prismaApiUrl = pick("prisma_api_url", "PRISMA_API_URL", "prisma-api-url");
  const computeUrlRaw = pick("prisma_compute_url", "PRISMA_COMPUTE_URL", "prisma-compute-url");
  const prisma = prismaAccessKeyId && prismaSecretKey
    ? { apiUrl: normalizeBaseUrl(prismaApiUrl ?? DEFAULT_PRISMA_API_URL), accessKeyId: prismaAccessKeyId, secretKey: prismaSecretKey }
    : undefined;
  if ((prismaAccessKeyId || prismaSecretKey) && !prisma) {
    throw new Error("Prisma Cloud requires both PRISMA_ACCESS_KEY_ID and PRISMA_SECRET_KEY (or prisma_access_key_id and prisma_secret_key arguments).");
  }

  const panosHostsRaw = pick("panos_hosts", "PANOS_HOST", "panos-host") ?? asString(input.panos_host);
  const pickedApiKey = pick("panos_api_key", "PANOS_API_KEY", "panos-api-key");
  const panosUsername = pick("panos_username", "PANOS_USERNAME", "panos-username");
  const panosPassword = pick("panos_password", "PANOS_PASSWORD", "panos-password");
  const credentialsOutrankKey = Boolean(panosUsername && panosPassword)
    && Math.min(ranks.get("panos_username") ?? 0, ranks.get("panos_password") ?? 0) > (ranks.get("panos_api_key") ?? 0);
  const panosApiKey = credentialsOutrankKey ? undefined : pickedApiKey;
  const panosHosts = splitList(panosHostsRaw);
  if (panosHosts.length > 0 && !panosApiKey && !(panosUsername && panosPassword)) {
    throw new Error("PAN-OS requires PANOS_API_KEY or both PANOS_USERNAME and PANOS_PASSWORD for keygen.");
  }
  const panos = panosHosts.map((host) => ({
    host,
    baseUrl: normalizeBaseUrl(host),
    apiKey: panosApiKey,
    username: panosApiKey ? undefined : panosUsername,
    password: panosApiKey ? undefined : panosPassword,
  }));

  if (!prisma && panos.length === 0) {
    throw new Error("Configure Prisma Cloud (PRISMA_API_URL, PRISMA_ACCESS_KEY_ID, PRISMA_SECRET_KEY) and/or PAN-OS (PANOS_HOST plus PANOS_API_KEY or PANOS_USERNAME and PANOS_PASSWORD).");
  }

  const verifyTlsRaw = typeof input.verify_tls === "boolean"
    ? input.verify_tls
    : asBoolean(env.PANOS_VERIFY_TLS) ?? asBoolean(configFile.PANOS_VERIFY_TLS);
  const verifyTls = verifyTlsRaw !== false;
  if (!verifyTls) sourceChain.push("tls-verification-disabled");

  return {
    prisma,
    computeUrl: computeUrlRaw ? normalizeBaseUrl(computeUrlRaw) : undefined,
    panos,
    verifyTls,
    timeoutMs: parseTimeoutSeconds(asNumber(input.timeout_seconds) ?? asNumber(env.PALOALTO_TIMEOUT)),
    retryAttempts: DEFAULT_RETRY_ATTEMPTS,
    sourceChain: [...new Set(sourceChain)],
  };
}

interface HttpOptions {
  timeoutMs: number;
  retryAttempts: number;
  fetchImpl: FetchImpl;
  secrets: Array<string | undefined>;
  sleepImpl?: (ms: number) => Promise<void>;
}

/**
 * A fetch-compatible transport built on node:https that skips certificate
 * verification for the requests it serves only. It exists so a lab firewall
 * with a self-signed certificate never forces a process-wide TLS opt-out.
 */
export function createInsecureFetch(): FetchImpl {
  return (input, init = {}) => new Promise<Response>((resolvePromise, rejectPromise) => {
    const url = new URL(typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url);
    const headers: Record<string, string> = {};
    new Headers(init.headers ?? {}).forEach((value, key) => {
      headers[key] = value;
    });
    const requestImpl = url.protocol === "http:" ? httpRequest : httpsRequest;
    const request = requestImpl(url, {
      method: init.method ?? "GET",
      headers,
      rejectUnauthorized: false,
    }, (incoming) => {
      const chunks: Buffer[] = [];
      incoming.on("data", (chunk: Buffer) => chunks.push(chunk));
      incoming.on("error", rejectPromise);
      incoming.on("end", () => {
        const responseHeaders = new Headers();
        for (const [key, value] of Object.entries(incoming.headers)) {
          if (typeof value === "string") responseHeaders.set(key, value);
          else if (Array.isArray(value)) responseHeaders.set(key, value.join(", "));
        }
        const status = incoming.statusCode ?? 0;
        resolvePromise(new Response(status === 204 || status === 304 ? null : Buffer.concat(chunks), {
          status,
          statusText: incoming.statusMessage ?? "",
          headers: responseHeaders,
        }));
      });
    });
    request.on("error", rejectPromise);
    const signal = init.signal;
    if (signal) {
      const abort = () => {
        const error = new Error("The operation was aborted.");
        error.name = "AbortError";
        request.destroy(error);
      };
      if (signal.aborted) abort();
      else signal.addEventListener("abort", abort, { once: true });
    }
    if (init.body !== undefined && init.body !== null) {
      request.write(typeof init.body === "string" ? init.body : Buffer.from(String(init.body)));
    }
    request.end();
  });
}

// endpoint names the request for the error thrown when no response arrives; the
// URL is never used for that because a PAN-OS URL carries the API key in its query.
async function fetchWithRetry(url: string, init: RequestInit, options: HttpOptions, endpoint: string): Promise<Response> {
  let attempt = 0;
  for (;;) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), options.timeoutMs);
    try {
      const response = await options.fetchImpl(url, { ...init, signal: controller.signal });
      if ((response.status === 429 || response.status >= 500) && attempt < options.retryAttempts) {
        attempt += 1;
        const retryAfter = asNumber(response.headers.get("retry-after"));
        await (options.sleepImpl ?? sleep)(retryAfter ? retryAfter * 1000 : 250 * 2 ** attempt);
        continue;
      }
      return response;
    } catch (error) {
      if (attempt < options.retryAttempts && !(error instanceof Error && error.name === "AbortError")) {
        attempt += 1;
        await (options.sleepImpl ?? sleep)(250 * 2 ** attempt);
        continue;
      }
      throw new PaloaltoApiError(redactSecrets(`Request to ${url} failed: ${errorMessage(error)}`, options.secrets), null, endpoint);
    } finally {
      clearTimeout(timeout);
    }
  }
}

// The media type of a response is server-controlled text: it is quoted only when it has
// the shape of a media type, otherwise it is described as unknown.
const MEDIA_TYPE_PATTERN = /^[a-z0-9][a-z0-9!#$&^_.+-]{0,31}\/[a-z0-9][a-z0-9!#$&^_.+-]{0,39}$/;

function responseContentType(response: Response): string {
  const value = response.headers.get("content-type")?.split(";")[0].trim().toLowerCase() ?? "";
  return MEDIA_TYPE_PATTERN.test(value) ? value : "unknown";
}

/** Status-and-length note for a body that is not the JSON the API documents; the body is never echoed. */
function nonJsonBodyNote(response: Response, rawText: string): string {
  return `non-JSON ${responseContentType(response)} response body (${rawText.length} bytes, not echoed)`;
}

function jsonValueKind(value: unknown): string {
  if (value === null) return "null";
  if (Array.isArray(value)) return "array";
  return typeof value;
}

// What a 2xx answer was expected to carry: the documented JSON document of any kind, a
// JSON object, a JSON array, one documented member of a JSON object, or any one of the
// members that identify a documented object.
type DocumentExpectation =
  | { kind: "document" }
  | { kind: "object" }
  | { kind: "array" }
  | { kind: "member"; key: string; type: "array" | "object" | "member" }
  | { kind: "members"; keys: string[] }
  | { kind: "records"; count: number; keys: string[] };

/**
 * A 2xx answer whose body is not the documented JSON document (an empty body, the HTML
 * page a proxy or SSO portal serves in place of the API, a foreign JSON value, a JSON
 * object without the documented member) is described like an error body, by status,
 * media type, and size only, and is recorded as an unreadable surface: its missing
 * members are never read as an empty inventory or an empty policy.
 */
export function describeNonDocumentBody(response: Response, rawText: string, expected: DocumentExpectation = { kind: "document" }): string {
  const base = `status ${response.status}`;
  const size = `${rawText.length} bytes, not echoed`;
  let what: string;
  switch (expected.kind) {
    case "member":
      return `${base} with a JSON response body without the documented "${expected.key}" ${expected.type} (${size})`;
    case "members":
      return `${base} with a JSON response body without any of the documented members ${expected.keys.map((key) => `"${key}"`).join(", ")} (${size})`;
    case "records":
      return `${base} with a JSON array of ${expected.count} records none of which carries any of the documented members ${expected.keys.map((key) => `"${key}"`).join(", ")} (${size})`;
    case "document":
      what = "the documented JSON document";
      break;
    case "object":
      what = "the documented JSON object";
      break;
    case "array":
      what = "the documented JSON array";
      break;
    default: {
      const exhaustive: never = expected;
      throw new Error(`Unhandled document expectation: ${String(exhaustive)}`);
    }
  }
  if (rawText.length === 0) return `${base} with an empty response body where ${what} was expected`;
  const parsed = safeJsonParse(rawText);
  if (parsed === undefined) return `${base} with a ${nonJsonBodyNote(response, rawText)} where ${what} was expected`;
  return `${base} with a JSON ${jsonValueKind(parsed)} response body (${size}) where ${what} was expected`;
}

// One 2xx answer that passed the parse guard, kept with what the request observed so a
// missing documented shape can be described by status, media type, and size. The label
// names the product and request the way the client's other error strings do.
interface PrismaDocument {
  value: unknown;
  response: Response;
  rawText: string;
  endpoint: string;
  label: string;
}

function nonDocumentError(document: PrismaDocument, expected: DocumentExpectation, secrets: HttpOptions["secrets"]): PaloaltoApiError {
  return new PaloaltoApiError(redactSecrets(`${document.label} returned ${describeNonDocumentBody(document.response, document.rawText, expected)}.`, secrets), document.response.status, document.endpoint);
}

// A non-empty array (or one page of a walk) in which no record carries any of the
// surface's documented members is a foreign document: a list of something else served
// with a 2xx, or a list of primitives. It is thrown, never read as an inventory. Records
// without the members inside an otherwise documented array are the collector's to count.
function documentedRecordArray(document: PrismaDocument, value: unknown, label: string, secrets: HttpOptions["secrets"]): JsonRecord[] {
  const entries = asArray(value);
  const members = documentedMembersOf(label);
  if (entries.length > 0 && !asRecords(entries).some((record) => isDocumentedRecord(record, members))) {
    throw nonDocumentError(document, { kind: "records", count: entries.length, keys: members }, secrets);
  }
  return asRecords(entries);
}

// The documented answer is a JSON array of records; Compute serves null for an empty
// collection, which is the documented empty answer. Any other value is a foreign document.
function documentedArray(document: PrismaDocument, label: string, secrets: HttpOptions["secrets"]): JsonRecord[] {
  if (document.value !== null && !Array.isArray(document.value)) throw nonDocumentError(document, { kind: "array" }, secrets);
  return documentedRecordArray(document, document.value, label, secrets);
}

// A documented object is recognised by any one of the members that identify it; an
// object carrying none of them (a health page, a portal's JSON) is a foreign document.
function documentedObject(document: PrismaDocument, keys: string[], secrets: HttpOptions["secrets"]): JsonRecord {
  const payload = asObject(document.value);
  if (payload === undefined) throw nonDocumentError(document, { kind: "object" }, secrets);
  if (!keys.some((key) => key in payload)) throw nonDocumentError(document, { kind: "members", keys }, secrets);
  return payload;
}

// The documented collection member must be present on every page, as an array or null,
// and a non-empty page must carry at least one documented record of the surface.
function documentedRecords(document: PrismaDocument, key: string, label: string, secrets: HttpOptions["secrets"]): { payload: JsonRecord; records: JsonRecord[] } {
  const payload = asObject(document.value);
  if (payload === undefined) throw nonDocumentError(document, { kind: "object" }, secrets);
  const value = payload[key];
  if (!(key in payload) || (value !== null && !Array.isArray(value))) throw nonDocumentError(document, { kind: "member", key, type: "array" }, secrets);
  return { payload, records: documentedRecordArray(document, value, label, secrets) };
}

// Prisma Cloud's documented error fields: the x-redlock-status header (a JSON array of
// {i18nKey, severity, subject}) and body message or i18nKey fields; Compute answers with
// {err}. Anything else in a body is described by length only.
function prismaErrorFields(payload: unknown): string[] {
  const record = asObject(payload);
  const fields = [
    ...(record ? [asString(record.message), asString(record.i18nKey), asString(record.err), asString(asObject(record.error)?.message)] : []),
    ...asRecords(payload).flatMap((item) => [asString(item.i18nKey), asString(item.message), asString(item.subject)]),
  ];
  return [...new Set(fields.filter((field): field is string => Boolean(field)))];
}

/**
 * The status-and-length note or Prisma Cloud's documented error fields for a failed
 * response. Each field is scrubbed before it is shortened, with the caller's scrub when
 * it knows the configured secrets, so the cut never leaves a fragment of a secret behind.
 */
export function describePrismaErrorBody(response: Response, rawText: string, scrub: (text: string) => string = redactErrorText): string {
  const parts: string[] = [];
  const header = response.headers.get("x-redlock-status");
  if (header) {
    const headerFields = prismaErrorFields(safeJsonParse(header));
    parts.push(headerFields.length > 0 ? `x-redlock-status ${headerFields.join(", ")}` : "x-redlock-status header present (not echoed)");
  }
  if (rawText.length === 0) {
    parts.push("empty response body");
  } else {
    const parsed = safeJsonParse(rawText);
    if (parsed === undefined) {
      parts.push(nonJsonBodyNote(response, rawText));
    } else {
      const fields = prismaErrorFields(parsed);
      parts.push(fields.length > 0 ? fields.join("; ") : `JSON response body without documented error fields (${rawText.length} bytes, not echoed)`);
    }
  }
  return parts.map((part) => scrub(part.replace(/\s+/g, " ")).slice(0, 200)).join("; ");
}

export class PrismaCloudClient {
  private readonly config: PaloaltoPrismaConfig;
  private readonly http: HttpOptions;
  // The client-side scrub, handed to describePrismaErrorBody so a field is scrubbed of the configured secrets before it is shortened.
  private readonly scrub = (text: string): string => redactSecrets(text, this.http.secrets);
  private token?: string;
  private tokenExpiresAt = 0;
  private prismaId?: string;
  private tokenPromise?: Promise<string>;

  constructor(
    config: PaloaltoPrismaConfig,
    options: { fetchImpl?: FetchImpl; timeoutMs?: number; retryAttempts?: number; sleepImpl?: (ms: number) => Promise<void> } = {},
  ) {
    this.config = config;
    this.http = {
      fetchImpl: options.fetchImpl ?? fetch,
      timeoutMs: options.timeoutMs ?? DEFAULT_TIMEOUT_MS,
      retryAttempts: options.retryAttempts ?? DEFAULT_RETRY_ATTEMPTS,
      secrets: [config.secretKey, config.accessKeyId],
      sleepImpl: options.sleepImpl,
    };
  }

  get apiUrl(): string {
    return this.config.apiUrl;
  }

  /** The credentials this client was configured with, for the boundary scrub (guard 2). */
  get knownSecrets(): string[] {
    return this.http.secrets.filter((secret): secret is string => typeof secret === "string");
  }

  private async login(): Promise<string> {
    const endpoint = "POST /login";
    const response = await fetchWithRetry(`${this.config.apiUrl}/login`, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json; charset=UTF-8" },
      body: JSON.stringify({ username: this.config.accessKeyId, password: this.config.secretKey }),
    }, this.http, endpoint);
    const rawText = await response.text();
    if (!response.ok) {
      throw new PaloaltoApiError(redactSecrets(`Prisma Cloud login failed (${response.status}): ${describePrismaErrorBody(response, rawText, this.scrub)}`, this.http.secrets), response.status, endpoint);
    }
    // The same shape guard as every other 2xx answer: an empty or non-JSON body, or a JSON
    // document without the documented token member, is an unreadable surface described by
    // status, media type, and size, never a login that silently yielded no session.
    const document: PrismaDocument = { value: rawText.length === 0 ? undefined : safeJsonParse(rawText), response, rawText, endpoint, label: "Prisma Cloud POST /login" };
    if (document.value === undefined) throw nonDocumentError(document, { kind: "document" }, this.http.secrets);
    const payload = asObject(document.value);
    const token = asString(payload?.token);
    if (!token) throw nonDocumentError(document, { kind: "member", key: "token", type: "member" }, this.http.secrets);
    this.prismaId = asString(asRecords(payload?.customerNames)[0]?.prismaId) ?? this.prismaId;
    this.token = token;
    this.tokenExpiresAt = Date.now() + PRISMA_TOKEN_TTL_MS;
    // The session token is a secret this client now holds, for guard 2 at every sink.
    if (!this.http.secrets.includes(token)) this.http.secrets.push(token);
    return token;
  }

  async getToken(): Promise<string> {
    if (this.token && Date.now() < this.tokenExpiresAt) return this.token;
    if (!this.tokenPromise) this.tokenPromise = this.login();
    try {
      return await this.tokenPromise;
    } finally {
      this.tokenPromise = undefined;
    }
  }

  get credentials(): { username: string; password: string } {
    return { username: this.config.accessKeyId, password: this.config.secretKey };
  }

  get httpOptions(): HttpOptions {
    return this.http;
  }

  async request(method: "GET" | "POST", path: string, query: JsonRecord = {}, body?: unknown, retryAuth = true): Promise<unknown> {
    return (await this.requestDocument(method, path, query, body, retryAuth)).value;
  }

  /**
   * One request, with the shape guard every 2xx answer passes: a body that is empty or
   * not JSON is not the documented document and is thrown as an unreadable surface
   * carrying the status the request observed, never returned as an empty object. The
   * JSON value is returned with the response so a caller can describe a missing
   * documented member the same way.
   */
  private async requestDocument(method: "GET" | "POST", path: string, query: JsonRecord = {}, body?: unknown, retryAuth = true): Promise<PrismaDocument> {
    const url = new URL(`${this.config.apiUrl}${path.startsWith("/") ? path : `/${path}`}`);
    for (const [key, value] of Object.entries(query)) {
      if (value === undefined || value === null || value === "") continue;
      url.searchParams.set(key, String(value));
    }
    const endpoint = `${method} ${path.startsWith("/") ? path : `/${path}`}`;
    const response = await fetchWithRetry(url.toString(), {
      method,
      headers: {
        accept: "application/json; charset=UTF-8",
        "content-type": "application/json",
        "x-redlock-auth": await this.getToken(),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    }, this.http, endpoint);
    const rawText = await response.text();
    if (response.status === 401 && retryAuth) {
      this.token = undefined;
      return this.requestDocument(method, path, query, body, false);
    }
    if (!response.ok) {
      throw new PaloaltoApiError(redactSecrets(`Prisma Cloud ${method} ${path} failed (${response.status}): ${describePrismaErrorBody(response, rawText, this.scrub)}`, this.http.secrets), response.status, endpoint);
    }
    const document: PrismaDocument = { value: rawText.length === 0 ? undefined : safeJsonParse(rawText), response, rawText, endpoint, label: `Prisma Cloud ${method} ${path}` };
    if (document.value === undefined) throw nonDocumentError(document, { kind: "document" }, this.http.secrets);
    return document;
  }

  async get(path: string, query: JsonRecord = {}): Promise<unknown> {
    return this.request("GET", path, query);
  }

  private async getDocument(path: string, query: JsonRecord = {}): Promise<PrismaDocument> {
    return this.requestDocument("GET", path, query);
  }

  // A read whose documented answer is a JSON array of records of the named surface.
  private async getList(path: string, label: string): Promise<JsonRecord[]> {
    return documentedArray(await this.getDocument(path), label, this.http.secrets);
  }

  async getCompliancePosture(): Promise<JsonRecord> {
    return documentedObject(await this.getDocument("/v2/compliance/posture"), ["summary", "complianceDetails", "requestedTimestamp"], this.http.secrets);
  }

  async listAlertRules(): Promise<JsonRecord[]> {
    return this.getList("/v2/alert/rule", "alert rules");
  }

  /**
   * Walks GET /v2/alert with its nextPageToken cursor. The collection is
   * truncated, with the reason recorded, whenever the loop exits for any
   * reason other than the cursor ending: the alert_limit cap, an empty page
   * that still carries a token, a token that repeats (stuck cursor), or a
   * totalRows count larger than what the cursor delivered.
   */
  async collectOpenAlerts(limit = DEFAULT_ALERT_LIMIT): Promise<AlertPage> {
    const items: JsonRecord[] = [];
    const seenTokens = new Set<string>();
    let pageToken: string | undefined;
    let totalRows: number | undefined;
    let truncationReason: string | undefined;
    for (;;) {
      // Every page must carry the documented items array (or null); a 2xx object without
      // it is a foreign document, not the end of the cursor.
      const { payload, records: pageItems } = documentedRecords(await this.getDocument("/v2/alert", {
        "alert.status": "open",
        timeType: "relative",
        timeAmount: "30",
        timeUnit: "day",
        detailed: "true",
        limit: Math.min(DEFAULT_ALERT_PAGE_SIZE, Math.max(limit - items.length, 1)),
        pageToken,
      }), "items", "open alerts", this.http.secrets);
      totalRows = asNumber(payload.totalRows) ?? totalRows;
      const room = Math.max(limit - items.length, 0);
      items.push(...pageItems.slice(0, room));
      const nextToken = asString(payload.nextPageToken);
      if (pageItems.length > room || (nextToken !== undefined && items.length >= limit)) {
        truncationReason = `alert_limit ${limit} reached while GET /v2/alert still had alerts to return; raise alert_limit`;
        break;
      }
      if (!nextToken) break;
      if (pageItems.length === 0) {
        truncationReason = "GET /v2/alert returned an empty page while still returning a nextPageToken, so the remaining alerts were not read";
        break;
      }
      if (nextToken === pageToken || seenTokens.has(nextToken)) {
        truncationReason = "GET /v2/alert repeated a nextPageToken (stuck cursor), so the remaining alerts were not read";
        break;
      }
      seenTokens.add(nextToken);
      pageToken = nextToken;
    }
    if (truncationReason === undefined && totalRows !== undefined && items.length < totalRows) {
      truncationReason = `GET /v2/alert reported totalRows ${totalRows} but the cursor ended after ${items.length} alerts`;
    }
    return { items, truncated: truncationReason !== undefined, truncationReason, totalRows };
  }

  async listOpenAlerts(limit = DEFAULT_ALERT_LIMIT): Promise<JsonRecord[]> {
    return (await this.collectOpenAlerts(limit)).items;
  }

  async getMetaInfo(): Promise<JsonRecord> {
    return documentedObject(await this.getDocument("/meta_info"), ["twistlockUrl", "licenseType", "marketplace", "startTs", "endTs"], this.http.secrets);
  }

  async listPolicies(): Promise<JsonRecord[]> {
    return this.getList("/v2/policy", "policies");
  }

  async listCloudAccounts(): Promise<JsonRecord[]> {
    return this.getList("/cloud", "cloud accounts");
  }

  async listAccountGroups(): Promise<JsonRecord[]> {
    return this.getList("/cloud/group", "account groups");
  }

  async listUserRoles(): Promise<JsonRecord[]> {
    return this.getList("/user/role", "user roles");
  }

  /**
   * Push integrations (Splunk, SQS, webhook, ServiceNow, and so on) live under
   * the tenant-scoped microservice path; GET /integration only returns the
   * Okta, Qualys, and Tenable pull integrations. The prismaId comes from the
   * login response customerNames[] entry.
   */
  async listIntegrations(): Promise<JsonRecord[]> {
    await this.getToken();
    if (this.prismaId) return this.getList(`/api/v1/tenant/${encodeURIComponent(this.prismaId)}/integration`, "integrations");
    return this.getList("/integration", "integrations");
  }

  get tenantPrismaId(): string | undefined {
    return this.prismaId;
  }
}

/**
 * Prisma Cloud Compute (CWPP) console client. Authenticates with
 * POST /api/v1/authenticate using the access key credentials and falls back
 * to the CSPM JWT in x-redlock-auth, both documented on the PCEE access page.
 */
export class PrismaComputeClient {
  private readonly consoleUrl: string;
  private readonly cspm: Pick<PrismaCloudClient, "getToken" | "credentials" | "httpOptions">;
  private readonly http: HttpOptions;
  private readonly scrub = (text: string): string => redactSecrets(text, this.http.secrets);
  private bearer?: string;
  private bearerExpiresAt = 0;
  private useRedlockHeader = false;

  constructor(consoleUrl: string, cspm: Pick<PrismaCloudClient, "getToken" | "credentials" | "httpOptions">) {
    this.consoleUrl = normalizeBaseUrl(consoleUrl);
    this.cspm = cspm;
    this.http = cspm.httpOptions;
  }

  get baseUrl(): string {
    return this.consoleUrl;
  }

  private async authHeaders(): Promise<Record<string, string>> {
    if (this.useRedlockHeader) return { "x-redlock-auth": await this.cspm.getToken() };
    if (this.bearer && Date.now() < this.bearerExpiresAt) return { authorization: `Bearer ${this.bearer}` };
    const response = await fetchWithRetry(`${this.consoleUrl}/api/v1/authenticate`, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify(this.cspm.credentials),
    }, this.http, "POST /api/v1/authenticate");
    const rawText = await response.text();
    const token = response.ok ? asString(asObject(safeJsonParse(rawText))?.token) : undefined;
    if (!token) {
      this.useRedlockHeader = true;
      return { "x-redlock-auth": await this.cspm.getToken() };
    }
    this.bearer = token;
    this.bearerExpiresAt = Date.now() + PRISMA_TOKEN_TTL_MS;
    if (!this.http.secrets.includes(token)) this.http.secrets.push(token);
    return { authorization: `Bearer ${token}` };
  }

  async get(path: string, query: JsonRecord = {}): Promise<unknown> {
    return (await this.getDocument(path, query)).value;
  }

  // One request with the same shape guard as the CSPM client: an empty or non-JSON 2xx
  // body is thrown as an unreadable surface, never returned as an empty object.
  private async getDocument(path: string, query: JsonRecord = {}): Promise<PrismaDocument> {
    const url = new URL(`${this.consoleUrl}/api/v1${path.startsWith("/") ? path : `/${path}`}`);
    for (const [key, value] of Object.entries(query)) {
      if (value === undefined || value === null || value === "") continue;
      url.searchParams.set(key, String(value));
    }
    const endpoint = `GET /api/v1${path.startsWith("/") ? path : `/${path}`}`;
    const response = await fetchWithRetry(url.toString(), {
      method: "GET",
      headers: { accept: "application/json", ...(await this.authHeaders()) },
    }, this.http, endpoint);
    const rawText = await response.text();
    if (!response.ok) {
      throw new PaloaltoApiError(redactSecrets(`Prisma Cloud Compute GET ${path} failed (${response.status}): ${describePrismaErrorBody(response, rawText, this.scrub)}`, this.http.secrets), response.status, endpoint);
    }
    const document: PrismaDocument = { value: rawText.length === 0 ? undefined : safeJsonParse(rawText), response, rawText, endpoint, label: `Prisma Cloud Compute GET ${path}` };
    if (document.value === undefined) throw nonDocumentError(document, { kind: "document" }, this.http.secrets);
    return document;
  }

  // A read whose documented answer is a JSON array of records of the named surface (or null when empty).
  private async getList(path: string, label: string): Promise<JsonRecord[]> {
    return documentedArray(await this.getDocument(path), label, this.http.secrets);
  }

  // A read whose documented answer is the JSON object identified by any of the keys.
  private async getObject(path: string, keys: string[]): Promise<JsonRecord> {
    return documentedObject(await this.getDocument(path), keys, this.http.secrets);
  }

  /**
   * Walks an offset-paged Compute list. A full page followed by the same page
   * again means the console ignored the offset (stuck offset); that and the
   * record cap both end the walk as truncated with the reason recorded.
   */
  async listPaged(path: string, label: string, limit: number): Promise<PagedResult> {
    const items: JsonRecord[] = [];
    let offset = 0;
    let previousSignature: string | undefined;
    for (;;) {
      const page = documentedArray(await this.getDocument(path, { limit: DEFAULT_COMPUTE_PAGE_SIZE, offset }), label, this.http.secrets);
      const signature = page.length > 0 ? JSON.stringify(page[0]) : undefined;
      if (signature !== undefined && signature === previousSignature) {
        return { items, truncated: true, truncationReason: `GET /api/v1${path} returned the same page for offset ${offset} as for the previous offset (stuck offset), so the remaining records were not read` };
      }
      items.push(...page);
      if (page.length < DEFAULT_COMPUTE_PAGE_SIZE) return { items, truncated: false };
      if (items.length >= limit) {
        return { items, truncated: true, truncationReason: `GET /api/v1${path} capped at ${limit} records while full pages were still being returned` };
      }
      previousSignature = signature;
      offset += page.length;
    }
  }

  async getVersion(): Promise<string> {
    // The documented answer is the version string itself, or an object carrying it.
    const document = await this.getDocument("/version");
    const version = asString(document.value) ?? asString(asObject(document.value)?.version);
    if (version === undefined) throw nonDocumentError(document, { kind: "member", key: "version", type: "member" }, this.http.secrets);
    return version;
  }

  async listDefenders(limit = DEFAULT_COMPUTE_LIMIT): Promise<PagedResult> {
    return this.listPaged("/defenders", "defenders", limit);
  }

  async getRuntimeContainerPolicy(): Promise<JsonRecord> {
    return this.getObject("/policies/runtime/container", ["rules", "_id", "learningDisabled"]);
  }

  async getComplianceContainerPolicy(): Promise<JsonRecord> {
    return this.getObject("/policies/compliance/container", ["rules", "_id", "policyType"]);
  }

  async getComplianceHostPolicy(): Promise<JsonRecord> {
    return this.getObject("/policies/compliance/host", ["rules", "_id", "policyType"]);
  }

  async getVulnerabilityImagePolicy(): Promise<JsonRecord> {
    return this.getObject("/policies/vulnerability/images", ["rules", "_id", "policyType"]);
  }

  async getRegistrySettings(): Promise<JsonRecord> {
    return this.getObject("/settings/registry", ["specifications", "harborScannerUrlSuffix", "webhookUrlSuffix"]);
  }

  async listRegistryScans(limit = DEFAULT_COMPUTE_LIMIT): Promise<PagedResult> {
    return this.listPaged("/registry", "registry scans", limit);
  }

  async listImages(limit = DEFAULT_COMPUTE_LIMIT): Promise<PagedResult> {
    return this.listPaged("/images", "images", limit);
  }

  async getVulnerabilityStats(): Promise<JsonRecord[]> {
    return this.getList("/stats/vulnerabilities", "vulnerability stats");
  }

  async getComplianceStats(): Promise<JsonRecord> {
    return this.getObject("/stats/compliance", ["rules", "categories", "templates", "daily", "ids", "_id"]);
  }

  async listCloudDiscovery(limit = DEFAULT_COMPUTE_LIMIT): Promise<PagedResult> {
    return this.listPaged("/cloud/discovery", "cloud discovery", limit);
  }

  async listCiScans(limit = DEFAULT_COMPUTE_LIMIT): Promise<PagedResult> {
    return this.listPaged("/scans", "ci scans", limit);
  }
}

function safeJsonParse(rawText: string): unknown {
  try {
    return JSON.parse(rawText) as unknown;
  } catch {
    return undefined;
  }
}

export class PanosApiClient {
  private readonly config: PaloaltoPanosHostConfig;
  private readonly http: HttpOptions;
  private readonly verifyTls: boolean;
  private apiKey?: string;
  private keyPromise?: Promise<string>;

  constructor(
    config: PaloaltoPanosHostConfig,
    options: { fetchImpl?: FetchImpl; timeoutMs?: number; retryAttempts?: number; sleepImpl?: (ms: number) => Promise<void>; verifyTls?: boolean } = {},
  ) {
    this.config = config;
    this.apiKey = config.apiKey;
    this.verifyTls = options.verifyTls !== false;
    this.http = {
      fetchImpl: options.fetchImpl ?? (this.verifyTls ? fetch : createInsecureFetch()),
      timeoutMs: options.timeoutMs ?? DEFAULT_TIMEOUT_MS,
      retryAttempts: options.retryAttempts ?? DEFAULT_RETRY_ATTEMPTS,
      secrets: [config.apiKey, config.password],
      sleepImpl: options.sleepImpl,
    };
  }

  get host(): string {
    return this.config.host;
  }

  get tlsVerification(): boolean {
    return this.verifyTls;
  }

  /** The credentials this client holds, including the key keygen returned, for the boundary scrub (guard 2). */
  get knownSecrets(): string[] {
    return this.http.secrets.filter((secret): secret is string => typeof secret === "string");
  }

  /**
   * A body without a <response> element (an HTML proxy or captive-portal page,
   * a JSON error from a load balancer) is described by status, content type,
   * and length only. Error responses keep the documented msg or line text,
   * scrubbed of any credential-shaped value the device echoed.
   */
  private parseResponse(response: Response, rawText: string, context: string, endpoint: string): XmlNode {
    const document = parseXml(rawText);
    const responseNode = xmlChild(document, "response");
    if (!responseNode) {
      throw new PaloaltoApiError(`PAN-OS ${context} returned a non-XML ${responseContentType(response)} response (status ${response.status}, ${rawText.length} bytes, not echoed).`, response.status, endpoint);
    }
    if (responseNode.attributes.status !== "success") {
      const message = xmlText(xmlPath(responseNode, ["result", "msg"]))
        || xmlFindAll(responseNode, "line").map(xmlText).filter(Boolean).join("; ")
        || xmlText(xmlChild(responseNode, "msg"))
        || "no message";
      const code = /^[a-z0-9_-]{1,16}$/i.test(responseNode.attributes.code ?? "") ? responseNode.attributes.code : "unknown";
      const detail = redactSecrets(message.replace(/\s+/g, " "), this.http.secrets).slice(0, 300);
      throw new PaloaltoApiError(redactSecrets(`PAN-OS ${context} failed (code ${code}, status ${response.status}): ${detail}`, this.http.secrets), response.status, endpoint);
    }
    return responseNode;
  }

  private async generateApiKey(): Promise<string> {
    const endpoint = PANOS_KEYGEN_ENDPOINT;
    if (!this.config.username || !this.config.password) {
      throw new PaloaltoApiError(`PAN-OS ${this.config.host} has no API key and no username/password for keygen.`, null, endpoint);
    }
    const body = new URLSearchParams({ type: "keygen", user: this.config.username, password: this.config.password });
    const response = await fetchWithRetry(`${this.config.baseUrl}/api/`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: body.toString(),
    }, this.http, endpoint);
    const rawText = await response.text();
    if (!response.ok && rawText.length === 0) {
      throw new PaloaltoApiError(`PAN-OS keygen for ${this.config.host} failed (${response.status}).`, response.status, endpoint);
    }
    const key = xmlText(xmlPath(this.parseResponse(response, rawText, `keygen for ${this.config.host}`, endpoint), ["result", "key"]));
    if (!key) throw new PaloaltoApiError(`PAN-OS keygen for ${this.config.host} did not return a key.`, response.status, endpoint);
    this.apiKey = key;
    this.http.secrets.push(key);
    return key;
  }

  private async getApiKey(): Promise<string> {
    if (this.apiKey) return this.apiKey;
    if (!this.keyPromise) this.keyPromise = this.generateApiKey();
    try {
      return await this.keyPromise;
    } finally {
      this.keyPromise = undefined;
    }
  }

  async request(params: Record<string, string>, context: string): Promise<XmlNode> {
    const url = new URL(`${this.config.baseUrl}/api/`);
    for (const [key, value] of Object.entries(params)) url.searchParams.set(key, value);
    const endpoint = panosEndpoint("GET", params);
    const response = await fetchWithRetry(url.toString(), {
      method: "GET",
      headers: { "X-PAN-KEY": await this.getApiKey(), accept: "application/xml" },
    }, this.http, endpoint);
    const rawText = await response.text();
    if (!response.ok && rawText.length === 0) {
      throw new PaloaltoApiError(`PAN-OS ${context} on ${this.config.host} failed (${response.status} ${response.statusText}).`, response.status, endpoint);
    }
    return this.parseResponse(response, rawText, `${context} on ${this.config.host}`, endpoint);
  }

  async showConfig(xpath: string): Promise<XmlNode> {
    const response = await this.request({ type: "config", action: "show", xpath }, `config show ${xpath}`);
    return xmlChild(response, "result") ?? response;
  }

  async op(command: string): Promise<XmlNode> {
    const response = await this.request({ type: "op", cmd: command }, `op ${command.slice(0, 60)}`);
    return xmlChild(response, "result") ?? response;
  }

  async showSystemInfo(): Promise<JsonRecord> {
    const result = await this.op(PANOS_SHOW_SYSTEM_INFO_CMD);
    const system = xmlChild(result, "system") ?? result;
    return asObject(xmlToJson(system)) ?? {};
  }

  async showHighAvailabilityState(): Promise<XmlNode> {
    return this.op(PANOS_SHOW_HA_STATE_CMD);
  }
}

const PANOS_SHOW_SYSTEM_INFO_CMD = "<show><system><info></info></system></show>";
const PANOS_SHOW_HA_STATE_CMD = "<show><high-availability><state></state></high-availability></show>";
const PANOS_KEYGEN_ENDPOINT = "POST /api/?type=keygen";

/**
 * The endpoint label of a PAN-OS XML API request: the /api/ path with the
 * request's own parameters (type, action, xpath, cmd), never the key or any
 * credential parameter, so the label can be recorded anywhere.
 */
function panosEndpoint(method: string, params: Record<string, string>): string {
  const query = Object.entries(params)
    .filter(([name]) => !["key", "user", "password"].includes(name))
    .map(([name, value]) => `${name}=${value}`)
    .join("&");
  return `${method} /api/${query ? `?${query}` : ""}`;
}

/** The documented request behind a PAN-OS config read, in the same form a failed read reports. */
export function panosConfigEndpoint(xpath: string): string {
  return panosEndpoint("GET", { type: "config", action: "show", xpath });
}

/** The documented request behind a PAN-OS operational command, in the same form a failed read reports. */
export function panosOpEndpoint(command: string): string {
  return panosEndpoint("GET", { type: "op", cmd: command });
}

export const PANOS_SYSTEM_INFO_READ = "show system info";
export const PANOS_HA_STATE_READ = "show high-availability state";
const PANOS_READ_ENDPOINTS: Record<string, string> = {
  [PANOS_SYSTEM_INFO_READ]: panosOpEndpoint(PANOS_SHOW_SYSTEM_INFO_CMD),
  [PANOS_HA_STATE_READ]: panosOpEndpoint(PANOS_SHOW_HA_STATE_CMD),
};

function detectPlatform(systemInfo: JsonRecord): "firewall" | "panorama" {
  const model = asString(systemInfo.model) ?? "";
  const family = asString(systemInfo.family) ?? "";
  return /panorama|^M-\d|^pra-|^pa-vm-panorama/i.test(`${model} ${family}`) || asString(systemInfo["system-mode"]) !== undefined
    ? "panorama"
    : "firewall";
}

const FIREWALL_XPATHS = [
  "/config/devices/entry/vsys",
  "/config/devices/entry/network",
  "/config/devices/entry/deviceconfig",
  "/config/shared",
  "/config/mgt-config",
];

const PANORAMA_XPATHS = [
  "/config/devices/entry/device-group",
  "/config/devices/entry/template",
  "/config/devices/entry/template-stack",
  "/config/devices/entry/deviceconfig",
  "/config/shared",
  "/config/mgt-config",
  "/config/panorama",
];

function platformXpaths(platform: PanosDeviceSnapshot["platform"]): string[] {
  return platform === "panorama" ? PANORAMA_XPATHS : FIREWALL_XPATHS;
}

/**
 * Every read records how it failed (the request that failed and the status it
 * observed) under failures, keyed by the read name or the xpath, so the bundle
 * can write a not-collected marker in place of the subtree that was not read.
 */
export async function collectPanosSnapshot(client: Pick<PanosApiClient, "host" | "showSystemInfo" | "showHighAvailabilityState" | "showConfig">): Promise<PanosDeviceSnapshot> {
  const errors: string[] = [];
  const failedXpaths: string[] = [];
  const failures: Record<string, PaloaltoSurfaceFailure> = {};
  let reachable = true;
  const systemInfo = await client.showSystemInfo().catch((error: unknown) => {
    errors.push(`${client.host}: ${PANOS_SYSTEM_INFO_READ} failed: ${errorMessage(error)}`);
    failures[PANOS_SYSTEM_INFO_READ] = describeFailure(error);
    reachable = false;
    return {} as JsonRecord;
  });
  const platform = detectPlatform(systemInfo);
  let haStateFailed = false;
  const haState = await client.showHighAvailabilityState().catch((error: unknown) => {
    errors.push(`${client.host}: ${PANOS_HA_STATE_READ} failed: ${errorMessage(error)}`);
    failures[PANOS_HA_STATE_READ] = describeFailure(error);
    haStateFailed = true;
    return undefined;
  });
  const config: XmlNode[] = [];
  const configXpaths: string[] = [];
  for (const xpath of platformXpaths(platform)) {
    try {
      config.push(await client.showConfig(xpath));
      configXpaths.push(xpath);
    } catch (error) {
      failedXpaths.push(xpath);
      failures[xpath] = describeFailure(error);
      errors.push(`${client.host}: config show ${xpath} failed: ${errorMessage(error)}`);
    }
  }
  return { host: client.host, platform, reachable, systemInfo, haState, haStateFailed, config, configXpaths, failedXpaths, failures, errors };
}

type ComputeSource = Pick<PrismaComputeClient, "baseUrl" | "listDefenders" | "getRuntimeContainerPolicy" | "getComplianceContainerPolicy" | "getComplianceHostPolicy" | "getVulnerabilityImagePolicy" | "getRegistrySettings" | "listRegistryScans" | "listImages" | "getVulnerabilityStats" | "getComplianceStats" | "listCloudDiscovery" | "listCiScans">;

/**
 * Every Compute payload is redacted as it is collected (credential-named
 * properties such as registry credential blocks, image secrets, and webhook
 * tokens are replaced), so assessments, tool payloads, and the bundle all read
 * the same redacted copy and the raw response is never retained.
 */
export async function collectComputeSnapshot(client: ComputeSource): Promise<ComputeSnapshot> {
  const errors: string[] = [];
  const failed: string[] = [];
  const failures: Record<string, PaloaltoSurfaceFailure> = {};
  const truncated: string[] = [];
  const truncationReasons: Record<string, string> = {};
  const unevaluable: Record<string, number> = {};
  const guard = async <T>(label: string, fallback: T, load: () => Promise<T>): Promise<T> => {
    try {
      return redactCredentialProperties(await load());
    } catch (error) {
      failed.push(label);
      failures[label] = describeFailure(error);
      errors.push(`prisma-compute: ${label} failed: ${errorMessage(error)}`);
      return fallback;
    }
  };
  // Records without any documented member never enter the inventory; their count is kept
  // per surface so every dependent verdict is capped with the count named.
  const documented = (label: string, records: JsonRecord[]): JsonRecord[] => {
    const partition = partitionDocumentedRecords(label, records);
    if (partition.unevaluable > 0) unevaluable[label] = partition.unevaluable;
    return partition.records;
  };
  const list = async (label: string, load: () => Promise<JsonRecord[]>): Promise<JsonRecord[]> => documented(label, await guard(label, [] as JsonRecord[], load));
  const paged = async (label: string, load: () => Promise<PagedResult>): Promise<JsonRecord[]> => {
    const result = await guard(label, { items: [] as JsonRecord[], truncated: false } as PagedResult, load);
    if (result.truncated) {
      truncated.push(label);
      truncationReasons[label] = result.truncationReason ?? `capped at ${DEFAULT_COMPUTE_LIMIT} records`;
    }
    return documented(label, result.items);
  };
  const defenders = await paged("defenders", () => client.listDefenders());
  const runtimeContainerPolicy = await guard("runtime container policy", {} as JsonRecord, () => client.getRuntimeContainerPolicy());
  const complianceContainerPolicy = await guard("compliance container policy", {} as JsonRecord, () => client.getComplianceContainerPolicy());
  const complianceHostPolicy = await guard("compliance host policy", {} as JsonRecord, () => client.getComplianceHostPolicy());
  const vulnerabilityImagePolicy = await guard("vulnerability image policy", {} as JsonRecord, () => client.getVulnerabilityImagePolicy());
  const registrySettings = await guard("registry settings", {} as JsonRecord, () => client.getRegistrySettings());
  const registryScans = await paged("registry scans", () => client.listRegistryScans());
  const images = await paged("images", () => client.listImages());
  const vulnerabilityStats = await list("vulnerability stats", () => client.getVulnerabilityStats());
  const complianceStats = await guard("compliance stats", {} as JsonRecord, () => client.getComplianceStats());
  const cloudDiscovery = await paged("cloud discovery", () => client.listCloudDiscovery());
  const ciScans = await paged("ci scans", () => client.listCiScans());
  return {
    consoleUrl: client.baseUrl,
    defenders,
    runtimeContainerPolicy,
    complianceContainerPolicy,
    complianceHostPolicy,
    vulnerabilityImagePolicy,
    registrySettings,
    registryScans,
    images,
    vulnerabilityStats,
    complianceStats,
    cloudDiscovery,
    ciScans,
    failed,
    failures,
    truncated,
    truncationReasons,
    unevaluable,
    errors,
  };
}

type PrismaSource = Pick<PrismaCloudClient, "getCompliancePosture" | "listAlertRules" | "collectOpenAlerts" | "listPolicies" | "listCloudAccounts" | "listAccountGroups" | "listUserRoles" | "listIntegrations"> & Partial<Pick<PrismaCloudClient, "tenantPrismaId">>;

/**
 * Every CSPM payload is redacted as it is collected: integrations[]
 * integrationConfig (auth tokens, API keys, passwords, secure header pairs,
 * webhook URLs with tokens) and any other credential-named property are
 * replaced before the snapshot exists, so no consumer can reach the raw value.
 */
export async function collectPrismaSnapshot(
  client: PrismaSource,
  alertLimit = DEFAULT_ALERT_LIMIT,
  compute?: { client?: ComputeSource; unavailableReason?: string; unavailableFailure?: PaloaltoSurfaceFailure },
): Promise<PrismaSnapshot> {
  const errors: string[] = [];
  const failed: string[] = [];
  const failures: Record<string, PaloaltoSurfaceFailure> = {};
  const unevaluable: Record<string, number> = {};
  const guard = async <T>(label: string, fallback: T, load: () => Promise<T>): Promise<T> => {
    try {
      return redactCredentialProperties(await load());
    } catch (error) {
      failed.push(label);
      failures[label] = describeFailure(error);
      errors.push(`prisma-cloud: ${label} failed: ${errorMessage(error)}`);
      return fallback;
    }
  };
  // Records without any documented member never enter the inventory; their count is kept
  // per surface so every dependent verdict is capped with the count named.
  const documented = (label: string, records: JsonRecord[]): JsonRecord[] => {
    const partition = partitionDocumentedRecords(label, records);
    if (partition.unevaluable > 0) unevaluable[label] = partition.unevaluable;
    return partition.records;
  };
  const list = async (label: string, load: () => Promise<JsonRecord[]>): Promise<JsonRecord[]> => documented(label, await guard(label, [] as JsonRecord[], load));
  const posture = await guard("compliance posture", undefined as JsonRecord | undefined, () => client.getCompliancePosture());
  const alertRules = await list("alert rules", () => client.listAlertRules());
  const alertPage = await guard("open alerts", { items: [] as JsonRecord[], truncated: false } as AlertPage, () => client.collectOpenAlerts(alertLimit));
  const alerts = documented("open alerts", alertPage.items);
  const policies = await list("policies", () => client.listPolicies());
  const cloudAccounts = await list("cloud accounts", () => client.listCloudAccounts());
  const accountGroups = await list("account groups", () => client.listAccountGroups());
  const userRoles = await list("user roles", () => client.listUserRoles());
  const integrations = await list("integrations", () => client.listIntegrations());
  const computeSnapshot = compute?.client ? await collectComputeSnapshot(compute.client) : undefined;
  if (computeSnapshot) errors.push(...computeSnapshot.errors);
  else if (compute?.unavailableReason) errors.push(`prisma-compute: ${compute.unavailableReason}`);
  const alertsRead = !failed.includes("open alerts");
  return {
    posture,
    alertRules,
    alerts,
    // No walk happened when the read failed, so it was neither complete nor truncated.
    alertsTruncated: alertsRead ? alertPage.truncated : null,
    alertsTruncationReason: alertsRead ? alertPage.truncationReason : undefined,
    alertsTotal: alertsRead ? alertPage.totalRows : undefined,
    policies,
    cloudAccounts,
    accountGroups,
    userRoles,
    integrations,
    failed,
    failures,
    // Read after the integrations call so the tenant id learned at login is reflected.
    readEndpoints: { integrations: prismaIntegrationsEndpoint(client.tenantPrismaId) },
    unevaluable,
    compute: computeSnapshot,
    computeUnavailableReason: computeSnapshot ? undefined : compute?.unavailableReason,
    computeUnavailableFailure: computeSnapshot ? undefined : compute?.unavailableFailure,
    errors,
  };
}

export interface PaloaltoClients {
  config: PaloaltoResolvedConfig;
  prisma?: PrismaCloudClient;
  compute?: PrismaComputeClient;
  computeUnavailableReason?: string;
  /** The CSPM /meta_info request that failed while locating the Compute console, when that is why it is unavailable. */
  computeUnavailableFailure?: PaloaltoSurfaceFailure;
  panos: PanosApiClient[];
}

export function createPaloaltoClients(config: PaloaltoResolvedConfig, fetchImpl?: FetchImpl): PaloaltoClients {
  const options = { fetchImpl, timeoutMs: config.timeoutMs, retryAttempts: config.retryAttempts };
  const prisma = config.prisma ? new PrismaCloudClient(config.prisma, options) : undefined;
  return {
    config,
    prisma,
    compute: prisma && config.computeUrl ? new PrismaComputeClient(config.computeUrl, prisma) : undefined,
    panos: config.panos.map((host) => new PanosApiClient(host, { ...options, verifyTls: config.verifyTls })),
  };
}

/**
 * Every configured credential the clients hold (the Prisma Cloud access key ID and
 * secret key, each PAN-OS API key and keygen password, and the key keygen returned),
 * for the tool boundary and the bundle writer, which remove them from the whole
 * payload in every encoded form (guard 2).
 */
export function configuredSecrets(clients: PaloaltoClients): string[] {
  const values = [
    clients.config.prisma?.accessKeyId,
    clients.config.prisma?.secretKey,
    ...clients.config.panos.flatMap((host) => [host.apiKey, host.password]),
    ...(clients.prisma?.knownSecrets ?? []),
    ...clients.panos.flatMap((client) => client.knownSecrets ?? []),
  ];
  return [...new Set(values.filter((value): value is string => typeof value === "string" && value.length >= MIN_CONFIGURED_SECRET_LENGTH))];
}

/**
 * Locates the Compute console. PRISMA_COMPUTE_URL wins; otherwise the CSPM
 * meta_info endpoint is asked for twistlockUrl. Failure leaves Compute
 * controls manual with the reason recorded.
 */
export async function resolveComputeClient(clients: PaloaltoClients): Promise<PrismaComputeClient | undefined> {
  if (clients.compute) return clients.compute;
  if (!clients.prisma) {
    clients.computeUnavailableReason = "Prisma Cloud credentials were not configured, so the Compute console could not be reached.";
    return undefined;
  }
  try {
    const meta = await clients.prisma.getMetaInfo();
    const consoleUrl = asString(meta.twistlockUrl);
    if (!consoleUrl) {
      clients.computeUnavailableReason = "CSPM /meta_info did not return twistlockUrl; set PRISMA_COMPUTE_URL to the Compute console path (Compute > Manage > System > Utilities > Path to Console).";
      return undefined;
    }
    clients.compute = new PrismaComputeClient(consoleUrl, clients.prisma);
    return clients.compute;
  } catch (error) {
    clients.computeUnavailableReason = `Compute console discovery via CSPM /meta_info failed (${errorMessage(error)}); set PRISMA_COMPUTE_URL to the Compute console path.`;
    clients.computeUnavailableFailure = describeFailure(error);
    return undefined;
  }
}

export async function loadPrismaSnapshot(clients: PaloaltoClients, alertLimit = DEFAULT_ALERT_LIMIT): Promise<PrismaSnapshot | undefined> {
  if (!clients.prisma) return undefined;
  const compute = await resolveComputeClient(clients);
  return collectPrismaSnapshot(clients.prisma, alertLimit, {
    client: compute,
    unavailableReason: clients.computeUnavailableReason,
    unavailableFailure: clients.computeUnavailableFailure,
  });
}

interface EvidenceGate {
  unreadable: string[];
  partial: string[];
  /** Per surface the finding reads, the collected records that carried none of the documented members. */
  unevaluable?: Record<string, number>;
}

/**
 * Applies the verdict-safety rules: unreadable evidence forces manual,
 * partial inventories (a truncated walk, or records that carried none of the
 * documented members and could not be evaluated) cap the verdict at warn.
 */
function gate(result: PaloaltoFinding, gateInfo: EvidenceGate, evidenceInstruction: string): PaloaltoFinding {
  if (gateInfo.unreadable.length > 0) {
    return {
      ...result,
      status: "manual",
      summary: `Evidence unavailable (${gateInfo.unreadable.join("; ")}), so the verdict cannot be derived from the API. Manual evidence required: ${evidenceInstruction}`,
      evidence: { ...(result.evidence ?? {}), unreadable_sources: gateInfo.unreadable, manual_evidence: evidenceInstruction },
    };
  }
  if (gateInfo.partial.length > 0) {
    const unevaluable = gateInfo.unevaluable && Object.keys(gateInfo.unevaluable).length > 0 ? { unevaluable_records: gateInfo.unevaluable } : {};
    return {
      ...result,
      status: result.status === "pass" ? "warn" : result.status,
      summary: `${result.summary} Partial inventory: ${gateInfo.partial.join("; ")}.`,
      evidence: { ...(result.evidence ?? {}), partial_inventory: gateInfo.partial, ...unevaluable },
    };
  }
  return result;
}

/** The unevaluable-record entries of a snapshot for the named surfaces, as gate notes and as counts keyed by surface. */
function unevaluableGate(product: string, snapshot: { unevaluable?: Record<string, number>; failed: string[] }, surfaces: string[], evaluated: (surface: string) => number): Pick<EvidenceGate, "partial" | "unevaluable"> {
  const affected = surfaces.filter((surface) => (snapshot.unevaluable?.[surface] ?? 0) > 0 && !snapshot.failed.includes(surface));
  return {
    partial: affected.map((surface) => unevaluableRecordsNote(product, surface, snapshot.unevaluable?.[surface] ?? 0, evaluated(surface))),
    unevaluable: Object.fromEntries(affected.map((surface) => [snakeCase(surface), snapshot.unevaluable?.[surface] ?? 0])),
  };
}

function prismaSurfaceRecords(snapshot: PrismaSnapshot, surface: string): JsonRecord[] {
  switch (surface) {
    case "alert rules":
      return snapshot.alertRules;
    case "open alerts":
      return snapshot.alerts;
    case "policies":
      return snapshot.policies;
    case "cloud accounts":
      return snapshot.cloudAccounts;
    case "account groups":
      return snapshot.accountGroups;
    case "user roles":
      return snapshot.userRoles;
    case "integrations":
      return snapshot.integrations;
    default:
      return [];
  }
}

function computeSurfaceRecords(snapshot: ComputeSnapshot, surface: string): JsonRecord[] {
  switch (surface) {
    case "defenders":
      return snapshot.defenders;
    case "registry scans":
      return snapshot.registryScans;
    case "images":
      return snapshot.images;
    case "vulnerability stats":
      return snapshot.vulnerabilityStats;
    case "cloud discovery":
      return snapshot.cloudDiscovery;
    case "ci scans":
      return snapshot.ciScans;
    default:
      return [];
  }
}

function prismaGate(snapshot: PrismaSnapshot, surfaces: string[]): EvidenceGate {
  const unreadable = surfaces.filter((surface) => snapshot.failed.includes(surface)).map((surface) => `prisma-cloud ${surface} unreadable`);
  const partial: string[] = [];
  if (surfaces.includes("open alerts") && snapshot.alertsTruncated && !snapshot.failed.includes("open alerts")) {
    const reach = `${snapshot.alerts.length}${snapshot.alertsTotal !== undefined ? ` of ${snapshot.alertsTotal}` : ""}`;
    partial.push(`open alerts truncated at ${reach} (${snapshot.alertsTruncationReason ?? "raise alert_limit"})`);
  }
  const unevaluable = unevaluableGate("prisma-cloud", snapshot, surfaces, (surface) => prismaSurfaceRecords(snapshot, surface).length);
  return { unreadable, partial: [...partial, ...unevaluable.partial], unevaluable: unevaluable.unevaluable };
}

function computeGate(snapshot: ComputeSnapshot, surfaces: string[]): EvidenceGate {
  const unevaluable = unevaluableGate("prisma-compute", snapshot, surfaces, (surface) => computeSurfaceRecords(snapshot, surface).length);
  return {
    unreadable: surfaces.filter((surface) => snapshot.failed.includes(surface)).map((surface) => `prisma-compute ${surface} unreadable`),
    partial: [
      ...surfaces
        .filter((surface) => snapshot.truncated.includes(surface) && !snapshot.failed.includes(surface))
        .map((surface) => {
          const reason = snapshot.truncationReasons?.[surface];
          return reason ? `prisma-compute ${surface} truncated (${reason})` : `prisma-compute ${surface} truncated at ${DEFAULT_COMPUTE_LIMIT} records`;
        }),
      ...unevaluable.partial,
    ],
    unevaluable: unevaluable.unevaluable,
  };
}

/** True when every named CSPM surface was read; evidence derived from a failed surface renders null. */
function prismaReadable(snapshot: PrismaSnapshot, ...surfaces: string[]): boolean {
  return surfaces.every((surface) => !snapshot.failed.includes(surface));
}

function computeReadable(snapshot: ComputeSnapshot, ...surfaces: string[]): boolean {
  return surfaces.every((surface) => !snapshot.failed.includes(surface));
}

function nullUnless<T>(readable: boolean, value: T): T | null {
  return readable ? value : null;
}

function panosGate(snapshots: PanosDeviceSnapshot[], xpathFragments: string[], options: { needsHaState?: boolean } = {}): EvidenceGate {
  const unreadable: string[] = [];
  for (const snapshot of snapshots) {
    if (!snapshot.reachable) {
      unreadable.push(`${snapshot.host} unreachable (show system info failed)`);
      continue;
    }
    const failed = snapshot.failedXpaths.filter((xpath) => xpathFragments.some((fragment) => xpath.includes(fragment)));
    if (failed.length > 0) unreadable.push(`${snapshot.host} config show failed for ${failed.join(", ")}`);
    if (options.needsHaState && snapshot.haStateFailed) unreadable.push(`${snapshot.host} show high-availability state failed`);
  }
  return { unreadable, partial: [] };
}

function mergeGates(...gates: Array<EvidenceGate | undefined>): EvidenceGate {
  return {
    unreadable: gates.flatMap((item) => item?.unreadable ?? []),
    partial: gates.flatMap((item) => item?.partial ?? []),
    unevaluable: Object.assign({}, ...gates.map((item) => item?.unevaluable ?? {})) as Record<string, number>,
  };
}

/** True when every device answered show system info and none of the named subtrees failed. */
function panosReadable(snapshots: PanosDeviceSnapshot[], xpathFragments: string[], options: { needsHaState?: boolean } = {}): boolean {
  return panosGate(snapshots, xpathFragments, options).unreadable.length === 0;
}

const POLICY_XPATHS = ["/vsys", "/device-group", "/config/shared"];
const ZONE_XPATHS = ["/network", "/template"];
const DEVICE_XPATHS = ["/deviceconfig", "/mgt-config", "/config/shared", "/template", "/config/panorama"];
const GLOBALPROTECT_XPATHS = ["/vsys", "/network", "/template"];
// Authentication profiles (and the MFA flag PA-15 reads) live under vsys, templates,
// and /config/shared, so the shared tree gates that finding as well.
const AUTHENTICATION_PROFILE_XPATHS = [...GLOBALPROTECT_XPATHS, "/config/shared"];

function finding(
  control: number,
  severity: PaloaltoSeverity,
  status: PaloaltoStatus,
  summary: string,
  evidence?: JsonRecord,
): PaloaltoFinding {
  const definition = CONTROLS_BY_NUMBER.get(control);
  return {
    id: definition?.id ?? `PA-${String(control).padStart(2, "0")}`,
    control,
    title: definition?.title ?? `Control ${control}`,
    severity,
    status,
    summary,
    evidence,
    mappings: controlMappings(control),
  };
}

function manualFinding(control: number, severity: PaloaltoSeverity, evidenceInstruction: string, reason: string): PaloaltoFinding {
  return finding(control, severity, "manual", `${reason} Manual evidence required: ${evidenceInstruction}`, { manual_evidence: evidenceInstruction });
}

function prismaNotConfigured(control: number, severity: PaloaltoSeverity, evidenceInstruction: string): PaloaltoFinding {
  return manualFinding(control, severity, evidenceInstruction, "Prisma Cloud credentials were not configured, so this control could not be evaluated through the CSPM API.");
}

function panosNotConfigured(control: number, severity: PaloaltoSeverity, evidenceInstruction: string): PaloaltoFinding {
  return manualFinding(control, severity, evidenceInstruction, "No PAN-OS firewall or Panorama host was configured, so this control could not be evaluated through the XML API.");
}

const CWPP_EVIDENCE: Array<{ control: number; severity: PaloaltoSeverity; instruction: string }> = [
  { control: 7, severity: "high", instruction: "export the Prisma Cloud Compute Monitor > Vulnerabilities > Images report and confirm critical and high CVE thresholds are enforced." },
  { control: 8, severity: "medium", instruction: "export Compute > Monitor > Compliance > Hosts results showing CIS benchmark pass rates for Defender-protected hosts." },
  { control: 9, severity: "high", instruction: "export Compute > Defend > Runtime container and host policies showing process, network, and file system protections enabled." },
  { control: 10, severity: "high", instruction: "export Compute > Manage > Defenders showing connected Defenders per host and cluster and the Defender version distribution." },
  { control: 11, severity: "medium", instruction: "export Compute > Defend > Vulnerabilities > Registry settings showing scan schedules and thresholds for every registry." },
  { control: 24, severity: "medium", instruction: "export Compute > Radars > Cloud discovery results listing unprotected clusters, registries, and serverless functions." },
  { control: 25, severity: "medium", instruction: "export Compute > Defend > Vulnerabilities > CI results and the admission (OPA) rules showing pipeline gates and admission control." },
];

function policyName(alert: JsonRecord): string {
  const policy = asObject(alert.policy);
  return asString(policy?.name) ?? asString(alert.policyId) ?? "unknown-policy";
}

function policyType(record: JsonRecord): string {
  return (asString(asObject(record.policy)?.policyType) ?? asString(record.policyType) ?? "").toLowerCase();
}

function policySeverity(record: JsonRecord): string {
  return (asString(asObject(record.policy)?.severity) ?? asString(record.severity) ?? "").toLowerCase();
}

function policyLabels(record: JsonRecord): string {
  const policy = asObject(record.policy) ?? record;
  return [asString(policy.name), ...asArray(policy.labels).map(asString), asString(policy.description)]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();
}

const NETWORK_EXPOSURE_PATTERN = /public|internet|0\.0\.0\.0|::\/0|exposed|open to|unrestricted|any source|wide open|world/i;
const ENCRYPTION_PATTERN = /encrypt|kms|cmk|customer.managed key/i;
const DLP_PATTERN = /\bdlp\b|data loss|sensitive data|pii|data classification|data security/i;

/** Alert counts, or the same shape with every value null when the alert list was not read. */
function summarizeAlerts(alerts: JsonRecord[], readable = true): JsonRecord {
  if (!readable) return { count: null, critical: null, high: null, top_policies: null };
  const byPolicy = new Map<string, number>();
  for (const alert of alerts) byPolicy.set(policyName(alert), (byPolicy.get(policyName(alert)) ?? 0) + 1);
  return {
    count: alerts.length,
    critical: alerts.filter((item) => policySeverity(item) === "critical").length,
    high: alerts.filter((item) => policySeverity(item) === "high").length,
    top_policies: [...byPolicy.entries()].sort((a, b) => b[1] - a[1]).slice(0, 10).map(([name, count]) => ({ policy: name, open_alerts: count })),
  };
}

export function assessPrismaCloudPosture(
  snapshot: PrismaSnapshot,
  options: { minCompliancePassRate?: number } = {},
): PaloaltoFinding[] {
  const minPassRate = clampNumber(options.minCompliancePassRate, DEFAULT_MIN_COMPLIANCE_PASS_RATE, 1, 100);
  const findings: PaloaltoFinding[] = [];
  const postureReadable = prismaReadable(snapshot, "compliance posture");
  const rulesReadable = prismaReadable(snapshot, "alert rules");
  const alertsReadable = prismaReadable(snapshot, "open alerts");
  const policiesReadable = prismaReadable(snapshot, "policies");
  const accountsReadable = prismaReadable(snapshot, "cloud accounts");
  const groupsReadable = prismaReadable(snapshot, "account groups");

  const summary = asObject(snapshot.posture?.summary) ?? snapshot.posture ?? {};
  const passed = asNumber(summary.passedResources) ?? 0;
  const failed = asNumber(summary.failedResources) ?? 0;
  const total = asNumber(summary.totalResources) ?? passed + failed;
  const passRate = total > 0 ? Math.round((passed / total) * 1000) / 10 : undefined;
  const standards = asRecords(snapshot.posture?.complianceDetails);
  findings.push(gate(finding(
    1,
    "high",
    passRate === undefined ? "manual" : passRate >= minPassRate ? "pass" : passRate >= minPassRate - 20 ? "warn" : "fail",
    passRate === undefined
      ? "Compliance posture returned zero evaluated resources; emptiness is treated as manual because it usually means no cloud account has finished scanning. Manual evidence required: confirm onboarded accounts have completed their first scan and export the compliance dashboard."
      : `${passRate}% of ${total} evaluated resources passed across ${standards.length} compliance standards (threshold ${minPassRate}%).`,
    {
      pass_rate: passRate ?? null,
      passed_resources: nullUnless(postureReadable, passed),
      failed_resources: nullUnless(postureReadable, failed),
      high_severity_failed: asNumber(summary.highSeverityFailedResources) ?? null,
      standards: nullUnless(postureReadable, standards.slice(0, 25).map((item) => ({ name: asString(item.name), passed: asNumber(item.passedResources), failed: asNumber(item.failedResources) }))),
    },
  ), prismaGate(snapshot, ["compliance posture"]), "export the Prisma Cloud compliance dashboard with per-standard pass rates."));

  const enabledRules = snapshot.alertRules.filter((rule) => asBoolean(rule.enabled) === true);
  const disabledRules = snapshot.alertRules.filter((rule) => asBoolean(rule.enabled) !== true);
  const openCritical = snapshot.alerts.filter((alert) => policySeverity(alert) === "critical").length;
  findings.push(gate(finding(
    2,
    "high",
    enabledRules.length === 0 ? "fail" : disabledRules.length > 0 || openCritical > 0 ? "warn" : "pass",
    snapshot.alertRules.length === 0
      ? "Zero alert rules were returned; emptiness is treated as fail because no policy violation can generate an alert or notification."
      : enabledRules.length === 0
        ? "No alert rule reports enabled=true, so policy violations will not generate alerts or notifications."
        : `${enabledRules.length} alert rules report enabled=true (${disabledRules.length} disabled or without an explicit enabled flag); ${openCritical} open critical alerts in the last 30 days.`,
    {
      enabled_rules: nullUnless(rulesReadable, enabledRules.map((rule) => asString(rule.name)).slice(0, 25)),
      disabled_rules: nullUnless(rulesReadable, disabledRules.map((rule) => asString(rule.name)).slice(0, 25)),
      rules_with_notifications: nullUnless(rulesReadable, snapshot.alertRules.filter((rule) => asArray(rule.alertRuleNotificationConfig).length > 0).length),
      open_alerts: summarizeAlerts(snapshot.alerts, alertsReadable),
    },
  ), prismaGate(snapshot, ["alert rules", "open alerts"]), "export Alerts > Alert Rules showing enabled rules and their notification channels."));

  const iamPolicies = snapshot.policies.filter((policy) => policyType(policy) === "iam");
  const iamEnabled = iamPolicies.filter((policy) => asBoolean(policy.enabled) === true);
  const iamAlerts = snapshot.alerts.filter((alert) => policyType(alert) === "iam");
  findings.push(gate(finding(
    3,
    "high",
    iamPolicies.length === 0 ? "manual" : iamEnabled.length === 0 ? "fail" : iamAlerts.length > 0 ? "fail" : "pass",
    iamPolicies.length === 0
      ? "No IAM Security policies were visible, so the CIEM module is either unlicensed or hidden from this access key; treated as manual. Manual evidence required: confirm the IAM Security subscription and export the Identity Security dashboard."
      : iamEnabled.length === 0
        ? `${iamPolicies.length} IAM policies exist but none report enabled=true.`
        : iamAlerts.length > 0
          ? `${iamAlerts.length} open IAM alerts indicate overprivileged or risky identities.`
          : `${iamEnabled.length} IAM policies report enabled=true with no open IAM alerts in the sampled window.`,
    {
      iam_policies: nullUnless(policiesReadable, iamPolicies.length),
      iam_policies_enabled: nullUnless(policiesReadable, iamEnabled.length),
      iam_alerts: summarizeAlerts(iamAlerts, alertsReadable),
    },
  ), prismaGate(snapshot, ["policies", "open alerts"]), "export the IAM Security policy list and open identity alerts."));

  const enabledAccounts = snapshot.cloudAccounts.filter((account) => asBoolean(account.enabled) === true);
  const disabledAccounts = snapshot.cloudAccounts.filter((account) => asBoolean(account.enabled) !== true);
  const ungroupedAccounts = snapshot.cloudAccounts.filter((account) => asArray(account.groups).length === 0 && asArray(account.groupIds).length === 0);
  const erroredAccounts = snapshot.cloudAccounts.filter((account) => /error|warning|disabled/i.test(asString(account.status) ?? ""));
  findings.push(gate(finding(
    4,
    "medium",
    snapshot.cloudAccounts.length === 0 ? "fail" : disabledAccounts.length > 0 || ungroupedAccounts.length > 0 ? "fail" : erroredAccounts.length > 0 ? "warn" : "pass",
    snapshot.cloudAccounts.length === 0
      ? "Zero cloud accounts are onboarded or visible to the access key; emptiness is treated as fail because nothing is being monitored."
      : `${snapshot.cloudAccounts.length} cloud accounts across ${snapshot.accountGroups.length} account groups; ${enabledAccounts.length} report enabled=true, ${disabledAccounts.length} disabled or without an explicit flag, ${ungroupedAccounts.length} without account groups, ${erroredAccounts.length} reporting errors.`,
    {
      accounts: nullUnless(accountsReadable, snapshot.cloudAccounts.length),
      account_groups: nullUnless(groupsReadable, snapshot.accountGroups.length),
      disabled_accounts: nullUnless(accountsReadable, disabledAccounts.map((account) => asString(account.name)).slice(0, 25)),
      ungrouped_accounts: nullUnless(accountsReadable, ungroupedAccounts.map((account) => asString(account.name)).slice(0, 25)),
      errored_accounts: nullUnless(accountsReadable, erroredAccounts.map((account) => `${asString(account.name)}: ${asString(account.status)}`).slice(0, 25)),
    },
  ), prismaGate(snapshot, ["cloud accounts", "account groups"]), "export Settings > Cloud Accounts with status and account group membership."));

  const networkPolicies = snapshot.policies.filter((policy) => policyType(policy) === "network" && asBoolean(policy.enabled) === true);
  const networkAlerts = snapshot.alerts.filter((alert) => policyType(alert) === "network" || NETWORK_EXPOSURE_PATTERN.test(policyLabels(alert)));
  const networkHighOrCritical = networkAlerts.filter((alert) => ["critical", "high"].includes(policySeverity(alert)));
  findings.push(gate(finding(
    5,
    "high",
    networkPolicies.length === 0 ? "manual" : networkHighOrCritical.length > 0 ? "fail" : networkAlerts.length > 0 ? "warn" : "pass",
    networkPolicies.length === 0
      ? "No enabled network policies were visible, so exposure cannot be detected from alerts; treated as manual. Manual evidence required: enable network exposure policies and export their open alerts."
      : networkAlerts.length === 0
        ? `No open network exposure alerts across ${networkPolicies.length} enabled network policies in the sampled window; emptiness is compliant here because detection policies are active and alerts were readable.`
        : `${networkAlerts.length} open network exposure alerts (${networkHighOrCritical.length} critical or high).`,
    { network_policies_enabled: nullUnless(policiesReadable, networkPolicies.length), ...summarizeAlerts(networkAlerts, alertsReadable) },
  ), prismaGate(snapshot, ["policies", "open alerts"]), "export open network exposure alerts and the enabled network policy list."));

  const encryptionPolicies = snapshot.policies.filter((policy) => ENCRYPTION_PATTERN.test(policyLabels(policy)));
  const encryptionEnabled = encryptionPolicies.filter((policy) => asBoolean(policy.enabled) === true);
  const encryptionAlerts = snapshot.alerts.filter((alert) => ENCRYPTION_PATTERN.test(policyLabels(alert)));
  findings.push(gate(finding(
    6,
    "high",
    encryptionEnabled.length === 0 ? "fail" : encryptionAlerts.length > 0 ? "fail" : encryptionPolicies.length > encryptionEnabled.length ? "warn" : "pass",
    encryptionEnabled.length === 0
      ? "No encryption-at-rest policies report enabled=true; emptiness is treated as fail because unencrypted storage would go undetected."
      : `${encryptionEnabled.length}/${encryptionPolicies.length} encryption policies report enabled=true with ${encryptionAlerts.length} open encryption alerts.`,
    {
      encryption_policies: nullUnless(policiesReadable, encryptionPolicies.length),
      encryption_policies_enabled: nullUnless(policiesReadable, encryptionEnabled.length),
      encryption_alerts: summarizeAlerts(encryptionAlerts, alertsReadable),
    },
  ), prismaGate(snapshot, ["policies", "open alerts"]), "export enabled encryption policies and their open alerts."));

  return findings;
}

function policyRules(policy: JsonRecord): JsonRecord[] {
  return asRecords(policy.rules);
}

function enabledPolicyRules(policy: JsonRecord): JsonRecord[] {
  return policyRules(policy).filter((rule) => asBoolean(rule.disabled) !== true);
}

function ruleEffect(rule: JsonRecord): string {
  return (asString(rule.effect) ?? asString(asObject(rule.processes)?.effect) ?? "").toLowerCase();
}

const VULNERABILITY_RESOURCE_KEYS = ["images", "registryImages", "containers", "hosts", "functions"];

/**
 * Aggregates the documented /stats/vulnerabilities shape: an array of
 * types.VulnerabilityStats whose images, registryImages, containers, hosts,
 * and functions members carry a cves distribution (critical, high, medium,
 * low, total). Image scan results contribute vulnerabilityDistribution as a
 * second source; the stricter of the two drives the verdict.
 */
function summarizeVulnerabilityStats(stats: JsonRecord[], images: JsonRecord[]): { critical?: number; high?: number; source: string; byResource: JsonRecord } {
  const byResource: JsonRecord = {};
  let statsCritical: number | undefined;
  let statsHigh: number | undefined;
  for (const entry of stats) {
    for (const key of VULNERABILITY_RESOURCE_KEYS) {
      const resource = asObject(entry[key]);
      const cves = asObject(resource?.cves);
      if (!resource || !cves) continue;
      const critical = asNumber(cves.critical);
      const high = asNumber(cves.high);
      byResource[key] = {
        count: asNumber(resource.count) ?? null,
        critical: critical ?? null,
        high: high ?? null,
        impacted_critical: asNumber(asObject(resource.impacted)?.critical) ?? null,
      };
      if (critical !== undefined) statsCritical = (statsCritical ?? 0) + critical;
      if (high !== undefined) statsHigh = (statsHigh ?? 0) + high;
    }
  }
  let imageCritical: number | undefined;
  let imageHigh: number | undefined;
  for (const image of images) {
    const distribution = asObject(image.vulnerabilityDistribution);
    if (!distribution) continue;
    const critical = asNumber(distribution.critical);
    const high = asNumber(distribution.high);
    if (critical !== undefined) imageCritical = (imageCritical ?? 0) + critical;
    if (high !== undefined) imageHigh = (imageHigh ?? 0) + high;
  }
  const pick = (a: number | undefined, b: number | undefined): number | undefined => (a === undefined ? b : b === undefined ? a : Math.max(a, b));
  const source = statsCritical !== undefined && imageCritical !== undefined
    ? "stats/vulnerabilities cves plus image vulnerabilityDistribution, stricter value used"
    : statsCritical !== undefined
      ? "stats/vulnerabilities cves distribution"
      : imageCritical !== undefined
        ? "image vulnerabilityDistribution"
        : "no severity distribution available";
  return { critical: pick(statsCritical, imageCritical), high: pick(statsHigh, imageHigh), source, byResource };
}

/**
 * Derives a compliance rate from the documented types.ComplianceStats shape:
 * rules[] (preferred) or categories[] entries carrying failed and total.
 */
function summarizeComplianceStats(stats: JsonRecord): { rate?: number; failed: number; total: number; source: string; worst: string[] } {
  const rules = asRecords(stats.rules);
  const categories = asRecords(stats.categories);
  const source = rules.some((rule) => asNumber(rule.total) !== undefined) ? "rules" : "categories";
  const entries = source === "rules" ? rules : categories;
  let failed = 0;
  let total = 0;
  for (const entry of entries) {
    failed += asNumber(entry.failed) ?? 0;
    total += asNumber(entry.total) ?? 0;
  }
  const worst = entries
    .filter((entry) => (asNumber(entry.total) ?? 0) > 0)
    .sort((a, b) => ((asNumber(b.failed) ?? 0) / (asNumber(b.total) ?? 1)) - ((asNumber(a.failed) ?? 0) / (asNumber(a.total) ?? 1)))
    .slice(0, 10)
    .map((entry) => `${asString(entry.name) ?? "unnamed"}: ${asNumber(entry.failed) ?? 0}/${asNumber(entry.total) ?? 0} failed`);
  return {
    rate: total > 0 ? Math.round(((total - Math.min(failed, total)) / total) * 1000) / 10 : undefined,
    failed,
    total,
    source: total > 0 ? `${source}[] failed versus total` : "no evaluations recorded",
    worst,
  };
}

function computeManual(control: number, severity: PaloaltoSeverity, reason: string): PaloaltoFinding {
  const item = CWPP_EVIDENCE.find((entry) => entry.control === control);
  return manualFinding(control, severity, item?.instruction ?? "export the corresponding Prisma Cloud Compute console page.", reason);
}

export function assessPrismaCompute(snapshot: PrismaSnapshot | undefined): PaloaltoFinding[] {
  if (!snapshot) return CWPP_EVIDENCE.map((item) => prismaNotConfigured(item.control, item.severity, item.instruction));
  const compute = snapshot.compute;
  if (!compute) {
    const reason = snapshot.computeUnavailableReason ?? "The Prisma Cloud Compute console was not configured or reachable (set PRISMA_COMPUTE_URL).";
    return CWPP_EVIDENCE.map((item) => computeManual(item.control, item.severity, reason));
  }
  const findings: PaloaltoFinding[] = [];
  const readable = (...surfaces: string[]) => computeReadable(compute, ...surfaces);

  const vulnPolicyRules = enabledPolicyRules(compute.vulnerabilityImagePolicy);
  const blockingRules = vulnPolicyRules.filter((rule) => ruleEffect(rule).includes("block") || ruleEffect(rule).includes("prevent"));
  const cveStats = summarizeVulnerabilityStats(compute.vulnerabilityStats, compute.images);
  const criticalCves = cveStats.critical;
  const highCves = cveStats.high;
  const imagesWithoutScanTime = compute.images.filter((image) => !asString(image.scanTime));
  const vulnPolicyReadable = readable("vulnerability image policy");
  const imagesReadable = readable("images");
  const cveStatsReadable = readable("vulnerability stats", "images");
  findings.push(gate(finding(
    7,
    "high",
    vulnPolicyRules.length === 0
      ? "fail"
      : blockingRules.length === 0 || (criticalCves ?? 0) > DEFAULT_MAX_CRITICAL_CVES
        ? "fail"
        : compute.images.length === 0 || imagesWithoutScanTime.length > 0 || criticalCves === undefined
          ? "warn"
          : "pass",
    vulnPolicyRules.length === 0
      ? "Zero enabled image vulnerability policy rules were returned; emptiness is treated as fail because no CVE threshold is enforced on deployed images."
      : blockingRules.length === 0
        ? `${vulnPolicyRules.length} image vulnerability rules are enabled but none block or prevent, so CVE thresholds are alert-only.`
        : (criticalCves ?? 0) > DEFAULT_MAX_CRITICAL_CVES
          ? `${criticalCves} critical CVEs remain in the environment despite ${blockingRules.length} blocking vulnerability rules.`
          : compute.images.length === 0
            ? `${blockingRules.length} blocking vulnerability rules are enabled but zero scanned images were returned; treated as warn until deployed images appear in Monitor > Vulnerabilities > Images.`
            : imagesWithoutScanTime.length > 0
              ? `${imagesWithoutScanTime.length} of ${compute.images.length} images have no scanTime and cannot be counted as freshly scanned.`
              : criticalCves === undefined
                ? "Neither /stats/vulnerabilities nor the image scan results exposed severity distributions, so the environment-wide CVE exposure is unknown."
                : `${blockingRules.length} blocking image vulnerability rules enforce thresholds; ${compute.images.length} scanned images, ${criticalCves} critical and ${highCves ?? "unknown"} high CVEs reported (${cveStats.source}).`,
    {
      vulnerability_rules_enabled: nullUnless(vulnPolicyReadable, vulnPolicyRules.length),
      blocking_rules: nullUnless(vulnPolicyReadable, blockingRules.map((rule) => asString(rule.name)).slice(0, 25)),
      images_scanned: nullUnless(imagesReadable, compute.images.length),
      images_without_scan_time: nullUnless(imagesReadable, imagesWithoutScanTime.map((image) => asString(image.id) ?? asString(asObject(image.repoTag)?.repo)).slice(0, 25)),
      critical_cves: cveStatsReadable ? criticalCves ?? null : null,
      high_cves: cveStatsReadable ? highCves ?? null : null,
      cve_stats_by_resource: nullUnless(cveStatsReadable, cveStats.byResource),
      cve_stats_source: nullUnless(cveStatsReadable, cveStats.source),
    },
  ), computeGate(compute, ["vulnerability image policy", "images", "vulnerability stats"]), CWPP_EVIDENCE[0].instruction));

  const hostRules = enabledPolicyRules(compute.complianceHostPolicy);
  const containerRules = enabledPolicyRules(compute.complianceContainerPolicy);
  const compliance = summarizeComplianceStats(compute.complianceStats);
  const complianceRate = compliance.rate;
  const connectedDefenders = compute.defenders.filter((defender) => asBoolean(defender.connected) === true).length;
  const defendersReadable = readable("defenders");
  const complianceStatsReadable = readable("compliance stats");
  findings.push(gate(finding(
    8,
    "medium",
    hostRules.length === 0 && containerRules.length === 0
      ? "fail"
      : hostRules.length === 0
        ? "fail"
        : connectedDefenders === 0
          ? "fail"
          : complianceRate === undefined
            ? "warn"
            : complianceRate < DEFAULT_MIN_HOST_COMPLIANCE_RATE
              ? "fail"
              : "pass",
    hostRules.length === 0 && containerRules.length === 0
      ? "Zero enabled host or container compliance rules were returned; emptiness is treated as fail because CIS benchmarks are not being evaluated."
      : hostRules.length === 0
        ? `${containerRules.length} container compliance rules are enabled but no host compliance rule is, so host CIS benchmarks are not evaluated.`
        : connectedDefenders === 0
          ? `${hostRules.length} host compliance rules are enabled but no Defender reports connected=true, so no host is actually being evaluated.`
          : complianceRate === undefined
            ? `${hostRules.length} host and ${containerRules.length} container compliance rules are enabled, but /stats/compliance recorded zero evaluations in rules[] and categories[], so no compliance rate can be derived; treated as warn.`
            : `${hostRules.length} host and ${containerRules.length} container compliance rules enabled across ${connectedDefenders} connected Defenders; ${compliance.failed} failed of ${compliance.total} compliance evaluations (${compliance.source}) gives a ${complianceRate}% compliance rate (threshold ${DEFAULT_MIN_HOST_COMPLIANCE_RATE}%).`,
    {
      host_rules_enabled: nullUnless(readable("compliance host policy"), hostRules.length),
      container_rules_enabled: nullUnless(readable("compliance container policy"), containerRules.length),
      connected_defenders: nullUnless(defendersReadable, connectedDefenders),
      compliance_rate: complianceStatsReadable ? complianceRate ?? null : null,
      compliance_failed: nullUnless(complianceStatsReadable, compliance.failed),
      compliance_total: nullUnless(complianceStatsReadable, compliance.total),
      compliance_source: nullUnless(complianceStatsReadable, compliance.source),
      worst_rules: nullUnless(complianceStatsReadable, compliance.worst),
    },
  ), computeGate(compute, ["compliance host policy", "compliance container policy", "compliance stats", "defenders"]), CWPP_EVIDENCE[1].instruction));

  const runtimeRules = enabledPolicyRules(compute.runtimeContainerPolicy);
  const protectiveRules = runtimeRules.filter((rule) => {
    const effects = ["processes", "network", "filesystem", "dns"].map((key) => (asString(asObject(rule[key])?.effect) ?? "").toLowerCase());
    return effects.some((effect) => effect === "prevent" || effect === "block");
  });
  const alertOnlyRules = runtimeRules.filter((rule) => !protectiveRules.includes(rule));
  const runtimeDefenders = compute.defenders.filter((defender) => asBoolean(defender.connected) === true).length;
  findings.push(gate(finding(
    9,
    "high",
    runtimeRules.length === 0 ? "fail" : protectiveRules.length === 0 ? "warn" : runtimeDefenders === 0 ? "fail" : "pass",
    runtimeRules.length === 0
      ? "Zero enabled container runtime rules were returned; emptiness is treated as fail because Defenders have no runtime policy to enforce."
      : protectiveRules.length === 0
        ? `${runtimeRules.length} container runtime rules are enabled but every process, network, file system, and DNS effect is alert or disable, so nothing is prevented.`
        : runtimeDefenders === 0
          ? `${protectiveRules.length} preventive runtime rules exist but no Defender reports connected=true, so nothing enforces them.`
          : `${protectiveRules.length} of ${runtimeRules.length} enabled container runtime rules prevent or block at least one behavior class (${alertOnlyRules.length} alert-only), enforced by ${runtimeDefenders} connected Defenders.`,
    {
      runtime_rules_enabled: nullUnless(readable("runtime container policy"), runtimeRules.length),
      connected_defenders: nullUnless(defendersReadable, runtimeDefenders),
      protective_rules: nullUnless(readable("runtime container policy"), protectiveRules.map((rule) => asString(rule.name)).slice(0, 25)),
      alert_only_rules: nullUnless(readable("runtime container policy"), alertOnlyRules.map((rule) => asString(rule.name)).slice(0, 25)),
    },
  ), computeGate(compute, ["runtime container policy", "defenders"]), CWPP_EVIDENCE[2].instruction));

  const connected = compute.defenders.filter((defender) => asBoolean(defender.connected) === true);
  const disconnected = compute.defenders.filter((defender) => asBoolean(defender.connected) !== true);
  const withoutTimestamp = compute.defenders.filter((defender) => !asString(defender.lastModified));
  const versions = new Set(compute.defenders.map((defender) => asString(defender.version) ?? "unknown"));
  findings.push(gate(finding(
    10,
    "high",
    compute.defenders.length === 0 ? "fail" : disconnected.length > 0 ? "fail" : withoutTimestamp.length > 0 || versions.size > 2 ? "warn" : "pass",
    compute.defenders.length === 0
      ? "Zero Defenders are deployed; emptiness is treated as fail because no host or cluster is protected."
      : disconnected.length > 0
        ? `${disconnected.length} of ${compute.defenders.length} Defenders do not report connected=true.`
        : withoutTimestamp.length > 0
          ? `${connected.length} Defenders report connected=true, but ${withoutTimestamp.length} have no lastModified timestamp and cannot be counted as recently seen.`
          : `${connected.length} Defenders report connected=true across ${versions.size} version(s).`,
    {
      defenders: nullUnless(defendersReadable, compute.defenders.length),
      connected: nullUnless(defendersReadable, connected.length),
      disconnected: nullUnless(defendersReadable, disconnected.map((defender) => asString(defender.hostname)).slice(0, 25)),
      without_timestamp: nullUnless(defendersReadable, withoutTimestamp.map((defender) => asString(defender.hostname)).slice(0, 25)),
      versions: nullUnless(defendersReadable, [...versions]),
    },
  ), computeGate(compute, ["defenders"]), CWPP_EVIDENCE[3].instruction));

  const registries = asRecords(compute.registrySettings.specifications);
  const registriesWithoutCadence = registries.filter((registry) => !asString(registry.cap) && asNumber(registry.cap) === undefined && !asString(registry.scanners) && asNumber(registry.scanners) === undefined);
  const registryScansWithoutTime = compute.registryScans.filter((scan) => !asString(scan.scanTime));
  findings.push(gate(finding(
    11,
    "medium",
    registries.length === 0 ? "manual" : compute.registryScans.length === 0 ? "fail" : registryScansWithoutTime.length > 0 || registriesWithoutCadence.length > 0 ? "warn" : "pass",
    registries.length === 0
      ? "Zero registries are configured for scanning; treated as manual because an organization without container registries has nothing to scan. Manual evidence required: confirm no container registry is in use or configure registry scanning."
      : compute.registryScans.length === 0
        ? `${registries.length} registries are configured but zero registry scan results exist, so scanning has not completed.`
        : registryScansWithoutTime.length > 0
          ? `${registryScansWithoutTime.length} of ${compute.registryScans.length} registry scan results have no scanTime and cannot be counted as fresh.`
          : `${registries.length} registries configured with ${compute.registryScans.length} scanned images.`,
    {
      registries: nullUnless(readable("registry settings"), registries.map((registry) => `${asString(registry.registry) ?? ""}/${asString(registry.repository) ?? "*"}`).slice(0, 25)),
      registry_scans: nullUnless(readable("registry scans"), compute.registryScans.length),
      scans_without_time: nullUnless(readable("registry scans"), registryScansWithoutTime.length),
    },
  ), computeGate(compute, ["registry settings", "registry scans"]), CWPP_EVIDENCE[4].instruction));

  // An entry that reports neither total nor defended carries nothing the coverage
  // comparison can read, so it is unevaluable: it can never count as covered.
  const evaluableDiscovery = compute.cloudDiscovery.filter((entry) => asNumber(entry.total) !== undefined || asNumber(entry.defended) !== undefined);
  const unevaluableDiscovery = compute.cloudDiscovery.length - evaluableDiscovery.length;
  const unprotected = evaluableDiscovery.filter((entry) => (asNumber(entry.total) ?? 0) > (asNumber(entry.defended) ?? 0));
  const discoveryErrors = compute.cloudDiscovery.filter((entry) => asString(entry.err));
  findings.push(gate(finding(
    24,
    "medium",
    compute.cloudDiscovery.length === 0 ? "manual" : unprotected.length > 0 ? "fail" : unevaluableDiscovery > 0 || discoveryErrors.length > 0 ? "warn" : "pass",
    compute.cloudDiscovery.length === 0
      ? "Zero cloud discovery results were returned; treated as manual because discovery requires cloud account credentials in Compute. Manual evidence required: configure cloud discovery and export Radars > Cloud."
      : unprotected.length > 0
        ? `${unprotected.length} discovered cloud services report more total resources than defended ones.`
        : unevaluableDiscovery > 0
          ? `${unevaluableDiscovery} of ${compute.cloudDiscovery.length} cloud discovery entries report neither total nor defended resources, so their coverage cannot be evaluated${discoveryErrors.length > 0 ? `; ${discoveryErrors.length} entries report errors` : ""}.`
          : discoveryErrors.length > 0
            ? `${discoveryErrors.length} cloud discovery entries report errors, so coverage is uncertain.`
            : `${compute.cloudDiscovery.length} cloud discovery entries all report total resources equal to defended resources.`,
    {
      discovery_entries: nullUnless(readable("cloud discovery"), compute.cloudDiscovery.length),
      unevaluable_entries: nullUnless(readable("cloud discovery"), unevaluableDiscovery),
      unprotected: nullUnless(readable("cloud discovery"), unprotected.map((entry) => `${asString(entry.provider)}/${asString(entry.serviceType)}: ${asNumber(entry.defended) ?? 0}/${asNumber(entry.total) ?? 0}`).slice(0, 25)),
      errors: nullUnless(readable("cloud discovery"), discoveryErrors.map((entry) => redactErrorText(asString(entry.err) ?? "")).slice(0, 10)),
    },
  ), computeGate(compute, ["cloud discovery"]), CWPP_EVIDENCE[5].instruction));

  const scansWithoutTime = compute.ciScans.filter((scan) => !asString(scan.time));
  const failedScans = compute.ciScans.filter((scan) => asBoolean(scan.pass) === false);
  findings.push(gate(finding(
    25,
    "medium",
    compute.ciScans.length === 0 ? "fail" : "warn",
    compute.ciScans.length === 0
      ? "Zero CI image scan results were returned; emptiness is treated as fail because no pipeline is submitting images to twistcli or the Jenkins plugin."
      : `${compute.ciScans.length} CI scan results (${failedScans.length} failed policy, ${scansWithoutTime.length} without a scan time). Admission control policy has no verified public read endpoint, so this control stays at warn until admission rules are reviewed manually.`,
    {
      ci_scans: nullUnless(readable("ci scans"), compute.ciScans.length),
      failed_scans: nullUnless(readable("ci scans"), failedScans.length),
      scans_without_time: nullUnless(readable("ci scans"), scansWithoutTime.length),
      manual_evidence: "export Compute > Defend > Access > Admission rules to confirm admission control gating.",
    },
  ), computeGate(compute, ["ci scans"]), CWPP_EVIDENCE[6].instruction));

  return findings;
}

interface SecurityRule {
  name: string;
  location: string;
  disabled: boolean;
  action: string;
  from: string[];
  to: string[];
  source: string[];
  destination: string[];
  application: string[];
  service: string[];
  logEnd?: string;
  logStart: boolean;
  logForwarding?: string;
  profileGroup?: string;
  profiles: Record<string, string[]>;
}

function isAnyList(values: string[]): boolean {
  return values.length === 0 || values.some((value) => value === "any");
}

function collectSecurityRules(snapshot: PanosDeviceSnapshot): SecurityRule[] {
  const rules: SecurityRule[] = [];
  for (const tree of snapshot.config) {
    for (const security of xmlFindAll(tree, "security")) {
      const rulesNode = xmlChild(security, "rules");
      if (!rulesNode) continue;
      const parentName = security.name;
      for (const entry of xmlEntries(rulesNode)) {
        const profileSetting = xmlChild(entry, "profile-setting");
        const profiles: Record<string, string[]> = {};
        for (const profile of xmlChild(profileSetting, "profiles")?.children ?? []) {
          profiles[profile.name] = xmlMembers(profile);
        }
        rules.push({
          name: xmlEntryName(entry),
          location: `${snapshot.host}:${parentName}`,
          disabled: xmlText(xmlChild(entry, "disabled")) === "yes",
          action: xmlText(xmlChild(entry, "action")) ?? "allow",
          from: xmlMembers(xmlChild(entry, "from")),
          to: xmlMembers(xmlChild(entry, "to")),
          source: xmlMembers(xmlChild(entry, "source")),
          destination: xmlMembers(xmlChild(entry, "destination")),
          application: xmlMembers(xmlChild(entry, "application")),
          service: xmlMembers(xmlChild(entry, "service")),
          logEnd: xmlText(xmlChild(entry, "log-end")),
          logStart: xmlText(xmlChild(entry, "log-start")) === "yes",
          logForwarding: xmlText(xmlChild(entry, "log-setting")),
          profileGroup: xmlMembers(xmlChild(profileSetting, "group"))[0],
          profiles,
        });
      }
    }
  }
  return rules;
}

function isShadowed(rule: SecurityRule, earlier: SecurityRule[]): boolean {
  return earlier.some((candidate) =>
    !candidate.disabled
    && candidate.location === rule.location
    && (isAnyList(candidate.from) || rule.from.every((zone) => candidate.from.includes(zone)))
    && (isAnyList(candidate.to) || rule.to.every((zone) => candidate.to.includes(zone)))
    && isAnyList(candidate.source)
    && isAnyList(candidate.destination)
    && isAnyList(candidate.application)
    && (isAnyList(candidate.service) || candidate.service.includes("application-default")));
}

function profileEntries(snapshot: PanosDeviceSnapshot, profileType: string): XmlNode[] {
  const entries: XmlNode[] = [];
  for (const tree of snapshot.config) {
    for (const profiles of xmlFindAll(tree, "profiles")) {
      entries.push(...xmlEntries(xmlChild(profiles, profileType)));
    }
  }
  return entries;
}

function profileGroups(snapshot: PanosDeviceSnapshot): Map<string, Record<string, string[]>> {
  const groups = new Map<string, Record<string, string[]>>();
  for (const tree of snapshot.config) {
    for (const groupNode of xmlFindAll(tree, "profile-group")) {
      for (const entry of xmlEntries(groupNode)) {
        const members: Record<string, string[]> = {};
        for (const child of entry.children) members[child.name] = xmlMembers(child);
        groups.set(xmlEntryName(entry), members);
      }
    }
  }
  return groups;
}

function ruleProfileCoverage(rule: SecurityRule, groups: Map<string, Record<string, string[]>>, profileType: string): boolean {
  if ((rule.profiles[profileType] ?? []).length > 0) return true;
  if (!rule.profileGroup) return false;
  return (groups.get(rule.profileGroup)?.[profileType] ?? []).length > 0;
}

function allowRules(rules: SecurityRule[]): SecurityRule[] {
  return rules.filter((rule) => !rule.disabled && rule.action === "allow");
}

export function assessPanosFirewallPolicy(snapshots: PanosDeviceSnapshot[]): PaloaltoFinding[] {
  const rules = snapshots.flatMap(collectSecurityRules);
  const enabledRules = rules.filter((rule) => !rule.disabled);
  const permissive = enabledRules.filter((rule) =>
    rule.action === "allow" && isAnyList(rule.source) && isAnyList(rule.destination) && isAnyList(rule.application) && (isAnyList(rule.service) || rule.service.includes("application-default")));
  const anyZone = enabledRules.filter((rule) => rule.action === "allow" && (isAnyList(rule.from) || isAnyList(rule.to)));
  const unlogged = enabledRules.filter((rule) => rule.logEnd === "no");
  const implicitLog = enabledRules.filter((rule) => rule.logEnd === undefined);
  const shadowed = enabledRules.filter((rule, index) => isShadowed(rule, enabledRules.slice(0, index).filter((item) => item.location === rule.location)));
  const findings: PaloaltoFinding[] = [];
  const policyReadable = panosReadable(snapshots, POLICY_XPATHS);
  const zonesReadable = panosReadable(snapshots, [...ZONE_XPATHS, ...POLICY_XPATHS]);
  const decryptionReadable = panosReadable(snapshots, [...POLICY_XPATHS, ...DEVICE_XPATHS]);

  findings.push(gate(finding(
    12,
    "critical",
    rules.length === 0 ? "manual" : permissive.length > 0 ? "fail" : unlogged.length > 0 || shadowed.length > 0 || implicitLog.length > 0 ? "warn" : "pass",
    rules.length === 0
      ? "Zero security rules were returned by the configured devices; treated as manual because an empty rulebase usually means the wrong vsys or device group scope rather than a hardened policy. Manual evidence required: export the security rulebase for every vsys and device group."
      : `${enabledRules.length} enabled security rules: ${permissive.length} any/any allow, ${shadowed.length} likely shadowed, ${unlogged.length} with log-end=no, ${implicitLog.length} without an explicit log-end flag (implicit default not counted as logged).`,
    {
      rules_total: nullUnless(policyReadable, rules.length),
      rules_enabled: nullUnless(policyReadable, enabledRules.length),
      rules_without_explicit_log_end: nullUnless(policyReadable, implicitLog.map((rule) => `${rule.location}/${rule.name}`).slice(0, 25)),
      permissive_rules: nullUnless(policyReadable, permissive.map((rule) => `${rule.location}/${rule.name}`).slice(0, 25)),
      shadowed_rules: nullUnless(policyReadable, shadowed.map((rule) => `${rule.location}/${rule.name}`).slice(0, 25)),
      unlogged_rules: nullUnless(policyReadable, unlogged.map((rule) => `${rule.location}/${rule.name}`).slice(0, 25)),
    },
  ), panosGate(snapshots, POLICY_XPATHS), "export the security rulebase with rule usage, logging, and disabled state."));

  const zones: Array<{ host: string; name: string; zoneProtection?: string }> = [];
  const defaultRules: Array<{ host: string; name: string; action?: string; logEnd?: string }> = [];
  for (const snapshot of snapshots) {
    for (const tree of snapshot.config) {
      for (const zoneNode of xmlFindAll(tree, "zone")) {
        for (const entry of xmlEntries(zoneNode)) {
          zones.push({
            host: snapshot.host,
            name: xmlEntryName(entry),
            zoneProtection: xmlText(xmlPath(entry, ["network", "zone-protection-profile"])),
          });
        }
      }
      for (const defaults of xmlFindAll(tree, "default-security-rules")) {
        for (const entry of xmlEntries(xmlChild(defaults, "rules"))) {
          defaultRules.push({
            host: snapshot.host,
            name: xmlEntryName(entry),
            action: xmlText(xmlChild(entry, "action")),
            logEnd: xmlText(xmlChild(entry, "log-end")),
          });
        }
      }
    }
  }
  const intrazoneDenied = defaultRules.some((rule) => rule.name === "intrazone-default" && rule.action === "deny");
  const interzoneLogged = defaultRules.some((rule) => rule.name === "interzone-default" && rule.logEnd === "yes");
  const unprotectedZones = zones.filter((zone) => !zone.zoneProtection);
  findings.push(gate(finding(
    13,
    "high",
    zones.length === 0 ? "manual" : anyZone.length > 0 ? "fail" : !intrazoneDenied || unprotectedZones.length > 0 || !interzoneLogged ? "warn" : "pass",
    zones.length === 0
      ? "Zero zones were returned; treated as manual because a firewall always has zones, so the network subtree is probably hidden from this API role. Manual evidence required: export Network > Zones with zone protection assignments."
      : `${zones.length} zones; ${anyZone.length} allow rules use any zone, intrazone-default ${intrazoneDenied ? "denies" : "allows (default)"}, interzone-default logging ${interzoneLogged ? "enabled" : "not enabled"}, ${unprotectedZones.length} zones without a zone protection profile.`,
    {
      zones: nullUnless(zonesReadable, zones.map((zone) => `${zone.host}/${zone.name}`).slice(0, 50)),
      any_zone_allow_rules: nullUnless(policyReadable, anyZone.map((rule) => `${rule.location}/${rule.name}`).slice(0, 25)),
      intrazone_default_denied: nullUnless(policyReadable, intrazoneDenied),
      interzone_default_logged: nullUnless(policyReadable, interzoneLogged),
      zones_without_zone_protection: nullUnless(zonesReadable, unprotectedZones.map((zone) => `${zone.host}/${zone.name}`).slice(0, 50)),
    },
  ), panosGate(snapshots, [...ZONE_XPATHS, ...POLICY_XPATHS]), "export zone protection profile assignments and the intrazone and interzone default rule settings."));

  const decryptionRules: Array<{ host: string; name: string; action?: string; disabled: boolean }> = [];
  const weakTlsProfiles: string[] = [];
  let tlsProfiles = 0;
  for (const snapshot of snapshots) {
    for (const tree of snapshot.config) {
      for (const decryption of xmlFindAll(tree, "decryption")) {
        for (const entry of xmlEntries(xmlChild(decryption, "rules"))) {
          decryptionRules.push({
            host: snapshot.host,
            name: xmlEntryName(entry),
            action: xmlText(xmlChild(entry, "action")),
            disabled: xmlText(xmlChild(entry, "disabled")) === "yes",
          });
        }
      }
      for (const profileNode of xmlFindAll(tree, "ssl-tls-service-profile")) {
        for (const entry of xmlEntries(profileNode)) {
          tlsProfiles += 1;
          const minVersion = xmlText(xmlPath(entry, ["protocol-settings", "min-version"])) ?? "tls1-0";
          if (/tls1-0|tls1-1|sslv3/i.test(minVersion)) weakTlsProfiles.push(`${snapshot.host}/${xmlEntryName(entry)} (${minVersion})`);
        }
      }
    }
  }
  const activeDecrypt = decryptionRules.filter((rule) => !rule.disabled && rule.action === "decrypt");
  findings.push(gate(finding(
    14,
    "high",
    activeDecrypt.length === 0 ? "fail" : weakTlsProfiles.length > 0 ? "warn" : "pass",
    activeDecrypt.length === 0
      ? "No enabled decryption rules with action decrypt were found; encrypted traffic is not inspected."
      : `${activeDecrypt.length} active decrypt rules (${decryptionRules.length - activeDecrypt.length} no-decrypt or disabled); ${weakTlsProfiles.length}/${tlsProfiles} SSL/TLS service profiles allow TLS below 1.2.`,
    {
      decryption_rules: nullUnless(policyReadable, decryptionRules.map((rule) => `${rule.host}/${rule.name}: ${rule.action ?? "unknown"}${rule.disabled ? " (disabled)" : ""}`).slice(0, 25)),
      tls_service_profiles: nullUnless(decryptionReadable, tlsProfiles),
      weak_tls_profiles: nullUnless(decryptionReadable, weakTlsProfiles.slice(0, 25)),
    },
  ), panosGate(snapshots, [...POLICY_XPATHS, ...DEVICE_XPATHS]), "export the decryption rulebase and SSL/TLS service profiles."));

  return findings;
}

export function assessPanosThreatPrevention(snapshots: PanosDeviceSnapshot[]): PaloaltoFinding[] {
  const rules = snapshots.flatMap(collectSecurityRules);
  const allows = allowRules(rules);
  const findings: PaloaltoFinding[] = [];
  const groups = new Map<string, Record<string, string[]>>();
  for (const snapshot of snapshots) for (const [name, members] of profileGroups(snapshot)) groups.set(name, members);
  const policyReadable = panosReadable(snapshots, POLICY_XPATHS);

  const virus = snapshots.flatMap((snapshot) => profileEntries(snapshot, "virus"));
  const spyware = snapshots.flatMap((snapshot) => profileEntries(snapshot, "spyware"));
  const vulnerability = snapshots.flatMap((snapshot) => profileEntries(snapshot, "vulnerability"));
  const missingThreat = allows.filter((rule) =>
    !ruleProfileCoverage(rule, groups, "virus") || !ruleProfileCoverage(rule, groups, "spyware") || !ruleProfileCoverage(rule, groups, "vulnerability"));
  const lenientVulnerability = vulnerability.filter((profile) =>
    xmlEntries(xmlChild(profile, "rules")).some((rule) =>
      xmlMembers(xmlChild(rule, "severity")).some((severity) => /critical|high/i.test(severity))
      && ["allow", "alert", "default"].includes(xmlChild(rule, "action")?.children[0]?.name ?? "default")));
  findings.push(gate(finding(
    16,
    "critical",
    virus.length === 0 || spyware.length === 0 || vulnerability.length === 0 ? "fail" : missingThreat.length > 0 ? "fail" : lenientVulnerability.length > 0 ? "warn" : "pass",
    virus.length === 0 || spyware.length === 0 || vulnerability.length === 0
      ? `Custom threat prevention profiles are incomplete (antivirus ${virus.length}, anti-spyware ${spyware.length}, vulnerability ${vulnerability.length}).`
      : missingThreat.length > 0
        ? `${missingThreat.length}/${allows.length} allow rules lack antivirus, anti-spyware, or vulnerability protection profiles.`
        : `All ${allows.length} allow rules carry threat prevention profiles; ${lenientVulnerability.length} vulnerability profiles alert or allow on critical/high signatures.`,
    {
      antivirus_profiles: nullUnless(policyReadable, virus.map(xmlEntryName)),
      antispyware_profiles: nullUnless(policyReadable, spyware.map(xmlEntryName)),
      vulnerability_profiles: nullUnless(policyReadable, vulnerability.map(xmlEntryName)),
      allow_rules_missing_threat_profiles: nullUnless(policyReadable, missingThreat.map((rule) => `${rule.location}/${rule.name}`).slice(0, 25)),
      lenient_vulnerability_profiles: nullUnless(policyReadable, lenientVulnerability.map(xmlEntryName)),
    },
  ), panosGate(snapshots, POLICY_XPATHS), "export antivirus, anti-spyware, and vulnerability profiles and their rule attachments."));

  const wildfire = snapshots.flatMap((snapshot) => profileEntries(snapshot, "wildfire-analysis"));
  const fullCoverage = wildfire.filter((profile) =>
    xmlEntries(xmlChild(profile, "rules")).some((rule) =>
      isAnyList(xmlMembers(xmlChild(rule, "application"))) && isAnyList(xmlMembers(xmlChild(rule, "file-type")))));
  const missingWildfire = allows.filter((rule) => !ruleProfileCoverage(rule, groups, "wildfire-analysis"));
  findings.push(gate(finding(
    17,
    "high",
    wildfire.length === 0 ? "fail" : missingWildfire.length > 0 || fullCoverage.length === 0 ? "warn" : "pass",
    wildfire.length === 0
      ? "No WildFire analysis profiles are configured."
      : `${wildfire.length} WildFire profiles (${fullCoverage.length} forward any application and any file type); ${missingWildfire.length}/${allows.length} allow rules lack WildFire coverage. Cloud connectivity must be confirmed with 'show wildfire status'.`,
    {
      wildfire_profiles: nullUnless(policyReadable, wildfire.map(xmlEntryName)),
      full_coverage_profiles: nullUnless(policyReadable, fullCoverage.map(xmlEntryName)),
      allow_rules_missing_wildfire: nullUnless(policyReadable, missingWildfire.map((rule) => `${rule.location}/${rule.name}`).slice(0, 25)),
    },
  ), panosGate(snapshots, POLICY_XPATHS), "export WildFire analysis profiles, rule attachments, and show wildfire status output."));

  const urlProfiles = snapshots.flatMap((snapshot) => profileEntries(snapshot, "url-filtering"));
  const requiredCategories = ["malware", "phishing", "command-and-control"];
  const weakUrlProfiles = urlProfiles.filter((profile) => {
    const blocked = xmlMembers(xmlChild(profile, "block"));
    return !requiredCategories.every((category) => blocked.includes(category));
  });
  const credentialDisabled = urlProfiles.filter((profile) => {
    const mode = xmlPath(profile, ["credential-enforcement", "mode"]);
    return !mode || xmlChild(mode, "disabled") !== undefined;
  });
  const missingUrl = allows.filter((rule) => !ruleProfileCoverage(rule, groups, "url-filtering"));
  findings.push(gate(finding(
    18,
    "high",
    urlProfiles.length === 0 || weakUrlProfiles.length > 0 ? "fail" : credentialDisabled.length > 0 || missingUrl.length > 0 ? "warn" : "pass",
    urlProfiles.length === 0
      ? "No URL filtering profiles are configured."
      : `${urlProfiles.length} URL filtering profiles; ${weakUrlProfiles.length} do not block malware, phishing, and command-and-control; ${credentialDisabled.length} have credential phishing protection disabled; ${missingUrl.length}/${allows.length} allow rules lack URL filtering.`,
    {
      url_profiles: nullUnless(policyReadable, urlProfiles.map(xmlEntryName)),
      weak_url_profiles: nullUnless(policyReadable, weakUrlProfiles.map(xmlEntryName)),
      credential_enforcement_disabled: nullUnless(policyReadable, credentialDisabled.map(xmlEntryName)),
      allow_rules_missing_url_filtering: nullUnless(policyReadable, missingUrl.map((rule) => `${rule.location}/${rule.name}`).slice(0, 25)),
    },
  ), panosGate(snapshots, POLICY_XPATHS), "export URL filtering profiles with blocked categories and credential enforcement settings."));

  const fileBlocking = snapshots.flatMap((snapshot) => profileEntries(snapshot, "file-blocking"));
  const blockingPe = fileBlocking.filter((profile) =>
    xmlEntries(xmlChild(profile, "rules")).some((rule) => {
      const types = xmlMembers(xmlChild(rule, "file-type"));
      return xmlText(xmlChild(rule, "action")) === "block" && (types.includes("any") || types.includes("pe") || types.includes("PE"));
    }));
  const missingFileBlocking = allows.filter((rule) => !ruleProfileCoverage(rule, groups, "file-blocking"));
  findings.push(gate(finding(
    22,
    "medium",
    blockingPe.length === 0 ? "fail" : missingFileBlocking.length > 0 ? "warn" : "pass",
    blockingPe.length === 0
      ? "No file blocking profile blocks PE executables or all file types."
      : `${blockingPe.length}/${fileBlocking.length} file blocking profiles block PE or all file types; ${missingFileBlocking.length}/${allows.length} allow rules lack file blocking.`,
    {
      file_blocking_profiles: nullUnless(policyReadable, fileBlocking.map(xmlEntryName)),
      profiles_blocking_pe: nullUnless(policyReadable, blockingPe.map(xmlEntryName)),
      allow_rules_missing_file_blocking: nullUnless(policyReadable, missingFileBlocking.map((rule) => `${rule.location}/${rule.name}`).slice(0, 25)),
    },
  ), panosGate(snapshots, POLICY_XPATHS), "export file blocking profiles and their rule attachments."));

  return findings;
}

function dataFilteringEvidence(snapshots: PanosDeviceSnapshot[]): { profiles: string[]; attachedRules: number; allowRules: number } {
  const rules = snapshots.flatMap(collectSecurityRules);
  const allows = allowRules(rules);
  const groups = new Map<string, Record<string, string[]>>();
  for (const snapshot of snapshots) for (const [name, members] of profileGroups(snapshot)) groups.set(name, members);
  const profiles = snapshots.flatMap((snapshot) => profileEntries(snapshot, "data-filtering")).map(xmlEntryName);
  return {
    profiles,
    attachedRules: allows.filter((rule) => ruleProfileCoverage(rule, groups, "data-filtering")).length,
    allowRules: allows.length,
  };
}

export function assessDataLossPrevention(prisma: PrismaSnapshot | undefined, snapshots: PanosDeviceSnapshot[]): PaloaltoFinding {
  const instruction = "export Prisma Cloud Data Security policies and PAN-OS data filtering profiles with the rules they are attached to.";
  if (!prisma && snapshots.length === 0) return manualFinding(21, "medium", instruction, "Neither Prisma Cloud nor PAN-OS was configured.");

  const dlpPolicies = prisma ? prisma.policies.filter((policy) => policyType(policy) === "data" || DLP_PATTERN.test(policyLabels(policy))) : [];
  const dlpEnabled = dlpPolicies.filter((policy) => asBoolean(policy.enabled) === true);
  const panos = dataFilteringEvidence(snapshots);
  const prismaOk = prisma ? dlpEnabled.length > 0 : undefined;
  const panosOk = snapshots.length > 0 ? panos.profiles.length > 0 && panos.attachedRules > 0 : undefined;
  const evaluated = [prismaOk, panosOk].filter((value): value is boolean => value !== undefined);
  const status: PaloaltoStatus = evaluated.every(Boolean) ? (evaluated.length === 2 ? "pass" : "warn") : evaluated.some(Boolean) ? "warn" : "fail";
  const parts = [
    prisma ? `Prisma Cloud: ${dlpEnabled.length}/${dlpPolicies.length} data security policies enabled.` : "Prisma Cloud not configured.",
    snapshots.length > 0
      ? `PAN-OS: ${panos.profiles.length} data filtering profiles attached to ${panos.attachedRules}/${panos.allowRules} allow rules.`
      : "PAN-OS not configured.",
  ];
  const gateInfo = mergeGates(prisma ? prismaGate(prisma, ["policies"]) : undefined, snapshots.length > 0 ? panosGate(snapshots, POLICY_XPATHS) : undefined);
  const prismaPoliciesReadable = prisma !== undefined && prismaReadable(prisma, "policies");
  const panosPolicyReadable = snapshots.length > 0 && panosReadable(snapshots, POLICY_XPATHS);
  return gate(finding(21, "medium", status, parts.join(" "), {
    prisma_dlp_policies: nullUnless(prismaPoliciesReadable, dlpPolicies.map((policy) => asString(policy.name)).slice(0, 25)),
    panos_data_filtering_profiles: nullUnless(panosPolicyReadable, panos.profiles),
    panos_rules_with_data_filtering: nullUnless(panosPolicyReadable, panos.attachedRules),
  }), gateInfo, instruction);
}

interface AdminAccount {
  host: string;
  name: string;
  superuser: boolean;
  localPassword: boolean;
  authenticationProfile?: string;
  publicKey: boolean;
}

function collectAdmins(snapshot: PanosDeviceSnapshot): AdminAccount[] {
  const admins: AdminAccount[] = [];
  for (const tree of snapshot.config) {
    for (const users of xmlFindAll(tree, "users")) {
      if (!xmlEntries(users).some((entry) => xmlChild(entry, "permissions") || xmlChild(entry, "phash"))) continue;
      for (const entry of xmlEntries(users)) {
        const roleBased = xmlPath(entry, ["permissions", "role-based"]);
        admins.push({
          host: snapshot.host,
          name: xmlEntryName(entry),
          superuser: xmlChild(roleBased, "superuser") !== undefined,
          localPassword: xmlChild(entry, "phash") !== undefined,
          authenticationProfile: xmlText(xmlChild(entry, "authentication-profile")),
          publicKey: xmlChild(entry, "public-key") !== undefined,
        });
      }
    }
  }
  return admins;
}

function passwordComplexityEnabled(snapshot: PanosDeviceSnapshot): boolean | undefined {
  for (const tree of snapshot.config) {
    const complexity = xmlFindAll(tree, "password-complexity")[0];
    if (complexity) return xmlText(xmlChild(complexity, "enabled")) === "yes";
  }
  return undefined;
}

export function assessAdminAccess(prisma: PrismaSnapshot | undefined, snapshots: PanosDeviceSnapshot[], options: { maxSuperusers?: number } = {}): PaloaltoFinding {
  const maxSuperusers = clampNumber(options.maxSuperusers, DEFAULT_MAX_SUPERUSERS, 0, 1000);
  const instruction = "export the PAN-OS administrator list with roles and authentication profiles, plus the Prisma Cloud Settings > Access Control roles list.";
  if (!prisma && snapshots.length === 0) return manualFinding(19, "high", instruction, "Neither Prisma Cloud nor PAN-OS was configured.");

  const admins = snapshots.flatMap(collectAdmins);
  const superusers = admins.filter((admin) => admin.superuser);
  const localOnly = admins.filter((admin) => admin.localPassword && !admin.authenticationProfile && !admin.publicKey);
  const complexity = snapshots.map(passwordComplexityEnabled);
  const complexityDisabled = complexity.some((value) => value !== true);
  const sysadminRoles = prisma ? prisma.userRoles.filter((role) => /system admin/i.test(asString(role.roleType) ?? asString(role.name) ?? "")) : [];
  const panosFail = snapshots.length > 0 && (superusers.length > maxSuperusers || complexityDisabled);
  const panosWarn = snapshots.length > 0 && localOnly.length > 0;
  const prismaWarn = prisma !== undefined && (sysadminRoles.length > maxSuperusers || prisma.userRoles.length === 0);
  const panosEmpty = snapshots.length > 0 && admins.length === 0;
  const singleProduct = !prisma || snapshots.length === 0;
  const status: PaloaltoStatus = panosEmpty ? "manual" : panosFail ? "fail" : panosWarn || prismaWarn || singleProduct ? "warn" : "pass";
  const parts = [
    snapshots.length > 0
      ? panosEmpty
        ? `PAN-OS: zero administrator accounts were readable, which is treated as manual because every device has at least one admin; the mgt-config users subtree is probably hidden from this API role. Manual evidence required: ${instruction}`
        : `PAN-OS: ${admins.length} administrators, ${superusers.length} superusers (threshold ${maxSuperusers}), ${localOnly.length} local-password-only accounts, password complexity ${complexityDisabled ? "not enabled on every device" : "enabled"}. MFA for admin logins must be confirmed in the authentication profiles.`
      : "PAN-OS not configured, so only the Prisma Cloud half of this control was evaluated (capped at warn).",
    prisma ? `Prisma Cloud: ${prisma.userRoles.length} roles, ${sysadminRoles.length} System Admin roles.${prisma.userRoles.length === 0 ? " Zero roles were returned, so role assignments could not be evaluated (warn)." : ""}` : "Prisma Cloud not configured.",
  ];
  const gateInfo = mergeGates(prisma ? prismaGate(prisma, ["user roles"]) : undefined, snapshots.length > 0 ? panosGate(snapshots, DEVICE_XPATHS) : undefined);
  const deviceReadable = snapshots.length > 0 && panosReadable(snapshots, DEVICE_XPATHS);
  const rolesReadable = prisma !== undefined && prismaReadable(prisma, "user roles");
  return gate(finding(19, "high", status, parts.join(" "), {
    panos_admins: nullUnless(deviceReadable, admins.map((admin) => `${admin.host}/${admin.name}${admin.superuser ? " (superuser)" : ""}`).slice(0, 50)),
    panos_local_password_only: nullUnless(deviceReadable, localOnly.map((admin) => `${admin.host}/${admin.name}`).slice(0, 50)),
    password_complexity_by_device: nullUnless(deviceReadable, snapshots.map((snapshot, index) => ({ host: snapshot.host, enabled: complexity[index] ?? null }))),
    prisma_roles: nullUnless(rolesReadable, prisma?.userRoles.map((role) => `${asString(role.name)} (${asString(role.roleType) ?? "unknown"})`).slice(0, 50) ?? null),
  }), gateInfo, instruction);
}

export function assessLogging(prisma: PrismaSnapshot | undefined, snapshots: PanosDeviceSnapshot[]): PaloaltoFinding {
  const instruction = "export PAN-OS log forwarding profiles and syslog or Panorama server profiles, plus the Prisma Cloud Settings > Integrations list.";
  if (!prisma && snapshots.length === 0) return manualFinding(20, "high", instruction, "Neither Prisma Cloud nor PAN-OS was configured.");

  const rules = snapshots.flatMap(collectSecurityRules);
  const enabled = rules.filter((rule) => !rule.disabled);
  const unlogged = enabled.filter((rule) => rule.logEnd === "no");
  const implicitLog = enabled.filter((rule) => rule.logEnd === undefined);
  const noForwarding = enabled.filter((rule) => !rule.logForwarding);
  let syslogServers = 0;
  let panoramaForwarding = false;
  let forwardingProfiles = 0;
  for (const snapshot of snapshots) {
    for (const tree of snapshot.config) {
      for (const logSettings of xmlFindAll(tree, "log-settings")) {
        syslogServers += xmlEntries(xmlChild(logSettings, "syslog")).length;
        forwardingProfiles += xmlEntries(xmlChild(logSettings, "profiles")).length;
        if (xmlFindAll(logSettings, "send-to-panorama").some((node) => xmlText(node) === "yes")) panoramaForwarding = true;
      }
      if (xmlFindAll(tree, "panorama-server").length > 0) panoramaForwarding = true;
    }
  }
  const externalForwarding = syslogServers > 0 || panoramaForwarding;
  const siemIntegrations = prisma ? prisma.integrations.filter((item) => /splunk|siem|syslog|qradar|sentinel|webhook|sqs|pubsub|snow|servicenow/i.test(`${asString(item.integrationType) ?? ""} ${asString(item.name) ?? ""}`)) : [];
  const panosFail = snapshots.length > 0 && (unlogged.length > 0 || !externalForwarding);
  const panosWarn = snapshots.length > 0 && (noForwarding.length > 0 || implicitLog.length > 0 || enabled.length === 0);
  const prismaWarn = Boolean(prisma) && siemIntegrations.length === 0;
  const singleProduct = !prisma || snapshots.length === 0;
  const status: PaloaltoStatus = panosFail ? "fail" : panosWarn || prismaWarn || singleProduct ? "warn" : "pass";
  const parts = [
    snapshots.length > 0
      ? `PAN-OS: ${unlogged.length}/${enabled.length} rules set log-end=no, ${implicitLog.length} rely on the implicit log-end default, ${noForwarding.length} lack a log forwarding profile, ${syslogServers} syslog server profiles, Panorama forwarding ${panoramaForwarding ? "configured" : "not configured"}.${enabled.length === 0 ? " Zero enabled rules were readable, so rule logging could not be evaluated (warn)." : ""} Log retention must be confirmed against the storage quota.`
      : "PAN-OS not configured, so only the Prisma Cloud half of this control was evaluated (capped at warn).",
    prisma ? `Prisma Cloud: ${siemIntegrations.length}/${prisma.integrations.length} integrations forward alerts to a SIEM or notification channel.` : "Prisma Cloud not configured.",
  ];
  const gateInfo = mergeGates(prisma ? prismaGate(prisma, ["integrations"]) : undefined, snapshots.length > 0 ? panosGate(snapshots, [...POLICY_XPATHS, ...DEVICE_XPATHS]) : undefined);
  const rulesReadable = snapshots.length > 0 && panosReadable(snapshots, POLICY_XPATHS);
  const forwardingReadable = snapshots.length > 0 && panosReadable(snapshots, [...POLICY_XPATHS, ...DEVICE_XPATHS]);
  const integrationsReadable = prisma !== undefined && prismaReadable(prisma, "integrations");
  return gate(finding(20, "high", status, parts.join(" "), {
    unlogged_rules: nullUnless(rulesReadable, unlogged.map((rule) => `${rule.location}/${rule.name}`).slice(0, 25)),
    rules_without_log_forwarding: nullUnless(rulesReadable, noForwarding.map((rule) => `${rule.location}/${rule.name}`).slice(0, 25)),
    syslog_server_profiles: nullUnless(forwardingReadable, syslogServers),
    log_forwarding_profiles: nullUnless(forwardingReadable, forwardingProfiles),
    panorama_forwarding: nullUnless(forwardingReadable, panoramaForwarding),
    prisma_integrations: nullUnless(integrationsReadable, prisma?.integrations.map((item) => `${asString(item.name)} (${asString(item.integrationType) ?? "unknown"})`).slice(0, 25) ?? null),
  }), gateInfo, instruction);
}

export function assessPanosDeviceHardening(snapshots: PanosDeviceSnapshot[]): PaloaltoFinding[] {
  const findings: PaloaltoFinding[] = [];

  const portals: string[] = [];
  const gateways: string[] = [];
  const gatewaysWithoutAuth: string[] = [];
  const portalsWithoutAuth: string[] = [];
  const mfaProfiles: string[] = [];
  const splitTunnelGateways: string[] = [];
  for (const snapshot of snapshots) {
    for (const tree of snapshot.config) {
      for (const authProfiles of xmlFindAll(tree, "authentication-profile")) {
        for (const entry of xmlEntries(authProfiles)) {
          if (xmlText(xmlPath(entry, ["multi-factor-auth", "mfa-enable"])) === "yes") mfaProfiles.push(`${snapshot.host}/${xmlEntryName(entry)}`);
        }
      }
      for (const gp of xmlFindAll(tree, "global-protect")) {
        for (const entry of xmlEntries(xmlChild(gp, "global-protect-portal"))) {
          portals.push(`${snapshot.host}/${xmlEntryName(entry)}`);
          if (xmlFindAll(entry, "authentication-profile").length === 0) portalsWithoutAuth.push(`${snapshot.host}/${xmlEntryName(entry)}`);
        }
        for (const entry of xmlEntries(xmlChild(gp, "global-protect-gateway"))) {
          gateways.push(`${snapshot.host}/${xmlEntryName(entry)}`);
          if (xmlFindAll(entry, "authentication-profile").length === 0) gatewaysWithoutAuth.push(`${snapshot.host}/${xmlEntryName(entry)}`);
          if (xmlFindAll(entry, "split-tunneling").some((node) => xmlMembers(xmlChild(node, "include-access-route")).length > 0)) {
            splitTunnelGateways.push(`${snapshot.host}/${xmlEntryName(entry)}`);
          }
        }
      }
    }
  }
  const gpConfigured = portals.length + gateways.length > 0;
  const gpReadable = panosReadable(snapshots, GLOBALPROTECT_XPATHS);
  const authProfilesReadable = panosReadable(snapshots, AUTHENTICATION_PROFILE_XPATHS);
  findings.push(gate(finding(
    15,
    "high",
    !gpConfigured ? "manual" : portalsWithoutAuth.length + gatewaysWithoutAuth.length > 0 ? "fail" : mfaProfiles.length === 0 || splitTunnelGateways.length > 0 ? "warn" : "pass",
    !gpConfigured
      ? "GlobalProtect is not configured on the inspected devices, so the control is scoped out and reported as manual rather than pass. Manual evidence required: confirm no remote access VPN is expected for these devices or provide the device that hosts GlobalProtect."
      : `${portals.length} portals and ${gateways.length} gateways; ${portalsWithoutAuth.length + gatewaysWithoutAuth.length} without an authentication profile, ${mfaProfiles.length} authentication profiles enforce MFA, ${splitTunnelGateways.length} gateways use split tunneling. HIP profile requirements must be reviewed manually.`,
    {
      portals: nullUnless(gpReadable, portals),
      gateways: nullUnless(gpReadable, gateways),
      portals_without_authentication: nullUnless(gpReadable, portalsWithoutAuth),
      gateways_without_authentication: nullUnless(gpReadable, gatewaysWithoutAuth),
      mfa_authentication_profiles: nullUnless(authProfilesReadable, mfaProfiles),
      split_tunnel_gateways: nullUnless(gpReadable, splitTunnelGateways),
    },
  ), panosGate(snapshots, AUTHENTICATION_PROFILE_XPATHS), "export GlobalProtect portal and gateway authentication settings with the referenced authentication profiles."));

  const hardening: JsonRecord[] = [];
  let failures = 0;
  let warnings = 0;
  for (const snapshot of snapshots) {
    const system = snapshot.config.map((tree) => xmlFindAll(tree, "system").find((node) => xmlChild(node, "hostname") || xmlChild(node, "ntp-servers") || xmlChild(node, "dns-setting") || xmlChild(node, "service"))).find(Boolean);
    const setting = snapshot.config.map((tree) => xmlFindAll(tree, "setting").find((node) => xmlChild(node, "management"))).find(Boolean);
    if (!system) continue;
    const ntp = xmlFindAll(system, "ntp-server-address").map(xmlText).filter(Boolean);
    const dns = xmlText(xmlPath(system, ["dns-setting", "servers", "primary"]));
    const banner = xmlText(xmlChild(system, "login-banner"));
    const permittedIps = xmlEntries(xmlChild(system, "permitted-ip")).map(xmlEntryName);
    const idleTimeout = asNumber(xmlText(xmlPath(setting, ["management", "idle-timeout"])));
    const communities = xmlFindAll(system, "snmp-community-string").map(xmlText).filter((item): item is string => Boolean(item));
    const defaultCommunity = communities.some((item) => /^(public|private)$/i.test(item));
    const telnetDisabled = xmlText(xmlPath(system, ["service", "disable-telnet"])) !== "no";
    const httpDisabled = xmlText(xmlPath(system, ["service", "disable-http"])) !== "no";
    const deviceFail = ntp.length === 0 || defaultCommunity || !telnetDisabled || !httpDisabled;
    const deviceWarn = !banner || permittedIps.length === 0 || idleTimeout === undefined || idleTimeout === 0 || idleTimeout > 15 || !dns;
    if (deviceFail) failures += 1;
    else if (deviceWarn) warnings += 1;
    hardening.push({
      host: snapshot.host,
      ntp_servers: ntp,
      dns_primary: dns ?? null,
      login_banner: Boolean(banner),
      permitted_ips: permittedIps,
      idle_timeout_minutes: idleTimeout ?? null,
      default_snmp_community: defaultCommunity,
      telnet_disabled: telnetDisabled,
      http_disabled: httpDisabled,
    });
  }
  findings.push(gate(finding(
    23,
    "medium",
    snapshots.length === 0 || hardening.length === 0 ? "manual" : failures > 0 ? "fail" : warnings > 0 ? "warn" : "pass",
    snapshots.length === 0 || hardening.length === 0
      ? "No deviceconfig system settings were readable from any device, so hardening cannot be evaluated. Manual evidence required: export Device > Setup > Management and Services settings."
      : `${snapshots.length} devices inspected: ${failures} fail hardening checks (NTP, default SNMP community, telnet or HTTP management), ${warnings} have warnings (banner, permitted IPs, idle timeout, DNS).`,
    { devices: nullUnless(panosReadable(snapshots, DEVICE_XPATHS), hardening) },
  ), panosGate(snapshots, DEVICE_XPATHS, { needsHaState: true }), "export management interface service settings, admin lockout settings, certificates, and HA state."));

  const haDetails = snapshots.map((snapshot) => {
    const enabled = xmlText(xmlChild(snapshot.haState, "enabled"));
    const state = xmlText(xmlFindAll(snapshot.haState, "state")[0]);
    return { host: snapshot.host, ha_enabled: enabled ?? null, local_state: state ?? null };
  });
  const haDisabled = haDetails.filter((item) => item.ha_enabled !== "yes");
  const haUnreadable = snapshots.filter((snapshot) => snapshot.haStateFailed || !snapshot.reachable);
  findings.push({
    id: "PA-HA-01",
    control: 23,
    title: "High availability state",
    severity: "medium",
    status: snapshots.length === 0 || haUnreadable.length > 0 ? "manual" : haDisabled.length > 0 ? "warn" : "pass",
    summary: snapshots.length === 0
      ? "No devices were inspected. Manual evidence required: export show high-availability state for each device."
      : haUnreadable.length > 0
        ? `HA state could not be read from ${haUnreadable.map((snapshot) => snapshot.host).join(", ")}. Manual evidence required: export show high-availability state for each device.`
        : `${haDetails.length - haDisabled.length}/${haDetails.length} devices report enabled=yes for high availability${haDisabled.length > 0 ? " (devices without an explicit enabled flag are counted as disabled)" : ""}.`,
    evidence: { devices: haDetails, unreadable_hosts: haUnreadable.map((snapshot) => snapshot.host) },
    mappings: controlMappings(23),
  });

  const versions = snapshots.map((snapshot) => ({
    host: snapshot.host,
    model: asString(snapshot.systemInfo.model) ?? null,
    sw_version: asString(snapshot.systemInfo["sw-version"]) ?? null,
    app_version: asString(snapshot.systemInfo["app-version"]) ?? null,
    av_version: asString(snapshot.systemInfo["av-version"]) ?? null,
    threat_version: asString(snapshot.systemInfo["threat-version"]) ?? null,
    wildfire_version: asString(snapshot.systemInfo["wildfire-version"]) ?? null,
    url_filtering_version: asString(snapshot.systemInfo["url-filtering-version"]) ?? null,
  }));
  const legacy = versions.filter((item) => {
    const major = Number.parseInt((item.sw_version ?? "").split(".")[0] ?? "", 10);
    return Number.isFinite(major) && major < 10;
  });
  const missingContent = versions.filter((item) => !item.av_version || item.av_version === "0" || !item.threat_version || item.threat_version === "0");
  const unreadableInfo = snapshots.filter((snapshot) => !snapshot.reachable);
  const withoutVersion = versions.filter((item) => !item.sw_version);
  findings.push({
    id: "PA-SW-01",
    control: 23,
    title: "Software and content versions",
    severity: "high",
    status: versions.length === 0 || unreadableInfo.length > 0 ? "manual" : legacy.length > 0 ? "fail" : missingContent.length > 0 || withoutVersion.length > 0 ? "warn" : "pass",
    summary: versions.length === 0 || unreadableInfo.length > 0
      ? `System information was not readable from ${unreadableInfo.map((snapshot) => snapshot.host).join(", ") || "any device"}. Manual evidence required: export show system info for each device.`
      : `${legacy.length} devices run PAN-OS 9.x or older; ${missingContent.length} devices lack installed antivirus or threat content; ${withoutVersion.length} report no sw-version (not counted as current). Content release dates are not exposed by show system info, so freshness must be confirmed against Device > Dynamic Updates.`,
    evidence: { devices: versions },
    mappings: controlMappings(23),
  });

  return findings;
}

async function readableSurface(
  product: PaloaltoAccessSurface["product"],
  target: string,
  name: string,
  endpoint: string,
  load: () => Promise<unknown>,
  countResolver?: (value: unknown) => number | undefined,
  partialResolver?: (value: unknown) => boolean,
): Promise<PaloaltoAccessSurface> {
  try {
    const value = await load();
    const partial = partialResolver?.(value) === true;
    return { product, target, name, endpoint, status: "readable", count: countResolver?.(value) ?? null, httpStatus: null, ...(partial ? { partial } : {}) };
  } catch (error) {
    // A failed probe names the request that actually failed (a login or keygen
    // request when authentication is what broke) and reads nothing, so count and
    // partial are null rather than 0 and false.
    const failure = describeFailure(error);
    return { product, target, name, endpoint: failure.endpoint ?? endpoint, status: "not_readable", count: null, partial: null, httpStatus: failure.status, error: failure.error };
  }
}

const arrayCount = (value: unknown) => (Array.isArray(value) ? value.length : undefined);
const pagedCount = (value: unknown) => (value as PagedResult).items.length;
const pagedPartial = (value: unknown) => (value as PagedResult).truncated;

export async function checkPaloaltoAccess(clients: PaloaltoClients): Promise<PaloaltoAccessCheckResult> {
  const surfaces: PaloaltoAccessSurface[] = [];
  const products: string[] = [];
  const notes: string[] = [];

  if (clients.prisma) {
    const prisma = clients.prisma;
    products.push("prisma-cloud");
    notes.push(`Prisma Cloud API: ${prisma.apiUrl}`);
    surfaces.push(
      await readableSurface("prisma-cloud", prisma.apiUrl, "compliance_posture", PRISMA_READ_ENDPOINTS["compliance posture"], () => prisma.getCompliancePosture(), () => 1),
      await readableSurface("prisma-cloud", prisma.apiUrl, "alert_rules", PRISMA_READ_ENDPOINTS["alert rules"], () => prisma.listAlertRules(), arrayCount),
      await readableSurface("prisma-cloud", prisma.apiUrl, "open_alerts", PRISMA_READ_ENDPOINTS["open alerts"], () => prisma.collectOpenAlerts(DEFAULT_ALERT_PAGE_SIZE), pagedCount, pagedPartial),
      await readableSurface("prisma-cloud", prisma.apiUrl, "policies", PRISMA_READ_ENDPOINTS.policies, () => prisma.listPolicies(), arrayCount),
      await readableSurface("prisma-cloud", prisma.apiUrl, "cloud_accounts", PRISMA_READ_ENDPOINTS["cloud accounts"], () => prisma.listCloudAccounts(), arrayCount),
      await readableSurface("prisma-cloud", prisma.apiUrl, "account_groups", PRISMA_READ_ENDPOINTS["account groups"], () => prisma.listAccountGroups(), arrayCount),
      await readableSurface("prisma-cloud", prisma.apiUrl, "user_roles", PRISMA_READ_ENDPOINTS["user roles"], () => prisma.listUserRoles(), arrayCount),
      // Evaluated after the probes above logged in, so the tenant-scoped path is named when login returned a prismaId.
      await readableSurface("prisma-cloud", prisma.apiUrl, "integrations", prismaIntegrationsEndpoint(prisma.tenantPrismaId), () => prisma.listIntegrations(), arrayCount),
    );
    const compute = await resolveComputeClient(clients);
    if (compute) {
      products.push("prisma-compute");
      notes.push(`Prisma Cloud Compute console: ${compute.baseUrl}`);
      surfaces.push(
        await readableSurface("prisma-compute", compute.baseUrl, "defenders", COMPUTE_READ_ENDPOINTS.defenders, () => compute.listDefenders(DEFAULT_COMPUTE_PAGE_SIZE), pagedCount, pagedPartial),
        await readableSurface("prisma-compute", compute.baseUrl, "runtime_container_policy", COMPUTE_READ_ENDPOINTS["runtime container policy"], () => compute.getRuntimeContainerPolicy(), (value) => asRecords(asObject(value)?.rules).length),
        await readableSurface("prisma-compute", compute.baseUrl, "compliance_container_policy", COMPUTE_READ_ENDPOINTS["compliance container policy"], () => compute.getComplianceContainerPolicy(), (value) => asRecords(asObject(value)?.rules).length),
        await readableSurface("prisma-compute", compute.baseUrl, "compliance_host_policy", COMPUTE_READ_ENDPOINTS["compliance host policy"], () => compute.getComplianceHostPolicy(), (value) => asRecords(asObject(value)?.rules).length),
        await readableSurface("prisma-compute", compute.baseUrl, "vulnerability_image_policy", COMPUTE_READ_ENDPOINTS["vulnerability image policy"], () => compute.getVulnerabilityImagePolicy(), (value) => asRecords(asObject(value)?.rules).length),
        await readableSurface("prisma-compute", compute.baseUrl, "registry_settings", COMPUTE_READ_ENDPOINTS["registry settings"], () => compute.getRegistrySettings(), (value) => asRecords(asObject(value)?.specifications).length),
        await readableSurface("prisma-compute", compute.baseUrl, "vulnerability_stats", COMPUTE_READ_ENDPOINTS["vulnerability stats"], () => compute.getVulnerabilityStats(), arrayCount),
        await readableSurface("prisma-compute", compute.baseUrl, "cloud_discovery", COMPUTE_READ_ENDPOINTS["cloud discovery"], () => compute.listCloudDiscovery(DEFAULT_COMPUTE_PAGE_SIZE), pagedCount, pagedPartial),
        await readableSurface("prisma-compute", compute.baseUrl, "ci_scans", COMPUTE_READ_ENDPOINTS["ci scans"], () => compute.listCiScans(DEFAULT_COMPUTE_PAGE_SIZE), pagedCount, pagedPartial),
      );
    } else {
      notes.push(`Prisma Cloud Compute not reachable: ${clients.computeUnavailableReason ?? "unknown"} Controls 7-11, 24, and 25 fall back to manual findings.`);
    }
  } else {
    notes.push("Prisma Cloud not configured (PRISMA_ACCESS_KEY_ID and PRISMA_SECRET_KEY missing); controls 1-11, 24, and 25 fall back to manual findings.");
  }

  if (clients.panos.length > 0) products.push("pan-os");
  for (const device of clients.panos) {
    const systemInfoSurface = await readableSurface("pan-os", device.host, "system_info", PANOS_READ_ENDPOINTS[PANOS_SYSTEM_INFO_READ], () => device.showSystemInfo(), () => 1);
    surfaces.push(systemInfoSurface);
    const systemInfo: JsonRecord = systemInfoSurface.status === "readable" ? await device.showSystemInfo().catch(() => ({})) : {};
    const platform = detectPlatform(systemInfo);
    notes.push(`${device.host}: ${platform}${asString(systemInfo.model) ? ` ${asString(systemInfo.model)}` : ""}${asString(systemInfo["sw-version"]) ? ` PAN-OS ${asString(systemInfo["sw-version"])}` : ""}`);
    surfaces.push(await readableSurface("pan-os", device.host, "ha_state", PANOS_READ_ENDPOINTS[PANOS_HA_STATE_READ], () => device.showHighAvailabilityState(), () => 1));
    for (const xpath of platformXpaths(platform)) {
      surfaces.push(await readableSurface("pan-os", device.host, xpath.split("/").slice(-1)[0], panosConfigEndpoint(xpath), () => device.showConfig(xpath), (value) => (value as XmlNode).children.length));
    }
  }
  if (clients.panos.length === 0) {
    notes.push("PAN-OS not configured (PANOS_HOST missing); controls 12-18, 22, and 23 fall back to manual findings.");
  }
  if (!clients.config.verifyTls) notes.push("TLS certificate verification is disabled for PAN-OS requests only (PANOS_VERIFY_TLS=false); Prisma Cloud requests and the rest of the process keep verification on.");

  const readable = surfaces.filter((surface) => surface.status === "readable").length;
  const partialProbes = surfaces.filter((surface) => surface.partial).length;
  const status: PaloaltoAccessCheckResult["status"] = surfaces.length === 0 ? "unconfigured" : readable === surfaces.length ? "healthy" : "degraded";
  // A refusal (401 or 403, or PAN-OS's own error status) is a role problem; a surface that
  // failed any other way (a proxy or portal answering in place of the API, a transport
  // fault) is not fixed by a role.
  const refused = surfaces.some((surface) => surface.status !== "readable" && (surface.httpStatus === 401 || surface.httpStatus === 403));
  notes.push(`${readable}/${surfaces.length} Palo Alto audit surfaces are readable.${partialProbes > 0 ? ` ${partialProbes} probe${partialProbes === 1 ? "" : "s"} stopped at the page cap, so counts marked + are lower bounds, not inventory totals.` : ""}`);
  return {
    status,
    products,
    surfaces,
    notes,
    recommendedNextStep: status === "healthy"
      ? "Run paloalto_assess_cloud_posture, paloalto_assess_firewall_policy, paloalto_assess_threat_prevention, paloalto_assess_device_hardening, or paloalto_export_audit_bundle."
      : status === "degraded" && !refused
        ? "Investigate the failed surfaces (the configured URL or host, a proxy or portal answering in place of the API, or a transport fault) before relying on the assessments; findings that read them are manual."
        : "Grant the Prisma Cloud access key a read-only System Admin or Account Group Read Only role and the PAN-OS admin a read-only (auditadmin or custom XML API read) role, then re-run paloalto_check_access.",
  };
}

async function collectPanosSnapshots(clients: PaloaltoClients): Promise<PanosDeviceSnapshot[]> {
  return Promise.all(clients.panos.map((device) => collectPanosSnapshot(device)));
}

/**
 * Per-device collection status for assessment summaries: which hosts and
 * subtrees were not read, plus a per-read collection block (status, the request
 * behind the read, the HTTP status a failed read observed, and counts that are
 * null rather than 0 when the read never happened).
 */
function panosCollectionSummary(devices: PanosDeviceSnapshot[]): JsonRecord {
  return {
    devices: devices.length,
    platforms: devices.map((item) => `${item.host}: ${item.platform}`),
    unreachable_hosts: devices.filter((item) => !item.reachable).map((item) => item.host),
    failed_xpaths: devices.flatMap((item) => item.failedXpaths.map((xpath) => `${item.host}: ${xpath}`)),
    ha_state_unreadable: devices.filter((item) => item.haStateFailed).map((item) => item.host),
    collection: Object.fromEntries(devices.map((item) => [item.host, panosCollectionStatus(item)])),
  };
}

/** CSPM and Compute collection status for assessment summaries; counts from failed surfaces render null. */
function prismaCollectionSummary(snapshot: PrismaSnapshot): JsonRecord {
  return {
    prisma_configured: true,
    compute_configured: Boolean(snapshot.compute),
    compute_console: snapshot.compute?.consoleUrl ?? null,
    cloud_accounts: nullUnless(prismaReadable(snapshot, "cloud accounts"), snapshot.cloudAccounts.length),
    open_alerts_sampled: nullUnless(prismaReadable(snapshot, "open alerts"), snapshot.alerts.length),
    open_alerts_truncated: nullUnless(prismaReadable(snapshot, "open alerts"), snapshot.alertsTruncated),
    open_alerts_truncation_reason: prismaReadable(snapshot, "open alerts") ? snapshot.alertsTruncationReason ?? null : null,
    unreadable_surfaces: [
      ...snapshot.failed.map((surface) => `prisma-cloud ${surface}`),
      ...(snapshot.compute?.failed ?? []).map((surface) => `prisma-compute ${surface}`),
    ],
    truncated_surfaces: (snapshot.compute?.truncated ?? []).map((surface) => `prisma-compute ${surface}`),
    compute_unavailable_reason: snapshot.compute ? null : snapshot.computeUnavailableReason ?? null,
    collection: {
      prisma_cloud: prismaCollectionStatus(snapshot),
      prisma_compute: snapshot.compute ? computeCollectionStatus(snapshot.compute) : computeUnavailableMarker(snapshot),
    },
  };
}

function assessmentResult(title: string, findings: PaloaltoFinding[], errors: string[], extra: JsonRecord = {}): PaloaltoAssessmentResult {
  return {
    title,
    summary: {
      controls: findings.length,
      pass: findings.filter((item) => item.status === "pass").length,
      warn: findings.filter((item) => item.status === "warn").length,
      fail: findings.filter((item) => item.status === "fail").length,
      manual: findings.filter((item) => item.status === "manual").length,
      collection_errors: errors.length,
      ...extra,
    },
    findings,
    errors,
  };
}

export async function assessPaloaltoCloudPosture(
  clients: PaloaltoClients,
  options: { alertLimit?: number; minCompliancePassRate?: number } = {},
  prismaSnapshot?: PrismaSnapshot,
): Promise<PaloaltoAssessmentResult> {
  if (!clients.prisma) {
    const findings = [
      prismaNotConfigured(1, "high", "export the Prisma Cloud Compliance dashboard posture for every enabled standard."),
      prismaNotConfigured(2, "high", "export the Alerts > Alert Rules list showing enabled rules, target account groups, and notification channels."),
      prismaNotConfigured(3, "high", "export IAM Security > Overly permissive identities findings."),
      prismaNotConfigured(4, "medium", "export Settings > Cloud Accounts with status and account group membership."),
      prismaNotConfigured(5, "high", "export open network exposure alerts (public resources, unrestricted security groups)."),
      prismaNotConfigured(6, "high", "export enabled encryption-at-rest policies and their open alerts."),
      ...assessPrismaCompute(undefined),
    ];
    return assessmentResult("Palo Alto cloud posture (Prisma Cloud)", findings, [], { prisma_configured: false, compute_configured: false });
  }
  const snapshot = prismaSnapshot ?? await loadPrismaSnapshot(clients, clampNumber(options.alertLimit, DEFAULT_ALERT_LIMIT, 1, 10000));
  if (!snapshot) throw new Error("Prisma Cloud snapshot could not be collected.");
  const findings = [...assessPrismaCloudPosture(snapshot, options), ...assessPrismaCompute(snapshot)];
  return assessmentResult("Palo Alto cloud posture (Prisma Cloud)", findings, snapshot.errors, prismaCollectionSummary(snapshot));
}

export async function assessPaloaltoFirewallPolicy(clients: PaloaltoClients, snapshots?: PanosDeviceSnapshot[]): Promise<PaloaltoAssessmentResult> {
  if (clients.panos.length === 0) {
    const findings = [
      panosNotConfigured(12, "critical", "export the security rulebase (Policies > Security) and highlight any/any allow rules and rules without log at session end."),
      panosNotConfigured(13, "high", "export Network > Zones with zone protection profiles and the intrazone/interzone default rule actions."),
      panosNotConfigured(14, "high", "export Policies > Decryption and Device > Certificate Management > SSL/TLS Service Profiles."),
    ];
    return assessmentResult("Palo Alto firewall policy (PAN-OS)", findings, [], { devices: 0 });
  }
  const devices = snapshots ?? await collectPanosSnapshots(clients);
  return assessmentResult("Palo Alto firewall policy (PAN-OS)", assessPanosFirewallPolicy(devices), devices.flatMap((item) => item.errors), panosCollectionSummary(devices));
}

export async function assessPaloaltoThreatPrevention(clients: PaloaltoClients, snapshots?: PanosDeviceSnapshot[], prismaSnapshot?: PrismaSnapshot): Promise<PaloaltoAssessmentResult> {
  const prisma = clients.prisma ? (prismaSnapshot ?? await loadPrismaSnapshot(clients)) : undefined;
  if (clients.panos.length === 0) {
    const findings = [
      panosNotConfigured(16, "critical", "export Objects > Security Profiles (Antivirus, Anti-Spyware, Vulnerability Protection) and the rules they are attached to."),
      panosNotConfigured(17, "high", "export Objects > Security Profiles > WildFire Analysis and the output of 'show wildfire status'."),
      panosNotConfigured(18, "high", "export Objects > Security Profiles > URL Filtering showing blocked categories and credential phishing settings."),
      assessDataLossPrevention(prisma, []),
      panosNotConfigured(22, "medium", "export Objects > Security Profiles > File Blocking showing blocked file types per rule."),
    ];
    return assessmentResult("Palo Alto threat prevention (PAN-OS)", findings, prisma?.errors ?? [], { devices: 0 });
  }
  const devices = snapshots ?? await collectPanosSnapshots(clients);
  const findings = [...assessPanosThreatPrevention(devices)];
  findings.splice(3, 0, assessDataLossPrevention(prisma, devices));
  return assessmentResult("Palo Alto threat prevention (PAN-OS)", findings, [...devices.flatMap((item) => item.errors), ...(prisma?.errors ?? [])], {
    ...panosCollectionSummary(devices),
    prisma_configured: Boolean(prisma),
    prisma_unreadable_surfaces: prisma ? prisma.failed.map((surface) => `prisma-cloud ${surface}`) : null,
  });
}

export async function assessPaloaltoDeviceHardening(
  clients: PaloaltoClients,
  options: { maxSuperusers?: number } = {},
  snapshots?: PanosDeviceSnapshot[],
  prismaSnapshot?: PrismaSnapshot,
): Promise<PaloaltoAssessmentResult> {
  const prisma = clients.prisma ? (prismaSnapshot ?? await loadPrismaSnapshot(clients)) : undefined;
  const devices = clients.panos.length > 0 ? (snapshots ?? await collectPanosSnapshots(clients)) : [];
  const findings: PaloaltoFinding[] = [];
  if (devices.length === 0) {
    findings.push(panosNotConfigured(15, "high", "export Network > GlobalProtect portal and gateway configuration including authentication profiles, MFA, HIP profiles, and split tunnel settings."));
  }
  findings.push(assessAdminAccess(prisma, devices, options));
  findings.push(assessLogging(prisma, devices));
  if (devices.length === 0) {
    findings.push(panosNotConfigured(23, "medium", "export Device > Setup > Management and Services (NTP, DNS, login banner, idle timeout, permitted IPs, SNMP community strings)."));
  } else {
    const hardening = assessPanosDeviceHardening(devices);
    findings.unshift(hardening[0]);
    findings.push(...hardening.slice(1));
  }
  return assessmentResult("Palo Alto device hardening and access", findings, [...devices.flatMap((item) => item.errors), ...(prisma?.errors ?? [])], {
    ...panosCollectionSummary(devices),
    prisma_configured: Boolean(prisma),
    prisma_unreadable_surfaces: prisma ? prisma.failed.map((surface) => `prisma-cloud ${surface}`) : null,
  });
}

function formatAccessCheckText(result: PaloaltoAccessCheckResult): string {
  const rows = result.surfaces.map((surface) => [
    surface.product,
    surface.target.replace(/^https?:\/\//, "").slice(0, 32),
    surface.name,
    surface.status,
    surface.count === null ? "-" : `${surface.count}${surface.partial ? "+" : ""}`,
    surface.httpStatus === null ? "-" : String(surface.httpStatus),
    surface.error ? redactErrorText(surface.error).replace(/\s+/g, " ").slice(0, 80) : "",
  ]);
  return [
    `Palo Alto access check: ${result.status}`,
    "",
    ...result.notes,
    "",
    formatTable(["Product", "Target", "Surface", "Status", "Count", "HTTP", "Note"], rows),
    "",
    `Next: ${result.recommendedNextStep}`,
  ].join("\n");
}

/** One line per surface that was not read: "<group> <surface>: <dataset status> <HTTP status or no response> (<request>)"; "all surfaces read" otherwise. */
function describeCollectionBlock(block: unknown): string {
  const notRead: string[] = [];
  const walk = (value: unknown, path: string[]) => {
    const record = asObject(value);
    if (!record) return;
    if (record.collected === false || (typeof record.status === "string" && record.status !== "ok" && "http_status" in record)) {
      const http = asNumber(record.http_status ?? record.status);
      const endpoint = asString(record.endpoint);
      const datasetStatus = asString(record.dataset_status) ?? asString(record.status) ?? "not read";
      notRead.push(`${path.join(" ")}: ${datasetStatus} ${http === undefined ? "no response" : `HTTP ${http}`}${endpoint ? ` (${endpoint})` : ""}`);
      return;
    }
    for (const [key, child] of Object.entries(record)) walk(child, [...path, key]);
  };
  walk(block, []);
  return notRead.length === 0 ? "all surfaces read" : notRead.join("; ");
}

function formatAssessmentText(result: PaloaltoAssessmentResult): string {
  const rows = result.findings.map((item) => [
    item.id,
    item.severity.toUpperCase(),
    item.status.toUpperCase(),
    item.title,
    item.summary.length > 160 ? `${item.summary.slice(0, 157)}...` : item.summary,
  ]);
  // The per-surface collection block is structured data for the JSON result and
  // the bundle; the text rendering names only the surfaces that were not read.
  const summary = Object.entries(result.summary)
    .map(([key, value]) => `- ${key}: ${Array.isArray(value) ? value.join(", ") : key === "collection" ? describeCollectionBlock(value) : String(value)}`)
    .join("\n");
  return [
    result.title,
    "",
    "Summary:",
    summary,
    "",
    formatTable(["Control", "Severity", "Status", "Title", "Summary"], rows),
    ...(result.errors.length > 0 ? ["", "Collection errors:", ...result.errors.map((item) => `- ${item}`)] : []),
  ].join("\n");
}

function buildExecutiveSummary(config: PaloaltoResolvedConfig, assessments: PaloaltoAssessmentResult[]): string {
  const findings = assessments.flatMap((assessment) => assessment.findings);
  const count = (status: PaloaltoStatus) => findings.filter((item) => item.status === status).length;
  return [
    "# Palo Alto Networks Audit Bundle: Executive Summary",
    "",
    `Generated: ${new Date().toISOString()}`,
    `Prisma Cloud: ${config.prisma ? config.prisma.apiUrl : "not configured"}`,
    `PAN-OS devices: ${config.panos.length > 0 ? config.panos.map((item) => item.host).join(", ") : "not configured"}`,
    "",
    "## Result Counts",
    "",
    `- Failed controls: ${count("fail")}`,
    `- Warning controls: ${count("warn")}`,
    `- Passing controls: ${count("pass")}`,
    `- Manual evidence controls: ${count("manual")}`,
    "",
    "## Highest Priority Findings",
    "",
    ...findings
      .filter((item) => item.status === "fail" || item.status === "warn")
      .sort((a, b) => (a.status === b.status ? 0 : a.status === "fail" ? -1 : 1))
      .slice(0, 12)
      .map((item) => `- ${item.id} (${item.severity.toUpperCase()} / ${item.status.toUpperCase()}): ${item.summary}`),
    "",
    "## Manual Evidence Required",
    "",
    ...findings.filter((item) => item.status === "manual").map((item) => `- ${item.id} ${item.title}: ${item.summary}`),
  ].join("\n");
}

const PRIMARY_FINDING_ID = /^PA-\d\d$/;

export function isPrimaryFinding(item: PaloaltoFinding): boolean {
  return PRIMARY_FINDING_ID.test(item.id);
}

function matrixRow(item: PaloaltoFinding): string[] {
  return [
    item.id,
    String(item.control),
    item.status.toUpperCase(),
    ...FRAMEWORK_ORDER.map((framework) =>
      item.mappings.filter((mapping) => mapping.startsWith(`${framework} `)).map((mapping) => mapping.slice(framework.length + 1)).join(", ") || "-"),
  ];
}

export function buildComplianceMatrix(findings: PaloaltoFinding[]): string {
  const primary = new Map<number, PaloaltoFinding>();
  for (const item of findings) {
    if (isPrimaryFinding(item) && !primary.has(item.control)) primary.set(item.control, item);
  }
  const primaryRows = [...primary.values()].sort((a, b) => a.control - b.control).map(matrixRow);
  const supplementary = findings.filter((item) => !isPrimaryFinding(item));
  const header = [
    `| Finding | Control | Status | ${FRAMEWORK_ORDER.join(" | ")} |`,
    `|${"---|".repeat(FRAMEWORK_ORDER.length + 3)}`,
  ];
  return [
    "# Unified Compliance Matrix",
    "",
    `One row per numbered spec control (${primaryRows.length} of ${PALOALTO_CONTROLS.length}).`,
    "",
    ...header,
    ...primaryRows.map((row) => `| ${row.join(" | ")} |`),
    "",
    "## Supplementary findings",
    "",
    "Additional evidence rows that share a numbered control and are excluded from the per-control matrix above.",
    "",
    ...header,
    ...supplementary.map((item) => `| ${matrixRow(item).join(" | ")} |`),
  ].join("\n");
}

function buildFrameworkReport(framework: PaloaltoFramework, findings: PaloaltoFinding[]): string {
  const relevant = findings.filter((item) => item.mappings.some((mapping) => mapping.startsWith(`${framework} `)));
  return [
    `# ${framework} Report`,
    "",
    `${relevant.length} findings map to ${framework} requirements.`,
    "",
    "| Finding | Title | Status | Severity | Requirements | Summary |",
    "|---|---|---|---|---|---|",
    ...relevant.map((item) => {
      const references = item.mappings.filter((mapping) => mapping.startsWith(`${framework} `)).map((mapping) => mapping.slice(framework.length + 1)).join(", ");
      return `| ${item.id} | ${item.title} | ${item.status.toUpperCase()} | ${item.severity} | ${references} | ${item.summary.replace(/\|/g, "/")} |`;
    }),
  ].join("\n");
}

function buildQuickReference(result: PaloaltoAccessCheckResult, assessments: PaloaltoAssessmentResult[]): string {
  return [
    "# Quick Reference",
    "",
    `Access status: ${result.status} (${result.products.join(", ") || "no products configured"})`,
    "",
    "## Layout",
    "",
    `- \`core_data/\`: redacted API snapshots (Prisma Cloud and Compute JSON with credential-named properties replaced by ${REDACTION_MARKER}, PAN-OS system info and configuration as JSON with credential-bearing nodes replaced by ${REDACTION_MARKER})`,
    "- `analysis/findings.json`: normalized findings with framework mappings; evidence derived from a surface that could not be read renders null, never 0 or an empty list",
    "- `analysis/<area>.json`: per-assessment summaries with the collection status (unreadable surfaces, truncated collections, unreachable hosts, failed subtrees)",
    "- `compliance/executive_summary.md`, `compliance/unified_compliance_matrix.md`, one report per framework",
    "- `_errors.log`: present only when collection partially failed; error strings carry the HTTP status and the vendor's documented error fields only, and non-JSON or non-XML bodies are summarized as a status-and-length note that is never echoed",
    "",
    "## Assessments",
    "",
    ...assessments.map((item) => `- ${item.title}: ${item.summary.pass} pass, ${item.summary.warn} warn, ${item.summary.fail} fail, ${item.summary.manual} manual`),
    "",
    "Credentials, API keys, and JWTs are never written into the bundle.",
    `Prisma Cloud integration configurations (auth tokens, API keys, passwords, secure header values, webhook URLs with tokens) and Compute registry credentials and image secrets are replaced with ${REDACTION_MARKER} as they are collected.`,
    `PAN-OS configuration nodes that carry password hashes, shared secrets, keys, passphrases, tokens, or SNMP community strings are replaced with ${REDACTION_MARKER} before core_data/ is written.`,
    "Verdicts: a finding whose evidence could not be read is manual, and a finding whose inventory was truncated (page cap, empty page with a cursor, repeated cursor, or a totalRows count larger than what was read) is capped at warn.",
  ].join("\n");
}

export async function exportPaloaltoAuditBundle(
  clients: PaloaltoClients,
  outputRoot: string,
  options: { alertLimit?: number; minCompliancePassRate?: number; maxSuperusers?: number } = {},
): Promise<PaloaltoAuditBundleResult> {
  const config = clients.config;
  const access = await checkPaloaltoAccess(clients);
  const prismaSnapshot = await loadPrismaSnapshot(clients, clampNumber(options.alertLimit, DEFAULT_ALERT_LIMIT, 1, 10000));
  const deviceSnapshots = await collectPanosSnapshots(clients);
  const assessments = [
    await assessPaloaltoCloudPosture(clients, options, prismaSnapshot),
    await assessPaloaltoFirewallPolicy(clients, deviceSnapshots),
    await assessPaloaltoThreatPrevention(clients, deviceSnapshots, prismaSnapshot),
    await assessPaloaltoDeviceHardening(clients, options, deviceSnapshots, prismaSnapshot),
  ];
  const findings = assessments.flatMap((assessment) => assessment.findings);
  const errors = [...new Set([...(prismaSnapshot?.errors ?? []), ...deviceSnapshots.flatMap((item) => item.errors)])];

  ensurePrivateDir(outputRoot);
  const label = safeDirName(config.prisma ? new URL(config.prisma.apiUrl).hostname : config.panos[0]?.host ?? "paloalto");
  const outputDir = await nextAvailableAuditDir(outputRoot, `${label}-audit-bundle`);
  // Collected after the reads so the key PAN-OS keygen returned is included.
  const secrets = configuredSecrets(clients);
  const write = (relativePathname: string, content: string) => writeSecureTextFile(outputDir, relativePathname, content, secrets);
  const writeJson = (relativePathname: string, value: unknown) => writeSecureJsonFile(outputDir, relativePathname, value, secrets);

  await write("QUICK_REFERENCE.md", `${buildQuickReference(access, assessments)}\n`);
  await writeJson("metadata.json", {
    generated_at: new Date().toISOString(),
    prisma_api_url: config.prisma?.apiUrl ?? null,
    prisma_compute_url: prismaSnapshot?.compute?.consoleUrl ?? null,
    panos_hosts: config.panos.map((item) => item.host),
    tls_verification: config.verifyTls,
    tls_verification_scope: config.verifyTls ? "all requests" : "disabled for PAN-OS requests only",
    source_chain: config.sourceChain,
  });
  await writeJson("core_data/access.json", access);
  if (prismaSnapshot) {
    await writeJson("core_data/prisma_cloud.json", prismaSnapshotToJson(prismaSnapshot));
  }
  for (const snapshot of deviceSnapshots) {
    await writeJson(`core_data/panos_${safeDirName(snapshot.host)}.json`, panosSnapshotToJson(snapshot));
  }
  await writeJson("analysis/findings.json", findings);
  const analysisNames = ["cloud_posture", "firewall_policy", "threat_prevention", "device_hardening"];
  for (const [index, assessment] of assessments.entries()) {
    await writeJson(`analysis/${analysisNames[index]}.json`, assessment);
  }
  await write("compliance/executive_summary.md", `${buildExecutiveSummary(config, assessments)}\n`);
  await write("compliance/unified_compliance_matrix.md", `${buildComplianceMatrix(findings)}\n`);
  for (const framework of FRAMEWORK_ORDER) {
    await write(`compliance/${FRAMEWORK_FILES[framework]}`, `${buildFrameworkReport(framework, findings)}\n`);
  }
  if (errors.length > 0) {
    await write("_errors.log", `${errors.join("\n")}\n`);
  }

  const zipPath = resolveSecureOutputPath(outputRoot, `${basename(outputDir)}.zip`);
  await createZipArchive(outputDir, zipPath);
  return {
    outputDir,
    zipPath,
    fileCount: await countFilesRecursively(outputDir),
    findingCount: findings.length,
    errorCount: errors.length,
  };
}

function normalizeAuthArgs(args: unknown): AuthArgs {
  const value = asObject(args) ?? {};
  return {
    prisma_api_url: asString(value.prisma_api_url),
    prisma_access_key_id: asString(value.prisma_access_key_id),
    prisma_secret_key: asString(value.prisma_secret_key),
    panos_hosts: asString(value.panos_hosts) ?? asString(value.panos_host),
    panos_api_key: asString(value.panos_api_key),
    panos_username: asString(value.panos_username),
    panos_password: asString(value.panos_password),
    config_file: asString(value.config_file),
    verify_tls: typeof value.verify_tls === "boolean" ? value.verify_tls : undefined,
    timeout_seconds: asNumber(value.timeout_seconds),
  };
}

function normalizeCloudPostureArgs(args: unknown): CloudPostureArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeAuthArgs(args),
    alert_limit: asNumber(value.alert_limit),
    min_compliance_pass_rate: asNumber(value.min_compliance_pass_rate),
  };
}

function normalizeDeviceHardeningArgs(args: unknown): DeviceHardeningArgs {
  const value = asObject(args) ?? {};
  return { ...normalizeAuthArgs(args), max_superusers: asNumber(value.max_superusers) };
}

function normalizeExportArgs(args: unknown): ExportAuditBundleArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeCloudPostureArgs(args),
    max_superusers: asNumber(value.max_superusers),
    output_dir: asString(value.output_dir) ?? asString(value.output),
  };
}

function createClients(args: AuthArgs): PaloaltoClients {
  return createPaloaltoClients(resolvePaloaltoConfiguration(args as JsonRecord));
}

const authParams = {
  prisma_api_url: Type.Optional(Type.String({ description: "Prisma Cloud API URL for the tenant region (for example https://api2.prismacloud.io). Defaults to PRISMA_API_URL." })),
  prisma_access_key_id: Type.Optional(Type.String({ description: "Prisma Cloud access key ID. Defaults to PRISMA_ACCESS_KEY_ID." })),
  prisma_secret_key: Type.Optional(Type.String({ description: "Prisma Cloud secret key. Defaults to PRISMA_SECRET_KEY." })),
  panos_hosts: Type.Optional(Type.String({ description: "Comma-separated PAN-OS firewall or Panorama hostnames or IPs. Defaults to PANOS_HOST." })),
  panos_api_key: Type.Optional(Type.String({ description: "Pre-generated PAN-OS API key. Defaults to PANOS_API_KEY." })),
  panos_username: Type.Optional(Type.String({ description: "PAN-OS admin username for type=keygen. Defaults to PANOS_USERNAME." })),
  panos_password: Type.Optional(Type.String({ description: "PAN-OS admin password for type=keygen. Defaults to PANOS_PASSWORD." })),
  config_file: Type.Optional(Type.String({ description: "JSON config file with the same keys as the environment variables. Defaults to PALOALTO_CONFIG_FILE or ~/.grclanker/paloalto.json." })),
  verify_tls: Type.Optional(Type.Boolean({ description: "Verify device TLS certificates. Defaults to true; set false only for lab devices with self-signed certificates (PANOS_VERIFY_TLS).", default: true })),
  timeout_seconds: Type.Optional(Type.Number({ description: "HTTP timeout in seconds. Defaults to 30.", default: 30 })),
};

type ToolResult = ReturnType<typeof textResult> & { isError?: boolean };

function toolError(tool: string, label: string, error: unknown): ToolResult {
  return errorResult(`${label} failed: ${errorMessage(error)}`, { tool });
}

/** Credentials passed as arguments or present in the environment, known before the clients exist. */
function argumentSecrets(args: AuthArgs): string[] {
  return [
    args.prisma_access_key_id,
    args.prisma_secret_key,
    args.panos_api_key,
    args.panos_password,
    process.env.PRISMA_ACCESS_KEY_ID,
    process.env.PRISMA_SECRET_KEY,
    process.env.PANOS_API_KEY,
    process.env.PANOS_PASSWORD,
  ].filter((value): value is string => typeof value === "string");
}

/**
 * Runs one tool and removes every configured secret from the whole result (guard 2):
 * the text rendering and the structured details alike, whether the run succeeded or
 * the catch block rendered the error. The secrets are gathered after the run so the
 * key PAN-OS keygen returned is included.
 */
async function runSealed(tool: string, label: string, args: AuthArgs, run: (clients: PaloaltoClients) => Promise<ToolResult>): Promise<ToolResult> {
  const secrets = new Set<string>(argumentSecrets(args));
  let clients: PaloaltoClients | undefined;
  try {
    clients = createClients(args);
    const result = await run(clients);
    for (const secret of configuredSecrets(clients)) secrets.add(secret);
    return sealValue(result, [...secrets]);
  } catch (error) {
    for (const secret of clients ? configuredSecrets(clients) : []) secrets.add(secret);
    return sealValue(toolError(tool, label, error), [...secrets]);
  }
}

export function registerPaloaltoTools(pi: any): void {
  pi.registerTool({
    name: "paloalto_check_access",
    label: "Check Palo Alto audit access",
    description:
      "Validate read-only access to Prisma Cloud CSPM (compliance posture, alert rules, alerts, policies, cloud accounts, roles, integrations) and PAN-OS firewalls or Panorama (system info, HA state, configuration subtrees) and report which surfaces are missing permissions.",
    parameters: Type.Object(authParams),
    prepareArguments: normalizeAuthArgs,
    async execute(_toolCallId: string, args: AuthArgs) {
      return runSealed("paloalto_check_access", "Palo Alto access check", args, async (clients) => {
        const result = await checkPaloaltoAccess(clients);
        return textResult(formatAccessCheckText(result), { tool: "paloalto_check_access", ...result });
      });
    },
  });

  pi.registerTool({
    name: "paloalto_assess_cloud_posture",
    label: "Assess Prisma Cloud posture",
    description:
      "Assess Prisma Cloud CSPM posture: compliance pass rate, alert rule coverage, IAM overprivilege alerts, cloud account governance, network exposure alerts, and encryption-at-rest policies (spec controls 1-6), with manual evidence findings for the Compute controls 7-11, 24, and 25.",
    parameters: Type.Object({
      ...authParams,
      alert_limit: Type.Optional(Type.Number({ description: "Maximum open alerts to sample from the last 30 days. Defaults to 500.", default: 500 })),
      min_compliance_pass_rate: Type.Optional(Type.Number({ description: "Minimum compliance pass rate percentage before warning. Defaults to 90.", default: 90 })),
    }),
    prepareArguments: normalizeCloudPostureArgs,
    async execute(_toolCallId: string, args: CloudPostureArgs) {
      return runSealed("paloalto_assess_cloud_posture", "Palo Alto cloud posture assessment", args, async (clients) => {
        const result = await assessPaloaltoCloudPosture(clients, {
          alertLimit: args.alert_limit,
          minCompliancePassRate: args.min_compliance_pass_rate,
        });
        return textResult(formatAssessmentText(result), { tool: "paloalto_assess_cloud_posture", ...result });
      });
    },
  });

  pi.registerTool({
    name: "paloalto_assess_firewall_policy",
    label: "Assess PAN-OS firewall policy",
    description:
      "Assess PAN-OS firewall or Panorama security policy hygiene: any/any and shadowed rules, missing session-end logging, zone segmentation and zone protection, default rule actions, and SSL/TLS decryption coverage (spec controls 12-14).",
    parameters: Type.Object(authParams),
    prepareArguments: normalizeAuthArgs,
    async execute(_toolCallId: string, args: AuthArgs) {
      return runSealed("paloalto_assess_firewall_policy", "Palo Alto firewall policy assessment", args, async (clients) => {
        const result = await assessPaloaltoFirewallPolicy(clients);
        return textResult(formatAssessmentText(result), { tool: "paloalto_assess_firewall_policy", ...result });
      });
    },
  });

  pi.registerTool({
    name: "paloalto_assess_threat_prevention",
    label: "Assess PAN-OS threat prevention",
    description:
      "Assess PAN-OS threat prevention profiles (antivirus, anti-spyware, vulnerability protection), WildFire analysis, URL filtering and credential phishing protection, data loss prevention across Prisma Cloud and PAN-OS, and file blocking (spec controls 16-18, 21, 22).",
    parameters: Type.Object(authParams),
    prepareArguments: normalizeAuthArgs,
    async execute(_toolCallId: string, args: AuthArgs) {
      return runSealed("paloalto_assess_threat_prevention", "Palo Alto threat prevention assessment", args, async (clients) => {
        const result = await assessPaloaltoThreatPrevention(clients);
        return textResult(formatAssessmentText(result), { tool: "paloalto_assess_threat_prevention", ...result });
      });
    },
  });

  pi.registerTool({
    name: "paloalto_assess_device_hardening",
    label: "Assess PAN-OS device hardening and access",
    description:
      "Assess GlobalProtect configuration, admin roles and password complexity across PAN-OS and Prisma Cloud, logging and SIEM forwarding, system hardening (NTP, DNS, banner, idle timeout, SNMP, management services), HA state, and software versions (spec controls 15, 19, 20, 23).",
    parameters: Type.Object({
      ...authParams,
      max_superusers: Type.Optional(Type.Number({ description: "Maximum acceptable superuser or System Admin accounts before failing. Defaults to 3.", default: 3 })),
    }),
    prepareArguments: normalizeDeviceHardeningArgs,
    async execute(_toolCallId: string, args: DeviceHardeningArgs) {
      return runSealed("paloalto_assess_device_hardening", "Palo Alto device hardening assessment", args, async (clients) => {
        const result = await assessPaloaltoDeviceHardening(clients, { maxSuperusers: args.max_superusers });
        return textResult(formatAssessmentText(result), { tool: "paloalto_assess_device_hardening", ...result });
      });
    },
  });

  pi.registerTool({
    name: "paloalto_export_audit_bundle",
    label: "Export Palo Alto audit bundle",
    description:
      "Export a Palo Alto Networks audit bundle with redacted Prisma Cloud and PAN-OS snapshots (core_data/, credential-bearing values replaced with [REDACTED]), normalized findings (analysis/), executive summary, unified compliance matrix and per-framework reports (compliance/), QUICK_REFERENCE.md, an _errors.log when collection partially failed, and a zip archive.",
    parameters: Type.Object({
      ...authParams,
      output_dir: Type.Optional(Type.String({ description: `Output root. Defaults to ${DEFAULT_OUTPUT_DIR}.` })),
      alert_limit: Type.Optional(Type.Number({ description: "Maximum open alerts to sample. Defaults to 500.", default: 500 })),
      min_compliance_pass_rate: Type.Optional(Type.Number({ description: "Minimum compliance pass rate percentage before warning. Defaults to 90.", default: 90 })),
      max_superusers: Type.Optional(Type.Number({ description: "Maximum acceptable superuser accounts before failing. Defaults to 3.", default: 3 })),
    }),
    prepareArguments: normalizeExportArgs,
    async execute(_toolCallId: string, args: ExportAuditBundleArgs) {
      return runSealed("paloalto_export_audit_bundle", "Palo Alto audit bundle export", args, async (clients) => {
        const outputRoot = resolve(process.cwd(), args.output_dir?.trim() || DEFAULT_OUTPUT_DIR);
        const result = await exportPaloaltoAuditBundle(clients, outputRoot, {
          alertLimit: args.alert_limit,
          minCompliancePassRate: args.min_compliance_pass_rate,
          maxSuperusers: args.max_superusers,
        });
        return textResult(
          [
            "Palo Alto audit bundle exported.",
            `Output dir: ${result.outputDir}`,
            `Zip archive: ${result.zipPath}`,
            `Findings: ${result.findingCount}`,
            `Files: ${result.fileCount}`,
            `Collection errors: ${result.errorCount}`,
          ].join("\n"),
          {
            tool: "paloalto_export_audit_bundle",
            output_dir: result.outputDir,
            zip_path: result.zipPath,
            finding_count: result.findingCount,
            file_count: result.fileCount,
            error_count: result.errorCount,
          },
        );
      });
    },
  });
}
