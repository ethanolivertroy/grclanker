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
  endpoint: string;
  status: "readable" | "not_readable" | "not_configured";
  count?: number;
  error?: string;
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
  failedXpaths: string[];
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
  vulnerabilityStats: JsonRecord;
  complianceStats: JsonRecord;
  cloudDiscovery: JsonRecord[];
  ciScans: JsonRecord[];
  failed: string[];
  truncated: string[];
  errors: string[];
}

export interface PrismaSnapshot {
  posture?: JsonRecord;
  alertRules: JsonRecord[];
  alerts: JsonRecord[];
  alertsTruncated: boolean;
  alertsTotal?: number;
  policies: JsonRecord[];
  cloudAccounts: JsonRecord[];
  accountGroups: JsonRecord[];
  userRoles: JsonRecord[];
  integrations: JsonRecord[];
  failed: string[];
  compute?: ComputeSnapshot;
  computeUnavailableReason?: string;
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

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
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

export function redactSecrets(message: string, secrets: Array<string | undefined>): string {
  let output = message.replace(/([?&](?:key|password|secret|token)=)[^&\s"']+/gi, "$1[redacted]");
  for (const secret of secrets) {
    if (!secret || secret.length < 4) continue;
    output = output.split(secret).join("[redacted]");
  }
  return output;
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

function readConfigFile(pathname: string | undefined): JsonRecord {
  const candidate = pathname ?? DEFAULT_CONFIG_FILE;
  if (!existsSync(candidate)) {
    if (pathname) throw new Error(`Palo Alto config file not found: ${pathname}`);
    return {};
  }
  try {
    return asObject(JSON.parse(readFileSync(candidate, "utf8"))) ?? {};
  } catch (error) {
    throw new Error(`Unable to parse Palo Alto config file ${candidate}: ${errorMessage(error)}`);
  }
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

async function fetchWithRetry(url: string, init: RequestInit, options: HttpOptions): Promise<Response> {
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
      throw new Error(redactSecrets(`Request to ${url} failed: ${errorMessage(error)}`, options.secrets));
    } finally {
      clearTimeout(timeout);
    }
  }
}

function prismaErrorSummary(response: Response, rawText: string): string {
  const header = response.headers.get("x-redlock-status");
  const parsed = (() => {
    try {
      return JSON.parse(rawText) as unknown;
    } catch {
      return undefined;
    }
  })();
  const detail = asString(asObject(parsed)?.message)
    ?? asRecords(parsed).map((item) => asString(item.i18nKey) ?? asString(item.message)).filter(Boolean).join("; ")
    ?? undefined;
  return header ?? detail ?? rawText.slice(0, 200);
}

export class PrismaCloudClient {
  private readonly config: PaloaltoPrismaConfig;
  private readonly http: HttpOptions;
  private token?: string;
  private tokenExpiresAt = 0;
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

  private async login(): Promise<string> {
    const response = await fetchWithRetry(`${this.config.apiUrl}/login`, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json; charset=UTF-8" },
      body: JSON.stringify({ username: this.config.accessKeyId, password: this.config.secretKey }),
    }, this.http);
    const rawText = await response.text();
    if (!response.ok) {
      throw new Error(redactSecrets(`Prisma Cloud login failed (${response.status}): ${prismaErrorSummary(response, rawText)}`, this.http.secrets));
    }
    const token = asString(asObject(JSON.parse(rawText))?.token);
    if (!token) throw new Error("Prisma Cloud login response did not include a token.");
    this.token = token;
    this.tokenExpiresAt = Date.now() + PRISMA_TOKEN_TTL_MS;
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
    const url = new URL(`${this.config.apiUrl}${path.startsWith("/") ? path : `/${path}`}`);
    for (const [key, value] of Object.entries(query)) {
      if (value === undefined || value === null || value === "") continue;
      url.searchParams.set(key, String(value));
    }
    const response = await fetchWithRetry(url.toString(), {
      method,
      headers: {
        accept: "application/json; charset=UTF-8",
        "content-type": "application/json",
        "x-redlock-auth": await this.getToken(),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    }, this.http);
    const rawText = await response.text();
    if (response.status === 401 && retryAuth) {
      this.token = undefined;
      return this.request(method, path, query, body, false);
    }
    if (!response.ok) {
      throw new Error(redactSecrets(`Prisma Cloud ${method} ${path} failed (${response.status}): ${prismaErrorSummary(response, rawText)}`, this.http.secrets));
    }
    return rawText.length > 0 ? JSON.parse(rawText) as unknown : {};
  }

  async get(path: string, query: JsonRecord = {}): Promise<unknown> {
    return this.request("GET", path, query);
  }

  async getCompliancePosture(): Promise<JsonRecord> {
    return asObject(await this.get("/v2/compliance/posture")) ?? {};
  }

  async listAlertRules(): Promise<JsonRecord[]> {
    return asRecords(await this.get("/v2/alert/rule"));
  }

  async collectOpenAlerts(limit = DEFAULT_ALERT_LIMIT): Promise<{ items: JsonRecord[]; truncated: boolean; totalRows?: number }> {
    const items: JsonRecord[] = [];
    let pageToken: string | undefined;
    let totalRows: number | undefined;
    let truncated = false;
    for (;;) {
      const payload = asObject(await this.get("/v2/alert", {
        "alert.status": "open",
        timeType: "relative",
        timeAmount: "30",
        timeUnit: "day",
        detailed: "true",
        limit: Math.min(DEFAULT_ALERT_PAGE_SIZE, Math.max(limit - items.length, 1)),
        pageToken,
      })) ?? {};
      const pageItems = asRecords(payload.items);
      totalRows = asNumber(payload.totalRows) ?? totalRows;
      items.push(...pageItems.slice(0, Math.max(limit - items.length, 0)));
      pageToken = asString(payload.nextPageToken);
      if (!pageToken || pageItems.length === 0) break;
      if (items.length >= limit) {
        truncated = true;
        break;
      }
    }
    return { items, truncated, totalRows };
  }

  async listOpenAlerts(limit = DEFAULT_ALERT_LIMIT): Promise<JsonRecord[]> {
    return (await this.collectOpenAlerts(limit)).items;
  }

  async getMetaInfo(): Promise<JsonRecord> {
    return asObject(await this.get("/meta_info")) ?? {};
  }

  async listPolicies(): Promise<JsonRecord[]> {
    return asRecords(await this.get("/v2/policy"));
  }

  async listCloudAccounts(): Promise<JsonRecord[]> {
    return asRecords(await this.get("/cloud"));
  }

  async listAccountGroups(): Promise<JsonRecord[]> {
    return asRecords(await this.get("/cloud/group"));
  }

  async listUserRoles(): Promise<JsonRecord[]> {
    return asRecords(await this.get("/user/role"));
  }

  async listIntegrations(): Promise<JsonRecord[]> {
    return asRecords(await this.get("/integration"));
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
    }, this.http);
    const rawText = await response.text();
    const token = response.ok ? asString(asObject(safeJsonParse(rawText))?.token) : undefined;
    if (!token) {
      this.useRedlockHeader = true;
      return { "x-redlock-auth": await this.cspm.getToken() };
    }
    this.bearer = token;
    this.bearerExpiresAt = Date.now() + PRISMA_TOKEN_TTL_MS;
    return { authorization: `Bearer ${token}` };
  }

  async get(path: string, query: JsonRecord = {}): Promise<unknown> {
    const url = new URL(`${this.consoleUrl}/api/v1${path.startsWith("/") ? path : `/${path}`}`);
    for (const [key, value] of Object.entries(query)) {
      if (value === undefined || value === null || value === "") continue;
      url.searchParams.set(key, String(value));
    }
    const response = await fetchWithRetry(url.toString(), {
      method: "GET",
      headers: { accept: "application/json", ...(await this.authHeaders()) },
    }, this.http);
    const rawText = await response.text();
    if (!response.ok) {
      throw new Error(redactSecrets(`Prisma Cloud Compute GET ${path} failed (${response.status}): ${prismaErrorSummary(response, rawText)}`, this.http.secrets));
    }
    return rawText.length > 0 ? safeJsonParse(rawText) : {};
  }

  async listPaged(path: string, limit: number): Promise<{ items: JsonRecord[]; truncated: boolean }> {
    const items: JsonRecord[] = [];
    let offset = 0;
    for (;;) {
      const page = asRecords(await this.get(path, { limit: DEFAULT_COMPUTE_PAGE_SIZE, offset }));
      items.push(...page);
      if (page.length < DEFAULT_COMPUTE_PAGE_SIZE) return { items, truncated: false };
      offset += page.length;
      if (items.length >= limit) return { items, truncated: true };
    }
  }

  async getVersion(): Promise<string> {
    const payload = await this.get("/version");
    return asString(payload) ?? asString(asObject(payload)?.version) ?? "unknown";
  }

  async listDefenders(limit = DEFAULT_COMPUTE_LIMIT): Promise<{ items: JsonRecord[]; truncated: boolean }> {
    return this.listPaged("/defenders", limit);
  }

  async getRuntimeContainerPolicy(): Promise<JsonRecord> {
    return asObject(await this.get("/policies/runtime/container")) ?? {};
  }

  async getComplianceContainerPolicy(): Promise<JsonRecord> {
    return asObject(await this.get("/policies/compliance/container")) ?? {};
  }

  async getComplianceHostPolicy(): Promise<JsonRecord> {
    return asObject(await this.get("/policies/compliance/host")) ?? {};
  }

  async getVulnerabilityImagePolicy(): Promise<JsonRecord> {
    return asObject(await this.get("/policies/vulnerability/images")) ?? {};
  }

  async getRegistrySettings(): Promise<JsonRecord> {
    return asObject(await this.get("/settings/registry")) ?? {};
  }

  async listRegistryScans(limit = DEFAULT_COMPUTE_LIMIT): Promise<{ items: JsonRecord[]; truncated: boolean }> {
    return this.listPaged("/registry", limit);
  }

  async listImages(limit = DEFAULT_COMPUTE_LIMIT): Promise<{ items: JsonRecord[]; truncated: boolean }> {
    return this.listPaged("/images", limit);
  }

  async getVulnerabilityStats(): Promise<JsonRecord> {
    return asObject(await this.get("/stats/vulnerabilities")) ?? {};
  }

  async getComplianceStats(): Promise<JsonRecord> {
    return asObject(await this.get("/stats/compliance")) ?? {};
  }

  async listCloudDiscovery(limit = DEFAULT_COMPUTE_LIMIT): Promise<{ items: JsonRecord[]; truncated: boolean }> {
    return this.listPaged("/cloud/discovery", limit);
  }

  async listCiScans(limit = DEFAULT_COMPUTE_LIMIT): Promise<{ items: JsonRecord[]; truncated: boolean }> {
    return this.listPaged("/scans", limit);
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

  private parseResponse(rawText: string, context: string): XmlNode {
    const document = parseXml(rawText);
    const response = xmlChild(document, "response");
    if (!response) {
      throw new Error(`PAN-OS ${context} returned a non-XML response: ${redactSecrets(rawText.slice(0, 160), this.http.secrets)}`);
    }
    if (response.attributes.status !== "success") {
      const message = xmlText(xmlPath(response, ["result", "msg"]))
        ?? xmlFindAll(response, "line").map(xmlText).filter(Boolean).join("; ")
        ?? xmlText(xmlChild(response, "msg"));
      throw new Error(redactSecrets(`PAN-OS ${context} failed (code ${response.attributes.code ?? "unknown"}): ${message ?? "no message"}`, this.http.secrets));
    }
    return response;
  }

  private async generateApiKey(): Promise<string> {
    if (!this.config.username || !this.config.password) {
      throw new Error(`PAN-OS ${this.config.host} has no API key and no username/password for keygen.`);
    }
    const body = new URLSearchParams({ type: "keygen", user: this.config.username, password: this.config.password });
    const response = await fetchWithRetry(`${this.config.baseUrl}/api/`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: body.toString(),
    }, this.http);
    const rawText = await response.text();
    if (!response.ok && rawText.length === 0) {
      throw new Error(`PAN-OS keygen for ${this.config.host} failed (${response.status}).`);
    }
    const key = xmlText(xmlPath(this.parseResponse(rawText, "keygen"), ["result", "key"]));
    if (!key) throw new Error(`PAN-OS keygen for ${this.config.host} did not return a key.`);
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
    const response = await fetchWithRetry(url.toString(), {
      method: "GET",
      headers: { "X-PAN-KEY": await this.getApiKey(), accept: "application/xml" },
    }, this.http);
    const rawText = await response.text();
    if (!response.ok && rawText.length === 0) {
      throw new Error(`PAN-OS ${context} on ${this.config.host} failed (${response.status} ${response.statusText}).`);
    }
    return this.parseResponse(rawText, `${context} on ${this.config.host}`);
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
    const result = await this.op("<show><system><info></info></system></show>");
    const system = xmlChild(result, "system") ?? result;
    return asObject(xmlToJson(system)) ?? {};
  }

  async showHighAvailabilityState(): Promise<XmlNode> {
    return this.op("<show><high-availability><state></state></high-availability></show>");
  }
}

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

export async function collectPanosSnapshot(client: Pick<PanosApiClient, "host" | "showSystemInfo" | "showHighAvailabilityState" | "showConfig">): Promise<PanosDeviceSnapshot> {
  const errors: string[] = [];
  const failedXpaths: string[] = [];
  let reachable = true;
  const systemInfo = await client.showSystemInfo().catch((error: unknown) => {
    errors.push(`${client.host}: show system info failed: ${errorMessage(error)}`);
    reachable = false;
    return {} as JsonRecord;
  });
  const platform = detectPlatform(systemInfo);
  let haStateFailed = false;
  const haState = await client.showHighAvailabilityState().catch((error: unknown) => {
    errors.push(`${client.host}: show high-availability state failed: ${errorMessage(error)}`);
    haStateFailed = true;
    return undefined;
  });
  const config: XmlNode[] = [];
  for (const xpath of platform === "panorama" ? PANORAMA_XPATHS : FIREWALL_XPATHS) {
    try {
      config.push(await client.showConfig(xpath));
    } catch (error) {
      failedXpaths.push(xpath);
      errors.push(`${client.host}: config show ${xpath} failed: ${errorMessage(error)}`);
    }
  }
  return { host: client.host, platform, reachable, systemInfo, haState, haStateFailed, config, failedXpaths, errors };
}

type ComputeSource = Pick<PrismaComputeClient, "baseUrl" | "listDefenders" | "getRuntimeContainerPolicy" | "getComplianceContainerPolicy" | "getComplianceHostPolicy" | "getVulnerabilityImagePolicy" | "getRegistrySettings" | "listRegistryScans" | "listImages" | "getVulnerabilityStats" | "getComplianceStats" | "listCloudDiscovery" | "listCiScans">;

export async function collectComputeSnapshot(client: ComputeSource): Promise<ComputeSnapshot> {
  const errors: string[] = [];
  const failed: string[] = [];
  const truncated: string[] = [];
  const guard = async <T>(label: string, fallback: T, load: () => Promise<T>): Promise<T> => {
    try {
      return await load();
    } catch (error) {
      failed.push(label);
      errors.push(`prisma-compute: ${label} failed: ${errorMessage(error)}`);
      return fallback;
    }
  };
  const paged = async (label: string, load: () => Promise<{ items: JsonRecord[]; truncated: boolean }>): Promise<JsonRecord[]> => {
    const result = await guard(label, { items: [] as JsonRecord[], truncated: false }, load);
    if (result.truncated) truncated.push(label);
    return result.items;
  };
  const defenders = await paged("defenders", () => client.listDefenders());
  const runtimeContainerPolicy = await guard("runtime container policy", {} as JsonRecord, () => client.getRuntimeContainerPolicy());
  const complianceContainerPolicy = await guard("compliance container policy", {} as JsonRecord, () => client.getComplianceContainerPolicy());
  const complianceHostPolicy = await guard("compliance host policy", {} as JsonRecord, () => client.getComplianceHostPolicy());
  const vulnerabilityImagePolicy = await guard("vulnerability image policy", {} as JsonRecord, () => client.getVulnerabilityImagePolicy());
  const registrySettings = await guard("registry settings", {} as JsonRecord, () => client.getRegistrySettings());
  const registryScans = await paged("registry scans", () => client.listRegistryScans());
  const images = await paged("images", () => client.listImages());
  const vulnerabilityStats = await guard("vulnerability stats", {} as JsonRecord, () => client.getVulnerabilityStats());
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
    truncated,
    errors,
  };
}

type PrismaSource = Pick<PrismaCloudClient, "getCompliancePosture" | "listAlertRules" | "collectOpenAlerts" | "listPolicies" | "listCloudAccounts" | "listAccountGroups" | "listUserRoles" | "listIntegrations">;

export async function collectPrismaSnapshot(
  client: PrismaSource,
  alertLimit = DEFAULT_ALERT_LIMIT,
  compute?: { client?: ComputeSource; unavailableReason?: string },
): Promise<PrismaSnapshot> {
  const errors: string[] = [];
  const failed: string[] = [];
  const guard = async <T>(label: string, fallback: T, load: () => Promise<T>): Promise<T> => {
    try {
      return await load();
    } catch (error) {
      failed.push(label);
      errors.push(`prisma-cloud: ${label} failed: ${errorMessage(error)}`);
      return fallback;
    }
  };
  const posture = await guard("compliance posture", undefined as JsonRecord | undefined, () => client.getCompliancePosture());
  const alertRules = await guard("alert rules", [] as JsonRecord[], () => client.listAlertRules());
  const alertPage = await guard("open alerts", { items: [] as JsonRecord[], truncated: false, totalRows: undefined as number | undefined }, () => client.collectOpenAlerts(alertLimit));
  const policies = await guard("policies", [] as JsonRecord[], () => client.listPolicies());
  const cloudAccounts = await guard("cloud accounts", [] as JsonRecord[], () => client.listCloudAccounts());
  const accountGroups = await guard("account groups", [] as JsonRecord[], () => client.listAccountGroups());
  const userRoles = await guard("user roles", [] as JsonRecord[], () => client.listUserRoles());
  const integrations = await guard("integrations", [] as JsonRecord[], () => client.listIntegrations());
  const computeSnapshot = compute?.client ? await collectComputeSnapshot(compute.client) : undefined;
  if (computeSnapshot) errors.push(...computeSnapshot.errors);
  else if (compute?.unavailableReason) errors.push(`prisma-compute: ${compute.unavailableReason}`);
  return {
    posture,
    alertRules,
    alerts: alertPage.items,
    alertsTruncated: alertPage.truncated,
    alertsTotal: alertPage.totalRows,
    policies,
    cloudAccounts,
    accountGroups,
    userRoles,
    integrations,
    failed,
    compute: computeSnapshot,
    computeUnavailableReason: computeSnapshot ? undefined : compute?.unavailableReason,
    errors,
  };
}

export interface PaloaltoClients {
  config: PaloaltoResolvedConfig;
  prisma?: PrismaCloudClient;
  compute?: PrismaComputeClient;
  computeUnavailableReason?: string;
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
    return undefined;
  }
}

export async function loadPrismaSnapshot(clients: PaloaltoClients, alertLimit = DEFAULT_ALERT_LIMIT): Promise<PrismaSnapshot | undefined> {
  if (!clients.prisma) return undefined;
  const compute = await resolveComputeClient(clients);
  return collectPrismaSnapshot(clients.prisma, alertLimit, { client: compute, unavailableReason: clients.computeUnavailableReason });
}

interface EvidenceGate {
  unreadable: string[];
  partial: string[];
}

/**
 * Applies the verdict-safety rules: unreadable evidence forces manual,
 * partial inventories cap the verdict at warn.
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
    return {
      ...result,
      status: result.status === "pass" ? "warn" : result.status,
      summary: `${result.summary} Partial inventory: ${gateInfo.partial.join("; ")}.`,
      evidence: { ...(result.evidence ?? {}), partial_inventory: gateInfo.partial },
    };
  }
  return result;
}

function prismaGate(snapshot: PrismaSnapshot, surfaces: string[]): EvidenceGate {
  const unreadable = surfaces.filter((surface) => snapshot.failed.includes(surface)).map((surface) => `prisma-cloud ${surface} unreadable`);
  const partial: string[] = [];
  if (surfaces.includes("open alerts") && snapshot.alertsTruncated) {
    partial.push(`open alerts truncated at ${snapshot.alerts.length}${snapshot.alertsTotal !== undefined ? ` of ${snapshot.alertsTotal}` : ""} (raise alert_limit)`);
  }
  return { unreadable, partial };
}

function computeGate(snapshot: ComputeSnapshot, surfaces: string[]): EvidenceGate {
  return {
    unreadable: surfaces.filter((surface) => snapshot.failed.includes(surface)).map((surface) => `prisma-compute ${surface} unreadable`),
    partial: surfaces.filter((surface) => snapshot.truncated.includes(surface)).map((surface) => `prisma-compute ${surface} truncated at ${DEFAULT_COMPUTE_LIMIT} records`),
  };
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
  };
}

const POLICY_XPATHS = ["/vsys", "/device-group", "/config/shared"];
const ZONE_XPATHS = ["/network", "/template"];
const DEVICE_XPATHS = ["/deviceconfig", "/mgt-config", "/config/shared", "/template", "/config/panorama"];
const GLOBALPROTECT_XPATHS = ["/vsys", "/network", "/template"];

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

function summarizeAlerts(alerts: JsonRecord[]): JsonRecord {
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
      passed_resources: passed,
      failed_resources: failed,
      high_severity_failed: asNumber(summary.highSeverityFailedResources) ?? null,
      standards: standards.slice(0, 25).map((item) => ({ name: asString(item.name), passed: asNumber(item.passedResources), failed: asNumber(item.failedResources) })),
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
      enabled_rules: enabledRules.map((rule) => asString(rule.name)).slice(0, 25),
      disabled_rules: disabledRules.map((rule) => asString(rule.name)).slice(0, 25),
      rules_with_notifications: snapshot.alertRules.filter((rule) => asArray(rule.alertRuleNotificationConfig).length > 0).length,
      open_alerts: summarizeAlerts(snapshot.alerts),
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
    { iam_policies: iamPolicies.length, iam_policies_enabled: iamEnabled.length, iam_alerts: summarizeAlerts(iamAlerts) },
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
      accounts: snapshot.cloudAccounts.length,
      account_groups: snapshot.accountGroups.length,
      disabled_accounts: disabledAccounts.map((account) => asString(account.name)).slice(0, 25),
      ungrouped_accounts: ungroupedAccounts.map((account) => asString(account.name)).slice(0, 25),
      errored_accounts: erroredAccounts.map((account) => `${asString(account.name)}: ${asString(account.status)}`).slice(0, 25),
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
    { network_policies_enabled: networkPolicies.length, ...summarizeAlerts(networkAlerts) },
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
    { encryption_policies: encryptionPolicies.length, encryption_policies_enabled: encryptionEnabled.length, encryption_alerts: summarizeAlerts(encryptionAlerts) },
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

  const vulnPolicyRules = enabledPolicyRules(compute.vulnerabilityImagePolicy);
  const blockingRules = vulnPolicyRules.filter((rule) => ruleEffect(rule).includes("block") || ruleEffect(rule).includes("prevent"));
  const criticalCves = asNumber(asObject(compute.vulnerabilityStats.criticalVulnerabilities ?? compute.vulnerabilityStats)?.critical) ?? asNumber(compute.vulnerabilityStats.criticalVulnerabilities) ?? asNumber(compute.vulnerabilityStats.critical);
  const highCves = asNumber(compute.vulnerabilityStats.highVulnerabilities) ?? asNumber(compute.vulnerabilityStats.high);
  const imagesWithoutScanTime = compute.images.filter((image) => !asString(image.scanTime));
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
                ? "Vulnerability stats did not expose critical CVE counts, so the environment-wide CVE exposure is unknown."
                : `${blockingRules.length} blocking image vulnerability rules enforce thresholds; ${compute.images.length} scanned images, ${criticalCves} critical and ${highCves ?? "unknown"} high CVEs reported.`,
    {
      vulnerability_rules_enabled: vulnPolicyRules.length,
      blocking_rules: blockingRules.map((rule) => asString(rule.name)).slice(0, 25),
      images_scanned: compute.images.length,
      images_without_scan_time: imagesWithoutScanTime.map((image) => asString(image.id) ?? asString(asObject(image.repoTag)?.repo)).slice(0, 25),
      critical_cves: criticalCves ?? null,
      high_cves: highCves ?? null,
    },
  ), computeGate(compute, ["vulnerability image policy", "images", "vulnerability stats"]), CWPP_EVIDENCE[0].instruction));

  const hostRules = enabledPolicyRules(compute.complianceHostPolicy);
  const containerRules = enabledPolicyRules(compute.complianceContainerPolicy);
  const complianceRate = asNumber(compute.complianceStats.complianceRate) ?? asNumber(asObject(compute.complianceStats.summary)?.complianceRate);
  findings.push(gate(finding(
    8,
    "medium",
    hostRules.length === 0 && containerRules.length === 0 ? "fail" : hostRules.length === 0 ? "fail" : complianceRate === undefined ? "warn" : complianceRate < 90 ? "fail" : "pass",
    hostRules.length === 0 && containerRules.length === 0
      ? "Zero enabled host or container compliance rules were returned; emptiness is treated as fail because CIS benchmarks are not being evaluated."
      : hostRules.length === 0
        ? `${containerRules.length} container compliance rules are enabled but no host compliance rule is, so host CIS benchmarks are not evaluated.`
        : complianceRate === undefined
          ? `${hostRules.length} host and ${containerRules.length} container compliance rules are enabled, but compliance stats returned no complianceRate; treated as warn.`
          : `${hostRules.length} host and ${containerRules.length} container compliance rules enabled; overall compliance rate ${complianceRate}%.`,
    { host_rules_enabled: hostRules.length, container_rules_enabled: containerRules.length, compliance_rate: complianceRate ?? null },
  ), computeGate(compute, ["compliance host policy", "compliance container policy", "compliance stats"]), CWPP_EVIDENCE[1].instruction));

  const runtimeRules = enabledPolicyRules(compute.runtimeContainerPolicy);
  const protectiveRules = runtimeRules.filter((rule) => {
    const effects = ["processes", "network", "filesystem", "dns"].map((key) => (asString(asObject(rule[key])?.effect) ?? "").toLowerCase());
    return effects.some((effect) => effect === "prevent" || effect === "block");
  });
  const alertOnlyRules = runtimeRules.filter((rule) => !protectiveRules.includes(rule));
  findings.push(gate(finding(
    9,
    "high",
    runtimeRules.length === 0 ? "fail" : protectiveRules.length === 0 ? "warn" : "pass",
    runtimeRules.length === 0
      ? "Zero enabled container runtime rules were returned; emptiness is treated as fail because Defenders have no runtime policy to enforce."
      : protectiveRules.length === 0
        ? `${runtimeRules.length} container runtime rules are enabled but every process, network, file system, and DNS effect is alert or disable, so nothing is prevented.`
        : `${protectiveRules.length} of ${runtimeRules.length} enabled container runtime rules prevent or block at least one behavior class (${alertOnlyRules.length} alert-only).`,
    { runtime_rules_enabled: runtimeRules.length, protective_rules: protectiveRules.map((rule) => asString(rule.name)).slice(0, 25), alert_only_rules: alertOnlyRules.map((rule) => asString(rule.name)).slice(0, 25) },
  ), computeGate(compute, ["runtime container policy"]), CWPP_EVIDENCE[2].instruction));

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
      defenders: compute.defenders.length,
      connected: connected.length,
      disconnected: disconnected.map((defender) => asString(defender.hostname)).slice(0, 25),
      without_timestamp: withoutTimestamp.map((defender) => asString(defender.hostname)).slice(0, 25),
      versions: [...versions],
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
      registries: registries.map((registry) => `${asString(registry.registry) ?? ""}/${asString(registry.repository) ?? "*"}`).slice(0, 25),
      registry_scans: compute.registryScans.length,
      scans_without_time: registryScansWithoutTime.length,
    },
  ), computeGate(compute, ["registry settings", "registry scans"]), CWPP_EVIDENCE[4].instruction));

  const unprotected = compute.cloudDiscovery.filter((entry) => (asNumber(entry.total) ?? 0) > (asNumber(entry.defended) ?? 0));
  const discoveryErrors = compute.cloudDiscovery.filter((entry) => asString(entry.err));
  findings.push(gate(finding(
    24,
    "medium",
    compute.cloudDiscovery.length === 0 ? "manual" : unprotected.length > 0 ? "fail" : discoveryErrors.length > 0 ? "warn" : "pass",
    compute.cloudDiscovery.length === 0
      ? "Zero cloud discovery results were returned; treated as manual because discovery requires cloud account credentials in Compute. Manual evidence required: configure cloud discovery and export Radars > Cloud."
      : unprotected.length > 0
        ? `${unprotected.length} discovered cloud services report more total resources than defended ones.`
        : discoveryErrors.length > 0
          ? `${discoveryErrors.length} cloud discovery entries report errors, so coverage is uncertain.`
          : `${compute.cloudDiscovery.length} cloud discovery entries all report total resources equal to defended resources.`,
    {
      discovery_entries: compute.cloudDiscovery.length,
      unprotected: unprotected.map((entry) => `${asString(entry.provider)}/${asString(entry.serviceType)}: ${asNumber(entry.defended) ?? 0}/${asNumber(entry.total) ?? 0}`).slice(0, 25),
      errors: discoveryErrors.map((entry) => asString(entry.err)).slice(0, 10),
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
    { ci_scans: compute.ciScans.length, failed_scans: failedScans.length, scans_without_time: scansWithoutTime.length, manual_evidence: "export Compute > Defend > Access > Admission rules to confirm admission control gating." },
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

  findings.push(gate(finding(
    12,
    "critical",
    rules.length === 0 ? "manual" : permissive.length > 0 ? "fail" : unlogged.length > 0 || shadowed.length > 0 || implicitLog.length > 0 ? "warn" : "pass",
    rules.length === 0
      ? "Zero security rules were returned by the configured devices; treated as manual because an empty rulebase usually means the wrong vsys or device group scope rather than a hardened policy. Manual evidence required: export the security rulebase for every vsys and device group."
      : `${enabledRules.length} enabled security rules: ${permissive.length} any/any allow, ${shadowed.length} likely shadowed, ${unlogged.length} with log-end=no, ${implicitLog.length} without an explicit log-end flag (implicit default not counted as logged).`,
    {
      rules_total: rules.length,
      rules_enabled: enabledRules.length,
      rules_without_explicit_log_end: implicitLog.map((rule) => `${rule.location}/${rule.name}`).slice(0, 25),
      permissive_rules: permissive.map((rule) => `${rule.location}/${rule.name}`).slice(0, 25),
      shadowed_rules: shadowed.map((rule) => `${rule.location}/${rule.name}`).slice(0, 25),
      unlogged_rules: unlogged.map((rule) => `${rule.location}/${rule.name}`).slice(0, 25),
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
      zones: zones.map((zone) => `${zone.host}/${zone.name}`).slice(0, 50),
      any_zone_allow_rules: anyZone.map((rule) => `${rule.location}/${rule.name}`).slice(0, 25),
      intrazone_default_denied: intrazoneDenied,
      interzone_default_logged: interzoneLogged,
      zones_without_zone_protection: unprotectedZones.map((zone) => `${zone.host}/${zone.name}`).slice(0, 50),
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
      decryption_rules: decryptionRules.map((rule) => `${rule.host}/${rule.name}: ${rule.action ?? "unknown"}${rule.disabled ? " (disabled)" : ""}`).slice(0, 25),
      tls_service_profiles: tlsProfiles,
      weak_tls_profiles: weakTlsProfiles.slice(0, 25),
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
      antivirus_profiles: virus.map(xmlEntryName),
      antispyware_profiles: spyware.map(xmlEntryName),
      vulnerability_profiles: vulnerability.map(xmlEntryName),
      allow_rules_missing_threat_profiles: missingThreat.map((rule) => `${rule.location}/${rule.name}`).slice(0, 25),
      lenient_vulnerability_profiles: lenientVulnerability.map(xmlEntryName),
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
      wildfire_profiles: wildfire.map(xmlEntryName),
      full_coverage_profiles: fullCoverage.map(xmlEntryName),
      allow_rules_missing_wildfire: missingWildfire.map((rule) => `${rule.location}/${rule.name}`).slice(0, 25),
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
      url_profiles: urlProfiles.map(xmlEntryName),
      weak_url_profiles: weakUrlProfiles.map(xmlEntryName),
      credential_enforcement_disabled: credentialDisabled.map(xmlEntryName),
      allow_rules_missing_url_filtering: missingUrl.map((rule) => `${rule.location}/${rule.name}`).slice(0, 25),
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
      file_blocking_profiles: fileBlocking.map(xmlEntryName),
      profiles_blocking_pe: blockingPe.map(xmlEntryName),
      allow_rules_missing_file_blocking: missingFileBlocking.map((rule) => `${rule.location}/${rule.name}`).slice(0, 25),
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
  return gate(finding(21, "medium", status, parts.join(" "), {
    prisma_dlp_policies: dlpPolicies.map((policy) => asString(policy.name)).slice(0, 25),
    panos_data_filtering_profiles: panos.profiles,
    panos_rules_with_data_filtering: panos.attachedRules,
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
  return gate(finding(19, "high", status, parts.join(" "), {
    panos_admins: admins.map((admin) => `${admin.host}/${admin.name}${admin.superuser ? " (superuser)" : ""}`).slice(0, 50),
    panos_local_password_only: localOnly.map((admin) => `${admin.host}/${admin.name}`).slice(0, 50),
    password_complexity_by_device: snapshots.map((snapshot, index) => ({ host: snapshot.host, enabled: complexity[index] ?? null })),
    prisma_roles: prisma?.userRoles.map((role) => `${asString(role.name)} (${asString(role.roleType) ?? "unknown"})`).slice(0, 50),
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
  return gate(finding(20, "high", status, parts.join(" "), {
    unlogged_rules: unlogged.map((rule) => `${rule.location}/${rule.name}`).slice(0, 25),
    rules_without_log_forwarding: noForwarding.map((rule) => `${rule.location}/${rule.name}`).slice(0, 25),
    syslog_server_profiles: syslogServers,
    log_forwarding_profiles: forwardingProfiles,
    panorama_forwarding: panoramaForwarding,
    prisma_integrations: prisma?.integrations.map((item) => `${asString(item.name)} (${asString(item.integrationType) ?? "unknown"})`).slice(0, 25),
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
  findings.push(gate(finding(
    15,
    "high",
    !gpConfigured ? "manual" : portalsWithoutAuth.length + gatewaysWithoutAuth.length > 0 ? "fail" : mfaProfiles.length === 0 || splitTunnelGateways.length > 0 ? "warn" : "pass",
    !gpConfigured
      ? "GlobalProtect is not configured on the inspected devices, so the control is scoped out and reported as manual rather than pass. Manual evidence required: confirm no remote access VPN is expected for these devices or provide the device that hosts GlobalProtect."
      : `${portals.length} portals and ${gateways.length} gateways; ${portalsWithoutAuth.length + gatewaysWithoutAuth.length} without an authentication profile, ${mfaProfiles.length} authentication profiles enforce MFA, ${splitTunnelGateways.length} gateways use split tunneling. HIP profile requirements must be reviewed manually.`,
    {
      portals,
      gateways,
      portals_without_authentication: portalsWithoutAuth,
      gateways_without_authentication: gatewaysWithoutAuth,
      mfa_authentication_profiles: mfaProfiles,
      split_tunnel_gateways: splitTunnelGateways,
    },
  ), panosGate(snapshots, GLOBALPROTECT_XPATHS), "export GlobalProtect portal and gateway authentication settings with the referenced authentication profiles."));

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
    { devices: hardening },
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
    control: 7,
    title: "Software and content versions",
    severity: "high",
    status: versions.length === 0 || unreadableInfo.length > 0 ? "manual" : legacy.length > 0 ? "fail" : missingContent.length > 0 || withoutVersion.length > 0 ? "warn" : "pass",
    summary: versions.length === 0 || unreadableInfo.length > 0
      ? `System information was not readable from ${unreadableInfo.map((snapshot) => snapshot.host).join(", ") || "any device"}. Manual evidence required: export show system info for each device.`
      : `${legacy.length} devices run PAN-OS 9.x or older; ${missingContent.length} devices lack installed antivirus or threat content; ${withoutVersion.length} report no sw-version (not counted as current). Content release dates are not exposed by show system info, so freshness must be confirmed against Device > Dynamic Updates.`,
    evidence: { devices: versions },
    mappings: controlMappings(7),
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
): Promise<PaloaltoAccessSurface> {
  try {
    const value = await load();
    return { product, target, name, endpoint, status: "readable", count: countResolver?.(value) };
  } catch (error) {
    return { product, target, name, endpoint, status: "not_readable", error: errorMessage(error) };
  }
}

const arrayCount = (value: unknown) => (Array.isArray(value) ? value.length : undefined);

export async function checkPaloaltoAccess(clients: PaloaltoClients): Promise<PaloaltoAccessCheckResult> {
  const surfaces: PaloaltoAccessSurface[] = [];
  const products: string[] = [];
  const notes: string[] = [];

  if (clients.prisma) {
    const prisma = clients.prisma;
    products.push("prisma-cloud");
    notes.push(`Prisma Cloud API: ${prisma.apiUrl}`);
    surfaces.push(
      await readableSurface("prisma-cloud", prisma.apiUrl, "compliance_posture", "GET /v2/compliance/posture", () => prisma.getCompliancePosture(), () => 1),
      await readableSurface("prisma-cloud", prisma.apiUrl, "alert_rules", "GET /v2/alert/rule", () => prisma.listAlertRules(), arrayCount),
      await readableSurface("prisma-cloud", prisma.apiUrl, "open_alerts", "GET /v2/alert", () => prisma.listOpenAlerts(DEFAULT_ALERT_PAGE_SIZE), arrayCount),
      await readableSurface("prisma-cloud", prisma.apiUrl, "policies", "GET /v2/policy", () => prisma.listPolicies(), arrayCount),
      await readableSurface("prisma-cloud", prisma.apiUrl, "cloud_accounts", "GET /cloud", () => prisma.listCloudAccounts(), arrayCount),
      await readableSurface("prisma-cloud", prisma.apiUrl, "account_groups", "GET /cloud/group", () => prisma.listAccountGroups(), arrayCount),
      await readableSurface("prisma-cloud", prisma.apiUrl, "user_roles", "GET /user/role", () => prisma.listUserRoles(), arrayCount),
      await readableSurface("prisma-cloud", prisma.apiUrl, "integrations", "GET /integration", () => prisma.listIntegrations(), arrayCount),
    );
    const compute = await resolveComputeClient(clients);
    if (compute) {
      products.push("prisma-compute");
      notes.push(`Prisma Cloud Compute console: ${compute.baseUrl}`);
      surfaces.push(
        await readableSurface("prisma-compute", compute.baseUrl, "defenders", "GET /api/v1/defenders", () => compute.listDefenders(DEFAULT_COMPUTE_PAGE_SIZE), (value) => (value as { items: unknown[] }).items.length),
        await readableSurface("prisma-compute", compute.baseUrl, "runtime_container_policy", "GET /api/v1/policies/runtime/container", () => compute.getRuntimeContainerPolicy(), (value) => asRecords(asObject(value)?.rules).length),
        await readableSurface("prisma-compute", compute.baseUrl, "compliance_policies", "GET /api/v1/policies/compliance/{container,host}", async () => [await compute.getComplianceContainerPolicy(), await compute.getComplianceHostPolicy()], () => 2),
        await readableSurface("prisma-compute", compute.baseUrl, "vulnerability_image_policy", "GET /api/v1/policies/vulnerability/images", () => compute.getVulnerabilityImagePolicy(), (value) => asRecords(asObject(value)?.rules).length),
        await readableSurface("prisma-compute", compute.baseUrl, "registry_settings", "GET /api/v1/settings/registry", () => compute.getRegistrySettings(), (value) => asRecords(asObject(value)?.specifications).length),
        await readableSurface("prisma-compute", compute.baseUrl, "vulnerability_stats", "GET /api/v1/stats/vulnerabilities", () => compute.getVulnerabilityStats(), () => 1),
        await readableSurface("prisma-compute", compute.baseUrl, "cloud_discovery", "GET /api/v1/cloud/discovery", () => compute.listCloudDiscovery(DEFAULT_COMPUTE_PAGE_SIZE), (value) => (value as { items: unknown[] }).items.length),
        await readableSurface("prisma-compute", compute.baseUrl, "ci_scans", "GET /api/v1/scans", () => compute.listCiScans(DEFAULT_COMPUTE_PAGE_SIZE), (value) => (value as { items: unknown[] }).items.length),
      );
    } else {
      notes.push(`Prisma Cloud Compute not reachable: ${clients.computeUnavailableReason ?? "unknown"} Controls 7-11, 24, and 25 fall back to manual findings.`);
    }
  } else {
    notes.push("Prisma Cloud not configured (PRISMA_ACCESS_KEY_ID and PRISMA_SECRET_KEY missing); controls 1-11, 24, and 25 fall back to manual findings.");
  }

  if (clients.panos.length > 0) products.push("pan-os");
  for (const device of clients.panos) {
    const systemInfoSurface = await readableSurface("pan-os", device.host, "system_info", "type=op show system info", () => device.showSystemInfo(), () => 1);
    surfaces.push(systemInfoSurface);
    const systemInfo: JsonRecord = systemInfoSurface.status === "readable" ? await device.showSystemInfo().catch(() => ({})) : {};
    const platform = detectPlatform(systemInfo);
    notes.push(`${device.host}: ${platform}${asString(systemInfo.model) ? ` ${asString(systemInfo.model)}` : ""}${asString(systemInfo["sw-version"]) ? ` PAN-OS ${asString(systemInfo["sw-version"])}` : ""}`);
    surfaces.push(await readableSurface("pan-os", device.host, "ha_state", "type=op show high-availability state", () => device.showHighAvailabilityState(), () => 1));
    for (const xpath of platform === "panorama" ? PANORAMA_XPATHS : FIREWALL_XPATHS) {
      surfaces.push(await readableSurface("pan-os", device.host, xpath.split("/").slice(-1)[0], `type=config action=show xpath=${xpath}`, () => device.showConfig(xpath), (value) => (value as XmlNode).children.length));
    }
  }
  if (clients.panos.length === 0) {
    notes.push("PAN-OS not configured (PANOS_HOST missing); controls 12-18, 22, and 23 fall back to manual findings.");
  }
  if (!clients.config.verifyTls) notes.push("TLS certificate verification is disabled for PAN-OS requests only (PANOS_VERIFY_TLS=false); Prisma Cloud requests and the rest of the process keep verification on.");

  const readable = surfaces.filter((surface) => surface.status === "readable").length;
  const status: PaloaltoAccessCheckResult["status"] = surfaces.length === 0 ? "unconfigured" : readable === surfaces.length ? "healthy" : "degraded";
  notes.push(`${readable}/${surfaces.length} Palo Alto audit surfaces are readable.`);
  return {
    status,
    products,
    surfaces,
    notes,
    recommendedNextStep: status === "healthy"
      ? "Run paloalto_assess_cloud_posture, paloalto_assess_firewall_policy, paloalto_assess_threat_prevention, paloalto_assess_device_hardening, or paloalto_export_audit_bundle."
      : "Grant the Prisma Cloud access key a read-only System Admin or Account Group Read Only role and the PAN-OS admin a read-only (auditadmin or custom XML API read) role, then re-run paloalto_check_access.",
  };
}

async function collectPanosSnapshots(clients: PaloaltoClients): Promise<PanosDeviceSnapshot[]> {
  return Promise.all(clients.panos.map((device) => collectPanosSnapshot(device)));
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
  return assessmentResult("Palo Alto cloud posture (Prisma Cloud)", findings, snapshot.errors, {
    prisma_configured: true,
    compute_configured: Boolean(snapshot.compute),
    compute_console: snapshot.compute?.consoleUrl ?? null,
    cloud_accounts: snapshot.cloudAccounts.length,
    open_alerts_sampled: snapshot.alerts.length,
    open_alerts_truncated: snapshot.alertsTruncated,
  });
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
  return assessmentResult("Palo Alto firewall policy (PAN-OS)", assessPanosFirewallPolicy(devices), devices.flatMap((item) => item.errors), {
    devices: devices.length,
    platforms: devices.map((item) => `${item.host}: ${item.platform}`),
  });
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
  return assessmentResult("Palo Alto threat prevention (PAN-OS)", findings, [...devices.flatMap((item) => item.errors), ...(prisma?.errors ?? [])], { devices: devices.length });
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
    devices: devices.length,
    prisma_configured: Boolean(prisma),
  });
}

function formatAccessCheckText(result: PaloaltoAccessCheckResult): string {
  const rows = result.surfaces.map((surface) => [
    surface.product,
    surface.target.replace(/^https?:\/\//, "").slice(0, 32),
    surface.name,
    surface.status,
    surface.count === undefined ? "-" : String(surface.count),
    surface.error ? surface.error.replace(/\s+/g, " ").slice(0, 80) : "",
  ]);
  return [
    `Palo Alto access check: ${result.status}`,
    "",
    ...result.notes,
    "",
    formatTable(["Product", "Target", "Surface", "Status", "Count", "Note"], rows),
    "",
    `Next: ${result.recommendedNextStep}`,
  ].join("\n");
}

function formatAssessmentText(result: PaloaltoAssessmentResult): string {
  const rows = result.findings.map((item) => [
    item.id,
    item.severity.toUpperCase(),
    item.status.toUpperCase(),
    item.title,
    item.summary.length > 160 ? `${item.summary.slice(0, 157)}...` : item.summary,
  ]);
  const summary = Object.entries(result.summary)
    .map(([key, value]) => `- ${key}: ${Array.isArray(value) ? value.join(", ") : String(value)}`)
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

function buildComplianceMatrix(findings: PaloaltoFinding[]): string {
  const rows = findings.map((item) => [
    item.id,
    String(item.control),
    item.status.toUpperCase(),
    ...FRAMEWORK_ORDER.map((framework) =>
      item.mappings.filter((mapping) => mapping.startsWith(`${framework} `)).map((mapping) => mapping.slice(framework.length + 1)).join(", ") || "-"),
  ]);
  return [
    "# Unified Compliance Matrix",
    "",
    `| Finding | Control | Status | ${FRAMEWORK_ORDER.join(" | ")} |`,
    `|${"---|".repeat(FRAMEWORK_ORDER.length + 3)}`,
    ...rows.map((row) => `| ${row.join(" | ")} |`),
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
    "- `core_data/`: raw API snapshots (Prisma Cloud JSON, PAN-OS system info and configuration as JSON)",
    "- `analysis/findings.json`: normalized findings with framework mappings",
    "- `analysis/<area>.json`: per-assessment summaries",
    "- `compliance/executive_summary.md`, `compliance/unified_compliance_matrix.md`, one report per framework",
    "- `_errors.log`: present only when collection partially failed",
    "",
    "## Assessments",
    "",
    ...assessments.map((item) => `- ${item.title}: ${item.summary.pass} pass, ${item.summary.warn} warn, ${item.summary.fail} fail, ${item.summary.manual} manual`),
    "",
    "Credentials, API keys, and JWTs are never written into the bundle.",
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

  await writeSecureTextFile(outputDir, "QUICK_REFERENCE.md", `${buildQuickReference(access, assessments)}\n`);
  await writeSecureTextFile(outputDir, "metadata.json", serializeJson({
    generated_at: new Date().toISOString(),
    prisma_api_url: config.prisma?.apiUrl ?? null,
    prisma_compute_url: prismaSnapshot?.compute?.consoleUrl ?? null,
    panos_hosts: config.panos.map((item) => item.host),
    tls_verification: config.verifyTls,
    tls_verification_scope: config.verifyTls ? "all requests" : "disabled for PAN-OS requests only",
    source_chain: config.sourceChain,
  }));
  await writeSecureTextFile(outputDir, "core_data/access.json", serializeJson(access));
  if (prismaSnapshot) {
    const { errors: _ignored, ...raw } = prismaSnapshot;
    await writeSecureTextFile(outputDir, "core_data/prisma_cloud.json", serializeJson(raw));
  }
  for (const snapshot of deviceSnapshots) {
    await writeSecureTextFile(outputDir, `core_data/panos_${safeDirName(snapshot.host)}.json`, serializeJson({
      host: snapshot.host,
      platform: snapshot.platform,
      system_info: snapshot.systemInfo,
      ha_state: snapshot.haState ? xmlToJson(snapshot.haState) : null,
      config: snapshot.config.map(xmlToJson),
    }));
  }
  await writeSecureTextFile(outputDir, "analysis/findings.json", serializeJson(findings));
  const analysisNames = ["cloud_posture", "firewall_policy", "threat_prevention", "device_hardening"];
  for (const [index, assessment] of assessments.entries()) {
    await writeSecureTextFile(outputDir, `analysis/${analysisNames[index]}.json`, serializeJson(assessment));
  }
  await writeSecureTextFile(outputDir, "compliance/executive_summary.md", `${buildExecutiveSummary(config, assessments)}\n`);
  await writeSecureTextFile(outputDir, "compliance/unified_compliance_matrix.md", `${buildComplianceMatrix(findings)}\n`);
  for (const framework of FRAMEWORK_ORDER) {
    await writeSecureTextFile(outputDir, `compliance/${FRAMEWORK_FILES[framework]}`, `${buildFrameworkReport(framework, findings)}\n`);
  }
  if (errors.length > 0) {
    await writeSecureTextFile(outputDir, "_errors.log", `${errors.join("\n")}\n`);
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

function toolError(tool: string, label: string, error: unknown) {
  return errorResult(`${label} failed: ${errorMessage(error)}`, { tool });
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
      try {
        const result = await checkPaloaltoAccess(createClients(args));
        return textResult(formatAccessCheckText(result), { tool: "paloalto_check_access", ...result });
      } catch (error) {
        return toolError("paloalto_check_access", "Palo Alto access check", error);
      }
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
      try {
        const result = await assessPaloaltoCloudPosture(createClients(args), {
          alertLimit: args.alert_limit,
          minCompliancePassRate: args.min_compliance_pass_rate,
        });
        return textResult(formatAssessmentText(result), { tool: "paloalto_assess_cloud_posture", ...result });
      } catch (error) {
        return toolError("paloalto_assess_cloud_posture", "Palo Alto cloud posture assessment", error);
      }
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
      try {
        const result = await assessPaloaltoFirewallPolicy(createClients(args));
        return textResult(formatAssessmentText(result), { tool: "paloalto_assess_firewall_policy", ...result });
      } catch (error) {
        return toolError("paloalto_assess_firewall_policy", "Palo Alto firewall policy assessment", error);
      }
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
      try {
        const result = await assessPaloaltoThreatPrevention(createClients(args));
        return textResult(formatAssessmentText(result), { tool: "paloalto_assess_threat_prevention", ...result });
      } catch (error) {
        return toolError("paloalto_assess_threat_prevention", "Palo Alto threat prevention assessment", error);
      }
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
      try {
        const result = await assessPaloaltoDeviceHardening(createClients(args), { maxSuperusers: args.max_superusers });
        return textResult(formatAssessmentText(result), { tool: "paloalto_assess_device_hardening", ...result });
      } catch (error) {
        return toolError("paloalto_assess_device_hardening", "Palo Alto device hardening assessment", error);
      }
    },
  });

  pi.registerTool({
    name: "paloalto_export_audit_bundle",
    label: "Export Palo Alto audit bundle",
    description:
      "Export a Palo Alto Networks audit bundle with raw Prisma Cloud and PAN-OS snapshots (core_data/), normalized findings (analysis/), executive summary, unified compliance matrix and per-framework reports (compliance/), QUICK_REFERENCE.md, an _errors.log when collection partially failed, and a zip archive.",
    parameters: Type.Object({
      ...authParams,
      output_dir: Type.Optional(Type.String({ description: `Output root. Defaults to ${DEFAULT_OUTPUT_DIR}.` })),
      alert_limit: Type.Optional(Type.Number({ description: "Maximum open alerts to sample. Defaults to 500.", default: 500 })),
      min_compliance_pass_rate: Type.Optional(Type.Number({ description: "Minimum compliance pass rate percentage before warning. Defaults to 90.", default: 90 })),
      max_superusers: Type.Optional(Type.Number({ description: "Maximum acceptable superuser accounts before failing. Defaults to 3.", default: 3 })),
    }),
    prepareArguments: normalizeExportArgs,
    async execute(_toolCallId: string, args: ExportAuditBundleArgs) {
      try {
        const clients = createClients(args);
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
      } catch (error) {
        return toolError("paloalto_export_audit_bundle", "Palo Alto audit bundle export", error);
      }
    },
  });
}
