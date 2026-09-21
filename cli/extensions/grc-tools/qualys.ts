/**
 * Qualys security inspector tools for grclanker.
 *
 * Read-only assessment of a Qualys subscription across scan coverage, asset
 * inventory, vulnerability management, and administration hygiene. Uses the
 * VM/PC API (XML), the Asset Management and Tagging, Cloud Agent, and
 * Administration APIs (QPS 2.0, JSON), and the WAS API (QPS 3.0, JSON).
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
import { homedir } from "node:os";
import { dirname, join, relative, resolve } from "node:path";
import { ZipArchive } from "archiver";
import { Type } from "@sinclair/typebox";
import { errorResult, formatTable, textResult } from "./shared.js";

type FetchImpl = typeof fetch;
type SleepImpl = (ms: number) => Promise<void>;
type JsonRecord = Record<string, unknown>;

const DEFAULT_OUTPUT_DIR = "./export/qualys";
const DEFAULT_TIMEOUT_MS = 60_000;
const DEFAULT_MAX_RETRIES = 3;
const DEFAULT_LOOKBACK_DAYS = 30;
const DEFAULT_HOST_LIMIT = 5000;
const DEFAULT_DETECTION_LIMIT = 5000;
const DEFAULT_MAX_PAGES = 25;
const DEFAULT_QPS_PAGE_SIZE = 1000;
const DEFAULT_SLA_CRITICAL_DAYS = 15;
const DEFAULT_SLA_HIGH_DAYS = 30;
const DEFAULT_SLA_MEDIUM_DAYS = 90;
const DEFAULT_MIN_AUTH_SCAN_PERCENT = 80;
const DEFAULT_MIN_AGENT_COVERAGE_PERCENT = 50;
const DEFAULT_MAX_MANAGERS = 5;
const DEFAULT_MAX_RATE_LIMIT_WAIT_MS = 30_000;
const DEFAULT_LIST_LIMIT = 5000;
const DEFAULT_TAG_LIMIT = 2000;
const KNOWLEDGE_BASE_QID_BATCH = 200;
const WAS_HISTORY_ID_BATCH = 100;
const KNOWLEDGE_BASE_MAX_QIDS = 2000;
const STALE_CONNECTOR_DAYS = 7;
const STALE_AGENT_DAYS = 7;
const STALE_WAS_AUTH_DAYS = 180;
const INACTIVE_USER_DAYS = 90;
const BROAD_EXCLUSION_ADDRESS_COUNT = 256;
const USER_AGENT_HEADER = "grclanker";

export type QualysAuthMode = "basic" | "bearer" | "oauth";
export type QualysFindingStatus = "pass" | "warn" | "fail" | "manual";
export type QualysFindingSeverity = "critical" | "high" | "medium" | "low" | "info";

export interface QualysPlatform {
  id: string;
  apiServer: string;
  gateway: string;
}

export const QUALYS_PLATFORMS: QualysPlatform[] = [
  { id: "US1", apiServer: "https://qualysapi.qualys.com", gateway: "https://gateway.qg1.apps.qualys.com" },
  { id: "US2", apiServer: "https://qualysapi.qg2.apps.qualys.com", gateway: "https://gateway.qg2.apps.qualys.com" },
  { id: "US3", apiServer: "https://qualysapi.qg3.apps.qualys.com", gateway: "https://gateway.qg3.apps.qualys.com" },
  { id: "US4", apiServer: "https://qualysapi.qg4.apps.qualys.com", gateway: "https://gateway.qg4.apps.qualys.com" },
  { id: "GOV1", apiServer: "https://qualysapi.gov1.qualys.us", gateway: "https://gateway.gov1.qualys.us" },
  { id: "EU1", apiServer: "https://qualysapi.qualys.eu", gateway: "https://gateway.qg1.apps.qualys.eu" },
  { id: "EU2", apiServer: "https://qualysapi.qg2.apps.qualys.eu", gateway: "https://gateway.qg2.apps.qualys.eu" },
  { id: "EU3", apiServer: "https://qualysapi.qg3.apps.qualys.it", gateway: "https://gateway.qg3.apps.qualys.it" },
  { id: "IN1", apiServer: "https://qualysapi.qg1.apps.qualys.in", gateway: "https://gateway.qg1.apps.qualys.in" },
  { id: "CA1", apiServer: "https://qualysapi.qg1.apps.qualys.ca", gateway: "https://gateway.qg1.apps.qualys.ca" },
  { id: "AE1", apiServer: "https://qualysapi.qg1.apps.qualys.ae", gateway: "https://gateway.qg1.apps.qualys.ae" },
  { id: "UK1", apiServer: "https://qualysapi.qg1.apps.qualys.co.uk", gateway: "https://gateway.qg1.apps.qualys.co.uk" },
  { id: "AU1", apiServer: "https://qualysapi.qg1.apps.qualys.com.au", gateway: "https://gateway.qg1.apps.qualys.com.au" },
  { id: "KSA1", apiServer: "https://qualysapi.qg1.apps.qualysksa.com", gateway: "https://gateway.qg1.apps.qualysksa.com" },
];

export interface QualysResolvedConfig {
  username?: string;
  password?: string;
  token?: string;
  authMode: QualysAuthMode;
  platform: string;
  baseUrl: string;
  gatewayUrl: string;
  timeoutMs: number;
  maxRetries: number;
  lookbackDays: number;
  sourceChain: string[];
}

export interface QualysAccessSurface {
  name: string;
  module: string;
  endpoint: string;
  status: "readable" | "not_readable" | "module_unavailable";
  count?: number;
  truncation?: string;
  error?: string;
}

export interface QualysAccessCheckResult {
  status: "healthy" | "degraded" | "limited";
  platform: string;
  baseUrl: string;
  authMode: QualysAuthMode;
  surfaces: QualysAccessSurface[];
  unavailableModules: string[];
  viewScope: QualysViewScope;
  rateLimit: JsonRecord;
  notes: string[];
  recommendedNextStep: string;
}

export interface QualysFinding {
  id: string;
  control: number;
  title: string;
  severity: QualysFindingSeverity;
  status: QualysFindingStatus;
  summary: string;
  evidence: JsonRecord;
  mappings: string[];
}

export interface QualysAssessmentResult {
  category: string;
  title: string;
  summary: JsonRecord;
  findings: QualysFinding[];
  errors: string[];
  rawData: Record<string, unknown>;
}

export interface QualysAuditBundleResult {
  outputDir: string;
  zipPath: string;
  fileCount: number;
  findingCount: number;
  errorCount: number;
}

export interface QualysAssessmentOptions {
  lookbackDays?: number;
  hostLimit?: number;
  detectionLimit?: number;
  minAuthScanPercent?: number;
  minAgentCoveragePercent?: number;
  maxManagers?: number;
  slaCriticalDays?: number;
  slaHighDays?: number;
  slaMediumDays?: number;
}

export interface QualysListResult {
  items: JsonRecord[];
  truncated: boolean;
  truncationReason?: string;
  pages: number;
}

export type QualysListLike = JsonRecord[] | QualysListResult;

export interface QualysViewScope {
  verified: boolean;
  partial: boolean;
  roles: string[];
  scopeTags: string[];
  source: "user_search" | "user_list" | "activity_log" | "unverified";
  note: string;
}

export interface QualysSourceStatus {
  name: string;
  status: "readable" | "unreadable" | "truncated";
  count: number;
  cap?: number;
  reason?: string;
}

export interface XmlNode {
  name: string;
  attributes: Record<string, string>;
  children: XmlNode[];
  text: string;
}

type AuthArgs = {
  username?: string;
  password?: string;
  token?: string;
  platform?: string;
  base_url?: string;
  gateway_url?: string;
  use_oauth?: boolean;
  config_file?: string;
  timeout_seconds?: number;
  lookback_days?: number;
};

type AssessArgs = AuthArgs & {
  host_limit?: number;
  detection_limit?: number;
  min_auth_scan_percent?: number;
  min_agent_coverage_percent?: number;
  max_managers?: number;
  sla_critical_days?: number;
  sla_high_days?: number;
  sla_medium_days?: number;
};

type ExportArgs = AssessArgs & {
  output_dir?: string;
};

const CONTROL_TITLES: Record<number, string> = {
  1: "Scan schedule coverage",
  2: "Authenticated scan ratio",
  3: "Scan option profile review",
  4: "Asset group completeness",
  5: "Cloud connector status",
  6: "Scanner appliance health",
  7: "Agent deployment coverage",
  8: "Authentication record completeness",
  9: "Policy compliance profile assignment",
  10: "Vulnerability SLA adherence",
  11: "Patch management tracking",
  12: "Report template and distribution",
  13: "User role and permission audit",
  14: "External scanner configuration",
  15: "Web application inventory",
  16: "Exclusion list review",
  17: "Vulnerability prioritization (QDS)",
  18: "Tag-based asset management",
  19: "Activity log monitoring",
  20: "Network segmentation scanning",
};

const CONTROL_MAPPINGS: Record<number, string[]> = {
  1: ["FedRAMP RA-5", "CMMC 3.11.2", "SOC 2 CC7.1", "CIS 7.1", "PCI-DSS 11.3.1", "STIG SRG-APP-000516", "IRAP ISM-1163", "ISMAP CPS.RA-5"],
  2: ["FedRAMP RA-5(1)", "CMMC 3.11.2", "SOC 2 CC7.1", "CIS 7.2", "PCI-DSS 11.3.2", "STIG SRG-APP-000516", "IRAP ISM-1163", "ISMAP CPS.RA-5"],
  3: ["FedRAMP RA-5(2)", "CMMC 3.11.1", "SOC 2 CC7.1", "CIS 7.3", "PCI-DSS 11.3.1", "STIG SRG-APP-000516", "IRAP ISM-1163", "ISMAP CPS.RA-5"],
  4: ["FedRAMP CM-8", "CMMC 3.4.1", "SOC 2 CC6.1", "CIS 1.1", "PCI-DSS 2.4", "STIG SRG-APP-000383", "IRAP ISM-1599", "ISMAP CPS.CM-8"],
  5: ["FedRAMP CM-8(2)", "CMMC 3.4.1", "SOC 2 CC6.1", "PCI-DSS 2.4", "STIG SRG-APP-000383", "IRAP ISM-1599", "ISMAP CPS.CM-8"],
  6: ["FedRAMP SI-2(2)", "CMMC 3.14.1", "SOC 2 CC7.1", "PCI-DSS 11.3.1", "STIG SRG-APP-000456", "IRAP ISM-1163", "ISMAP CPS.SI-2"],
  7: ["FedRAMP CM-8(1)", "CMMC 3.4.1", "SOC 2 CC6.1", "CIS 1.1", "PCI-DSS 2.4", "STIG SRG-APP-000383", "IRAP ISM-1599", "ISMAP CPS.CM-8"],
  8: ["FedRAMP RA-5(5)", "CMMC 3.11.2", "SOC 2 CC7.1", "CIS 7.2", "PCI-DSS 11.3.2", "STIG SRG-APP-000516", "IRAP ISM-1163", "ISMAP CPS.RA-5"],
  9: ["FedRAMP CM-6(1)", "CMMC 3.4.2", "SOC 2 CC8.1", "CIS 4.1", "PCI-DSS 2.2.1", "STIG SRG-APP-000384", "IRAP ISM-1624", "ISMAP CPS.CM-6"],
  10: ["FedRAMP RA-5(3)", "CMMC 3.11.2", "SOC 2 CC7.1", "CIS 7.4", "PCI-DSS 6.1", "STIG SRG-APP-000456", "IRAP ISM-1690", "ISMAP CPS.RA-5"],
  11: ["FedRAMP SI-2", "CMMC 3.14.1", "SOC 2 CC7.1", "CIS 7.5", "PCI-DSS 6.3.3", "STIG SRG-APP-000456", "IRAP ISM-1143", "ISMAP CPS.SI-2"],
  12: ["FedRAMP RA-5(4)", "CMMC 3.11.3", "SOC 2 CC7.2", "PCI-DSS 11.3.4", "STIG SRG-APP-000516", "IRAP ISM-0109", "ISMAP CPS.RA-5"],
  13: ["FedRAMP AC-6(5)", "CMMC 3.1.5", "SOC 2 CC6.3", "PCI-DSS 7.1.1", "STIG SRG-APP-000340", "IRAP ISM-1507", "ISMAP CPS.AC-6"],
  14: ["FedRAMP RA-5", "CMMC 3.11.2", "SOC 2 CC7.1", "PCI-DSS 11.3.1", "STIG SRG-APP-000516", "IRAP ISM-1163", "ISMAP CPS.RA-5"],
  15: ["FedRAMP RA-5(3)", "CMMC 3.11.2", "SOC 2 CC7.1", "PCI-DSS 6.4.1", "STIG SRG-APP-000516", "IRAP ISM-1163", "ISMAP CPS.RA-5"],
  16: ["FedRAMP RA-5(2)", "CMMC 3.11.1", "SOC 2 CC7.1", "CIS 7.3", "PCI-DSS 11.3.1", "STIG SRG-APP-000516", "IRAP ISM-1163", "ISMAP CPS.RA-5"],
  17: ["FedRAMP RA-5(3)", "CMMC 3.11.1", "SOC 2 CC7.1", "CIS 7.6", "PCI-DSS 6.1", "STIG SRG-APP-000456", "IRAP ISM-1690", "ISMAP CPS.RA-5"],
  18: ["FedRAMP CM-8(5)", "CMMC 3.4.1", "SOC 2 CC6.1", "CIS 1.1", "PCI-DSS 2.4", "STIG SRG-APP-000383", "IRAP ISM-1599", "ISMAP CPS.CM-8"],
  19: ["FedRAMP AU-6", "CMMC 3.3.5", "SOC 2 CC7.2", "CIS 8.2", "PCI-DSS 10.6.1", "STIG SRG-APP-000516", "IRAP ISM-0580", "ISMAP CPS.AU-6"],
  20: ["FedRAMP RA-5", "CMMC 3.11.2", "SOC 2 CC7.1", "PCI-DSS 11.3.1", "STIG SRG-APP-000516", "IRAP ISM-1163", "ISMAP CPS.RA-5"],
};

const FRAMEWORKS: Array<{ prefix: string; dir: string; file: string; title: string }> = [
  { prefix: "FedRAMP ", dir: "fedramp", file: "fedramp_compliance_report.md", title: "FedRAMP / NIST 800-53 Compliance Report" },
  { prefix: "CMMC ", dir: "cmmc", file: "cmmc_compliance_report.md", title: "CMMC Compliance Report" },
  { prefix: "SOC 2 ", dir: "soc2", file: "soc2_compliance_report.md", title: "SOC 2 Compliance Report" },
  { prefix: "CIS ", dir: "cis", file: "cis_compliance_report.md", title: "CIS Controls Compliance Report" },
  { prefix: "PCI-DSS ", dir: "pci_dss", file: "pci_dss_compliance_report.md", title: "PCI-DSS Compliance Report" },
  { prefix: "STIG ", dir: "disa_stig", file: "stig_compliance_checklist.md", title: "DISA STIG Compliance Checklist" },
  { prefix: "IRAP ", dir: "irap", file: "irap_compliance_report.md", title: "IRAP / ISM Compliance Report" },
  { prefix: "ISMAP ", dir: "ismap", file: "ismap_compliance_report.md", title: "ISMAP Compliance Report" },
];

function asObject(value: unknown): JsonRecord | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
  return value as JsonRecord;
}

function asArray(value: unknown): unknown[] {
  if (value === undefined || value === null) return [];
  return Array.isArray(value) ? value : [value];
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
  if (typeof value === "boolean") return String(value);
  const object = asObject(value);
  if (object && typeof object["#text"] === "string") return asString(object["#text"]);
  return undefined;
}

function asNumber(value: unknown): number | undefined {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  const text = asString(value);
  if (text !== undefined) {
    const parsed = Number(text);
    if (Number.isFinite(parsed)) return parsed;
  }
  return undefined;
}

function asBoolean(value: unknown): boolean | undefined {
  if (typeof value === "boolean") return value;
  const text = asString(value);
  if (!text) return undefined;
  if (/^(true|1|yes)$/i.test(text)) return true;
  if (/^(false|0|no)$/i.test(text)) return false;
  return undefined;
}

function clampNumber(value: number | undefined, fallback: number, min: number, max: number): number {
  const parsed = Math.trunc(value ?? fallback);
  return Math.min(Math.max(parsed, min), max);
}

function pathValue(value: unknown, ...keys: string[]): unknown {
  let current: unknown = value;
  for (const key of keys) {
    current = asObject(current)?.[key];
    if (current === undefined) return undefined;
  }
  return current;
}

function pathString(value: unknown, ...keys: string[]): string | undefined {
  return asString(pathValue(value, ...keys));
}

function pathRecords(value: unknown, ...keys: string[]): JsonRecord[] {
  return asRecords(pathValue(value, ...keys));
}

function percent(part: number, total: number): number {
  if (total <= 0) return 0;
  return Math.round((part / total) * 1000) / 10;
}

function parseDate(value: unknown): Date | undefined {
  const text = asString(value);
  if (!text) return undefined;
  const parsed = new Date(text);
  return Number.isNaN(parsed.getTime()) ? undefined : parsed;
}

function ageInDays(value: unknown, now: Date = new Date()): number | undefined {
  const parsed = parseDate(value);
  if (!parsed) return undefined;
  return Math.floor((now.getTime() - parsed.getTime()) / 86_400_000);
}

function isoDaysAgo(days: number, now: Date = new Date()): string {
  const date = new Date(now.getTime() - days * 86_400_000);
  return date.toISOString().replace(/\.\d{3}Z$/, "Z");
}

function serializeJson(value: unknown): string {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function uniqueStrings(values: Array<string | undefined>): string[] {
  return [...new Set(values.filter((value): value is string => Boolean(value)))];
}

function decodeXmlEntities(value: string): string {
  return value.replace(/&(#x[0-9a-fA-F]+|#\d+|lt|gt|amp|quot|apos);/g, (match, entity: string) => {
    switch (entity) {
      case "lt":
        return "<";
      case "gt":
        return ">";
      case "amp":
        return "&";
      case "quot":
        return "\"";
      case "apos":
        return "'";
      default: {
        if (entity.startsWith("#x")) return String.fromCodePoint(Number.parseInt(entity.slice(2), 16));
        if (entity.startsWith("#")) return String.fromCodePoint(Number.parseInt(entity.slice(1), 10));
        return match;
      }
    }
  });
}

function parseXmlAttributes(source: string): Record<string, string> {
  const attributes: Record<string, string> = {};
  const pattern = /([^\s=/]+)\s*=\s*(?:"([^"]*)"|'([^']*)')/g;
  let match: RegExpExecArray | null = pattern.exec(source);
  while (match) {
    attributes[match[1]] = decodeXmlEntities(match[2] ?? match[3] ?? "");
    match = pattern.exec(source);
  }
  return attributes;
}

export function parseXml(source: string): XmlNode {
  const root: XmlNode = { name: "#document", attributes: {}, children: [], text: "" };
  const stack: XmlNode[] = [root];
  let index = 0;
  const length = source.length;

  while (index < length) {
    const current = stack[stack.length - 1];
    if (source[index] !== "<") {
      const next = source.indexOf("<", index);
      const end = next === -1 ? length : next;
      current.text += decodeXmlEntities(source.slice(index, end));
      index = end;
      continue;
    }

    if (source.startsWith("<!--", index)) {
      const end = source.indexOf("-->", index);
      if (end === -1) throw new Error("Malformed XML: unterminated comment.");
      index = end + 3;
      continue;
    }
    if (source.startsWith("<![CDATA[", index)) {
      const end = source.indexOf("]]>", index);
      if (end === -1) throw new Error("Malformed XML: unterminated CDATA section.");
      current.text += source.slice(index + 9, end);
      index = end + 3;
      continue;
    }
    if (source.startsWith("<?", index)) {
      const end = source.indexOf("?>", index);
      if (end === -1) throw new Error("Malformed XML: unterminated processing instruction.");
      index = end + 2;
      continue;
    }
    if (source.startsWith("<!", index)) {
      const bracket = source.indexOf("[", index);
      const close = source.indexOf(">", index);
      if (close === -1) throw new Error("Malformed XML: unterminated declaration.");
      if (bracket !== -1 && bracket < close) {
        const end = source.indexOf("]>", bracket);
        if (end === -1) throw new Error("Malformed XML: unterminated DOCTYPE subset.");
        index = end + 2;
      } else {
        index = close + 1;
      }
      continue;
    }
    if (source.startsWith("</", index)) {
      const end = source.indexOf(">", index);
      if (end === -1) throw new Error("Malformed XML: unterminated closing tag.");
      const name = source.slice(index + 2, end).trim();
      if (stack.length < 2 || current.name !== name) {
        throw new Error(`Malformed XML: unexpected closing tag ${name}.`);
      }
      stack.pop();
      index = end + 1;
      continue;
    }

    const end = source.indexOf(">", index);
    if (end === -1) throw new Error("Malformed XML: unterminated opening tag.");
    const rawTag = source.slice(index + 1, end);
    const selfClosing = rawTag.endsWith("/");
    const body = selfClosing ? rawTag.slice(0, -1) : rawTag;
    const nameMatch = /^([^\s/>]+)/.exec(body);
    if (!nameMatch) throw new Error("Malformed XML: missing element name.");
    const node: XmlNode = {
      name: nameMatch[1],
      attributes: parseXmlAttributes(body.slice(nameMatch[1].length)),
      children: [],
      text: "",
    };
    current.children.push(node);
    if (!selfClosing) stack.push(node);
    index = end + 1;
  }

  if (stack.length !== 1) {
    throw new Error(`Malformed XML: unclosed element ${stack[stack.length - 1].name}.`);
  }
  return root;
}

export function findXmlElements(node: XmlNode, name: string): XmlNode[] {
  const matches: XmlNode[] = [];
  const visit = (candidate: XmlNode): void => {
    if (candidate.name === name) matches.push(candidate);
    for (const child of candidate.children) visit(child);
  };
  visit(node);
  return matches;
}

export function findXmlElement(node: XmlNode, name: string): XmlNode | undefined {
  return findXmlElements(node, name)[0];
}

export function xmlText(node: XmlNode | undefined, childName?: string): string | undefined {
  if (!node) return undefined;
  const target = childName ? node.children.find((child) => child.name === childName) : node;
  const text = target?.text.trim();
  return text ? text : undefined;
}

export function xmlToRecord(node: XmlNode): unknown {
  const attributeKeys = Object.keys(node.attributes);
  if (node.children.length === 0 && attributeKeys.length === 0) return node.text.trim();
  const record: JsonRecord = {};
  for (const key of attributeKeys) record[`@${key}`] = node.attributes[key];
  const text = node.text.trim();
  if (text) record["#text"] = text;
  for (const child of node.children) {
    const value = xmlToRecord(child);
    const existing = record[child.name];
    if (existing === undefined) {
      record[child.name] = value;
    } else if (Array.isArray(existing)) {
      existing.push(value);
    } else {
      record[child.name] = [existing, value];
    }
  }
  return record;
}

function xmlRecords(node: XmlNode, elementName: string): JsonRecord[] {
  return findXmlElements(node, elementName).map((element) => asObject(xmlToRecord(element)) ?? {});
}

export function parseCsv(source: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let field = "";
  let quoted = false;
  for (let index = 0; index < source.length; index += 1) {
    const char = source[index];
    if (quoted) {
      if (char === "\"") {
        if (source[index + 1] === "\"") {
          field += "\"";
          index += 1;
        } else {
          quoted = false;
        }
      } else {
        field += char;
      }
      continue;
    }
    if (char === "\"") {
      quoted = true;
    } else if (char === ",") {
      row.push(field);
      field = "";
    } else if (char === "\n" || char === "\r") {
      if (char === "\r" && source[index + 1] === "\n") index += 1;
      row.push(field);
      if (row.some((cell) => cell.trim().length > 0)) rows.push(row);
      row = [];
      field = "";
    } else {
      field += char;
    }
  }
  row.push(field);
  if (row.some((cell) => cell.trim().length > 0)) rows.push(row);
  return rows;
}

function csvToRecords(source: string): JsonRecord[] {
  const rows = parseCsv(source);
  const headerIndex = rows.findIndex((row) => row.some((cell) => /^date$/i.test(cell.trim())));
  if (headerIndex === -1) return [];
  const headers = rows[headerIndex].map((cell) => cell.trim().toLowerCase().replace(/\s+/g, "_"));
  return rows.slice(headerIndex + 1).map((row) => {
    const record: JsonRecord = {};
    headers.forEach((header, index) => {
      record[header] = row[index] ?? "";
    });
    return record;
  });
}

function normalizeBaseUrl(rawUrl: string): string {
  const parsed = new URL(rawUrl.trim());
  parsed.hash = "";
  parsed.search = "";
  parsed.pathname = parsed.pathname.replace(/\/+$/, "");
  return parsed.toString().replace(/\/+$/, "");
}

export function resolveQualysPlatform(value: string | undefined): { platform: string; baseUrl: string; gatewayUrl: string } {
  const trimmed = (value ?? "US1").trim();
  const byId = QUALYS_PLATFORMS.find((platform) => platform.id.toLowerCase() === trimmed.toLowerCase());
  if (byId) return { platform: byId.id, baseUrl: byId.apiServer, gatewayUrl: byId.gateway };

  const asUrl = /^https?:\/\//i.test(trimmed) ? trimmed : trimmed.includes(".") ? `https://${trimmed}` : undefined;
  if (!asUrl) {
    throw new Error(
      `Unknown Qualys platform "${trimmed}". Use one of ${QUALYS_PLATFORMS.map((platform) => platform.id).join(", ")}, an API server hostname, or a full https URL.`,
    );
  }
  const baseUrl = normalizeBaseUrl(asUrl);
  const host = new URL(baseUrl).host;
  const byHost = QUALYS_PLATFORMS.find((platform) => new URL(platform.apiServer).host === host);
  if (byHost) return { platform: byHost.id, baseUrl: byHost.apiServer, gatewayUrl: byHost.gateway };
  const gatewayHost = host.startsWith("qualysapi.") ? host.replace(/^qualysapi\./, "qualysgateway.") : host;
  return { platform: "custom", baseUrl, gatewayUrl: `https://${gatewayHost}` };
}

export function readQualysConfigFile(pathname: string | undefined): Record<string, string> {
  if (!pathname || !existsSync(pathname)) return {};
  const values: Record<string, string> = {};
  const content = readFileSync(pathname, "utf8");
  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#") || line.startsWith(";") || line.startsWith("[")) continue;
    const separator = line.indexOf("=");
    if (separator === -1) continue;
    const key = line.slice(0, separator).trim().toLowerCase();
    const value = line.slice(separator + 1).trim().replace(/^["']|["']$/g, "");
    if (key && value) values[key] = value;
  }
  return values;
}

export function resolveQualysConfiguration(
  input: JsonRecord = {},
  env: NodeJS.ProcessEnv = process.env,
): QualysResolvedConfig {
  const sourceChain: string[] = [];
  const configPath = asString(input.config_file) ?? asString(env.QUALYS_CONFIG_FILE) ?? join(homedir(), ".qcrc");
  const file = readQualysConfigFile(configPath);

  const pick = (argKey: string, envKeys: string[], fileKeys: string[]): string | undefined => {
    const fromArgs = asString(input[argKey]);
    if (fromArgs) {
      sourceChain.push(`arguments-${argKey}`);
      return fromArgs;
    }
    for (const envKey of envKeys) {
      const fromEnv = asString(env[envKey]);
      if (fromEnv) {
        sourceChain.push(`environment-${argKey}`);
        return fromEnv;
      }
    }
    for (const fileKey of fileKeys) {
      const fromFile = asString(file[fileKey]);
      if (fromFile) {
        sourceChain.push(`config-file-${argKey}`);
        return fromFile;
      }
    }
    return undefined;
  };

  const username = pick("username", ["QUALYS_USERNAME", "QUALYS_USER"], ["username", "user"]);
  const password = pick("password", ["QUALYS_PASSWORD"], ["password"]);
  const token = pick("token", ["QUALYS_TOKEN", "QUALYS_ACCESS_TOKEN"], ["token"]);
  const useOauth = asBoolean(input.use_oauth) ?? asBoolean(env.QUALYS_USE_OAUTH) ?? asBoolean(file.use_oauth) ?? false;
  const platformValue = pick("platform", ["QUALYS_PLATFORM", "QUALYS_API_SERVER"], ["platform", "hostname"]);
  const baseUrlOverride = pick("base_url", ["QUALYS_BASE_URL", "QUALYS_API_URL"], ["base_url"]);
  const gatewayOverride = pick("gateway_url", ["QUALYS_GATEWAY_URL"], ["gateway_url"]);

  const resolvedPlatform = resolveQualysPlatform(baseUrlOverride ?? platformValue);
  const authMode: QualysAuthMode = token ? "bearer" : useOauth ? "oauth" : "basic";
  if (authMode !== "bearer" && (!username || !password)) {
    throw new Error("Provide QUALYS_USERNAME and QUALYS_PASSWORD (or username/password arguments), or a pre-issued QUALYS_TOKEN.");
  }

  return {
    username,
    password,
    token,
    authMode,
    platform: resolvedPlatform.platform,
    baseUrl: resolvedPlatform.baseUrl,
    gatewayUrl: gatewayOverride ? normalizeBaseUrl(gatewayOverride) : resolvedPlatform.gatewayUrl,
    timeoutMs: clampNumber(asNumber(input.timeout_seconds) ?? asNumber(env.QUALYS_TIMEOUT) ?? asNumber(file.timeout), DEFAULT_TIMEOUT_MS / 1000, 1, 600) * 1000,
    maxRetries: clampNumber(asNumber(input.max_retries) ?? asNumber(env.QUALYS_MAX_RETRIES), DEFAULT_MAX_RETRIES, 0, 10),
    lookbackDays: clampNumber(asNumber(input.lookback_days) ?? asNumber(env.QUALYS_LOOKBACK_DAYS), DEFAULT_LOOKBACK_DAYS, 1, 365),
    sourceChain: [...new Set(sourceChain)],
  };
}

function redactSecrets(message: string, config: QualysResolvedConfig): string {
  let redacted = message;
  for (const secret of [config.password, config.token]) {
    if (secret && secret.length > 0) redacted = redacted.split(secret).join("[redacted]");
  }
  if (config.username && config.password) {
    const basic = Buffer.from(`${config.username}:${config.password}`).toString("base64");
    redacted = redacted.split(basic).join("[redacted]");
  }
  return redacted.replace(/Bearer\s+[A-Za-z0-9._-]{16,}/g, "Bearer [redacted]");
}

function xmlErrorSummary(document: XmlNode): string | undefined {
  const simpleReturn = findXmlElement(document, "SIMPLE_RETURN") ?? findXmlElement(document, "GENERIC_RETURN");
  if (!simpleReturn) return undefined;
  const code = xmlText(findXmlElement(simpleReturn, "CODE"));
  const text = xmlText(findXmlElement(simpleReturn, "TEXT"));
  if (!code && !text) return undefined;
  return `${code ? `code ${code}` : "error"}${text ? `: ${text}` : ""}`;
}

function isModuleUnavailableError(message: string): boolean {
  return /\b(401|403)\b|unauthori[sz]ed|not\s+(enabled|subscribed|licensed|available)|module|permission|forbidden|access denied|not authorized/i.test(message);
}

function looksLikeXml(text: string): boolean {
  return /^\s*(<\?xml|<!DOCTYPE|<[A-Za-z_])/.test(text);
}

interface QualysHttpResponse {
  status: number;
  text: string;
  headers: Headers;
}

const defaultSleep: SleepImpl = (ms) => new Promise((resolvePromise) => setTimeout(resolvePromise, ms));

export class QualysApiClient {
  private readonly config: QualysResolvedConfig;
  private readonly fetchImpl: FetchImpl;
  private readonly sleepImpl: SleepImpl;
  private readonly now: () => Date;
  private bearerToken?: string;
  private bearerExpiresAt = 0;
  lastRateLimit: JsonRecord = {};

  constructor(
    config: QualysResolvedConfig,
    options: { fetchImpl?: FetchImpl; sleepImpl?: SleepImpl; now?: () => Date } = {},
  ) {
    this.config = config;
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.sleepImpl = options.sleepImpl ?? defaultSleep;
    this.now = options.now ?? (() => new Date());
    if (config.token) {
      this.bearerToken = config.token;
      this.bearerExpiresAt = Number.MAX_SAFE_INTEGER;
    }
  }

  getResolvedConfig(): QualysResolvedConfig {
    return this.config;
  }

  private buildUrl(pathOrUrl: string, query: JsonRecord = {}): string {
    const url = new URL(
      /^https?:\/\//i.test(pathOrUrl)
        ? pathOrUrl
        : `${this.config.baseUrl}${pathOrUrl.startsWith("/") ? pathOrUrl : `/${pathOrUrl}`}`,
    );
    for (const [key, value] of Object.entries(query)) {
      if (value === undefined || value === null || value === "") continue;
      url.searchParams.set(key, String(value));
    }
    return url.toString();
  }

  // Pagination follows absolute WARNING/URL continuations; error text keeps only the
  // endpoint path so the Qualys error code and message fit inside finding summaries.
  private endpointLabel(pathOrUrl: string): string {
    if (!/^https?:\/\//i.test(pathOrUrl)) return pathOrUrl;
    try {
      return new URL(pathOrUrl).pathname;
    } catch {
      return pathOrUrl;
    }
  }

  private async fetchGatewayToken(): Promise<string> {
    if (!this.config.username || !this.config.password) {
      throw new Error("Qualys OAuth mode requires QUALYS_USERNAME and QUALYS_PASSWORD.");
    }
    const body = new URLSearchParams({
      username: this.config.username,
      password: this.config.password,
      token: "true",
    });
    const response = await this.rawRequest("POST", `${this.config.gatewayUrl}/auth`, {
      body: body.toString(),
      contentType: "application/x-www-form-urlencoded",
      skipAuth: true,
    });
    if (response.status >= 400 || response.text.trim().length === 0) {
      throw new Error(`Qualys gateway token request failed (${response.status}).`);
    }
    this.bearerToken = response.text.trim();
    this.bearerExpiresAt = Date.now() + 3.5 * 3_600_000;
    return this.bearerToken;
  }

  private async authorizationHeader(): Promise<string> {
    const mode = this.config.authMode;
    switch (mode) {
      case "basic": {
        const encoded = Buffer.from(`${this.config.username ?? ""}:${this.config.password ?? ""}`).toString("base64");
        return `Basic ${encoded}`;
      }
      case "bearer":
        return `Bearer ${this.bearerToken ?? this.config.token ?? ""}`;
      case "oauth": {
        if (this.bearerToken && Date.now() < this.bearerExpiresAt) return `Bearer ${this.bearerToken}`;
        return `Bearer ${await this.fetchGatewayToken()}`;
      }
      default: {
        const exhaustive: never = mode;
        throw new Error(`Unsupported Qualys auth mode: ${String(exhaustive)}`);
      }
    }
  }

  private recordRateLimit(headers: Headers): void {
    const captured: JsonRecord = {};
    for (const name of [
      "X-RateLimit-Limit",
      "X-RateLimit-Window-Sec",
      "X-RateLimit-Remaining",
      "X-RateLimit-ToWait-Sec",
      "X-Concurrency-Limit-Limit",
      "X-Concurrency-Limit-Running",
    ]) {
      const value = headers.get(name);
      if (value !== null) captured[name] = value;
    }
    if (Object.keys(captured).length > 0) this.lastRateLimit = captured;
  }

  private async rawRequest(
    method: string,
    url: string,
    options: { body?: string; contentType?: string; accept?: string; skipAuth?: boolean } = {},
  ): Promise<QualysHttpResponse> {
    let attempt = 0;
    for (;;) {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), this.config.timeoutMs);
      try {
        const headers = new Headers();
        headers.set("X-Requested-With", USER_AGENT_HEADER);
        headers.set("Accept", options.accept ?? "application/xml");
        if (options.contentType) headers.set("Content-Type", options.contentType);
        if (!options.skipAuth) headers.set("Authorization", await this.authorizationHeader());

        const response = await this.fetchImpl(url, {
          method,
          headers,
          body: options.body,
          signal: controller.signal,
        });
        this.recordRateLimit(response.headers);
        const text = await response.text();
        if ((response.status === 409 || response.status === 429 || response.status >= 500) && attempt < this.config.maxRetries) {
          attempt += 1;
          const toWait = asNumber(response.headers.get("X-RateLimit-ToWait-Sec"));
          const waitMs = Math.min(
            toWait !== undefined ? toWait * 1000 : 1000 * 2 ** attempt,
            DEFAULT_MAX_RATE_LIMIT_WAIT_MS,
          );
          await this.sleepImpl(waitMs);
          continue;
        }
        return { status: response.status, text, headers: response.headers };
      } catch (error) {
        if (attempt < this.config.maxRetries && error instanceof Error && error.name !== "AbortError") {
          attempt += 1;
          await this.sleepImpl(Math.min(1000 * 2 ** attempt, DEFAULT_MAX_RATE_LIMIT_WAIT_MS));
          continue;
        }
        const message = error instanceof Error ? error.message : String(error);
        throw new Error(redactSecrets(`Qualys request to ${url} failed: ${message}`, this.config));
      } finally {
        clearTimeout(timeout);
      }
    }
  }

  async getXml(path: string, query: JsonRecord = {}): Promise<XmlNode> {
    const url = this.buildUrl(path, query);
    const response = await this.rawRequest("GET", url);
    const document = looksLikeXml(response.text) ? parseXml(response.text) : undefined;
    const errorSummary = document ? xmlErrorSummary(document) : undefined;
    const label = this.endpointLabel(path);
    if (response.status >= 400 || errorSummary) {
      const detail = errorSummary ?? response.text.replace(/\s+/g, " ").slice(0, 240);
      throw new Error(redactSecrets(`Qualys request failed (${response.status}) for ${label}${detail ? `: ${detail}` : ""}`, this.config));
    }
    if (!document) {
      throw new Error(`Qualys request for ${label} did not return XML.`);
    }
    return document;
  }

  async getText(path: string, query: JsonRecord = {}): Promise<string> {
    const url = this.buildUrl(path, query);
    const response = await this.rawRequest("GET", url, { accept: "text/csv, application/xml" });
    const label = this.endpointLabel(path);
    if (looksLikeXml(response.text)) {
      const errorSummary = xmlErrorSummary(parseXml(response.text));
      if (errorSummary) throw new Error(`Qualys request failed (${response.status}) for ${label}: ${errorSummary}`);
    }
    if (response.status >= 400) {
      throw new Error(redactSecrets(`Qualys request failed (${response.status}) for ${label}: ${response.text.replace(/\s+/g, " ").slice(0, 240)}`, this.config));
    }
    return response.text;
  }

  async postQps(path: string, request: JsonRecord = {}): Promise<JsonRecord> {
    const url = this.buildUrl(path);
    const response = await this.rawRequest("POST", url, {
      body: JSON.stringify({ ServiceRequest: request }),
      contentType: "application/json",
      accept: "application/json",
    });
    let payload: JsonRecord = {};
    if (response.text.trim().length > 0) {
      try {
        payload = asObject(JSON.parse(response.text)) ?? {};
      } catch {
        throw new Error(redactSecrets(`Qualys QPS request failed (${response.status}) for ${path}: ${response.text.replace(/\s+/g, " ").slice(0, 240)}`, this.config));
      }
    }
    const serviceResponse = asObject(payload.ServiceResponse) ?? payload;
    const responseCode = asString(serviceResponse.responseCode);
    if (response.status >= 400 || (responseCode && responseCode !== "SUCCESS")) {
      const detail = pathString(serviceResponse, "responseErrorDetails", "errorMessage") ?? responseCode ?? response.text.slice(0, 240);
      throw new Error(redactSecrets(`Qualys QPS request failed (${response.status}) for ${path}: ${detail}`, this.config));
    }
    return serviceResponse;
  }

  async listXml(
    path: string,
    query: JsonRecord,
    elementName: string,
    options: { limit?: number; maxPages?: number } = {},
  ): Promise<QualysListResult> {
    const limit = clampNumber(options.limit, DEFAULT_HOST_LIMIT, 1, 1_000_000);
    const maxPages = clampNumber(options.maxPages, DEFAULT_MAX_PAGES, 1, 500);
    const items: JsonRecord[] = [];
    let nextUrl: string | undefined = this.buildUrl(path, query);
    let pages = 0;
    let dropped = false;
    while (nextUrl && items.length < limit && pages < maxPages) {
      const document: XmlNode = await this.getXml(nextUrl);
      pages += 1;
      const pageItems = xmlRecords(document, elementName);
      const room = limit - items.length;
      if (pageItems.length > room) dropped = true;
      items.push(...pageItems.slice(0, room));
      const warning = findXmlElement(document, "WARNING");
      nextUrl = warning ? xmlText(findXmlElement(warning, "URL")) : undefined;
      if (pageItems.length === 0) break;
    }
    let truncationReason: string | undefined;
    if (dropped || (nextUrl && items.length >= limit)) {
      truncationReason = `item cap ${limit} reached with more records available`;
    } else if (nextUrl && pages >= maxPages) {
      truncationReason = `page cap ${maxPages} reached with a WARNING/URL continuation not followed`;
    }
    return listResult(items, pages, truncationReason);
  }

  async searchQps(
    path: string,
    criteria: Array<{ field: string; operator: string; value?: string }> = [],
    options: { limit?: number; pageSize?: number; verbose?: boolean; maxPages?: number } = {},
  ): Promise<QualysListResult> {
    const limit = clampNumber(options.limit, DEFAULT_HOST_LIMIT, 1, 1_000_000);
    const pageSize = clampNumber(options.pageSize, DEFAULT_QPS_PAGE_SIZE, 1, 1000);
    const maxPages = clampNumber(options.maxPages, DEFAULT_MAX_PAGES, 1, 500);
    const items: JsonRecord[] = [];
    let lastId: string | undefined;
    let hasMore = false;
    let pages = 0;
    while (items.length < limit && pages < maxPages) {
      const activeCriteria = [...criteria];
      if (lastId) activeCriteria.push({ field: "id", operator: "GREATER", value: lastId });
      const request: JsonRecord = {
        preferences: {
          limitResults: Math.min(pageSize, limit - items.length),
          ...(options.verbose ? { verbose: true } : {}),
        },
      };
      if (activeCriteria.length > 0) {
        request.filters = { Criteria: activeCriteria.map((item) => ({ field: item.field, operator: item.operator, value: item.value ?? "" })) };
      }
      const response = await this.postQps(path, request);
      pages += 1;
      const data = asRecords(response.data).map((entry) => {
        const values = Object.values(entry);
        return asObject(values[0]) ?? entry;
      });
      items.push(...data);
      hasMore = asBoolean(response.hasMoreRecords) ?? false;
      lastId = asString(response.lastId);
      if (!hasMore || !lastId || data.length === 0) break;
    }
    let truncationReason: string | undefined;
    if (hasMore && !lastId) {
      truncationReason = "hasMoreRecords was true but no lastId was returned to continue paging";
    } else if (hasMore && items.length >= limit) {
      truncationReason = `item cap ${limit} reached with hasMoreRecords true`;
    } else if (hasMore && pages >= maxPages) {
      truncationReason = `page cap ${maxPages} reached with hasMoreRecords true`;
    } else if (items.length > limit) {
      truncationReason = `item cap ${limit} reached`;
    }
    return listResult(items.slice(0, limit), pages, truncationReason);
  }

  private lookbackStart(days?: number): string {
    return isoDaysAgo(clampNumber(days, this.config.lookbackDays, 1, 3650), this.now());
  }

  private async listSingleXml(path: string, query: JsonRecord, elementName: string): Promise<QualysListResult> {
    return this.listXml(path, query, elementName, { limit: DEFAULT_LIST_LIMIT });
  }

  async listScheduledScans(): Promise<QualysListResult> {
    // schedule_scan_list_output.dtd: RESPONSE > SCHEDULE_SCAN_LIST > SCAN+
    return this.listSingleXml("/api/2.0/fo/schedule/scan/", { action: "list", show_notifications: 0 }, "SCAN");
  }

  async listScans(lookbackDays?: number): Promise<QualysListResult> {
    return this.listSingleXml(
      "/api/2.0/fo/scan/",
      { action: "list", launched_after_datetime: this.lookbackStart(lookbackDays), show_ags: 1, show_op: 1 },
      "SCAN",
    );
  }

  async listHosts(limit = DEFAULT_HOST_LIMIT): Promise<QualysListResult> {
    return this.listXml(
      "/api/2.0/fo/asset/host/",
      { action: "list", details: "All", show_tags: 1, truncation_limit: Math.min(limit, 1000) },
      "HOST",
      { limit },
    );
  }

  async listOptionProfiles(): Promise<QualysListResult> {
    // VM/PC API user guide, "VM Option Profile List": action=list lives under /option_profile/vm/;
    // the parent path documents action=export and action=import only. Output follows option_profile_info.dtd.
    return this.listSingleXml("/api/2.0/fo/subscription/option_profile/vm/", { action: "list" }, "OPTION_PROFILE");
  }

  async listExcludedIps(): Promise<QualysListResult> {
    const document = await this.getXml("/api/2.0/fo/asset/excluded_ip/", { action: "list" });
    const ipSet = findXmlElement(document, "IP_SET");
    const items = ipSet
      ? ipSet.children
        .filter((child) => child.name === "IP" || child.name === "IP_RANGE")
        .map((child) => ({ type: child.name === "IP" ? "ip" : "range", value: child.text.trim(), ...child.attributes }))
      : [];
    return listResult(items, 1, unfollowedWarning(document));
  }

  async listAssetGroups(): Promise<QualysListResult> {
    return this.listXml(
      "/api/2.0/fo/asset/group/",
      { action: "list", show_attributes: "ALL", truncation_limit: 500 },
      "ASSET_GROUP",
      { limit: DEFAULT_LIST_LIMIT },
    );
  }

  async listAppliances(): Promise<QualysListResult> {
    return this.listSingleXml("/api/2.0/fo/appliance/", { action: "list", output_mode: "full" }, "APPLIANCE");
  }

  async listAuthRecordSummary(): Promise<QualysListResult> {
    const document = await this.getXml("/api/2.0/fo/auth/", { action: "list" });
    const container = findXmlElement(document, "AUTH_RECORDS");
    const items = container
      ? container.children
        .filter((child) => child.name.startsWith("AUTH_"))
        .map((child) => ({
          type: child.name.replace(/^AUTH_/, "").toLowerCase(),
          count: findXmlElements(child, "ID").length + findXmlElements(child, "ID_RANGE").length,
        }))
      : [];
    return listResult(items, 1, unfollowedWarning(document));
  }

  async listCompliancePolicies(): Promise<QualysListResult> {
    return this.listSingleXml("/api/2.0/fo/compliance/policy/", { action: "list", details: "Basic" }, "POLICY");
  }

  async listDetections(limit = DEFAULT_DETECTION_LIMIT): Promise<QualysListResult> {
    const hosts = await this.listXml(
      "/api/2.0/fo/asset/host/vm/detection/",
      {
        action: "list",
        status: "Active,New,Re-Opened",
        severities: "3,4,5",
        show_qds: 1,
        truncation_limit: Math.min(limit, 1000),
        output_format: "XML",
      },
      "HOST",
      { limit },
    );
    const detections: JsonRecord[] = [];
    let cut = false;
    for (const host of hosts.items) {
      for (const detection of pathRecords(host, "DETECTION_LIST", "DETECTION")) {
        if (detections.length >= limit) {
          cut = true;
          break;
        }
        detections.push({ host_id: asString(host.ID), ip: asString(host.IP), ...detection });
      }
      if (cut) break;
    }
    const truncationReason = hosts.truncationReason ?? (cut ? `detection cap ${limit} reached with more detections available` : undefined);
    return listResult(detections, hosts.pages, truncationReason);
  }

  async listKnowledgeBase(qids: string[]): Promise<QualysListResult> {
    const unique = uniqueStrings(qids);
    const items: JsonRecord[] = [];
    let pages = 0;
    for (let index = 0; index < Math.min(unique.length, KNOWLEDGE_BASE_MAX_QIDS); index += KNOWLEDGE_BASE_QID_BATCH) {
      const batch = unique.slice(index, index + KNOWLEDGE_BASE_QID_BATCH);
      const document = await this.getXml("/api/2.0/fo/knowledge_base/vuln/", { action: "list", details: "Basic", ids: batch.join(",") });
      pages += 1;
      items.push(...xmlRecords(document, "VULN"));
    }
    const truncationReason = unique.length > KNOWLEDGE_BASE_MAX_QIDS
      ? `knowledge base lookup capped at ${KNOWLEDGE_BASE_MAX_QIDS} of ${unique.length} QIDs`
      : undefined;
    return listResult(items, pages, truncationReason);
  }

  async listScheduledReports(): Promise<QualysListResult> {
    return this.listSingleXml("/api/2.0/fo/schedule/report/", { action: "list", is_active: 1 }, "REPORT");
  }

  async listReports(): Promise<QualysListResult> {
    return this.listSingleXml("/api/2.0/fo/report/", { action: "list" }, "REPORT");
  }

  async listActivityLog(lookbackDays?: number): Promise<QualysListResult> {
    const text = await this.getText("/api/2.0/fo/activity_log/", {
      action: "list",
      since_datetime: this.lookbackStart(lookbackDays),
      truncation_limit: DEFAULT_LIST_LIMIT,
    });
    const items = csvToRecords(text);
    return listResult(items, 1, items.length >= DEFAULT_LIST_LIMIT ? `activity log truncation_limit ${DEFAULT_LIST_LIMIT} reached` : undefined);
  }

  async searchUsers(): Promise<QualysListResult> {
    // Administration API search/am/user (user.xsd): id, username, firstName, lastName, emailAddress, title,
    // scopeTags, roleList. Active users only; no status or last-login field exists on this response.
    return this.searchQps("/qps/rest/2.0/search/am/user/", [], { pageSize: 500, limit: DEFAULT_LIST_LIMIT });
  }

  async listUsers(): Promise<QualysListResult> {
    // VM/PC API user guide "User List" (/msp/user_list.php, user_list_output.dtd): USER carries USER_LOGIN,
    // USER_STATUS, CREATION_DATE, LAST_LOGIN_DATE (Manager and Unit Manager callers only), USER_ROLE,
    // BUSINESS_UNIT, and CONTACT_INFO/EMAIL. Errors arrive as USER_LIST_OUTPUT/ERROR with a number attribute.
    const document = await this.getXml("/msp/user_list.php", {});
    const output = findXmlElement(document, "USER_LIST_OUTPUT");
    const error = output?.children.find((child) => child.name === "ERROR");
    if (error) {
      const number = error.attributes.number;
      throw new Error(redactSecrets(`Qualys request failed for /msp/user_list.php: error${number ? ` ${number}` : ""}: ${error.text.trim()}`, this.config));
    }
    if (!output) {
      throw new Error("Qualys request for /msp/user_list.php did not return USER_LIST_OUTPUT.");
    }
    return listResult(xmlRecords(output, "USER"), 1);
  }

  async searchCloudAgents(limit = DEFAULT_HOST_LIMIT): Promise<QualysListResult> {
    return this.searchQps(
      "/qps/rest/2.0/search/am/hostasset",
      [{ field: "tagName", operator: "EQUALS", value: "Cloud Agent" }],
      { limit },
    );
  }

  async searchConnectors(): Promise<QualysListResult> {
    return this.searchQps("/qps/rest/2.0/search/am/assetdataconnector", [], { pageSize: 100, limit: DEFAULT_LIST_LIMIT });
  }

  async searchTags(limit = DEFAULT_TAG_LIMIT): Promise<QualysListResult> {
    return this.searchQps("/qps/rest/2.0/search/am/tag", [], { limit });
  }

  async searchWebApps(): Promise<QualysListResult> {
    return this.searchQps("/qps/rest/3.0/search/was/webapp", [], { pageSize: 100, verbose: true, limit: DEFAULT_LIST_LIMIT });
  }

  async searchWasScans(lookbackDays?: number): Promise<QualysListResult> {
    // WAS API "Search Scans" (wasscan.xsd): launchedDate, type, and status are documented filters and
    // WasScan carries id, target/webApp/id, launchedDate, and status.
    return this.searchQps(
      "/qps/rest/3.0/search/was/wasscan",
      [
        { field: "launchedDate", operator: "GREATER", value: this.lookbackStart(lookbackDays) },
        { field: "type", operator: "EQUALS", value: "VULNERABILITY" },
      ],
      { pageSize: 100, limit: DEFAULT_LIST_LIMIT },
    );
  }

  async searchWasScanHistory(webAppIds: string[]): Promise<QualysListResult> {
    // Resolves the last finished vulnerability scan of web applications that had none inside the lookback
    // window. webApp.id is a documented integer filter, and the WAS API operator table documents IN with a
    // comma-separated value list. No date bound, so a scan older than the window is still found.
    const ids = uniqueStrings(webAppIds.map((id) => id.trim()));
    const items: JsonRecord[] = [];
    let pages = 0;
    let truncationReason: string | undefined;
    let index = 0;
    while (index < ids.length && items.length < DEFAULT_LIST_LIMIT) {
      const batch = ids.slice(index, index + WAS_HISTORY_ID_BATCH);
      const result = await this.searchQps(
        "/qps/rest/3.0/search/was/wasscan",
        [
          { field: "webApp.id", operator: "IN", value: batch.join(",") },
          { field: "type", operator: "EQUALS", value: "VULNERABILITY" },
          { field: "status", operator: "EQUALS", value: "FINISHED" },
        ],
        { pageSize: 100, limit: DEFAULT_LIST_LIMIT - items.length },
      );
      pages += result.pages;
      items.push(...result.items);
      index += WAS_HISTORY_ID_BATCH;
      if (result.truncated) {
        truncationReason = result.truncationReason;
        break;
      }
    }
    if (!truncationReason && index < ids.length) {
      truncationReason = `item cap ${DEFAULT_LIST_LIMIT} reached before all ${ids.length} web applications were queried`;
    }
    return listResult(items, pages, truncationReason);
  }

  async searchWasAuthRecords(): Promise<QualysListResult> {
    return this.searchQps("/qps/rest/3.0/search/was/webappauthrecord", [], { pageSize: 100, limit: DEFAULT_LIST_LIMIT });
  }

  async searchWasSchedules(): Promise<QualysListResult> {
    return this.searchQps("/qps/rest/3.0/search/was/wasscanschedule", [], { pageSize: 100, limit: DEFAULT_LIST_LIMIT });
  }
}

function listResult(items: JsonRecord[], pages = 1, truncationReason?: string): QualysListResult {
  return { items, truncated: Boolean(truncationReason), truncationReason, pages };
}

function unfollowedWarning(document: XmlNode): string | undefined {
  const warning = findXmlElement(document, "WARNING");
  const url = warning ? xmlText(findXmlElement(warning, "URL")) : undefined;
  return url ? "WARNING/URL continuation present and not followed" : undefined;
}

export function normalizeList(value: unknown): QualysListResult {
  if (Array.isArray(value)) return listResult(value.filter((item): item is JsonRecord => Boolean(asObject(item))));
  const record = asObject(value);
  if (record && Array.isArray(record.items)) {
    const truncationReason = asString(record.truncationReason);
    return {
      items: record.items.filter((item): item is JsonRecord => Boolean(asObject(item))),
      truncated: asBoolean(record.truncated) === true || Boolean(truncationReason),
      truncationReason,
      pages: asNumber(record.pages) ?? 1,
    };
  }
  return listResult([]);
}

export type QualysDataClient = Pick<
  QualysApiClient,
  | "getResolvedConfig"
  | "listScheduledScans"
  | "listScans"
  | "listHosts"
  | "listOptionProfiles"
  | "listExcludedIps"
  | "listAssetGroups"
  | "listAppliances"
  | "listAuthRecordSummary"
  | "listCompliancePolicies"
  | "listDetections"
  | "listKnowledgeBase"
  | "listScheduledReports"
  | "listReports"
  | "listActivityLog"
  | "listUsers"
  | "searchUsers"
  | "searchCloudAgents"
  | "searchConnectors"
  | "searchTags"
  | "searchWebApps"
  | "searchWasScans"
  | "searchWasScanHistory"
  | "searchWasAuthRecords"
  | "searchWasSchedules"
>;

interface Collected {
  name: string;
  data: JsonRecord[];
  error?: string;
  moduleUnavailable: boolean;
  truncated: boolean;
  truncationReason?: string;
  cap?: number;
}

async function collect(
  name: string,
  load: () => Promise<QualysListLike>,
  errors: string[],
  cap?: number,
): Promise<Collected> {
  try {
    const list = normalizeList(await load());
    let truncationReason = list.truncationReason;
    if (!truncationReason && cap !== undefined && list.items.length >= cap) {
      truncationReason = `returned ${list.items.length} records, reaching the ${cap} record cap`;
    }
    return { name, data: list.items, moduleUnavailable: false, truncated: Boolean(truncationReason), truncationReason, cap };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    errors.push(`${name}: ${message}`);
    return { name, data: [], error: message, moduleUnavailable: isModuleUnavailableError(message), truncated: false, cap };
  }
}

function emptyCollected(name: string): Collected {
  return { name, data: [], moduleUnavailable: false, truncated: false };
}

function shortenMessage(message: string, length = 160): string {
  return message.replace(/\s+/g, " ").trim().slice(0, length);
}

interface ApiUserContext {
  users: Collected;
  legacyUsers: Collected;
}

// Both user surfaces are read with their own error sink: they only establish the API user's role and scope.
async function collectApiUserContext(client: QualysDataClient): Promise<ApiUserContext> {
  const [users, legacyUsers] = await Promise.all([
    collect("api_user", () => client.searchUsers(), [], DEFAULT_LIST_LIMIT),
    collect("api_user_list", () => client.listUsers(), [], DEFAULT_LIST_LIMIT),
  ]);
  return { users, legacyUsers };
}

function describeSource(source: Collected): QualysSourceStatus {
  if (source.error) {
    return { name: source.name, status: "unreadable", count: 0, cap: source.cap, reason: shortenMessage(source.error) };
  }
  if (source.truncated) {
    return { name: source.name, status: "truncated", count: source.data.length, cap: source.cap, reason: source.truncationReason };
  }
  return { name: source.name, status: "readable", count: source.data.length, cap: source.cap };
}

function unverifiedScope(note: string): QualysViewScope {
  return { verified: false, partial: false, roles: [], scopeTags: [], source: "unverified", note };
}

function roleGrantsFullView(roles: string[]): boolean {
  return roles.some((role) => /^manager$|super ?user/i.test(role.trim()));
}

export function resolveViewScope(config: QualysResolvedConfig, users: Collected, activity?: Collected, legacyUsers?: Collected): QualysViewScope {
  const username = config.username?.trim().toLowerCase();
  if (!username) {
    return unverifiedScope("API user role not verified: bearer token authentication does not expose the username.");
  }
  const self = users.error
    ? undefined
    : users.data.find((user) => (asString(user.username) ?? "").trim().toLowerCase() === username);
  if (self) {
    const roles = userRoles(self);
    const scopeTags = pathRecords(self, "scopeTags", "list")
      .flatMap((entry) => asRecords(entry.TagData ?? entry))
      .map((tag) => asString(tag.name))
      .filter((name): name is string => Boolean(name));
    const partial = !roleGrantsFullView(roles) || scopeTags.length > 0;
    return {
      verified: true,
      partial,
      roles,
      scopeTags,
      source: "user_search",
      note: partial
        ? `API user ${config.username} holds role ${roles.join(", ") || "unknown"}${scopeTags.length > 0 ? ` scoped to tags ${scopeTags.join(", ")}` : ""}, so list endpoints return only the assets and objects that role can see.`
        : `API user ${config.username} holds the Manager role and sees the whole subscription.`,
    };
  }
  // user_list_output.dtd: USER_LOGIN? and USER_ROLE? are documented on /msp/user_list.php, and a Manager
  // caller sees every user in the subscription including itself.
  const legacySelf = legacyUsers && !legacyUsers.error
    ? legacyUsers.data.find((user) => (xmlScalarText(user.USER_LOGIN) ?? "").trim().toLowerCase() === username)
    : undefined;
  const legacyRole = legacySelf ? xmlScalarText(legacySelf.USER_ROLE)?.trim() : undefined;
  if (legacyRole) {
    const partial = !roleGrantsFullView([legacyRole]);
    return {
      verified: true,
      partial,
      roles: [legacyRole],
      scopeTags: [],
      source: "user_list",
      note: partial
        ? `The User List API records API user ${config.username} with role ${legacyRole}, so list endpoints return only the assets and objects that role can see.`
        : `The User List API records API user ${config.username} with the Manager role and sees the whole subscription.`,
    };
  }
  const activityRoles = activity && !activity.error
    ? uniqueStrings(activity.data
      .filter((entry) => (asString(entry.user_name) ?? "").trim().toLowerCase() === username)
      .map((entry) => asString(entry.user_role)))
    : [];
  if (activityRoles.length > 0) {
    const partial = !roleGrantsFullView(activityRoles);
    return {
      verified: true,
      partial,
      roles: activityRoles,
      scopeTags: [],
      source: "activity_log",
      note: partial
        ? `Activity log records API user ${config.username} with role ${activityRoles.join(", ")}, so list endpoints return only the assets and objects that role can see.`
        : `Activity log records API user ${config.username} with the Manager role.`,
    };
  }
  if (users.error) {
    return unverifiedScope(`API user role not verified: user search failed (${shortenMessage(users.error, 100)}).`);
  }
  return unverifiedScope(`API user ${config.username} was not returned by the user search (Managers and Super Users are hidden from it), so role scope was not verified.`);
}

function finding(
  control: number,
  severity: QualysFindingSeverity,
  status: QualysFindingStatus,
  summary: string,
  evidence: JsonRecord = {},
): QualysFinding {
  return {
    id: `QUALYS-C${String(control).padStart(2, "0")}`,
    control,
    title: CONTROL_TITLES[control] ?? `Control ${control}`,
    severity,
    status,
    summary,
    evidence,
    mappings: CONTROL_MAPPINGS[control] ?? [],
  };
}

interface VerdictInput {
  control: number;
  severity: QualysFindingSeverity;
  status: QualysFindingStatus;
  summary: string;
  evidence: JsonRecord;
  sources: Collected[];
  scope: QualysViewScope;
  manualEvidence: string;
  unknownBuckets?: Record<string, number>;
}

function guardedFinding(input: VerdictInput): QualysFinding {
  const unreadable = input.sources.filter((source) => source.error);
  const truncated = input.sources.filter((source) => !source.error && source.truncated);
  const buckets = Object.entries(input.unknownBuckets ?? {}).filter(([, count]) => count > 0);
  const unknownTotal = buckets.reduce((total, [, count]) => total + count, 0);
  const notes: string[] = [];
  let status = input.status;

  if (unreadable.length > 0) {
    const causes = unreadable.map((source) => `${source.name}${source.moduleUnavailable ? " (module unlicensed or role not permitted)" : ""}: ${shortenMessage(source.error ?? "", 120)}`);
    if (status !== "fail") status = "manual";
    notes.push(`${status === "fail" ? "Additional evidence was not readable" : "Required evidence was not readable"}: ${causes.join("; ")}.`);
  }
  if (truncated.length > 0) {
    if (status === "pass") status = "warn";
    notes.push(`Partial view: ${truncated.map((source) => `${source.name} ${source.truncationReason} (${source.data.length} seen${source.cap ? ` of cap ${source.cap}` : ""})`).join("; ")}.`);
  }
  if (unknownTotal > 0) {
    if (status === "pass") status = "warn";
    notes.push(`${unknownTotal} records lack the date or flag needed to count as compliant (${buckets.map(([name, count]) => `${name}: ${count}`).join(", ")}) and were not counted as compliant.`);
  }
  if (input.scope.partial) {
    if (status === "pass") status = "warn";
    notes.push(`Partial view: ${input.scope.note}`);
  }

  const parts = [input.summary, ...notes];
  if (status === "manual" && !/Collect manually:/.test(input.summary)) {
    parts.push(`Collect manually: ${input.manualEvidence}`);
  }
  return finding(input.control, input.severity, status, parts.join(" "), {
    ...input.evidence,
    verdict_basis: input.status,
    manual_evidence: input.manualEvidence,
    unknown_buckets: Object.fromEntries(buckets),
    collection: {
      sources: input.sources.map(describeSource),
      view_scope: { verified: input.scope.verified, partial: input.scope.partial, roles: input.scope.roles, scope_tags: input.scope.scopeTags, source: input.scope.source },
    },
  });
}

function unreadableSummary(control: number, sources: Collected[]): string {
  const missing = sources.filter((source) => source.error);
  const unlicensed = missing.some((source) => source.moduleUnavailable);
  return `${CONTROL_TITLES[control] ?? `Control ${control}`} could not be evaluated: ${missing.map((source) => source.name).join(", ")} ${missing.length === 1 ? "was" : "were"} not readable${unlicensed ? " (module unlicensed, not applicable, or role not permitted)" : ""}.`;
}

function resolveAssessmentOptions(config: QualysResolvedConfig, options: QualysAssessmentOptions): Required<QualysAssessmentOptions> {
  return {
    lookbackDays: clampNumber(options.lookbackDays, config.lookbackDays, 1, 365),
    hostLimit: clampNumber(options.hostLimit, DEFAULT_HOST_LIMIT, 1, 200_000),
    detectionLimit: clampNumber(options.detectionLimit, DEFAULT_DETECTION_LIMIT, 1, 200_000),
    minAuthScanPercent: clampNumber(options.minAuthScanPercent, DEFAULT_MIN_AUTH_SCAN_PERCENT, 0, 100),
    minAgentCoveragePercent: clampNumber(options.minAgentCoveragePercent, DEFAULT_MIN_AGENT_COVERAGE_PERCENT, 0, 100),
    maxManagers: clampNumber(options.maxManagers, DEFAULT_MAX_MANAGERS, 0, 10_000),
    slaCriticalDays: clampNumber(options.slaCriticalDays, DEFAULT_SLA_CRITICAL_DAYS, 1, 3650),
    slaHighDays: clampNumber(options.slaHighDays, DEFAULT_SLA_HIGH_DAYS, 1, 3650),
    slaMediumDays: clampNumber(options.slaMediumDays, DEFAULT_SLA_MEDIUM_DAYS, 1, 3650),
  };
}

function scheduleIsActive(schedule: JsonRecord): boolean {
  return asBoolean(schedule.ACTIVE) === true;
}

function scheduleActiveFlagMissing(schedule: JsonRecord): boolean {
  return asBoolean(schedule.ACTIVE) === undefined;
}

function recordLabel(record: JsonRecord, fallback: string): string {
  return asString(record.TITLE) ?? asString(record.NAME) ?? asString(record.name) ?? asString(record.ID) ?? asString(record.id) ?? fallback;
}

// schedule_scan_list_output.dtd: TARGET holds this placeholder when the schedule is targeted by asset tags.
const TAG_TARGET_PLACEHOLDER = /^asset tags included$/i;
// The VM/PC API user guide schedule list samples name Qualys external scanners with this literal ISCANNER_NAME.
const EXTERNAL_SCANNER_NAME = /^external scanner$/i;

function splitCsvText(value: unknown): string[] {
  return (xmlScalarText(value) ?? "").split(",").map((item) => item.trim()).filter(Boolean);
}

function scheduleTargets(schedule: JsonRecord): string[] {
  // schedule_scan_list_output.dtd: ASSET_GROUP_TITLE_LIST (ASSET_GROUP_TITLE+), ASSET_TAGS > TAG_SET_INCLUDE (#PCDATA)
  const groups = asArray(pathValue(schedule, "ASSET_GROUP_TITLE_LIST", "ASSET_GROUP_TITLE")).map(xmlScalarText);
  const tags = splitCsvText(pathValue(schedule, "ASSET_TAGS", "TAG_SET_INCLUDE"));
  const target = xmlScalarText(schedule.TARGET)?.trim();
  return uniqueStrings([...groups, ...tags, target && !TAG_TARGET_PLACEHOLDER.test(target) ? target : undefined]);
}

function scheduleScannerName(schedule: JsonRecord): string | undefined {
  const name = xmlScalarText(schedule.ISCANNER_NAME)?.replace(/\s+/g, " ").trim();
  return name ? name : undefined;
}

function scheduleUsesExternalScanner(schedule: JsonRecord): boolean {
  const name = scheduleScannerName(schedule);
  return name !== undefined && EXTERNAL_SCANNER_NAME.test(name);
}

function scheduleScannerUnverified(schedule: JsonRecord): boolean {
  return scheduleScannerName(schedule) === undefined;
}

function scheduleNextLaunch(schedule: JsonRecord): string | undefined {
  return pathString(schedule, "SCHEDULE", "NEXTLAUNCH_UTC") ?? asString(schedule.NEXTLAUNCH_UTC);
}

function hostOs(host: JsonRecord): string {
  return asString(host.OS) ?? "";
}

function hostTrackingMethod(host: JsonRecord): string {
  return (asString(host.TRACKING_METHOD) ?? "").toLowerCase();
}

function hostIsAgentTracked(host: JsonRecord): boolean {
  return /agent/.test(hostTrackingMethod(host));
}

function hostTags(host: JsonRecord): string[] {
  return pathRecords(host, "TAGS", "TAG").map((tag) => asString(tag.NAME)).filter((name): name is string => Boolean(name));
}

function assetGroupHasTargets(group: JsonRecord): boolean {
  const ipSet = asObject(group.IP_SET);
  const hasIps = Boolean(ipSet && (asArray(ipSet.IP).length > 0 || asArray(ipSet.IP_RANGE).length > 0));
  return hasIps || asArray(group.DOMAIN_LIST).length > 0 || asArray(pathValue(group, "HOST_IDS")).length > 0 || asArray(group.DNS_LIST).length > 0;
}

function addressCountForRange(range: string): number {
  const match = /^(\d+\.\d+\.\d+\.\d+)\s*-\s*(\d+\.\d+\.\d+\.\d+)$/.exec(range.trim());
  if (!match) return range.includes("/") ? 2 ** (32 - Number(range.split("/")[1] || 32)) : 1;
  const toNumber = (ip: string): number => ip.split(".").reduce((total, octet) => total * 256 + Number(octet), 0);
  return Math.max(toNumber(match[2]) - toNumber(match[1]) + 1, 1);
}

function optionProfileName(profile: JsonRecord): string {
  return pathString(profile, "BASIC_INFO", "GROUP_NAME") ?? asString(profile.GROUP_NAME) ?? pathString(profile, "BASIC_INFO", "ID") ?? "option profile";
}

function optionProfileAuthTypes(profile: JsonRecord): string[] {
  const value = pathValue(profile, "SCAN", "AUTHENTICATION");
  if (value === undefined) return [];
  const text = asString(value);
  if (text) return text.split(",").map((item) => item.trim()).filter(Boolean);
  return Object.keys(asObject(value) ?? {}).filter((key) => !key.startsWith("@") && key !== "#text");
}

function optionProfileExclusionLists(profile: JsonRecord): string[] {
  // option_profile_info.dtd: SCAN > VULNERABILITY_DETECTION > DETECTION_EXCLUDE (CUSTOM_LIST+) > CUSTOM (ID, TITLE, ...)
  return pathRecords(profile, "SCAN", "VULNERABILITY_DETECTION", "DETECTION_EXCLUDE", "CUSTOM_LIST")
    .flatMap((list) => asRecords(list.CUSTOM))
    .map((custom) => xmlScalarText(custom.TITLE) ?? xmlScalarText(custom.ID) ?? "search list");
}

function optionProfileExcludedQidCount(profile: JsonRecord): number {
  return optionProfileExclusionLists(profile).length;
}

export async function assessQualysScanCoverage(
  client: QualysDataClient,
  options: QualysAssessmentOptions = {},
): Promise<QualysAssessmentResult> {
  const config = client.getResolvedConfig();
  const settings = resolveAssessmentOptions(config, options);
  const errors: string[] = [];
  const now = new Date();

  const [schedules, scans, hosts, profiles, excluded, groups, apiUser] = await Promise.all([
    collect("scheduled_scans", () => client.listScheduledScans(), errors, DEFAULT_LIST_LIMIT),
    collect("scans", () => client.listScans(settings.lookbackDays), errors, DEFAULT_LIST_LIMIT),
    collect("hosts", () => client.listHosts(settings.hostLimit), errors, settings.hostLimit),
    collect("option_profiles", () => client.listOptionProfiles(), errors, DEFAULT_LIST_LIMIT),
    collect("excluded_ips", () => client.listExcludedIps(), errors),
    collect("asset_groups", () => client.listAssetGroups(), errors, DEFAULT_LIST_LIMIT),
    collectApiUserContext(client),
  ]);
  const scope = resolveViewScope(config, apiUser.users, undefined, apiUser.legacyUsers);

  const activeSchedules = schedules.data.filter(scheduleIsActive);
  const schedulesWithoutActiveFlag = schedules.data.filter(scheduleActiveFlagMissing);
  const scheduledTargets = new Set(activeSchedules.flatMap(scheduleTargets).map((target) => target.toLowerCase()));
  const groupsWithoutSchedule = groups.data
    .map((group) => recordLabel(group, "group"))
    .filter((title) => !scheduledTargets.has(title.toLowerCase()) && !scheduledTargets.has("all"));
  const hostsWithoutScanDate = hosts.data.filter((host) => !parseDate(hostLastScan(host)));
  const scannedHosts = hosts.data.filter((host) => parseDate(hostLastScan(host)));
  const staleScannedHosts = scannedHosts.filter((host) => (ageInDays(hostLastScan(host), now) ?? Number.POSITIVE_INFINITY) > settings.lookbackDays);
  const authScannedHosts = scannedHosts.filter((host) => hostRecentlyAuthScanned(host, now, settings.lookbackDays));
  const authPercent = percent(authScannedHosts.length, scannedHosts.length);

  const profilesWithoutAuth = profiles.data.filter((profile) => optionProfileAuthTypes(profile).length === 0).map(optionProfileName);
  const excludedQidCount = profiles.data.reduce((total, profile) => total + optionProfileExcludedQidCount(profile), 0);
  const broadExclusions = excluded.data.filter((entry) => entry.type === "range" && addressCountForRange(asString(entry.value) ?? "") > BROAD_EXCLUSION_ADDRESS_COUNT);
  const externalSchedules = activeSchedules.filter(scheduleUsesExternalScanner);
  const schedulesWithoutScannerName = activeSchedules.filter(scheduleScannerUnverified);
  const distinctTargets = uniqueStrings(activeSchedules.flatMap(scheduleTargets));
  const distinctScanners = uniqueStrings(activeSchedules.map(scheduleScannerName));
  const internalScanners = distinctScanners.filter((name) => !EXTERNAL_SCANNER_NAME.test(name));
  const finishedScans = scans.data.filter((scan) => /finished/i.test(pathString(scan, "STATUS", "STATE") ?? asString(scan.STATUS) ?? ""));

  const findings: QualysFinding[] = [];

  const coverageStatus: QualysFindingStatus = schedules.error
    ? "manual"
    : activeSchedules.length === 0
      ? "fail"
      : groups.data.length === 0 || hosts.data.length === 0
        ? "manual"
        : groupsWithoutSchedule.length > 0 || staleScannedHosts.length > 0 || hostsWithoutScanDate.length > 0
          ? "warn"
          : "pass";
  findings.push(guardedFinding({
    control: 1,
    severity: "high",
    status: coverageStatus,
    summary: schedules.error
      ? unreadableSummary(1, [schedules])
      : activeSchedules.length === 0
        ? `No active scheduled vulnerability scans were found (${schedules.data.length} schedules returned, ${schedulesWithoutActiveFlag.length} without an ACTIVE flag). Emptiness is a failure for this control because recurring scans are required.`
        : groups.error || hosts.error
          ? unreadableSummary(1, [groups, hosts])
          : groups.data.length === 0
          ? `${activeSchedules.length} active schedules exist but the asset group list is empty, so coverage of every asset group cannot be confirmed; either no asset groups are defined or the API user cannot see them.`
          : hosts.data.length === 0
            ? `${activeSchedules.length} active schedules exist but no host assets were returned, so scan recency cannot be evaluated; either nothing has been scanned or the API user cannot see hosts.`
            : `${activeSchedules.length} active schedules cover ${distinctTargets.length} distinct targets; ${groupsWithoutSchedule.length}/${groups.data.length} asset groups are not referenced by an active schedule, ${staleScannedHosts.length}/${scannedHosts.length} scanned hosts have no vulnerability scan within ${settings.lookbackDays} days, and ${hostsWithoutScanDate.length}/${hosts.data.length} hosts have no scan date at all.`,
    evidence: {
      active_schedules: activeSchedules.length,
      total_schedules: schedules.data.length,
      schedules_without_active_flag: schedulesWithoutActiveFlag.length,
      finished_scans_in_lookback: finishedScans.length,
      asset_groups: groups.data.length,
      asset_groups_without_schedule: groupsWithoutSchedule.slice(0, 50),
      hosts: hosts.data.length,
      stale_scanned_hosts: staleScannedHosts.length,
      hosts_without_scan_date: hostsWithoutScanDate.length,
      next_launches: activeSchedules.map(scheduleNextLaunch).filter(Boolean).slice(0, 20),
    },
    sources: [schedules, groups, hosts],
    scope,
    manualEvidence: "export Scans > Schedules and Assets > Asset Groups from the Qualys UI and confirm each asset group has an active recurring scan and each host was scanned within the review window.",
    unknownBuckets: { hosts_without_scan_date: hostsWithoutScanDate.length, schedules_without_active_flag: schedulesWithoutActiveFlag.length },
  }));

  const authStatus: QualysFindingStatus = hosts.error
    ? "manual"
    : hosts.data.length === 0
      ? "manual"
      : scannedHosts.length === 0
        ? "fail"
        : authPercent >= settings.minAuthScanPercent
          ? "pass"
          : "fail";
  findings.push(guardedFinding({
    control: 2,
    severity: "high",
    status: authStatus,
    summary: hosts.error
      ? unreadableSummary(2, [hosts])
      : hosts.data.length === 0
        ? "No host assets were returned, so the authenticated scan ratio cannot be computed; an empty host inventory is treated as unknown, not compliant."
        : scannedHosts.length === 0
          ? `${hosts.data.length} hosts were returned but none has a vulnerability scan date, so 0% of hosts have evidence of an authenticated scan.`
          : `${authScannedHosts.length}/${scannedHosts.length} scanned hosts (${authPercent}%) had an authenticated scan within ${Math.max(settings.lookbackDays, 30)} days against a ${settings.minAuthScanPercent}% threshold; ${hostsWithoutScanDate.length} hosts without a scan date were excluded from the ratio and never counted as authenticated.`,
    evidence: {
      hosts: hosts.data.length,
      scanned_hosts: scannedHosts.length,
      authenticated_hosts: authScannedHosts.length,
      authenticated_percent: authPercent,
      threshold_percent: settings.minAuthScanPercent,
      hosts_without_scan_date: hostsWithoutScanDate.length,
    },
    sources: [hosts],
    scope,
    manualEvidence: "run an Authentication Report in Qualys and record the percentage of hosts with successful authenticated scans.",
    unknownBuckets: { hosts_without_scan_date: hostsWithoutScanDate.length },
  }));

  findings.push(guardedFinding({
    control: 3,
    severity: "medium",
    status: profiles.error ? "manual" : profiles.data.length === 0 ? "fail" : "warn",
    summary: profiles.error
      ? unreadableSummary(3, [profiles])
      : profiles.data.length === 0
        ? "No option profiles were returned; emptiness is a failure for this control because at least one authenticated option profile is required for scanning."
        : `${profiles.data.length} option profiles reviewed; ${profilesWithoutAuth.length} have no authentication types enabled (SCAN/AUTHENTICATION absent or empty). Port ranges and internal versus external intent are not machine-verifiable, so the verdict is capped at warn until reviewed.`,
    evidence: {
      option_profiles: profiles.data.map(optionProfileName).slice(0, 50),
      profiles_without_authentication: profilesWithoutAuth.slice(0, 50),
      authentication_types: Object.fromEntries(profiles.data.slice(0, 50).map((profile) => [optionProfileName(profile), optionProfileAuthTypes(profile)])),
    },
    sources: [profiles],
    scope,
    manualEvidence: "export each option profile from Scans > Option Profiles and review authentication, port, and performance settings against internal and external scanning requirements.",
  }));

  const unverifiedScannerNote = schedulesWithoutScannerName.length > 0
    ? ` ${schedulesWithoutScannerName.length} active schedules carry no ISCANNER_NAME, so their scanner is unverifiable and was never assumed to be external.`
    : "";
  findings.push(guardedFinding({
    control: 14,
    severity: "medium",
    status: schedules.error ? "manual" : activeSchedules.length === 0 ? "fail" : externalSchedules.length > 0 ? "pass" : "warn",
    summary: schedules.error
      ? unreadableSummary(14, [schedules])
      : activeSchedules.length === 0
        ? "No active schedules were found, so external perimeter scanning is not configured; emptiness is a failure for this control."
        : externalSchedules.length > 0
          ? `${externalSchedules.length}/${activeSchedules.length} active schedules name the Qualys External Scanner (ISCANNER_NAME "External Scanner") and therefore provide perimeter coverage.${unverifiedScannerNote}`
          : `${activeSchedules.length} active schedules name only internal scanner appliances (${internalScanners.join(", ") || "none named"}); none names the Qualys External Scanner, so perimeter coverage is not confirmed.${unverifiedScannerNote}`,
    evidence: {
      active_schedules: activeSchedules.length,
      external_schedules: externalSchedules.map((schedule) => recordLabel(schedule, "schedule")).slice(0, 50),
      schedules_without_scanner_name: schedulesWithoutScannerName.map((schedule) => recordLabel(schedule, "schedule")).slice(0, 50),
      scanners_in_use: distinctScanners.slice(0, 50),
      external_scanner_match: "ISCANNER_NAME equals the documented literal External Scanner",
    },
    sources: [schedules],
    scope,
    manualEvidence: "confirm at least one recurring perimeter scan uses Qualys external scanners against the public IP ranges.",
    // A missing ISCANNER_NAME only leaves the verdict uncertain when no schedule is confirmed external.
    unknownBuckets: externalSchedules.length > 0 ? {} : { schedules_without_scanner_name: schedulesWithoutScannerName.length },
  }));

  const exclusionStatus: QualysFindingStatus = excluded.error
    ? "manual"
    : broadExclusions.length > 0
      ? "fail"
      : excluded.data.length > 0 || excludedQidCount > 0
        ? "warn"
        : profiles.data.length === 0
          ? "manual"
          : "pass";
  findings.push(guardedFinding({
    control: 16,
    severity: "medium",
    status: exclusionStatus,
    summary: excluded.error
      ? unreadableSummary(16, [excluded])
      : broadExclusions.length > 0
        ? `${broadExclusions.length} excluded IP ranges span more than ${BROAD_EXCLUSION_ADDRESS_COUNT} addresses.`
        : excluded.data.length > 0 || excludedQidCount > 0
          ? `${excluded.data.length} excluded host entries and ${excludedQidCount} detection exclusion search lists (VULNERABILITY_DETECTION/DETECTION_EXCLUDE) in option profiles require documented justification.`
          : profiles.error
            ? unreadableSummary(16, [profiles])
            : profiles.data.length === 0
            ? "The excluded host list is empty, but no option profiles were returned so detection exclusion search lists could not be evaluated."
            : `No excluded hosts and no detection exclusion search lists across ${profiles.data.length} option profiles; the excluded host list was read completely, so emptiness is compliant for this control.`,
    evidence: {
      excluded_entries: excluded.data.slice(0, 100),
      broad_exclusions: broadExclusions.slice(0, 50),
      option_profiles_reviewed: profiles.data.length,
      option_profile_detection_exclusions: excludedQidCount,
      option_profile_exclusion_lists: profiles.data.flatMap(optionProfileExclusionLists).slice(0, 50),
    },
    sources: [excluded, profiles],
    scope,
    manualEvidence: "export Assets > Excluded Hosts and review each excluded IP range and option profile detection exclusion search list for justification.",
  }));

  findings.push(guardedFinding({
    control: 20,
    severity: "medium",
    status: schedules.error ? "manual" : activeSchedules.length === 0 ? "fail" : "warn",
    summary: schedules.error
      ? unreadableSummary(20, [schedules])
      : activeSchedules.length === 0
        ? "No active schedules exist, so no segment-specific scanning is configured; emptiness is a failure for this control."
        : `${activeSchedules.length} active schedules target ${distinctTargets.length} distinct targets (asset group titles, TAG_SET_INCLUDE tags, and IP targets) across ${distinctScanners.length} named scanner sources${schedulesWithoutScannerName.length > 0 ? ` plus ${schedulesWithoutScannerName.length} schedules without an ISCANNER_NAME` : ""}. The API does not label segments, so mapping to DMZ, internal, and OT/ICS is manual and the verdict is capped at warn.`,
    evidence: {
      active_schedules: activeSchedules.length,
      distinct_targets: distinctTargets.slice(0, 50),
      distinct_scanners: distinctScanners.slice(0, 50),
      schedules_without_scanner_name: schedulesWithoutScannerName.length,
    },
    sources: [schedules],
    scope,
    manualEvidence: "document which scan schedules cover DMZ, internal, and OT/ICS segments and which scanner appliances serve each segment.",
  }));

  return {
    category: "scan_coverage",
    title: "Qualys scan coverage and cadence",
    summary: {
      platform: config.platform,
      lookback_days: settings.lookbackDays,
      view_scope: scope.note,
      active_schedules: activeSchedules.length,
      finished_scans_in_lookback: finishedScans.length,
      hosts: hosts.data.length,
      hosts_without_scan_date: hostsWithoutScanDate.length,
      stale_scanned_hosts: staleScannedHosts.length,
      authenticated_percent: authPercent,
      option_profiles: profiles.data.length,
      excluded_entries: excluded.data.length,
      external_schedules: externalSchedules.length,
      truncated_sources: [schedules, scans, hosts, profiles, excluded, groups].filter((source) => source.truncated).map((source) => source.name),
      collection_errors: errors.length,
    },
    findings,
    errors,
    rawData: {
      scheduled_scans: schedules.data,
      scans: scans.data,
      hosts: hosts.data,
      option_profiles: profiles.data,
      excluded_ips: excluded.data,
      asset_groups: groups.data,
    },
  };
}

function hostLastScan(host: JsonRecord): unknown {
  return host.LAST_VULN_SCAN_DATETIME ?? host.LAST_VM_SCANNED_DATE;
}

function hostRecentlyAuthScanned(host: JsonRecord, now: Date, lookbackDays: number): boolean {
  const age = ageInDays(host.LAST_VM_AUTH_SCANNED_DATE, now);
  return age !== undefined && age <= Math.max(lookbackDays, 30);
}

function connectorState(connector: JsonRecord): string {
  return (asString(connector.connectorState) ?? asString(connector.state) ?? "unknown").toUpperCase();
}

function connectorStateUnknown(connector: JsonRecord): boolean {
  return connectorState(connector) === "UNKNOWN";
}

function connectorIsUnhealthy(connector: JsonRecord): boolean {
  return /ERROR|DISABLED|INCOMPLETE/.test(connectorState(connector)) || asBoolean(connector.disabled) === true || Boolean(asString(connector.lastError));
}

function applianceStatus(appliance: JsonRecord): string {
  return (asString(appliance.STATUS) ?? "unknown").toLowerCase();
}

function applianceStatusUnknown(appliance: JsonRecord): boolean {
  return applianceStatus(appliance) === "unknown";
}

function applianceIsOffline(appliance: JsonRecord): boolean {
  return /offline|inactive|disconnected/.test(applianceStatus(appliance));
}

function applianceIsOutdated(appliance: JsonRecord): boolean {
  const version = asString(appliance.SOFTWARE_VERSION);
  const latest = asString(appliance.ML_LATEST);
  const missed = asNumber(appliance.HEARTBEATS_MISSED) ?? 0;
  const vulnsigsLatest = asString(appliance.VULNSIGS_LATEST);
  const vulnsigsVersion = asString(appliance.VULNSIGS_VERSION);
  return missed > 0
    || (Boolean(version && latest) && version !== latest)
    || (Boolean(vulnsigsLatest && vulnsigsVersion) && vulnsigsLatest !== vulnsigsVersion);
}

function agentStatus(agent: JsonRecord): string {
  return (pathString(agent, "agentInfo", "status") ?? "unknown").toUpperCase();
}

function agentStatusUnknown(agent: JsonRecord): boolean {
  return agentStatus(agent) === "UNKNOWN";
}

function agentLastCheckIn(agent: JsonRecord): unknown {
  const value = pathValue(agent, "agentInfo", "lastCheckedIn");
  const nested = asObject(value);
  return nested ? nested.date ?? nested["#text"] : value;
}

function agentHasActivationKey(agent: JsonRecord): boolean {
  const key = asObject(pathValue(agent, "agentInfo", "activationKey"));
  return Boolean(key && (asString(key.activationId) ?? asString(key.title) ?? asString(key.id)));
}

export async function assessQualysAssetInventory(
  client: QualysDataClient,
  options: QualysAssessmentOptions = {},
): Promise<QualysAssessmentResult> {
  const config = client.getResolvedConfig();
  const settings = resolveAssessmentOptions(config, options);
  const errors: string[] = [];
  const now = new Date();

  const [groups, hosts, connectors, appliances, agents, tags, apiUser] = await Promise.all([
    collect("asset_groups", () => client.listAssetGroups(), errors, DEFAULT_LIST_LIMIT),
    collect("hosts", () => client.listHosts(settings.hostLimit), errors, settings.hostLimit),
    collect("connectors", () => client.searchConnectors(), errors, DEFAULT_LIST_LIMIT),
    collect("appliances", () => client.listAppliances(), errors, DEFAULT_LIST_LIMIT),
    collect("cloud_agents", () => client.searchCloudAgents(settings.hostLimit), errors, settings.hostLimit),
    collect("tags", () => client.searchTags(), errors, DEFAULT_TAG_LIMIT),
    collectApiUserContext(client),
  ]);
  const scope = resolveViewScope(config, apiUser.users, undefined, apiUser.legacyUsers);

  const emptyGroups = groups.data.filter((group) => !assetGroupHasTargets(group)).map((group) => recordLabel(group, "group"));
  const neverScannedHosts = hosts.data.filter((host) => !parseDate(hostLastScan(host)));
  const unhealthyConnectors = connectors.data.filter(connectorIsUnhealthy);
  const unknownStateConnectors = connectors.data.filter((connector) => !connectorIsUnhealthy(connector) && connectorStateUnknown(connector));
  const connectorsWithoutSyncDate = connectors.data.filter((connector) => !connectorIsUnhealthy(connector) && !parseDate(connector.lastSync));
  const staleConnectors = connectors.data.filter((connector) => (ageInDays(connector.lastSync, now) ?? -1) > STALE_CONNECTOR_DAYS);
  const offlineAppliances = appliances.data.filter(applianceIsOffline);
  const unknownStatusAppliances = appliances.data.filter(applianceStatusUnknown);
  const outdatedAppliances = appliances.data.filter((appliance) => !applianceIsOffline(appliance) && applianceIsOutdated(appliance));
  const agentHosts = hosts.data.filter(hostIsAgentTracked);
  const hostsWithoutTrackingMethod = hosts.data.filter((host) => hostTrackingMethod(host) === "");
  const agentPercent = percent(agentHosts.length, hosts.data.length);
  const inactiveAgents = agents.data.filter((agent) => /INACTIVE|UNINSTALL/.test(agentStatus(agent)));
  const unknownStatusAgents = agents.data.filter(agentStatusUnknown);
  const agentsWithoutCheckIn = agents.data.filter((agent) => !parseDate(agentLastCheckIn(agent)));
  const agentsWithoutActivationKey = agents.data.filter((agent) => !agentHasActivationKey(agent));
  const staleAgents = agents.data.filter((agent) => (ageInDays(agentLastCheckIn(agent), now) ?? -1) > STALE_AGENT_DAYS);
  const untaggedHosts = hosts.data.filter((host) => hostTags(host).length === 0);
  const untaggedPercent = percent(untaggedHosts.length, hosts.data.length);
  const dynamicTags = tags.data.filter((tag) => Boolean(asString(tag.ruleType)));

  const findings: QualysFinding[] = [];

  findings.push(guardedFinding({
    control: 4,
    severity: "medium",
    status: "manual",
    summary: `Qualys exposes ${groups.data.length} asset groups and ${hosts.data.length} host assets, but the API cannot compare them against the authoritative CMDB or network range register, so this control is always manual. Investigate ${emptyGroups.length} asset groups without targets and ${neverScannedHosts.length} hosts that were never scanned.`,
    evidence: {
      asset_groups: groups.data.length,
      asset_groups_without_targets: emptyGroups.slice(0, 50),
      hosts: hosts.data.length,
      hosts_never_scanned: neverScannedHosts.length,
    },
    sources: [groups, hosts],
    scope,
    manualEvidence: "export the CMDB or IPAM network ranges and reconcile them against the Qualys asset group IP sets.",
  }));

  const connectorStatus: QualysFindingStatus = connectors.error
    ? "manual"
    : connectors.data.length === 0
      ? "manual"
      : unhealthyConnectors.length > 0
        ? "fail"
        : staleConnectors.length > 0
          ? "warn"
          : "pass";
  findings.push(guardedFinding({
    control: 5,
    severity: "medium",
    status: connectorStatus,
    summary: connectors.error
      ? unreadableSummary(5, [connectors])
      : connectors.data.length === 0
        ? "No cloud asset data connectors were returned. This is not applicable if no AWS, Azure, or GCP accounts are in scope; otherwise cloud asset discovery is missing. Emptiness is treated as unknown, not compliant."
        : unhealthyConnectors.length > 0
          ? `${unhealthyConnectors.length}/${connectors.data.length} cloud connectors are disabled or in an error state.`
          : staleConnectors.length > 0
            ? `${staleConnectors.length}/${connectors.data.length} cloud connectors have not synchronized within ${STALE_CONNECTOR_DAYS} days.`
            : `All ${connectors.data.length} cloud connectors report a healthy state and synchronized within ${STALE_CONNECTOR_DAYS} days.`,
    evidence: {
      connectors: connectors.data.map((connector) => ({
        name: asString(connector.name),
        type: asString(connector.type),
        state: connectorState(connector),
        last_sync: asString(connector.lastSync),
        last_error: asString(connector.lastError),
      })).slice(0, 100),
      unhealthy_connectors: unhealthyConnectors.length,
      stale_connectors: staleConnectors.length,
    },
    sources: [connectors],
    scope,
    manualEvidence: "open the AWS, Azure, and GCP connector lists in the Qualys UI and confirm whether cloud accounts are in scope and each connector last synchronized successfully.",
    unknownBuckets: { connectors_without_state: unknownStateConnectors.length, connectors_without_sync_date: connectorsWithoutSyncDate.length },
  }));

  const applianceStatusVerdict: QualysFindingStatus = appliances.error
    ? "manual"
    : appliances.data.length === 0
      ? "manual"
      : offlineAppliances.length > 0
        ? "fail"
        : outdatedAppliances.length > 0
          ? "warn"
          : "pass";
  findings.push(guardedFinding({
    control: 6,
    severity: "high",
    status: applianceStatusVerdict,
    summary: appliances.error
      ? unreadableSummary(6, [appliances])
      : appliances.data.length === 0
        ? "No scanner appliances were returned. This is not applicable if internal scanning relies only on Qualys external scanners or Cloud Agent; otherwise confirm the API user can see appliances. Emptiness is treated as unknown, not compliant."
        : offlineAppliances.length > 0
          ? `${offlineAppliances.length}/${appliances.data.length} scanner appliances are offline.`
          : outdatedAppliances.length > 0
            ? `${outdatedAppliances.length}/${appliances.data.length} scanner appliances missed heartbeats or run outdated software or signatures.`
            : `All ${appliances.data.length} scanner appliances report an online status with current software and signatures.`,
    evidence: {
      appliances: appliances.data.map((appliance) => ({
        name: asString(appliance.NAME),
        status: applianceStatus(appliance),
        software_version: asString(appliance.SOFTWARE_VERSION),
        latest_version: asString(appliance.ML_LATEST),
        heartbeats_missed: asNumber(appliance.HEARTBEATS_MISSED) ?? 0,
        last_updated: asString(appliance.LAST_UPDATED_DATE),
      })).slice(0, 100),
      offline_appliances: offlineAppliances.length,
      outdated_appliances: outdatedAppliances.length,
    },
    sources: [appliances],
    scope,
    manualEvidence: "review Scans > Appliances for offline scanners, missed heartbeats, and outdated software or signature versions.",
    unknownBuckets: { appliances_without_status: unknownStatusAppliances.length },
  }));

  const agentCoverageStatus: QualysFindingStatus = hosts.error || agents.error
    ? "manual"
    : hosts.data.length === 0
      ? "manual"
      : agentPercent >= settings.minAgentCoveragePercent && inactiveAgents.length === 0 && staleAgents.length === 0
        ? "pass"
        : agentPercent >= settings.minAgentCoveragePercent
          ? "warn"
          : "fail";
  findings.push(guardedFinding({
    control: 7,
    severity: "medium",
    status: agentCoverageStatus,
    summary: hosts.error || agents.error
      ? unreadableSummary(7, [hosts, agents])
      : hosts.data.length === 0
        ? "No host assets were returned, so agent coverage cannot be computed; an empty host inventory is treated as unknown, not compliant."
        : `${agentHosts.length}/${hosts.data.length} hosts (${agentPercent}%) carry TRACKING_METHOD Cloud Agent against a ${settings.minAgentCoveragePercent}% threshold; of ${agents.data.length} agents, ${inactiveAgents.length} report an inactive status and ${staleAgents.length} have not checked in for ${STALE_AGENT_DAYS} days.`,
    evidence: {
      agent_tracked_hosts: agentHosts.length,
      hosts: hosts.data.length,
      agent_coverage_percent: agentPercent,
      threshold_percent: settings.minAgentCoveragePercent,
      cloud_agents: agents.data.length,
      inactive_agents: inactiveAgents.length,
      stale_agents: staleAgents.length,
      agents_without_activation_key: agentsWithoutActivationKey.length,
    },
    sources: [hosts, agents],
    scope,
    manualEvidence: "compare the Cloud Agent inventory against the host inventory and record the agent coverage percentage, inactive agents, and last check-in dates.",
    unknownBuckets: {
      hosts_without_tracking_method: hostsWithoutTrackingMethod.length,
      agents_without_status: unknownStatusAgents.length,
      agents_without_checkin_date: agentsWithoutCheckIn.length,
      agents_without_activation_key: agentsWithoutActivationKey.length,
    },
  }));

  const tagStatus: QualysFindingStatus = tags.error || hosts.error
    ? "manual"
    : tags.data.length === 0
      ? "fail"
      : hosts.data.length === 0
        ? "manual"
        : untaggedPercent > 20
          ? "fail"
          : untaggedPercent > 0
            ? "warn"
            : "pass";
  findings.push(guardedFinding({
    control: 18,
    severity: "medium",
    status: tagStatus,
    summary: tags.error || hosts.error
      ? unreadableSummary(18, [tags, hosts])
      : tags.data.length === 0
        ? "No asset tags are defined, so compliance scope cannot be identified by tag; emptiness is a failure for this control."
        : hosts.data.length === 0
          ? `${tags.data.length} tags exist but no host assets were returned, so the untagged ratio cannot be computed; treated as unknown, not compliant.`
          : `${tags.data.length} tags exist (${dynamicTags.length} rule-based); ${untaggedHosts.length}/${hosts.data.length} hosts (${untaggedPercent}%) carry no tags.`,
    evidence: {
      tags: tags.data.length,
      dynamic_tags: dynamicTags.length,
      hosts: hosts.data.length,
      untagged_hosts: untaggedHosts.length,
      untagged_percent: untaggedPercent,
      tag_names: tags.data.map((tag) => asString(tag.name)).filter(Boolean).slice(0, 100),
    },
    sources: [tags, hosts],
    scope,
    manualEvidence: "export the tag tree and confirm every in-scope asset carries a compliance scope tag.",
  }));

  return {
    category: "asset_inventory",
    title: "Qualys asset inventory and sensors",
    summary: {
      platform: config.platform,
      view_scope: scope.note,
      asset_groups: groups.data.length,
      hosts: hosts.data.length,
      hosts_never_scanned: neverScannedHosts.length,
      connectors: connectors.data.length,
      unhealthy_connectors: unhealthyConnectors.length,
      appliances: appliances.data.length,
      offline_appliances: offlineAppliances.length,
      agent_coverage_percent: agentPercent,
      cloud_agents: agents.data.length,
      tags: tags.data.length,
      untagged_percent: untaggedPercent,
      truncated_sources: [groups, hosts, connectors, appliances, agents, tags].filter((source) => source.truncated).map((source) => source.name),
      collection_errors: errors.length,
    },
    findings,
    errors,
    rawData: {
      asset_groups: groups.data,
      hosts: hosts.data,
      connectors: connectors.data,
      appliances: appliances.data,
      cloud_agents: agents.data,
      tags: tags.data,
    },
  };
}

function detectionSeverity(detection: JsonRecord): number {
  return asNumber(detection.SEVERITY) ?? 0;
}

function detectionSlaDays(detection: JsonRecord, settings: Required<QualysAssessmentOptions>): number | undefined {
  const severity = detectionSeverity(detection);
  if (severity >= 5) return settings.slaCriticalDays;
  if (severity === 4) return settings.slaHighDays;
  if (severity === 3) return settings.slaMediumDays;
  return undefined;
}

function detectionAgeDays(detection: JsonRecord, now: Date): number | undefined {
  return ageInDays(detection.FIRST_FOUND_DATETIME, now);
}

function detectionHasQds(detection: JsonRecord): boolean {
  return detection.QDS !== undefined && asString(detection.QDS) !== undefined;
}

function detectionStatus(detection: JsonRecord): string | undefined {
  return asString(detection.STATUS)?.trim().toLowerCase();
}

function detectionIsOpen(detection: JsonRecord): boolean {
  const status = detectionStatus(detection);
  return status === undefined || /^(active|new|re-opened|reopened)$/.test(status);
}

function detectionIsFixedOrInfo(detection: JsonRecord): boolean {
  const status = detectionStatus(detection);
  const type = asString(detection.TYPE)?.trim().toLowerCase();
  return status === "fixed" || type === "info";
}

function detectionHasSeverity(detection: JsonRecord): boolean {
  return asNumber(detection.SEVERITY) !== undefined;
}

function policyStatus(policy: JsonRecord): "active" | "inactive" | "unknown" {
  const isActive = asBoolean(policy.IS_ACTIVE);
  if (isActive === true) return "active";
  if (isActive === false) return "inactive";
  const status = asString(policy.STATUS)?.trim().toLowerCase();
  if (status === "active") return "active";
  if (status && /inactive|draft|disabled/.test(status)) return "inactive";
  return "unknown";
}

function policyIsActive(policy: JsonRecord): boolean {
  return policyStatus(policy) === "active";
}

function xmlScalarText(value: unknown): string | undefined {
  const text = asString(value);
  if (text !== undefined) return text;
  const record = asObject(value);
  return record ? asString(record["#text"]) : undefined;
}

function policyHasHiddenAssetGroups(policy: JsonRecord): boolean {
  const record = asObject(policy.ASSET_GROUP_IDS);
  return Boolean(record && asBoolean(record["@has_hidden_data"]) === true);
}

function policyIsAssigned(policy: JsonRecord): boolean {
  // policy_list_output.dtd: ASSET_GROUP_IDS (#PCDATA, comma separated), TAG_SET_INCLUDE (TAG_ID+)
  const groupIds = splitCsvText(policy.ASSET_GROUP_IDS);
  const tagIds = asArray(pathValue(policy, "TAG_SET_INCLUDE", "TAG_ID")).filter((value) => Boolean(xmlScalarText(value)));
  return groupIds.length > 0 || tagIds.length > 0 || policyHasHiddenAssetGroups(policy);
}

const NETWORK_DEVICE_OS_PATTERN = /cisco|nx-os|ios[- ]?xe|junos|juniper|palo alto|pan-os|fortinet|fortios|fortigate|arista|big-ip|f5 |check ?point|gaia|router|switch|firewall|screenos|brocade|huawei/i;
const NETWORK_AUTH_TYPE_PATTERN = /snmp|cisco|checkpoint|check_point|palo|fortinet|juniper|arista|network|f5|huawei|brocade/i;

export async function assessQualysVulnerabilityManagement(
  client: QualysDataClient,
  options: QualysAssessmentOptions = {},
): Promise<QualysAssessmentResult> {
  const config = client.getResolvedConfig();
  const settings = resolveAssessmentOptions(config, options);
  const errors: string[] = [];
  const now = new Date();

  const [authRecords, hosts, policies, detections, apiUser] = await Promise.all([
    collect("auth_records", () => client.listAuthRecordSummary(), errors),
    collect("hosts", () => client.listHosts(settings.hostLimit), errors, settings.hostLimit),
    collect("compliance_policies", () => client.listCompliancePolicies(), errors, DEFAULT_LIST_LIMIT),
    collect("detections", () => client.listDetections(settings.detectionLimit), errors, settings.detectionLimit),
    collectApiUserContext(client),
  ]);
  const scope = resolveViewScope(config, apiUser.users, undefined, apiUser.legacyUsers);

  const excludedDetections = detections.data.filter(detectionIsFixedOrInfo);
  const openDetections = detections.data.filter((detection) => !detectionIsFixedOrInfo(detection) && detectionIsOpen(detection));
  const closedDetections = detections.data.filter((detection) => !detectionIsFixedOrInfo(detection) && !detectionIsOpen(detection));
  const detectionsWithoutStatus = openDetections.filter((detection) => detectionStatus(detection) === undefined);
  const detectionsWithoutSeverity = openDetections.filter((detection) => !detectionHasSeverity(detection));
  const openQids = uniqueStrings(openDetections.map((detection) => asString(detection.QID)));
  const knowledgeBase = openQids.length > 0
    ? await collect("knowledge_base", () => client.listKnowledgeBase(openQids), errors)
    : emptyCollected("knowledge_base");

  const authTypes = authRecords.data.filter((record) => (asNumber(record.count) ?? 0) > 0).map((record) => asString(record.type) ?? "");
  const windowsHosts = hosts.data.filter((host) => /windows/i.test(hostOs(host)));
  const unixHosts = hosts.data.filter((host) => /linux|unix|bsd|solaris|aix|hp-ux|esx|mac os|darwin/i.test(hostOs(host)));
  const networkHosts = hosts.data.filter((host) => NETWORK_DEVICE_OS_PATTERN.test(hostOs(host)));
  const hostsWithoutOs = hosts.data.filter((host) => hostOs(host).trim() === "");
  const missingAuthTypes: string[] = [];
  if (windowsHosts.length > 0 && !authTypes.some((type) => /windows/.test(type))) missingAuthTypes.push("windows");
  if (unixHosts.length > 0 && !authTypes.some((type) => /unix|linux/.test(type))) missingAuthTypes.push("unix");
  if (networkHosts.length > 0 && !authTypes.some((type) => NETWORK_AUTH_TYPE_PATTERN.test(type))) missingAuthTypes.push("network device");
  const scannedHosts = hosts.data.filter((host) => parseDate(hostLastScan(host)));
  const authScannedHosts = scannedHosts.filter((host) => hostRecentlyAuthScanned(host, now, settings.lookbackDays));
  const authScannedPercent = percent(authScannedHosts.length, scannedHosts.length);

  const inactivePolicies = policies.data.filter((policy) => policyStatus(policy) === "inactive").map((policy) => recordLabel(policy, "policy"));
  const unknownStatusPolicies = policies.data.filter((policy) => policyStatus(policy) === "unknown").map((policy) => recordLabel(policy, "policy"));
  const unassignedPolicies = policies.data.filter((policy) => policyIsActive(policy) && !policyIsAssigned(policy)).map((policy) => recordLabel(policy, "policy"));
  const hiddenAssignmentPolicies = policies.data.filter(policyHasHiddenAssetGroups).map((policy) => recordLabel(policy, "policy"));

  const slaScoped = openDetections.filter((detection) => detectionSlaDays(detection, settings) !== undefined);
  const slaDated = slaScoped.filter((detection) => detectionAgeDays(detection, now) !== undefined);
  const slaUndated = slaScoped.filter((detection) => detectionAgeDays(detection, now) === undefined);
  const slaBreaches = slaDated.filter((detection) => (detectionAgeDays(detection, now) ?? 0) > (detectionSlaDays(detection, settings) ?? 0));
  const slaPercent = slaDated.length === 0 ? 0 : percent(slaDated.length - slaBreaches.length, slaDated.length);
  const breachBySeverity = {
    critical: slaBreaches.filter((detection) => detectionSeverity(detection) >= 5).length,
    high: slaBreaches.filter((detection) => detectionSeverity(detection) === 4).length,
    medium: slaBreaches.filter((detection) => detectionSeverity(detection) === 3).length,
  };

  const patchableQids = new Set(knowledgeBase.data.filter((vuln) => asBoolean(vuln.PATCHABLE) === true).map((vuln) => asString(vuln.QID)).filter(Boolean));
  const kbQids = new Set(knowledgeBase.data.map((vuln) => asString(vuln.QID)).filter(Boolean));
  const unresolvedQids = openQids.filter((qid) => !kbQids.has(qid));
  const patchableDetections = openDetections.filter((detection) => patchableQids.has(asString(detection.QID)));
  const patchableDated = patchableDetections.filter((detection) => detectionAgeDays(detection, now) !== undefined);
  const patchableUndated = patchableDetections.filter((detection) => detectionAgeDays(detection, now) === undefined);
  const overduePatchable = patchableDated.filter((detection) => (detectionAgeDays(detection, now) ?? 0) > settings.slaHighDays);
  const overduePercent = percent(overduePatchable.length, patchableDated.length);

  const qdsDetections = openDetections.filter(detectionHasQds);
  const qdsPercent = percent(qdsDetections.length, openDetections.length);

  const detectionsFullyRead = !detections.error && !detections.truncated;
  const hostPopulationKnown = !hosts.error && hosts.data.length > 0;

  const findings: QualysFinding[] = [];

  const authRecordStatus: QualysFindingStatus = authRecords.error || hosts.error
    ? "manual"
    : authTypes.length === 0
      ? "fail"
      : hosts.data.length === 0
        ? "manual"
        : missingAuthTypes.length > 0
          ? "fail"
          : scannedHosts.length === 0
            ? "fail"
            : authScannedPercent >= settings.minAuthScanPercent
              ? "pass"
              : "warn";
  findings.push(guardedFinding({
    control: 8,
    severity: "high",
    status: authRecordStatus,
    summary: authRecords.error || hosts.error
      ? unreadableSummary(8, [authRecords, hosts])
      : authTypes.length === 0
        ? "No authentication records with assigned IDs exist, so credentialed scanning is not configured; emptiness is a failure for this control."
        : hosts.data.length === 0
          ? `Authentication record types ${authTypes.join(", ")} exist but no host assets were returned, so coverage of Windows, Unix, and network device populations cannot be compared; treated as unknown.`
          : missingAuthTypes.length > 0
            ? `Authentication records exist for ${authTypes.join(", ")} but ${missingAuthTypes.join(", ")} hosts (${windowsHosts.length} Windows, ${unixHosts.length} Unix-like, ${networkHosts.length} network devices) have no matching record type.`
            : scannedHosts.length === 0
              ? `Authentication record types ${authTypes.join(", ")} cover the host OS mix, but none of the ${hosts.data.length} hosts has a scan date, so there is no evidence the credentials work.`
              : `Authentication record types ${authTypes.join(", ")} cover the host OS mix (${windowsHosts.length} Windows, ${unixHosts.length} Unix-like, ${networkHosts.length} network devices) and ${authScannedHosts.length}/${scannedHosts.length} scanned hosts (${authScannedPercent}%) had a recent authenticated scan, which is the API evidence that credentials are not expired or failing (threshold ${settings.minAuthScanPercent}%).`,
    evidence: {
      auth_record_types: authRecords.data,
      windows_hosts: windowsHosts.length,
      unix_hosts: unixHosts.length,
      network_device_hosts: networkHosts.length,
      missing_auth_types: missingAuthTypes,
      authenticated_scan_percent: authScannedPercent,
    },
    sources: [authRecords, hosts],
    scope,
    manualEvidence: "review Scans > Authentication for Windows, Unix, and network device records and run an Authentication Report to find expired or failing credentials.",
    unknownBuckets: { hosts_without_os: hostsWithoutOs.length },
  }));

  const policyStatusVerdict: QualysFindingStatus = policies.error
    ? "manual"
    : policies.data.length === 0
      ? "manual"
      : unassignedPolicies.length > 0
        ? "fail"
        : inactivePolicies.length > 0
          ? "warn"
          : "pass";
  findings.push(guardedFinding({
    control: 9,
    severity: "medium",
    status: policyStatusVerdict,
    summary: policies.error
      ? unreadableSummary(9, [policies])
      : policies.data.length === 0
        ? "The Policy Compliance policy list is empty. This is not applicable if Policy Compliance is not in use; otherwise no compliance policy is assigned to any asset. Emptiness is treated as unknown, not compliant."
        : unassignedPolicies.length > 0
          ? `${unassignedPolicies.length}/${policies.data.length} active compliance policies have no ASSET_GROUP_IDS or TAG_SET_INCLUDE assignment.`
          : inactivePolicies.length > 0
            ? `${inactivePolicies.length}/${policies.data.length} compliance policies report an inactive or draft STATUS.`
            : `All ${policies.data.length} compliance policies report STATUS active and carry an asset group or tag assignment.`,
    evidence: {
      policies: policies.data.length,
      inactive_policies: inactivePolicies.slice(0, 50),
      unassigned_policies: unassignedPolicies.slice(0, 50),
      policies_with_hidden_asset_groups: hiddenAssignmentPolicies.slice(0, 50),
    },
    sources: [policies],
    scope,
    manualEvidence: "list Policy Compliance policies and confirm each active policy is assigned to asset groups or tags, or record that the PC module is not in use.",
    unknownBuckets: { policies_without_status: unknownStatusPolicies.length, policies_with_hidden_asset_groups: hiddenAssignmentPolicies.length },
  }));

  const slaStatus: QualysFindingStatus = detections.error || hosts.error
    ? "manual"
    : !hostPopulationKnown
      ? "manual"
      : slaScoped.length === 0
        ? detectionsFullyRead ? "pass" : "manual"
        : slaDated.length === 0
          ? "warn"
          : slaPercent >= 95
            ? "pass"
            : slaPercent >= 80
              ? "warn"
              : "fail";
  findings.push(guardedFinding({
    control: 10,
    severity: "critical",
    status: slaStatus,
    summary: detections.error || hosts.error
      ? unreadableSummary(10, [detections, hosts])
      : !hostPopulationKnown
        ? "No host assets were returned, so the absence or presence of open detections cannot be interpreted; treated as unknown, not compliant."
        : slaScoped.length === 0
          ? detectionsFullyRead
            ? `Zero open severity 3 to 5 detections across ${hosts.data.length} hosts with the detection list read completely; emptiness is compliant for this control because the host population is non-zero and no open detection exists to breach an SLA.`
            : `Zero open severity 3 to 5 detections were returned, but the detection list was not read completely (${detections.truncationReason ?? "truncated"}), so emptiness cannot be trusted.`
          : slaDated.length === 0
            ? `${slaScoped.length} open detections were returned but none carries FIRST_FOUND_DATETIME, so SLA age cannot be computed and none is counted as compliant.`
            : `${slaDated.length - slaBreaches.length}/${slaDated.length} dated open detections (${slaPercent}%) are within SLA (critical ${settings.slaCriticalDays}d, high ${settings.slaHighDays}d, medium ${settings.slaMediumDays}d); ${slaBreaches.length} breaches; ${slaUndated.length} detections without a first-found date were excluded from the compliant count.`,
    evidence: {
      hosts: hosts.data.length,
      detections_returned: detections.data.length,
      open_detections: openDetections.length,
      closed_detections_excluded: closedDetections.length,
      fixed_or_info_excluded: excludedDetections.length,
      sla_scoped_detections: slaScoped.length,
      sla_dated_detections: slaDated.length,
      sla_breaches: slaBreaches.length,
      sla_compliance_percent: slaPercent,
      breaches_by_severity: breachBySeverity,
      sla_days: { critical: settings.slaCriticalDays, high: settings.slaHighDays, medium: settings.slaMediumDays },
    },
    sources: [detections, hosts],
    scope,
    manualEvidence: "run a VMDR report of open severity 3 to 5 detections with first-found dates and compute SLA adherence against the 15/30/90 day windows.",
    unknownBuckets: {
      detections_without_first_found: slaUndated.length,
      detections_without_severity: detectionsWithoutSeverity.length,
      detections_without_status: detectionsWithoutStatus.length,
    },
  }));

  const knowledgeBaseUnusable = openQids.length > 0 && !knowledgeBase.error && kbQids.size === 0;
  const patchStatus: QualysFindingStatus = detections.error || hosts.error || knowledgeBase.error || knowledgeBaseUnusable
    ? "manual"
    : !hostPopulationKnown
      ? "manual"
      : openDetections.length === 0
        ? detectionsFullyRead ? "pass" : "manual"
        : patchableDetections.length === 0
          ? "pass"
          : patchableDated.length === 0
            ? "warn"
            : overduePercent > 25
              ? "fail"
              : overduePatchable.length > 0
                ? "warn"
                : "pass";
  findings.push(guardedFinding({
    control: 11,
    severity: "high",
    status: patchStatus,
    summary: detections.error || hosts.error || knowledgeBase.error
      ? unreadableSummary(11, [detections, hosts, knowledgeBase])
      : knowledgeBaseUnusable
        ? `The knowledge base lookup returned no entries for ${openQids.length} open QIDs, so patch availability cannot be determined.`
        : !hostPopulationKnown
          ? "No host assets were returned, so patch tracking cannot be interpreted; treated as unknown, not compliant."
          : openDetections.length === 0
            ? detectionsFullyRead
              ? `Zero open detections across ${hosts.data.length} hosts with the detection list read completely, so there is no patch backlog; emptiness is compliant for this control.`
              : `Zero open detections were returned but the detection list was not read completely (${detections.truncationReason ?? "truncated"}), so emptiness cannot be trusted.`
            : patchableDetections.length === 0
              ? `Patch availability was resolved for ${kbQids.size}/${openQids.length} open QIDs and none of the ${openDetections.length} open detections has a vendor patch available.`
              : patchableDated.length === 0
                ? `${patchableDetections.length} patchable detections exist but none carries FIRST_FOUND_DATETIME, so patch age cannot be computed.`
                : `${overduePatchable.length}/${patchableDated.length} dated patchable detections (${overduePercent}%) have been open longer than ${settings.slaHighDays} days; ${patchableUndated.length} undated patchable detections were excluded from the compliant count.`,
    evidence: {
      open_qids: openQids.length,
      knowledge_base_qids: kbQids.size,
      unresolved_qids: unresolvedQids.length,
      patchable_qids: patchableQids.size,
      patchable_detections: patchableDetections.length,
      overdue_patchable_detections: overduePatchable.length,
      overdue_percent: overduePercent,
    },
    sources: [detections, hosts, knowledgeBase],
    scope,
    manualEvidence: "export the patch report for open detections and record patch availability and patch age.",
    unknownBuckets: { patchable_detections_without_first_found: patchableUndated.length, qids_without_knowledge_base_entry: unresolvedQids.length },
  }));

  const qdsStatus: QualysFindingStatus = detections.error
    ? "manual"
    : openDetections.length === 0
      ? "manual"
      : qdsPercent > 0
        ? "warn"
        : "fail";
  findings.push(guardedFinding({
    control: 17,
    severity: "medium",
    status: qdsStatus,
    summary: detections.error
      ? unreadableSummary(17, [detections])
      : openDetections.length === 0
        ? "No open detections were returned, so QDS availability cannot be confirmed; treated as unknown, not compliant."
        : `${qdsDetections.length}/${openDetections.length} open detections (${qdsPercent}%) carry a Qualys Detection Score${qdsPercent >= 90 ? ", which confirms QDS is exposed" : ""}. The triage workflow that consumes QDS or CVSS is not machine-verifiable, so the verdict is capped at warn until documented.`,
    evidence: {
      detections_with_qds: qdsDetections.length,
      open_detections: openDetections.length,
      qds_percent: qdsPercent,
    },
    sources: [detections],
    scope,
    manualEvidence: "confirm the VMDR subscription exposes Qualys Detection Scores and document the triage workflow that uses QDS or CVSS.",
  }));

  return {
    category: "vulnerability_management",
    title: "Qualys vulnerability and compliance management",
    summary: {
      platform: config.platform,
      view_scope: scope.note,
      auth_record_types: authTypes,
      compliance_policies: policies.data.length,
      hosts: hosts.data.length,
      detections_returned: detections.data.length,
      open_detections: openDetections.length,
      sla_compliance_percent: slaPercent,
      sla_breaches: slaBreaches.length,
      patchable_detections: patchableDetections.length,
      overdue_patchable_detections: overduePatchable.length,
      qds_percent: qdsPercent,
      truncated_sources: [authRecords, hosts, policies, detections, knowledgeBase].filter((source) => source.truncated).map((source) => source.name),
      collection_errors: errors.length,
    },
    findings,
    errors,
    rawData: {
      auth_records: authRecords.data,
      hosts: hosts.data,
      compliance_policies: policies.data,
      detections: detections.data,
      knowledge_base: knowledgeBase.data,
    },
  };
}

function userRoles(user: JsonRecord): string[] {
  const roleList = pathRecords(user, "roleList", "list").flatMap((entry) => asRecords(entry.RoleData ?? entry));
  const roles = roleList.map((role) => asString(role.name)).filter((name): name is string => Boolean(name));
  const legacyRole = asString(user.USER_ROLE);
  return uniqueStrings([...roles, legacyRole]);
}

function userIsManager(user: JsonRecord): boolean {
  return userRoles(user).some((role) => /^manager$|super ?user|administrator/i.test(role.trim()));
}

function userName(user: JsonRecord): string {
  return asString(user.username) ?? asString(user.USER_LOGIN) ?? asString(user.id) ?? "user";
}

function userEmail(user: JsonRecord): string | undefined {
  return (asString(user.emailAddress) ?? pathString(user, "CONTACT_INFO", "EMAIL"))?.toLowerCase();
}

// user_list_output.dtd: USER_STATUS (#PCDATA) is required; the guide documents Active, Inactive, and Pending Activation.
function legacyUserStatus(user: JsonRecord): string | undefined {
  const status = xmlScalarText(user.USER_STATUS)?.trim().toLowerCase();
  return status ? status : undefined;
}

function legacyUserIsActive(user: JsonRecord): boolean {
  return legacyUserStatus(user) === "active";
}

function legacyUserStatusMissing(user: JsonRecord): boolean {
  return legacyUserStatus(user) === undefined;
}

// user_list_output.dtd: LAST_LOGIN_DATE? is present only when the caller is a Manager or Unit Manager.
function legacyUserLastLogin(user: JsonRecord): unknown {
  return xmlScalarText(user.LAST_LOGIN_DATE);
}

function reportIsActive(report: JsonRecord): boolean {
  const flag = asBoolean(report.ACTIVE) ?? asBoolean(report.IS_ACTIVE);
  return flag !== false;
}

function reportActiveFlagMissing(report: JsonRecord): boolean {
  return asBoolean(report.ACTIVE) === undefined && asBoolean(report.IS_ACTIVE) === undefined;
}

function wasScheduleIsActive(schedule: JsonRecord): boolean {
  return asBoolean(schedule.active) === true || /^active$/i.test(asString(schedule.status) ?? "");
}

function wasScheduleFlagMissing(schedule: JsonRecord): boolean {
  return asBoolean(schedule.active) === undefined && asString(schedule.status) === undefined;
}

// wasscan.xsd: WasScanTarget carries webApp (single target) or webApps/list/WebApp (multi target).
function wasScanWebAppIds(scan: JsonRecord): string[] {
  const single = pathString(scan, "target", "webApp", "id");
  const multi = pathRecords(scan, "target", "webApps", "list")
    .flatMap((entry) => asRecords(entry.WebApp ?? entry))
    .map((webApp) => asString(webApp.id));
  return uniqueStrings([single, ...multi]);
}

function wasScanIsFinishedVulnerabilityScan(scan: JsonRecord): boolean {
  // wasscan.xsd: status enum includes FINISHED; type enum is VULNERABILITY or DISCOVERY.
  const type = asString(scan.type);
  return /^FINISHED$/i.test(asString(scan.status) ?? "") && (type === undefined || /^VULNERABILITY$/i.test(type));
}

// webapp.xsd: WebApp.lastScan is a WasScan reference carrying id and name only, so the date of the last scan
// is always resolved through the WAS scan search (launchedDate), never read from the web application record.
function webAppLastScanDate(webApp: JsonRecord, scans: JsonRecord[]): Date | undefined {
  const id = asString(webApp.id);
  if (!id) return undefined;
  const dates = scans
    .filter((scan) => wasScanIsFinishedVulnerabilityScan(scan) && wasScanWebAppIds(scan).includes(id))
    .map((scan) => parseDate(scan.launchedDate))
    .filter((date): date is Date => Boolean(date));
  if (dates.length === 0) return undefined;
  return new Date(Math.max(...dates.map((date) => date.getTime())));
}

async function collectWasScanHistory(client: QualysDataClient, webApps: Collected, wasScans: Collected, errors: string[]): Promise<Collected> {
  if (webApps.error || wasScans.error) return emptyCollected("was_scan_history");
  const unresolved = webApps.data
    .filter((webApp) => !webAppLastScanDate(webApp, wasScans.data))
    .map((webApp) => asString(webApp.id))
    .filter((id): id is string => Boolean(id));
  if (unresolved.length === 0) return emptyCollected("was_scan_history");
  return collect("was_scan_history", () => client.searchWasScanHistory(unresolved), errors, DEFAULT_LIST_LIMIT);
}

interface WebAppScanClassification {
  fresh: JsonRecord[];
  stale: JsonRecord[];
  neverScanned: JsonRecord[];
  unresolved: JsonRecord[];
}

function classifyWebAppScans(webApps: JsonRecord[], recentScans: JsonRecord[], history: Collected, now: Date, lookbackDays: number): WebAppScanClassification {
  const result: WebAppScanClassification = { fresh: [], stale: [], neverScanned: [], unresolved: [] };
  for (const webApp of webApps) {
    const recent = webAppLastScanDate(webApp, recentScans);
    const historic = recent ? undefined : webAppLastScanDate(webApp, history.data);
    const last = recent ?? historic;
    if (last && (ageInDays(last, now) ?? Number.POSITIVE_INFINITY) <= lookbackDays) {
      result.fresh.push(webApp);
    } else if (history.error || history.truncated) {
      // Rule 4: a date that could not be resolved is reported separately, never counted as fresh or as never scanned.
      result.unresolved.push(webApp);
    } else if (last) {
      result.stale.push(webApp);
    } else {
      result.neverScanned.push(webApp);
    }
  }
  return result;
}

const SENSITIVE_ACTIVITY_PATTERN = /user|delete|remove|policy|exclu|schedule|option profile|permission|role|password/i;

export async function assessQualysAdministration(
  client: QualysDataClient,
  options: QualysAssessmentOptions = {},
): Promise<QualysAssessmentResult> {
  const config = client.getResolvedConfig();
  const settings = resolveAssessmentOptions(config, options);
  const errors: string[] = [];
  const now = new Date();

  const [scheduledReports, reports, users, userList, activity, webApps, wasScans, wasAuth, wasSchedules] = await Promise.all([
    collect("scheduled_reports", () => client.listScheduledReports(), errors, DEFAULT_LIST_LIMIT),
    collect("reports", () => client.listReports(), errors, DEFAULT_LIST_LIMIT),
    collect("users", () => client.searchUsers(), errors, DEFAULT_LIST_LIMIT),
    collect("user_list", () => client.listUsers(), errors, DEFAULT_LIST_LIMIT),
    collect("activity_log", () => client.listActivityLog(settings.lookbackDays), errors, DEFAULT_LIST_LIMIT),
    collect("was_webapps", () => client.searchWebApps(), errors, DEFAULT_LIST_LIMIT),
    collect("was_scans", () => client.searchWasScans(settings.lookbackDays), errors, DEFAULT_LIST_LIMIT),
    collect("was_auth_records", () => client.searchWasAuthRecords(), errors, DEFAULT_LIST_LIMIT),
    collect("was_schedules", () => client.searchWasSchedules(), errors, DEFAULT_LIST_LIMIT),
  ]);
  const scope = resolveViewScope(config, users, activity, userList);
  const wasHistory = await collectWasScanHistory(client, webApps, wasScans, errors);

  const activeScheduledReports = scheduledReports.data.filter(reportIsActive);
  const reportsWithoutActiveFlag = scheduledReports.data.filter(reportActiveFlagMissing);
  const recentReports = reports.data.filter((report) => (ageInDays(report.LAUNCH_DATETIME, now) ?? Number.POSITIVE_INFINITY) <= settings.lookbackDays);

  // Status, role, email, and last login come from the documented User List API (user_list_output.dtd).
  // The Administration API search returns Active users only and hides other Managers, so it is only the
  // fallback for a lower-bound manager count when the User List API is not readable.
  const userListReadable = !userList.error;
  const userPopulation = userListReadable ? userList.data : users.data;
  const activeUsers = userListReadable ? userList.data.filter(legacyUserIsActive) : users.data;
  const inactiveStatusUsers = userListReadable ? userList.data.filter((user) => legacyUserStatus(user) === "inactive") : [];
  const pendingUsers = userListReadable ? userList.data.filter((user) => legacyUserStatus(user) === "pending activation") : [];
  const usersWithoutStatus = userListReadable ? userList.data.filter(legacyUserStatusMissing) : [];
  const usersWithoutRole = activeUsers.filter((user) => userRoles(user).length === 0).map(userName);
  const managers = activeUsers.filter(userIsManager).map(userName);
  const emailCounts = new Map<string, number>();
  for (const user of activeUsers) {
    const email = userEmail(user);
    if (email) emailCounts.set(email, (emailCounts.get(email) ?? 0) + 1);
  }
  const sharedEmails = [...emailCounts.entries()].filter(([, count]) => count > 1).map(([email]) => email);
  const genericAccounts = activeUsers.map(userName).filter((name) => /shared|generic|service|svc|admin\d*$|test/i.test(name));
  const usersWithLastLogin = userListReadable ? activeUsers.filter((user) => parseDate(legacyUserLastLogin(user))) : [];
  const usersWithoutLastLogin = userListReadable ? activeUsers.filter((user) => !parseDate(legacyUserLastLogin(user))) : [];
  const staleLoginUsers = usersWithLastLogin.filter((user) => (ageInDays(legacyUserLastLogin(user), now) ?? 0) > INACTIVE_USER_DAYS).map(userName);

  const sensitiveActions = activity.data.filter((entry) => SENSITIVE_ACTIVITY_PATTERN.test(`${asString(entry.action) ?? ""} ${asString(entry.module) ?? ""} ${asString(entry.details) ?? ""}`));

  const webAppScans = classifyWebAppScans(webApps.data, wasScans.data, wasHistory, now, settings.lookbackDays);
  const neverScannedWebApps = webAppScans.neverScanned.map((webApp) => recordLabel(webApp, "web app"));
  const staleWebApps = webAppScans.stale.map((webApp) => recordLabel(webApp, "web app"));
  const unresolvedWebApps = webAppScans.unresolved.map((webApp) => recordLabel(webApp, "web app"));
  const wasAuthWithoutDate = wasAuth.data.filter((record) => !parseDate(record.updatedDate ?? record.createdDate)).map((record) => recordLabel(record, "auth record"));
  const staleWasAuth = wasAuth.data.filter((record) => (ageInDays(record.updatedDate ?? record.createdDate, now) ?? -1) > STALE_WAS_AUTH_DAYS).map((record) => recordLabel(record, "auth record"));
  const activeWasSchedules = wasSchedules.data.filter(wasScheduleIsActive);
  const wasSchedulesWithoutFlag = wasSchedules.data.filter(wasScheduleFlagMissing);

  const findings: QualysFinding[] = [];

  findings.push(guardedFinding({
    control: 12,
    severity: "medium",
    status: scheduledReports.error || reports.error ? "manual" : activeScheduledReports.length === 0 ? "fail" : "warn",
    summary: scheduledReports.error || reports.error
      ? unreadableSummary(12, [scheduledReports, reports])
      : activeScheduledReports.length === 0
        ? "No active scheduled reports exist (queried with is_active=1), so automated report generation is not configured; emptiness is a failure for this control."
        : `${activeScheduledReports.length} active scheduled reports (queried with is_active=1) and ${recentReports.length} reports generated in the last ${settings.lookbackDays} days${recentReports.length === 0 ? ", so schedules exist but produced nothing in the review window" : ""}. Distribution recipients are not exposed by the API, so the verdict is capped at warn until reviewed in the UI.`,
    evidence: {
      active_scheduled_reports: activeScheduledReports.map((report) => recordLabel(report, "report")).slice(0, 50),
      scheduled_reports_without_active_flag: reportsWithoutActiveFlag.length,
      active_filter: "is_active=1",
      recent_reports: recentReports.length,
      reports_returned: reports.data.length,
    },
    sources: [scheduledReports, reports],
    scope,
    manualEvidence: "review Reports > Schedules and each schedule's distribution list for appropriate recipients.",
  }));

  const bothUserSourcesUnreadable = Boolean(userList.error && users.error);
  const excessiveManagers = managers.length > settings.maxManagers;
  const userStatusVerdict: QualysFindingStatus = bothUserSourcesUnreadable
    ? "manual"
    : excessiveManagers || sharedEmails.length > 0
      ? "fail"
      : !userListReadable
        ? "manual"
        : activeUsers.length === 0
          ? "manual"
          : staleLoginUsers.length > 0 || genericAccounts.length > 0 || pendingUsers.length > 0
            ? "warn"
            : "pass";
  const userListUnreadableNote = userList.error
    ? ` Status and last login checks require the VM/PC User List API (/msp/user_list.php, user_list_output.dtd), which was not readable (${shortenMessage(userList.error, 120)}); the Administration API search returns Active users only, hides other Manager and Super User accounts, and documents no status or last-login field, so inactive-user detection is manual and the manager count is a lower bound.`
    : "";
  findings.push(guardedFinding({
    control: 13,
    severity: "high",
    status: userStatusVerdict,
    summary: bothUserSourcesUnreadable
      ? unreadableSummary(13, [userList, users])
      : excessiveManagers || sharedEmails.length > 0
        ? `${activeUsers.length} active users include ${managers.length} Manager or super user accounts (threshold ${settings.maxManagers}) and ${sharedEmails.length} email addresses shared by multiple accounts.${userListUnreadableNote}`
        : !userListReadable
          ? `${activeUsers.length} users visible through the Administration API search, ${managers.length} Manager or super user accounts (threshold ${settings.maxManagers}), ${sharedEmails.length} shared email addresses, ${genericAccounts.length} generic-looking account names.${userListUnreadableNote}`
          : activeUsers.length === 0
            ? `The User List API returned ${userList.data.length} users but none with USER_STATUS Active, which cannot be true for a working subscription, so the API user cannot see the user population; treated as unknown, not compliant.`
            : `${activeUsers.length} Active users (USER_STATUS) of ${userList.data.length} returned by the User List API, ${inactiveStatusUsers.length} Inactive, ${pendingUsers.length} Pending Activation; ${managers.length} Manager or super user accounts (threshold ${settings.maxManagers}), ${sharedEmails.length} shared email addresses, ${genericAccounts.length} generic-looking account names, ${staleLoginUsers.length} Active users whose LAST_LOGIN_DATE is older than ${INACTIVE_USER_DAYS} days, and ${usersWithoutLastLogin.length} Active users without a LAST_LOGIN_DATE (never counted as recently active).`,
    evidence: {
      users_returned: userPopulation.length,
      user_list_users: userList.error ? undefined : userList.data.length,
      administration_api_users: users.error ? undefined : users.data.length,
      active_users: activeUsers.length,
      inactive_status_users: inactiveStatusUsers.length,
      pending_activation_users: pendingUsers.length,
      managers: managers.slice(0, 50),
      max_managers: settings.maxManagers,
      shared_emails: sharedEmails.slice(0, 50),
      generic_accounts: genericAccounts.slice(0, 50),
      stale_login_users: staleLoginUsers.slice(0, 50),
      inactive_user_days: INACTIVE_USER_DAYS,
      users_with_last_login: usersWithLastLogin.length,
      status_source: userListReadable ? "/msp/user_list.php USER_STATUS, USER_ROLE, LAST_LOGIN_DATE" : "not available",
      api_contract: "search/am/user returns Active users only, hides other Super Users and Managers, and documents no status or last-login field; /msp/user_list.php documents USER_STATUS and LAST_LOGIN_DATE (Manager and Unit Manager callers).",
    },
    sources: userListReadable ? [userList] : [userList, users],
    scope,
    manualEvidence: "export Users > User Management with roles, status, and last login dates, and reconcile the full Manager list against the approved administrator roster.",
    unknownBuckets: {
      users_without_role: usersWithoutRole.length,
      users_without_status: usersWithoutStatus.length,
      users_without_last_login: usersWithoutLastLogin.length,
    },
  }));

  const wasStatus: QualysFindingStatus = webApps.error || wasScans.error || wasAuth.error
    ? "manual"
    : webApps.data.length === 0
      ? "manual"
      : neverScannedWebApps.length > 0 || staleWebApps.length > 0
        ? "fail"
        : staleWasAuth.length > 0
          ? "warn"
          : "pass";
  findings.push(guardedFinding({
    control: 15,
    severity: "medium",
    status: wasStatus,
    summary: webApps.error || wasScans.error || wasAuth.error
      ? `${unreadableSummary(15, [webApps, wasScans, wasAuth])}${webApps.moduleUnavailable ? " The WAS module is not licensed or not enabled for this API user, so this control is not applicable unless web applications are scanned elsewhere." : ""}`
      : webApps.data.length === 0
        ? "WAS responded but no web applications are inventoried. This is not applicable if no web applications are in scope; otherwise the WAS inventory is missing. Emptiness is treated as unknown, not compliant."
        : `${webAppScans.fresh.length}/${webApps.data.length} web applications have a finished vulnerability scan (WAS scan search launchedDate) within ${settings.lookbackDays} days, ${staleWebApps.length} were last scanned before the window per the unbounded scan history, ${neverScannedWebApps.length} have no finished vulnerability scan in the fully read scan history, and ${unresolvedWebApps.length} could not be resolved because the scan history was ${wasHistory.error ? "not readable" : "truncated"} (reported, never counted as fresh or as never scanned); ${staleWasAuth.length} WAS authentication records are older than ${STALE_WAS_AUTH_DAYS} days; ${activeWasSchedules.length}/${wasSchedules.data.length} WAS schedules report an active flag.`,
    evidence: {
      web_apps: webApps.data.length,
      recently_scanned_web_apps: webAppScans.fresh.length,
      never_scanned_web_apps: neverScannedWebApps.slice(0, 50),
      stale_web_apps: staleWebApps.slice(0, 50),
      unresolved_web_apps: unresolvedWebApps.slice(0, 50),
      stale_auth_records: staleWasAuth.slice(0, 50),
      active_schedules: activeWasSchedules.length,
      schedules_returned: wasSchedules.data.length,
      scans_in_lookback: wasScans.data.length,
      scan_history_scans: wasHistory.data.length,
      last_scan_source: "WAS scan search launchedDate (webapp.xsd lastScan carries id and name only)",
    },
    sources: [webApps, wasScans, wasHistory, wasAuth, wasSchedules],
    scope,
    manualEvidence: "export the WAS web application list with last scan dates and authentication record ages, or record that no web applications are in scope.",
    unknownBuckets: {
      web_apps_without_resolved_scan_date: unresolvedWebApps.length,
      was_auth_records_without_date: wasAuthWithoutDate.length,
      was_schedules_without_active_flag: wasSchedulesWithoutFlag.length,
    },
  }));

  findings.push(guardedFinding({
    control: 19,
    severity: "medium",
    status: activity.error ? "manual" : activity.data.length === 0 ? "manual" : "warn",
    summary: activity.error
      ? unreadableSummary(19, [activity])
      : activity.data.length === 0
        ? `The activity log returned no entries for the last ${settings.lookbackDays} days, which cannot be true when this API call itself is logged, so the API user cannot read the log; treated as unknown, not compliant.`
        : `${activity.data.length} activity log entries in the last ${settings.lookbackDays} days, ${sensitiveActions.length} involve sensitive administrative actions that need reviewer sign-off. Retention and review cadence are not exposed by the API, so the verdict is capped at warn until documented.`,
    evidence: {
      entries: activity.data.length,
      sensitive_actions_count: sensitiveActions.length,
      sensitive_actions: sensitiveActions.slice(0, 50).map((entry) => ({
        date: asString(entry.date),
        action: asString(entry.action),
        module: asString(entry.module),
        user: asString(entry.user_name),
        role: asString(entry.user_role),
      })),
    },
    sources: [activity],
    scope,
    manualEvidence: "export the Activity Log for the review period and document who reviews sensitive administrative actions and how long the log is retained.",
  }));

  return {
    category: "administration",
    title: "Qualys administration and reporting hygiene",
    summary: {
      platform: config.platform,
      view_scope: scope.note,
      active_scheduled_reports: activeScheduledReports.length,
      recent_reports: recentReports.length,
      users: users.data.length,
      active_users: activeUsers.length,
      managers: managers.length,
      shared_emails: sharedEmails.length,
      activity_entries: activity.data.length,
      sensitive_actions: sensitiveActions.length,
      web_apps: webApps.data.length,
      never_scanned_web_apps: neverScannedWebApps.length,
      stale_web_apps: staleWebApps.length,
      truncated_sources: [scheduledReports, reports, users, activity, webApps, wasScans, wasAuth, wasSchedules].filter((source) => source.truncated).map((source) => source.name),
      collection_errors: errors.length,
    },
    findings,
    errors,
    rawData: {
      scheduled_reports: scheduledReports.data,
      reports: reports.data,
      users: users.data,
      activity_log: activity.data,
      was_webapps: webApps.data,
      was_scans: wasScans.data,
      was_auth_records: wasAuth.data,
      was_schedules: wasSchedules.data,
    },
  };
}

async function probeSurface(
  name: string,
  module: string,
  endpoint: string,
  load: () => Promise<unknown>,
): Promise<QualysAccessSurface> {
  try {
    const value = await load();
    const list = normalizeList(value);
    return {
      name,
      module,
      endpoint,
      status: "readable",
      count: Array.isArray(value) || asObject(value) ? list.items.length : undefined,
      ...(list.truncated ? { truncation: list.truncationReason } : {}),
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return {
      name,
      module,
      endpoint,
      status: isModuleUnavailableError(message) ? "module_unavailable" : "not_readable",
      error: message,
    };
  }
}

export async function checkQualysAccess(client: QualysDataClient & Partial<Pick<QualysApiClient, "lastRateLimit">>): Promise<QualysAccessCheckResult> {
  const config = client.getResolvedConfig();
  const scopeErrors: string[] = [];
  const users = await collect("users", () => client.searchUsers(), scopeErrors, DEFAULT_LIST_LIMIT);
  const userList = await collect("user_list", () => client.listUsers(), scopeErrors, DEFAULT_LIST_LIMIT);
  const activity = await collect("activity_log", () => client.listActivityLog(7), scopeErrors, DEFAULT_LIST_LIMIT);
  const viewScope = resolveViewScope(config, users, activity, userList);
  const surfaces: QualysAccessSurface[] = [
    await probeSurface("scheduled_scans", "VM", "/api/2.0/fo/schedule/scan/", () => client.listScheduledScans()),
    await probeSurface("hosts", "VM", "/api/2.0/fo/asset/host/", () => client.listHosts(100)),
    await probeSurface("asset_groups", "VM", "/api/2.0/fo/asset/group/", () => client.listAssetGroups()),
    await probeSurface("option_profiles", "VM", "/api/2.0/fo/subscription/option_profile/vm/", () => client.listOptionProfiles()),
    await probeSurface("appliances", "VM", "/api/2.0/fo/appliance/", () => client.listAppliances()),
    await probeSurface("auth_records", "VM", "/api/2.0/fo/auth/", () => client.listAuthRecordSummary()),
    await probeSurface("detections", "VMDR", "/api/2.0/fo/asset/host/vm/detection/", () => client.listDetections(100)),
    await probeSurface("compliance_policies", "PC", "/api/2.0/fo/compliance/policy/", () => client.listCompliancePolicies()),
    await probeSurface("activity_log", "Administration", "/api/2.0/fo/activity_log/", () => (activity.error ? Promise.reject(new Error(activity.error)) : Promise.resolve(activity.data))),
    await probeSurface("users", "Administration", "/qps/rest/2.0/search/am/user/", () => (users.error ? Promise.reject(new Error(users.error)) : Promise.resolve(users.data))),
    await probeSurface("user_list", "Administration", "/msp/user_list.php", () => (userList.error ? Promise.reject(new Error(userList.error)) : Promise.resolve(userList.data))),
    await probeSurface("tags", "Asset Management", "/qps/rest/2.0/search/am/tag", () => client.searchTags(100)),
    await probeSurface("cloud_agents", "Cloud Agent", "/qps/rest/2.0/search/am/hostasset", () => client.searchCloudAgents(100)),
    await probeSurface("connectors", "Asset Management", "/qps/rest/2.0/search/am/assetdataconnector", () => client.searchConnectors()),
    await probeSurface("was_webapps", "WAS", "/qps/rest/3.0/search/was/webapp", () => client.searchWebApps()),
  ];

  const coreModules = new Set(["VM", "VMDR"]);
  const coreSurfaces = surfaces.filter((surface) => coreModules.has(surface.module));
  const coreReadable = coreSurfaces.filter((surface) => surface.status === "readable").length;
  const unavailableModules = uniqueStrings(surfaces.filter((surface) => surface.status === "module_unavailable").map((surface) => surface.module));
  const anyFailures = surfaces.some((surface) => surface.status !== "readable");
  const status: QualysAccessCheckResult["status"] = coreReadable < coreSurfaces.length ? "limited" : anyFailures || viewScope.partial ? "degraded" : "healthy";
  const readableCount = surfaces.filter((surface) => surface.status === "readable").length;

  return {
    status,
    platform: config.platform,
    baseUrl: config.baseUrl,
    authMode: config.authMode,
    surfaces,
    unavailableModules,
    viewScope,
    rateLimit: client.lastRateLimit ?? {},
    notes: [
      `Using Qualys platform ${config.platform} at ${config.baseUrl} with ${config.authMode} authentication.`,
      `${readableCount}/${surfaces.length} Qualys audit surfaces are readable.`,
      unavailableModules.length > 0
        ? `Modules or roles not available to this account: ${unavailableModules.join(", ")}. Controls depending on them are reported as manual.`
        : "All probed modules responded.",
      viewScope.note,
    ],
    recommendedNextStep:
      status === "limited"
        ? "Grant the API user Manager or Unit Manager role with API access and confirm the VM/VMDR module subscription before running assessments."
        : "Run qualys_assess_scan_coverage, qualys_assess_asset_inventory, qualys_assess_vulnerability_management, qualys_assess_administration, or qualys_export_audit_bundle.",
  };
}

function formatAccessCheckText(result: QualysAccessCheckResult): string {
  const rows = result.surfaces.map((surface) => [
    surface.name,
    surface.module,
    surface.status,
    surface.count === undefined ? "-" : String(surface.count),
    surface.error ? surface.error.replace(/\s+/g, " ").slice(0, 80) : "",
  ]);
  return [
    `Qualys access check: ${result.status}`,
    "",
    ...result.notes,
    "",
    formatTable(["Surface", "Module", "Status", "Count", "Note"], rows),
    "",
    `Next: ${result.recommendedNextStep}`,
  ].join("\n");
}

function formatAssessmentText(result: QualysAssessmentResult): string {
  const rows = result.findings.map((item) => [
    item.id,
    item.severity.toUpperCase(),
    item.status.toUpperCase(),
    item.title,
    item.summary,
  ]);
  const summary = Object.entries(result.summary)
    .map(([key, value]) => `- ${key}: ${Array.isArray(value) ? value.join(", ") : String(value)}`)
    .join("\n");
  const lines = [result.title, "", "Summary:", summary, "", formatTable(["Control", "Severity", "Status", "Title", "Summary"], rows)];
  if (result.errors.length > 0) {
    lines.push("", "Collection warnings:", ...result.errors.map((error) => `- ${error}`));
  }
  return lines.join("\n");
}

function statusCounts(findings: QualysFinding[]): Record<QualysFindingStatus, number> {
  const counts: Record<QualysFindingStatus, number> = { pass: 0, warn: 0, fail: 0, manual: 0 };
  for (const item of findings) counts[item.status] += 1;
  return counts;
}

function buildExecutiveSummary(config: QualysResolvedConfig, assessments: QualysAssessmentResult[], errors: string[]): string {
  const findings = assessments.flatMap((assessment) => assessment.findings);
  const counts = statusCounts(findings);
  const lines = [
    "# Qualys Audit Bundle Executive Summary",
    "",
    `Platform: ${config.platform} (${config.baseUrl})`,
    `Generated: ${new Date().toISOString()}`,
    "",
    "## Result Counts",
    "",
    `- Failed controls: ${counts.fail}`,
    `- Warning controls: ${counts.warn}`,
    `- Passing controls: ${counts.pass}`,
    `- Manual controls: ${counts.manual}`,
    "",
    "## Highest Priority Findings",
    "",
  ];
  const priority = findings.filter((item) => item.status === "fail" || item.status === "warn").slice(0, 10);
  if (priority.length === 0) lines.push("- No failing or warning findings were generated.");
  for (const item of priority) lines.push(`- ${item.id} (${item.severity.toUpperCase()} / ${item.status.toUpperCase()}): ${item.summary}`);
  if (errors.length > 0) {
    lines.push("", "## Partial Collection Warnings", "", ...errors.map((error) => `- ${error}`));
  }
  return `${lines.join("\n")}\n`;
}

function buildUnifiedMatrix(findings: QualysFinding[]): string {
  const rows = findings.map((item) => `| ${item.id} | ${item.control} | ${item.title} | ${item.severity} | ${item.status} | ${item.mappings.join(", ")} |`);
  return [
    "# Qualys Unified Compliance Matrix",
    "",
    "| Finding | Control | Title | Severity | Status | Mappings |",
    "|---|---|---|---|---|---|",
    ...rows,
    "",
  ].join("\n");
}

function buildFrameworkReport(title: string, prefix: string, findings: QualysFinding[]): string {
  const rows = findings
    .map((item) => ({ item, refs: item.mappings.filter((mapping) => mapping.startsWith(prefix)).map((mapping) => mapping.slice(prefix.length)) }))
    .filter((entry) => entry.refs.length > 0)
    .map((entry) => `| ${entry.refs.join(", ")} | ${entry.item.id} | ${entry.item.title} | ${entry.item.status} | ${entry.item.summary.replace(/\|/g, "/")} |`);
  return [
    `# ${title}`,
    "",
    `| ${prefix.trim()} Reference | Finding | Title | Status | Summary |`,
    "|---|---|---|---|---|",
    ...(rows.length > 0 ? rows : ["| - | - | No findings map to this framework | - | - |"]),
    "",
  ].join("\n");
}

function buildQuickReference(): string {
  return [
    "# Qualys Audit Bundle Quick Reference",
    "",
    "- `core_data/` contains normalized snapshots of the Qualys API responses used during this assessment.",
    "- `analysis/` contains normalized findings and per-category summaries.",
    "- `compliance/` contains the executive summary, unified matrix, and per-framework reports.",
    "- `_errors.log` appears only when some reads fail but the bundle still completes.",
    "- Review manual findings before asserting framework compliance from the automated output alone.",
    "",
    "Recommended reading order:",
    "1. `compliance/executive_summary.md`",
    "2. `compliance/unified_compliance_matrix.md`",
    "3. framework-specific report matching your engagement",
    "4. `analysis/*.json` for the supporting evidence behind each finding",
    "",
    "Credentials are never written into the bundle.",
  ].join("\n");
}

function safeDirName(value: string): string {
  const normalized = value
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 80);
  return normalized || "qualys";
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
  if (relativeTarget === ".." || relativeTarget.startsWith(`..${join("/")}`) || relativeTarget.startsWith("..")) {
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

const MAX_BUNDLE_SUFFIX = 99;

export function bundleZipPath(outputDir: string): string {
  return `${outputDir}.zip`;
}

async function nextAvailableAuditDir(root: string, preferredName: string): Promise<string> {
  ensurePrivateDir(root);
  for (let index = 1; index <= MAX_BUNDLE_SUFFIX; index += 1) {
    const candidate = resolveSecureOutputPath(root, index === 1 ? preferredName : `${preferredName}-${index}`);
    if (!existsSync(candidate) && !existsSync(bundleZipPath(candidate))) {
      mkdirSync(candidate, { recursive: true, mode: 0o700 });
      await chmod(candidate, 0o700);
      return candidate;
    }
  }
  throw new Error(`Unable to allocate output directory under ${root}: ${MAX_BUNDLE_SUFFIX} prior bundles already exist`);
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

export async function exportQualysAuditBundle(
  client: QualysDataClient & Partial<Pick<QualysApiClient, "lastRateLimit">>,
  config: QualysResolvedConfig,
  outputRoot: string,
  options: QualysAssessmentOptions = {},
): Promise<QualysAuditBundleResult> {
  const access = await checkQualysAccess(client);
  const assessments = [
    await assessQualysScanCoverage(client, options),
    await assessQualysAssetInventory(client, options),
    await assessQualysVulnerabilityManagement(client, options),
    await assessQualysAdministration(client, options),
  ];
  const findings = assessments.flatMap((assessment) => assessment.findings);
  const errors = uniqueStrings(assessments.flatMap((assessment) => assessment.errors));

  ensurePrivateDir(outputRoot);
  const outputDir = await nextAvailableAuditDir(outputRoot, safeDirName(`qualys-${config.platform}-audit-bundle`));

  await writeSecureTextFile(outputDir, "QUICK_REFERENCE.md", `${buildQuickReference()}\n`);
  await writeSecureTextFile(outputDir, "metadata.json", serializeJson({
    generated_at: new Date().toISOString(),
    platform: config.platform,
    base_url: config.baseUrl,
    auth_mode: config.authMode,
    source_chain: config.sourceChain,
  }));
  await writeSecureTextFile(outputDir, "core_data/access.json", serializeJson(access));
  for (const assessment of assessments) {
    for (const [name, value] of Object.entries(assessment.rawData)) {
      await writeSecureTextFile(outputDir, `core_data/${assessment.category}/${name}.json`, serializeJson(value));
    }
    await writeSecureTextFile(outputDir, `analysis/${assessment.category}.json`, serializeJson({
      category: assessment.category,
      title: assessment.title,
      summary: assessment.summary,
      findings: assessment.findings,
      errors: assessment.errors,
    }));
  }
  await writeSecureTextFile(outputDir, "analysis/findings.json", serializeJson(findings));
  await writeSecureTextFile(outputDir, "compliance/executive_summary.md", buildExecutiveSummary(config, assessments, errors));
  await writeSecureTextFile(outputDir, "compliance/unified_compliance_matrix.md", buildUnifiedMatrix(findings));
  for (const framework of FRAMEWORKS) {
    await writeSecureTextFile(outputDir, `compliance/${framework.dir}/${framework.file}`, buildFrameworkReport(framework.title, framework.prefix, findings));
  }
  if (errors.length > 0) {
    await writeSecureTextFile(outputDir, "_errors.log", `${errors.join("\n")}\n`);
  }

  const zipPath = bundleZipPath(outputDir);
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
    username: asString(value.username),
    password: asString(value.password),
    token: asString(value.token),
    platform: asString(value.platform),
    base_url: asString(value.base_url),
    gateway_url: asString(value.gateway_url),
    use_oauth: asBoolean(value.use_oauth),
    config_file: asString(value.config_file),
    timeout_seconds: asNumber(value.timeout_seconds),
    lookback_days: asNumber(value.lookback_days),
  };
}

function normalizeAssessArgs(args: unknown): AssessArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeAuthArgs(args),
    host_limit: asNumber(value.host_limit),
    detection_limit: asNumber(value.detection_limit),
    min_auth_scan_percent: asNumber(value.min_auth_scan_percent),
    min_agent_coverage_percent: asNumber(value.min_agent_coverage_percent),
    max_managers: asNumber(value.max_managers),
    sla_critical_days: asNumber(value.sla_critical_days),
    sla_high_days: asNumber(value.sla_high_days),
    sla_medium_days: asNumber(value.sla_medium_days),
  };
}

function normalizeExportArgs(args: unknown): ExportArgs {
  const value = asObject(args) ?? {};
  return {
    ...normalizeAssessArgs(args),
    output_dir: asString(value.output_dir) ?? asString(value.output),
  };
}

function assessmentOptionsFromArgs(args: AssessArgs): QualysAssessmentOptions {
  return {
    lookbackDays: args.lookback_days,
    hostLimit: args.host_limit,
    detectionLimit: args.detection_limit,
    minAuthScanPercent: args.min_auth_scan_percent,
    minAgentCoveragePercent: args.min_agent_coverage_percent,
    maxManagers: args.max_managers,
    slaCriticalDays: args.sla_critical_days,
    slaHighDays: args.sla_high_days,
    slaMediumDays: args.sla_medium_days,
  };
}

function createClient(args: AuthArgs): QualysApiClient {
  return new QualysApiClient(resolveQualysConfiguration(args as JsonRecord));
}

const authParams = {
  username: Type.Optional(Type.String({ description: "Qualys API username. Defaults to QUALYS_USERNAME or the config file." })),
  password: Type.Optional(Type.String({ description: "Qualys API password. Defaults to QUALYS_PASSWORD or the config file." })),
  token: Type.Optional(Type.String({ description: "Pre-issued bearer token used instead of basic auth. Defaults to QUALYS_TOKEN." })),
  platform: Type.Optional(Type.String({ description: "Qualys platform ID (US1, US2, US3, US4, GOV1, EU1, EU2, EU3, IN1, CA1, AE1, UK1, AU1, KSA1), API server hostname, or https URL. Defaults to QUALYS_PLATFORM or US1." })),
  base_url: Type.Optional(Type.String({ description: "Explicit API server base URL overriding the platform mapping. Defaults to QUALYS_BASE_URL." })),
  gateway_url: Type.Optional(Type.String({ description: "API Gateway URL used only for OAuth token requests. Defaults to the platform gateway." })),
  use_oauth: Type.Optional(Type.Boolean({ description: "Request a JWT from the platform gateway /auth endpoint with the username and password. Defaults to QUALYS_USE_OAUTH." })),
  config_file: Type.Optional(Type.String({ description: "Path to a key=value or INI config file with username, password, platform. Defaults to QUALYS_CONFIG_FILE or ~/.qcrc." })),
  timeout_seconds: Type.Optional(Type.Number({ description: "HTTP timeout in seconds. Defaults to 60.", default: 60 })),
  lookback_days: Type.Optional(Type.Number({ description: "Lookback window in days for scans, reports, activity, and WAS scans. Defaults to 30.", default: 30 })),
};

const assessParams = {
  ...authParams,
  host_limit: Type.Optional(Type.Number({ description: "Maximum host assets to sample. Defaults to 5000.", default: 5000 })),
  detection_limit: Type.Optional(Type.Number({ description: "Maximum open detections to sample. Defaults to 5000.", default: 5000 })),
  min_auth_scan_percent: Type.Optional(Type.Number({ description: "Minimum acceptable authenticated scan percentage. Defaults to 80.", default: 80 })),
  min_agent_coverage_percent: Type.Optional(Type.Number({ description: "Minimum acceptable Cloud Agent coverage percentage. Defaults to 50.", default: 50 })),
  max_managers: Type.Optional(Type.Number({ description: "Maximum acceptable Manager role accounts. Defaults to 5.", default: 5 })),
  sla_critical_days: Type.Optional(Type.Number({ description: "Remediation SLA in days for severity 5 detections. Defaults to 15.", default: 15 })),
  sla_high_days: Type.Optional(Type.Number({ description: "Remediation SLA in days for severity 4 detections. Defaults to 30.", default: 30 })),
  sla_medium_days: Type.Optional(Type.Number({ description: "Remediation SLA in days for severity 3 detections. Defaults to 90.", default: 90 })),
};

function registerAssessmentTool(
  pi: any,
  name: string,
  label: string,
  description: string,
  run: (client: QualysApiClient, options: QualysAssessmentOptions) => Promise<QualysAssessmentResult>,
): void {
  pi.registerTool({
    name,
    label,
    description,
    parameters: Type.Object(assessParams),
    prepareArguments: normalizeAssessArgs,
    async execute(_toolCallId: string, args: AssessArgs) {
      try {
        const result = await run(createClient(args), assessmentOptionsFromArgs(args));
        return textResult(formatAssessmentText(result), {
          tool: name,
          category: result.category,
          title: result.title,
          summary: result.summary,
          findings: result.findings,
          errors: result.errors,
        });
      } catch (error) {
        return errorResult(
          `${label} failed: ${error instanceof Error ? error.message : String(error)}`,
          { tool: name },
        );
      }
    },
  });
}

export function registerQualysTools(pi: any): void {
  pi.registerTool({
    name: "qualys_check_access",
    label: "Check Qualys audit access",
    description:
      "Validate read-only Qualys API access across VM schedules, hosts, asset groups, option profiles, appliances, authentication records, VMDR detections, Policy Compliance, Administration users and activity log, Asset Management tags and connectors, Cloud Agent inventory, and WAS web applications. Reports missing module subscriptions or roles.",
    parameters: Type.Object(authParams),
    prepareArguments: normalizeAuthArgs,
    async execute(_toolCallId: string, args: AuthArgs) {
      try {
        const result = await checkQualysAccess(createClient(args));
        return textResult(formatAccessCheckText(result), { tool: "qualys_check_access", ...result });
      } catch (error) {
        return errorResult(
          `Qualys access check failed: ${error instanceof Error ? error.message : String(error)}`,
          { tool: "qualys_check_access" },
        );
      }
    },
  });

  registerAssessmentTool(
    pi,
    "qualys_assess_scan_coverage",
    "Assess Qualys scan coverage",
    "Assess Qualys scan schedule coverage, authenticated scan ratio, option profile hygiene, external perimeter scanning, exclusion lists, and network segmentation scanning (spec controls 1, 2, 3, 14, 16, 20).",
    (client, options) => assessQualysScanCoverage(client, options),
  );

  registerAssessmentTool(
    pi,
    "qualys_assess_asset_inventory",
    "Assess Qualys asset inventory",
    "Assess Qualys asset group completeness evidence, cloud connector health, scanner appliance health, Cloud Agent deployment coverage, and tag-based scoping (spec controls 4, 5, 6, 7, 18).",
    (client, options) => assessQualysAssetInventory(client, options),
  );

  registerAssessmentTool(
    pi,
    "qualys_assess_vulnerability_management",
    "Assess Qualys vulnerability management",
    "Assess Qualys authentication record completeness, Policy Compliance policy assignment, vulnerability SLA adherence, patch availability tracking, and QDS prioritization (spec controls 8, 9, 10, 11, 17).",
    (client, options) => assessQualysVulnerabilityManagement(client, options),
  );

  registerAssessmentTool(
    pi,
    "qualys_assess_administration",
    "Assess Qualys administration hygiene",
    "Assess Qualys scheduled reporting, user role concentration and shared accounts, WAS web application inventory freshness, and activity log review evidence (spec controls 12, 13, 15, 19).",
    (client, options) => assessQualysAdministration(client, options),
  );

  pi.registerTool({
    name: "qualys_export_audit_bundle",
    label: "Export Qualys audit bundle",
    description:
      "Export a Qualys audit package with access checks, all four assessments, raw core_data snapshots, JSON analysis, per-framework compliance reports (FedRAMP, CMMC, SOC 2, CIS, PCI-DSS, STIG, IRAP, ISMAP), a quick reference, an error log on partial collection, and a zip archive.",
    parameters: Type.Object({
      ...assessParams,
      output_dir: Type.Optional(Type.String({ description: `Output root. Defaults to ${DEFAULT_OUTPUT_DIR}.` })),
    }),
    prepareArguments: normalizeExportArgs,
    async execute(_toolCallId: string, args: ExportArgs) {
      try {
        const config = resolveQualysConfiguration(args as JsonRecord);
        const outputRoot = resolve(process.cwd(), args.output_dir?.trim() || DEFAULT_OUTPUT_DIR);
        const result = await exportQualysAuditBundle(new QualysApiClient(config), config, outputRoot, assessmentOptionsFromArgs(args));
        return textResult(
          [
            "Qualys audit bundle exported.",
            `Output dir: ${result.outputDir}`,
            `Zip archive: ${result.zipPath}`,
            `Findings: ${result.findingCount}`,
            `Files: ${result.fileCount}`,
            `Collection errors: ${result.errorCount}`,
          ].join("\n"),
          {
            tool: "qualys_export_audit_bundle",
            output_dir: result.outputDir,
            zip_path: result.zipPath,
            finding_count: result.findingCount,
            file_count: result.fileCount,
            error_count: result.errorCount,
          },
        );
      } catch (error) {
        return errorResult(
          `Qualys audit bundle export failed: ${error instanceof Error ? error.message : String(error)}`,
          { tool: "qualys_export_audit_bundle" },
        );
      }
    },
  });
}
