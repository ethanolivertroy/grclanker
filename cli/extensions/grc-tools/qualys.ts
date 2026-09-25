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
  realpathSync,
} from "node:fs";
import { chmod, readdir, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join, relative, resolve } from "node:path";
import { ZipArchive } from "archiver";
import { Type } from "@sinclair/typebox";
import { readConfigText } from "./hardening/index.js";
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
  rawData: Record<string, QualysRawDataSurface>;
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

// roles and scopeTags are null, never [], when no surface verified the API user's role.
export interface QualysViewScope {
  verified: boolean;
  partial: boolean;
  roles: string[] | null;
  scopeTags: string[] | null;
  source: "user_search" | "user_list" | "activity_log" | "unverified";
  note: string;
}

export type QualysSourceState = "readable" | "truncated" | "unreadable" | "not_collected";

// One inventory read by a finding. A read that did not happen or was denied carries count null beside a status
// that names the endpoint; a read that happened carries its count marked complete or partial.
export interface QualysSourceStatus {
  name: string;
  endpoint: string;
  status: QualysSourceState;
  count: number | null;
  count_status?: "complete" | "partial";
  cap?: number;
  reason?: string;
}

// A core_data file: the same status block as collection.sources plus the projected records, or null when the
// inventory was denied or never requested so an empty array is never mistaken for an empty inventory.
export interface QualysRawDataSurface extends QualysSourceStatus {
  records: JsonRecord[] | null;
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

function percent(part: number, total: number): number | null {
  if (total <= 0) return null;
  return Math.round((part / total) * 1000) / 10;
}

function parseDate(value: unknown): Date | undefined {
  // Resolved dates (for example the newest WAS scan launchedDate) arrive as Date instances, everything
  // read from an API response arrives as text; both must age the same way.
  if (value instanceof Date) return Number.isNaN(value.getTime()) ? undefined : value;
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

/**
 * Maps a platform setting to its API server and gateway. `source` names where the setting came from (the platform
 * argument, an environment variable, or a config file key) so an unrecognised value can be reported without echoing
 * it: such a value is outside the documented grammar by definition and may be a pasted credential.
 */
export function resolveQualysPlatform(value: string | undefined, source = "the platform value"): { platform: string; baseUrl: string; gatewayUrl: string } {
  const trimmed = (value ?? "US1").trim();
  const byId = QUALYS_PLATFORMS.find((platform) => platform.id.toLowerCase() === trimmed.toLowerCase());
  if (byId) return { platform: byId.id, baseUrl: byId.apiServer, gatewayUrl: byId.gateway };

  const unrecognised = () =>
    new Error(
      scrubErrorText(
        `Unknown Qualys platform in ${source} (the value is not repeated here). Use one of ${QUALYS_PLATFORMS.map((platform) => platform.id).join(", ")}, an API server hostname, or a full https URL.`,
      ),
    );
  const asUrl = /^https?:\/\//i.test(trimmed) ? trimmed : trimmed.includes(".") ? `https://${trimmed}` : undefined;
  if (!asUrl) throw unrecognised();
  let baseUrl: string;
  try {
    baseUrl = normalizeBaseUrl(asUrl);
  } catch {
    // The URL parser's error carries the input; neither it nor the input is echoed.
    throw unrecognised();
  }
  const host = new URL(baseUrl).host;
  const byHost = QUALYS_PLATFORMS.find((platform) => new URL(platform.apiServer).host === host);
  if (byHost) return { platform: byHost.id, baseUrl: byHost.apiServer, gatewayUrl: byHost.gateway };
  const gatewayHost = host.startsWith("qualysapi.") ? host.replace(/^qualysapi\./, "qualysgateway.") : host;
  return { platform: "custom", baseUrl, gatewayUrl: `https://${gatewayHost}` };
}

/**
 * Reads the optional key=value config file. A missing file is an empty config (the existsSync check is kept in
 * front of the read: it is the first unguarded call in every tool handler and the tests probe the handlers' catch
 * blocks through it). The read itself goes through the shared `readConfigText` guard, so any failure is a
 * `ConfigFileError` whose message is the fixed `Unable to read Qualys config file <path> (<CODE>)`, built from the
 * path and the validated system error code only; neither a Node fs message nor a non-standard thrown value's
 * `toString()` can reach it. The parser below is a hand-rolled loop that cannot throw, so it has no parse guard.
 */
export function readQualysConfigFile(pathname: string | undefined): Record<string, string> {
  if (!pathname || !existsSync(pathname)) return {};
  const read = readConfigText(pathname, { label: "Qualys" });
  if (!read.ok) return {};
  const values: Record<string, string> = {};
  for (const rawLine of read.value.split(/\r?\n/)) {
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

  // Each setting remembers where it came from, so a validation error can name the source instead of the value.
  const pick = (argKey: string, envKeys: string[], fileKeys: string[]): { value: string; source: string } | undefined => {
    const fromArgs = asString(input[argKey]);
    if (fromArgs) {
      sourceChain.push(`arguments-${argKey}`);
      return { value: fromArgs, source: `the ${argKey} argument` };
    }
    for (const envKey of envKeys) {
      const fromEnv = asString(env[envKey]);
      if (fromEnv) {
        sourceChain.push(`environment-${argKey}`);
        return { value: fromEnv, source: envKey };
      }
    }
    for (const fileKey of fileKeys) {
      const fromFile = asString(file[fileKey]);
      if (fromFile) {
        sourceChain.push(`config-file-${argKey}`);
        return { value: fromFile, source: `the config file key ${fileKey}` };
      }
    }
    return undefined;
  };

  const username = pick("username", ["QUALYS_USERNAME", "QUALYS_USER"], ["username", "user"])?.value;
  const password = pick("password", ["QUALYS_PASSWORD"], ["password"])?.value;
  const token = pick("token", ["QUALYS_TOKEN", "QUALYS_ACCESS_TOKEN"], ["token"])?.value;
  const useOauth = asBoolean(input.use_oauth) ?? asBoolean(env.QUALYS_USE_OAUTH) ?? asBoolean(file.use_oauth) ?? false;
  const platformSetting = pick("platform", ["QUALYS_PLATFORM", "QUALYS_API_SERVER"], ["platform", "hostname"]);
  const baseUrlSetting = pick("base_url", ["QUALYS_BASE_URL", "QUALYS_API_URL"], ["base_url"]);
  const gatewayOverride = pick("gateway_url", ["QUALYS_GATEWAY_URL"], ["gateway_url"])?.value;

  const platformSource = baseUrlSetting ?? platformSetting;
  const resolvedPlatform = resolveQualysPlatform(platformSource?.value, platformSource?.source);
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

// ---------------------------------------------------------------------------------------------
// Rule 9, error-body class. Every error string the client creates passes through scrubErrorText in
// the QualysApiError constructor, and a response body that is not a recognised XML or JSON error
// envelope is never echoed at all: describeOpaqueBody substitutes the content type and byte length,
// while the status and endpoint are part of every message. The rules below therefore guard the
// documented fields that are echoed (SIMPLE_RETURN CODE and TEXT, GENERIC_RETURN RETURN, the /msp/
// USER_LIST_OUTPUT ERROR text, QPS responseCode and responseErrorDetails.errorMessage) and any prose
// assembled from them. Every pattern is unanchored so an embedded URL, header, or name-value pair
// anywhere in free text is caught. The bundle writer applies the same rules once more to every file,
// without the long-token heuristic, because QIDs, asset ids, and tag ids are evidence.
// ---------------------------------------------------------------------------------------------

const REDACTED = "[REDACTED]";
// Everything from the first ? of a scheme-prefixed URL found anywhere in the text (fetch tokens, session
// parameters); the host and path stay because they name the surface.
const EMBEDDED_URL_QUERY_PATTERN = /(\b[a-z][a-z0-9+.-]*:\/\/[^\s"'<>()?#]+)\?[^\s"'<>()#]*/gi;
// A fragment carrying name=value pairs (implicit-flow tokens); plain anchors stay.
const EMBEDDED_URL_FRAGMENT_PATTERN = /(\b[a-z][a-z0-9+.-]*:\/\/[^\s"'<>()#]+#)[^\s"'<>()]*=[^\s"'<>()]*/gi;
// A plain lowercase word after the scheme ("bearer authentication", "basic auth") is prose, not a credential.
const BEARER_PATTERN = /\b([Bb]earer)\s+(?![a-z]+\b)[A-Za-z0-9._~+/=-]{8,}/g;
const BASIC_AUTH_PATTERN = /\b([Bb]asic)\s+(?![a-z]+\b)[A-Za-z0-9+/=]{16,}/g;
const COOKIE_HEADER_PATTERN = /\b(set-cookie|cookie)(["']?\s*[:=]\s*)(?!\[REDACTED\])[^\s<>"'][^\r\n<>"']*/gi;
// key=value, key: value, or "key":"value" where the key names a credential (api key, session, access, refresh, and
// id tokens, client secret, password, cookie, signature). X-Requested-With names no credential and survives; a
// short plain value such as "token: user" is prose.
const CREDENTIAL_KEY_WORDS = "token|secret|passw(?:or)?d|passcode|session|api[_-]?key|apikey|private[_-]?key|signature|credential|cookie";
const CREDENTIAL_ASSIGNMENT_PATTERN = new RegExp(
  `\\b([a-z0-9_-]*(?:${CREDENTIAL_KEY_WORDS})[a-z0-9_-]*|authorization|x-auth-token|jsessionid|pwd)(["']?\\s*[:=]\\s*)(["']?)(?!bearer\\b|basic\\b|\\[REDACTED\\])[^\\s"'<>;,&]{6,}`,
  "gi",
);
// "/", ".", ":", and "=" are not run characters, so endpoint paths, JWT segments, timestamps, and query pairs split
// into short pieces that are judged on their own; base64url and hex material never contains them.
const LONG_TOKEN_RUN_PATTERN = /[A-Za-z0-9+_-]{16,}/g;
const UPPERCASE_CODE_PATTERN = /^[A-Z][A-Z_-]*$/;
const WORD_SEGMENT_PATTERN = /^(?:[A-Z]?[a-z]+|[A-Z]+|[a-z]+(?:[A-Z][a-z]+)+)$/;

function hasTokenShape(value: string): boolean {
  return /\d/.test(value) || (/[a-z]/.test(value) && /[A-Z]/.test(value));
}

// A run of 16 or more token characters is a credential when it carries a digit or mixed case and is not made of
// words: uppercase codes and DTD element names (SCHEDULE_SCAN_LIST_OUTPUT), snake_case and camelCase identifiers
// (truncation_limit, hasMoreRecords), and Header-Style names (X-Requested-With) are left alone.
function looksLikeToken(run: string): boolean {
  if (UPPERCASE_CODE_PATTERN.test(run)) return false;
  if (run.split(/[-_]/).every((segment) => WORD_SEGMENT_PATTERN.test(segment))) return false;
  return hasTokenShape(run);
}

export interface ScrubErrorTextOptions {
  // On by default because error text is the only place a bare token can arrive; data values and the bundle sink
  // turn it off because Qualys identifiers are evidence, not secrets.
  longTokens?: boolean;
}

// Exact credential values known to this process: the configured password and token plus the derived basic string.
export function credentialValues(config: Pick<QualysResolvedConfig, "username" | "password" | "token">): string[] {
  const values = [config.password, config.token];
  if (config.username && config.password) values.push(Buffer.from(`${config.username}:${config.password}`).toString("base64"));
  return values.filter((value): value is string => typeof value === "string" && value.length >= 4);
}

export function scrubErrorText(text: string, secrets: string[] = [], options: ScrubErrorTextOptions = {}): string {
  let scrubbed = text;
  for (const secret of secrets) {
    if (secret.length >= 4) scrubbed = scrubbed.split(secret).join(REDACTED);
  }
  scrubbed = scrubbed
    .replace(EMBEDDED_URL_QUERY_PATTERN, `$1?${REDACTED}`)
    .replace(EMBEDDED_URL_FRAGMENT_PATTERN, `$1${REDACTED}`)
    .replace(BEARER_PATTERN, `$1 ${REDACTED}`)
    .replace(BASIC_AUTH_PATTERN, (match, scheme: string) => (hasTokenShape(match.slice(scheme.length)) ? `${scheme} ${REDACTED}` : match))
    .replace(COOKIE_HEADER_PATTERN, `$1$2${REDACTED}`)
    .replace(CREDENTIAL_ASSIGNMENT_PATTERN, `$1$2$3${REDACTED}`);
  if (options.longTokens === false) return scrubbed;
  return scrubbed.replace(LONG_TOKEN_RUN_PATTERN, (run) => (looksLikeToken(run) ? REDACTED : run));
}

// Data values and bundle content: every rule except the long-token heuristic (see ScrubErrorTextOptions).
function scrubDataText(text: string, secrets: string[]): string {
  return scrubErrorText(text, secrets, { longTokens: false });
}

// The one place a client error string is created. Every site that fails a request builds its message here, so
// no downstream consumer (errors arrays, collection.sources reasons, finding summaries, access.json, _errors.log,
// compliance reports) ever receives an unscrubbed string.
export class QualysApiError extends Error {
  readonly status: number;
  readonly endpoint: string;

  constructor(message: string, status: number, endpoint: string, secrets: string[] = []) {
    super(scrubErrorText(message, secrets));
    this.name = "QualysApiError";
    this.status = status;
    this.endpoint = endpoint;
  }
}

// Every thrown value that becomes a surface error string or a tool result goes through here, so a plain Error raised
// outside the client (configuration resolution, a data-client stub, a parser) gets the same treatment as a
// QualysApiError. The six tool handlers render their catch through this function and nothing else.
function errorMessage(error: unknown): string {
  return scrubErrorText(error instanceof Error ? error.message : String(error));
}

function mediaType(headers: Headers): string {
  const type = headers.get("content-type")?.split(";")[0].trim().toLowerCase();
  return type ? type : "unknown content type";
}

// What a failed response contributes to its error string when it carries no recognised envelope: the content type
// and byte length only, never the body.
function describeOpaqueBody(response: QualysHttpResponse, description: string): string {
  const bytes = Buffer.byteLength(response.text, "utf8");
  if (bytes === 0) return "empty body";
  return `${description} (${mediaType(response.headers)}; ${bytes} bytes)`;
}

// A vendor error code copied out of a response body is server-controlled text like every other field, so it is
// rendered only when the scrub with the configured secrets leaves it unchanged, it has the documented shape, and it
// is one of the codes Qualys documents; anything else renders as the fixed UnknownError. Syntax alone is not enough:
// a six-digit one-time passcode has the numeric shape and a letters-only base32 fragment has the constant shape, and
// neither is a code.
//
// Numeric codes: the VM/PC API v2 <CODE> (simple_return.dtd), the generic_return.dtd <RETURN status="FAILED"
// number="..."> attribute, and the /msp/ <ERROR number="..."> attribute (user_list_output.dtd) carry the codes of
// Appendix D of the Qualys API (VM, PC) user guide (docs.qualys.com/en/vm/qweb-all-api/appendix/appendix_d.htm),
// which states that the /msp/ Users API returns the same codes at HTTP 200, plus the three codes the guide shows
// only in samples: 1980 (record limit warning), 1982 (duplicate hosts error output), and 2010 (basic authentication
// required). Every documented code has three or four digits.
const XML_ERROR_CODE_PATTERN = /^\d{3,4}$/;
export const QUALYS_DOCUMENTED_ERROR_CODES: ReadonlySet<string> = new Set([
  "999", "1901", "1903", "1904", "1905", "1907", "1908", "1920", "1922", "1960", "1965", "1980", "1981", "1982", "1999",
  "2000", "2002", "2003", "2010", "2011", "2012",
]);
// QPS ServiceResponse responseCode: the ResponseCode enumeration of the published QPS XSDs that the WAS API method
// pages reference (<qualys_base_url>/qps/xsd/3.0/was/webapp.xsd, wasscan.xsd, wasscanschedule.xsd,
// webappauthrecord.xsd, and the rest), which the Asset Management and Tagging API samples (SUCCESS, INVALID_REQUEST)
// are drawn from. The longest constant has 29 characters.
const QPS_RESPONSE_CODE_PATTERN = /^[A-Z][A-Z_]{0,31}$/;
export const QPS_DOCUMENTED_RESPONSE_CODES: ReadonlySet<string> = new Set([
  "AUTH_CREDENTIALS_NEEDED", "CANNOT_BE_NULL", "EVALUATION_EXPIRED", "INVALID_API_VERSION", "INVALID_CREDENTIALS",
  "INVALID_PARAM", "INVALID_REQUEST", "INVALID_URL", "INVALID_XML", "JMS_SERVER_DOWN", "NOT_FOUND",
  "OPERATION_NOT_SUPPORTED", "OTHER_ERROR", "RMI_SERVER_DOWN", "STILL_PROCESSING", "SUCCESS", "UNAUTHORIZED",
  "UNAUTHORIZED_DESTINATION_APPS", "UNIDENTIFIED_PRODUCER", "UNKNOWN_OBJECT",
]);
const UNKNOWN_ERROR_CODE = "UnknownError";

// Which documented vocabulary a copied code is checked against.
type QualysVendorCodeKind = "xml" | "qps";

function documentedVendorCode(value: string, kind: QualysVendorCodeKind): boolean {
  switch (kind) {
    case "xml":
      return XML_ERROR_CODE_PATTERN.test(value) && QUALYS_DOCUMENTED_ERROR_CODES.has(value);
    case "qps":
      return QPS_RESPONSE_CODE_PATTERN.test(value) && QPS_DOCUMENTED_RESPONSE_CODES.has(value);
    default: {
      const exhaustive: never = kind;
      throw new Error(`Unhandled Qualys vendor code kind ${String(exhaustive)}`);
    }
  }
}

// The scrub with the configured secrets runs first, so a configured credential returned as a code renders the
// placeholder whatever its shape and even when it collides with a documented value; the vocabulary then keeps every
// undocumented value out of the rendered string.
export function vendorErrorCode(value: string | undefined, kind: QualysVendorCodeKind, secrets: string[] = []): string | undefined {
  const trimmed = value?.trim();
  if (!trimmed) return undefined;
  if (scrubErrorText(trimmed, secrets) !== trimmed) return UNKNOWN_ERROR_CODE;
  return documentedVendorCode(trimmed, kind) ? trimmed : UNKNOWN_ERROR_CODE;
}

// The documented error envelopes, echoing only their documented fields: SIMPLE_RETURN or GENERIC_RETURN with
// CODE and TEXT (VM/PC API v2), GENERIC_RETURN/RETURN status="FAILED" with a number attribute (generic_return.dtd),
// and a root-level ERROR with a number attribute (user_list_output.dtd and the other /msp/ outputs). Every code
// goes through vendorErrorCode with the configured secrets; the TEXT is scrubbed by the QualysApiError constructor.
function xmlErrorEnvelope(document: XmlNode, secrets: string[]): string | undefined {
  const simpleReturn = findXmlElement(document, "SIMPLE_RETURN") ?? findXmlElement(document, "GENERIC_RETURN");
  if (simpleReturn) {
    const code = vendorErrorCode(xmlText(findXmlElement(simpleReturn, "CODE")), "xml", secrets);
    const text = xmlText(findXmlElement(simpleReturn, "TEXT"));
    if (code || text) return `${code ? `code ${code}` : "error"}${text ? `: ${text}` : ""}`;
    const failed = findXmlElements(simpleReturn, "RETURN").find((node) => /^failed$/i.test(node.attributes.status ?? ""));
    if (failed) {
      const number = vendorErrorCode(failed.attributes.number, "xml", secrets);
      return `error${number ? ` ${number}` : ""}${xmlText(failed) ? `: ${xmlText(failed)}` : ""}`;
    }
  }
  const rootError = document.children.flatMap((root) => root.children).find((child) => child.name === "ERROR");
  if (rootError) {
    const number = vendorErrorCode(rootError.attributes.number, "xml", secrets);
    return `error${number ? ` ${number}` : ""}${xmlText(rootError) ? `: ${xmlText(rootError)}` : ""}`;
  }
  return undefined;
}

function parseXmlBody(text: string): XmlNode | undefined {
  if (!looksLikeXml(text)) return undefined;
  try {
    return parseXml(text);
  } catch {
    // An HTML gateway page starts with "<" but is not XML; it is described by type and length, never echoed.
    return undefined;
  }
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
    if (!/^https?:\/\//i.test(pathOrUrl)) return pathOrUrl.split("?")[0];
    try {
      return new URL(pathOrUrl).pathname;
    } catch {
      return pathOrUrl;
    }
  }

  // Exact credential values removed from every error string: the configured ones plus a gateway-issued JWT.
  private secrets(): string[] {
    return [...credentialValues(this.config), ...(this.bearerToken && this.bearerToken.length >= 4 ? [this.bearerToken] : [])];
  }

  private failure(what: string, response: Pick<QualysHttpResponse, "status">, endpoint: string, detail: string | undefined): QualysApiError {
    return new QualysApiError(`${what} failed (${response.status}) for ${endpoint}${detail ? `: ${detail}` : ""}`, response.status, endpoint, this.secrets());
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
      throw this.failure("Qualys gateway token request", response, "/auth", describeOpaqueBody(response, "error body"));
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
        throw new QualysApiError(`Qualys request to ${this.endpointLabel(url)} failed: ${message}`, 0, this.endpointLabel(url), this.secrets());
      } finally {
        clearTimeout(timeout);
      }
    }
  }

  // XML and CSV surfaces share one failure path: a documented envelope contributes its CODE and TEXT (scrubbed
  // by the constructor), anything else contributes only its content type and byte length.
  private xmlFailure(response: QualysHttpResponse, endpoint: string, document: XmlNode | undefined): QualysApiError | undefined {
    const envelope = document ? xmlErrorEnvelope(document, this.secrets()) : undefined;
    if (envelope) return this.failure("Qualys request", response, endpoint, envelope);
    if (response.status < 400) return undefined;
    return this.failure(
      "Qualys request",
      response,
      endpoint,
      describeOpaqueBody(response, document ? "XML error body without a SIMPLE_RETURN or ERROR envelope" : "non-XML error body"),
    );
  }

  async getXml(path: string, query: JsonRecord = {}): Promise<XmlNode> {
    const url = this.buildUrl(path, query);
    const response = await this.rawRequest("GET", url);
    const endpoint = this.endpointLabel(path);
    const document = parseXmlBody(response.text);
    const failure = this.xmlFailure(response, endpoint, document);
    if (failure) throw failure;
    if (!document) {
      throw new QualysApiError(`Qualys request for ${endpoint} did not return XML (${response.status}; ${describeOpaqueBody(response, "body")}).`, response.status, endpoint, this.secrets());
    }
    return document;
  }

  async getText(path: string, query: JsonRecord = {}): Promise<string> {
    const url = this.buildUrl(path, query);
    const response = await this.rawRequest("GET", url, { accept: "text/csv, application/xml" });
    const failure = this.xmlFailure(response, this.endpointLabel(path), parseXmlBody(response.text));
    if (failure) throw failure;
    return response.text;
  }

  async postQps(path: string, request: JsonRecord = {}): Promise<JsonRecord> {
    const url = this.buildUrl(path);
    const response = await this.rawRequest("POST", url, {
      body: JSON.stringify({ ServiceRequest: request }),
      contentType: "application/json",
      accept: "application/json",
    });
    const endpoint = this.endpointLabel(path);
    let payload: JsonRecord | undefined = {};
    if (response.text.trim().length > 0) {
      try {
        payload = asObject(JSON.parse(response.text));
      } catch {
        payload = undefined;
      }
      if (!payload) throw this.failure("Qualys QPS request", response, endpoint, describeOpaqueBody(response, "non-JSON error body"));
    }
    // ServiceResponse (qps/rest): only responseCode and responseErrorDetails.errorMessage are documented error fields,
    // and only those two are echoed; the code only when it is in the documented vocabulary (vendorErrorCode), the
    // message scrubbed.
    const serviceResponse = asObject(payload.ServiceResponse) ?? payload;
    const rawResponseCode = asString(serviceResponse.responseCode);
    if (response.status >= 400 || (rawResponseCode && rawResponseCode !== "SUCCESS")) {
      const responseCode = vendorErrorCode(rawResponseCode, "qps", this.secrets());
      const message = pathString(serviceResponse, "responseErrorDetails", "errorMessage");
      const detail = responseCode
        ? `responseCode ${responseCode}${message ? `: ${message}` : ""}`
        : describeOpaqueBody(response, "JSON error body without a ServiceResponse.responseCode");
      throw this.failure("Qualys QPS request", response, endpoint, detail);
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
    let hasMoreFlag: boolean | undefined;
    let pages = 0;
    while (items.length < limit && pages < maxPages) {
      const activeCriteria = [...criteria];
      if (lastId) activeCriteria.push({ field: "id", operator: "GREATER", value: lastId });
      const limitResults = Math.min(pageSize, limit - items.length);
      const request: JsonRecord = {
        preferences: {
          limitResults,
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
      // A page that fills limitResults without a hasMoreRecords flag cannot prove the population ended, so the
      // count stands in for the missing flag; only an explicit false ends paging on a full page.
      hasMoreFlag = asBoolean(response.hasMoreRecords);
      hasMore = hasMoreFlag ?? data.length >= limitResults;
      lastId = asString(response.lastId);
      if (!hasMore || !lastId || data.length === 0) break;
    }
    let truncationReason: string | undefined;
    if (hasMore && !lastId) {
      truncationReason = hasMoreFlag === undefined
        ? "a full page was returned without hasMoreRecords or lastId, so the population may continue beyond it"
        : "hasMoreRecords was true but no lastId was returned to continue paging";
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
    // auth_records.dtd: RESPONSE > AUTH_RECORDS > AUTH_<TECHNOLOGY>_IDS > ID_SET > (ID|ID_RANGE)+. The older
    // guide sample names the wrappers AUTH_<TECHNOLOGY>_RECORDS, so both suffixes normalize to the technology.
    const document = await this.getXml("/api/2.0/fo/auth/", { action: "list" });
    const container = findXmlElement(document, "AUTH_RECORDS");
    const items = container
      ? container.children
        .filter((child) => /^AUTH_.+_(IDS|RECORDS)$/.test(child.name))
        .map((child) => ({
          type: child.name.replace(/^AUTH_/, "").replace(/_(IDS|RECORDS)$/, "").toLowerCase(),
          count: idSetCount(child),
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
    const truncationReasons: string[] = [];
    let pages = 0;
    for (let index = 0; index < Math.min(unique.length, KNOWLEDGE_BASE_MAX_QIDS); index += KNOWLEDGE_BASE_QID_BATCH) {
      const batch = unique.slice(index, index + KNOWLEDGE_BASE_QID_BATCH);
      // knowledge_base_vuln_list_output.dtd: RESPONSE (DATETIME, (VULN_LIST|ID_SET)?, WARNING?) with
      // WARNING (CODE?, TEXT, URL?), so every batch follows its WARNING/URL continuation like the other lists
      // and records the page cap when the continuation cannot be followed.
      const page = await this.listXml(
        "/api/2.0/fo/knowledge_base/vuln/",
        { action: "list", details: "Basic", ids: batch.join(",") },
        "VULN",
        { limit: DEFAULT_LIST_LIMIT },
      );
      pages += page.pages;
      items.push(...page.items);
      if (page.truncationReason) truncationReasons.push(page.truncationReason);
    }
    if (unique.length > KNOWLEDGE_BASE_MAX_QIDS) {
      truncationReasons.push(`knowledge base lookup capped at ${KNOWLEDGE_BASE_MAX_QIDS} of ${unique.length} QIDs`);
    }
    return listResult(items, pages, truncationReasons.length > 0 ? uniqueStrings(truncationReasons).join("; ") : undefined);
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
    // BUSINESS_UNIT, and CONTACT_INFO/EMAIL. Errors arrive as USER_LIST_OUTPUT/ERROR with a number attribute, which
    // getXml recognises as a documented envelope.
    const document = await this.getXml("/msp/user_list.php", {});
    const output = findXmlElement(document, "USER_LIST_OUTPUT");
    if (!output) {
      throw new QualysApiError("Qualys request for /msp/user_list.php did not return USER_LIST_OUTPUT.", 200, "/msp/user_list.php", this.secrets());
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

// auth_records.dtd: ID_SET (ID|ID_RANGE)+ where an ID_RANGE is written first-last (the guide documents
// ranges such as 3000-3250), so a range counts every record it spans rather than one entry.
export function idSetCount(node: XmlNode): number {
  const singles = findXmlElements(node, "ID").length;
  const spanned = findXmlElements(node, "ID_RANGE").reduce((total, range) => {
    const match = /^\s*(\d+)\s*-\s*(\d+)\s*$/.exec(range.text);
    if (!match) return total + 1;
    const first = Number(match[1]);
    const last = Number(match[2]);
    return total + (last >= first ? last - first + 1 : 1);
  }, 0);
  return singles + spanned;
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

// Every inventory a finding can read, keyed by the source name used in collection.sources and core_data.
export const SURFACE_ENDPOINTS: Record<string, string> = {
  scheduled_scans: "/api/2.0/fo/schedule/scan/",
  scans: "/api/2.0/fo/scan/",
  hosts: "/api/2.0/fo/asset/host/",
  option_profiles: "/api/2.0/fo/subscription/option_profile/vm/",
  excluded_ips: "/api/2.0/fo/asset/excluded_ip/",
  asset_groups: "/api/2.0/fo/asset/group/",
  connectors: "/qps/rest/2.0/search/am/assetdataconnector",
  appliances: "/api/2.0/fo/appliance/",
  cloud_agents: "/qps/rest/2.0/search/am/hostasset",
  tags: "/qps/rest/2.0/search/am/tag",
  auth_records: "/api/2.0/fo/auth/",
  compliance_policies: "/api/2.0/fo/compliance/policy/",
  detections: "/api/2.0/fo/asset/host/vm/detection/",
  knowledge_base: "/api/2.0/fo/knowledge_base/vuln/",
  scheduled_reports: "/api/2.0/fo/schedule/report/",
  reports: "/api/2.0/fo/report/",
  users: "/qps/rest/2.0/search/am/user/",
  user_list: "/msp/user_list.php",
  activity_log: "/api/2.0/fo/activity_log/",
  was_webapps: "/qps/rest/3.0/search/was/webapp",
  was_scans: "/qps/rest/3.0/search/was/wasscan",
  was_scan_history: "/qps/rest/3.0/search/was/wasscan",
  was_auth_records: "/qps/rest/3.0/search/was/webappauthrecord",
  was_schedules: "/qps/rest/3.0/search/was/wasscanschedule",
  api_user: "/qps/rest/2.0/search/am/user/",
  api_user_list: "/msp/user_list.php",
};

function surfaceEndpoint(name: string): string {
  const endpoint = SURFACE_ENDPOINTS[name];
  if (!endpoint) throw new Error(`No endpoint is registered for surface ${name}`);
  return endpoint;
}

// A call that was never issued. blocked is true when an unreadable upstream inventory prevented the call, so
// values derived from it are unknown; false when nothing needed the call, so derived values stay known.
interface NotCollected {
  reason: string;
  blocked: boolean;
}

interface Collected {
  name: string;
  endpoint: string;
  data: JsonRecord[];
  error?: string;
  notCollected?: NotCollected;
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
  const endpoint = surfaceEndpoint(name);
  try {
    const list = normalizeList(await load());
    let truncationReason = list.truncationReason;
    if (!truncationReason && cap !== undefined && list.items.length >= cap) {
      truncationReason = `returned ${list.items.length} records, reaching the ${cap} record cap`;
    }
    return { name, endpoint, data: list.items, moduleUnavailable: false, truncated: Boolean(truncationReason), truncationReason, cap };
  } catch (error) {
    const message = errorMessage(error);
    errors.push(`${name}: ${message}`);
    return { name, endpoint, data: [], error: message, moduleUnavailable: isModuleUnavailableError(message), truncated: false, cap };
  }
}

function notCollected(name: string, reason: string, blockedBy?: Collected): Collected {
  return {
    name,
    endpoint: surfaceEndpoint(name),
    data: [],
    notCollected: { reason, blocked: Boolean(blockedBy) },
    moduleUnavailable: false,
    truncated: false,
  };
}

function sourceLabel(source: Collected): string {
  return `${source.name} (${source.endpoint})`;
}

function unreadableLabel(source: Collected): string {
  return `${sourceLabel(source)} was not readable (${shortenMessage(source.error ?? "", 120)})`;
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

// Rule 1 corollary and the uniform null standard: data taken from an inventory that was denied or never requested
// renders as null beside a status that names the read, never as 0, [], or {}. A Disclosed pairs a value with that
// status until the record is rendered, where it becomes `<field>` and `<field>_status`.
class Disclosed {
  constructor(readonly value: unknown, readonly status: string) {}
}

function disclosed(value: unknown, status: string): Disclosed {
  return new Disclosed(value, status);
}

function withheld(status: string): Disclosed {
  return new Disclosed(null, status);
}

function isPlainRecord(value: unknown): value is JsonRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value) && !(value instanceof Date) && !(value instanceof Disclosed);
}

function renderRecord(record: JsonRecord): JsonRecord {
  const rendered: JsonRecord = {};
  for (const [key, value] of Object.entries(record)) {
    if (value instanceof Disclosed) {
      rendered[key] = isPlainRecord(value.value) ? renderRecord(value.value) : value.value;
      rendered[`${key}_status`] = value.status;
    } else if (isPlainRecord(value)) {
      rendered[key] = renderRecord(value);
    } else {
      rendered[key] = value;
    }
  }
  return rendered;
}

// The status text for an inventory that did not deliver: unreadable, not_collected, or (when a partial read
// leaves a derived value undeterminable) unknown.
function unavailableStatus(source: Collected, truncatedIsUnknown = false): string | undefined {
  if (source.error) return `unreadable: ${unreadableLabel(source)}`;
  if (source.notCollected) return `not_collected: ${sourceLabel(source)} ${source.notCollected.reason}`;
  if (truncatedIsUnknown && source.truncated) {
    return `unknown: ${sourceLabel(source)} was read partially (${source.truncationReason ?? "truncated"}), so the value cannot be determined`;
  }
  return undefined;
}

// A call skipped because nothing needed it leaves derived values known; a denied call or one blocked by a denied
// upstream leaves them unknown.
function blocksDerivation(source: Collected, truncatedIsUnknown = false): boolean {
  return Boolean(source.error) || Boolean(source.notCollected?.blocked) || (truncatedIsUnknown && source.truncated);
}

function toSources(sources: Collected | Collected[]): Collected[] {
  return Array.isArray(sources) ? sources : [sources];
}

function withheldFor(sources: Collected | Collected[], truncatedIsUnknown = false): Disclosed | undefined {
  const statuses = toSources(sources)
    .filter((source) => blocksDerivation(source, truncatedIsUnknown))
    .map((source) => unavailableStatus(source, truncatedIsUnknown))
    .filter((status): status is string => Boolean(status));
  return statuses.length > 0 ? withheld(statuses.join("; ")) : undefined;
}

function countIfReadable(source: Collected, count: number): number | Disclosed {
  const status = unavailableStatus(source);
  return status ? withheld(status) : count;
}

function sourceCount(source: Collected): number | Disclosed {
  return countIfReadable(source, source.data.length);
}

function derivedCount(sources: Collected | Collected[], count: number): number | Disclosed {
  return withheldFor(sources) ?? count;
}

function listIfReadable<T>(sources: Collected | Collected[], list: T[], truncatedIsUnknown = false): T[] | Disclosed {
  return withheldFor(sources, truncatedIsUnknown) ?? list;
}

function objectIfReadable(sources: Collected | Collected[], value: JsonRecord): JsonRecord | Disclosed {
  return withheldFor(sources) ?? value;
}

function percentIfReadable(sources: Collected | Collected[], part: number, total: number, denominator: string): number | Disclosed {
  const blocked = withheldFor(sources);
  if (blocked) return blocked;
  const value = percent(part, total);
  return value === null ? withheld(`unknown: ratio undefined because ${denominator} is 0`) : value;
}

function describeSource(source: Collected): QualysSourceStatus {
  const base = { name: source.name, endpoint: source.endpoint };
  if (source.error) {
    return { ...base, status: "unreadable", count: null, reason: shortenMessage(source.error) };
  }
  if (source.notCollected) {
    return { ...base, status: "not_collected", count: null, reason: source.notCollected.reason };
  }
  if (source.truncated) {
    return { ...base, status: "truncated", count: source.data.length, count_status: "partial", cap: source.cap, reason: source.truncationReason };
  }
  return { ...base, status: "readable", count: source.data.length, count_status: "complete", cap: source.cap };
}

// The core_data rendering of one inventory: the status block plus projected records, or null records when the
// inventory was denied or never requested.
function exportableSurface(source: Collected): QualysRawDataSurface {
  const status = describeSource(source);
  return {
    ...status,
    records: status.status === "unreadable" || status.status === "not_collected" ? null : exportableRecords(source.name, source.data),
  };
}

function unverifiedScope(note: string): QualysViewScope {
  return { verified: false, partial: false, roles: null, scopeTags: null, source: "unverified", note };
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
  // A call blocked by an unreadable upstream is disclosed with the read it would have made; a call skipped because
  // nothing needed it is recorded in collection.sources only.
  const blocked = input.sources.filter((source) => source.notCollected?.blocked);
  if (blocked.length > 0) {
    notes.push(`Not collected: ${blocked.map((source) => `${sourceLabel(source)} ${source.notCollected?.reason ?? ""}`).join("; ")}.`);
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
  // Bucket counts describe records that were read; once any input was denied or blocked they are unknown too.
  return finding(input.control, input.severity, status, parts.join(" "), renderRecord({
    ...input.evidence,
    verdict_basis: input.status,
    manual_evidence: input.manualEvidence,
    unknown_buckets: withheldFor(input.sources) ?? Object.fromEntries(buckets),
    collection: {
      sources: input.sources.map(describeSource),
      view_scope: {
        verified: input.scope.verified,
        partial: input.scope.partial,
        roles: input.scope.roles,
        scope_tags: input.scope.scopeTags,
        source: input.scope.source,
        status: input.scope.verified ? `verified: ${input.scope.note}` : `unknown: ${input.scope.note}`,
      },
    },
  }));
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

// schedule_scan_list_output.dtd: ACTIVE (#PCDATA). The VM/PC API user guide documents 0 as a deactivated
// schedule and states that an active=1 request returns records with ACTIVE 1, 2, and 3, all active statuses.
function scheduleActiveState(schedule: JsonRecord): "active" | "inactive" | "unknown" {
  const text = xmlScalarText(schedule.ACTIVE)?.trim();
  if (text === undefined) return "unknown";
  if (text === "0") return "inactive";
  if (/^[123]$/.test(text)) return "active";
  return "unknown";
}

function scheduleIsActive(schedule: JsonRecord): boolean {
  return scheduleActiveState(schedule) === "active";
}

function scheduleActiveFlagMissing(schedule: JsonRecord): boolean {
  return scheduleActiveState(schedule) === "unknown";
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
  // schedule_scan_list_output.dtd: SCHEDULE > NEXTLAUNCH_UTC?
  return pathString(schedule, "SCHEDULE", "NEXTLAUNCH_UTC");
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

function scalarEntries(value: unknown): string[] {
  return asArray(value).map(xmlScalarText).filter((text): text is string => Boolean(text));
}

function assetGroupHasTargets(group: JsonRecord): boolean {
  // asset_group_list_output.dtd: IP_SET ((IP|IP_RANGE)+), DOMAIN_LIST (DOMAIN+), DNS_LIST (DNS+),
  // NETBIOS_LIST (NETBIOS+), HOST_IDS (#PCDATA, comma separated), EC2_IDS (#PCDATA)
  const ipSet = asObject(group.IP_SET);
  const targets = [
    ...(ipSet ? [...scalarEntries(ipSet.IP), ...scalarEntries(ipSet.IP_RANGE)] : []),
    ...scalarEntries(pathValue(group, "DOMAIN_LIST", "DOMAIN")),
    ...scalarEntries(pathValue(group, "DNS_LIST", "DNS")),
    ...scalarEntries(pathValue(group, "NETBIOS_LIST", "NETBIOS")),
    ...splitCsvText(group.HOST_IDS),
    ...splitCsvText(group.EC2_IDS),
  ];
  return targets.length > 0;
}

function addressCountForRange(range: string): number {
  const match = /^(\d+\.\d+\.\d+\.\d+)\s*-\s*(\d+\.\d+\.\d+\.\d+)$/.exec(range.trim());
  if (!match) return range.includes("/") ? 2 ** (32 - Number(range.split("/")[1] || 32)) : 1;
  const toNumber = (ip: string): number => ip.split(".").reduce((total, octet) => total * 256 + Number(octet), 0);
  return Math.max(toNumber(match[2]) - toNumber(match[1]) + 1, 1);
}

function optionProfileName(profile: JsonRecord): string {
  // option_profile_info.dtd: BASIC_INFO (ID, GROUP_NAME, ...)
  return xmlScalarText(pathValue(profile, "BASIC_INFO", "GROUP_NAME")) ?? xmlScalarText(pathValue(profile, "BASIC_INFO", "ID")) ?? "option profile";
}

function optionProfileAuthTypes(profile: JsonRecord): string[] {
  // option_profile_info.dtd: SCAN > AUTHENTICATION (#PCDATA), a comma separated list such as
  // "Windows,Unix,Oracle,Oracle Listener,SNMP,VMware,DB2,HTTP,MySQL,Sybase" in the guide sample.
  return splitCsvText(pathValue(profile, "SCAN", "AUTHENTICATION"));
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

// ---------------------------------------------------------------------------------------------
// Rule 9: audit bundles carry a per-record projection of every collected surface, never the verbatim
// API response. Each allowlist names the documented identifiers, names, statuses, dates, counts, and the
// fields the verdicts read. Passwords, activation keys and IDs, connector role ARNs and external IDs,
// authentication record values, report distribution settings, and option profile configuration are never
// listed, so an undocumented or unexpected field is dropped rather than exported.
// ---------------------------------------------------------------------------------------------

// true keeps a scalar or a DTD text node; "date" also keeps the QPS JSON date wrapper {"date": "..."}; a nested
// allowlist descends into an object (or into every element of an array) and keeps only the listed fields.
type FieldRule = true | "date" | FieldAllowlist;
type FieldAllowlist = { readonly [field: string]: FieldRule };

function isXmlTextNode(record: JsonRecord): boolean {
  return Object.keys(record).every((key) => key.startsWith("@") || key === "#text");
}

function projectScalar(value: unknown): unknown {
  if (value === null || typeof value !== "object") return value;
  // DTD scalars with attributes such as <ML_VERSION updated="no"> arrive as {"@updated", "#text"} nodes.
  return isXmlTextNode(value as JsonRecord) ? value : undefined;
}

function projectField(value: unknown, rule: FieldRule): unknown {
  if (value === undefined) return undefined;
  if (Array.isArray(value)) {
    return value.map((item) => projectField(item, rule)).filter((item) => item !== undefined);
  }
  if (rule === true) return projectScalar(value);
  if (rule === "date") {
    const wrapped = asObject(value);
    if (wrapped && !isXmlTextNode(wrapped)) {
      const date = projectScalar(wrapped.date);
      return date === undefined ? undefined : { date };
    }
    return projectScalar(value);
  }
  const record = asObject(value);
  if (!record) return undefined;
  const projected: JsonRecord = {};
  for (const [field, nested] of Object.entries(rule)) {
    const item = projectField(record[field], nested);
    if (item !== undefined) projected[field] = item;
  }
  return projected;
}

export function projectRecords(records: JsonRecord[], allowlist: FieldAllowlist): JsonRecord[] {
  return records
    .map((record) => projectField(record, allowlist))
    .filter((record): record is JsonRecord => Boolean(asObject(record)));
}

// schedule_scan_list_output.dtd and schedule_report_list_output.dtd: SCHEDULE
const SCHEDULE_PLAN_FIELDS: FieldAllowlist = {
  DAILY: true,
  WEEKLY: true,
  MONTHLY: true,
  START_DATE_UTC: true,
  START_HOUR: true,
  START_MINUTE: true,
  NEXTLAUNCH_UTC: true,
  TIME_ZONE: { TIME_ZONE_CODE: true, TIME_ZONE_DETAILS: true },
  DST_SELECTED: true,
  MAX_OCCURRENCE: true,
  END_AFTER: true,
  END_AFTER_MINS: true,
  PAUSE_AFTER_HOURS: true,
  RESUME_IN_DAYS: true,
  RESUME_IN_HOURS: true,
};

// host_list_output.dtd (details=All, show_tags=1). METADATA, CLOUD_PROVIDER_TAGS, USER_DEF, OWNER, and
// COMMENTS are free-form and are not exported.
const HOST_FIELDS: FieldAllowlist = {
  ID: true,
  ASSET_ID: true,
  IP: true,
  IPV6: true,
  TRACKING_METHOD: true,
  NETWORK_ID: true,
  DNS: true,
  DNS_DATA: { HOSTNAME: true, DOMAIN: true, FQDN: true },
  CLOUD_PROVIDER: true,
  CLOUD_SERVICE: true,
  CLOUD_RESOURCE_ID: true,
  EC2_INSTANCE_ID: true,
  NETBIOS: true,
  OS: true,
  QG_HOSTID: true,
  LAST_BOOT: true,
  FIRST_FOUND_DATE: true,
  LAST_ACTIVITY: true,
  AGENT_STATUS: true,
  CLOUD_AGENT_RUNNING_ON: true,
  TAGS: { TAG: { TAG_ID: true, NAME: true } },
  LAST_VULN_SCAN_DATETIME: true,
  LAST_VULN_SCAN_DURATION: true,
  LAST_VM_SCANNED_DATE: true,
  LAST_VM_SCANNED_DURATION: true,
  LAST_VM_AUTH_SCANNED_DATE: true,
  LAST_VM_AUTH_SCANNED_DURATION: true,
  LAST_COMPLIANCE_SCAN_DATETIME: true,
  LAST_SCAP_SCAN_DATETIME: true,
  ASSET_GROUP_IDS: true,
};

// asset_group_list_output.dtd; COMMENTS is not exported.
const ASSET_GROUP_FIELDS: FieldAllowlist = {
  ID: true,
  TITLE: true,
  OWNER_USER_ID: true,
  OWNER_UNIT_ID: true,
  OWNER_USER_NAME: true,
  NETWORK_ID: true,
  NETWORK_IDS: true,
  LAST_UPDATE: true,
  BUSINESS_IMPACT: true,
  DEFAULT_APPLIANCE_ID: true,
  APPLIANCE_IDS: true,
  IP_SET: { IP: true, IP_RANGE: true },
  DOMAIN_LIST: { DOMAIN: true },
  DNS_LIST: { DNS: true },
  NETBIOS_LIST: { NETBIOS: true },
  HOST_IDS: true,
  EC2_IDS: true,
  ASSIGNED_USER_IDS: true,
  ASSIGNED_UNIT_IDS: true,
};

// user.xsd (Administration API search/am/user)
const ADMIN_USER_FIELDS: FieldAllowlist = {
  id: true,
  username: true,
  firstName: true,
  lastName: true,
  title: true,
  emailAddress: true,
  roleList: { count: true, list: { RoleData: { id: true, name: true } } },
  scopeTags: { count: true, list: { TagData: { id: true, name: true } } },
};

const QPS_USER_REFERENCE: FieldAllowlist = { id: true, username: true, firstName: true, lastName: true };
const QPS_NAMED_REFERENCE: FieldAllowlist = { id: true, name: true };
const QPS_TAG_LIST: FieldAllowlist = { count: true, list: { Tag: QPS_NAMED_REFERENCE } };
const WAS_WEB_APP_REFERENCE: FieldAllowlist = { id: true, name: true, url: true };
const WAS_SCANNER_REFERENCE: FieldAllowlist = { type: true, friendlyName: true };

// wasscan.xsd: options, sensitiveContents, vulns, igs, and stats are not exported.
const WAS_SCAN_FIELDS: FieldAllowlist = {
  id: true,
  name: true,
  reference: true,
  type: true,
  mode: true,
  multi: true,
  progressiveScanning: true,
  target: {
    webApp: WAS_WEB_APP_REFERENCE,
    webApps: { count: true, list: { WebApp: WAS_WEB_APP_REFERENCE } },
    tags: QPS_TAG_LIST,
    scannerAppliance: WAS_SCANNER_REFERENCE,
    cancelOption: true,
    authRecord: QPS_NAMED_REFERENCE,
  },
  profile: QPS_NAMED_REFERENCE,
  launchedDate: "date",
  launchedBy: QPS_USER_REFERENCE,
  status: true,
  endScanDate: "date",
  scanDuration: true,
  summary: { crawlDuration: true, testDuration: true, linksCrawled: true, nbRequests: true, resultsStatus: true, authStatus: true, os: true },
};

const RAW_DATA_ALLOWLISTS: Record<string, FieldAllowlist> = {
  // schedule_scan_list_output.dtd; NOTIFICATIONS (custom messages and distribution) is not exported.
  scheduled_scans: {
    ID: true,
    SCAN_TYPE: true,
    ACTIVE: true,
    TITLE: true,
    CLIENT: { ID: true, NAME: true },
    USER_LOGIN: true,
    TARGET: true,
    NETWORK_ID: true,
    ISCANNER_NAME: true,
    EC2_INSTANCE: { CONNECTOR_UUID: true, EC2_ENDPOINT: true, EC2_ONLY_CLASSIC: true },
    CLOUD_DETAILS: { PROVIDER: true, CONNECTOR: { ID: true, UUID: true, NAME: true }, SCAN_TYPE: true, CLOUD_TARGET: { PLATFORM: true, REGION: { UUID: true, CODE: true, NAME: true }, VPC_SCOPE: true } },
    ASSET_GROUP_TITLE_LIST: { ASSET_GROUP_TITLE: true },
    ASSET_TAGS: {
      TAG_INCLUDE_SELECTOR: true,
      TAG_SET_INCLUDE: true,
      TAG_EXCLUDE_SELECTOR: true,
      TAG_SET_EXCLUDE: true,
      USE_IP_NT_RANGE_TAGS: true,
      USE_IP_NT_RANGE_TAGS_INCLUDE: true,
      USE_IP_NT_RANGE_TAGS_EXCLUDE: true,
    },
    EXCLUDE_IP_PER_SCAN: true,
    DEFAULT_SCANNER: true,
    USER_ENTERED_IPS: { IP: true, RANGE: { START: true, END: true } },
    ELB_DNS: { DNS: true },
    OPTION_PROFILE: { TITLE: true, DEFAULT_FLAG: true },
    PROCESSING_PRIORITY: true,
    SCHEDULE: SCHEDULE_PLAN_FIELDS,
  },
  // scan_list_output.dtd
  scans: {
    ID: true,
    REF: true,
    SCAN_TYPE: true,
    TYPE: true,
    TITLE: true,
    CLIENT: { ID: true, NAME: true },
    USER_LOGIN: true,
    LAUNCH_DATETIME: true,
    DURATION: true,
    PROCESSING_PRIORITY: true,
    PROCESSED: true,
    STATUS: { STATE: true, SUB_STATE: true },
    TARGET: true,
    ASSET_GROUP_TITLE_LIST: { ASSET_GROUP_TITLE: true },
    OPTION_PROFILE: { TITLE: true, DEFAULT_FLAG: true },
  },
  hosts: HOST_FIELDS,
  // option_profile_info.dtd: only the identity block and the settings the verdicts read (authentication types
  // and detection exclusion search lists). PASSWORD_BRUTE_FORCING, CUSTOM_HTTP_HEADER, SYSTEM_AUTH_RECORD, and
  // the rest of the configuration are never exported.
  option_profiles: {
    BASIC_INFO: { ID: true, GROUP_NAME: true, GROUP_TYPE: true, USER_ID: true, UNIT_ID: true, SUBSCRIPTION_ID: true, IS_DEFAULT: true, IS_GLOBAL: true, IS_OFFLINE_SYNCABLE: true, UPDATE_DATE: true },
    SCAN: {
      AUTHENTICATION: true,
      AUTHENTICATION_LEAST_PRIVILEGE: true,
      VULNERABILITY_DETECTION: {
        COMPLETE: true,
        RUNTIME: true,
        CUSTOM_LIST: { CUSTOM: { ID: true, TITLE: true } },
        DETECTION_INCLUDE: { BASIC_HOST_INFO_CHECKS: true, OVAL_CHECKS: true, QRDI_CHECKS: true },
        DETECTION_EXCLUDE: { CUSTOM_LIST: { CUSTOM: { ID: true, TITLE: true } } },
      },
    },
  },
  // ip_list_output.dtd: IP and IP_RANGE text with network_id and expiration_date attributes.
  excluded_ips: { type: true, value: true, network_id: true, expiration_date: true },
  asset_groups: ASSET_GROUP_FIELDS,
  // asset_data_connector.xsd plus the documented cloud account identifiers; arn, externalId, authRecord, and
  // any other credential material are not exported.
  connectors: {
    id: true,
    name: true,
    awsAccountId: true,
    subscriptionId: true,
    projectId: true,
    lastSync: "date",
    lastError: true,
    connectorState: true,
    type: true,
    serviceType: true,
    disabled: true,
    isGovCloudConfigured: true,
    isChinaConfigured: true,
    isInstantAssessmentEnabled: true,
    isSnapshotAssessmentEnabled: true,
    isAttachedToOrganization: true,
    isDeleted: true,
  },
  // appliance_list_output.dtd; ACTIVATION_CODE, INTERFACE_SETTINGS, PROXY_SETTINGS, CLOUD_INFO, VLANS,
  // STATIC_ROUTES, and COMMENTS are not exported.
  appliances: {
    ID: true,
    UUID: true,
    NAME: true,
    NETWORK_ID: true,
    SOFTWARE_VERSION: true,
    RUNNING_SLICES_COUNT: true,
    RUNNING_SCAN_COUNT: true,
    STATUS: true,
    MODEL_NUMBER: true,
    TYPE: true,
    IS_CLOUD_DEPLOYED: true,
    ML_LATEST: true,
    ML_VERSION: true,
    VULNSIGS_LATEST: true,
    VULNSIGS_VERSION: true,
    ASSET_GROUP_COUNT: true,
    ASSET_GROUP_LIST: { ASSET_GROUP: { ID: true, NAME: true } },
    ASSET_TAGS_LIST: { ASSET_TAG: { UUID: true, NAME: true } },
    LAST_UPDATED_DATE: true,
    POLLING_INTERVAL: true,
    USER_LOGIN: true,
    HEARTBEATS_MISSED: true,
    SS_CONNECTION: true,
    SS_LAST_CONNECTED: true,
    UPDATED: true,
    MAX_CAPACITY_UNITS: true,
  },
  // hostasset.xsd with agent_source.xsd; activationKey keeps its title only, never the activationId.
  cloud_agents: {
    id: true,
    name: true,
    created: "date",
    modified: "date",
    type: true,
    qwebHostId: true,
    trackingMethod: true,
    fqdn: true,
    dnsHostName: true,
    netbiosName: true,
    os: true,
    address: true,
    lastVulnScan: "date",
    lastComplianceScan: "date",
    lastSystemBoot: "date",
    criticalityScore: true,
    agentInfo: {
      agentVersion: true,
      agentId: true,
      status: true,
      lastCheckedIn: "date",
      platform: true,
      activatedModule: true,
      chirpStatus: true,
      manifestVersion: { vm: true, pc: true, sca: true },
      agentConfiguration: QPS_NAMED_REFERENCE,
      activationKey: { title: true },
    },
    tags: QPS_TAG_LIST,
  },
  // tag.xsd; ruleText and description are free-form configuration and are not exported.
  tags: {
    id: true,
    name: true,
    created: "date",
    modified: "date",
    ruleType: true,
    color: true,
    parentTagId: true,
    criticalityScore: true,
    provider: true,
    srcAssetGroupId: true,
    srcBusinessUnitId: true,
    srcOperatingSystemName: true,
  },
  // Summary rows built from auth_records.dtd ID_SET counts.
  auth_records: { type: true, count: true },
  // policy_list_output.dtd (details=Basic)
  compliance_policies: {
    ID: true,
    TITLE: true,
    CREATED: { DATETIME: true, BY: true },
    LAST_MODIFIED: { DATETIME: true, BY: true },
    LAST_EVALUATED: { DATETIME: true },
    STATUS: true,
    IS_LOCKED: true,
    EVALUATE_NOW: true,
    ASSET_GROUP_IDS: true,
    TAG_SET_INCLUDE: { TAG_ID: true },
    TAG_INCLUDE_SELECTOR: true,
    TAG_SET_EXCLUDE: { TAG_ID: true },
    TAG_EXCLUDE_SELECTOR: true,
    INCLUDE_AGENT_IPS: true,
  },
  // host_list_vm_detection_output.dtd flattened with host_id and ip; RESULTS (scanner output) is not exported.
  detections: {
    host_id: true,
    ip: true,
    UNIQUE_VULN_ID: true,
    QID: true,
    TYPE: true,
    SEVERITY: true,
    PORT: true,
    PROTOCOL: true,
    FQDN: true,
    SSL: true,
    INSTANCE: true,
    STATUS: true,
    FIRST_FOUND_DATETIME: true,
    LAST_FOUND_DATETIME: true,
    QDS: true,
    TIMES_FOUND: true,
    LAST_TEST_DATETIME: true,
    LAST_UPDATE_DATETIME: true,
    LAST_FIXED_DATETIME: true,
    LAST_PROCESSED_DATETIME: true,
    IS_IGNORED: true,
    IS_DISABLED: true,
    AFFECT_RUNNING_KERNEL: true,
    AFFECT_RUNNING_SERVICE: true,
    AFFECT_EXPLOITABLE_CONFIG: true,
  },
  // knowledge_base_vuln_list_output.dtd (details=Basic); DIAGNOSIS, CONSEQUENCE, and SOLUTION text is not exported.
  knowledge_base: {
    QID: true,
    VULN_TYPE: true,
    SEVERITY_LEVEL: true,
    TITLE: true,
    CATEGORY: true,
    LAST_SERVICE_MODIFICATION_DATETIME: true,
    PUBLISHED_DATETIME: true,
    PATCHABLE: true,
    PCI_FLAG: true,
    IS_DISABLED: true,
    DISCOVERY: { REMOTE: true, AUTH_TYPE_LIST: { AUTH_TYPE: true } },
    CVE_LIST: { CVE: { ID: true, URL: true } },
    CVSS: { BASE: true, TEMPORAL: true, VECTOR_STRING: true },
    CVSS_V3: { BASE: true, TEMPORAL: true, VECTOR_STRING: true, CVSS3_VERSION: true },
    THREAT_INTELLIGENCE: { THREAT_INTEL: true },
  },
  // schedule_report_list_output.dtd; any distribution or recipient element is not exported.
  scheduled_reports: {
    ID: true,
    TITLE: true,
    OUTPUT_FORMAT: true,
    TEMPLATE_TITLE: true,
    ACTIVE: true,
    SCHEDULE: SCHEDULE_PLAN_FIELDS,
  },
  // report_list_output.dtd
  reports: {
    ID: true,
    TITLE: true,
    TYPE: true,
    USER_LOGIN: true,
    LAUNCH_DATETIME: true,
    OUTPUT_FORMAT: true,
    SIZE: true,
    STATUS: { STATE: true, MESSAGE: true, PERCENT: true },
    EXPIRATION_DATETIME: true,
  },
  users: ADMIN_USER_FIELDS,
  // user_list_output.dtd; postal address and phone contact details are not exported.
  user_list: {
    USER_LOGIN: true,
    USER_ID: true,
    EXTERNAL_ID: true,
    CONTACT_INFO: { FIRSTNAME: true, LASTNAME: true, TITLE: true, EMAIL: true, COMPANY: true, COUNTRY: true, TIME_ZONE_CODE: true },
    ASSIGNED_ASSET_GROUPS: { ASSET_GROUP_TITLE: true },
    USER_STATUS: true,
    CREATION_DATE: true,
    LAST_LOGIN_DATE: true,
    USER_ROLE: true,
    BUSINESS_UNIT: true,
    UNIT_MANAGER_POC: true,
    MANAGER_POC: true,
  },
  // Activity Log CSV columns.
  activity_log: { date: true, action: true, module: true, details: true, user_name: true, user_role: true, user_ip: true },
  // webapp.xsd; headers, proxy, config, crawlingScripts, authRecords values, and screenshot are not exported.
  was_webapps: {
    id: true,
    name: true,
    url: true,
    os: true,
    owner: QPS_USER_REFERENCE,
    scope: true,
    tags: QPS_TAG_LIST,
    defaultProfile: QPS_NAMED_REFERENCE,
    defaultScanner: WAS_SCANNER_REFERENCE,
    scannerLocked: true,
    progressiveScanning: true,
    authRecords: { count: true, list: { WebAppAuthRecord: QPS_NAMED_REFERENCE } },
    useRobots: true,
    useSitemap: true,
    malwareMonitoring: true,
    isScheduled: true,
    lastScan: QPS_NAMED_REFERENCE,
    lastScanStatus: true,
    riskScore: true,
    createdBy: QPS_USER_REFERENCE,
    createdDate: "date",
    updatedBy: QPS_USER_REFERENCE,
    updatedDate: "date",
  },
  was_scans: WAS_SCAN_FIELDS,
  was_scan_history: WAS_SCAN_FIELDS,
  // webappauthrecord.xsd: form field values, server record credentials, OAuth2 client secrets and tokens,
  // selenium scripts, certificates, and auth vault details are not exported.
  was_auth_records: {
    id: true,
    name: true,
    owner: QPS_USER_REFERENCE,
    formRecord: {
      type: true,
      sslOnly: true,
      fields: { count: true, list: { WebAppAuthFormRecordField: { id: true, name: true, secured: true } } },
    },
    serverRecord: {
      type: true,
      sslOnly: true,
      fields: { count: true, list: { WebAppAuthServerRecordField: { id: true, type: true, domain: true } } },
    },
    oauth2Record: { grantType: true },
    tags: QPS_TAG_LIST,
    createdBy: QPS_USER_REFERENCE,
    createdDate: "date",
    updatedBy: QPS_USER_REFERENCE,
    updatedDate: "date",
  },
  // wasscanschedule.xsd; notification recipients and proxy settings are not exported.
  was_schedules: {
    id: true,
    name: true,
    type: true,
    active: true,
    multi: true,
    progressiveScanning: true,
    target: {
      webApp: WAS_WEB_APP_REFERENCE,
      webApps: { count: true, list: { WebApp: WAS_WEB_APP_REFERENCE } },
      tags: QPS_TAG_LIST,
      scannerAppliance: WAS_SCANNER_REFERENCE,
      cancelOption: true,
      authRecord: QPS_NAMED_REFERENCE,
    },
    profile: QPS_NAMED_REFERENCE,
    schedule: { startDate: "date", timeZone: { code: true, offset: true }, occurrenceType: true, occurrenceCount: true },
    launchedCount: true,
    launchedDate: "date",
    nextLaunchDate: "date",
    owner: QPS_USER_REFERENCE,
    createdBy: QPS_USER_REFERENCE,
    createdDate: "date",
    updatedBy: QPS_USER_REFERENCE,
    updatedDate: "date",
  },
};

export function exportableRecords(name: string, records: JsonRecord[]): JsonRecord[] {
  const allowlist = RAW_DATA_ALLOWLISTS[name];
  if (!allowlist) {
    throw new Error(`No rawData allowlist is defined for surface ${name}; refusing to export verbatim records.`);
  }
  return projectRecords(records, allowlist);
}

export function rawDataSurfaceNames(): string[] {
  return Object.keys(RAW_DATA_ALLOWLISTS);
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
  const authPercentEvidence = percentIfReadable(hosts, authScannedHosts.length, scannedHosts.length, "scanned_hosts");

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
      active_schedules: countIfReadable(schedules, activeSchedules.length),
      total_schedules: sourceCount(schedules),
      schedules_without_active_flag: countIfReadable(schedules, schedulesWithoutActiveFlag.length),
      finished_scans_in_lookback: countIfReadable(scans, finishedScans.length),
      asset_groups: sourceCount(groups),
      asset_groups_without_schedule: listIfReadable([groups, schedules], groupsWithoutSchedule.slice(0, 50)),
      hosts: sourceCount(hosts),
      stale_scanned_hosts: countIfReadable(hosts, staleScannedHosts.length),
      hosts_without_scan_date: countIfReadable(hosts, hostsWithoutScanDate.length),
      next_launches: listIfReadable(schedules, activeSchedules.map(scheduleNextLaunch).filter(Boolean).slice(0, 20)),
    },
    // The finished scan count is read from the scan list, so that inventory is a source of this finding too.
    sources: [schedules, scans, groups, hosts],
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
        : (authPercent ?? 0) >= settings.minAuthScanPercent
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
      hosts: sourceCount(hosts),
      scanned_hosts: countIfReadable(hosts, scannedHosts.length),
      authenticated_hosts: countIfReadable(hosts, authScannedHosts.length),
      authenticated_percent: authPercentEvidence,
      threshold_percent: settings.minAuthScanPercent,
      hosts_without_scan_date: countIfReadable(hosts, hostsWithoutScanDate.length),
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
      option_profiles: listIfReadable(profiles, profiles.data.map(optionProfileName).slice(0, 50)),
      profiles_without_authentication: listIfReadable(profiles, profilesWithoutAuth.slice(0, 50)),
      authentication_types: objectIfReadable(profiles, Object.fromEntries(profiles.data.slice(0, 50).map((profile) => [optionProfileName(profile), optionProfileAuthTypes(profile)]))),
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
      active_schedules: countIfReadable(schedules, activeSchedules.length),
      external_schedules: listIfReadable(schedules, externalSchedules.map((schedule) => recordLabel(schedule, "schedule")).slice(0, 50)),
      schedules_without_scanner_name: listIfReadable(schedules, schedulesWithoutScannerName.map((schedule) => recordLabel(schedule, "schedule")).slice(0, 50)),
      scanners_in_use: listIfReadable(schedules, distinctScanners.slice(0, 50)),
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
      excluded_entries: listIfReadable(excluded, excluded.data.slice(0, 100)),
      broad_exclusions: listIfReadable(excluded, broadExclusions.slice(0, 50)),
      option_profiles_reviewed: sourceCount(profiles),
      option_profile_detection_exclusions: countIfReadable(profiles, excludedQidCount),
      option_profile_exclusion_lists: listIfReadable(profiles, profiles.data.flatMap(optionProfileExclusionLists).slice(0, 50)),
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
      active_schedules: countIfReadable(schedules, activeSchedules.length),
      distinct_targets: listIfReadable(schedules, distinctTargets.slice(0, 50)),
      distinct_scanners: listIfReadable(schedules, distinctScanners.slice(0, 50)),
      schedules_without_scanner_name: countIfReadable(schedules, schedulesWithoutScannerName.length),
    },
    sources: [schedules],
    scope,
    manualEvidence: "document which scan schedules cover DMZ, internal, and OT/ICS segments and which scanner appliances serve each segment.",
  }));

  return {
    category: "scan_coverage",
    title: "Qualys scan coverage and cadence",
    summary: renderRecord({
      platform: config.platform,
      lookback_days: settings.lookbackDays,
      view_scope: scope.note,
      active_schedules: countIfReadable(schedules, activeSchedules.length),
      finished_scans_in_lookback: countIfReadable(scans, finishedScans.length),
      hosts: sourceCount(hosts),
      hosts_without_scan_date: countIfReadable(hosts, hostsWithoutScanDate.length),
      stale_scanned_hosts: countIfReadable(hosts, staleScannedHosts.length),
      authenticated_percent: authPercentEvidence,
      option_profiles: sourceCount(profiles),
      excluded_entries: sourceCount(excluded),
      external_schedules: countIfReadable(schedules, externalSchedules.length),
      truncated_sources: [schedules, scans, hosts, profiles, excluded, groups].filter((source) => source.truncated).map((source) => source.name),
      collection_errors: errors.length,
    }),
    findings,
    errors,
    rawData: Object.fromEntries([schedules, scans, hosts, profiles, excluded, groups].map((source) => [source.name, exportableSurface(source)])),
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
  // asset_data_connector.xsd: connectorState (AssetDataConnectorState enum), lastSync (dateTime), lastError, disabled
  return (asString(connector.connectorState) ?? "unknown").toUpperCase();
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

type VersionState = "current" | "outdated" | "unknown";

// appliance_list_output.dtd: ML_LATEST?, ML_VERSION? with attribute updated, VULNSIGS_LATEST?, VULNSIGS_VERSION?
// with attribute updated. The guide sample shows an offline appliance as <ML_VERSION updated="no"></ML_VERSION>,
// so the version text is compared with the latest release first and the updated attribute decides when the
// text is empty. SOFTWARE_VERSION is the appliance software build and is never compared with ML_LATEST.
function versionPairState(versionValue: unknown, latestValue: unknown): VersionState {
  const version = xmlScalarText(versionValue);
  const latest = xmlScalarText(latestValue);
  if (version && latest) return version === latest ? "current" : "outdated";
  const updated = asBoolean(asObject(versionValue)?.["@updated"]);
  if (updated === false) return "outdated";
  if (updated === true) return "current";
  return "unknown";
}

function applianceVersionState(appliance: JsonRecord): VersionState {
  const states = [
    versionPairState(appliance.ML_VERSION, appliance.ML_LATEST),
    versionPairState(appliance.VULNSIGS_VERSION, appliance.VULNSIGS_LATEST),
  ];
  if (states.includes("outdated")) return "outdated";
  if (states.includes("unknown")) return "unknown";
  return "current";
}

function applianceMissedHeartbeats(appliance: JsonRecord): number {
  return asNumber(appliance.HEARTBEATS_MISSED) ?? 0;
}

function applianceIsOutdated(appliance: JsonRecord): boolean {
  return applianceMissedHeartbeats(appliance) > 0 || applianceVersionState(appliance) === "outdated";
}

function applianceVersionUnknown(appliance: JsonRecord): boolean {
  return applianceVersionState(appliance) === "unknown";
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
  const appliancesWithoutVersionData = appliances.data.filter((appliance) => !applianceIsOffline(appliance) && !applianceIsOutdated(appliance) && applianceVersionUnknown(appliance));
  const agentHosts = hosts.data.filter(hostIsAgentTracked);
  const hostsWithoutTrackingMethod = hosts.data.filter((host) => hostTrackingMethod(host) === "");
  const agentPercent = percent(agentHosts.length, hosts.data.length);
  const agentPercentEvidence = percentIfReadable(hosts, agentHosts.length, hosts.data.length, "hosts");
  const inactiveAgents = agents.data.filter((agent) => /INACTIVE|UNINSTALL/.test(agentStatus(agent)));
  const unknownStatusAgents = agents.data.filter(agentStatusUnknown);
  const agentsWithoutCheckIn = agents.data.filter((agent) => !parseDate(agentLastCheckIn(agent)));
  const agentsWithoutActivationKey = agents.data.filter((agent) => !agentHasActivationKey(agent));
  const staleAgents = agents.data.filter((agent) => (ageInDays(agentLastCheckIn(agent), now) ?? -1) > STALE_AGENT_DAYS);
  const untaggedHosts = hosts.data.filter((host) => hostTags(host).length === 0);
  const untaggedPercent = percent(untaggedHosts.length, hosts.data.length);
  const untaggedPercentEvidence = percentIfReadable(hosts, untaggedHosts.length, hosts.data.length, "hosts");
  // tag.xsd: ruleType is a TagRuleType enum whose values include STATIC; only the other values are rule based.
  const dynamicTags = tags.data.filter((tag) => {
    const ruleType = asString(tag.ruleType);
    return Boolean(ruleType) && !/^STATIC$/i.test(ruleType ?? "");
  });

  const findings: QualysFinding[] = [];

  findings.push(guardedFinding({
    control: 4,
    severity: "medium",
    status: "manual",
    summary: `Qualys exposes ${groups.data.length} asset groups and ${hosts.data.length} host assets, but the API cannot compare them against the authoritative CMDB or network range register, so this control is always manual. Investigate ${emptyGroups.length} asset groups without targets and ${neverScannedHosts.length} hosts that were never scanned.`,
    evidence: {
      asset_groups: sourceCount(groups),
      asset_groups_without_targets: listIfReadable(groups, emptyGroups.slice(0, 50)),
      hosts: sourceCount(hosts),
      hosts_never_scanned: countIfReadable(hosts, neverScannedHosts.length),
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
      connectors: listIfReadable(connectors, connectors.data.map((connector) => ({
        name: asString(connector.name),
        type: asString(connector.type),
        state: connectorState(connector),
        last_sync: asString(connector.lastSync),
        last_error: asString(connector.lastError),
      })).slice(0, 100)),
      unhealthy_connectors: countIfReadable(connectors, unhealthyConnectors.length),
      stale_connectors: countIfReadable(connectors, staleConnectors.length),
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
            ? `${outdatedAppliances.length}/${appliances.data.length} scanner appliances missed heartbeats (HEARTBEATS_MISSED) or run a scanner (ML_VERSION versus ML_LATEST) or signature (VULNSIGS_VERSION versus VULNSIGS_LATEST) release behind the latest.`
            : `All ${appliances.data.length} scanner appliances report an online STATUS, zero missed heartbeats, and ML_VERSION and VULNSIGS_VERSION equal to ML_LATEST and VULNSIGS_LATEST.`,
    evidence: {
      appliances: listIfReadable(appliances, appliances.data.map((appliance) => ({
        name: xmlScalarText(appliance.NAME),
        appliance_status: applianceStatus(appliance),
        software_version: xmlScalarText(appliance.SOFTWARE_VERSION),
        ml_version: xmlScalarText(appliance.ML_VERSION),
        ml_latest: xmlScalarText(appliance.ML_LATEST),
        vulnsigs_version: xmlScalarText(appliance.VULNSIGS_VERSION),
        vulnsigs_latest: xmlScalarText(appliance.VULNSIGS_LATEST),
        version_state: applianceVersionState(appliance),
        heartbeats_missed: asNumber(appliance.HEARTBEATS_MISSED) ?? null,
        last_updated: xmlScalarText(appliance.LAST_UPDATED_DATE),
      })).slice(0, 100)),
      offline_appliances: countIfReadable(appliances, offlineAppliances.length),
      outdated_appliances: countIfReadable(appliances, outdatedAppliances.length),
      version_comparison: "ML_VERSION against ML_LATEST and VULNSIGS_VERSION against VULNSIGS_LATEST (appliance_list_output.dtd); SOFTWARE_VERSION is reported only",
    },
    sources: [appliances],
    scope,
    manualEvidence: "review Scans > Appliances for offline scanners, missed heartbeats, and outdated software or signature versions.",
    unknownBuckets: { appliances_without_status: unknownStatusAppliances.length, appliances_without_version_data: appliancesWithoutVersionData.length },
  }));

  const agentCoverageStatus: QualysFindingStatus = hosts.error || agents.error
    ? "manual"
    : hosts.data.length === 0
      ? "manual"
      : (agentPercent ?? 0) >= settings.minAgentCoveragePercent && inactiveAgents.length === 0 && staleAgents.length === 0
        ? "pass"
        : (agentPercent ?? 0) >= settings.minAgentCoveragePercent
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
      agent_tracked_hosts: countIfReadable(hosts, agentHosts.length),
      hosts: sourceCount(hosts),
      agent_coverage_percent: agentPercentEvidence,
      threshold_percent: settings.minAgentCoveragePercent,
      cloud_agents: sourceCount(agents),
      inactive_agents: countIfReadable(agents, inactiveAgents.length),
      stale_agents: countIfReadable(agents, staleAgents.length),
      agents_without_activation_key: countIfReadable(agents, agentsWithoutActivationKey.length),
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
        : (untaggedPercent ?? 0) > 20
          ? "fail"
          : (untaggedPercent ?? 0) > 0
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
      tags: sourceCount(tags),
      dynamic_tags: countIfReadable(tags, dynamicTags.length),
      hosts: sourceCount(hosts),
      untagged_hosts: countIfReadable(hosts, untaggedHosts.length),
      untagged_percent: untaggedPercentEvidence,
      tag_names: listIfReadable(tags, tags.data.map((tag) => asString(tag.name)).filter(Boolean).slice(0, 100)),
    },
    sources: [tags, hosts],
    scope,
    manualEvidence: "export the tag tree and confirm every in-scope asset carries a compliance scope tag.",
  }));

  return {
    category: "asset_inventory",
    title: "Qualys asset inventory and sensors",
    summary: renderRecord({
      platform: config.platform,
      view_scope: scope.note,
      asset_groups: sourceCount(groups),
      hosts: sourceCount(hosts),
      hosts_never_scanned: countIfReadable(hosts, neverScannedHosts.length),
      connectors: sourceCount(connectors),
      unhealthy_connectors: countIfReadable(connectors, unhealthyConnectors.length),
      appliances: sourceCount(appliances),
      offline_appliances: countIfReadable(appliances, offlineAppliances.length),
      agent_coverage_percent: agentPercentEvidence,
      cloud_agents: sourceCount(agents),
      tags: sourceCount(tags),
      untagged_percent: untaggedPercentEvidence,
      truncated_sources: [groups, hosts, connectors, appliances, agents, tags].filter((source) => source.truncated).map((source) => source.name),
      collection_errors: errors.length,
    }),
    findings,
    errors,
    rawData: Object.fromEntries([groups, hosts, connectors, appliances, agents, tags].map((source) => [source.name, exportableSurface(source)])),
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
  // policy_list_output.dtd: STATUS? (#PCDATA); the guide sample carries <STATUS><![CDATA[active]]></STATUS>.
  // No IS_ACTIVE element exists on a compliance policy, so only STATUS is read.
  const status = xmlScalarText(policy.STATUS)?.trim().toLowerCase();
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
  // The knowledge base is looked up only for open QIDs, so without a readable detection list the call never happens
  // and its status says so instead of claiming a readable, empty knowledge base.
  const knowledgeBase = detections.error
    ? notCollected("knowledge_base", `was not called because ${unreadableLabel(detections)}`, detections)
    : openQids.length > 0
      ? await collect("knowledge_base", () => client.listKnowledgeBase(openQids), errors)
      : notCollected("knowledge_base", `was not called because ${sourceLabel(detections)} returned no open detections with a QID`);

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
  const authScannedPercentEvidence = percentIfReadable(hosts, authScannedHosts.length, scannedHosts.length, "scanned_hosts");

  const inactivePolicies = policies.data.filter((policy) => policyStatus(policy) === "inactive").map((policy) => recordLabel(policy, "policy"));
  const unknownStatusPolicies = policies.data.filter((policy) => policyStatus(policy) === "unknown").map((policy) => recordLabel(policy, "policy"));
  const unassignedPolicies = policies.data.filter((policy) => policyIsActive(policy) && !policyIsAssigned(policy)).map((policy) => recordLabel(policy, "policy"));
  const hiddenAssignmentPolicies = policies.data.filter(policyHasHiddenAssetGroups).map((policy) => recordLabel(policy, "policy"));

  const slaScoped = openDetections.filter((detection) => detectionSlaDays(detection, settings) !== undefined);
  const slaDated = slaScoped.filter((detection) => detectionAgeDays(detection, now) !== undefined);
  const slaUndated = slaScoped.filter((detection) => detectionAgeDays(detection, now) === undefined);
  const slaBreaches = slaDated.filter((detection) => (detectionAgeDays(detection, now) ?? 0) > (detectionSlaDays(detection, settings) ?? 0));
  const slaPercent = percent(slaDated.length - slaBreaches.length, slaDated.length);
  const slaPercentEvidence = percentIfReadable(detections, slaDated.length - slaBreaches.length, slaDated.length, "sla_dated_detections");
  const breachBySeverity = objectIfReadable(detections, {
    critical: slaBreaches.filter((detection) => detectionSeverity(detection) >= 5).length,
    high: slaBreaches.filter((detection) => detectionSeverity(detection) === 4).length,
    medium: slaBreaches.filter((detection) => detectionSeverity(detection) === 3).length,
  });

  const patchableQids = new Set(knowledgeBase.data.filter((vuln) => asBoolean(vuln.PATCHABLE) === true).map((vuln) => asString(vuln.QID)).filter(Boolean));
  const kbQids = new Set(knowledgeBase.data.map((vuln) => asString(vuln.QID)).filter(Boolean));
  const unresolvedQids = openQids.filter((qid) => !kbQids.has(qid));
  const patchableDetections = openDetections.filter((detection) => patchableQids.has(asString(detection.QID)));
  const patchableDated = patchableDetections.filter((detection) => detectionAgeDays(detection, now) !== undefined);
  const patchableUndated = patchableDetections.filter((detection) => detectionAgeDays(detection, now) === undefined);
  const overduePatchable = patchableDated.filter((detection) => (detectionAgeDays(detection, now) ?? 0) > settings.slaHighDays);
  const overduePercent = percent(overduePatchable.length, patchableDated.length);
  const overduePercentEvidence = percentIfReadable([detections, knowledgeBase], overduePatchable.length, patchableDated.length, "dated_patchable_detections");

  const qdsDetections = openDetections.filter(detectionHasQds);
  const qdsPercent = percent(qdsDetections.length, openDetections.length);
  const qdsPercentEvidence = percentIfReadable(detections, qdsDetections.length, openDetections.length, "open_detections");

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
            : (authScannedPercent ?? 0) >= settings.minAuthScanPercent
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
      auth_record_types: listIfReadable(authRecords, authRecords.data),
      windows_hosts: countIfReadable(hosts, windowsHosts.length),
      unix_hosts: countIfReadable(hosts, unixHosts.length),
      network_device_hosts: countIfReadable(hosts, networkHosts.length),
      missing_auth_types: listIfReadable([authRecords, hosts], missingAuthTypes),
      authenticated_scan_percent: authScannedPercentEvidence,
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
      policies: sourceCount(policies),
      inactive_policies: listIfReadable(policies, inactivePolicies.slice(0, 50)),
      unassigned_policies: listIfReadable(policies, unassignedPolicies.slice(0, 50)),
      policies_with_hidden_asset_groups: listIfReadable(policies, hiddenAssignmentPolicies.slice(0, 50)),
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
          : (slaPercent ?? 0) >= 95
            ? "pass"
            : (slaPercent ?? 0) >= 80
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
      hosts: sourceCount(hosts),
      detections_returned: sourceCount(detections),
      open_detections: countIfReadable(detections, openDetections.length),
      closed_detections_excluded: countIfReadable(detections, closedDetections.length),
      fixed_or_info_excluded: countIfReadable(detections, excludedDetections.length),
      sla_scoped_detections: countIfReadable(detections, slaScoped.length),
      sla_dated_detections: countIfReadable(detections, slaDated.length),
      sla_breaches: countIfReadable(detections, slaBreaches.length),
      sla_compliance_percent: slaPercentEvidence,
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
            : (overduePercent ?? 0) > 25
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
      open_qids: countIfReadable(detections, openQids.length),
      knowledge_base_qids: countIfReadable(knowledgeBase, kbQids.size),
      unresolved_qids: derivedCount([detections, knowledgeBase], unresolvedQids.length),
      patchable_qids: countIfReadable(knowledgeBase, patchableQids.size),
      patchable_detections: derivedCount([detections, knowledgeBase], patchableDetections.length),
      overdue_patchable_detections: derivedCount([detections, knowledgeBase], overduePatchable.length),
      overdue_percent: overduePercentEvidence,
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
      : (qdsPercent ?? 0) > 0
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
        : `${qdsDetections.length}/${openDetections.length} open detections (${qdsPercent}%) carry a Qualys Detection Score${(qdsPercent ?? 0) >= 90 ? ", which confirms QDS is exposed" : ""}. The triage workflow that consumes QDS or CVSS is not machine-verifiable, so the verdict is capped at warn until documented.`,
    evidence: {
      detections_with_qds: countIfReadable(detections, qdsDetections.length),
      open_detections: countIfReadable(detections, openDetections.length),
      qds_percent: qdsPercentEvidence,
    },
    sources: [detections],
    scope,
    manualEvidence: "confirm the VMDR subscription exposes Qualys Detection Scores and document the triage workflow that uses QDS or CVSS.",
  }));

  return {
    category: "vulnerability_management",
    title: "Qualys vulnerability and compliance management",
    summary: renderRecord({
      platform: config.platform,
      view_scope: scope.note,
      auth_record_types: listIfReadable(authRecords, authTypes),
      compliance_policies: sourceCount(policies),
      hosts: sourceCount(hosts),
      detections_returned: sourceCount(detections),
      open_detections: countIfReadable(detections, openDetections.length),
      sla_compliance_percent: slaPercentEvidence,
      sla_breaches: countIfReadable(detections, slaBreaches.length),
      patchable_detections: derivedCount([detections, knowledgeBase], patchableDetections.length),
      overdue_patchable_detections: derivedCount([detections, knowledgeBase], overduePatchable.length),
      qds_percent: qdsPercentEvidence,
      truncated_sources: [authRecords, hosts, policies, detections, knowledgeBase].filter((source) => source.truncated).map((source) => source.name),
      collection_errors: errors.length,
    }),
    findings,
    errors,
    rawData: Object.fromEntries([authRecords, hosts, policies, detections, knowledgeBase].map((source) => [source.name, exportableSurface(source)])),
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

// user.xsd username or id; user_list_output.dtd USER_LOGIN? and USER_ID? (both hidden in the Restricted view for
// users outside the caller's business unit) and then the required CONTACT_INFO/EMAIL before a labeled placeholder.
function userName(user: JsonRecord): string {
  const candidates = [asString(user.username), xmlScalarText(user.USER_LOGIN), asString(user.id), xmlScalarText(user.USER_ID), userEmail(user)];
  return candidates.map((value) => value?.trim()).find((value): value is string => Boolean(value)) ?? "[login hidden in Restricted view]";
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

// schedule_report_list_output.dtd: REPORT (ID, TITLE?, OUTPUT_FORMAT, TEMPLATE_TITLE?, ACTIVE, SCHEDULE) with
// ACTIVE (#PCDATA) carrying 0 or 1. No IS_ACTIVE element exists, and a missing flag never counts as active.
function reportIsActive(report: JsonRecord): boolean {
  return asBoolean(report.ACTIVE) === true;
}

function reportActiveFlagMissing(report: JsonRecord): boolean {
  return asBoolean(report.ACTIVE) === undefined;
}

// wasscanschedule.xsd: WasScanSchedule.active is an optional xs:boolean; no status element exists.
function wasScheduleIsActive(schedule: JsonRecord): boolean {
  return asBoolean(schedule.active) === true;
}

function wasScheduleFlagMissing(schedule: JsonRecord): boolean {
  return asBoolean(schedule.active) === undefined;
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

const WAS_HISTORY_SEARCH = "the unbounded WAS scan history search (webApp.id filtered, no launchedDate bound)";

// The unbounded history search runs only for web applications the bounded scan search did not resolve. When it is
// not issued, its status records why, so C15 never claims a readable history it did not read.
async function collectWasScanHistory(client: QualysDataClient, webApps: Collected, wasScans: Collected, errors: string[], lookbackDays: number): Promise<Collected> {
  const blockedBy = [webApps, wasScans].find((source) => source.error);
  if (blockedBy) {
    return notCollected("was_scan_history", `${WAS_HISTORY_SEARCH} was not issued because ${unreadableLabel(blockedBy)}`, blockedBy);
  }
  const unresolved = webApps.data
    .filter((webApp) => !webAppLastScanDate(webApp, wasScans.data))
    .map((webApp) => asString(webApp.id))
    .filter((id): id is string => Boolean(id));
  if (unresolved.length === 0) {
    return notCollected("was_scan_history", webApps.data.length === 0
      ? `${WAS_HISTORY_SEARCH} was not issued because ${sourceLabel(webApps)} returned no web applications`
      : `${WAS_HISTORY_SEARCH} was not issued because every web application returned by ${sourceLabel(webApps)} resolved a finished vulnerability scan inside the ${lookbackDays} day window through ${sourceLabel(wasScans)}`);
  }
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
  const wasHistory = await collectWasScanHistory(client, webApps, wasScans, errors, settings.lookbackDays);

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
      active_scheduled_reports: listIfReadable(scheduledReports, activeScheduledReports.map((report) => recordLabel(report, "report")).slice(0, 50)),
      scheduled_reports_without_active_flag: countIfReadable(scheduledReports, reportsWithoutActiveFlag.length),
      active_filter: "is_active=1",
      recent_reports: countIfReadable(reports, recentReports.length),
      reports_returned: sourceCount(reports),
    },
    sources: [scheduledReports, reports],
    scope,
    manualEvidence: "review Reports > Schedules and each schedule's distribution list for appropriate recipients.",
  }));

  const bothUserSourcesUnreadable = Boolean(userList.error && users.error);
  // Every population-derived value discloses which surface it was counted from, because the Administration API
  // fallback is a partial population (Active users only, other Managers hidden), never the tenant's roster.
  const populationStatus = userListReadable
    ? `readable: USER_STATUS Active users from ${sourceLabel(userList)}`
    : bothUserSourcesUnreadable
      ? `unreadable: ${unreadableLabel(userList)}; ${unreadableLabel(users)}`
      : `partial: ${unreadableLabel(userList)}, so the population is the Administration API user search (${users.endpoint}), which returns Active users only and hides other Manager and Super User accounts`;
  const fromPopulation = (value: unknown): Disclosed => disclosed(bothUserSourcesUnreadable ? null : value, populationStatus);
  // Matching over the Administration API fallback can surface accounts but never show their absence, because that
  // population hides other Manager and Super User accounts; an empty match list is therefore withheld, and a
  // non-empty one is a lower bound.
  const partialPopulation = !userListReadable && !bothUserSourcesUnreadable;
  const matchStatus = partialPopulation
    ? `${populationStatus}, so matches are a lower bound and an empty match list cannot show there are none`
    : populationStatus;
  const fromMatches = (matches: string[], render: (matches: string[]) => unknown): Disclosed =>
    disclosed(bothUserSourcesUnreadable || (partialPopulation && matches.length === 0) ? null : render(matches), matchStatus);
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
  const usersUnreadableNote = users.error && userListReadable
    ? ` The Administration API user search (/qps/rest/2.0/search/am/user/) was not readable (${shortenMessage(users.error, 120)}), so the roleList and scopeTags cross-check of the User List roster is unavailable.`
    : "";
  // user_list_output.dtd documents a Restricted view in which USER_LOGIN and USER_ID are hidden for users outside
  // the caller's business unit; those rows cannot be matched by name, so generic-account matching under-reports.
  const restrictedViewUsers = userListReadable ? userList.data.filter((user) => !xmlScalarText(user.USER_LOGIN)?.trim()) : [];
  const restrictedViewNote = restrictedViewUsers.length > 0
    ? ` ${restrictedViewUsers.length} users were returned without a USER_LOGIN (the Restricted view hides logins outside the caller's business unit), so generic_accounts and shared_emails under-report for them.`
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
            ? `The User List API returned ${userList.data.length} users but none with USER_STATUS Active, which cannot be true for a working subscription, so the API user cannot see the user population; treated as unknown, not compliant.${usersUnreadableNote}`
            : `${activeUsers.length} Active users (USER_STATUS) of ${userList.data.length} returned by the User List API, ${inactiveStatusUsers.length} Inactive, ${pendingUsers.length} Pending Activation; ${managers.length} Manager or super user accounts (threshold ${settings.maxManagers}), ${sharedEmails.length} shared email addresses, ${genericAccounts.length} generic-looking account names, ${staleLoginUsers.length} Active users whose LAST_LOGIN_DATE is older than ${INACTIVE_USER_DAYS} days, and ${usersWithoutLastLogin.length} Active users without a LAST_LOGIN_DATE (never counted as recently active).${usersUnreadableNote}${restrictedViewNote}`,
    evidence: {
      users_returned: fromPopulation(userPopulation.length),
      user_list_users: sourceCount(userList),
      administration_api_users: sourceCount(users),
      restricted_view_users_without_login: countIfReadable(userList, restrictedViewUsers.length),
      active_users: fromPopulation(activeUsers.length),
      inactive_status_users: countIfReadable(userList, inactiveStatusUsers.length),
      pending_activation_users: countIfReadable(userList, pendingUsers.length),
      managers: fromPopulation(managers.slice(0, 50)),
      max_managers: settings.maxManagers,
      shared_emails: fromMatches(sharedEmails, (matches) => matches.slice(0, 50)),
      generic_accounts: fromMatches(genericAccounts, (matches) => matches.slice(0, 50)),
      stale_login_users: listIfReadable(userList, staleLoginUsers.slice(0, 50)),
      inactive_user_days: INACTIVE_USER_DAYS,
      users_with_last_login: countIfReadable(userList, usersWithLastLogin.length),
      status_source: userListReadable ? "/msp/user_list.php USER_STATUS, USER_ROLE, LAST_LOGIN_DATE" : "not available",
      api_contract: "search/am/user returns Active users only, hides other Super Users and Managers, and documents no status or last-login field; /msp/user_list.php documents USER_STATUS and LAST_LOGIN_DATE (Manager and Unit Manager callers).",
    },
    // Both user inventories are read for this finding, so an unreadable Administration API search demotes it
    // even when the User List API answered.
    sources: [userList, users],
    scope,
    manualEvidence: "export Users > User Management with roles, status, and last login dates, and reconcile the full Manager list against the approved administrator roster.",
    unknownBuckets: {
      users_without_role: usersWithoutRole.length,
      users_without_status: usersWithoutStatus.length,
      users_without_last_login: usersWithoutLastLogin.length,
      users_without_login_in_restricted_view: restrictedViewUsers.length,
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
  // The history clause only claims a complete or unbounded read when that read happened and finished.
  const historyClause = wasHistory.error
    ? `; ${unresolvedWebApps.length} could not be resolved because ${WAS_HISTORY_SEARCH} on ${wasHistory.endpoint} was not readable, so the stale and never-scanned counts are unknown (reported, never counted as fresh or as never scanned)`
    : wasHistory.truncated
      ? `; ${unresolvedWebApps.length} could not be resolved because ${WAS_HISTORY_SEARCH} was truncated (${wasHistory.truncationReason ?? "truncated"}), so the stale and never-scanned counts are unknown (reported, never counted as fresh or as never scanned)`
      : wasHistory.notCollected
        ? `; ${WAS_HISTORY_SEARCH} was not issued because every web application resolved a finished scan inside the window`
        : `, ${staleWebApps.length} were last scanned before the window per the unbounded scan history, and ${neverScannedWebApps.length} have no finished vulnerability scan in the fully read scan history`;
  // Stale and never-scanned lists are unknown when the bounded scan search, the web app inventory, or a needed
  // history read did not deliver; a history search that nothing needed leaves them known and empty.
  const scanDateWithheld = withheldFor([webApps, wasScans]) ?? withheldFor(wasHistory, true);
  findings.push(guardedFinding({
    control: 15,
    severity: "medium",
    status: wasStatus,
    summary: webApps.error || wasScans.error || wasAuth.error
      ? `${unreadableSummary(15, [webApps, wasScans, wasAuth])}${webApps.moduleUnavailable ? " The WAS module is not licensed or not enabled for this API user, so this control is not applicable unless web applications are scanned elsewhere." : ""}`
      : webApps.data.length === 0
        ? "WAS responded but no web applications are inventoried. This is not applicable if no web applications are in scope; otherwise the WAS inventory is missing. Emptiness is treated as unknown, not compliant."
        : `${webAppScans.fresh.length}/${webApps.data.length} web applications have a finished vulnerability scan (WAS scan search launchedDate) within ${settings.lookbackDays} days${historyClause}; ${staleWasAuth.length} WAS authentication records are older than ${STALE_WAS_AUTH_DAYS} days; ${activeWasSchedules.length}/${wasSchedules.data.length} WAS schedules report an active flag.`,
    evidence: {
      web_apps: sourceCount(webApps),
      recently_scanned_web_apps: derivedCount([webApps, wasScans], webAppScans.fresh.length),
      never_scanned_web_apps: scanDateWithheld ?? neverScannedWebApps.slice(0, 50),
      stale_web_apps: scanDateWithheld ?? staleWebApps.slice(0, 50),
      unresolved_web_apps: listIfReadable([webApps, wasScans], unresolvedWebApps.slice(0, 50)),
      stale_auth_records: listIfReadable(wasAuth, staleWasAuth.slice(0, 50)),
      active_schedules: countIfReadable(wasSchedules, activeWasSchedules.length),
      schedules_returned: sourceCount(wasSchedules),
      scans_in_lookback: sourceCount(wasScans),
      scan_history_scans: sourceCount(wasHistory),
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
      entries: sourceCount(activity),
      sensitive_actions_count: countIfReadable(activity, sensitiveActions.length),
      sensitive_actions: listIfReadable(activity, sensitiveActions.slice(0, 50).map((entry) => ({
        date: asString(entry.date),
        action: asString(entry.action),
        module: asString(entry.module),
        user: asString(entry.user_name),
        role: asString(entry.user_role),
      }))),
    },
    sources: [activity],
    scope,
    manualEvidence: "export the Activity Log for the review period and document who reviews sensitive administrative actions and how long the log is retained.",
  }));

  return {
    category: "administration",
    title: "Qualys administration and reporting hygiene",
    summary: renderRecord({
      platform: config.platform,
      view_scope: scope.note,
      active_scheduled_reports: countIfReadable(scheduledReports, activeScheduledReports.length),
      recent_reports: countIfReadable(reports, recentReports.length),
      users: sourceCount(users),
      user_list_users: sourceCount(userList),
      active_users: fromPopulation(activeUsers.length),
      managers: fromPopulation(managers.length),
      shared_emails: fromMatches(sharedEmails, (matches) => matches.length),
      activity_entries: sourceCount(activity),
      sensitive_actions: countIfReadable(activity, sensitiveActions.length),
      web_apps: sourceCount(webApps),
      never_scanned_web_apps: scanDateWithheld ?? neverScannedWebApps.length,
      stale_web_apps: scanDateWithheld ?? staleWebApps.length,
      truncated_sources: [scheduledReports, reports, users, userList, activity, webApps, wasScans, wasHistory, wasAuth, wasSchedules].filter((source) => source.truncated).map((source) => source.name),
      collection_errors: errors.length,
    }),
    findings,
    errors,
    rawData: Object.fromEntries(
      [scheduledReports, reports, users, userList, activity, webApps, wasScans, wasHistory, wasAuth, wasSchedules].map((source) => [source.name, exportableSurface(source)]),
    ),
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
    const message = errorMessage(error);
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
    await probeSurface("scheduled_scans", "VM", surfaceEndpoint("scheduled_scans"), () => client.listScheduledScans()),
    await probeSurface("hosts", "VM", surfaceEndpoint("hosts"), () => client.listHosts(100)),
    await probeSurface("asset_groups", "VM", surfaceEndpoint("asset_groups"), () => client.listAssetGroups()),
    await probeSurface("option_profiles", "VM", surfaceEndpoint("option_profiles"), () => client.listOptionProfiles()),
    await probeSurface("appliances", "VM", surfaceEndpoint("appliances"), () => client.listAppliances()),
    await probeSurface("auth_records", "VM", surfaceEndpoint("auth_records"), () => client.listAuthRecordSummary()),
    await probeSurface("detections", "VMDR", surfaceEndpoint("detections"), () => client.listDetections(100)),
    await probeSurface("compliance_policies", "PC", surfaceEndpoint("compliance_policies"), () => client.listCompliancePolicies()),
    await probeSurface("activity_log", "Administration", surfaceEndpoint("activity_log"), () => (activity.error ? Promise.reject(new Error(activity.error)) : Promise.resolve(activity.data))),
    await probeSurface("users", "Administration", surfaceEndpoint("users"), () => (users.error ? Promise.reject(new Error(users.error)) : Promise.resolve(users.data))),
    await probeSurface("user_list", "Administration", surfaceEndpoint("user_list"), () => (userList.error ? Promise.reject(new Error(userList.error)) : Promise.resolve(userList.data))),
    await probeSurface("tags", "Asset Management", surfaceEndpoint("tags"), () => client.searchTags(100)),
    await probeSurface("cloud_agents", "Cloud Agent", surfaceEndpoint("cloud_agents"), () => client.searchCloudAgents(100)),
    await probeSurface("connectors", "Asset Management", surfaceEndpoint("connectors"), () => client.searchConnectors()),
    await probeSurface("was_webapps", "WAS", surfaceEndpoint("was_webapps"), () => client.searchWebApps()),
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
    "- `core_data/` contains one file per collected surface: `name`, `endpoint`, `status` (readable, truncated, unreadable, or not_collected), `count`, and the projected `records`.",
    "- A surface that was denied or never requested carries `count` and `records` as null with the reason; an empty `records` array means the read completed and returned nothing.",
    "- `analysis/` contains normalized findings and per-category summaries; a null value beside a `<field>_status` names the read that did not deliver it.",
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
  // Second layer for every bundle file: the same scrub the error constructor applies, minus the long-token heuristic
  // (QIDs, asset ids, and tag ids are evidence). The first layer is the constructor plus the per-surface allowlist.
  const secrets = credentialValues(config);
  const write = (relativePathname: string, content: string) => writeSecureTextFile(outputDir, relativePathname, scrubDataText(content, secrets));

  await write("QUICK_REFERENCE.md", `${buildQuickReference()}\n`);
  await write("metadata.json", serializeJson({
    generated_at: new Date().toISOString(),
    platform: config.platform,
    base_url: config.baseUrl,
    auth_mode: config.authMode,
    source_chain: config.sourceChain,
  }));
  await write("core_data/access.json", serializeJson(access));
  for (const assessment of assessments) {
    for (const [name, value] of Object.entries(assessment.rawData)) {
      await write(`core_data/${assessment.category}/${name}.json`, serializeJson(value));
    }
    await write(`analysis/${assessment.category}.json`, serializeJson({
      category: assessment.category,
      title: assessment.title,
      summary: assessment.summary,
      findings: assessment.findings,
      errors: assessment.errors,
    }));
  }
  await write("analysis/findings.json", serializeJson(findings));
  await write("compliance/executive_summary.md", buildExecutiveSummary(config, assessments, errors));
  await write("compliance/unified_compliance_matrix.md", buildUnifiedMatrix(findings));
  for (const framework of FRAMEWORKS) {
    await write(`compliance/${framework.dir}/${framework.file}`, buildFrameworkReport(framework.title, framework.prefix, findings));
  }
  if (errors.length > 0) {
    await write("_errors.log", `${errors.join("\n")}\n`);
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
        return errorResult(`${label} failed: ${errorMessage(error)}`, { tool: name });
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
        return errorResult(`Qualys access check failed: ${errorMessage(error)}`, { tool: "qualys_check_access" });
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
        return errorResult(`Qualys audit bundle export failed: ${errorMessage(error)}`, { tool: "qualys_export_audit_bundle" });
      }
    },
  });
}
