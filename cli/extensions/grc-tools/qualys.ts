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
const KNOWLEDGE_BASE_QID_BATCH = 200;
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
  error?: string;
}

export interface QualysAccessCheckResult {
  status: "healthy" | "degraded" | "limited";
  platform: string;
  baseUrl: string;
  authMode: QualysAuthMode;
  surfaces: QualysAccessSurface[];
  unavailableModules: string[];
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
    if (response.status >= 400 || errorSummary) {
      const detail = errorSummary ?? response.text.replace(/\s+/g, " ").slice(0, 240);
      throw new Error(redactSecrets(`Qualys request failed (${response.status}) for ${path}${detail ? `: ${detail}` : ""}`, this.config));
    }
    if (!document) {
      throw new Error(`Qualys request for ${path} did not return XML.`);
    }
    return document;
  }

  async getText(path: string, query: JsonRecord = {}): Promise<string> {
    const url = this.buildUrl(path, query);
    const response = await this.rawRequest("GET", url, { accept: "text/csv, application/xml" });
    if (looksLikeXml(response.text)) {
      const errorSummary = xmlErrorSummary(parseXml(response.text));
      if (errorSummary) throw new Error(`Qualys request failed (${response.status}) for ${path}: ${errorSummary}`);
    }
    if (response.status >= 400) {
      throw new Error(redactSecrets(`Qualys request failed (${response.status}) for ${path}: ${response.text.replace(/\s+/g, " ").slice(0, 240)}`, this.config));
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
  ): Promise<JsonRecord[]> {
    const limit = clampNumber(options.limit, DEFAULT_HOST_LIMIT, 1, 1_000_000);
    const maxPages = clampNumber(options.maxPages, DEFAULT_MAX_PAGES, 1, 500);
    const items: JsonRecord[] = [];
    let nextUrl: string | undefined = this.buildUrl(path, query);
    let pages = 0;
    while (nextUrl && items.length < limit && pages < maxPages) {
      const document: XmlNode = await this.getXml(nextUrl);
      pages += 1;
      const pageItems = xmlRecords(document, elementName);
      items.push(...pageItems.slice(0, limit - items.length));
      const warning = findXmlElement(document, "WARNING");
      nextUrl = warning ? xmlText(findXmlElement(warning, "URL")) : undefined;
      if (pageItems.length === 0) break;
    }
    return items;
  }

  async searchQps(
    path: string,
    criteria: Array<{ field: string; operator: string; value?: string }> = [],
    options: { limit?: number; pageSize?: number; verbose?: boolean; maxPages?: number } = {},
  ): Promise<JsonRecord[]> {
    const limit = clampNumber(options.limit, DEFAULT_HOST_LIMIT, 1, 1_000_000);
    const pageSize = clampNumber(options.pageSize, DEFAULT_QPS_PAGE_SIZE, 1, 1000);
    const maxPages = clampNumber(options.maxPages, DEFAULT_MAX_PAGES, 1, 500);
    const items: JsonRecord[] = [];
    let lastId: string | undefined;
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
      const hasMore = asBoolean(response.hasMoreRecords) ?? false;
      lastId = asString(response.lastId);
      if (!hasMore || !lastId || data.length === 0) break;
    }
    return items.slice(0, limit);
  }

  private lookbackStart(days?: number): string {
    return isoDaysAgo(clampNumber(days, this.config.lookbackDays, 1, 3650), this.now());
  }

  async listScheduledScans(): Promise<JsonRecord[]> {
    const document = await this.getXml("/api/2.0/fo/schedule/scan/", { action: "list", show_notifications: 0 });
    return xmlRecords(document, "SCHEDULE_SCAN");
  }

  async listScans(lookbackDays?: number): Promise<JsonRecord[]> {
    const document = await this.getXml("/api/2.0/fo/scan/", {
      action: "list",
      launched_after_datetime: this.lookbackStart(lookbackDays),
      show_ags: 1,
      show_op: 1,
    });
    return xmlRecords(document, "SCAN");
  }

  async listHosts(limit = DEFAULT_HOST_LIMIT): Promise<JsonRecord[]> {
    return this.listXml(
      "/api/2.0/fo/asset/host/",
      { action: "list", details: "All", show_tags: 1, truncation_limit: Math.min(limit, 1000) },
      "HOST",
      { limit },
    );
  }

  async listOptionProfiles(): Promise<JsonRecord[]> {
    const document = await this.getXml("/api/2.0/fo/subscription/option_profile/", { action: "list" });
    return xmlRecords(document, "OPTION_PROFILE");
  }

  async listExcludedIps(): Promise<JsonRecord[]> {
    const document = await this.getXml("/api/2.0/fo/asset/excluded_ip/", { action: "list" });
    const ipSet = findXmlElement(document, "IP_SET");
    if (!ipSet) return [];
    return ipSet.children
      .filter((child) => child.name === "IP" || child.name === "IP_RANGE")
      .map((child) => ({ type: child.name === "IP" ? "ip" : "range", value: child.text.trim(), ...child.attributes }));
  }

  async listAssetGroups(): Promise<JsonRecord[]> {
    return this.listXml(
      "/api/2.0/fo/asset/group/",
      { action: "list", show_attributes: "ALL", truncation_limit: 500 },
      "ASSET_GROUP",
      { limit: 5000 },
    );
  }

  async listAppliances(): Promise<JsonRecord[]> {
    const document = await this.getXml("/api/2.0/fo/appliance/", { action: "list", output_mode: "full" });
    return xmlRecords(document, "APPLIANCE");
  }

  async listAuthRecordSummary(): Promise<JsonRecord[]> {
    const document = await this.getXml("/api/2.0/fo/auth/", { action: "list" });
    const container = findXmlElement(document, "AUTH_RECORDS");
    if (!container) return [];
    return container.children
      .filter((child) => child.name.startsWith("AUTH_"))
      .map((child) => ({
        type: child.name.replace(/^AUTH_/, "").toLowerCase(),
        count: findXmlElements(child, "ID").length + findXmlElements(child, "ID_RANGE").length,
      }));
  }

  async listCompliancePolicies(): Promise<JsonRecord[]> {
    const document = await this.getXml("/api/2.0/fo/compliance/policy/", { action: "list", details: "Basic" });
    return xmlRecords(document, "POLICY");
  }

  async listDetections(limit = DEFAULT_DETECTION_LIMIT): Promise<JsonRecord[]> {
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
    for (const host of hosts) {
      for (const detection of pathRecords(host, "DETECTION_LIST", "DETECTION")) {
        detections.push({ host_id: asString(host.ID), ip: asString(host.IP), ...detection });
        if (detections.length >= limit) return detections;
      }
    }
    return detections;
  }

  async listKnowledgeBase(qids: string[]): Promise<JsonRecord[]> {
    const unique = uniqueStrings(qids).slice(0, KNOWLEDGE_BASE_QID_BATCH);
    if (unique.length === 0) return [];
    const document = await this.getXml("/api/2.0/fo/knowledge_base/vuln/", {
      action: "list",
      details: "Basic",
      ids: unique.join(","),
    });
    return xmlRecords(document, "VULN");
  }

  async listScheduledReports(): Promise<JsonRecord[]> {
    const document = await this.getXml("/api/2.0/fo/schedule/report/", { action: "list" });
    return xmlRecords(document, "REPORT");
  }

  async listReports(): Promise<JsonRecord[]> {
    const document = await this.getXml("/api/2.0/fo/report/", { action: "list" });
    return xmlRecords(document, "REPORT");
  }

  async listActivityLog(lookbackDays?: number): Promise<JsonRecord[]> {
    const text = await this.getText("/api/2.0/fo/activity_log/", {
      action: "list",
      since_datetime: this.lookbackStart(lookbackDays),
    });
    return csvToRecords(text);
  }

  async searchUsers(): Promise<JsonRecord[]> {
    return this.searchQps("/qps/rest/2.0/search/am/user/", [], { pageSize: 500 });
  }

  async searchCloudAgents(limit = DEFAULT_HOST_LIMIT): Promise<JsonRecord[]> {
    return this.searchQps(
      "/qps/rest/2.0/search/am/hostasset",
      [{ field: "tagName", operator: "EQUALS", value: "Cloud Agent" }],
      { limit },
    );
  }

  async searchConnectors(): Promise<JsonRecord[]> {
    return this.searchQps("/qps/rest/2.0/search/am/assetdataconnector", [], { pageSize: 100 });
  }

  async searchTags(limit = 2000): Promise<JsonRecord[]> {
    return this.searchQps("/qps/rest/2.0/search/am/tag", [], { limit });
  }

  async searchWebApps(): Promise<JsonRecord[]> {
    return this.searchQps("/qps/rest/3.0/search/was/webapp", [], { pageSize: 100, verbose: true });
  }

  async searchWasScans(lookbackDays?: number): Promise<JsonRecord[]> {
    return this.searchQps(
      "/qps/rest/3.0/search/was/wasscan",
      [
        { field: "launchedDate", operator: "GREATER", value: this.lookbackStart(lookbackDays) },
        { field: "type", operator: "EQUALS", value: "VULNERABILITY" },
      ],
      { pageSize: 100 },
    );
  }

  async searchWasAuthRecords(): Promise<JsonRecord[]> {
    return this.searchQps("/qps/rest/3.0/search/was/webappauthrecord", [], { pageSize: 100 });
  }

  async searchWasSchedules(): Promise<JsonRecord[]> {
    return this.searchQps("/qps/rest/3.0/search/was/wasscanschedule", [], { pageSize: 100 });
  }
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
  | "searchUsers"
  | "searchCloudAgents"
  | "searchConnectors"
  | "searchTags"
  | "searchWebApps"
  | "searchWasScans"
  | "searchWasAuthRecords"
  | "searchWasSchedules"
>;

interface Collected<T> {
  data: T;
  error?: string;
}

async function collect<T>(
  name: string,
  load: () => Promise<T>,
  fallback: T,
  errors: string[],
): Promise<Collected<T>> {
  try {
    return { data: await load() };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    errors.push(`${name}: ${message}`);
    return { data: fallback, error: message };
  }
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

function unavailableFinding(control: number, severity: QualysFindingSeverity, error: string, manualEvidence: string): QualysFinding {
  return finding(
    control,
    severity,
    "manual",
    `The Qualys API surface needed for this control was not readable (${error.replace(/\s+/g, " ").slice(0, 160)}). Collect manually: ${manualEvidence}`,
    { collection_error: error, manual_evidence: manualEvidence },
  );
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
  return asBoolean(schedule.ACTIVE) !== false;
}

function scheduleTargets(schedule: JsonRecord): string[] {
  const groups = asArray(pathValue(schedule, "ASSET_GROUP_TITLE_LIST", "ASSET_GROUP_TITLE")).map(asString);
  const tags = asRecords(pathValue(schedule, "ASSET_TAGS", "TAG_SET_INCLUDE", "TAG_INCLUDE")).map((tag) => asString(tag.NAME) ?? asString(tag));
  const rawTags = asArray(pathValue(schedule, "ASSET_TAGS", "TAG_SET_INCLUDE", "TAG_INCLUDE")).map(asString);
  const target = asString(schedule.TARGET);
  return uniqueStrings([...groups, ...tags, ...rawTags, target]);
}

function scheduleScanner(schedule: JsonRecord): string {
  return asString(schedule.ISCANNER_NAME)
    ?? asString(schedule.EC2_INSTANCE)
    ?? asString(pathValue(schedule, "ISCANNER_ID"))
    ?? "external";
}

function scheduleUsesExternalScanner(schedule: JsonRecord): boolean {
  return /^external$/i.test(scheduleScanner(schedule));
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

function optionProfileExcludedQidCount(profile: JsonRecord): number {
  let count = 0;
  const visit = (value: unknown, key: string): void => {
    if (/EXCLUDE/i.test(key)) {
      const text = asString(value);
      if (text) count += text.split(",").filter(Boolean).length;
      else count += asRecords(value).length;
      return;
    }
    const object = asObject(value);
    if (object) for (const [childKey, childValue] of Object.entries(object)) visit(childValue, childKey);
  };
  visit(profile, "");
  return count;
}

export async function assessQualysScanCoverage(
  client: QualysDataClient,
  options: QualysAssessmentOptions = {},
): Promise<QualysAssessmentResult> {
  const config = client.getResolvedConfig();
  const settings = resolveAssessmentOptions(config, options);
  const errors: string[] = [];
  const now = new Date();

  const [schedules, scans, hosts, profiles, excluded, groups] = await Promise.all([
    collect("scheduled_scans", () => client.listScheduledScans(), [] as JsonRecord[], errors),
    collect("scans", () => client.listScans(settings.lookbackDays), [] as JsonRecord[], errors),
    collect("hosts", () => client.listHosts(settings.hostLimit), [] as JsonRecord[], errors),
    collect("option_profiles", () => client.listOptionProfiles(), [] as JsonRecord[], errors),
    collect("excluded_ips", () => client.listExcludedIps(), [] as JsonRecord[], errors),
    collect("asset_groups", () => client.listAssetGroups(), [] as JsonRecord[], errors),
  ]);

  const activeSchedules = schedules.data.filter(scheduleIsActive);
  const scheduledTargets = new Set(activeSchedules.flatMap(scheduleTargets).map((target) => target.toLowerCase()));
  const groupsWithoutSchedule = groups.data
    .map((group) => asString(group.TITLE) ?? asString(group.ID) ?? "group")
    .filter((title) => !scheduledTargets.has(title.toLowerCase()) && !scheduledTargets.has("all"));
  const staleHosts = hosts.data.filter((host) => {
    const age = ageInDays(host.LAST_VULN_SCAN_DATETIME ?? host.LAST_VM_SCANNED_DATE, now);
    return age === undefined || age > settings.lookbackDays;
  });
  const scannedHosts = hosts.data.filter((host) => parseDate(host.LAST_VULN_SCAN_DATETIME ?? host.LAST_VM_SCANNED_DATE));
  const authScannedHosts = scannedHosts.filter((host) => {
    const age = ageInDays(host.LAST_VM_AUTH_SCANNED_DATE, now);
    return age !== undefined && age <= Math.max(settings.lookbackDays, 30);
  });
  const authPercent = percent(authScannedHosts.length, scannedHosts.length);

  const profilesWithoutAuth = profiles.data.filter((profile) => optionProfileAuthTypes(profile).length === 0).map(optionProfileName);
  const excludedQidCount = profiles.data.reduce((total, profile) => total + optionProfileExcludedQidCount(profile), 0);
  const broadExclusions = excluded.data.filter((entry) => entry.type === "range" && addressCountForRange(asString(entry.value) ?? "") > BROAD_EXCLUSION_ADDRESS_COUNT);
  const externalSchedules = activeSchedules.filter(scheduleUsesExternalScanner);
  const distinctTargets = uniqueStrings(activeSchedules.flatMap(scheduleTargets));
  const distinctScanners = uniqueStrings(activeSchedules.map(scheduleScanner));
  const finishedScans = scans.data.filter((scan) => /finished/i.test(pathString(scan, "STATUS", "STATE") ?? asString(scan.STATUS) ?? ""));

  const findings: QualysFinding[] = [];

  findings.push(schedules.error
    ? unavailableFinding(1, "high", schedules.error, "export the Scans > Schedules list and the asset group list from the Qualys UI and confirm each asset group has an active recurring scan.")
    : finding(
      1,
      "high",
      activeSchedules.length === 0 ? "fail" : groupsWithoutSchedule.length > 0 || staleHosts.length > 0 ? "warn" : "pass",
      activeSchedules.length === 0
        ? "No active scheduled vulnerability scans were found."
        : `${activeSchedules.length} active schedules cover ${distinctTargets.length} distinct targets; ${groupsWithoutSchedule.length}/${groups.data.length} asset groups are not referenced by an active schedule and ${staleHosts.length}/${hosts.data.length} hosts have no vulnerability scan within ${settings.lookbackDays} days.`,
      {
        active_schedules: activeSchedules.length,
        total_schedules: schedules.data.length,
        finished_scans_in_lookback: finishedScans.length,
        asset_groups_without_schedule: groupsWithoutSchedule.slice(0, 50),
        stale_hosts: staleHosts.length,
        next_launches: activeSchedules.map(scheduleNextLaunch).filter(Boolean).slice(0, 20),
      },
    ));

  findings.push(hosts.error
    ? unavailableFinding(2, "high", hosts.error, "run an Authentication Report in Qualys and record the percentage of hosts with successful authenticated scans.")
    : finding(
      2,
      "high",
      scannedHosts.length === 0 ? "warn" : authPercent >= settings.minAuthScanPercent ? "pass" : "fail",
      scannedHosts.length === 0
        ? "No scanned hosts were returned, so the authenticated scan ratio could not be computed."
        : `${authScannedHosts.length}/${scannedHosts.length} scanned hosts (${authPercent}%) had a recent authenticated scan; threshold ${settings.minAuthScanPercent}%.`,
      {
        scanned_hosts: scannedHosts.length,
        authenticated_hosts: authScannedHosts.length,
        authenticated_percent: authPercent,
        threshold_percent: settings.minAuthScanPercent,
      },
    ));

  findings.push(profiles.error
    ? unavailableFinding(3, "medium", profiles.error, "export each option profile from Scans > Option Profiles and review authentication, port, and performance settings against internal and external scanning requirements.")
    : finding(
      3,
      "medium",
      profiles.data.length === 0 ? "fail" : profilesWithoutAuth.length > 0 ? "warn" : "pass",
      profiles.data.length === 0
        ? "No option profiles were returned."
        : `${profiles.data.length} option profiles reviewed; ${profilesWithoutAuth.length} have no authentication types enabled. Confirm internal versus external profile intent manually.`,
      {
        option_profiles: profiles.data.map(optionProfileName).slice(0, 50),
        profiles_without_authentication: profilesWithoutAuth.slice(0, 50),
      },
    ));

  findings.push(schedules.error
    ? unavailableFinding(14, "medium", schedules.error, "confirm at least one recurring perimeter scan uses Qualys external scanners against the public IP ranges.")
    : finding(
      14,
      "medium",
      externalSchedules.length > 0 ? "pass" : activeSchedules.length > 0 ? "warn" : "fail",
      externalSchedules.length > 0
        ? `${externalSchedules.length} active schedules run from Qualys external scanners.`
        : activeSchedules.length > 0
          ? "Active schedules exist but none appear to use Qualys external scanners for perimeter coverage."
          : "No active schedules were found, so external perimeter scanning is not configured.",
      {
        external_schedules: externalSchedules.map((schedule) => asString(schedule.TITLE) ?? asString(schedule.ID)).slice(0, 50),
        scanners_in_use: distinctScanners.slice(0, 50),
      },
    ));

  findings.push(excluded.error
    ? unavailableFinding(16, "medium", excluded.error, "export Assets > Excluded Hosts and review each excluded IP range and option profile QID exclusion for justification.")
    : finding(
      16,
      "medium",
      broadExclusions.length > 0 ? "fail" : excluded.data.length > 0 || excludedQidCount > 0 ? "warn" : "pass",
      broadExclusions.length > 0
        ? `${broadExclusions.length} excluded IP ranges span more than ${BROAD_EXCLUSION_ADDRESS_COUNT} addresses.`
        : excluded.data.length > 0 || excludedQidCount > 0
          ? `${excluded.data.length} excluded host entries and ${excludedQidCount} QID exclusions in option profiles require documented justification.`
          : "No excluded hosts or QID exclusions were found.",
      {
        excluded_entries: excluded.data.slice(0, 100),
        broad_exclusions: broadExclusions.slice(0, 50),
        option_profile_qid_exclusions: excludedQidCount,
      },
    ));

  findings.push(schedules.error
    ? unavailableFinding(20, "medium", schedules.error, "document which scan schedules cover DMZ, internal, and OT/ICS segments and which scanner appliances serve each segment.")
    : finding(
      20,
      "medium",
      activeSchedules.length === 0 ? "fail" : distinctTargets.length >= 2 && distinctScanners.length >= 2 ? "pass" : "warn",
      activeSchedules.length === 0
        ? "No active schedules exist, so no segment-specific scanning is configured."
        : `${activeSchedules.length} active schedules target ${distinctTargets.length} distinct targets across ${distinctScanners.length} scanner sources. Map these to DMZ, internal, and OT/ICS segments manually.`,
      {
        distinct_targets: distinctTargets.slice(0, 50),
        distinct_scanners: distinctScanners.slice(0, 50),
      },
    ));

  return {
    category: "scan_coverage",
    title: "Qualys scan coverage and cadence",
    summary: {
      platform: config.platform,
      lookback_days: settings.lookbackDays,
      active_schedules: activeSchedules.length,
      finished_scans_in_lookback: finishedScans.length,
      hosts: hosts.data.length,
      stale_hosts: staleHosts.length,
      authenticated_percent: authPercent,
      option_profiles: profiles.data.length,
      excluded_entries: excluded.data.length,
      external_schedules: externalSchedules.length,
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

function connectorState(connector: JsonRecord): string {
  return (asString(connector.connectorState) ?? asString(connector.state) ?? "unknown").toUpperCase();
}

function connectorIsUnhealthy(connector: JsonRecord): boolean {
  return /ERROR|DISABLED|INCOMPLETE/.test(connectorState(connector)) || asBoolean(connector.disabled) === true || Boolean(asString(connector.lastError));
}

function applianceStatus(appliance: JsonRecord): string {
  return (asString(appliance.STATUS) ?? "unknown").toLowerCase();
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

function agentLastCheckIn(agent: JsonRecord): unknown {
  return pathValue(agent, "agentInfo", "lastCheckedIn") ?? pathValue(agent, "agentInfo", "lastCheckedIn", "date");
}

export async function assessQualysAssetInventory(
  client: QualysDataClient,
  options: QualysAssessmentOptions = {},
): Promise<QualysAssessmentResult> {
  const config = client.getResolvedConfig();
  const settings = resolveAssessmentOptions(config, options);
  const errors: string[] = [];
  const now = new Date();

  const [groups, hosts, connectors, appliances, agents, tags] = await Promise.all([
    collect("asset_groups", () => client.listAssetGroups(), [] as JsonRecord[], errors),
    collect("hosts", () => client.listHosts(settings.hostLimit), [] as JsonRecord[], errors),
    collect("connectors", () => client.searchConnectors(), [] as JsonRecord[], errors),
    collect("appliances", () => client.listAppliances(), [] as JsonRecord[], errors),
    collect("cloud_agents", () => client.searchCloudAgents(settings.hostLimit), [] as JsonRecord[], errors),
    collect("tags", () => client.searchTags(), [] as JsonRecord[], errors),
  ]);

  const emptyGroups = groups.data.filter((group) => !assetGroupHasTargets(group)).map((group) => asString(group.TITLE) ?? asString(group.ID) ?? "group");
  const neverScannedHosts = hosts.data.filter((host) => !parseDate(host.LAST_VULN_SCAN_DATETIME ?? host.LAST_VM_SCANNED_DATE));
  const unhealthyConnectors = connectors.data.filter(connectorIsUnhealthy);
  const staleConnectors = connectors.data.filter((connector) => (ageInDays(connector.lastSync, now) ?? Number.POSITIVE_INFINITY) > 7);
  const offlineAppliances = appliances.data.filter(applianceIsOffline);
  const outdatedAppliances = appliances.data.filter((appliance) => !applianceIsOffline(appliance) && applianceIsOutdated(appliance));
  const agentHosts = hosts.data.filter(hostIsAgentTracked);
  const agentPercent = percent(agentHosts.length, hosts.data.length);
  const inactiveAgents = agents.data.filter((agent) => /INACTIVE|UNINSTALL/.test(agentStatus(agent)));
  const staleAgents = agents.data.filter((agent) => {
    const age = ageInDays(agentLastCheckIn(agent), now);
    return age !== undefined && age > 7;
  });
  const untaggedHosts = hosts.data.filter((host) => hostTags(host).length === 0);
  const untaggedPercent = percent(untaggedHosts.length, hosts.data.length);
  const dynamicTags = tags.data.filter((tag) => Boolean(asString(tag.ruleType)));

  const findings: QualysFinding[] = [];

  findings.push(finding(
    4,
    "medium",
    "manual",
    `Qualys exposes ${groups.data.length} asset groups and ${hosts.data.length} host assets, but the API cannot compare them against the authoritative CMDB or network range register. Collect manually: export the CMDB or IPAM network ranges and reconcile them against the Qualys asset group IP sets; investigate ${emptyGroups.length} asset groups without targets and ${neverScannedHosts.length} hosts that were never scanned.`,
    {
      asset_groups: groups.data.length,
      asset_groups_without_targets: emptyGroups.slice(0, 50),
      hosts: hosts.data.length,
      hosts_never_scanned: neverScannedHosts.length,
      manual_evidence: "CMDB or IPAM range export reconciled against Qualys asset group IP sets.",
      collection_errors: [groups.error, hosts.error].filter(Boolean),
    },
  ));

  findings.push(connectors.error
    ? unavailableFinding(5, "medium", connectors.error, "open the AWS, Azure, and GCP connector lists in the Qualys UI and confirm each connector last synchronized successfully.")
    : finding(
      5,
      "medium",
      connectors.data.length === 0 ? "warn" : unhealthyConnectors.length > 0 ? "fail" : staleConnectors.length > 0 ? "warn" : "pass",
      connectors.data.length === 0
        ? "No cloud asset data connectors are configured."
        : unhealthyConnectors.length > 0
          ? `${unhealthyConnectors.length}/${connectors.data.length} cloud connectors are disabled or in an error state.`
          : staleConnectors.length > 0
            ? `${staleConnectors.length}/${connectors.data.length} cloud connectors have not synchronized within 7 days.`
            : `All ${connectors.data.length} cloud connectors are enabled and synchronized recently.`,
      {
        connectors: connectors.data.map((connector) => ({
          name: asString(connector.name),
          type: asString(connector.type),
          state: connectorState(connector),
          last_sync: asString(connector.lastSync),
          last_error: asString(connector.lastError),
        })).slice(0, 100),
      },
    ));

  findings.push(appliances.error
    ? unavailableFinding(6, "high", appliances.error, "review Scans > Appliances for offline scanners, missed heartbeats, and outdated software or signature versions.")
    : finding(
      6,
      "high",
      offlineAppliances.length > 0 ? "fail" : outdatedAppliances.length > 0 ? "warn" : appliances.data.length === 0 ? "warn" : "pass",
      appliances.data.length === 0
        ? "No scanner appliances were returned; internal scanning relies on external scanners or agents only."
        : offlineAppliances.length > 0
          ? `${offlineAppliances.length}/${appliances.data.length} scanner appliances are offline.`
          : outdatedAppliances.length > 0
            ? `${outdatedAppliances.length}/${appliances.data.length} scanner appliances missed heartbeats or run outdated software or signatures.`
            : `All ${appliances.data.length} scanner appliances are online and current.`,
      {
        appliances: appliances.data.map((appliance) => ({
          name: asString(appliance.NAME),
          status: applianceStatus(appliance),
          software_version: asString(appliance.SOFTWARE_VERSION),
          latest_version: asString(appliance.ML_LATEST),
          heartbeats_missed: asNumber(appliance.HEARTBEATS_MISSED) ?? 0,
          last_updated: asString(appliance.LAST_UPDATED_DATE),
        })).slice(0, 100),
      },
    ));

  findings.push(hosts.error && agents.error
    ? unavailableFinding(7, "medium", `${hosts.error}; ${agents.error}`, "compare the Cloud Agent inventory against the host inventory and record the agent coverage percentage.")
    : finding(
      7,
      "medium",
      hosts.data.length === 0 ? "warn" : agentPercent >= settings.minAgentCoveragePercent && inactiveAgents.length === 0 && staleAgents.length === 0 ? "pass" : agentPercent >= settings.minAgentCoveragePercent ? "warn" : "fail",
      hosts.data.length === 0
        ? "No host assets were returned, so agent coverage could not be computed."
        : `${agentHosts.length}/${hosts.data.length} hosts (${agentPercent}%) are tracked by Cloud Agent against a ${settings.minAgentCoveragePercent}% threshold; ${inactiveAgents.length} agents are inactive and ${staleAgents.length} have not checked in for 7 days.`,
      {
        agent_tracked_hosts: agentHosts.length,
        hosts: hosts.data.length,
        agent_coverage_percent: agentPercent,
        threshold_percent: settings.minAgentCoveragePercent,
        cloud_agents: agents.data.length,
        inactive_agents: inactiveAgents.length,
        stale_agents: staleAgents.length,
      },
    ));

  findings.push(hosts.error && tags.error
    ? unavailableFinding(18, "medium", `${hosts.error}; ${tags.error}`, "export the tag tree and confirm every in-scope asset carries a compliance scope tag.")
    : finding(
      18,
      "medium",
      tags.data.length === 0 ? "fail" : untaggedPercent > 20 ? "fail" : untaggedPercent > 0 ? "warn" : "pass",
      tags.data.length === 0
        ? "No asset tags are defined, so compliance scope cannot be identified by tag."
        : `${tags.data.length} tags exist (${dynamicTags.length} rule-based); ${untaggedHosts.length}/${hosts.data.length} hosts (${untaggedPercent}%) carry no tags.`,
      {
        tags: tags.data.length,
        dynamic_tags: dynamicTags.length,
        untagged_hosts: untaggedHosts.length,
        untagged_percent: untaggedPercent,
        tag_names: tags.data.map((tag) => asString(tag.name)).filter(Boolean).slice(0, 100),
      },
    ));

  return {
    category: "asset_inventory",
    title: "Qualys asset inventory and sensors",
    summary: {
      platform: config.platform,
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

function policyIsActive(policy: JsonRecord): boolean {
  return asBoolean(policy.IS_ACTIVE) !== false && !/inactive|draft/i.test(asString(policy.STATUS) ?? "");
}

function policyIsAssigned(policy: JsonRecord): boolean {
  return asArray(pathValue(policy, "ASSET_GROUP_IDS")).some((value) => Boolean(asString(value)))
    || asArray(pathValue(policy, "ASSET_TAGS", "TAG_SET_INCLUDE")).length > 0
    || asArray(pathValue(policy, "ASSET_TAGS", "TAG_SET_INCLUDE", "TAG_INCLUDE")).length > 0;
}

export async function assessQualysVulnerabilityManagement(
  client: QualysDataClient,
  options: QualysAssessmentOptions = {},
): Promise<QualysAssessmentResult> {
  const config = client.getResolvedConfig();
  const settings = resolveAssessmentOptions(config, options);
  const errors: string[] = [];
  const now = new Date();

  const [authRecords, hosts, policies, detections] = await Promise.all([
    collect("auth_records", () => client.listAuthRecordSummary(), [] as JsonRecord[], errors),
    collect("hosts", () => client.listHosts(settings.hostLimit), [] as JsonRecord[], errors),
    collect("compliance_policies", () => client.listCompliancePolicies(), [] as JsonRecord[], errors),
    collect("detections", () => client.listDetections(settings.detectionLimit), [] as JsonRecord[], errors),
  ]);
  const openQids = uniqueStrings(detections.data.map((detection) => asString(detection.QID)));
  const knowledgeBase = openQids.length > 0
    ? await collect("knowledge_base", () => client.listKnowledgeBase(openQids), [] as JsonRecord[], errors)
    : { data: [] as JsonRecord[] };

  const authTypes = authRecords.data.filter((record) => (asNumber(record.count) ?? 0) > 0).map((record) => asString(record.type) ?? "");
  const windowsHosts = hosts.data.filter((host) => /windows/i.test(hostOs(host)));
  const unixHosts = hosts.data.filter((host) => /linux|unix|bsd|solaris|aix|hp-ux|esx|mac os|darwin/i.test(hostOs(host)));
  const missingAuthTypes: string[] = [];
  if (windowsHosts.length > 0 && !authTypes.some((type) => /windows/.test(type))) missingAuthTypes.push("windows");
  if (unixHosts.length > 0 && !authTypes.some((type) => /unix|linux/.test(type))) missingAuthTypes.push("unix");

  const inactivePolicies = policies.data.filter((policy) => !policyIsActive(policy)).map((policy) => asString(policy.TITLE) ?? asString(policy.ID) ?? "policy");
  const unassignedPolicies = policies.data.filter((policy) => policyIsActive(policy) && !policyIsAssigned(policy)).map((policy) => asString(policy.TITLE) ?? asString(policy.ID) ?? "policy");

  const slaScoped = detections.data.filter((detection) => detectionSlaDays(detection, settings) !== undefined);
  const slaBreaches = slaScoped.filter((detection) => {
    const age = detectionAgeDays(detection, now);
    const sla = detectionSlaDays(detection, settings) ?? 0;
    return age !== undefined && age > sla;
  });
  const slaPercent = slaScoped.length === 0 ? 100 : percent(slaScoped.length - slaBreaches.length, slaScoped.length);
  const breachBySeverity = {
    critical: slaBreaches.filter((detection) => detectionSeverity(detection) >= 5).length,
    high: slaBreaches.filter((detection) => detectionSeverity(detection) === 4).length,
    medium: slaBreaches.filter((detection) => detectionSeverity(detection) === 3).length,
  };

  const patchableQids = new Set(knowledgeBase.data.filter((vuln) => asBoolean(vuln.PATCHABLE) === true).map((vuln) => asString(vuln.QID)).filter(Boolean));
  const kbQids = new Set(knowledgeBase.data.map((vuln) => asString(vuln.QID)).filter(Boolean));
  const patchableDetections = detections.data.filter((detection) => patchableQids.has(asString(detection.QID)));
  const overduePatchable = patchableDetections.filter((detection) => (detectionAgeDays(detection, now) ?? 0) > settings.slaHighDays);
  const overduePercent = percent(overduePatchable.length, patchableDetections.length);

  const qdsDetections = detections.data.filter(detectionHasQds);
  const qdsPercent = percent(qdsDetections.length, detections.data.length);

  const findings: QualysFinding[] = [];

  findings.push(authRecords.error
    ? unavailableFinding(8, "high", authRecords.error, "review Scans > Authentication for Windows, Unix, and network device records and run an Authentication Report to find failing credentials.")
    : finding(
      8,
      "high",
      authTypes.length === 0 ? "fail" : missingAuthTypes.length > 0 ? "fail" : "pass",
      authTypes.length === 0
        ? "No authentication records exist, so credentialed scanning is not configured."
        : missingAuthTypes.length > 0
          ? `Authentication records exist for ${authTypes.join(", ")} but hosts of type ${missingAuthTypes.join(", ")} have no matching record type. Credential failures still require the Authentication Report.`
          : `Authentication record types present: ${authTypes.join(", ")}. Verify expired or failing credentials with the Authentication Report.`,
      {
        auth_record_types: authRecords.data,
        windows_hosts: windowsHosts.length,
        unix_hosts: unixHosts.length,
        missing_auth_types: missingAuthTypes,
      },
    ));

  findings.push(policies.error
    ? unavailableFinding(9, "medium", policies.error, "list Policy Compliance policies and confirm each active policy is assigned to asset groups or tags (the PC module may not be subscribed).")
    : finding(
      9,
      "medium",
      policies.data.length === 0 ? "warn" : unassignedPolicies.length > 0 ? "fail" : inactivePolicies.length > 0 ? "warn" : "pass",
      policies.data.length === 0
        ? "No Policy Compliance policies were returned."
        : unassignedPolicies.length > 0
          ? `${unassignedPolicies.length}/${policies.data.length} active compliance policies have no asset group or tag assignment.`
          : inactivePolicies.length > 0
            ? `${inactivePolicies.length}/${policies.data.length} compliance policies are inactive or draft.`
            : `All ${policies.data.length} compliance policies are active and assigned.`,
      {
        policies: policies.data.length,
        inactive_policies: inactivePolicies.slice(0, 50),
        unassigned_policies: unassignedPolicies.slice(0, 50),
      },
    ));

  findings.push(detections.error
    ? unavailableFinding(10, "critical", detections.error, "run a VMDR report of open severity 3 to 5 detections with first-found dates and compute SLA adherence against the 15/30/90 day windows.")
    : finding(
      10,
      "critical",
      slaScoped.length === 0 ? "pass" : slaPercent >= 95 ? "pass" : slaPercent >= 80 ? "warn" : "fail",
      slaScoped.length === 0
        ? "No open severity 3 to 5 detections were returned within the sampled scope."
        : `${slaScoped.length - slaBreaches.length}/${slaScoped.length} sampled open detections (${slaPercent}%) are within SLA (critical ${settings.slaCriticalDays}d, high ${settings.slaHighDays}d, medium ${settings.slaMediumDays}d); ${slaBreaches.length} breaches.`,
      {
        sampled_detections: slaScoped.length,
        sla_breaches: slaBreaches.length,
        sla_compliance_percent: slaPercent,
        breaches_by_severity: breachBySeverity,
        sla_days: { critical: settings.slaCriticalDays, high: settings.slaHighDays, medium: settings.slaMediumDays },
      },
    ));

  findings.push(detections.error || (openQids.length > 0 && kbQids.size === 0)
    ? unavailableFinding(11, "high", detections.error ?? "knowledge base lookup returned no entries", "export the patch report for open detections and record patch availability and patch age.")
    : finding(
      11,
      "high",
      patchableDetections.length === 0 ? "pass" : overduePercent > 25 ? "fail" : overduePatchable.length > 0 ? "warn" : "pass",
      patchableDetections.length === 0
        ? `Patch availability tracking resolved ${kbQids.size} QIDs and none of the sampled open detections have a vendor patch available.`
        : `${overduePatchable.length}/${patchableDetections.length} sampled patchable detections (${overduePercent}%) have been open longer than ${settings.slaHighDays} days.`,
      {
        knowledge_base_qids: kbQids.size,
        patchable_qids: patchableQids.size,
        patchable_detections: patchableDetections.length,
        overdue_patchable_detections: overduePatchable.length,
        overdue_percent: overduePercent,
      },
    ));

  findings.push(detections.error
    ? unavailableFinding(17, "medium", detections.error, "confirm the VMDR subscription exposes Qualys Detection Scores and document the triage workflow that uses QDS or CVSS.")
    : finding(
      17,
      "medium",
      detections.data.length === 0 ? "warn" : qdsPercent >= 90 ? "pass" : qdsPercent > 0 ? "warn" : "fail",
      detections.data.length === 0
        ? "No open detections were returned, so QDS availability could not be confirmed."
        : `${qdsDetections.length}/${detections.data.length} sampled detections (${qdsPercent}%) carry a Qualys Detection Score. Document the triage workflow manually.`,
      {
        detections_with_qds: qdsDetections.length,
        sampled_detections: detections.data.length,
        qds_percent: qdsPercent,
      },
    ));

  return {
    category: "vulnerability_management",
    title: "Qualys vulnerability and compliance management",
    summary: {
      platform: config.platform,
      auth_record_types: authTypes,
      compliance_policies: policies.data.length,
      sampled_detections: detections.data.length,
      sla_compliance_percent: slaPercent,
      sla_breaches: slaBreaches.length,
      patchable_detections: patchableDetections.length,
      overdue_patchable_detections: overduePatchable.length,
      qds_percent: qdsPercent,
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
  return userRoles(user).some((role) => /^manager$|super user|administrator/i.test(role));
}

function userName(user: JsonRecord): string {
  return asString(user.username) ?? asString(user.USER_LOGIN) ?? asString(user.id) ?? "user";
}

function userEmail(user: JsonRecord): string | undefined {
  return (asString(user.emailAddress) ?? pathString(user, "CONTACT_INFO", "EMAIL"))?.toLowerCase();
}

function reportIsActive(report: JsonRecord): boolean {
  return asBoolean(report.ACTIVE) !== false;
}

function webAppLastScanDate(webApp: JsonRecord, scans: JsonRecord[]): Date | undefined {
  const id = asString(webApp.id);
  const dates = scans
    .filter((scan) => pathString(scan, "target", "webApp", "id") === id && /FINISHED/i.test(asString(scan.status) ?? ""))
    .map((scan) => parseDate(scan.launchedDate))
    .filter((date): date is Date => Boolean(date));
  const fromWebApp = parseDate(pathValue(webApp, "lastScan", "date") ?? webApp.lastScanDate);
  if (fromWebApp) dates.push(fromWebApp);
  if (dates.length === 0) return undefined;
  return new Date(Math.max(...dates.map((date) => date.getTime())));
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

  const [scheduledReports, reports, users, activity, webApps, wasScans, wasAuth, wasSchedules] = await Promise.all([
    collect("scheduled_reports", () => client.listScheduledReports(), [] as JsonRecord[], errors),
    collect("reports", () => client.listReports(), [] as JsonRecord[], errors),
    collect("users", () => client.searchUsers(), [] as JsonRecord[], errors),
    collect("activity_log", () => client.listActivityLog(settings.lookbackDays), [] as JsonRecord[], errors),
    collect("was_webapps", () => client.searchWebApps(), [] as JsonRecord[], errors),
    collect("was_scans", () => client.searchWasScans(settings.lookbackDays), [] as JsonRecord[], errors),
    collect("was_auth_records", () => client.searchWasAuthRecords(), [] as JsonRecord[], errors),
    collect("was_schedules", () => client.searchWasSchedules(), [] as JsonRecord[], errors),
  ]);

  const activeScheduledReports = scheduledReports.data.filter(reportIsActive);
  const recentReports = reports.data.filter((report) => (ageInDays(report.LAUNCH_DATETIME, now) ?? Number.POSITIVE_INFINITY) <= settings.lookbackDays);

  const managers = users.data.filter(userIsManager).map(userName);
  const emailCounts = new Map<string, number>();
  for (const user of users.data) {
    const email = userEmail(user);
    if (email) emailCounts.set(email, (emailCounts.get(email) ?? 0) + 1);
  }
  const sharedEmails = [...emailCounts.entries()].filter(([, count]) => count > 1).map(([email]) => email);
  const genericAccounts = users.data.map(userName).filter((name) => /shared|generic|service|svc|admin\d*$|test/i.test(name));
  const inactiveUsers = users.data.filter((user) => {
    const age = ageInDays(user.LAST_LOGIN_DATE ?? user.lastLoginDate, now);
    return age !== undefined && age > 90;
  }).map(userName);

  const sensitiveActions = activity.data.filter((entry) => SENSITIVE_ACTIVITY_PATTERN.test(`${asString(entry.action) ?? ""} ${asString(entry.module) ?? ""} ${asString(entry.details) ?? ""}`));

  const unscannedWebApps = webApps.data.filter((webApp) => {
    const last = webAppLastScanDate(webApp, wasScans.data);
    return !last || ageInDays(last, now)! > settings.lookbackDays;
  }).map((webApp) => asString(webApp.name) ?? asString(webApp.id) ?? "web app");
  const staleWasAuth = wasAuth.data.filter((record) => (ageInDays(record.updatedDate ?? record.createdDate, now) ?? 0) > 180).map((record) => asString(record.name) ?? asString(record.id) ?? "auth record");
  const activeWasSchedules = wasSchedules.data.filter((schedule) => asBoolean(schedule.active) !== false);
  const wasModuleMissing = Boolean(webApps.error && isModuleUnavailableError(webApps.error));

  const findings: QualysFinding[] = [];

  findings.push(scheduledReports.error
    ? unavailableFinding(12, "medium", scheduledReports.error, "review Reports > Schedules and each schedule's distribution list for appropriate recipients.")
    : finding(
      12,
      "medium",
      activeScheduledReports.length === 0 ? "fail" : recentReports.length === 0 ? "warn" : "pass",
      activeScheduledReports.length === 0
        ? "No active scheduled reports exist, so automated report generation is not configured."
        : `${activeScheduledReports.length} active scheduled reports and ${recentReports.length} reports generated in the last ${settings.lookbackDays} days. Distribution recipients are not exposed by the API and must be reviewed in the UI.`,
      {
        active_scheduled_reports: activeScheduledReports.map((report) => asString(report.TITLE) ?? asString(report.ID)).slice(0, 50),
        recent_reports: recentReports.length,
        manual_evidence: "Distribution list recipients per scheduled report.",
      },
    ));

  findings.push(users.error
    ? unavailableFinding(13, "high", users.error, "export Users > User Management and review roles, last login dates, and shared accounts.")
    : finding(
      13,
      "high",
      users.data.length === 0 ? "warn" : managers.length > settings.maxManagers || sharedEmails.length > 0 ? "fail" : genericAccounts.length > 0 || inactiveUsers.length > 0 ? "warn" : "pass",
      users.data.length === 0
        ? "No users were returned by the Administration API."
        : `${users.data.length} active users, ${managers.length} Manager or super user accounts (threshold ${settings.maxManagers}), ${sharedEmails.length} email addresses shared by multiple accounts, ${genericAccounts.length} generic-looking account names. Last login is not exposed by the Administration API, so inactive users must be reviewed in the UI.`,
      {
        users: users.data.length,
        managers: managers.slice(0, 50),
        max_managers: settings.maxManagers,
        shared_emails: sharedEmails.slice(0, 50),
        generic_accounts: genericAccounts.slice(0, 50),
        inactive_users: inactiveUsers.slice(0, 50),
        manual_evidence: "Users > User Management export with last login dates.",
      },
    ));

  findings.push(webApps.error
    ? unavailableFinding(15, "medium", webApps.error, wasModuleMissing
      ? "WAS module is not enabled for this account; confirm whether web applications are in scope and where they are scanned."
      : "export the WAS web application list with last scan dates and authentication record ages.")
    : finding(
      15,
      "medium",
      webApps.data.length === 0 ? "warn" : unscannedWebApps.length > 0 ? "fail" : staleWasAuth.length > 0 ? "warn" : "pass",
      webApps.data.length === 0
        ? "WAS is enabled but no web applications are inventoried."
        : `${unscannedWebApps.length}/${webApps.data.length} web applications have no finished vulnerability scan within ${settings.lookbackDays} days; ${staleWasAuth.length} WAS authentication records are older than 180 days; ${activeWasSchedules.length} WAS schedules are active.`,
      {
        web_apps: webApps.data.length,
        unscanned_web_apps: unscannedWebApps.slice(0, 50),
        stale_auth_records: staleWasAuth.slice(0, 50),
        active_schedules: activeWasSchedules.length,
        scans_in_lookback: wasScans.data.length,
      },
    ));

  findings.push(activity.error
    ? unavailableFinding(19, "medium", activity.error, "export the Activity Log for the review period and document who reviews sensitive administrative actions and how long the log is retained.")
    : finding(
      19,
      "medium",
      activity.data.length === 0 ? "warn" : sensitiveActions.length > 0 ? "warn" : "pass",
      activity.data.length === 0
        ? `The activity log returned no entries for the last ${settings.lookbackDays} days.`
        : `${activity.data.length} activity log entries in the last ${settings.lookbackDays} days, ${sensitiveActions.length} involve sensitive administrative actions that need reviewer sign-off. Retention and review cadence must be documented manually.`,
      {
        entries: activity.data.length,
        sensitive_actions: sensitiveActions.slice(0, 50).map((entry) => ({
          date: asString(entry.date),
          action: asString(entry.action),
          module: asString(entry.module),
          user: asString(entry.user_name),
        })),
        manual_evidence: "Activity log retention setting and evidence of periodic review.",
      },
    ));

  return {
    category: "administration",
    title: "Qualys administration and reporting hygiene",
    summary: {
      platform: config.platform,
      active_scheduled_reports: activeScheduledReports.length,
      recent_reports: recentReports.length,
      users: users.data.length,
      managers: managers.length,
      shared_emails: sharedEmails.length,
      activity_entries: activity.data.length,
      sensitive_actions: sensitiveActions.length,
      web_apps: webApps.data.length,
      unscanned_web_apps: unscannedWebApps.length,
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
    return { name, module, endpoint, status: "readable", count: Array.isArray(value) ? value.length : undefined };
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
  const surfaces: QualysAccessSurface[] = [
    await probeSurface("scheduled_scans", "VM", "/api/2.0/fo/schedule/scan/", () => client.listScheduledScans()),
    await probeSurface("hosts", "VM", "/api/2.0/fo/asset/host/", () => client.listHosts(100)),
    await probeSurface("asset_groups", "VM", "/api/2.0/fo/asset/group/", () => client.listAssetGroups()),
    await probeSurface("option_profiles", "VM", "/api/2.0/fo/subscription/option_profile/", () => client.listOptionProfiles()),
    await probeSurface("appliances", "VM", "/api/2.0/fo/appliance/", () => client.listAppliances()),
    await probeSurface("auth_records", "VM", "/api/2.0/fo/auth/", () => client.listAuthRecordSummary()),
    await probeSurface("detections", "VMDR", "/api/2.0/fo/asset/host/vm/detection/", () => client.listDetections(100)),
    await probeSurface("compliance_policies", "PC", "/api/2.0/fo/compliance/policy/", () => client.listCompliancePolicies()),
    await probeSurface("activity_log", "Administration", "/api/2.0/fo/activity_log/", () => client.listActivityLog(7)),
    await probeSurface("users", "Administration", "/qps/rest/2.0/search/am/user/", () => client.searchUsers()),
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
  const status: QualysAccessCheckResult["status"] = coreReadable < coreSurfaces.length ? "limited" : anyFailures ? "degraded" : "healthy";
  const readableCount = surfaces.filter((surface) => surface.status === "readable").length;

  return {
    status,
    platform: config.platform,
    baseUrl: config.baseUrl,
    authMode: config.authMode,
    surfaces,
    unavailableModules,
    rateLimit: client.lastRateLimit ?? {},
    notes: [
      `Using Qualys platform ${config.platform} at ${config.baseUrl} with ${config.authMode} authentication.`,
      `${readableCount}/${surfaces.length} Qualys audit surfaces are readable.`,
      unavailableModules.length > 0
        ? `Modules or roles not available to this account: ${unavailableModules.join(", ")}. Controls depending on them are reported as manual.`
        : "All probed modules responded.",
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

  const zipPath = `${outputDir}.zip`;
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
