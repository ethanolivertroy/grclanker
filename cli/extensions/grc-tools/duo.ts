/**
 * Duo GRC assessment tools.
 *
 * Native TypeScript implementation grounded in the official Duo Admin API and
 * the current official Duo Node client signing behavior. The first slice stays
 * read-only and Admin API–first so GRC engineers can assess a tenant with one
 * audit principal.
 */
import { createHash, createHmac } from "node:crypto";
import {
  createWriteStream,
  existsSync,
  lstatSync,
  mkdirSync,
  realpathSync,
} from "node:fs";
import { chmod, readdir, writeFile } from "node:fs/promises";
import { basename, dirname, join, relative, resolve } from "node:path";
import archiver from "archiver";
import { Type } from "@sinclair/typebox";
import { errorResult, formatTable, textResult } from "./shared.js";

type JsonRecord = Record<string, unknown>;
type DuoFindingStatus = "Pass" | "Partial" | "Fail" | "Manual" | "Info";
type DuoSeverity = "critical" | "high" | "medium" | "low" | "info";
type FrameworkKey =
  | "fedramp"
  | "cmmc"
  | "soc2"
  | "cis"
  | "pci_dss"
  | "disa_stig"
  | "irap"
  | "ismap"
  | "general";

const DEFAULT_OUTPUT_DIR = "./export/duo";
const DEFAULT_LOOKBACK_DAYS = 30;
const OFFSET_PAGE_SIZE = 100;
const LOG_PAGE_SIZE = 200;
const MAX_LOG_RECORDS = 400;
const MAX_RETRIES = 4;

type RawConfigArgs = {
  api_host?: string;
  ikey?: string;
  skey?: string;
  lookback_days?: number;
};

type DuoConfigOverlay = {
  apiHost?: string;
  ikey?: string;
  skey?: string;
  lookbackDays?: number;
};

export interface DuoResolvedConfig {
  apiHost: string;
  ikey: string;
  skey: string;
  lookbackDays: number;
  sourceChain: string[];
}

type DuoEndpointStatus = "ok" | "forbidden" | "unauthorized" | "error";

export interface DuoAccessProbe {
  key: string;
  path: string;
  status: DuoEndpointStatus;
  detail: string;
}

export interface DuoAccessCheckResult {
  organization: string;
  status: "healthy" | "limited";
  sourceChain: string[];
  probes: DuoAccessProbe[];
  notes: string[];
  recommendedNextStep: string;
}

interface FrameworkMap {
  fedramp: string[];
  cmmc: string[];
  soc2: string[];
  cis: string[];
  pci_dss: string[];
  disa_stig: string[];
  irap: string[];
  ismap: string[];
  general: string[];
}

interface CheckDefinition {
  id: string;
  title: string;
  category: "authentication" | "admin_access" | "integrations" | "monitoring";
  severity: DuoSeverity;
  frameworks: FrameworkMap;
}

export interface DuoFinding {
  id: string;
  title: string;
  category: CheckDefinition["category"];
  status: DuoFindingStatus;
  severity: DuoSeverity;
  summary: string;
  evidence: string[];
  recommendation: string;
  manualNote?: string;
  frameworks: FrameworkMap;
}

export interface DuoAssessmentResult {
  category: CheckDefinition["category"];
  findings: DuoFinding[];
  summary: Record<DuoFindingStatus, number>;
  snapshotSummary: Record<string, number | string>;
  text: string;
}

interface CollectedDataset<T = unknown> {
  data: T;
  error?: string;
}

interface DuoAuthenticationData {
  settings: CollectedDataset<JsonRecord | null>;
  policies: CollectedDataset<JsonRecord[]>;
  globalPolicy: CollectedDataset<JsonRecord | null>;
  users: CollectedDataset<JsonRecord[]>;
  bypassCodes: CollectedDataset<JsonRecord[]>;
  webauthnCredentials: CollectedDataset<JsonRecord[]>;
  allowedAdminAuthMethods: CollectedDataset<JsonRecord | null>;
  authenticationLogs: CollectedDataset<JsonRecord[]>;
}

interface DuoAdminAccessData {
  settings: CollectedDataset<JsonRecord | null>;
  admins: CollectedDataset<JsonRecord[]>;
  allowedAdminAuthMethods: CollectedDataset<JsonRecord | null>;
  activityLogs: CollectedDataset<JsonRecord[]>;
}

interface DuoIntegrationData {
  settings: CollectedDataset<JsonRecord | null>;
  policies: CollectedDataset<JsonRecord[]>;
  globalPolicy: CollectedDataset<JsonRecord | null>;
  integrations: CollectedDataset<JsonRecord[]>;
}

interface DuoMonitoringData {
  settings: CollectedDataset<JsonRecord | null>;
  infoSummary: CollectedDataset<JsonRecord | null>;
  authenticationLogs: CollectedDataset<JsonRecord[]>;
  activityLogs: CollectedDataset<JsonRecord[]>;
  telephonyLogs: CollectedDataset<JsonRecord[]>;
  trustMonitorEvents: CollectedDataset<JsonRecord[]>;
}

interface DuoAuditBundleResult {
  outputDir: string;
  zipPath: string;
  fileCount: number;
  findingCount: number;
  errorCount: number;
}

type FetchImpl = typeof fetch;
type DuoRequestParamValue = string | number | boolean | Array<string | number | boolean>;
type DuoRequestParams = Record<string, DuoRequestParamValue | undefined>;

const DUO_ACCESS_PROBES = [
  { key: "settings", path: "/admin/v1/settings" },
  { key: "users", path: "/admin/v1/users", params: { limit: 1 } },
  { key: "policies", path: "/admin/v2/policies", params: { limit: 1 } },
  { key: "admins", path: "/admin/v1/admins", params: { limit: 1 } },
  { key: "logs", path: "/admin/v2/logs/authentication", logWindow: true },
  { key: "integrations", path: "/admin/v3/integrations", params: { limit: 1 } },
] as const;

const DUO_CHECKS: Record<string, CheckDefinition> = {
  "DUO-AUTH-001": {
    id: "DUO-AUTH-001",
    title: "Phishing-resistant authentication methods",
    category: "authentication",
    severity: "high",
    frameworks: {
      fedramp: ["IA-2(1)", "IA-2(11)"],
      cmmc: ["3.5.3"],
      soc2: ["CC6.1"],
      cis: ["6.3"],
      pci_dss: ["8.4.2"],
      disa_stig: ["SRG-APP-000149"],
      irap: ["ISM-1504"],
      ismap: ["CPS.AT-2"],
      general: ["phishing-resistant MFA"],
    },
  },
  "DUO-AUTH-002": {
    id: "DUO-AUTH-002",
    title: "Deprecated authentication methods restricted",
    category: "authentication",
    severity: "medium",
    frameworks: {
      fedramp: ["IA-2(6)"],
      cmmc: ["3.5.3"],
      soc2: ["CC6.1"],
      cis: ["6.4"],
      pci_dss: ["8.4.3"],
      disa_stig: ["SRG-APP-000156"],
      irap: ["ISM-1515"],
      ismap: ["CPS.IA-2"],
      general: ["legacy factors minimized"],
    },
  },
  "DUO-AUTH-003": {
    id: "DUO-AUTH-003",
    title: "New user enrollment policy",
    category: "authentication",
    severity: "high",
    frameworks: {
      fedramp: ["AC-2(2)"],
      cmmc: ["3.1.1"],
      soc2: ["CC6.2"],
      cis: ["5.3"],
      pci_dss: ["8.2.1"],
      disa_stig: ["SRG-APP-000024"],
      irap: ["ISM-0415"],
      ismap: ["CPS.AC-2"],
      general: ["new users enroll before access"],
    },
  },
  "DUO-AUTH-004": {
    id: "DUO-AUTH-004",
    title: "Remembered devices posture",
    category: "authentication",
    severity: "medium",
    frameworks: {
      fedramp: ["AC-12"],
      cmmc: ["3.1.10"],
      soc2: ["CC6.1"],
      cis: ["5.4"],
      pci_dss: ["8.2.8"],
      disa_stig: ["SRG-APP-000295"],
      irap: ["ISM-1164"],
      ismap: ["CPS.AC-7"],
      general: ["persistent sessions limited"],
    },
  },
  "DUO-AUTH-005": {
    id: "DUO-AUTH-005",
    title: "Trusted endpoints and device health",
    category: "authentication",
    severity: "high",
    frameworks: {
      fedramp: ["CM-6", "CM-8(3)"],
      cmmc: ["3.4.1", "3.4.2"],
      soc2: ["CC6.7"],
      cis: ["4.1"],
      pci_dss: ["2.2.1"],
      disa_stig: ["SRG-APP-000383", "SRG-APP-000384"],
      irap: ["ISM-1082", "ISM-1599"],
      ismap: ["CPS.CM-6", "CPS.CM-8"],
      general: ["managed devices preferred"],
    },
  },
  "DUO-AUTH-006": {
    id: "DUO-AUTH-006",
    title: "Bypass code hygiene",
    category: "authentication",
    severity: "high",
    frameworks: {
      fedramp: ["IA-5(1)"],
      cmmc: ["3.5.10"],
      soc2: ["CC6.1"],
      cis: ["6.6"],
      pci_dss: ["8.6.3"],
      disa_stig: ["SRG-APP-000175"],
      irap: ["ISM-1557"],
      ismap: ["CPS.IA-5"],
      general: ["break-glass controls constrained"],
    },
  },
  "DUO-ADMIN-001": {
    id: "DUO-ADMIN-001",
    title: "Owner and privileged admin concentration",
    category: "admin_access",
    severity: "high",
    frameworks: {
      fedramp: ["AC-6(5)"],
      cmmc: ["3.1.5"],
      soc2: ["CC6.3"],
      cis: ["4.3"],
      pci_dss: ["7.1.1"],
      disa_stig: ["SRG-APP-000340"],
      irap: ["ISM-1507"],
      ismap: ["CPS.AC-6"],
      general: ["least privilege"],
    },
  },
  "DUO-ADMIN-002": {
    id: "DUO-ADMIN-002",
    title: "Administrator authentication strength",
    category: "admin_access",
    severity: "high",
    frameworks: {
      fedramp: ["IA-2(1)", "IA-2(11)"],
      cmmc: ["3.5.3"],
      soc2: ["CC6.1"],
      cis: ["6.4"],
      pci_dss: ["8.4.2"],
      disa_stig: ["SRG-APP-000149"],
      irap: ["ISM-1504"],
      ismap: ["CPS.AT-2"],
      general: ["admin MFA hardening"],
    },
  },
  "DUO-ADMIN-003": {
    id: "DUO-ADMIN-003",
    title: "Help desk bypass governance",
    category: "admin_access",
    severity: "high",
    frameworks: {
      fedramp: ["AC-6(10)"],
      cmmc: ["3.1.7"],
      soc2: ["CC6.3"],
      cis: ["6.7"],
      pci_dss: ["7.2.1"],
      disa_stig: ["SRG-APP-000343"],
      irap: ["ISM-0988"],
      ismap: ["CPS.AC-6"],
      general: ["support bypass scoped"],
    },
  },
  "DUO-ADMIN-004": {
    id: "DUO-ADMIN-004",
    title: "Stale privileged administrator review",
    category: "admin_access",
    severity: "medium",
    frameworks: {
      fedramp: ["AC-2(3)"],
      cmmc: ["3.1.12"],
      soc2: ["CC6.2"],
      cis: ["5.3"],
      pci_dss: ["8.1.4"],
      disa_stig: ["SRG-APP-000025"],
      irap: ["ISM-1591"],
      ismap: ["CPS.AC-2"],
      general: ["inactive admins reviewed"],
    },
  },
  "DUO-INTEGRATIONS-001": {
    id: "DUO-INTEGRATIONS-001",
    title: "Protected integrations have explicit policy coverage",
    category: "integrations",
    severity: "high",
    frameworks: {
      fedramp: ["CM-2", "CM-8"],
      cmmc: ["3.4.1"],
      soc2: ["CC6.8"],
      cis: ["4.5"],
      pci_dss: ["2.2.1"],
      disa_stig: ["SRG-APP-000386"],
      irap: ["ISM-1624"],
      ismap: ["CPS.CM-2"],
      general: ["integration policy assignment"],
    },
  },
  "DUO-INTEGRATIONS-002": {
    id: "DUO-INTEGRATIONS-002",
    title: "Universal Prompt adoption",
    category: "integrations",
    severity: "medium",
    frameworks: {
      fedramp: ["IA-2(1)"],
      cmmc: ["3.5.3"],
      soc2: ["CC6.1"],
      cis: ["6.4"],
      pci_dss: ["8.4.2"],
      disa_stig: ["SRG-APP-000149"],
      irap: ["ISM-1515"],
      ismap: ["CPS.IA-2"],
      general: ["modern Duo prompt coverage"],
    },
  },
  "DUO-INTEGRATIONS-003": {
    id: "DUO-INTEGRATIONS-003",
    title: "Self-service portal governance",
    category: "integrations",
    severity: "medium",
    frameworks: {
      fedramp: ["AC-2(1)"],
      cmmc: ["3.1.1"],
      soc2: ["CC6.2"],
      cis: ["5.3"],
      pci_dss: ["8.2.4"],
      disa_stig: ["SRG-APP-000023"],
      irap: ["ISM-1594"],
      ismap: ["CPS.AC-2"],
      general: ["self-service bounded"],
    },
  },
  "DUO-INTEGRATIONS-004": {
    id: "DUO-INTEGRATIONS-004",
    title: "Administrative API integration permissions",
    category: "integrations",
    severity: "high",
    frameworks: {
      fedramp: ["AC-6(10)"],
      cmmc: ["3.1.7"],
      soc2: ["CC6.3"],
      cis: ["4.3"],
      pci_dss: ["7.2.1"],
      disa_stig: ["SRG-APP-000343"],
      irap: ["ISM-0988"],
      ismap: ["CPS.AC-6"],
      general: ["API credentials least privilege"],
    },
  },
  "DUO-MON-001": {
    id: "DUO-MON-001",
    title: "Authentication log visibility and factor hygiene",
    category: "monitoring",
    severity: "medium",
    frameworks: {
      fedramp: ["AU-6", "SI-4"],
      cmmc: ["3.3.5", "3.14.6"],
      soc2: ["CC7.2"],
      cis: ["8.2"],
      pci_dss: ["10.6.1"],
      disa_stig: ["SRG-APP-000516"],
      irap: ["ISM-0109"],
      ismap: ["CPS.AU-6"],
      general: ["auth telemetry reviewed"],
    },
  },
  "DUO-MON-002": {
    id: "DUO-MON-002",
    title: "Trust Monitor coverage",
    category: "monitoring",
    severity: "medium",
    frameworks: {
      fedramp: ["SI-4"],
      cmmc: ["3.14.6"],
      soc2: ["CC7.2"],
      cis: ["8.7"],
      pci_dss: ["10.6.1"],
      disa_stig: ["SRG-APP-000516"],
      irap: ["ISM-0580"],
      ismap: ["CPS.SI-4"],
      general: ["anomaly monitoring active"],
    },
  },
  "DUO-MON-003": {
    id: "DUO-MON-003",
    title: "Telephony reliance and credit headroom",
    category: "monitoring",
    severity: "low",
    frameworks: {
      fedramp: ["SA-9"],
      cmmc: ["3.13.2"],
      soc2: ["CC9.1"],
      cis: ["13.1"],
      pci_dss: [],
      disa_stig: ["SRG-APP-000516"],
      irap: ["ISM-0888"],
      ismap: ["CPS.SA-9"],
      general: ["telephony capacity monitored"],
    },
  },
  "DUO-MON-004": {
    id: "DUO-MON-004",
    title: "Administrative and fraud notifications",
    category: "monitoring",
    severity: "medium",
    frameworks: {
      fedramp: ["AU-5", "AU-6"],
      cmmc: ["3.3.6"],
      soc2: ["CC7.2"],
      cis: ["8.8"],
      pci_dss: ["10.7.2"],
      disa_stig: ["SRG-APP-000516"],
      irap: ["ISM-0109"],
      ismap: ["CPS.AU-6"],
      general: ["operator notification path"],
    },
  },
};

function compareUnicode(a: string, b: string): number {
  for (let index = 0; index < Math.min(a.length, b.length); index += 1) {
    const aChar = a.charCodeAt(index);
    const bChar = b.charCodeAt(index);
    if (aChar < bChar) return -1;
    if (aChar > bChar) return 1;
  }
  if (a.length < b.length) return -1;
  if (a.length > b.length) return 1;
  return 0;
}

function encodeComponent(value: string): string {
  return encodeURIComponent(value).replace(/[!'()*]/g, (match) =>
    `%${match.charCodeAt(0).toString(16).toUpperCase()}`,
  );
}

function canonParams(params: Record<string, string | string[]>): string {
  return Object.keys(params)
    .sort(compareUnicode)
    .map((key) => {
      const prefix = `${encodeComponent(key)}=`;
      const value = params[key];
      if (Array.isArray(value)) {
        return value.map((item) => `${prefix}${encodeComponent(item)}`).join("&");
      }
      return `${prefix}${encodeComponent(value)}`;
    })
    .join("&");
}

function canonicalizeV2(
  method: string,
  host: string,
  path: string,
  params: Record<string, string | string[]>,
  date: string,
): string {
  return [date, method.toUpperCase(), host.toLowerCase(), path, canonParams(params)].join("\n");
}

function hashString(value: string): string {
  return createHash("sha512").update(value).digest("hex");
}

function canonicalizeV5(
  method: string,
  host: string,
  path: string,
  params: Record<string, string | string[]>,
  date: string,
  body: string,
): string {
  return [
    date,
    method.toUpperCase(),
    host.toLowerCase(),
    path,
    canonParams(params),
    hashString(body),
    hashString(""),
  ].join("\n");
}

function signV2(
  ikey: string,
  skey: string,
  method: string,
  host: string,
  path: string,
  params: Record<string, string | string[]>,
  date: string,
): string {
  const signature = createHmac("sha512", skey)
    .update(canonicalizeV2(method, host, path, params, date))
    .digest("hex");
  return `Basic ${Buffer.from(`${ikey}:${signature}`).toString("base64")}`;
}

function signV5(
  ikey: string,
  skey: string,
  method: string,
  host: string,
  path: string,
  params: Record<string, string | string[]>,
  date: string,
  body: string,
): string {
  const signature = createHmac("sha512", skey)
    .update(canonicalizeV5(method, host, path, params, date, body))
    .digest("hex");
  return `Basic ${Buffer.from(`${ikey}:${signature}`).toString("base64")}`;
}

function normalizeHost(value: string): string {
  const trimmed = value.trim();
  if (!trimmed) return "";
  if (trimmed.startsWith("http://") || trimmed.startsWith("https://")) {
    const url = new URL(trimmed);
    return url.host.toLowerCase();
  }
  return trimmed.replace(/^\/+|\/+$/g, "").toLowerCase();
}

function parseOptionalNumber(value: unknown): number | undefined {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string" && value.trim().length > 0) {
    const parsed = Number.parseInt(value.trim(), 10);
    if (Number.isFinite(parsed)) return parsed;
  }
  return undefined;
}

function clampLookbackDays(value: number | undefined): number {
  const raw = value ?? DEFAULT_LOOKBACK_DAYS;
  return Math.min(180, Math.max(1, raw));
}

function overlayFromArgs(args: RawConfigArgs): DuoConfigOverlay {
  return {
    apiHost: args.api_host?.trim(),
    ikey: args.ikey?.trim(),
    skey: args.skey?.trim(),
    lookbackDays: parseOptionalNumber(args.lookback_days),
  };
}

function overlayFromEnv(env: NodeJS.ProcessEnv): DuoConfigOverlay {
  return {
    apiHost: env.DUO_API_HOST?.trim(),
    ikey: env.DUO_IKEY?.trim(),
    skey: env.DUO_SKEY?.trim(),
    lookbackDays: parseOptionalNumber(env.DUO_LOOKBACK_DAYS),
  };
}

function applyOverlay(base: DuoConfigOverlay, overlay: DuoConfigOverlay | undefined): DuoConfigOverlay {
  if (!overlay) return base;
  return {
    apiHost: overlay.apiHost ?? base.apiHost,
    ikey: overlay.ikey ?? base.ikey,
    skey: overlay.skey ?? base.skey,
    lookbackDays: overlay.lookbackDays ?? base.lookbackDays,
  };
}

export function resolveDuoConfiguration(
  args: RawConfigArgs = {},
  env: NodeJS.ProcessEnv = process.env,
): DuoResolvedConfig {
  let merged: DuoConfigOverlay = {};
  const sourceChain: string[] = [];

  const envOverlay = overlayFromEnv(env);
  if (envOverlay.apiHost || envOverlay.ikey || envOverlay.skey || envOverlay.lookbackDays !== undefined) {
    merged = applyOverlay(merged, envOverlay);
    sourceChain.push("environment");
  }

  const argOverlay = overlayFromArgs(args);
  if (argOverlay.apiHost || argOverlay.ikey || argOverlay.skey || argOverlay.lookbackDays !== undefined) {
    merged = applyOverlay(merged, argOverlay);
    sourceChain.push("arguments");
  }

  const apiHost = normalizeHost(merged.apiHost ?? "");
  if (!apiHost) {
    throw new Error(
      "Duo API hostname is required. Set DUO_API_HOST or pass api_host explicitly.",
    );
  }

  const ikey = merged.ikey?.trim();
  if (!ikey) {
    throw new Error("Duo integration key is required. Set DUO_IKEY or pass ikey explicitly.");
  }

  const skey = merged.skey?.trim();
  if (!skey) {
    throw new Error("Duo secret key is required. Set DUO_SKEY or pass skey explicitly.");
  }

  return {
    apiHost,
    ikey,
    skey,
    lookbackDays: clampLookbackDays(merged.lookbackDays),
    sourceChain,
  };
}

function compactParams(params: DuoRequestParams): Record<string, string | string[]> {
  return Object.entries(params).reduce<Record<string, string | string[]>>((result, [key, value]) => {
    if (value === undefined || value === null) return result;
    if (Array.isArray(value)) {
      result[key] = value.map((item) => String(item));
      return result;
    }
    result[key] = String(value);
    return result;
  }, {});
}

function isV5Path(path: string): boolean {
  return path.startsWith("/admin/v3/");
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolveSleep) => setTimeout(resolveSleep, ms));
}

function parseDetailFromBody(body: unknown): string | undefined {
  const record = asRecord(body);
  const message = asString(record.message);
  const detail = asString(record.message_detail);
  if (message && detail) return `${message}: ${detail}`;
  return message ?? detail;
}

function extractMetadata(payload: unknown): JsonRecord {
  const envelope = asRecord(payload);
  const topLevel = asRecord(envelope.metadata);
  if (Object.keys(topLevel).length > 0) return topLevel;
  return asRecord(asRecord(envelope.response).metadata);
}

function extractArrayPayload(payload: unknown): JsonRecord[] {
  if (Array.isArray(payload)) {
    return payload.filter((item): item is JsonRecord => typeof item === "object" && item !== null);
  }

  const record = asRecord(payload);
  const candidateKeys = ["items", "events", "users", "admins", "results"];
  for (const key of candidateKeys) {
    const candidate = record[key];
    if (Array.isArray(candidate)) {
      return candidate.filter((item): item is JsonRecord => typeof item === "object" && item !== null);
    }
  }

  return [];
}

function nextOffsetValue(metadata: JsonRecord, key: "offset" | "next_offset"): string | number | undefined {
  const raw = metadata.next_offset;
  if (raw === undefined || raw === null) return undefined;
  if (key === "offset" && typeof raw === "number") return raw;
  if (typeof raw === "string" || typeof raw === "number") return raw;
  if (Array.isArray(raw)) return raw.map(String).join(",");
  return undefined;
}

export class DuoAuditorClient {
  private readonly config: DuoResolvedConfig;
  private readonly fetchImpl: FetchImpl;

  constructor(config: DuoResolvedConfig, options?: { fetchImpl?: FetchImpl }) {
    this.config = config;
    this.fetchImpl = options?.fetchImpl ?? fetch;
  }

  private buildWindow(days: number): Record<string, number> {
    const now = Date.now() - 2 * 60 * 1000;
    return {
      mintime: now - clampLookbackDays(days) * 24 * 60 * 60 * 1000,
      maxtime: now,
    };
  }

  private async requestEnvelope(
    path: string,
    params: DuoRequestParams = {},
    options?: { method?: "GET" | "POST"; signatureVersion?: 2 | 5; body?: string },
  ): Promise<JsonRecord> {
    const method = options?.method ?? "GET";
    const signatureVersion = options?.signatureVersion ?? (isV5Path(path) ? 5 : 2);
    const normalizedParams = compactParams(params);
    const date = new Date().toUTCString();
    const body = options?.body ?? "";
    const authorization =
      signatureVersion === 5
        ? signV5(
            this.config.ikey,
            this.config.skey,
            method,
            this.config.apiHost,
            path,
            normalizedParams,
            date,
            body,
          )
        : signV2(
            this.config.ikey,
            this.config.skey,
            method,
            this.config.apiHost,
            path,
            normalizedParams,
            date,
          );

    let url = `https://${this.config.apiHost}${path}`;
    const query = canonParams(normalizedParams);
    if (method === "GET" && query) {
      url = `${url}?${query}`;
    }

    const headers: Record<string, string> = {
      Authorization: authorization,
      Date: date,
      Host: this.config.apiHost,
      "User-Agent": "grclanker/0.0.1 duo-audit",
    };

    if (method !== "GET" && body.length > 0) {
      headers["Content-Type"] = signatureVersion === 5 ? "application/json" : "application/x-www-form-urlencoded";
    }

    for (let attempt = 0; attempt <= MAX_RETRIES; attempt += 1) {
      const response = await this.fetchImpl(url, { method, headers, body: body || undefined });
      const text = await response.text();
      let parsed: JsonRecord | null = null;

      if (text.trim().length > 0) {
        try {
          parsed = JSON.parse(text) as JsonRecord;
        } catch {
          parsed = null;
        }
      }

      if (response.status === 429 && attempt < MAX_RETRIES) {
        const retryAfterHeader = response.headers.get("retry-after");
        const retryAfterMs = retryAfterHeader ? Number.parseInt(retryAfterHeader, 10) * 1000 : 0;
        const backoffMs = retryAfterMs > 0 ? retryAfterMs : (attempt + 1) * 1000 + Math.floor(Math.random() * 250);
        await sleep(backoffMs);
        continue;
      }

      if (!response.ok) {
        const detail = parseDetailFromBody(parsed ?? text);
        throw new Error(
          `Duo API request failed for ${path} (${response.status} ${response.statusText})${detail ? `: ${detail}` : ""}`,
        );
      }

      if (!parsed || asString(parsed.stat) !== "OK") {
        const detail = parseDetailFromBody(parsed ?? text);
        throw new Error(
          `Duo API request returned an unexpected payload for ${path}${detail ? `: ${detail}` : ""}`,
        );
      }

      return parsed;
    }

    throw new Error(`Duo API request exceeded retry budget for ${path}.`);
  }

  private async request<T>(
    path: string,
    params: DuoRequestParams = {},
    options?: { method?: "GET" | "POST"; signatureVersion?: 2 | 5; body?: string },
  ): Promise<T> {
    const envelope = await this.requestEnvelope(path, params, options);
    return envelope.response as T;
  }

  async getSettings(): Promise<JsonRecord> {
    return this.request<JsonRecord>("/admin/v1/settings");
  }

  async getInfoSummary(): Promise<JsonRecord> {
    return this.request<JsonRecord>("/admin/v1/info/summary");
  }

  async getAdminAllowedAuthMethods(): Promise<JsonRecord> {
    return this.request<JsonRecord>("/admin/v1/admins/allowed_auth_methods");
  }

  async getGlobalPolicy(): Promise<JsonRecord> {
    return this.request<JsonRecord>("/admin/v2/policies/global");
  }

  async listPolicies(): Promise<JsonRecord[]> {
    return this.listOffsetPages("/admin/v2/policies", {}, OFFSET_PAGE_SIZE);
  }

  async listUsers(): Promise<JsonRecord[]> {
    return this.listOffsetPages("/admin/v1/users", {}, OFFSET_PAGE_SIZE);
  }

  async listBypassCodes(): Promise<JsonRecord[]> {
    return this.listOffsetPages("/admin/v1/bypass_codes", {}, OFFSET_PAGE_SIZE);
  }

  async listWebauthnCredentials(): Promise<JsonRecord[]> {
    return this.listOffsetPages("/admin/v1/webauthncredentials", {}, OFFSET_PAGE_SIZE);
  }

  async listAdmins(): Promise<JsonRecord[]> {
    return this.listOffsetPages("/admin/v1/admins", {}, OFFSET_PAGE_SIZE);
  }

  async listIntegrations(): Promise<JsonRecord[]> {
    return this.listOffsetPages("/admin/v3/integrations", {}, OFFSET_PAGE_SIZE, 5);
  }

  async listAuthenticationLogs(days: number, maxRecords: number = MAX_LOG_RECORDS): Promise<JsonRecord[]> {
    return this.listCursorPages("/admin/v2/logs/authentication", this.buildWindow(days), maxRecords);
  }

  async listActivityLogs(days: number, maxRecords: number = MAX_LOG_RECORDS): Promise<JsonRecord[]> {
    return this.listCursorPages("/admin/v2/logs/activity", this.buildWindow(days), maxRecords);
  }

  async listTelephonyLogs(days: number, maxRecords: number = MAX_LOG_RECORDS): Promise<JsonRecord[]> {
    return this.listCursorPages("/admin/v2/logs/telephony", this.buildWindow(days), maxRecords);
  }

  async listTrustMonitorEvents(days: number, maxRecords: number = MAX_LOG_RECORDS): Promise<JsonRecord[]> {
    return this.listOffsetPages("/admin/v1/trust_monitor/events", this.buildWindow(days), 50, 2, maxRecords);
  }

  private async listOffsetPages(
    path: string,
    params: DuoRequestParams,
    pageSize: number,
    signatureVersion?: 2 | 5,
    maxRecords?: number,
  ): Promise<JsonRecord[]> {
    const items: JsonRecord[] = [];
    let offset = 0;

    while (true) {
      const envelope = await this.requestEnvelope(
        path,
        { ...params, limit: pageSize, offset },
        signatureVersion ? { signatureVersion } : undefined,
      );
      items.push(...extractArrayPayload(envelope.response));
      if (maxRecords && items.length >= maxRecords) break;
      const metadata = extractMetadata(envelope);
      const next = nextOffsetValue(metadata, "offset");
      if (typeof next !== "number") break;
      offset = next;
    }

    return maxRecords ? items.slice(0, maxRecords) : items;
  }

  private async listCursorPages(
    path: string,
    params: DuoRequestParams,
    maxRecords: number,
  ): Promise<JsonRecord[]> {
    const items: JsonRecord[] = [];
    let nextOffset: string | undefined;

    while (items.length < maxRecords) {
      const envelope = await this.requestEnvelope(path, {
        ...params,
        limit: Math.min(LOG_PAGE_SIZE, maxRecords - items.length),
        sort: "ts:desc",
        next_offset: nextOffset,
      });
      items.push(...extractArrayPayload(envelope.response));
      const metadata = extractMetadata(envelope);
      const next = nextOffsetValue(metadata, "next_offset");
      if (next === undefined) break;
      nextOffset = String(next);
    }

    return items;
  }
}

function asRecord(value: unknown): JsonRecord {
  return typeof value === "object" && value !== null ? (value as JsonRecord) : {};
}

function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function asString(value: unknown): string | undefined {
  return typeof value === "string" && value.trim().length > 0 ? value : undefined;
}

function asNumber(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function asBoolean(value: unknown): boolean | undefined {
  return typeof value === "boolean" ? value : undefined;
}

function listStrings(value: unknown): string[] {
  return asArray(value).map(asString).filter((item): item is string => Boolean(item));
}

function parseTimestamp(value: unknown): number | null {
  if (typeof value === "number" && Number.isFinite(value)) {
    return value > 10_000_000_000 ? value : value * 1000;
  }
  if (typeof value === "string") {
    const parsed = Date.parse(value);
    if (!Number.isNaN(parsed)) return parsed;
    const numeric = Number.parseInt(value, 10);
    if (Number.isFinite(numeric)) return numeric > 10_000_000_000 ? numeric : numeric * 1000;
  }
  return null;
}

function daysSince(value: unknown): number | null {
  const timestamp = parseTimestamp(value);
  if (timestamp === null) return null;
  return Math.floor((Date.now() - timestamp) / (24 * 60 * 60 * 1000));
}

async function collectArrayDataset<T extends JsonRecord>(
  loader: () => Promise<T[]>,
): Promise<CollectedDataset<T[]>> {
  try {
    return { data: await loader() };
  } catch (error) {
    return { data: [], error: error instanceof Error ? error.message : String(error) };
  }
}

async function collectObjectDataset<T>(
  loader: () => Promise<T>,
  fallback: T,
): Promise<CollectedDataset<T>> {
  try {
    return { data: await loader() };
  } catch (error) {
    return { data: fallback, error: error instanceof Error ? error.message : String(error) };
  }
}

export async function collectDuoAuthenticationData(
  client: Pick<
    DuoAuditorClient,
    | "getSettings"
    | "listPolicies"
    | "getGlobalPolicy"
    | "listUsers"
    | "listBypassCodes"
    | "listWebauthnCredentials"
    | "getAdminAllowedAuthMethods"
    | "listAuthenticationLogs"
  >,
  lookbackDays: number,
): Promise<DuoAuthenticationData> {
  return {
    settings: await collectObjectDataset(() => client.getSettings(), null),
    policies: await collectArrayDataset(() => client.listPolicies()),
    globalPolicy: await collectObjectDataset(() => client.getGlobalPolicy(), null),
    users: await collectArrayDataset(() => client.listUsers()),
    bypassCodes: await collectArrayDataset(() => client.listBypassCodes()),
    webauthnCredentials: await collectArrayDataset(() => client.listWebauthnCredentials()),
    allowedAdminAuthMethods: await collectObjectDataset(() => client.getAdminAllowedAuthMethods(), null),
    authenticationLogs: await collectArrayDataset(() => client.listAuthenticationLogs(lookbackDays)),
  };
}

export async function collectDuoAdminAccessData(
  client: Pick<
    DuoAuditorClient,
    "getSettings" | "listAdmins" | "getAdminAllowedAuthMethods" | "listActivityLogs"
  >,
  lookbackDays: number,
): Promise<DuoAdminAccessData> {
  return {
    settings: await collectObjectDataset(() => client.getSettings(), null),
    admins: await collectArrayDataset(() => client.listAdmins()),
    allowedAdminAuthMethods: await collectObjectDataset(() => client.getAdminAllowedAuthMethods(), null),
    activityLogs: await collectArrayDataset(() => client.listActivityLogs(lookbackDays)),
  };
}

export async function collectDuoIntegrationData(
  client: Pick<DuoAuditorClient, "getSettings" | "listPolicies" | "getGlobalPolicy" | "listIntegrations">,
): Promise<DuoIntegrationData> {
  return {
    settings: await collectObjectDataset(() => client.getSettings(), null),
    policies: await collectArrayDataset(() => client.listPolicies()),
    globalPolicy: await collectObjectDataset(() => client.getGlobalPolicy(), null),
    integrations: await collectArrayDataset(() => client.listIntegrations()),
  };
}

export async function collectDuoMonitoringData(
  client: Pick<
    DuoAuditorClient,
    | "getSettings"
    | "getInfoSummary"
    | "listAuthenticationLogs"
    | "listActivityLogs"
    | "listTelephonyLogs"
    | "listTrustMonitorEvents"
  >,
  lookbackDays: number,
): Promise<DuoMonitoringData> {
  return {
    settings: await collectObjectDataset(() => client.getSettings(), null),
    infoSummary: await collectObjectDataset(() => client.getInfoSummary(), null),
    authenticationLogs: await collectArrayDataset(() => client.listAuthenticationLogs(lookbackDays)),
    activityLogs: await collectArrayDataset(() => client.listActivityLogs(lookbackDays)),
    telephonyLogs: await collectArrayDataset(() => client.listTelephonyLogs(lookbackDays)),
    trustMonitorEvents: await collectArrayDataset(() => client.listTrustMonitorEvents(lookbackDays)),
  };
}

function buildFinding(
  id: keyof typeof DUO_CHECKS,
  status: DuoFindingStatus,
  summary: string,
  evidence: string[],
  recommendation: string,
  options?: { severity?: DuoSeverity; manualNote?: string },
): DuoFinding {
  const definition = DUO_CHECKS[id];
  return {
    id: definition.id,
    title: definition.title,
    category: definition.category,
    status,
    severity: options?.severity ?? definition.severity,
    summary,
    evidence,
    recommendation,
    manualNote: options?.manualNote,
    frameworks: definition.frameworks,
  };
}

function summarizeFindings(findings: DuoFinding[]): Record<DuoFindingStatus, number> {
  return findings.reduce<Record<DuoFindingStatus, number>>(
    (summary, finding) => {
      summary[finding.status] += 1;
      return summary;
    },
    { Pass: 0, Partial: 0, Fail: 0, Manual: 0, Info: 0 },
  );
}

function buildAssessmentText(
  title: string,
  organization: string,
  findings: DuoFinding[],
  snapshotSummary: Record<string, number | string>,
): string {
  const summary = summarizeFindings(findings);
  const summaryLines = Object.entries(snapshotSummary).map(([key, value]) => `${key.replace(/_/g, " ")}: ${value}`);
  const rows = findings.map((finding) => [
    finding.title,
    finding.status,
    finding.severity,
    finding.summary,
  ]);

  return [
    `${title} for ${organization}`,
    `Pass: ${summary.Pass}  Partial: ${summary.Partial}  Fail: ${summary.Fail}  Manual: ${summary.Manual}  Info: ${summary.Info}`,
    "",
    ...summaryLines,
    "",
    formatTable(["Check", "Status", "Severity", "Summary"], rows),
  ].join("\n");
}

function getOrganizationName(config: DuoResolvedConfig): string {
  return config.apiHost;
}

function getGlobalPolicyRecord(data: { globalPolicy: CollectedDataset<JsonRecord | null>; policies?: CollectedDataset<JsonRecord[]> }): JsonRecord {
  if (data.globalPolicy.data) return data.globalPolicy.data;
  if (data.policies) {
    const global = data.policies.data.find((policy) => asBoolean(asRecord(policy).is_global_policy));
    if (global) return global;
  }
  return {};
}

function getPolicySections(policy: JsonRecord): JsonRecord {
  return asRecord(policy.sections);
}

function getAllowedAuthList(policy: JsonRecord): string[] {
  return listStrings(asRecord(getPolicySections(policy).authentication_methods).allowed_auth_list).map((value) => value.toLowerCase());
}

function getBooleanish(record: JsonRecord, key: string): boolean | undefined {
  const value = record[key];
  if (typeof value === "boolean") return value;
  if (typeof value === "number") return value === 1;
  if (typeof value === "string") {
    if (value === "true" || value === "1") return true;
    if (value === "false" || value === "0") return false;
  }
  return undefined;
}

function rememberedDeviceWindowDays(policy: JsonRecord): number | null {
  const remembered = asRecord(asRecord(getPolicySections(policy).remembered_devices).browser_apps);
  const enabled = getBooleanish(remembered, "enabled");
  if (!enabled) return 0;
  const userBased = asRecord(remembered.user_based);
  const value = asNumber(userBased.max_time_value);
  const unit = asString(userBased.max_time_units)?.toLowerCase();
  if (value === undefined || !unit) return null;
  if (unit.startsWith("day")) return value;
  if (unit.startsWith("week")) return value * 7;
  if (unit.startsWith("hour")) return value / 24;
  return null;
}

function adminRoleNames(admin: JsonRecord): string[] {
  const roles = listStrings(admin.roles);
  const directCandidates = [
    asString(admin.role),
    asString(admin.role_name),
    asString(admin.admin_type),
    asString(admin.user_role),
  ].filter((item): item is string => Boolean(item));
  return [...roles, ...directCandidates].map((role) => role.toLowerCase());
}

function isOwnerAdmin(admin: JsonRecord): boolean {
  return adminRoleNames(admin).some((role) => role.includes("owner"));
}

function integrationIsProtected(integration: JsonRecord): boolean {
  const type = asString(integration.type)?.toLowerCase() ?? "";
  return !["adminapi", "accountsapi"].includes(type);
}

function activeIntegrations(integrations: JsonRecord[]): JsonRecord[] {
  return integrations.filter((integration) => {
    const userAccess = asString(integration.user_access);
    return integrationIsProtected(integration) && userAccess !== "NO_USERS";
  });
}

function policyKey(integration: JsonRecord): string | undefined {
  return asString(integration.policy_key);
}

function hasUniversalPrompt(integration: JsonRecord): boolean {
  return getBooleanish(integration, "prompt_v4_enabled") === true || getBooleanish(integration, "frameless_auth_prompt_enabled") === true;
}

function listErrors(datasets: Array<CollectedDataset<unknown>>): string[] {
  return datasets.map((dataset) => dataset.error).filter((item): item is string => Boolean(item));
}

export function assessDuoAuthentication(
  data: DuoAuthenticationData,
  config: DuoResolvedConfig,
): DuoAssessmentResult {
  const findings: DuoFinding[] = [];
  const globalPolicy = getGlobalPolicyRecord(data);
  const allowedFactors = getAllowedAuthList(globalPolicy);
  const authMethods = asRecord(getPolicySections(globalPolicy).authentication_methods);
  const requireVerifiedPush = getBooleanish(authMethods, "require_verified_push");
  const verifiedDigits = asNumber(authMethods.verified_push_digits);
  const hasWebAuthn = allowedFactors.some((factor) => factor.includes("webauthn"));
  const allowsPush = allowedFactors.some((factor) => factor.includes("duo-push") || factor.includes("verified_duo_push"));
  const strongFactorEvidence = [
    hasWebAuthn ? "WebAuthn is allowed in authentication_methods.allowed_auth_list." : undefined,
    allowsPush && requireVerifiedPush ? `Verified Duo Push required (${verifiedDigits ?? 0} digits).` : undefined,
    data.allowedAdminAuthMethods.data && getBooleanish(data.allowedAdminAuthMethods.data, "webauthn_enabled")
      ? "Admin auth methods allow WebAuthn."
      : undefined,
  ].filter((item): item is string => Boolean(item));

  if (hasWebAuthn || (allowsPush && requireVerifiedPush)) {
    findings.push(
      buildFinding(
        "DUO-AUTH-001",
        "Pass",
        "The global authentication policy includes phishing-resistant factors.",
        strongFactorEvidence,
        "Keep WebAuthn and Verified Duo Push coverage in policy and enrollment guidance.",
      ),
    );
  } else if (allowsPush || strongFactorEvidence.length > 0) {
    findings.push(
      buildFinding(
        "DUO-AUTH-001",
        "Partial",
        "Duo Push or administrator hardening exists, but phishing-resistant coverage is incomplete or not enforced globally.",
        strongFactorEvidence.length > 0 ? strongFactorEvidence : ["No explicit WebAuthn or Verified Duo Push requirement found in the global policy."],
        "Prefer WebAuthn and Verified Duo Push as the default factors for regulated tenants.",
      ),
    );
  } else {
    findings.push(
      buildFinding(
        "DUO-AUTH-001",
        "Fail",
        "The global policy does not show phishing-resistant factors.",
        ["No WebAuthn or Verified Duo Push requirement was detected in the collected policy data."],
        "Enable WebAuthn or Verified Duo Push in Duo authentication methods before relying on the tenant for higher-assurance workflows.",
      ),
    );
  }

  const deprecatedAllowed = allowedFactors.filter((factor) =>
    factor.includes("sms") || factor.includes("phone") || factor.includes("voice"),
  );
  if (allowedFactors.length === 0) {
    findings.push(
      buildFinding(
        "DUO-AUTH-002",
        "Manual",
        "Authentication method restrictions could not be confirmed from the global policy payload.",
        ["The global policy did not expose authentication_methods.allowed_auth_list."],
        "Review the Authentication Methods policy section manually and verify SMS and phone callback posture.",
      ),
    );
  } else if (deprecatedAllowed.length === 0) {
    findings.push(
      buildFinding(
        "DUO-AUTH-002",
        "Pass",
        "Deprecated telephony factors are not present in the global allow-list.",
        [`Allowed factors: ${allowedFactors.join(", ")}`],
        "Keep SMS and phone callback disabled unless you have a documented break-glass exception.",
      ),
    );
  } else {
    findings.push(
      buildFinding(
        "DUO-AUTH-002",
        deprecatedAllowed.length === allowedFactors.length ? "Fail" : "Partial",
        "Legacy telephony factors are still allowed in the global policy.",
        [`Allowed factors: ${allowedFactors.join(", ")}`],
        "Remove SMS and phone callback from standard authentication paths and reserve them only for tightly governed exceptions.",
      ),
    );
  }

  const newUserBehavior = asString(asRecord(getPolicySections(globalPolicy).new_user).new_user_behavior)?.toLowerCase();
  if (!newUserBehavior) {
    findings.push(
      buildFinding(
        "DUO-AUTH-003",
        "Manual",
        "New user policy could not be resolved from the collected policy data.",
        ["The global policy did not include a new_user.new_user_behavior value."],
        "Confirm that new users must enroll before accessing protected applications.",
      ),
    );
  } else if (newUserBehavior === "enroll") {
    findings.push(
      buildFinding(
        "DUO-AUTH-003",
        "Pass",
        "New users are required to enroll before access.",
        [`new_user_behavior=${newUserBehavior}`],
        "Keep enrollment-required behavior in place for new users.",
      ),
    );
  } else {
    findings.push(
      buildFinding(
        "DUO-AUTH-003",
        newUserBehavior === "no-mfa" ? "Fail" : "Partial",
        `New user policy is set to ${newUserBehavior}.`,
        [`new_user_behavior=${newUserBehavior}`],
        "Set the Duo New User policy to enroll users instead of allowing access without MFA.",
      ),
    );
  }

  const rememberedDays = rememberedDeviceWindowDays(globalPolicy);
  if (rememberedDays === null) {
    findings.push(
      buildFinding(
        "DUO-AUTH-004",
        "Manual",
        "Remembered device duration could not be interpreted.",
        ["The Remembered Devices policy exists, but the effective duration could not be normalized."],
        "Review remembered device settings and cap the window to a justifiable interval for the scoped risk.",
      ),
    );
  } else if (rememberedDays === 0) {
    findings.push(
      buildFinding(
        "DUO-AUTH-004",
        "Pass",
        "Remembered devices are disabled.",
        ["remembered_devices.browser_apps.enabled=false"],
        "Keep remembered devices disabled for higher-assurance applications unless there is a documented exception.",
      ),
    );
  } else if (rememberedDays <= 14) {
    findings.push(
      buildFinding(
        "DUO-AUTH-004",
        "Pass",
        `Remembered devices are enabled for ${rememberedDays} day(s).`,
        [`remembered_device_window_days=${rememberedDays}`],
        "Revisit the remembered-device window if risk tolerance changes.",
      ),
    );
  } else if (rememberedDays <= 30) {
    findings.push(
      buildFinding(
        "DUO-AUTH-004",
        "Partial",
        `Remembered devices persist for ${rememberedDays} day(s).`,
        [`remembered_device_window_days=${rememberedDays}`],
        "Consider shortening remembered-device duration for high-sensitivity applications or administrator flows.",
      ),
    );
  } else {
    findings.push(
      buildFinding(
        "DUO-AUTH-004",
        "Fail",
        `Remembered devices persist for ${rememberedDays} day(s).`,
        [`remembered_device_window_days=${rememberedDays}`],
        "Shorten or disable remembered devices so the cached MFA window stays aligned with regulated access expectations.",
      ),
    );
  }

  const trustedEndpoints = asRecord(getPolicySections(globalPolicy).trusted_endpoints);
  const trustedChecking = asString(trustedEndpoints.trusted_endpoint_checking);
  const trustedCheckingMobile = asString(trustedEndpoints.trusted_endpoint_checking_mobile);
  const duoDesktop = asRecord(getPolicySections(globalPolicy).duo_desktop);
  const screenLock = asRecord(getPolicySections(globalPolicy).screen_lock);
  const diskEncryption = asRecord(getPolicySections(globalPolicy).full_disk_encryption);
  const healthEvidence = [
    trustedChecking ? `trusted_endpoint_checking=${trustedChecking}` : undefined,
    trustedCheckingMobile ? `trusted_endpoint_checking_mobile=${trustedCheckingMobile}` : undefined,
    getBooleanish(duoDesktop, "requires_duo_desktop") ? "Duo Desktop required." : undefined,
    getBooleanish(screenLock, "require_screen_lock") ? "Screen lock required." : undefined,
    getBooleanish(diskEncryption, "require_disk_encryption") ? "Full disk encryption required." : undefined,
  ].filter((item): item is string => Boolean(item));
  if (trustedChecking === "require-trusted") {
    findings.push(
      buildFinding(
        "DUO-AUTH-005",
        "Pass",
        "Trusted endpoints are required by policy.",
        healthEvidence,
        "Keep trusted endpoint and device health checks aligned with platform coverage and operational reality.",
      ),
    );
  } else if (trustedChecking === "allow-all") {
    findings.push(
      buildFinding(
        "DUO-AUTH-005",
        "Partial",
        "Trusted endpoints are evaluated but not required.",
        healthEvidence.length > 0 ? healthEvidence : ["trusted_endpoint_checking=allow-all"],
        "Move the policy to require-trusted where managed device coverage supports it.",
      ),
    );
  } else {
    findings.push(
      buildFinding(
        "DUO-AUTH-005",
        "Fail",
        "Trusted endpoint requirements are not configured.",
        healthEvidence.length > 0 ? healthEvidence : ["trusted_endpoint_checking is not configured."],
        "Configure trusted endpoints and the supporting device-health controls before treating device trust as enforced.",
      ),
    );
  }

  const bypassCount = data.bypassCodes.data.length;
  const helpdeskBypass = asString(asRecord(data.settings.data).helpdesk_bypass)?.toLowerCase();
  const helpdeskBypassExpiration = asNumber(asRecord(data.settings.data).helpdesk_bypass_expiration);
  const unlimitedLikeCodes = data.bypassCodes.data.filter((code) => {
    const remainingUses = asNumber(code.remaining_uses);
    const validSecs = asNumber(code.valid_secs);
    return remainingUses === 0 || validSecs === 0;
  }).length;

  if (bypassCount === 0) {
    findings.push(
      buildFinding(
        "DUO-AUTH-006",
        "Pass",
        "No active bypass codes were returned.",
        ["Global bypass code inventory is empty."],
        "Keep break-glass issuance exceptional and time-bounded.",
      ),
    );
  } else if (helpdeskBypass === "allow" || unlimitedLikeCodes > 0 || (helpdeskBypass === "limit" && (helpdeskBypassExpiration ?? 0) <= 0)) {
    findings.push(
      buildFinding(
        "DUO-AUTH-006",
        "Fail",
        "Bypass code issuance is active without strong expiration controls.",
        [
          `active_bypass_codes=${bypassCount}`,
          `helpdesk_bypass=${helpdeskBypass ?? "unknown"}`,
          `helpdesk_bypass_expiration=${helpdeskBypassExpiration ?? "unset"}`,
          unlimitedLikeCodes > 0 ? `codes_with_zero_limits=${unlimitedLikeCodes}` : undefined,
        ].filter((item): item is string => Boolean(item)),
        "Constrain bypass-code creation to expiring, break-glass workflows and remove unrestricted help-desk issuance.",
      ),
    );
  } else {
    findings.push(
      buildFinding(
        "DUO-AUTH-006",
        "Partial",
        "Bypass codes are in use, but the account shows at least some expiration controls.",
        [
          `active_bypass_codes=${bypassCount}`,
          `helpdesk_bypass=${helpdeskBypass ?? "unknown"}`,
          `helpdesk_bypass_expiration=${helpdeskBypassExpiration ?? "unset"}`,
        ],
        "Review active bypass code usage and keep creation tightly governed.",
      ),
    );
  }

  const snapshotSummary = {
    users: data.users.data.length,
    active_bypass_codes: bypassCount,
    webauthn_credentials: data.webauthnCredentials.data.length,
    auth_logs_collected: data.authenticationLogs.data.length,
  };

  return {
    category: "authentication",
    findings,
    summary: summarizeFindings(findings),
    snapshotSummary,
    text: buildAssessmentText("Duo authentication assessment", getOrganizationName(config), findings, snapshotSummary),
  };
}

export function assessDuoAdminAccess(
  data: DuoAdminAccessData,
  config: DuoResolvedConfig,
): DuoAssessmentResult {
  const findings: DuoFinding[] = [];
  const admins = data.admins.data;
  const ownerCount = admins.filter(isOwnerAdmin).length;
  const staleAdmins = admins.filter((admin) => {
    const age = daysSince(admin.last_login ?? admin.last_login_time ?? admin.last_seen);
    return age !== null && age > 90;
  });

  if (admins.length === 0) {
    findings.push(
      buildFinding(
        "DUO-ADMIN-001",
        "Manual",
        "Administrator inventory could not be established.",
        [data.admins.error ?? "No administrators were returned by the Admin API."],
        "Confirm that the audit principal has Grant administrators - Read and Grant resource - Read permissions.",
      ),
    );
  } else if (ownerCount <= 2) {
    findings.push(
      buildFinding(
        "DUO-ADMIN-001",
        "Pass",
        "Owner-level access is concentrated in a small number of admins.",
        [`admins=${admins.length}`, `owners=${ownerCount}`],
        "Keep Owner-role assignments limited and review them periodically.",
      ),
    );
  } else if (ownerCount <= Math.max(3, Math.ceil(admins.length / 2))) {
    findings.push(
      buildFinding(
        "DUO-ADMIN-001",
        "Partial",
        "Owner-level access is broader than ideal.",
        [`admins=${admins.length}`, `owners=${ownerCount}`],
        "Reduce Owner assignments and shift routine work to narrower administrative roles.",
      ),
    );
  } else {
    findings.push(
      buildFinding(
        "DUO-ADMIN-001",
        "Fail",
        "Owner-level access is over-distributed across the administrator population.",
        [`admins=${admins.length}`, `owners=${ownerCount}`],
        "Constrain Owner access to the minimum practical set of operators and use narrower roles for everything else.",
      ),
    );
  }

  const allowed = asRecord(data.allowedAdminAuthMethods.data);
  const verifiedPushEnabled = getBooleanish(allowed, "verified_push_enabled");
  const webauthnEnabled = getBooleanish(allowed, "webauthn_enabled");
  const smsEnabled = getBooleanish(allowed, "sms_enabled");
  const voiceEnabled = getBooleanish(allowed, "voice_enabled");
  if (verifiedPushEnabled || webauthnEnabled) {
    findings.push(
      buildFinding(
        "DUO-ADMIN-002",
        smsEnabled || voiceEnabled ? "Partial" : "Pass",
        "Administrator login supports stronger MFA factors.",
        [
          `verified_push_enabled=${verifiedPushEnabled ?? false}`,
          `webauthn_enabled=${webauthnEnabled ?? false}`,
          `sms_enabled=${smsEnabled ?? false}`,
          `voice_enabled=${voiceEnabled ?? false}`,
        ],
        "Prefer Verified Duo Push and WebAuthn for administrators, and retire SMS and phone callback where possible.",
      ),
    );
  } else {
    findings.push(
      buildFinding(
        "DUO-ADMIN-002",
        "Fail",
        "Administrator login does not show phishing-resistant factors.",
        [
          `verified_push_enabled=${verifiedPushEnabled ?? false}`,
          `webauthn_enabled=${webauthnEnabled ?? false}`,
        ],
        "Enable Verified Duo Push or WebAuthn for Duo administrator access before treating the tenant as strongly governed.",
      ),
    );
  }

  const settings = asRecord(data.settings.data);
  const helpdeskBypass = asString(settings.helpdesk_bypass)?.toLowerCase();
  const helpdeskBypassExpiration = asNumber(settings.helpdesk_bypass_expiration);
  if (helpdeskBypass === "deny") {
    findings.push(
      buildFinding(
        "DUO-ADMIN-003",
        "Pass",
        "Help desk administrators cannot mint bypass codes.",
        ["helpdesk_bypass=deny"],
        "Keep help desk bypass issuance disabled unless there is a documented operational need.",
      ),
    );
  } else if (helpdeskBypass === "limit" && (helpdeskBypassExpiration ?? 0) > 0) {
    findings.push(
      buildFinding(
        "DUO-ADMIN-003",
        "Partial",
        "Help desk bypass creation is allowed, but Duo enforces a fixed expiration.",
        [
          `helpdesk_bypass=limit`,
          `helpdesk_bypass_expiration=${helpdeskBypassExpiration}`,
        ],
        "Review whether help desk bypass generation is still needed and keep the expiration as short as possible.",
      ),
    );
  } else {
    findings.push(
      buildFinding(
        "DUO-ADMIN-003",
        "Fail",
        "Help desk bypass creation is too permissive.",
        [
          `helpdesk_bypass=${helpdeskBypass ?? "unknown"}`,
          `helpdesk_bypass_expiration=${helpdeskBypassExpiration ?? "unset"}`,
        ],
        "Restrict or disable help desk bypass creation so support staff cannot create broad, long-lived break-glass access.",
      ),
    );
  }

  if (admins.length === 0) {
    findings.push(
      buildFinding(
        "DUO-ADMIN-004",
        "Manual",
        "Stale administrator review could not be completed.",
        ["No administrator inventory was available."],
        "Review privileged account activity directly in the Duo admin console.",
      ),
    );
  } else if (staleAdmins.length === 0) {
    findings.push(
      buildFinding(
        "DUO-ADMIN-004",
        "Pass",
        "No privileged administrators were obviously stale based on available login timestamps.",
        [`admins_reviewed=${admins.length}`],
        "Keep periodic access reviews in place for privileged administrators.",
      ),
    );
  } else {
    findings.push(
      buildFinding(
        "DUO-ADMIN-004",
        staleAdmins.length >= Math.max(1, Math.ceil(admins.length / 3)) ? "Fail" : "Partial",
        "Some privileged administrators appear stale.",
        staleAdmins.slice(0, 10).map((admin) => `${asString(admin.email) ?? asString(admin.name) ?? "unknown-admin"} last_login_age_days=${daysSince(admin.last_login ?? admin.last_login_time ?? admin.last_seen) ?? "unknown"}`),
        "Review stale privileged accounts and remove or re-justify access for administrators who no longer need it.",
      ),
    );
  }

  findings.push(
    buildFinding(
      "DUO-MON-004",
      data.activityLogs.error ? "Manual" : "Pass",
      data.activityLogs.error
        ? "Administrative activity logs could not be collected."
        : "Administrative activity logs are readable to the audit principal.",
      data.activityLogs.error
        ? [data.activityLogs.error]
        : [`activity_logs_collected=${data.activityLogs.data.length}`],
      "Keep admin activity logs available to the audit or monitoring workflow so privileged changes are reviewable.",
    ),
  );

  const snapshotSummary = {
    admins: admins.length,
    owners: ownerCount,
    stale_admins: staleAdmins.length,
    activity_logs_collected: data.activityLogs.data.length,
  };

  return {
    category: "admin_access",
    findings,
    summary: summarizeFindings(findings),
    snapshotSummary,
    text: buildAssessmentText("Duo admin-access assessment", getOrganizationName(config), findings, snapshotSummary),
  };
}

export function assessDuoIntegrations(
  data: DuoIntegrationData,
  config: DuoResolvedConfig,
): DuoAssessmentResult {
  const findings: DuoFinding[] = [];
  const integrations = activeIntegrations(data.integrations.data);
  const policyAttachedCount = integrations.filter((integration) => Boolean(policyKey(integration))).length;
  const universalPromptApplicable = integrations.filter((integration) =>
    getBooleanish(integration, "frameless_auth_prompt_enabled") !== undefined ||
    getBooleanish(integration, "prompt_v4_enabled") !== undefined,
  );
  const universalPromptCount = universalPromptApplicable.filter(hasUniversalPrompt).length;
  const adminApiIntegrations = data.integrations.data.filter((integration) =>
    asString(integration.type)?.toLowerCase() === "adminapi",
  );
  const overPrivilegedAdminApis = adminApiIntegrations.filter((integration) =>
    getBooleanish(integration, "adminapi_integrations")
      || getBooleanish(integration, "adminapi_write_resource")
      || getBooleanish(integration, "adminapi_settings")
      || getBooleanish(integration, "adminapi_allow_to_set_permissions"),
  );

  if (integrations.length === 0) {
    findings.push(
      buildFinding(
        "DUO-INTEGRATIONS-001",
        data.integrations.error ? "Manual" : "Partial",
        data.integrations.error
          ? "Direct integration inventory could not be collected."
          : "No active protected integrations were returned.",
        [data.integrations.error ?? "Protected integration count was zero."],
        "Confirm integration inventory and policy attachment inside the Duo Admin Panel before concluding the environment has no protected apps.",
      ),
    );
  } else if (policyAttachedCount === integrations.length) {
    findings.push(
      buildFinding(
        "DUO-INTEGRATIONS-001",
        "Pass",
        "All active protected integrations expose an explicit policy attachment.",
        [`protected_integrations=${integrations.length}`, `with_policy_key=${policyAttachedCount}`],
        "Keep custom policy attachment visible for high-value applications instead of relying only on the global policy.",
      ),
    );
  } else if (policyAttachedCount > 0) {
    findings.push(
      buildFinding(
        "DUO-INTEGRATIONS-001",
        "Partial",
        "Some active integrations expose explicit policy attachments, but others appear to rely only on broader defaults.",
        [`protected_integrations=${integrations.length}`, `with_policy_key=${policyAttachedCount}`],
        "Review integrations without a policy_key and confirm they still inherit the intended control posture.",
      ),
    );
  } else {
    findings.push(
      buildFinding(
        "DUO-INTEGRATIONS-001",
        "Fail",
        "Active protected integrations do not expose explicit policy attachments.",
        [`protected_integrations=${integrations.length}`, `with_policy_key=${policyAttachedCount}`],
        "Attach explicit Duo policies to protected integrations so exception handling and control inheritance are reviewable.",
      ),
    );
  }

  if (universalPromptApplicable.length === 0) {
    findings.push(
      buildFinding(
        "DUO-INTEGRATIONS-002",
        "Manual",
        "Universal Prompt adoption could not be determined from the collected integration payloads.",
        ["No integration records exposed frameless_auth_prompt_enabled or prompt_v4_enabled."],
        "Review application prompt posture directly in Duo for the most sensitive integrations.",
      ),
    );
  } else if (universalPromptCount === universalPromptApplicable.length) {
    findings.push(
      buildFinding(
        "DUO-INTEGRATIONS-002",
        "Pass",
        "All inspected integrations that expose prompt posture are on Universal Prompt.",
        [`universal_prompt_integrations=${universalPromptCount}`, `prompt_applicable=${universalPromptApplicable.length}`],
        "Keep Universal Prompt adoption at full coverage as new integrations are added.",
      ),
    );
  } else {
    findings.push(
      buildFinding(
        "DUO-INTEGRATIONS-002",
        universalPromptCount === 0 ? "Fail" : "Partial",
        "Universal Prompt adoption is incomplete.",
        [`universal_prompt_integrations=${universalPromptCount}`, `prompt_applicable=${universalPromptApplicable.length}`],
        "Migrate the remaining applications to Universal Prompt so authentication posture stays current and consistent.",
      ),
    );
  }

  const globalSspPolicyEnforced = getBooleanish(asRecord(data.settings.data), "global_ssp_policy_enforced");
  if (globalSspPolicyEnforced === true) {
    findings.push(
      buildFinding(
        "DUO-INTEGRATIONS-003",
        "Pass",
        "A global self-service portal policy is enforced.",
        ["global_ssp_policy_enforced=true"],
        "Keep the self-service portal bound to the intended policy so device-management features do not drift per application.",
      ),
    );
  } else {
    findings.push(
      buildFinding(
        "DUO-INTEGRATIONS-003",
        globalSspPolicyEnforced === false ? "Partial" : "Manual",
        globalSspPolicyEnforced === false
          ? "The self-service portal follows destination application policy instead of a single enforced portal policy."
          : "Self-service portal governance could not be confirmed.",
        [`global_ssp_policy_enforced=${globalSspPolicyEnforced ?? "unknown"}`],
        "Review self-service portal behavior and enforce a global policy if portal behavior should be governed consistently.",
      ),
    );
  }

  if (adminApiIntegrations.length === 0) {
    findings.push(
      buildFinding(
        "DUO-INTEGRATIONS-004",
        "Pass",
        "No Admin API integrations were returned in the direct integration inventory.",
        ["adminapi_integrations=0"],
        "If Admin API applications exist outside the returned inventory, review them separately for least-privilege scope.",
      ),
    );
  } else if (overPrivilegedAdminApis.length === 0) {
    findings.push(
      buildFinding(
        "DUO-INTEGRATIONS-004",
        "Pass",
        "Admin API integrations appear read-oriented in the returned inventory.",
        [`adminapi_integrations=${adminApiIntegrations.length}`],
        "Keep Admin API applications constrained to read permissions unless a write path is formally justified.",
      ),
    );
  } else {
    findings.push(
      buildFinding(
        "DUO-INTEGRATIONS-004",
        overPrivilegedAdminApis.length === adminApiIntegrations.length ? "Fail" : "Partial",
        "Some Admin API integrations have broader write or permission-management scope.",
        overPrivilegedAdminApis.slice(0, 10).map((integration) => `${asString(integration.name) ?? asString(integration.integration_key) ?? "unknown-adminapi"} has elevated Admin API permissions.`),
        "Review Admin API applications and reduce them to read-only scope unless mutation rights are explicitly required and governed.",
      ),
    );
  }

  const snapshotSummary = {
    protected_integrations: integrations.length,
    policies: data.policies.data.length,
    adminapi_integrations: adminApiIntegrations.length,
    overprivileged_adminapi_integrations: overPrivilegedAdminApis.length,
  };

  return {
    category: "integrations",
    findings,
    summary: summarizeFindings(findings),
    snapshotSummary,
    text: buildAssessmentText("Duo integration assessment", getOrganizationName(config), findings, snapshotSummary),
  };
}

export function assessDuoMonitoring(
  data: DuoMonitoringData,
  config: DuoResolvedConfig,
): DuoAssessmentResult {
  const findings: DuoFinding[] = [];
  const authLogs = data.authenticationLogs.data;
  const telephonyLogs = data.telephonyLogs.data;
  const trustMonitorEvents = data.trustMonitorEvents.data;
  const bypassEvents = authLogs.filter((event) => {
    const factor = asString(event.factor)?.toLowerCase() ?? "";
    return factor.includes("bypass");
  }).length;
  const telephonyFactors = authLogs.filter((event) => {
    const factor = asString(event.factor)?.toLowerCase() ?? "";
    return factor.includes("sms") || factor.includes("phone");
  }).length;
  const fraudEvents = authLogs.filter((event) => {
    const result = `${asString(event.result) ?? ""} ${asString(event.reason) ?? ""}`.toLowerCase();
    return result.includes("fraud");
  }).length;

  if (data.authenticationLogs.error) {
    findings.push(
      buildFinding(
        "DUO-MON-001",
        "Manual",
        "Authentication logs could not be collected.",
        [data.authenticationLogs.error],
        "Grant read log permissions and confirm the audit principal can retrieve Duo authentication events.",
      ),
    );
  } else if (authLogs.length === 0) {
    findings.push(
      buildFinding(
        "DUO-MON-001",
        "Partial",
        "Authentication log collection succeeded but returned no events in the requested lookback window.",
        [`lookback_days=${config.lookbackDays}`],
        "Confirm the lookback window is appropriate and that authentication telemetry is retained for audit review.",
      ),
    );
  } else if (bypassEvents > 0 || telephonyFactors > 0 || fraudEvents > 0) {
    findings.push(
      buildFinding(
        "DUO-MON-001",
        "Partial",
        "Authentication telemetry is available and shows events worth review.",
        [
          `auth_logs_collected=${authLogs.length}`,
          `bypass_factor_events=${bypassEvents}`,
          `telephony_factor_events=${telephonyFactors}`,
          `fraud_related_events=${fraudEvents}`,
        ],
        "Review bypass, telephony, and fraud-related auth events to ensure the tenant is not leaning on weaker factors or recurring exception paths.",
      ),
    );
  } else {
    findings.push(
      buildFinding(
        "DUO-MON-001",
        "Pass",
        "Authentication telemetry is available and does not show obvious weak-factor reliance in the sampled window.",
        [`auth_logs_collected=${authLogs.length}`],
        "Keep the authentication log workflow in place and expand the lookback window when performing deeper investigations.",
      ),
    );
  }

  if (data.trustMonitorEvents.error) {
    findings.push(
      buildFinding(
        "DUO-MON-002",
        "Manual",
        "Trust Monitor events could not be collected.",
        [data.trustMonitorEvents.error],
        "Confirm the audit principal has read-log permissions and that Trust Monitor telemetry is available for the tenant edition.",
      ),
    );
  } else {
    const priorityEvents = trustMonitorEvents.filter((event) => getBooleanish(event, "priority_event")).length;
    const newStateEvents = trustMonitorEvents.filter((event) => asString(event.state)?.toLowerCase() === "new").length;
    findings.push(
      buildFinding(
        "DUO-MON-002",
        trustMonitorEvents.length > 0 ? "Pass" : "Partial",
        trustMonitorEvents.length > 0
          ? "Trust Monitor surfaced recent events for review."
          : "No Trust Monitor events were returned in the requested lookback window.",
        [
          `trust_monitor_events=${trustMonitorEvents.length}`,
          `priority_events=${priorityEvents}`,
          `new_state_events=${newStateEvents}`,
        ],
        "Keep Trust Monitor triage wired into the response workflow and verify zero-event windows are expected for the tenant.",
      ),
    );
  }

  const creditsRemaining = asNumber(asRecord(data.infoSummary.data).telephony_credits_remaining);
  const smsOrPhoneLogs = telephonyLogs.filter((event) => {
    const type = asString(event.type)?.toLowerCase() ?? "";
    return type === "sms" || type === "phone";
  }).length;
  if (data.telephonyLogs.error || data.infoSummary.error) {
    findings.push(
      buildFinding(
        "DUO-MON-003",
        "Manual",
        "Telephony monitoring could not be fully assessed.",
        [data.telephonyLogs.error, data.infoSummary.error].filter((item): item is string => Boolean(item)),
        "Confirm read-log and read-information permissions, then review telephony usage and remaining credits.",
      ),
    );
  } else if ((creditsRemaining ?? 0) < 25 && smsOrPhoneLogs > 0) {
    findings.push(
      buildFinding(
        "DUO-MON-003",
        "Fail",
        "Telephony-backed MFA usage is active while available credits are low.",
        [`telephony_logs=${telephonyLogs.length}`, `telephony_factor_events=${smsOrPhoneLogs}`, `telephony_credits_remaining=${creditsRemaining ?? "unknown"}`],
        "Reduce telephony reliance and replenish credits before low balance creates an authentication bottleneck.",
      ),
    );
  } else if (smsOrPhoneLogs > 0 || (creditsRemaining ?? Number.POSITIVE_INFINITY) < 100) {
    findings.push(
      buildFinding(
        "DUO-MON-003",
        "Partial",
        "Telephony capacity needs periodic review.",
        [`telephony_logs=${telephonyLogs.length}`, `telephony_factor_events=${smsOrPhoneLogs}`, `telephony_credits_remaining=${creditsRemaining ?? "unknown"}`],
        "Keep telephony credits monitored and continue moving users away from SMS and phone callback factors.",
      ),
    );
  } else {
    findings.push(
      buildFinding(
        "DUO-MON-003",
        "Pass",
        "Telephony capacity looks healthy in the sampled window.",
        [`telephony_logs=${telephonyLogs.length}`, `telephony_credits_remaining=${creditsRemaining ?? "unknown"}`],
        "Continue monitoring telephony usage so low credits or weak-factor fallback do not become a surprise.",
      ),
    );
  }

  const settings = asRecord(data.settings.data);
  const notificationSignals = [
    getBooleanish(settings, "fraud_email_enabled"),
    getBooleanish(settings, "push_activity_notification_enabled"),
    getBooleanish(settings, "email_activity_notification_enabled"),
  ].filter((value): value is boolean => value !== undefined);
  if (notificationSignals.some(Boolean)) {
    findings.push(
      buildFinding(
        "DUO-MON-004",
        "Pass",
        "Duo account notifications are enabled for at least one operator-facing path.",
        [
          `fraud_email_enabled=${getBooleanish(settings, "fraud_email_enabled") ?? false}`,
          `push_activity_notification_enabled=${getBooleanish(settings, "push_activity_notification_enabled") ?? false}`,
          `email_activity_notification_enabled=${getBooleanish(settings, "email_activity_notification_enabled") ?? false}`,
        ],
        "Confirm the notification destinations are monitored by the right operators and not just technically enabled.",
      ),
    );
  } else {
    findings.push(
      buildFinding(
        "DUO-MON-004",
        "Partial",
        "No operator-facing Duo account notification toggle was clearly enabled.",
        [
          `fraud_email_enabled=${getBooleanish(settings, "fraud_email_enabled") ?? "unknown"}`,
          `push_activity_notification_enabled=${getBooleanish(settings, "push_activity_notification_enabled") ?? "unknown"}`,
          `email_activity_notification_enabled=${getBooleanish(settings, "email_activity_notification_enabled") ?? "unknown"}`,
        ],
        "Enable and route Duo notifications so fraud and account activity signals reach the monitoring workflow.",
      ),
    );
  }

  const snapshotSummary = {
    auth_logs_collected: authLogs.length,
    trust_monitor_events: trustMonitorEvents.length,
    telephony_logs: telephonyLogs.length,
    telephony_credits_remaining: creditsRemaining ?? "unknown",
  };

  return {
    category: "monitoring",
    findings,
    summary: summarizeFindings(findings),
    snapshotSummary,
    text: buildAssessmentText("Duo monitoring assessment", getOrganizationName(config), findings, snapshotSummary),
  };
}

function buildConfigNotes(config: DuoResolvedConfig): string[] {
  return [
    `api_host=${config.apiHost}`,
    `lookback_days=${config.lookbackDays}`,
    `source_chain=${config.sourceChain.join(" -> ") || "direct"}`,
  ];
}

export async function runDuoAccessCheck(
  client: Pick<DuoAuditorClient, "getSettings" | "listUsers" | "listPolicies" | "listAdmins" | "listAuthenticationLogs" | "listIntegrations">,
  config: DuoResolvedConfig,
): Promise<DuoAccessCheckResult> {
  const probes: DuoAccessProbe[] = [];

  const actions: Record<string, () => Promise<unknown>> = {
    settings: () => client.getSettings(),
    users: () => client.listUsers(),
    policies: () => client.listPolicies(),
    admins: () => client.listAdmins(),
    logs: () => client.listAuthenticationLogs(1, 20),
    integrations: () => client.listIntegrations(),
  };

  for (const probe of DUO_ACCESS_PROBES) {
    try {
      await actions[probe.key]();
      probes.push({
        key: probe.key,
        path: probe.path,
        status: "ok",
        detail: "Readable",
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      probes.push({
        key: probe.key,
        path: probe.path,
        status: message.includes("(403 ") ? "forbidden" : message.includes("(401 ") ? "unauthorized" : "error",
        detail: message,
      });
    }
  }

  const readableCount = probes.filter((probe) => probe.status === "ok").length;
  const status = readableCount === probes.length ? "healthy" : "limited";

  return {
    organization: getOrganizationName(config),
    status,
    sourceChain: config.sourceChain,
    probes,
    notes: [
      ...buildConfigNotes(config),
      "Duo Admin API collection is read-only in this grclanker slice.",
      "Direct integration inventory uses the current Admin API v3 signing path when available.",
    ],
    recommendedNextStep:
      status === "healthy"
        ? "The audit principal can read the core Duo surfaces. Run the focused Duo assessment that matches your question, or export the full audit bundle."
        : "Use the probe details to add the missing Duo Admin API read permissions before relying on the deeper assessments.",
  };
}

function frameworkSummary(findings: DuoFinding[], key: FrameworkKey): DuoFinding[] {
  return findings.filter((finding) => finding.frameworks[key].length > 0);
}

function frameworkMatrixRow(finding: DuoFinding): string {
  const cells = [
    finding.id,
    finding.title,
    finding.status,
    finding.severity,
    Object.entries(finding.frameworks)
      .flatMap(([key, controls]) => (Array.isArray(controls) && controls.length > 0 ? [`${key}: ${controls.join(", ")}`] : []))
      .join(" | "),
  ];
  return `| ${cells.join(" | ")} |`;
}

function buildFrameworkReport(title: string, findings: DuoFinding[], key: FrameworkKey): string {
  const scoped = frameworkSummary(findings, key);
  const rows = scoped.map((finding) =>
    `- ${finding.id} (${finding.status}/${finding.severity}) — ${finding.title}: ${finding.summary}`,
  );
  return [
    `# ${title}`,
    "",
    scoped.length > 0 ? rows.join("\n") : "No findings mapped to this framework in the exported bundle.",
    "",
  ].join("\n");
}

function buildUnifiedMatrix(findings: DuoFinding[]): string {
  return [
    "# Unified Duo Compliance Matrix",
    "",
    "| Check | Title | Status | Severity | Mappings |",
    "| --- | --- | --- | --- | --- |",
    ...findings.map(frameworkMatrixRow),
    "",
  ].join("\n");
}

export function resolveSecureOutputPath(baseDir: string, targetDir: string): string {
  const root = resolve(baseDir);
  mkdirSync(root, { recursive: true });
  const rootReal = realpathSync(root);
  const destination = resolve(root, targetDir);

  let current = destination;
  while (current !== root && current !== dirname(current)) {
    if (existsSync(current) && lstatSync(current).isSymbolicLink()) {
      throw new Error(`Refusing to write through symlinked output path: ${current}`);
    }
    current = dirname(current);
  }

  const parent = dirname(destination);
  mkdirSync(parent, { recursive: true });
  const parentReal = realpathSync(parent);
  if (relative(rootReal, parentReal).startsWith("..")) {
    throw new Error(`Refusing to write outside output root: ${destination}`);
  }
  return destination;
}

function sanitizeSegment(value: string): string {
  return value
    .replace(/[^a-zA-Z0-9._-]+/g, "_")
    .replace(/^_+|_+$/g, "")
    .slice(0, 80) || "item";
}

function ensureUniqueRelativePath(root: string, preferredName: string): string {
  const extIndex = preferredName.lastIndexOf(".");
  const hasExt = extIndex > 0;
  const base = hasExt ? preferredName.slice(0, extIndex) : preferredName;
  const ext = hasExt ? preferredName.slice(extIndex) : "";
  for (let counter = 0; counter < 500; counter += 1) {
    const suffix = counter === 0 ? "" : `_${counter}`;
    const candidate = resolveSecureOutputPath(root, `${base}${suffix}${ext}`);
    if (!existsSync(candidate)) {
      return relative(root, candidate);
    }
  }
  throw new Error(`Unable to allocate unique output path for ${preferredName}`);
}

async function writeJson(rootDir: string, relativePathname: string, value: unknown): Promise<void> {
  const destination = resolveSecureOutputPath(rootDir, relativePathname);
  await writeFile(destination, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

async function writeText(rootDir: string, relativePathname: string, value: string): Promise<void> {
  const destination = resolveSecureOutputPath(rootDir, relativePathname);
  await writeFile(destination, `${value.trimEnd()}\n`, "utf8");
}

async function zipDirectory(sourceDir: string, zipPath: string): Promise<void> {
  const output = createWriteStream(zipPath);
  const archive = archiver("zip", { zlib: { level: 9 } });

  await new Promise<void>((resolveZip, rejectZip) => {
    output.on("close", resolveZip);
    archive.on("error", rejectZip);
    archive.pipe(output);
    archive.directory(sourceDir, false);
    archive.finalize().catch(rejectZip);
  });
}

async function countFiles(rootDir: string): Promise<number> {
  const entries = await readdir(rootDir, { withFileTypes: true });
  let count = 0;
  for (const entry of entries) {
    const full = join(rootDir, entry.name);
    if (entry.isDirectory()) {
      count += await countFiles(full);
    } else if (entry.isFile()) {
      count += 1;
    }
  }
  return count;
}

function buildFrameworkReports(findings: DuoFinding[]): Record<string, string> {
  return {
    fedramp: buildFrameworkReport("FedRAMP Mappings", findings, "fedramp"),
    cmmc: buildFrameworkReport("CMMC Mappings", findings, "cmmc"),
    soc2: buildFrameworkReport("SOC 2 Mappings", findings, "soc2"),
    cis: buildFrameworkReport("CIS Mappings", findings, "cis"),
    pci_dss: buildFrameworkReport("PCI-DSS Mappings", findings, "pci_dss"),
    disa_stig: buildFrameworkReport("DISA STIG Mappings", findings, "disa_stig"),
    irap: buildFrameworkReport("IRAP Mappings", findings, "irap"),
    ismap: buildFrameworkReport("ISMAP Mappings", findings, "ismap"),
  };
}

async function buildBundleReadme(rootDir: string): Promise<void> {
  await writeText(
    rootDir,
    "README.md",
    [
      "# Duo Audit Bundle Quick Reference",
      "",
      "- `core_data/` contains the raw Duo API payloads collected for this assessment.",
      "- `assessments/` contains normalized findings in JSON and terminal-friendly markdown.",
      "- `frameworks/` contains per-framework filtered reports.",
      "- `summary.md` and `unified-matrix.md` provide the high-level operator view.",
      "",
      "This bundle is read-only evidence and analysis output. It does not contain the Duo secret key or write-capable credentials.",
    ].join("\n"),
  );
}

export async function exportDuoAuditBundle(
  client: Pick<
    DuoAuditorClient,
    | "getSettings"
    | "listPolicies"
    | "getGlobalPolicy"
    | "listUsers"
    | "listBypassCodes"
    | "listWebauthnCredentials"
    | "getAdminAllowedAuthMethods"
    | "listAuthenticationLogs"
    | "listAdmins"
    | "listActivityLogs"
    | "listIntegrations"
    | "getInfoSummary"
    | "listTelephonyLogs"
    | "listTrustMonitorEvents"
  >,
  config: DuoResolvedConfig,
  outputRoot: string,
): Promise<DuoAuditBundleResult> {
  const authentication = await collectDuoAuthenticationData(client, config.lookbackDays);
  const adminAccess = await collectDuoAdminAccessData(client, config.lookbackDays);
  const integrations = await collectDuoIntegrationData(client);
  const monitoring = await collectDuoMonitoringData(client, config.lookbackDays);

  const assessments = [
    assessDuoAuthentication(authentication, config),
    assessDuoAdminAccess(adminAccess, config),
    assessDuoIntegrations(integrations, config),
    assessDuoMonitoring(monitoring, config),
  ];

  const findings = assessments.flatMap((assessment) => assessment.findings);
  const frameworkReports = buildFrameworkReports(findings);
  const timestamp = new Date().toISOString().replace(/[:]/g, "-");
  const folderName = sanitizeSegment(`${config.apiHost}_${timestamp}`);
  const outputDir = resolveSecureOutputPath(outputRoot, folderName);
  mkdirSync(outputDir, { recursive: true });
  await chmod(outputDir, 0o755);

  await buildBundleReadme(outputDir);
  await writeJson(outputDir, "config.json", {
    api_host: config.apiHost,
    lookback_days: config.lookbackDays,
    source_chain: config.sourceChain,
  });

  await writeJson(outputDir, "core_data/authentication.json", authentication);
  await writeJson(outputDir, "core_data/admin_access.json", adminAccess);
  await writeJson(outputDir, "core_data/integrations.json", integrations);
  await writeJson(outputDir, "core_data/monitoring.json", monitoring);
  await writeJson(outputDir, "assessments/authentication.json", assessments[0]);
  await writeJson(outputDir, "assessments/admin_access.json", assessments[1]);
  await writeJson(outputDir, "assessments/integrations.json", assessments[2]);
  await writeJson(outputDir, "assessments/monitoring.json", assessments[3]);
  await writeJson(outputDir, "findings.json", findings);
  await writeText(outputDir, "summary.md", assessments.map((assessment) => assessment.text).join("\n\n"));
  await writeText(outputDir, "unified-matrix.md", buildUnifiedMatrix(findings));

  for (const [name, report] of Object.entries(frameworkReports)) {
    await writeText(outputDir, `frameworks/${name}.md`, report);
  }

  const errorCount = listErrors([
    authentication.settings,
    authentication.policies,
    authentication.globalPolicy,
    authentication.users,
    authentication.bypassCodes,
    authentication.webauthnCredentials,
    authentication.allowedAdminAuthMethods,
    authentication.authenticationLogs,
    adminAccess.settings,
    adminAccess.admins,
    adminAccess.allowedAdminAuthMethods,
    adminAccess.activityLogs,
    integrations.settings,
    integrations.policies,
    integrations.globalPolicy,
    integrations.integrations,
    monitoring.settings,
    monitoring.infoSummary,
    monitoring.authenticationLogs,
    monitoring.activityLogs,
    monitoring.telephonyLogs,
    monitoring.trustMonitorEvents,
  ]).length;

  const zipRelative = ensureUniqueRelativePath(outputRoot, `${basename(outputDir)}.zip`);
  const zipPath = resolveSecureOutputPath(outputRoot, zipRelative);
  await zipDirectory(outputDir, zipPath);

  return {
    outputDir,
    zipPath,
    fileCount: await countFiles(outputDir),
    findingCount: findings.length,
    errorCount,
  };
}

function probeTable(probes: DuoAccessProbe[]): string {
  return formatTable(
    ["Probe", "Status", "Detail"],
    probes.map((probe) => [probe.key, probe.status, probe.detail]),
  );
}

function renderAssessmentToolResult(result: DuoAssessmentResult) {
  return textResult(result.text, {
    category: result.category,
    findings: result.findings,
    summary: result.summary,
    snapshot_summary: result.snapshotSummary,
  });
}

function renderAccessCheck(result: DuoAccessCheckResult) {
  return textResult(
    [
      `Duo access check for ${result.organization}`,
      `Status: ${result.status}`,
      "",
      probeTable(result.probes),
      "",
      "Notes:",
      ...result.notes.map((note) => `- ${note}`),
      "",
      `Next step: ${result.recommendedNextStep}`,
    ].join("\n"),
    {
      organization: result.organization,
      status: result.status,
      probes: result.probes,
      source_chain: result.sourceChain,
    },
  );
}

function buildExportText(config: DuoResolvedConfig, result: DuoAuditBundleResult): string {
  return [
    `Exported Duo audit bundle for ${config.apiHost}.`,
    `Output directory: ${result.outputDir}`,
    `Zip archive: ${result.zipPath}`,
    `Files written: ${result.fileCount}`,
    `Findings recorded: ${result.findingCount}`,
    `Collection warnings: ${result.errorCount}`,
  ].join("\n");
}

function normalizeAssessmentArgs(args: RawConfigArgs): RawConfigArgs {
  return {
    ...args,
    lookback_days: parseOptionalNumber(args.lookback_days),
  };
}

function normalizeExportArgs(args: RawConfigArgs & { output_dir?: string }): RawConfigArgs & { output_dir?: string } {
  return {
    ...normalizeAssessmentArgs(args),
    output_dir: args.output_dir?.trim(),
  };
}

export function registerDuoTools(pi: any): void {
  const authParams = {
    api_host: Type.Optional(
      Type.String({
        description:
          "Optional Duo Admin API hostname, like api-XXXXXXXX.duosecurity.com. Falls back to DUO_API_HOST.",
      }),
    ),
    ikey: Type.Optional(
      Type.String({
        description:
          "Optional Duo Admin API integration key. Falls back to DUO_IKEY.",
      }),
    ),
    skey: Type.Optional(
      Type.String({
        description:
          "Optional Duo Admin API secret key. Falls back to DUO_SKEY.",
      }),
    ),
    lookback_days: Type.Optional(
      Type.Integer({
        minimum: 1,
        maximum: 180,
        description:
          "Optional Duo log lookback window in days for monitoring-focused collection. Defaults to 30.",
      }),
    ),
  } as const;

  pi.registerTool({
    name: "duo_check_access",
    label: "Check Duo audit access",
    description:
      "Validate Duo Admin API access for a read-only audit principal and report which core GRC surfaces are readable.",
    parameters: Type.Object(authParams),
    prepareArguments: normalizeAssessmentArgs,
    async execute(_toolCallId: string, args: RawConfigArgs) {
      try {
        const config = resolveDuoConfiguration(args);
        const client = new DuoAuditorClient(config);
        const result = await runDuoAccessCheck(client, config);
        return renderAccessCheck(result);
      } catch (error) {
        return errorResult(
          `Duo access check failed: ${error instanceof Error ? error.message : String(error)}`,
          { tool: "duo_check_access" },
        );
      }
    },
  });

  pi.registerTool({
    name: "duo_assess_authentication",
    label: "Assess Duo authentication posture",
    description:
      "Evaluate Duo global MFA policy, factor strength, bypass-code hygiene, remembered devices, and trusted endpoint posture.",
    parameters: Type.Object(authParams),
    prepareArguments: normalizeAssessmentArgs,
    async execute(_toolCallId: string, args: RawConfigArgs) {
      try {
        const config = resolveDuoConfiguration(args);
        const client = new DuoAuditorClient(config);
        const data = await collectDuoAuthenticationData(client, config.lookbackDays);
        return renderAssessmentToolResult(assessDuoAuthentication(data, config));
      } catch (error) {
        return errorResult(
          `Duo authentication assessment failed: ${error instanceof Error ? error.message : String(error)}`,
          { tool: "duo_assess_authentication" },
        );
      }
    },
  });

  pi.registerTool({
    name: "duo_assess_admin_access",
    label: "Assess Duo admin access",
    description:
      "Review Duo privileged administrators, owner concentration, admin MFA methods, help-desk bypass governance, and stale privileged accounts.",
    parameters: Type.Object(authParams),
    prepareArguments: normalizeAssessmentArgs,
    async execute(_toolCallId: string, args: RawConfigArgs) {
      try {
        const config = resolveDuoConfiguration(args);
        const client = new DuoAuditorClient(config);
        const data = await collectDuoAdminAccessData(client, config.lookbackDays);
        return renderAssessmentToolResult(assessDuoAdminAccess(data, config));
      } catch (error) {
        return errorResult(
          `Duo admin-access assessment failed: ${error instanceof Error ? error.message : String(error)}`,
          { tool: "duo_assess_admin_access" },
        );
      }
    },
  });

  pi.registerTool({
    name: "duo_assess_integrations",
    label: "Assess Duo integrations",
    description:
      "Review Duo protected application inventory, explicit policy attachment, Universal Prompt adoption, self-service posture, and Admin API least privilege.",
    parameters: Type.Object(authParams),
    prepareArguments: normalizeAssessmentArgs,
    async execute(_toolCallId: string, args: RawConfigArgs) {
      try {
        const config = resolveDuoConfiguration(args);
        const client = new DuoAuditorClient(config);
        const data = await collectDuoIntegrationData(client);
        return renderAssessmentToolResult(assessDuoIntegrations(data, config));
      } catch (error) {
        return errorResult(
          `Duo integration assessment failed: ${error instanceof Error ? error.message : String(error)}`,
          { tool: "duo_assess_integrations" },
        );
      }
    },
  });

  pi.registerTool({
    name: "duo_assess_monitoring",
    label: "Assess Duo monitoring",
    description:
      "Review Duo authentication telemetry, Trust Monitor coverage, telephony reliance, credits, and notification posture.",
    parameters: Type.Object(authParams),
    prepareArguments: normalizeAssessmentArgs,
    async execute(_toolCallId: string, args: RawConfigArgs) {
      try {
        const config = resolveDuoConfiguration(args);
        const client = new DuoAuditorClient(config);
        const data = await collectDuoMonitoringData(client, config.lookbackDays);
        return renderAssessmentToolResult(assessDuoMonitoring(data, config));
      } catch (error) {
        return errorResult(
          `Duo monitoring assessment failed: ${error instanceof Error ? error.message : String(error)}`,
          { tool: "duo_assess_monitoring" },
        );
      }
    },
  });

  pi.registerTool({
    name: "duo_export_audit_bundle",
    label: "Export Duo audit bundle",
    description:
      "Export a multi-framework Duo audit package with raw API data, normalized findings, markdown reports, and a zip archive.",
    parameters: Type.Object({
      ...authParams,
      output_dir: Type.Optional(
        Type.String({
          description: "Optional output root. Defaults to ./export/duo.",
        }),
      ),
    }),
    prepareArguments: normalizeExportArgs,
    async execute(_toolCallId: string, args: RawConfigArgs & { output_dir?: string }) {
      try {
        const config = resolveDuoConfiguration(args);
        const client = new DuoAuditorClient(config);
        const outputRoot = resolve(process.cwd(), args.output_dir ?? DEFAULT_OUTPUT_DIR);
        const result = await exportDuoAuditBundle(client, config, outputRoot);
        return textResult(buildExportText(config, result), {
          tool: "duo_export_audit_bundle",
          output_dir: result.outputDir,
          zip_path: result.zipPath,
          file_count: result.fileCount,
          finding_count: result.findingCount,
          error_count: result.errorCount,
        });
      } catch (error) {
        return errorResult(
          `Duo audit export failed: ${error instanceof Error ? error.message : String(error)}`,
          { tool: "duo_export_audit_bundle" },
        );
      }
    },
  });
}
