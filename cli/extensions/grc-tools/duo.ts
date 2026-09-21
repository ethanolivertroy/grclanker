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
import { ZipArchive } from "archiver";
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
const INACTIVE_USER_DAYS = 90;
const LOCKOUT_THRESHOLD_MAX = 10;
const IMPOSSIBLE_TRAVEL_WINDOW_MS = 60 * 60 * 1000;

/**
 * Admin API endpoints read by this module. Each path is documented in the Duo
 * Admin API reference (https://duo.com/docs/adminapi) under the named section.
 */
const DUO_ENDPOINTS = {
  settings: "/admin/v1/settings",
  infoSummary: "/admin/v1/info/summary",
  authenticationAttempts: "/admin/v1/info/authentication_attempts",
  adminAllowedAuthMethods: "/admin/v1/admins/allowed_auth_methods",
  globalPolicy: "/admin/v2/policies/global",
  policies: "/admin/v2/policies",
  users: "/admin/v1/users",
  bypassCodes: "/admin/v1/bypass_codes",
  webauthnCredentials: "/admin/v1/webauthncredentials",
  admins: "/admin/v1/admins",
  integrations: "/admin/v3/integrations",
  authenticationLogs: "/admin/v2/logs/authentication",
  activityLogs: "/admin/v2/logs/activity",
  telephonyLogs: "/admin/v2/logs/telephony",
  offlineEnrollmentLogs: "/admin/v1/logs/offline_enrollment",
  trustMonitorEvents: "/admin/v1/trust_monitor/events",
} as const;

const DUO_PERMISSIONS = {
  settings: "Grant settings",
  readInformation: "Grant read information",
  readResource: "Grant resource - Read",
  readLog: "Grant read log",
  adminsRead: "Grant administrators - Read",
} as const;

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

export interface CollectedDataset<T = unknown> {
  data: T;
  error?: string;
  /** Documented metadata.total_objects for the list when the API reported it. */
  total?: number;
  /** False when paging stopped before metadata.next_offset was exhausted or a record cap was hit. */
  complete?: boolean;
}

export interface DuoCollectionStatus {
  totalObjects?: number;
  complete: boolean;
}

export interface DuoAuthenticationData {
  settings: CollectedDataset<JsonRecord | null>;
  policies: CollectedDataset<JsonRecord[]>;
  globalPolicy: CollectedDataset<JsonRecord | null>;
  users: CollectedDataset<JsonRecord[]>;
  bypassCodes: CollectedDataset<JsonRecord[]>;
  webauthnCredentials: CollectedDataset<JsonRecord[]>;
  allowedAdminAuthMethods: CollectedDataset<JsonRecord | null>;
  authenticationLogs: CollectedDataset<JsonRecord[]>;
  offlineEnrollmentLogs?: CollectedDataset<JsonRecord[]>;
}

export interface DuoAdminAccessData {
  settings: CollectedDataset<JsonRecord | null>;
  admins: CollectedDataset<JsonRecord[]>;
  allowedAdminAuthMethods: CollectedDataset<JsonRecord | null>;
  activityLogs: CollectedDataset<JsonRecord[]>;
}

export interface DuoIntegrationData {
  settings: CollectedDataset<JsonRecord | null>;
  policies: CollectedDataset<JsonRecord[]>;
  globalPolicy: CollectedDataset<JsonRecord | null>;
  integrations: CollectedDataset<JsonRecord[]>;
  infoSummary?: CollectedDataset<JsonRecord | null>;
}

export interface DuoMonitoringData {
  settings: CollectedDataset<JsonRecord | null>;
  infoSummary: CollectedDataset<JsonRecord | null>;
  authenticationLogs: CollectedDataset<JsonRecord[]>;
  activityLogs: CollectedDataset<JsonRecord[]>;
  telephonyLogs: CollectedDataset<JsonRecord[]>;
  trustMonitorEvents: CollectedDataset<JsonRecord[]>;
  authenticationAttempts?: CollectedDataset<JsonRecord | null>;
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
  "DUO-AUTH-007": {
    id: "DUO-AUTH-007",
    title: "Global MFA enforcement mode",
    category: "authentication",
    severity: "critical",
    frameworks: {
      fedramp: ["IA-2(1)"],
      cmmc: ["3.5.3"],
      soc2: ["CC6.1"],
      cis: ["6.3"],
      pci_dss: ["8.4.2"],
      disa_stig: ["SRG-APP-000149"],
      irap: ["ISM-1504"],
      ismap: ["CPS.AT-2"],
      general: ["MFA enforced globally"],
    },
  },
  "DUO-AUTH-008": {
    id: "DUO-AUTH-008",
    title: "User enrollment completeness",
    category: "authentication",
    severity: "high",
    frameworks: {
      fedramp: ["IA-2(2)"],
      cmmc: ["3.5.3"],
      soc2: ["CC6.1"],
      cis: ["6.3"],
      pci_dss: ["8.4.1"],
      disa_stig: ["SRG-APP-000150"],
      irap: ["ISM-1504"],
      ismap: ["CPS.AT-2"],
      general: ["all users enrolled, no bypass status"],
    },
  },
  "DUO-AUTH-009": {
    id: "DUO-AUTH-009",
    title: "Inactive user detection",
    category: "authentication",
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
      general: ["inactive users reviewed"],
    },
  },
  "DUO-AUTH-010": {
    id: "DUO-AUTH-010",
    title: "WebAuthn and U2F credential adoption",
    category: "authentication",
    severity: "medium",
    frameworks: {
      fedramp: ["IA-2(12)"],
      cmmc: ["3.5.3"],
      soc2: ["CC6.1"],
      cis: ["6.4"],
      pci_dss: ["8.4.3"],
      disa_stig: ["SRG-APP-000395"],
      irap: ["ISM-1515"],
      ismap: ["CPS.IA-2"],
      general: ["phishing-resistant credential adoption"],
    },
  },
  "DUO-AUTH-011": {
    id: "DUO-AUTH-011",
    title: "Offline access configuration",
    category: "authentication",
    severity: "medium",
    frameworks: {
      fedramp: ["IA-2(11)"],
      cmmc: ["3.5.3"],
      soc2: ["CC6.1"],
      cis: [],
      pci_dss: ["8.4.1"],
      disa_stig: ["SRG-APP-000394"],
      irap: ["ISM-1504"],
      ismap: ["CPS.IA-2"],
      general: ["offline MFA bounded"],
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
  "DUO-ADMIN-005": {
    id: "DUO-ADMIN-005",
    title: "User lockout policy",
    category: "admin_access",
    severity: "medium",
    frameworks: {
      fedramp: ["AC-7"],
      cmmc: ["3.1.8"],
      soc2: ["CC6.1"],
      cis: ["5.4"],
      pci_dss: ["8.3.4"],
      disa_stig: ["SRG-APP-000065"],
      irap: ["ISM-1403"],
      ismap: ["CPS.AC-7"],
      general: ["failed-attempt lockout enabled"],
    },
  },
  "DUO-INTEGRATIONS-005": {
    id: "DUO-INTEGRATIONS-005",
    title: "Critical application protection coverage",
    category: "integrations",
    severity: "high",
    frameworks: {
      fedramp: ["CM-8"],
      cmmc: ["3.4.1"],
      soc2: ["CC6.1"],
      cis: [],
      pci_dss: ["2.4"],
      disa_stig: ["SRG-APP-000383"],
      irap: ["ISM-1599"],
      ismap: ["CPS.CM-8"],
      general: ["critical apps carry explicit MFA policy"],
    },
  },
  "DUO-INTEGRATIONS-006": {
    id: "DUO-INTEGRATIONS-006",
    title: "Device health requirements depth",
    category: "integrations",
    severity: "medium",
    frameworks: {
      fedramp: ["CM-6"],
      cmmc: ["3.4.2"],
      soc2: ["CC6.7"],
      cis: [],
      pci_dss: ["2.2.1"],
      disa_stig: ["SRG-APP-000384"],
      irap: ["ISM-1082"],
      ismap: ["CPS.CM-6"],
      general: ["device health checks enforced"],
    },
  },
  "DUO-MON-005": {
    id: "DUO-MON-005",
    title: "Authentication outcome and travel anomalies",
    category: "monitoring",
    severity: "medium",
    frameworks: {
      fedramp: ["AU-6"],
      cmmc: ["3.3.5"],
      soc2: ["CC7.2"],
      cis: [],
      pci_dss: ["10.6.1"],
      disa_stig: ["SRG-APP-000516"],
      irap: ["ISM-0109"],
      ismap: ["CPS.AU-6"],
      general: ["fraud, denial, and travel anomalies reviewed"],
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

/**
 * Admin API reference sections that state "requires v5 signing. It does not support v2 signing":
 * Integrations v3, Integrations (Legacy v2), Retrieve Secret Key, Policies v2, and Passport v2.
 */
const V5_ONLY_PATH_PATTERNS: readonly RegExp[] = [
  /^\/admin\/v3\//,
  /^\/admin\/v2\/integrations(\/|$)/,
  /^\/admin\/v1\/integrations\/[^/]+\/skey$/,
  /^\/admin\/v2\/policies(\/|$)/,
  /^\/admin\/v2\/passport(\/|$)/,
];

function isV5Path(path: string): boolean {
  return V5_ONLY_PATH_PATTERNS.some((pattern) => pattern.test(path));
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
  private readonly collectionStatuses = new Map<string, DuoCollectionStatus>();

  constructor(config: DuoResolvedConfig, options?: { fetchImpl?: FetchImpl }) {
    this.config = config;
    this.fetchImpl = options?.fetchImpl ?? fetch;
  }

  /** Paging outcome of the most recent list call for a documented endpoint path. */
  collectionStatus(path: string): DuoCollectionStatus | undefined {
    return this.collectionStatuses.get(path);
  }

  private buildWindow(days: number): Record<string, number> {
    const now = Date.now() - 2 * 60 * 1000;
    return {
      mintime: now - clampLookbackDays(days) * 24 * 60 * 60 * 1000,
      maxtime: now,
    };
  }

  /** Same window in Unix seconds, for the v1 info and offline enrollment endpoints. */
  private buildSecondsWindow(days: number): Record<string, number> {
    const window = this.buildWindow(days);
    return {
      mintime: Math.floor(window.mintime / 1000),
      maxtime: Math.floor(window.maxtime / 1000),
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

  /** Admin API reference: Settings > Retrieve Settings. */
  async getSettings(): Promise<JsonRecord> {
    return this.request<JsonRecord>(DUO_ENDPOINTS.settings);
  }

  /** Admin API reference: Account Info > Retrieve Summary. */
  async getInfoSummary(): Promise<JsonRecord> {
    return this.request<JsonRecord>(DUO_ENDPOINTS.infoSummary);
  }

  /** Admin API reference: Account Info > Authentication Attempts Report (mintime and maxtime in Unix seconds). */
  async getAuthenticationAttempts(days: number): Promise<JsonRecord> {
    return this.request<JsonRecord>(DUO_ENDPOINTS.authenticationAttempts, this.buildSecondsWindow(days));
  }

  /** Admin API reference: Administrators > Retrieve Allowed Authentication Methods. */
  async getAdminAllowedAuthMethods(): Promise<JsonRecord> {
    return this.request<JsonRecord>(DUO_ENDPOINTS.adminAllowedAuthMethods);
  }

  /** Admin API reference: Policies > Retrieve Global Policy. */
  async getGlobalPolicy(): Promise<JsonRecord> {
    return this.request<JsonRecord>(DUO_ENDPOINTS.globalPolicy);
  }

  /** Admin API reference: Policies > Retrieve Policies. */
  async listPolicies(): Promise<JsonRecord[]> {
    return this.listOffsetPages(DUO_ENDPOINTS.policies, {}, OFFSET_PAGE_SIZE);
  }

  /** Admin API reference: Users > Retrieve Users (limit max 300). */
  async listUsers(): Promise<JsonRecord[]> {
    return this.listOffsetPages(DUO_ENDPOINTS.users, {}, OFFSET_PAGE_SIZE);
  }

  /** Admin API reference: Bypass Codes > Retrieve Bypass Codes. */
  async listBypassCodes(): Promise<JsonRecord[]> {
    return this.listOffsetPages(DUO_ENDPOINTS.bypassCodes, {}, OFFSET_PAGE_SIZE);
  }

  /** Admin API reference: WebAuthn Credentials > Retrieve WebAuthn Credentials (limit max 500). */
  async listWebauthnCredentials(): Promise<JsonRecord[]> {
    return this.listOffsetPages(DUO_ENDPOINTS.webauthnCredentials, {}, OFFSET_PAGE_SIZE);
  }

  /** Admin API reference: Administrators > Retrieve Administrators. */
  async listAdmins(): Promise<JsonRecord[]> {
    return this.listOffsetPages(DUO_ENDPOINTS.admins, {}, OFFSET_PAGE_SIZE);
  }

  /** Admin API reference: Integrations > Retrieve Integrations (v3, limit max 500). */
  async listIntegrations(): Promise<JsonRecord[]> {
    return this.listOffsetPages(DUO_ENDPOINTS.integrations, {}, OFFSET_PAGE_SIZE, 5);
  }

  /** Admin API reference: Logs > Authentication Logs (v2, mintime and maxtime in milliseconds). */
  async listAuthenticationLogs(days: number, maxRecords: number = MAX_LOG_RECORDS): Promise<JsonRecord[]> {
    return this.listCursorPages(DUO_ENDPOINTS.authenticationLogs, this.buildWindow(days), maxRecords);
  }

  /** Admin API reference: Logs > Activity Logs (v2). */
  async listActivityLogs(days: number, maxRecords: number = MAX_LOG_RECORDS): Promise<JsonRecord[]> {
    return this.listCursorPages(DUO_ENDPOINTS.activityLogs, this.buildWindow(days), maxRecords);
  }

  /** Admin API reference: Logs > Telephony Logs (v2). */
  async listTelephonyLogs(days: number, maxRecords: number = MAX_LOG_RECORDS): Promise<JsonRecord[]> {
    return this.listCursorPages(DUO_ENDPOINTS.telephonyLogs, this.buildWindow(days), maxRecords);
  }

  /** Admin API reference: Logs > Offline Enrollment Logs (mintime in Unix seconds, unpaged). */
  async listOfflineEnrollmentLogs(days: number): Promise<JsonRecord[]> {
    const envelope = await this.requestEnvelope(DUO_ENDPOINTS.offlineEnrollmentLogs, {
      mintime: this.buildSecondsWindow(days).mintime,
    });
    const items = extractArrayPayload(envelope.response);
    this.collectionStatuses.set(DUO_ENDPOINTS.offlineEnrollmentLogs, { complete: true, totalObjects: items.length });
    return items;
  }

  /** Admin API reference: Trust Monitor > Retrieve Events. */
  async listTrustMonitorEvents(days: number, maxRecords: number = MAX_LOG_RECORDS): Promise<JsonRecord[]> {
    return this.listOffsetPages(DUO_ENDPOINTS.trustMonitorEvents, this.buildWindow(days), 50, 2, maxRecords);
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
    let totalObjects: number | undefined;
    let complete = true;

    while (true) {
      const envelope = await this.requestEnvelope(
        path,
        { ...params, limit: pageSize, offset },
        signatureVersion ? { signatureVersion } : undefined,
      );
      items.push(...extractArrayPayload(envelope.response));
      const metadata = extractMetadata(envelope);
      totalObjects = asNumber(metadata.total_objects) ?? totalObjects;
      const next = nextOffsetValue(metadata, "offset");
      if (maxRecords && items.length >= maxRecords) {
        complete = typeof next !== "number" && items.length <= maxRecords;
        break;
      }
      if (typeof next !== "number") break;
      offset = next;
    }

    const result = maxRecords ? items.slice(0, maxRecords) : items;
    if (totalObjects !== undefined && result.length < totalObjects) complete = false;
    this.collectionStatuses.set(path, { totalObjects, complete });
    return result;
  }

  private async listCursorPages(
    path: string,
    params: DuoRequestParams,
    maxRecords: number,
  ): Promise<JsonRecord[]> {
    const items: JsonRecord[] = [];
    let nextOffset: string | undefined;
    let totalObjects: number | undefined;
    let complete = true;

    while (items.length < maxRecords) {
      const envelope = await this.requestEnvelope(path, {
        ...params,
        limit: Math.min(LOG_PAGE_SIZE, maxRecords - items.length),
        sort: "ts:desc",
        next_offset: nextOffset,
      });
      items.push(...extractArrayPayload(envelope.response));
      const metadata = extractMetadata(envelope);
      totalObjects = asNumber(metadata.total_objects) ?? totalObjects;
      const next = nextOffsetValue(metadata, "next_offset");
      if (next === undefined) break;
      nextOffset = String(next);
      if (items.length >= maxRecords) complete = false;
    }

    if (totalObjects !== undefined && items.length < totalObjects) complete = false;
    this.collectionStatuses.set(path, { totalObjects, complete });
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

/**
 * Accepts the comma-separated string the Admin API documents for list fields such as
 * allowed_auth_list and blocked_auth_list, as well as a JSON array of strings.
 */
function listStrings(value: unknown): string[] {
  if (typeof value === "string") {
    return value.split(",").map((item) => item.trim()).filter((item) => item.length > 0);
  }
  return asArray(value)
    .map(asString)
    .filter((item): item is string => Boolean(item))
    .map((item) => item.trim());
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

type CollectionStatusLookup = Partial<Pick<DuoAuditorClient, "collectionStatus">>;

function collectionStatusFor(client: CollectionStatusLookup, path: string): DuoCollectionStatus | undefined {
  return typeof client.collectionStatus === "function" ? client.collectionStatus(path) : undefined;
}

async function collectArrayDataset<T extends JsonRecord>(
  loader: () => Promise<T[]>,
  statusLookup?: () => DuoCollectionStatus | undefined,
): Promise<CollectedDataset<T[]>> {
  try {
    const data = await loader();
    const status = statusLookup?.();
    if (!status) return { data };
    return { data, total: status.totalObjects, complete: status.complete };
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

export type DuoAuthenticationClient = Pick<
  DuoAuditorClient,
  | "getSettings"
  | "listPolicies"
  | "getGlobalPolicy"
  | "listUsers"
  | "listBypassCodes"
  | "listWebauthnCredentials"
  | "getAdminAllowedAuthMethods"
  | "listAuthenticationLogs"
> & Partial<Pick<DuoAuditorClient, "listOfflineEnrollmentLogs">> & CollectionStatusLookup;

export type DuoAdminAccessClient = Pick<
  DuoAuditorClient,
  "getSettings" | "listAdmins" | "getAdminAllowedAuthMethods" | "listActivityLogs"
> & CollectionStatusLookup;

export type DuoIntegrationClient = Pick<
  DuoAuditorClient,
  "getSettings" | "listPolicies" | "getGlobalPolicy" | "listIntegrations"
> & Partial<Pick<DuoAuditorClient, "getInfoSummary">> & CollectionStatusLookup;

export type DuoMonitoringClient = Pick<
  DuoAuditorClient,
  | "getSettings"
  | "getInfoSummary"
  | "listAuthenticationLogs"
  | "listActivityLogs"
  | "listTelephonyLogs"
  | "listTrustMonitorEvents"
> & Partial<Pick<DuoAuditorClient, "getAuthenticationAttempts">> & CollectionStatusLookup;

export async function collectDuoAuthenticationData(
  client: DuoAuthenticationClient,
  lookbackDays: number,
): Promise<DuoAuthenticationData> {
  const status = (path: string) => () => collectionStatusFor(client, path);
  return {
    settings: await collectObjectDataset(() => client.getSettings(), null),
    policies: await collectArrayDataset(() => client.listPolicies(), status(DUO_ENDPOINTS.policies)),
    globalPolicy: await collectObjectDataset(() => client.getGlobalPolicy(), null),
    users: await collectArrayDataset(() => client.listUsers(), status(DUO_ENDPOINTS.users)),
    bypassCodes: await collectArrayDataset(() => client.listBypassCodes(), status(DUO_ENDPOINTS.bypassCodes)),
    webauthnCredentials: await collectArrayDataset(
      () => client.listWebauthnCredentials(),
      status(DUO_ENDPOINTS.webauthnCredentials),
    ),
    allowedAdminAuthMethods: await collectObjectDataset(() => client.getAdminAllowedAuthMethods(), null),
    authenticationLogs: await collectArrayDataset(
      () => client.listAuthenticationLogs(lookbackDays),
      status(DUO_ENDPOINTS.authenticationLogs),
    ),
    offlineEnrollmentLogs: await collectArrayDataset(
      () =>
        client.listOfflineEnrollmentLogs
          ? client.listOfflineEnrollmentLogs(lookbackDays)
          : Promise.reject(new Error(`${DUO_ENDPOINTS.offlineEnrollmentLogs} is not available on this client.`)),
      status(DUO_ENDPOINTS.offlineEnrollmentLogs),
    ),
  };
}

export async function collectDuoAdminAccessData(
  client: DuoAdminAccessClient,
  lookbackDays: number,
): Promise<DuoAdminAccessData> {
  const status = (path: string) => () => collectionStatusFor(client, path);
  return {
    settings: await collectObjectDataset(() => client.getSettings(), null),
    admins: await collectArrayDataset(() => client.listAdmins(), status(DUO_ENDPOINTS.admins)),
    allowedAdminAuthMethods: await collectObjectDataset(() => client.getAdminAllowedAuthMethods(), null),
    activityLogs: await collectArrayDataset(
      () => client.listActivityLogs(lookbackDays),
      status(DUO_ENDPOINTS.activityLogs),
    ),
  };
}

export async function collectDuoIntegrationData(
  client: DuoIntegrationClient,
): Promise<DuoIntegrationData> {
  const status = (path: string) => () => collectionStatusFor(client, path);
  return {
    settings: await collectObjectDataset(() => client.getSettings(), null),
    policies: await collectArrayDataset(() => client.listPolicies(), status(DUO_ENDPOINTS.policies)),
    globalPolicy: await collectObjectDataset(() => client.getGlobalPolicy(), null),
    integrations: await collectArrayDataset(() => client.listIntegrations(), status(DUO_ENDPOINTS.integrations)),
    infoSummary: await collectObjectDataset(
      () =>
        client.getInfoSummary
          ? client.getInfoSummary()
          : Promise.reject(new Error(`${DUO_ENDPOINTS.infoSummary} is not available on this client.`)),
      null,
    ),
  };
}

export async function collectDuoMonitoringData(
  client: DuoMonitoringClient,
  lookbackDays: number,
): Promise<DuoMonitoringData> {
  const status = (path: string) => () => collectionStatusFor(client, path);
  return {
    settings: await collectObjectDataset(() => client.getSettings(), null),
    infoSummary: await collectObjectDataset(() => client.getInfoSummary(), null),
    authenticationLogs: await collectArrayDataset(
      () => client.listAuthenticationLogs(lookbackDays),
      status(DUO_ENDPOINTS.authenticationLogs),
    ),
    activityLogs: await collectArrayDataset(
      () => client.listActivityLogs(lookbackDays),
      status(DUO_ENDPOINTS.activityLogs),
    ),
    telephonyLogs: await collectArrayDataset(
      () => client.listTelephonyLogs(lookbackDays),
      status(DUO_ENDPOINTS.telephonyLogs),
    ),
    trustMonitorEvents: await collectArrayDataset(
      () => client.listTrustMonitorEvents(lookbackDays),
      status(DUO_ENDPOINTS.trustMonitorEvents),
    ),
    authenticationAttempts: await collectObjectDataset(
      () =>
        client.getAuthenticationAttempts
          ? client.getAuthenticationAttempts(lookbackDays)
          : Promise.reject(new Error(`${DUO_ENDPOINTS.authenticationAttempts} is not available on this client.`)),
      null,
    ),
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

/** Authentication Methods section: the telephony method names the Admin API documents. */
const DOCUMENTED_TELEPHONY_METHODS = ["sms", "phonecall"] as const;

function isTelephonyMethod(method: string): boolean {
  return method.includes("sms") || method.includes("phone") || method.includes("voice");
}

interface TelephonyMethodPosture {
  allowed: string[];
  blocked: string[];
  allowedExposed: boolean;
  blockedExposed: boolean;
  explicitlyAllowedTelephony: string[];
  permittedTelephony: string[];
  blockedTelephony: string[];
}

/**
 * Authentication Methods: "An authentication method not included in blocked_auth_list is
 * allowed, even if not specified [in allowed_auth_list]", and the default allow-list
 * includes sms. A telephony method therefore counts as permitted unless it is blocked.
 */
function telephonyMethodPosture(policy: JsonRecord): TelephonyMethodPosture {
  const authMethods = asRecord(getPolicySections(policy).authentication_methods);
  const allowed = getAllowedAuthList(policy);
  const blocked = listStrings(authMethods.blocked_auth_list).map((value) => value.toLowerCase());
  const candidates = [...new Set<string>([...DOCUMENTED_TELEPHONY_METHODS, ...allowed.filter(isTelephonyMethod)])];
  const explicitlyAllowedTelephony = allowed.filter(isTelephonyMethod);
  return {
    allowed,
    blocked,
    allowedExposed: authMethods.allowed_auth_list !== undefined && authMethods.allowed_auth_list !== null,
    blockedExposed: authMethods.blocked_auth_list !== undefined && authMethods.blocked_auth_list !== null,
    explicitlyAllowedTelephony,
    permittedTelephony: candidates.filter((method) => allowed.includes(method) || !blocked.includes(method)),
    blockedTelephony: candidates.filter((method) => blocked.includes(method) && !allowed.includes(method)),
  };
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

function listErrors(datasets: Array<CollectedDataset<unknown> | undefined>): string[] {
  return datasets
    .map((dataset) => dataset?.error)
    .filter((item): item is string => Boolean(item));
}

function unavailableEvidence(endpoint: string, permission: string, error: string | undefined, collect: string): string[] {
  return [
    `endpoint=${endpoint}`,
    `required_permission=${permission}`,
    error ? `collection_error=${error}` : `${endpoint} returned no usable payload.`,
    `manual_evidence=${collect}`,
  ];
}

function inventoryNote(dataset: CollectedDataset<unknown[]>): string | undefined {
  if (dataset.complete === false) {
    return `inventory_seen=${dataset.data.length} inventory_total=${dataset.total ?? "unknown"} (paging incomplete, results not treated as authoritative)`;
  }
  return undefined;
}

const STATUS_RANK: Record<DuoFindingStatus, number> = { Pass: 0, Info: 1, Partial: 2, Manual: 3, Fail: 4 };

function capStatus(status: DuoFindingStatus, cap: DuoFindingStatus): DuoFindingStatus {
  return STATUS_RANK[status] < STATUS_RANK[cap] ? cap : status;
}

function withInventoryCap(
  finding: DuoFinding,
  dataset: CollectedDataset<unknown[]>,
): DuoFinding {
  const note = inventoryNote(dataset);
  if (!note) return finding;
  return {
    ...finding,
    status: finding.status === "Manual" ? "Manual" : capStatus(finding.status, "Partial"),
    evidence: [...finding.evidence, note],
    manualNote: `${finding.manualNote ? `${finding.manualNote} ` : ""}Follow metadata.next_offset to completion before relying on this verdict.`,
  };
}

const BYPASS_CODE_MAX_AGE_HOURS = 24;

interface BypassCodeSample {
  id: string;
  user: string;
  created: string;
  ageHours: number;
  reuseCount: string;
  expiration: string;
}

interface BypassCodeReview {
  stale: BypassCodeSample[];
  unlimited: BypassCodeSample[];
  unlimitedUses: number;
  neverExpire: number;
  undated: number;
  expired: number;
}

function formatUnixSeconds(value: unknown): string {
  const timestamp = parseTimestamp(value);
  return timestamp === null ? "unknown" : new Date(timestamp).toISOString();
}

/**
 * Retrieve Bypass Codes response fields: created (creation timestamp), expiration (null when
 * the code never expires on a date), reuse_count (null when uses are unlimited).
 */
function reviewBypassCodes(codes: JsonRecord[]): BypassCodeReview {
  const review: BypassCodeReview = { stale: [], unlimited: [], unlimitedUses: 0, neverExpire: 0, undated: 0, expired: 0 };
  const now = Date.now();
  for (const code of codes) {
    const created = parseTimestamp(code.created);
    const expiration = parseTimestamp(code.expiration);
    if (expiration !== null && expiration <= now) {
      review.expired += 1;
      continue;
    }
    const sample: BypassCodeSample = {
      id: asString(code.bypass_code_id) ?? "unknown",
      user: userLabel(asRecord(code.user)),
      created: formatUnixSeconds(code.created),
      ageHours: created === null ? -1 : Math.floor((now - created) / (60 * 60 * 1000)),
      reuseCount: code.reuse_count === null ? "null" : String(asNumber(code.reuse_count) ?? "unknown"),
      expiration: code.expiration === null ? "null" : formatUnixSeconds(code.expiration),
    };
    if (created === null) {
      review.undated += 1;
    } else if (now - created > BYPASS_CODE_MAX_AGE_HOURS * 60 * 60 * 1000) {
      review.stale.push(sample);
    }
    const unlimitedUses = code.reuse_count === null;
    const neverExpires = code.expiration === null;
    if (unlimitedUses) review.unlimitedUses += 1;
    if (neverExpires) review.neverExpire += 1;
    if (unlimitedUses || neverExpires) review.unlimited.push(sample);
  }
  return review;
}

function userStatus(user: JsonRecord): string {
  return asString(user.status)?.toLowerCase() ?? "unknown";
}

function userIsEnrolled(user: JsonRecord): boolean | undefined {
  const documentedFlag = asBoolean(user.is_enrolled);
  if (documentedFlag !== undefined) return documentedFlag;
  const authenticatorLists = [user.phones, user.tokens, user.u2f_tokens, user.webauthncredentials];
  if (authenticatorLists.every((list) => list === undefined)) return undefined;
  return authenticatorLists.some((list) => asArray(list).length > 0);
}

function userHasWebauthn(user: JsonRecord): boolean {
  return asArray(user.webauthncredentials).length > 0;
}

function userLabel(user: JsonRecord): string {
  return asString(user.username) ?? asString(user.email) ?? asString(user.user_id) ?? "unknown-user";
}

function percentage(numerator: number, denominator: number): number {
  if (denominator <= 0) return 0;
  return Math.round((numerator / denominator) * 1000) / 10;
}

function assessUserPopulation(data: DuoAuthenticationData): DuoFinding[] {
  const findings: DuoFinding[] = [];
  const users = data.users.data;
  const usersEvidence = unavailableEvidence(
    DUO_ENDPOINTS.users,
    DUO_PERMISSIONS.readResource,
    data.users.error,
    "Export the Users report from the Duo Admin Panel with status, last login, and enrolled authenticators.",
  );

  if (data.users.error || users.length === 0) {
    const reason = data.users.error
      ? "User inventory could not be collected."
      : "The user inventory was empty, so enrollment, inactivity, and credential adoption cannot be measured (Manual, not Pass).";
    findings.push(
      buildFinding("DUO-AUTH-008", "Manual", reason, usersEvidence, "Grant the audit principal Grant resource - Read and confirm the tenant has enrolled users."),
      buildFinding("DUO-AUTH-009", "Manual", reason, usersEvidence, "Review user last-login activity in the Duo Admin Panel Users page."),
      buildFinding("DUO-AUTH-010", "Manual", reason, usersEvidence, "Review WebAuthn registrations per user in the Duo Admin Panel."),
    );
  } else {
    const statusCounts = users.reduce<Record<string, number>>((counts, user) => {
      const status = userStatus(user);
      counts[status] = (counts[status] ?? 0) + 1;
      return counts;
    }, {});
    const bypassUsers = users.filter((user) => userStatus(user) === "bypass");
    const accessUsers = users.filter((user) => ["active", "bypass"].includes(userStatus(user)));
    const enrollmentKnown = accessUsers.filter((user) => userIsEnrolled(user) !== undefined);
    const enrolledUsers = enrollmentKnown.filter((user) => userIsEnrolled(user) === true);
    const unenrolledUsers = enrollmentKnown.filter((user) => userIsEnrolled(user) === false);
    const enrollmentPercent = percentage(enrolledUsers.length, enrollmentKnown.length);
    const enrollmentEvidence = [
      `users_total=${users.length}`,
      ...Object.entries(statusCounts).map(([status, count]) => `status_${status.replace(/\s+/g, "_")}=${count}`),
      `enrolled=${enrolledUsers.length}`,
      `not_enrolled=${unenrolledUsers.length}`,
      `enrollment_percent=${enrollmentPercent}`,
      ...bypassUsers.slice(0, 10).map((user) => `bypass_user=${userLabel(user)}`),
      ...unenrolledUsers.slice(0, 10).map((user) => `not_enrolled_user=${userLabel(user)}`),
    ];

    if (enrollmentKnown.length === 0) {
      findings.push(
        buildFinding(
          "DUO-AUTH-008",
          "Manual",
          "No active user exposed the documented is_enrolled flag or authenticator lists, so enrollment could not be measured.",
          enrollmentEvidence,
          "Confirm the audit principal reads full user objects (is_enrolled, phones, tokens, u2f_tokens, webauthncredentials).",
        ),
      );
    } else if (bypassUsers.length === 0 && unenrolledUsers.length === 0) {
      findings.push(
        withInventoryCap(
          buildFinding(
            "DUO-AUTH-008",
            "Pass",
            "Every active user is enrolled and no user is in bypass status.",
            enrollmentEvidence,
            "Keep enrollment completeness at 100 percent and treat bypass status as a time-boxed exception.",
          ),
          data.users,
        ),
      );
    } else if (bypassUsers.length === 0 && enrollmentPercent >= 90) {
      findings.push(
        withInventoryCap(
          buildFinding(
            "DUO-AUTH-008",
            "Partial",
            `Enrollment is at ${enrollmentPercent} percent with no bypass users, but some active users still have no authenticator.`,
            enrollmentEvidence,
            "Drive the remaining users through enrollment or disable accounts that no longer need access.",
          ),
          data.users,
        ),
      );
    } else {
      findings.push(
        withInventoryCap(
          buildFinding(
            "DUO-AUTH-008",
            "Fail",
            `Enrollment is incomplete: ${bypassUsers.length} bypass user(s) and ${unenrolledUsers.length} unenrolled active user(s).`,
            enrollmentEvidence,
            "Remove bypass status from standing accounts and enforce enrollment for every active user.",
          ),
          data.users,
        ),
      );
    }

    const inactiveUsers = accessUsers.filter((user) => {
      const age = daysSince(user.last_login);
      return age !== null && age > INACTIVE_USER_DAYS;
    });
    const undatedUsers = accessUsers.filter((user) => parseTimestamp(user.last_login) === null);
    const inactiveShare = percentage(inactiveUsers.length, accessUsers.length);
    const inactiveEvidence = [
      `access_users=${accessUsers.length}`,
      `inactive_over_${INACTIVE_USER_DAYS}_days=${inactiveUsers.length}`,
      `never_logged_in_or_undated=${undatedUsers.length}`,
      ...inactiveUsers.slice(0, 10).map((user) => `inactive_user=${userLabel(user)} last_login_age_days=${daysSince(user.last_login)}`),
      ...undatedUsers.slice(0, 10).map((user) => `undated_user=${userLabel(user)} last_login=null`),
    ];
    if (accessUsers.length === 0) {
      findings.push(
        buildFinding(
          "DUO-AUTH-009",
          "Manual",
          "No users are in active or bypass status, so inactivity review has no population to assess.",
          inactiveEvidence,
          "Confirm the user population and re-run once active users exist.",
        ),
      );
    } else if (inactiveUsers.length === 0 && undatedUsers.length === 0) {
      findings.push(
        withInventoryCap(
          buildFinding(
            "DUO-AUTH-009",
            "Pass",
            `No active user has been inactive for more than ${INACTIVE_USER_DAYS} days.`,
            inactiveEvidence,
            "Keep periodic access reviews in place and disable users who stop authenticating.",
          ),
          data.users,
        ),
      );
    } else if (inactiveUsers.length === 0) {
      findings.push(
        withInventoryCap(
          buildFinding(
            "DUO-AUTH-009",
            "Partial",
            `${undatedUsers.length} active user(s) have never logged in (last_login=null) and cannot be counted as active.`,
            inactiveEvidence,
            "Review users who have never authenticated and remove access that was never used.",
          ),
          data.users,
        ),
      );
    } else {
      findings.push(
        withInventoryCap(
          buildFinding(
            "DUO-AUTH-009",
            inactiveShare > 10 ? "Fail" : "Partial",
            `${inactiveUsers.length} active user(s) (${inactiveShare} percent) have not authenticated in ${INACTIVE_USER_DAYS}+ days.`,
            inactiveEvidence,
            "Disable or remove users who have not authenticated in 90 days and document any exceptions.",
          ),
          data.users,
        ),
      );
    }

    const enrolledWithWebauthn = enrolledUsers.filter(userHasWebauthn);
    const u2fUsers = enrolledUsers.filter((user) => asArray(user.u2f_tokens).length > 0);
    const adoptionPercent = percentage(enrolledWithWebauthn.length, enrolledUsers.length);
    const credentialInventory = data.webauthnCredentials.data;
    const uvCapable = credentialInventory.filter((credential) => asBoolean(credential.uv_capable) === true).length;
    const adoptionEvidence = [
      `enrolled_users=${enrolledUsers.length}`,
      `users_with_webauthn=${enrolledWithWebauthn.length}`,
      `webauthn_adoption_percent=${adoptionPercent}`,
      `users_with_deprecated_u2f=${u2fUsers.length}`,
      data.webauthnCredentials.error
        ? `webauthn_inventory_error=${data.webauthnCredentials.error}`
        : `webauthn_credentials_total=${credentialInventory.length} uv_capable=${uvCapable}`,
    ];
    if (enrolledUsers.length === 0) {
      findings.push(
        buildFinding(
          "DUO-AUTH-010",
          "Manual",
          "No enrolled users were available to measure WebAuthn adoption.",
          adoptionEvidence,
          "Confirm enrollment first, then measure phishing-resistant credential adoption.",
        ),
      );
    } else if (adoptionPercent >= 75 && u2fUsers.length === 0) {
      findings.push(
        withInventoryCap(
          buildFinding(
            "DUO-AUTH-010",
            "Pass",
            `${adoptionPercent} percent of enrolled users have a WebAuthn credential and no deprecated U2F tokens remain.`,
            adoptionEvidence,
            "Keep WebAuthn as the default enrollment path and retire remaining non-phishing-resistant authenticators.",
          ),
          data.users,
        ),
      );
    } else if (enrolledWithWebauthn.length > 0) {
      findings.push(
        withInventoryCap(
          buildFinding(
            "DUO-AUTH-010",
            "Partial",
            `${adoptionPercent} percent of enrolled users have a WebAuthn credential${u2fUsers.length > 0 ? ` and ${u2fUsers.length} still hold deprecated U2F tokens` : ""}.`,
            adoptionEvidence,
            "Expand WebAuthn enrollment toward full coverage and migrate U2F tokens to WebAuthn.",
          ),
          data.users,
        ),
      );
    } else {
      findings.push(
        withInventoryCap(
          buildFinding(
            "DUO-AUTH-010",
            "Fail",
            "No enrolled user has a WebAuthn credential.",
            adoptionEvidence,
            "Enable WebAuthn in the authentication methods policy and run an enrollment campaign for security keys or platform authenticators.",
          ),
          data.users,
        ),
      );
    }
  }

  const offline = data.offlineEnrollmentLogs;
  const offlineEvents = offline?.data ?? [];
  const provisioned = offlineEvents.filter((event) => asString(event.action) === "o2fa_user_provisioned").length;
  const deprovisioned = offlineEvents.filter((event) => asString(event.action) === "o2fa_user_deprovisioned").length;
  const securityKeyEvents = offlineEvents.filter((event) => {
    const description = asString(event.description);
    if (!description) return false;
    try {
      return asString(asRecord(JSON.parse(description)).factor) === "security_key";
    } catch {
      return false;
    }
  }).length;
  findings.push(
    buildFinding(
      "DUO-AUTH-011",
      "Manual",
      "Offline access limits are not exposed by the Admin API; the Policy Section Data reference documents no offline access section, so configuration must be verified in the Admin Panel.",
      offline?.error
        ? unavailableEvidence(
            DUO_ENDPOINTS.offlineEnrollmentLogs,
            DUO_PERMISSIONS.readLog,
            offline.error,
            "Review the Offline Access policy section and the Windows Logon offline enrollment report in the Duo Admin Panel.",
          )
        : [
            `offline_enrollment_events=${offlineEvents.length}`,
            `o2fa_user_provisioned=${provisioned}`,
            `o2fa_user_deprovisioned=${deprovisioned}`,
            `security_key_factor_events=${securityKeyEvents}`,
            "Policy Section Data (duo.com/docs/adminapi) lists no offline access section; limits cannot be read programmatically.",
          ],
      "Confirm in the Global Policy Offline Access section that offline access is disabled or limited by days and authentication count, and that security keys are preferred over Duo Mobile OTP.",
      {
        manualNote: "Offline access policy values are not returned by GET /admin/v2/policies/global; only offline enrollment events are readable.",
      },
    ),
  );

  return findings;
}

export function assessDuoAuthentication(
  data: DuoAuthenticationData,
  config: DuoResolvedConfig,
): DuoAssessmentResult {
  const findings: DuoFinding[] = [];
  const globalPolicy = getGlobalPolicyRecord(data);
  const policyUnavailable = Object.keys(getPolicySections(globalPolicy)).length === 0;
  const policyError = data.globalPolicy.error ?? data.policies.error;
  const policyEvidence = unavailableEvidence(
    DUO_ENDPOINTS.globalPolicy,
    DUO_PERMISSIONS.readResource,
    policyError,
    "Export the Global Policy from the Duo Admin Panel Policies page.",
  );
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

  const userAuthBehavior = asString(asRecord(getPolicySections(globalPolicy).authentication_policy).user_auth_behavior)?.toLowerCase();
  if (policyUnavailable) {
    findings.push(
      buildFinding(
        "DUO-AUTH-007",
        "Manual",
        "Global MFA enforcement mode could not be read because the global policy was unavailable.",
        policyEvidence,
        "Grant the audit principal Grant resource - Read and confirm authentication_policy.user_auth_behavior=enforce in the Global Policy.",
      ),
    );
  } else if (userAuthBehavior === undefined) {
    findings.push(
      buildFinding(
        "DUO-AUTH-007",
        "Manual",
        "The global policy payload did not include the authentication_policy section.",
        ["sections.authentication_policy.user_auth_behavior was absent from the Global Policy response."],
        "Confirm in the Duo Admin Panel that the Global Policy Authentication Policy is set to enforce 2FA.",
      ),
    );
  } else if (userAuthBehavior === "enforce") {
    findings.push(
      buildFinding(
        "DUO-AUTH-007",
        "Pass",
        "The global policy enforces two-factor authentication for all users.",
        ["authentication_policy.user_auth_behavior=enforce"],
        "Keep the Global Policy authentication behavior on enforce and review any custom policy that overrides it.",
      ),
    );
  } else if (userAuthBehavior === "bypass") {
    findings.push(
      buildFinding(
        "DUO-AUTH-007",
        "Fail",
        "The global policy bypasses two-factor authentication and enrollment.",
        ["authentication_policy.user_auth_behavior=bypass"],
        "Set the Global Policy authentication behavior to enforce so primary credentials alone never grant access.",
      ),
    );
  } else {
    findings.push(
      buildFinding(
        "DUO-AUTH-007",
        "Partial",
        `The global policy authentication behavior is ${userAuthBehavior}, which denies all authentication rather than enforcing MFA.`,
        [`authentication_policy.user_auth_behavior=${userAuthBehavior}`],
        "Confirm the deny posture is intentional (for example a maintenance freeze) and return the Global Policy to enforce afterwards.",
      ),
    );
  }

  if (policyUnavailable) {
    findings.push(
      buildFinding(
        "DUO-AUTH-001",
        "Manual",
        "Phishing-resistant factor posture could not be read because the global policy was unavailable.",
        policyEvidence,
        "Grant the audit principal Grant resource - Read and confirm WebAuthn or Verified Duo Push in authentication_methods.",
      ),
    );
  } else if (hasWebAuthn || (allowsPush && requireVerifiedPush)) {
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

  const telephony = telephonyMethodPosture(globalPolicy);
  const methodListEvidence = [
    `authentication_methods.allowed_auth_list=${telephony.allowed.join(",") || (telephony.allowedExposed ? "empty" : "absent")}`,
    `authentication_methods.blocked_auth_list=${telephony.blocked.join(",") || (telephony.blockedExposed ? "empty" : "absent")}`,
    "Admin API rule: a method not in blocked_auth_list is allowed even when it is not in allowed_auth_list.",
  ];
  if (policyUnavailable) {
    findings.push(
      buildFinding(
        "DUO-AUTH-002",
        "Manual",
        "Authentication method restrictions could not be read because the global policy was unavailable.",
        policyEvidence,
        "Grant the audit principal Grant resource - Read and confirm sms and phonecall appear in authentication_methods.blocked_auth_list.",
      ),
    );
  } else if (!telephony.allowedExposed && !telephony.blockedExposed) {
    findings.push(
      buildFinding(
        "DUO-AUTH-002",
        "Manual",
        "The global policy did not expose authentication_methods.allowed_auth_list or blocked_auth_list.",
        methodListEvidence,
        "Review the Authentication Methods policy section manually and verify SMS and phone callback are blocked.",
      ),
    );
  } else if (telephony.explicitlyAllowedTelephony.length > 0) {
    findings.push(
      buildFinding(
        "DUO-AUTH-002",
        telephony.blockedTelephony.length === 0 ? "Fail" : "Partial",
        `Telephony factors are explicitly allowed in the global policy: ${telephony.explicitlyAllowedTelephony.join(", ")}.`,
        [...methodListEvidence, `permitted_telephony_methods=${telephony.permittedTelephony.join(",")}`],
        "Remove sms and phonecall from allowed_auth_list and add them to blocked_auth_list, reserving telephony for tightly governed exceptions.",
      ),
    );
  } else if (!telephony.blockedExposed) {
    findings.push(
      buildFinding(
        "DUO-AUTH-002",
        "Manual",
        "The global policy did not expose authentication_methods.blocked_auth_list, so sms and phonecall cannot be confirmed blocked.",
        methodListEvidence,
        "Confirm in the Authentication Methods policy section that SMS and phone callback are blocked; a method absent from the allow-list is still permitted unless blocked.",
      ),
    );
  } else if (telephony.permittedTelephony.length === 0) {
    findings.push(
      buildFinding(
        "DUO-AUTH-002",
        "Pass",
        "SMS and phone callback are blocked by the global policy.",
        [...methodListEvidence, `blocked_telephony_methods=${telephony.blockedTelephony.join(",")}`],
        "Keep sms and phonecall in blocked_auth_list unless you have a documented break-glass exception.",
      ),
    );
  } else {
    findings.push(
      buildFinding(
        "DUO-AUTH-002",
        telephony.blockedTelephony.length === 0 ? "Fail" : "Partial",
        `Telephony factors remain permitted because they are not in blocked_auth_list: ${telephony.permittedTelephony.join(", ")}.`,
        [
          ...methodListEvidence,
          `permitted_telephony_methods=${telephony.permittedTelephony.join(",")}`,
          `blocked_telephony_methods=${telephony.blockedTelephony.join(",") || "none"}`,
        ],
        "Add sms and phonecall to authentication_methods.blocked_auth_list so telephony factors are unavailable outside governed exceptions.",
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
        policyUnavailable ? policyEvidence : ["The global policy did not include a new_user.new_user_behavior value."],
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
  if (policyUnavailable) {
    findings.push(
      buildFinding(
        "DUO-AUTH-004",
        "Manual",
        "Remembered device posture could not be read because the global policy was unavailable.",
        policyEvidence,
        "Grant the audit principal Grant resource - Read and review remembered_devices.browser_apps in the Global Policy.",
      ),
    );
  } else if (rememberedDays === null) {
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
  if (policyUnavailable) {
    findings.push(
      buildFinding(
        "DUO-AUTH-005",
        "Manual",
        "Trusted endpoint posture could not be read because the global policy was unavailable.",
        policyEvidence,
        "Grant the audit principal Grant resource - Read and review trusted_endpoints.trusted_endpoint_checking in the Global Policy.",
      ),
    );
  } else if (trustedChecking === "require-trusted") {
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
  const bypassReview = reviewBypassCodes(data.bypassCodes.data);
  const bypassEvidence = [
    `active_bypass_codes=${bypassCount}`,
    `codes_older_than_24_hours=${bypassReview.stale.length}`,
    `codes_with_unlimited_uses=${bypassReview.unlimitedUses}`,
    `codes_without_expiration=${bypassReview.neverExpire}`,
    `codes_undated=${bypassReview.undated}`,
    `codes_expired=${bypassReview.expired}`,
    `helpdesk_bypass=${helpdeskBypass ?? "unknown"}`,
    `helpdesk_bypass_expiration=${helpdeskBypassExpiration ?? "unset"}`,
    ...bypassReview.stale.slice(0, 5).map((code) =>
      `stale_bypass_code=${code.id} user=${code.user} created=${code.created} age_hours=${code.ageHours}`,
    ),
    ...bypassReview.unlimited.slice(0, 5).map((code) =>
      `unlimited_bypass_code=${code.id} user=${code.user} reuse_count=${code.reuseCount} expiration=${code.expiration}`,
    ),
  ];
  const flaggedBypassCodes = bypassReview.stale.length + bypassReview.unlimited.length;

  if (data.bypassCodes.error) {
    findings.push(
      buildFinding(
        "DUO-AUTH-006",
        "Manual",
        "Bypass code inventory could not be collected.",
        unavailableEvidence(
          DUO_ENDPOINTS.bypassCodes,
          DUO_PERMISSIONS.readResource,
          data.bypassCodes.error,
          "Export the Bypass Codes report from the Duo Admin Panel.",
        ),
        "Grant the audit principal Grant resource - Read so active bypass codes can be enumerated.",
      ),
    );
  } else if (bypassCount === 0) {
    findings.push(
      withInventoryCap(
        buildFinding(
          "DUO-AUTH-006",
          "Pass",
          "No active bypass codes were returned.",
          ["Global bypass code inventory is empty, which is compliant by intent: no outstanding break-glass codes."],
          "Keep break-glass issuance exceptional and time-bounded.",
        ),
        data.bypassCodes,
      ),
    );
  } else if (flaggedBypassCodes > 0 || helpdeskBypass === "allow" || (helpdeskBypass === "limit" && (helpdeskBypassExpiration ?? 0) <= 0)) {
    findings.push(
      withInventoryCap(
        buildFinding(
          "DUO-AUTH-006",
          "Fail",
          flaggedBypassCodes > 0
            ? `${bypassReview.stale.length} bypass code(s) are older than 24 hours and ${bypassReview.unlimited.length} have unlimited uses or no expiration.`
            : "Bypass codes are active while help desk issuance has no expiration limit.",
          bypassEvidence,
          "Revoke bypass codes older than 24 hours, issue only single-use codes with an expiration, and limit help desk issuance.",
        ),
        data.bypassCodes,
      ),
    );
  } else if (bypassReview.undated > 0) {
    findings.push(
      withInventoryCap(
        buildFinding(
          "DUO-AUTH-006",
          "Partial",
          `${bypassReview.undated} bypass code(s) have no created timestamp, so their age cannot be confirmed (Partial, not Pass).`,
          bypassEvidence,
          "Review the undated bypass codes in the Duo Admin Panel and revoke any older than 24 hours.",
        ),
        data.bypassCodes,
      ),
    );
  } else {
    findings.push(
      withInventoryCap(
        buildFinding(
          "DUO-AUTH-006",
          "Partial",
          bypassCount === bypassReview.expired
            ? `${bypassCount} bypass code(s) were returned but every one has passed its expiration timestamp (Partial until they are deleted).`
            : `${bypassCount - bypassReview.expired} active bypass code(s) were created within 24 hours and carry a reuse limit and expiration.`,
          bypassEvidence,
          "Confirm each active code maps to an approved break-glass request and revoke it once used.",
        ),
        data.bypassCodes,
      ),
    );
  }

  findings.push(...assessUserPopulation(data));

  const snapshotSummary = {
    users: data.users.data.length,
    active_bypass_codes: bypassCount,
    webauthn_credentials: data.webauthnCredentials.data.length,
    auth_logs_collected: data.authenticationLogs.data.length,
    offline_enrollment_events: data.offlineEnrollmentLogs?.data.length ?? 0,
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
  const activeAdmins = admins.filter((admin) => (asString(admin.status)?.toLowerCase() ?? "active") !== "disabled");
  const ownerCount = activeAdmins.filter(isOwnerAdmin).length;
  const staleAdmins = activeAdmins.filter((admin) => {
    const age = daysSince(admin.last_login);
    return age !== null && age > INACTIVE_USER_DAYS;
  });
  const undatedAdmins = activeAdmins.filter((admin) => parseTimestamp(admin.last_login) === null);
  const adminsEvidence = unavailableEvidence(
    DUO_ENDPOINTS.admins,
    `${DUO_PERMISSIONS.adminsRead} and ${DUO_PERMISSIONS.readResource}`,
    data.admins.error,
    "Export the Administrators list from the Duo Admin Panel with role, status, and last login.",
  );

  if (admins.length === 0) {
    findings.push(
      buildFinding(
        "DUO-ADMIN-001",
        "Manual",
        data.admins.error
          ? "Administrator inventory could not be collected."
          : "The administrator inventory was empty, which cannot be true for a live tenant, so the result is Manual rather than Pass.",
        adminsEvidence,
        "Confirm that the audit principal has Grant administrators - Read and Grant resource - Read permissions.",
      ),
    );
  } else if (ownerCount <= 2) {
    findings.push(
      withInventoryCap(
        buildFinding(
          "DUO-ADMIN-001",
          "Pass",
          "Owner-level access is concentrated in a small number of admins.",
          [`admins=${admins.length}`, `active_admins=${activeAdmins.length}`, `owners=${ownerCount}`],
          "Keep Owner-role assignments limited and review them periodically.",
        ),
        data.admins,
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
  if (data.allowedAdminAuthMethods.error || Object.keys(allowed).length === 0) {
    findings.push(
      buildFinding(
        "DUO-ADMIN-002",
        "Manual",
        "Administrator authentication methods could not be collected.",
        unavailableEvidence(
          DUO_ENDPOINTS.adminAllowedAuthMethods,
          DUO_PERMISSIONS.adminsRead,
          data.allowedAdminAuthMethods.error,
          "Review Administrators > Admin Login Settings in the Duo Admin Panel.",
        ),
        "Grant the audit principal Grant administrators - Read so admin login factors can be verified.",
      ),
    );
  } else if (verifiedPushEnabled || webauthnEnabled) {
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
  const settingsUnavailable = Boolean(data.settings.error) || Object.keys(settings).length === 0;
  const settingsEvidence = unavailableEvidence(
    DUO_ENDPOINTS.settings,
    DUO_PERMISSIONS.settings,
    data.settings.error,
    "Review Settings in the Duo Admin Panel (help desk bypass, lockout threshold, lockout duration).",
  );
  const helpdeskBypass = asString(settings.helpdesk_bypass)?.toLowerCase();
  const helpdeskBypassExpiration = asNumber(settings.helpdesk_bypass_expiration);
  if (settingsUnavailable) {
    findings.push(
      buildFinding(
        "DUO-ADMIN-003",
        "Manual",
        "Help desk bypass settings could not be collected.",
        settingsEvidence,
        "Grant the audit principal Grant settings so helpdesk_bypass can be verified.",
      ),
    );
  } else if (helpdeskBypass === "deny") {
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

  const staleEvidence = [
    `admins_reviewed=${activeAdmins.length}`,
    `stale_admins=${staleAdmins.length}`,
    `undated_admins=${undatedAdmins.length}`,
    ...staleAdmins.slice(0, 10).map((admin) => `${asString(admin.email) ?? asString(admin.name) ?? "unknown-admin"} last_login_age_days=${daysSince(admin.last_login) ?? "unknown"}`),
    ...undatedAdmins.slice(0, 10).map((admin) => `${asString(admin.email) ?? asString(admin.name) ?? "unknown-admin"} last_login=null`),
  ];
  if (admins.length === 0) {
    findings.push(
      buildFinding(
        "DUO-ADMIN-004",
        "Manual",
        "Stale administrator review could not be completed.",
        adminsEvidence,
        "Review privileged account activity directly in the Duo admin console.",
      ),
    );
  } else if (staleAdmins.length === 0 && undatedAdmins.length === 0) {
    findings.push(
      withInventoryCap(
        buildFinding(
          "DUO-ADMIN-004",
          "Pass",
          "No privileged administrators were obviously stale based on available login timestamps.",
          staleEvidence,
          "Keep periodic access reviews in place for privileged administrators.",
        ),
        data.admins,
      ),
    );
  } else if (staleAdmins.length === 0) {
    findings.push(
      withInventoryCap(
        buildFinding(
          "DUO-ADMIN-004",
          "Partial",
          `${undatedAdmins.length} administrator(s) have never logged in (last_login=null) and cannot be counted as active.`,
          staleEvidence,
          "Review administrators who have never logged in and remove accounts that were never activated or used.",
        ),
        data.admins,
      ),
    );
  } else {
    findings.push(
      withInventoryCap(
        buildFinding(
          "DUO-ADMIN-004",
          staleAdmins.length >= Math.max(1, Math.ceil(activeAdmins.length / 3)) ? "Fail" : "Partial",
          "Some privileged administrators appear stale.",
          staleEvidence,
          "Review stale privileged accounts and remove or re-justify access for administrators who no longer need it.",
        ),
        data.admins,
      ),
    );
  }

  const lockoutThreshold = settings.lockout_threshold;
  const lockoutThresholdNumber = asNumber(lockoutThreshold);
  const lockoutExpire = asNumber(settings.lockout_expire_duration);
  const unenrolledLockoutDays = asNumber(settings.unenrolled_user_lockout_threshold);
  const lockoutEvidence = [
    `lockout_threshold=${lockoutThreshold ?? "null"}`,
    `lockout_expire_duration=${settings.lockout_expire_duration ?? "null"}`,
    `unenrolled_user_lockout_threshold=${unenrolledLockoutDays ?? "null"}`,
  ];
  if (settingsUnavailable) {
    findings.push(
      buildFinding(
        "DUO-ADMIN-005",
        "Manual",
        "User lockout settings could not be collected.",
        settingsEvidence,
        "Grant the audit principal Grant settings so lockout_threshold can be verified.",
      ),
    );
  } else if (lockoutThresholdNumber === undefined) {
    findings.push(
      buildFinding(
        "DUO-ADMIN-005",
        "Manual",
        "The settings payload did not include a numeric lockout_threshold.",
        lockoutEvidence,
        "Confirm the Lockout and Fraud settings in the Duo Admin Panel.",
      ),
    );
  } else if (lockoutThresholdNumber <= 0) {
    findings.push(
      buildFinding(
        "DUO-ADMIN-005",
        "Fail",
        "Failed-attempt lockout is not configured.",
        lockoutEvidence,
        `Set lockout_threshold to ${LOCKOUT_THRESHOLD_MAX} or fewer consecutive failed attempts.`,
      ),
    );
  } else if (lockoutThresholdNumber <= LOCKOUT_THRESHOLD_MAX) {
    findings.push(
      buildFinding(
        "DUO-ADMIN-005",
        "Pass",
        `Users are locked out after ${lockoutThresholdNumber} consecutive failed attempts.`,
        [
          ...lockoutEvidence,
          lockoutExpire && lockoutExpire > 0
            ? `Locked-out users revert to Active after ${lockoutExpire} minutes.`
            : "Locked-out users stay locked until an administrator or API call clears the status.",
        ],
        "Keep the lockout threshold at or below 10 and review lockout events in the authentication log.",
      ),
    );
  } else {
    findings.push(
      buildFinding(
        "DUO-ADMIN-005",
        "Partial",
        `Lockout is enabled but only after ${lockoutThresholdNumber} consecutive failed attempts.`,
        lockoutEvidence,
        `Lower lockout_threshold to ${LOCKOUT_THRESHOLD_MAX} or fewer consecutive failed attempts.`,
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
        ? unavailableEvidence(
            DUO_ENDPOINTS.activityLogs,
            DUO_PERMISSIONS.readLog,
            data.activityLogs.error,
            "Export the Administrator Actions report from the Duo Admin Panel.",
          )
        : [`activity_logs_collected=${data.activityLogs.data.length}`],
      "Keep admin activity logs available to the audit or monitoring workflow so privileged changes are reviewable.",
    ),
  );

  const snapshotSummary = {
    admins: admins.length,
    owners: ownerCount,
    stale_admins: staleAdmins.length,
    undated_admins: undatedAdmins.length,
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

function integrationLabel(integration: JsonRecord): string {
  return asString(integration.name) ?? asString(integration.integration_key) ?? "unknown-integration";
}

function isCriticalIntegration(integration: JsonRecord): boolean {
  const sensitivity = asString(integration.sensitivity_level)?.toLowerCase();
  return sensitivity === "critical" || sensitivity === "high" || listStrings(integration.compliance_requirements).length > 0;
}

function assessCriticalApplications(data: DuoIntegrationData, integrationsEvidence: string[]): DuoFinding {
  if (data.integrations.error) {
    return buildFinding(
      "DUO-INTEGRATIONS-005",
      "Manual",
      "Critical application coverage could not be assessed because the integration inventory was unavailable.",
      integrationsEvidence,
      "Grant the audit principal Grant resource - Read and tag critical applications with a sensitivity level in the Duo Admin Panel.",
    );
  }

  const protectedIntegrations = data.integrations.data.filter(integrationIsProtected);
  const tagged = protectedIntegrations.filter(isCriticalIntegration);
  const taggedWithoutPolicy = tagged.filter((integration) => !policyKey(integration));
  const evidence = [
    `protected_integrations=${protectedIntegrations.length}`,
    `critical_or_high_or_regulated=${tagged.length}`,
    `critical_without_policy_key=${taggedWithoutPolicy.length}`,
    ...taggedWithoutPolicy.slice(0, 10).map((integration) =>
      `unprotected_critical_app=${integrationLabel(integration)} type=${asString(integration.type) ?? "unknown"} sensitivity_level=${asString(integration.sensitivity_level) ?? "null"} compliance_requirements=${listStrings(integration.compliance_requirements).join("/") || "none"}`,
    ),
  ];

  if (protectedIntegrations.length === 0) {
    return buildFinding(
      "DUO-INTEGRATIONS-005",
      "Manual",
      "No protected integrations were returned, so critical application coverage cannot be compared against the tenant inventory.",
      evidence,
      "Confirm the application inventory in the Duo Admin Panel and compare it with the organization's critical application list.",
    );
  }
  if (tagged.length === 0) {
    return buildFinding(
      "DUO-INTEGRATIONS-005",
      "Manual",
      "No integration carries a Critical or High sensitivity_level or any compliance_requirements, so critical applications cannot be identified from the API.",
      [...evidence, "sensitivity_level and compliance_requirements are read-only fields set in the Duo Admin Panel."],
      "Tag critical applications with a sensitivity level and compliance requirements in the Duo Admin Panel, then compare against the organization's critical application list.",
    );
  }
  if (taggedWithoutPolicy.length === 0) {
    return withInventoryCap(
      buildFinding(
        "DUO-INTEGRATIONS-005",
        "Pass",
        "Every Critical, High, or regulated application has an explicit Duo policy attached.",
        evidence,
        "Keep sensitivity tagging current and compare the Duo inventory against the organization's critical application list during access reviews.",
      ),
      data.integrations,
    );
  }
  return withInventoryCap(
    buildFinding(
      "DUO-INTEGRATIONS-005",
      taggedWithoutPolicy.length === tagged.length ? "Fail" : "Partial",
      `${taggedWithoutPolicy.length} Critical, High, or regulated application(s) rely on the global policy only.`,
      evidence,
      "Attach an explicit policy to every critical application so its MFA, device, and network requirements are reviewable.",
    ),
    data.integrations,
  );
}

function osList(value: unknown): string[] {
  return listStrings(value).map((item) => item.toLowerCase());
}

function assessDeviceHealthDepth(data: DuoIntegrationData): DuoFinding {
  const globalPolicy = getGlobalPolicyRecord(data);
  const sections = getPolicySections(globalPolicy);
  const edition = asString(asRecord(data.infoSummary?.data).edition) ?? "unknown";
  if (Object.keys(sections).length === 0) {
    return buildFinding(
      "DUO-INTEGRATIONS-006",
      "Manual",
      "Device health requirements could not be read because the global policy was unavailable.",
      unavailableEvidence(
        DUO_ENDPOINTS.globalPolicy,
        DUO_PERMISSIONS.readResource,
        data.globalPolicy.error ?? data.policies.error,
        "Export the Global Policy Duo Desktop, Operating Systems, Full Disk Encryption, and Screen Lock sections.",
      ),
      "Grant the audit principal Grant resource - Read and review the device health policy sections.",
    );
  }

  const healthChecks = asRecord(sections.health_checks);
  const duoDesktop = asRecord(sections.duo_desktop);
  const healthSource = Object.keys(healthChecks).length > 0 ? "health_checks" : Object.keys(duoDesktop).length > 0 ? "duo_desktop" : undefined;
  const health = healthSource === "health_checks" ? healthChecks : duoDesktop;
  const operatingSystems = asRecord(sections.operating_systems);
  const osRestrictions = asRecord(operatingSystems.os_restrictions);
  const fullDiskEncryption = asRecord(sections.full_disk_encryption);
  const screenLock = asRecord(sections.screen_lock);
  const hasEditionSections = [healthSource, sections.operating_systems, sections.full_disk_encryption, sections.screen_lock].some(Boolean);

  if (!hasEditionSections) {
    return buildFinding(
      "DUO-INTEGRATIONS-006",
      "Manual",
      `The global policy exposes no device health sections; health_checks, duo_desktop, operating_systems, full_disk_encryption, and screen_lock require Duo Advantage or Premier (edition reported: ${edition}).`,
      [`edition=${edition}`, "Policy Section Data marks these sections as Premier and Advantage edition features."],
      "Confirm the tenant edition and, if eligible, configure device health requirements in the Global Policy.",
    );
  }

  const requiresDuoDesktop = osList(health.requires_duo_desktop);
  const enforceEncryption = osList(health.enforce_encryption);
  const enforceFirewall = osList(health.enforce_firewall);
  const enforceSystemPassword = osList(health.enforce_system_password);
  const restrictedOs = Object.entries(osRestrictions).filter(([, rule]) => {
    const record = asRecord(rule);
    return Boolean(asString(record.block_policy) || asString(record.warn_policy) || asString(record.block_version) || asString(record.warn_version));
  }).map(([os]) => os);
  const requireEncryption = asBoolean(fullDiskEncryption.require_encryption);
  const requireScreenLock = asBoolean(screenLock.require_screen_lock);
  const evidence = [
    `edition=${edition}`,
    `health_section=${healthSource ?? "absent"}`,
    `requires_duo_desktop=${requiresDuoDesktop.join(",") || "none"}`,
    `enforce_encryption=${enforceEncryption.join(",") || "none"}`,
    `enforce_firewall=${enforceFirewall.join(",") || "none"}`,
    `enforce_system_password=${enforceSystemPassword.join(",") || "none"}`,
    `os_restrictions=${restrictedOs.join(",") || "none"}`,
    `full_disk_encryption.require_encryption=${requireEncryption ?? "absent"}`,
    `screen_lock.require_screen_lock=${requireScreenLock ?? "absent"}`,
  ];
  const checks = [
    requiresDuoDesktop.length > 0,
    enforceEncryption.length > 0 || requireEncryption === true,
    enforceFirewall.length > 0,
    enforceSystemPassword.length > 0 || requireScreenLock === true,
    restrictedOs.length > 0,
  ];
  const satisfied = checks.filter(Boolean).length;

  if (satisfied === checks.length) {
    return buildFinding(
      "DUO-INTEGRATIONS-006",
      "Pass",
      "Device health policy requires Duo Desktop with encryption, firewall, system password or screen lock, and operating system version restrictions.",
      evidence,
      "Keep device health requirements aligned with the managed fleet and review remediation notes for blocked users.",
    );
  }
  if (satisfied === 0) {
    return buildFinding(
      "DUO-INTEGRATIONS-006",
      "Fail",
      "Device health sections are present but no health requirement is enforced.",
      evidence,
      "Require Duo Desktop and enable encryption, firewall, system password, and OS version checks for managed platforms.",
    );
  }
  return buildFinding(
    "DUO-INTEGRATIONS-006",
    "Partial",
    `${satisfied} of ${checks.length} device health requirement groups are enforced.`,
    evidence,
    "Extend device health enforcement to encryption, firewall, system password or screen lock, and OS version restrictions.",
  );
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

  const integrationsEvidence = unavailableEvidence(
    DUO_ENDPOINTS.integrations,
    DUO_PERMISSIONS.readResource,
    data.integrations.error,
    "Export the Applications list from the Duo Admin Panel with type, policy, sensitivity level, and user access.",
  );

  if (integrations.length === 0) {
    findings.push(
      buildFinding(
        "DUO-INTEGRATIONS-001",
        data.integrations.error ? "Manual" : "Partial",
        data.integrations.error
          ? "Direct integration inventory could not be collected."
          : "No active protected integrations were returned (Partial, not Pass: an empty inventory cannot demonstrate policy coverage).",
        data.integrations.error ? integrationsEvidence : ["Protected integration count was zero."],
        "Confirm integration inventory and policy attachment inside the Duo Admin Panel before concluding the environment has no protected apps.",
      ),
    );
  } else if (policyAttachedCount === integrations.length) {
    findings.push(
      withInventoryCap(
        buildFinding(
          "DUO-INTEGRATIONS-001",
          "Pass",
          "All active protected integrations expose an explicit policy attachment.",
          [`protected_integrations=${integrations.length}`, `with_policy_key=${policyAttachedCount}`],
          "Keep custom policy attachment visible for high-value applications instead of relying only on the global policy.",
        ),
        data.integrations,
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

  if (data.integrations.error) {
    findings.push(
      buildFinding(
        "DUO-INTEGRATIONS-004",
        "Manual",
        "Admin API integration permissions could not be collected.",
        integrationsEvidence,
        "Grant the audit principal Grant resource - Read so Admin API application permissions can be reviewed.",
      ),
    );
  } else if (adminApiIntegrations.length === 0) {
    findings.push(
      buildFinding(
        "DUO-INTEGRATIONS-004",
        "Partial",
        "No Admin API integrations were returned even though this audit runs through one, so the inventory is not authoritative.",
        ["adminapi_integrations=0", `integrations_returned=${data.integrations.data.length}`],
        "Review Admin API applications directly in the Duo Admin Panel and confirm the audit principal can list them.",
      ),
    );
  } else if (overPrivilegedAdminApis.length === 0) {
    findings.push(
      withInventoryCap(
        buildFinding(
          "DUO-INTEGRATIONS-004",
          "Pass",
          "Admin API integrations appear read-oriented in the returned inventory.",
          [
            `adminapi_integrations=${adminApiIntegrations.length}`,
            "No integration sets adminapi_integrations, adminapi_write_resource, adminapi_settings, or adminapi_allow_to_set_permissions.",
          ],
          "Keep Admin API applications constrained to read permissions unless a write path is formally justified.",
        ),
        data.integrations,
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

  findings.push(assessCriticalApplications(data, integrationsEvidence));
  findings.push(assessDeviceHealthDepth(data));

  const snapshotSummary = {
    protected_integrations: integrations.length,
    policies: data.policies.data.length,
    adminapi_integrations: adminApiIntegrations.length,
    overprivileged_adminapi_integrations: overPrivilegedAdminApis.length,
    edition: asString(asRecord(data.infoSummary?.data).edition) ?? "unknown",
  };

  return {
    category: "integrations",
    findings,
    summary: summarizeFindings(findings),
    snapshotSummary,
    text: buildAssessmentText("Duo integration assessment", getOrganizationName(config), findings, snapshotSummary),
  };
}

interface TravelAnomaly {
  user: string;
  fromCountry: string;
  toCountry: string;
  minutesApart: number;
}

function eventCountry(event: JsonRecord): string | undefined {
  return asString(asRecord(asRecord(event.access_device).location).country);
}

function detectImpossibleTravel(events: JsonRecord[]): { anomalies: TravelAnomaly[]; locatedEvents: number } {
  const byUser = new Map<string, Array<{ timestamp: number; country: string }>>();
  let locatedEvents = 0;
  for (const event of events) {
    if (asString(event.result)?.toLowerCase() !== "success") continue;
    const country = eventCountry(event);
    const timestamp = parseTimestamp(event.timestamp);
    if (!country || timestamp === null) continue;
    locatedEvents += 1;
    const user = asString(asRecord(event.user).key) ?? asString(asRecord(event.user).name) ?? "unknown-user";
    const list = byUser.get(user) ?? [];
    list.push({ timestamp, country });
    byUser.set(user, list);
  }

  const anomalies: TravelAnomaly[] = [];
  for (const [user, list] of byUser) {
    list.sort((a, b) => a.timestamp - b.timestamp);
    for (let index = 1; index < list.length; index += 1) {
      const previous = list[index - 1];
      const current = list[index];
      if (previous.country !== current.country && current.timestamp - previous.timestamp <= IMPOSSIBLE_TRAVEL_WINDOW_MS) {
        anomalies.push({
          user,
          fromCountry: previous.country,
          toCountry: current.country,
          minutesApart: Math.round((current.timestamp - previous.timestamp) / 60000),
        });
      }
    }
  }
  return { anomalies, locatedEvents };
}

function assessAuthenticationAnomalies(data: DuoMonitoringData, config: DuoResolvedConfig): DuoFinding {
  const attempts = data.authenticationAttempts;
  const edition = asString(asRecord(data.infoSummary.data).edition) ?? "unknown";
  if (!attempts || attempts.error) {
    return buildFinding(
      "DUO-MON-005",
      "Manual",
      "Authentication attempt statistics could not be collected.",
      unavailableEvidence(
        DUO_ENDPOINTS.authenticationAttempts,
        DUO_PERMISSIONS.readInformation,
        attempts?.error ?? `${DUO_ENDPOINTS.authenticationAttempts} was not collected.`,
        "Export the Authentication Summary report from the Duo Admin Panel for the review window.",
      ),
      "Grant the audit principal Grant read information so fraud, failure, and error counts can be reviewed.",
    );
  }
  if (data.authenticationLogs.error) {
    return buildFinding(
      "DUO-MON-005",
      "Manual",
      "Authentication logs could not be collected, so travel anomalies cannot be evaluated.",
      unavailableEvidence(
        DUO_ENDPOINTS.authenticationLogs,
        DUO_PERMISSIONS.readLog,
        data.authenticationLogs.error,
        "Export the Authentication Log with access device location for the review window.",
      ),
      "Grant the audit principal Grant read log so authentication events can be analyzed.",
    );
  }

  const counts = asRecord(asRecord(attempts.data).authentication_attempts);
  const fraud = asNumber(counts.FRAUD) ?? 0;
  const failure = asNumber(counts.FAILURE) ?? 0;
  const error = asNumber(counts.ERROR) ?? 0;
  const success = asNumber(counts.SUCCESS) ?? 0;
  const total = fraud + failure + error + success;
  const failureShare = percentage(failure + fraud, total);
  const { anomalies, locatedEvents } = detectImpossibleTravel(data.authenticationLogs.data);
  const evidence = [
    `lookback_days=${config.lookbackDays}`,
    `attempts_success=${success}`,
    `attempts_failure=${failure}`,
    `attempts_fraud=${fraud}`,
    `attempts_error=${error}`,
    `denied_share_percent=${failureShare}`,
    `auth_logs_sampled=${data.authenticationLogs.data.length}`,
    `auth_logs_with_location=${locatedEvents}`,
    `impossible_travel_pairs=${anomalies.length}`,
    ...anomalies.slice(0, 10).map((anomaly) =>
      `impossible_travel user=${anomaly.user} ${anomaly.fromCountry} -> ${anomaly.toCountry} within ${anomaly.minutesApart} minutes`,
    ),
  ];

  if (Object.keys(counts).length === 0) {
    return buildFinding(
      "DUO-MON-005",
      "Manual",
      "The authentication attempts report did not include the documented authentication_attempts counts.",
      evidence,
      "Review the Authentication Summary report in the Duo Admin Panel.",
    );
  }
  if (total === 0 && data.authenticationLogs.data.length === 0) {
    return buildFinding(
      "DUO-MON-005",
      "Partial",
      "No authentication attempts or events were recorded in the lookback window, so anomaly review has no data (Partial, not Pass).",
      evidence,
      "Confirm the lookback window covers real usage and that authentication telemetry is retained.",
    );
  }
  if (anomalies.length > 0) {
    return buildFinding(
      "DUO-MON-005",
      "Fail",
      `${anomalies.length} successful authentication pair(s) show a country change within ${IMPOSSIBLE_TRAVEL_WINDOW_MS / 60000} minutes.`,
      evidence,
      "Investigate the flagged users for credential compromise or shared accounts and enable User Location or Trust Monitor policies.",
    );
  }
  if (locatedEvents === 0) {
    return buildFinding(
      "DUO-MON-005",
      "Manual",
      `No authentication event exposed access_device.location, which the Admin API documents for Duo Premier and Duo Advantage plans (edition reported: ${edition}); travel analysis requires manual review.`,
      evidence,
      "Confirm the tenant edition, then review authentication locations in the Duo Admin Panel or upgrade to an edition with access device location.",
      { manualNote: "Fraud, failure, and error counts were collected; only geographic analysis is blocked by missing location data." },
    );
  }
  if (fraud > 0 || failureShare > 20) {
    return buildFinding(
      "DUO-MON-005",
      "Partial",
      fraud > 0
        ? `${fraud} authentication attempt(s) were reported as fraud in the lookback window.`
        : `${failureShare} percent of authentication attempts were denied in the lookback window.`,
      evidence,
      "Review fraud reports and denied authentications with the affected users and confirm follow-up in the incident workflow.",
    );
  }
  return buildFinding(
    "DUO-MON-005",
    "Pass",
    "No fraud reports, elevated denial rates, or impossible travel pairs were found in the lookback window.",
    evidence,
    "Keep reviewing authentication summaries and location changes as part of routine monitoring.",
  );
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

  findings.push(assessAuthenticationAnomalies(data, config));

  const settings = asRecord(data.settings.data);
  const notificationSignals = [
    getBooleanish(settings, "fraud_email_enabled"),
    getBooleanish(settings, "push_activity_notification_enabled"),
    getBooleanish(settings, "email_activity_notification_enabled"),
  ].filter((value): value is boolean => value !== undefined);
  if (data.settings.error || Object.keys(settings).length === 0) {
    findings.push(
      buildFinding(
        "DUO-MON-004",
        "Manual",
        "Notification settings could not be collected.",
        unavailableEvidence(
          DUO_ENDPOINTS.settings,
          DUO_PERMISSIONS.settings,
          data.settings.error,
          "Review Settings > Notifications in the Duo Admin Panel.",
        ),
        "Grant the audit principal Grant settings so fraud and activity notification toggles can be verified.",
      ),
    );
  } else if (notificationSignals.some(Boolean)) {
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
    `- ${finding.id} (${finding.status}/${finding.severity}) [${finding.frameworks[key].join(", ")}] ${finding.title}: ${finding.summary}`,
  );
  return [
    `# ${title}`,
    "",
    scoped.length > 0 ? rows.join("\n") : "No findings mapped to this framework in the exported bundle.",
    "",
  ].join("\n");
}

function buildExecutiveSummary(
  config: DuoResolvedConfig,
  assessments: DuoAssessmentResult[],
  errors: string[],
): string {
  const findings = assessments.flatMap((assessment) => assessment.findings);
  const summary = summarizeFindings(findings);
  const lines = [
    "# Duo Security Inspector Executive Summary",
    "",
    `- Tenant API host: ${config.apiHost}`,
    `- Generated: ${new Date().toISOString()}`,
    `- Log lookback window: ${config.lookbackDays} days`,
    `- Findings: ${findings.length} (Pass ${summary.Pass}, Partial ${summary.Partial}, Fail ${summary.Fail}, Manual ${summary.Manual}, Info ${summary.Info})`,
    `- Collection warnings: ${errors.length}${errors.length > 0 ? " (see _errors.log)" : ""}`,
    "",
    "## Category summaries",
    "",
    ...assessments.map((assessment) => {
      const counts = assessment.summary;
      return `- ${assessment.category}: Pass ${counts.Pass}, Partial ${counts.Partial}, Fail ${counts.Fail}, Manual ${counts.Manual}`;
    }),
    "",
    "## Findings requiring action",
    "",
  ];
  const actionable = findings.filter((finding) => finding.status === "Fail" || finding.status === "Partial");
  if (actionable.length === 0) {
    lines.push("No Fail or Partial findings were recorded.");
  } else {
    for (const finding of actionable) {
      lines.push(`- ${finding.id} (${finding.status}/${finding.severity}) ${finding.title}: ${finding.recommendation}`);
    }
  }
  lines.push("", "## Manual verification required", "");
  const manual = findings.filter((finding) => finding.status === "Manual");
  if (manual.length === 0) {
    lines.push("No findings require manual verification.");
  } else {
    for (const finding of manual) {
      lines.push(`- ${finding.id} ${finding.title}: ${finding.summary}`);
    }
  }
  lines.push("", "## Category detail", "");
  for (const assessment of assessments) {
    lines.push(`### ${assessment.category}`, "", "```", assessment.text, "```", "");
  }
  return lines.join("\n");
}

function buildQuickReference(): string {
  return [
    "# Duo Audit Bundle Quick Reference",
    "",
    "- `core_data/` contains raw Duo Admin API responses used during this assessment.",
    "- `analysis/` contains normalized findings and category summaries.",
    "- `compliance/` contains the executive summary, unified matrix, and per-framework reports.",
    "- `_errors.log` appears only when some reads fail but the bundle still completes.",
    "- Review Manual findings before asserting framework compliance from the automated output alone.",
    "",
    "Recommended reading order:",
    "1. `compliance/executive_summary.md`",
    "2. `compliance/unified_compliance_matrix.md`",
    "3. framework-specific report matching your engagement",
    "4. `analysis/*.json` for the supporting evidence behind each finding",
    "",
    "This bundle is read-only evidence and analysis output. It does not contain the Duo secret key or write-capable credentials.",
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
  const archive = new ZipArchive({ zlib: { level: 9 } });

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

const FRAMEWORK_REPORTS: Array<{ key: FrameworkKey; path: string; title: string }> = [
  { key: "fedramp", path: "compliance/fedramp/fedramp_compliance_report.md", title: "FedRAMP / NIST 800-53 Compliance Report" },
  { key: "cmmc", path: "compliance/cmmc/cmmc_compliance_report.md", title: "CMMC Compliance Report" },
  { key: "soc2", path: "compliance/soc2/soc2_compliance_report.md", title: "SOC 2 Compliance Report" },
  { key: "cis", path: "compliance/cis/cis_compliance_report.md", title: "CIS Controls Compliance Report" },
  { key: "pci_dss", path: "compliance/pci_dss/pci_dss_compliance_report.md", title: "PCI-DSS Compliance Report" },
  { key: "disa_stig", path: "compliance/disa_stig/stig_compliance_checklist.md", title: "DISA STIG Compliance Checklist" },
  { key: "irap", path: "compliance/irap/irap_compliance_report.md", title: "IRAP / ISM Compliance Report" },
  { key: "ismap", path: "compliance/ismap/ismap_compliance_report.md", title: "ISMAP Compliance Report" },
];

export type DuoBundleClient = DuoAuthenticationClient & DuoAdminAccessClient & DuoIntegrationClient & DuoMonitoringClient;

export async function exportDuoAuditBundle(
  client: DuoBundleClient,
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
  const errors = listErrors([
    authentication.settings,
    authentication.policies,
    authentication.globalPolicy,
    authentication.users,
    authentication.bypassCodes,
    authentication.webauthnCredentials,
    authentication.allowedAdminAuthMethods,
    authentication.authenticationLogs,
    authentication.offlineEnrollmentLogs,
    adminAccess.settings,
    adminAccess.admins,
    adminAccess.allowedAdminAuthMethods,
    adminAccess.activityLogs,
    integrations.settings,
    integrations.policies,
    integrations.globalPolicy,
    integrations.integrations,
    integrations.infoSummary,
    monitoring.settings,
    monitoring.infoSummary,
    monitoring.authenticationLogs,
    monitoring.activityLogs,
    monitoring.telephonyLogs,
    monitoring.trustMonitorEvents,
    monitoring.authenticationAttempts,
  ]);

  const timestamp = new Date().toISOString().replace(/[:]/g, "-");
  const folderRelative = ensureUniqueRelativePath(outputRoot, sanitizeSegment(`${config.apiHost}_${timestamp}`));
  const outputDir = resolveSecureOutputPath(outputRoot, folderRelative);
  mkdirSync(outputDir, { recursive: true });
  await chmod(outputDir, 0o755);

  await writeText(outputDir, "QUICK_REFERENCE.md", buildQuickReference());
  await writeJson(outputDir, "config.json", {
    api_host: config.apiHost,
    lookback_days: config.lookbackDays,
    source_chain: config.sourceChain,
  });

  const coreData: Array<[string, unknown]> = [
    ["core_data/settings.json", authentication.settings.data],
    ["core_data/policies.json", authentication.policies.data],
    ["core_data/global_policy.json", authentication.globalPolicy.data],
    ["core_data/users.json", authentication.users.data],
    ["core_data/bypass_codes.json", authentication.bypassCodes.data],
    ["core_data/webauthn_credentials.json", authentication.webauthnCredentials.data],
    ["core_data/admin_allowed_auth_methods.json", authentication.allowedAdminAuthMethods.data],
    ["core_data/authentication_logs.json", authentication.authenticationLogs.data],
    ["core_data/offline_enrollment_logs.json", authentication.offlineEnrollmentLogs?.data ?? []],
    ["core_data/admins.json", adminAccess.admins.data],
    ["core_data/activity_logs.json", adminAccess.activityLogs.data],
    ["core_data/integrations.json", integrations.integrations.data],
    ["core_data/info_summary.json", monitoring.infoSummary.data],
    ["core_data/telephony_logs.json", monitoring.telephonyLogs.data],
    ["core_data/trust_monitor_events.json", monitoring.trustMonitorEvents.data],
    ["core_data/authentication_attempts.json", monitoring.authenticationAttempts?.data ?? null],
  ];
  for (const [path, value] of coreData) {
    await writeJson(outputDir, path, value);
  }
  await writeJson(outputDir, "core_data/collection_status.json", {
    authentication,
    admin_access: adminAccess,
    integrations,
    monitoring,
  });

  for (const assessment of assessments) {
    await writeJson(outputDir, `analysis/${assessment.category}.json`, assessment);
  }
  await writeJson(outputDir, "analysis/findings.json", findings);

  await writeText(outputDir, "compliance/executive_summary.md", buildExecutiveSummary(config, assessments, errors));
  await writeText(outputDir, "compliance/unified_compliance_matrix.md", buildUnifiedMatrix(findings));
  for (const report of FRAMEWORK_REPORTS) {
    await writeText(outputDir, report.path, buildFrameworkReport(report.title, findings, report.key));
  }

  if (errors.length > 0) {
    await writeText(outputDir, "_errors.log", errors.join("\n"));
  }

  const zipRelative = ensureUniqueRelativePath(outputRoot, `${basename(outputDir)}.zip`);
  const zipPath = resolveSecureOutputPath(outputRoot, zipRelative);
  await zipDirectory(outputDir, zipPath);

  return {
    outputDir,
    zipPath,
    fileCount: await countFiles(outputDir),
    findingCount: findings.length,
    errorCount: errors.length,
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
