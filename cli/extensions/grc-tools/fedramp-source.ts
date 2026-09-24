import { existsSync } from "node:fs";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";

import { ensureGrclankerHome, getGrclankerHome, getGrclankerStateDir } from "../../config/paths.js";
import { persistentCachesEnabled } from "./shared.js";

const DAY_MS = 24 * 60 * 60 * 1000;
const SOURCE_STATUS_TTL_MS = 6 * 60 * 60 * 1000;
const FEDRAMP_CACHE_SCHEMA_VERSION = 2;
const GITHUB_API = "https://api.github.com";
const GITHUB_ORG = "FedRAMP";

export const FEDRAMP_RULES_SOURCE = {
  org: GITHUB_ORG,
  repo: "rules",
  branch: "main",
  path: "fedramp-consolidated-rules.json",
  repoUrl: "https://github.com/FedRAMP/rules",
  rawUrl:
    "https://raw.githubusercontent.com/FedRAMP/rules/main/fedramp-consolidated-rules.json",
};

export const FEDRAMP_MARKDOWN_SOURCE = {
  org: GITHUB_ORG,
  repo: "2026-markdown",
  branch: "main",
  repoUrl: "https://github.com/FedRAMP/2026-markdown",
};

/** @deprecated Use FEDRAMP_RULES_SOURCE. */
export const FEDRAMP_DOCS_SOURCE = FEDRAMP_RULES_SOURCE;

export type FedrampApplicability = "20x" | "rev5" | "both";
export type FedrampCertificationClass = "A" | "B" | "C" | "D";
export type FedrampCacheStatus = "live" | "cached" | "stale";
export type FedrampSearchSection = "definition" | "process" | "requirement" | "ksi" | "any";

export interface FedrampUpdatedNote {
  date: string;
  comment: string;
}

export interface FedrampCatalogInfo {
  title: string;
  description: string;
  version: string;
  lastUpdated: string;
}

export interface FedrampDefinitionRecord {
  id: string;
  fka: string | null;
  term: string;
  alts: string[];
  definition: string;
  updated: FedrampUpdatedNote[];
  appliesTo: FedrampApplicability;
}

export interface FedrampProcessEffectiveWindow {
  is: string | null;
  signupUrl: string | null;
  currentStatus: string | null;
  startDate: string | null;
  endDate: string | null;
  comments: string[];
  warnings: string[];
  optionalAdoptionDate: string | null;
  graceDate: string | null;
  graceUntilNextAssessment: boolean | null;
}

export interface FedrampProcessLabelRecord {
  code: string;
  name: string;
  description: string;
  types: string[];
  paths: string[];
  classes: string[];
  affects: string[];
}

export interface FedrampAuthorityRecord {
  reference: string | null;
  referenceUrl: string | null;
  description: string | null;
  delegation: string | null;
  delegationUrl: string | null;
}

export interface FedrampProcessRecord {
  id: string;
  name: string;
  shortName: string;
  webName: string;
  sourceUrl: string | null;
  applicability: FedrampApplicability[];
  effective: Record<FedrampApplicability, FedrampProcessEffectiveWindow | undefined>;
  purpose: string | null;
  expectedOutcomes: string[];
  authority: FedrampAuthorityRecord[];
  labels: FedrampProcessLabelRecord[];
  status: string | null;
  tag: string | null;
  requirementIds: string[];
}

export interface FedrampClassVariantRecord {
  class: FedrampCertificationClass;
  statement: string;
  primaryKeyWord: string | null;
  followingInformation: string[];
  note: string | null;
  timeframeType: string | null;
  timeframeNum: number | null;
}

export interface FedrampRequirementRecord {
  id: string;
  fka: string | null;
  processId: string;
  processName: string;
  processShortName: string;
  processWebName: string;
  processSourceUrl: string | null;
  appliesTo: FedrampApplicability;
  labelCode: string;
  labelName: string;
  labelDescription: string;
  name: string | null;
  statement: string;
  primaryKeyWord: string | null;
  affects: string[];
  terms: string[];
  followingInformation: string[];
  note: string | null;
  timeframeType: string | null;
  timeframeNum: number | null;
  updated: FedrampUpdatedNote[];
  classVariants: FedrampClassVariantRecord[];
}

export interface FedrampKsiDomainRecord {
  id: string;
  code: string;
  name: string;
  shortName: string;
  webName: string;
  theme: string;
  status: string | null;
  appliesTo: "20x";
  indicatorIds: string[];
}

export interface FedrampKsiIndicatorRecord {
  id: string;
  fka: string | null;
  domainId: string;
  domainCode: string;
  domainName: string;
  domainShortName: string;
  domainWebName: string;
  name: string;
  statement: string;
  reference: string | null;
  referenceUrl: string | null;
  controls: string[];
  terms: string[];
  updated: FedrampUpdatedNote[];
  appliesTo: "20x";
  classVariants: FedrampClassVariantRecord[];
}

export interface FedrampCatalog {
  info: FedrampCatalogInfo;
  definitions: FedrampDefinitionRecord[];
  processes: FedrampProcessRecord[];
  requirements: FedrampRequirementRecord[];
  ksiDomains: FedrampKsiDomainRecord[];
  ksiIndicators: FedrampKsiIndicatorRecord[];
}

export interface FedrampPrimarySourceStatus {
  org: string;
  repo: string;
  branch: string;
  repoUrl: string;
  path: string;
  rawUrl: string;
  blobSha: string | null;
  fileHtmlUrl: string | null;
  repoUpdatedAt: string | null;
  version: string;
  upstreamLastUpdated: string;
}

export interface FedrampSupportingSourceStatus {
  org: string;
  repo: string;
  branch: string;
  repoUrl: string;
  repoUpdatedAt: string | null;
  state: "placeholder" | "ready" | "unavailable";
  rootEntries: string[];
  notes: string[];
}

/** @deprecated Use FedrampSupportingSourceStatus. */
export type FedrampRulesSourceStatus = FedrampSupportingSourceStatus;

export interface FedrampLoadedCatalog {
  catalog: FedrampCatalog;
  provenance: FedrampPrimarySourceStatus;
  cacheStatus: FedrampCacheStatus;
  fetchedAt: string;
  notes: string[];
}

export interface FedrampSourceStatus {
  primary: FedrampPrimarySourceStatus;
  secondary: FedrampRulesSourceStatus;
  cacheStatus: FedrampCacheStatus;
  fetchedAt: string;
  notes: string[];
}

export interface FedrampSearchMatch {
  section: Exclude<FedrampSearchSection, "any">;
  id: string;
  title: string;
  summary: string;
  appliesTo: FedrampApplicability;
  score: number;
}

type SourceCachePayload = {
  schemaVersion: number;
  fetchedAt: string;
  primary: FedrampPrimarySourceStatus;
  secondary: FedrampSupportingSourceStatus;
};

type CatalogCachePayload = {
  schemaVersion: number;
  fetchedAt: string;
  catalog: FedrampCatalog;
  provenance: FedrampPrimarySourceStatus;
};

type RepoOverviewResponse = {
  html_url?: string;
  updated_at?: string;
  default_branch?: string;
};

type GitHubContentFileResponse = {
  sha?: string;
  html_url?: string;
  download_url?: string;
};

type GitHubContentEntry = {
  name?: string;
  type?: string;
};

let catalogMemoryCache:
  | { key: string; expires: number; value: FedrampLoadedCatalog }
  | undefined;
let sourceMemoryCache:
  | { key: string; expires: number; value: FedrampSourceStatus }
  | undefined;

function asString(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : null;
}

function asStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value
    .map((entry) => asString(entry))
    .filter((entry): entry is string => Boolean(entry));
}

function asUpdatedNotes(value: unknown): FedrampUpdatedNote[] {
  if (!Array.isArray(value)) return [];
  return value
    .map((entry) => {
      if (!entry || typeof entry !== "object") return null;
      const item = entry as Record<string, unknown>;
      const date = asString(item.date);
      const comment = asString(item.comment);
      if (!date || !comment) return null;
      return { date, comment };
    })
    .filter((entry): entry is FedrampUpdatedNote => Boolean(entry));
}

function truncate(text: string, length = 140): string {
  if (text.length <= length) return text;
  return `${text.slice(0, length - 3)}...`;
}

function normalizeSearchSection(value: string | null | undefined): FedrampSearchSection {
  const normalized = value?.trim().toLowerCase();
  if (
    normalized === "definition" ||
    normalized === "process" ||
    normalized === "requirement" ||
    normalized === "ksi"
  ) {
    return normalized;
  }
  return "any";
}

function normalizeApplicability(value: string | null | undefined): FedrampApplicability | "any" {
  const normalized = value?.trim().toLowerCase();
  if (normalized === "20x" || normalized === "rev5" || normalized === "both") {
    return normalized;
  }
  return "any";
}

function fedrampStateDir(homeDir = getGrclankerHome()): string {
  return resolve(getGrclankerStateDir(homeDir), "fedramp");
}

function catalogCachePath(homeDir = getGrclankerHome()): string {
  return resolve(fedrampStateDir(homeDir), "catalog.json");
}

function sourcesCachePath(homeDir = getGrclankerHome()): string {
  return resolve(fedrampStateDir(homeDir), "sources.json");
}

/**
 * Create the FedRAMP state directory unless the caller disabled persistent
 * caches; reads tolerate a missing directory, so skipping it is safe.
 */
async function ensureFedrampStateDir(homeDir = getGrclankerHome()): Promise<void> {
  if (!persistentCachesEnabled()) return;
  ensureGrclankerHome(homeDir);
  await mkdir(fedrampStateDir(homeDir), { recursive: true });
}

async function readJsonFile<T>(path: string): Promise<T | undefined> {
  if (!existsSync(path)) return undefined;
  const raw = await readFile(path, "utf8");
  return JSON.parse(raw) as T;
}

/** Persist a cache payload unless the caller disabled persistent caches. */
async function writeCacheFile(path: string, value: unknown): Promise<void> {
  if (!persistentCachesEnabled()) return;
  await writeFile(path, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

function githubHeaders() {
  return {
    Accept: "application/vnd.github+json",
    "User-Agent": "grclanker-fedramp-sync",
  };
}

async function fetchJson<T>(url: string): Promise<T> {
  const response = await fetch(url, { headers: githubHeaders() });
  if (!response.ok) {
    throw new Error(`Fetch failed: ${url} (${response.status} ${response.statusText})`);
  }
  return (await response.json()) as T;
}

async function fetchPrimarySourceMetadata(): Promise<{
  repo: RepoOverviewResponse;
  file: GitHubContentFileResponse;
}> {
  const [repo, file] = await Promise.all([
    fetchJson<RepoOverviewResponse>(
      `${GITHUB_API}/repos/${FEDRAMP_RULES_SOURCE.org}/${FEDRAMP_RULES_SOURCE.repo}`,
    ),
    fetchJson<GitHubContentFileResponse>(
      `${GITHUB_API}/repos/${FEDRAMP_RULES_SOURCE.org}/${FEDRAMP_RULES_SOURCE.repo}/contents/${FEDRAMP_RULES_SOURCE.path}?ref=${FEDRAMP_RULES_SOURCE.branch}`,
    ),
  ]);

  return { repo, file };
}

async function fetchSupportingSourceMetadata(): Promise<FedrampSupportingSourceStatus> {
  try {
    const [repo, contents] = await Promise.all([
      fetchJson<RepoOverviewResponse>(
        `${GITHUB_API}/repos/${FEDRAMP_MARKDOWN_SOURCE.org}/${FEDRAMP_MARKDOWN_SOURCE.repo}`,
      ),
      fetchJson<GitHubContentEntry[]>(
        `${GITHUB_API}/repos/${FEDRAMP_MARKDOWN_SOURCE.org}/${FEDRAMP_MARKDOWN_SOURCE.repo}/contents/?ref=${FEDRAMP_MARKDOWN_SOURCE.branch}`,
      ),
    ]);

    const rootEntries = contents
      .map((entry) => asString(entry.name))
      .filter((entry): entry is string => Boolean(entry))
      .sort((left, right) => left.localeCompare(right));
    const isReady =
      rootEntries.includes("_sources.json") ||
      rootEntries.some((entry) => entry.endsWith(".md") && entry !== "README.md");

    return {
      org: FEDRAMP_MARKDOWN_SOURCE.org,
      repo: FEDRAMP_MARKDOWN_SOURCE.repo,
      branch: repo.default_branch ?? FEDRAMP_MARKDOWN_SOURCE.branch,
      repoUrl: repo.html_url ?? FEDRAMP_MARKDOWN_SOURCE.repoUrl,
      repoUpdatedAt: asString(repo.updated_at),
      state: isReady ? "ready" : "placeholder",
      rootEntries,
      notes: isReady
        ? []
        : [
            "The official FedRAMP/2026-markdown repo exists, but no generated narrative content was found.",
          ],
    };
  } catch (error) {
    return {
      org: FEDRAMP_MARKDOWN_SOURCE.org,
      repo: FEDRAMP_MARKDOWN_SOURCE.repo,
      branch: FEDRAMP_MARKDOWN_SOURCE.branch,
      repoUrl: FEDRAMP_MARKDOWN_SOURCE.repoUrl,
      repoUpdatedAt: null,
      state: "unavailable",
      rootEntries: [],
      notes: [
        `Unable to inspect FedRAMP/2026-markdown: ${error instanceof Error ? error.message : String(error)}`,
      ],
    };
  }
}

async function fetchPrimarySourceCatalog(): Promise<{
  catalog: FedrampCatalog;
  provenance: FedrampPrimarySourceStatus;
}> {
  const emptyRepoMetadata: RepoOverviewResponse = {};
  const emptyFileMetadata: GitHubContentFileResponse = {};
  const [rawCatalog, metadata] = await Promise.all([
    fetchJson<Record<string, unknown>>(FEDRAMP_RULES_SOURCE.rawUrl),
    fetchPrimarySourceMetadata().catch(() => ({ repo: emptyRepoMetadata, file: emptyFileMetadata })),
  ]);

  const catalog = normalizeFedrampConsolidatedRules(rawCatalog);

  const provenance: FedrampPrimarySourceStatus = {
    org: FEDRAMP_RULES_SOURCE.org,
    repo: FEDRAMP_RULES_SOURCE.repo,
    branch:
      asString(metadata.repo.default_branch) ??
      FEDRAMP_RULES_SOURCE.branch,
    repoUrl:
      asString(metadata.repo.html_url) ??
      FEDRAMP_RULES_SOURCE.repoUrl,
    path: FEDRAMP_RULES_SOURCE.path,
    rawUrl: FEDRAMP_RULES_SOURCE.rawUrl,
    blobSha: asString(metadata.file.sha),
    fileHtmlUrl: asString(metadata.file.html_url),
    repoUpdatedAt: asString(metadata.repo.updated_at),
    version: catalog.info.version,
    upstreamLastUpdated: catalog.info.lastUpdated,
  };

  return { catalog, provenance };
}

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

function asFiniteNumber(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function asBoolean(value: unknown): boolean | null {
  return typeof value === "boolean" ? value : null;
}

function uniqueStrings(values: string[]): string[] {
  return Array.from(new Set(values));
}

function combinedNote(record: Record<string, unknown>): string | null {
  const notes = [asString(record.note), ...asStringArray(record.notes)].filter(
    (value): value is string => Boolean(value),
  );
  return notes.length > 0 ? notes.join("\n") : null;
}

function sourceApplicability(value: string): FedrampApplicability | undefined {
  const normalized = value.toLowerCase();
  if (normalized === "all" || normalized === "both") return "both";
  if (normalized === "20x" || normalized === "rev5") return normalized;
  return undefined;
}

function effectiveWindow(value: unknown): FedrampProcessEffectiveWindow | undefined {
  const record = asRecord(value);
  if (Object.keys(record).length === 0) return undefined;
  const dates = asRecord(record.date);
  const grace = asRecord(dates.grace);
  return {
    is: asString(record.is),
    signupUrl: asString(record.signup_url),
    currentStatus: asString(record.current_status),
    startDate: asString(record.start_date) ?? asString(dates.obtain),
    endDate: asString(record.end_date) ?? asString(dates.maintain),
    comments: asStringArray(record.comments),
    warnings: asStringArray(record.warnings),
    optionalAdoptionDate: asString(dates.optional_adoption),
    graceDate: asString(grace.default),
    graceUntilNextAssessment: asBoolean(grace.until_next_assessment),
  };
}

function normalizeClassVariants(value: unknown): FedrampClassVariantRecord[] {
  const record = asRecord(value);
  const variants: FedrampClassVariantRecord[] = [];
  for (const key of ["a", "b", "c", "d"] as const) {
    const item = asRecord(record[key]);
    const statement = asString(item.statement);
    if (!statement) continue;
    variants.push({
      class: key.toUpperCase() as FedrampCertificationClass,
      statement,
      primaryKeyWord: asString(item.force),
      followingInformation: asStringArray(item.following_information),
      note: combinedNote(item),
      timeframeType: asString(item.timeframe_type),
      timeframeNum: asFiniteNumber(item.timeframe_num),
    });
  }
  return variants;
}

function aggregateStatement(
  record: Record<string, unknown>,
  variants: FedrampClassVariantRecord[],
): string {
  return (
    asString(record.statement) ??
    variants.map((variant) => `Class ${variant.class}: ${variant.statement}`).join("\n")
  );
}

function aggregateKeyword(
  record: Record<string, unknown>,
  variants: FedrampClassVariantRecord[],
): string | null {
  const direct = asString(record.force) ?? asString(record.primary_key_word);
  if (direct) return direct;
  const keywords = uniqueStrings(
    variants
      .map((variant) => variant.primaryKeyWord)
      .filter((value): value is string => Boolean(value)),
  );
  if (keywords.length === 1) return keywords[0]!;
  return keywords.length > 1 ? "VARIES BY CLASS" : null;
}

function aggregateFollowingInformation(
  record: Record<string, unknown>,
  variants: FedrampClassVariantRecord[],
): string[] {
  return uniqueStrings([
    ...asStringArray(record.following_information),
    ...asStringArray(record.following_information_bullets),
    ...variants.flatMap((variant) =>
      variant.followingInformation.map((item) => `Class ${variant.class}: ${item}`),
    ),
  ]);
}

function commonVariantString(
  variants: FedrampClassVariantRecord[],
  select: (variant: FedrampClassVariantRecord) => string | null,
): string | null {
  const values = uniqueStrings(
    variants.map(select).filter((value): value is string => Boolean(value)),
  );
  return values.length === 1 ? values[0]! : null;
}

function commonVariantNumber(
  variants: FedrampClassVariantRecord[],
  select: (variant: FedrampClassVariantRecord) => number | null,
): number | null {
  const values = Array.from(
    new Set(variants.map(select).filter((value): value is number => value !== null)),
  );
  return values.length === 1 ? values[0]! : null;
}

function collectProcessLabels(
  info: Record<string, unknown>,
  legacyLabels: unknown,
): FedrampProcessLabelRecord[] {
  const labels = new Map<string, FedrampProcessLabelRecord>();

  const addLabels = (value: unknown) => {
    for (const [code, rawLabel] of Object.entries(asRecord(value))) {
      const item = asRecord(rawLabel);
      const applicability = asRecord(item.applicability);
      const previous = labels.get(code);
      labels.set(code, {
        code,
        name: asString(item.name) ?? previous?.name ?? code,
        description: asString(item.description) ?? previous?.description ?? "",
        types: uniqueStrings([...(previous?.types ?? []), ...asStringArray(applicability.types)]),
        paths: uniqueStrings([...(previous?.paths ?? []), ...asStringArray(applicability.paths)]),
        classes: uniqueStrings([
          ...(previous?.classes ?? []),
          ...asStringArray(applicability.classes),
        ]),
        affects: uniqueStrings([
          ...(previous?.affects ?? []),
          ...asStringArray(applicability.affects),
        ]),
      });
    }
  };

  addLabels(legacyLabels);
  addLabels(info.subsets);
  addLabels(asRecord(info["20x"]).subsets);
  addLabels(asRecord(info.rev5).subsets);

  return Array.from(labels.values()).sort((left, right) => left.code.localeCompare(right.code));
}

export function normalizeFedrampConsolidatedRules(
  raw: Record<string, unknown>,
): FedrampCatalog {
  const infoRecord = (raw.info ?? {}) as Record<string, unknown>;
  const info: FedrampCatalogInfo = {
    title: asString(infoRecord.title) ?? "FedRAMP Consolidated Rules",
    description:
      asString(infoRecord.description) ??
      "Machine-readable FedRAMP requirements, recommendations, definitions, and key security indicators.",
    version: asString(infoRecord.version) ?? "unknown",
    lastUpdated: asString(infoRecord.last_updated) ?? "unknown",
  };

  const definitions: FedrampDefinitionRecord[] = [];
  const definitionData = (((raw.FRD ?? {}) as Record<string, unknown>).data ?? {}) as Record<
    string,
    unknown
  >;
  for (const [bucketName, rawBucket] of Object.entries(definitionData)) {
    const appliesTo = sourceApplicability(bucketName);
    if (!appliesTo) continue;
    for (const [id, entry] of Object.entries(asRecord(rawBucket))) {
      const item = asRecord(entry);
      if (Object.keys(item).length === 0) continue;
      definitions.push({
        id,
        fka: asString(item.fka),
        term: asString(item.term) ?? id,
        alts: asStringArray(item.alts),
        definition: asString(item.definition) ?? "",
        updated: asUpdatedNotes(item.updated),
        appliesTo,
      });
    }
  }

  const processes: FedrampProcessRecord[] = [];
  const requirements: FedrampRequirementRecord[] = [];
  const rawProcesses = (raw.FRR ?? {}) as Record<string, unknown>;

  for (const [processId, entry] of Object.entries(rawProcesses)) {
    if (!entry || typeof entry !== "object") continue;
    const record = entry as Record<string, unknown>;
    const infoRecord = (record.info ?? {}) as Record<string, unknown>;
    const frontMatter = (record.front_matter ?? {}) as Record<string, unknown>;
    const dataRecord = (record.data ?? {}) as Record<string, unknown>;
    const labels = collectProcessLabels(infoRecord, record.labels);

    const requirementIds: string[] = [];
    const applicabilityKeys = uniqueStrings(
      Object.keys(dataRecord)
        .filter((key) => Object.keys(asRecord(dataRecord[key])).length > 0)
        .map((key) => sourceApplicability(key))
        .filter((value): value is FedrampApplicability => Boolean(value)),
    ) as FedrampApplicability[];
    const webName = asString(infoRecord.web_name) ?? processId.toLowerCase();
    const sourceUrl = `https://www.fedramp.gov/2026/reference/${webName}/`;

    for (const [bucketName, rawBucket] of Object.entries(dataRecord)) {
      const appliesTo = sourceApplicability(bucketName);
      if (!appliesTo) continue;
      const applicabilityBucket = asRecord(rawBucket);
      for (const [labelCode, rawLabelBucket] of Object.entries(applicabilityBucket)) {
        const labelBucket = asRecord(rawLabelBucket);
        if (Object.keys(labelBucket).length === 0) continue;
        const labelMeta = labels.find((label) => label.code === labelCode) ?? {
          code: labelCode,
          name: labelCode,
          description: "",
          types: [],
          paths: [],
          classes: [],
          affects: [],
        };

        for (const [requirementId, rawRequirement] of Object.entries(labelBucket)) {
          const requirement = asRecord(rawRequirement);
          if (Object.keys(requirement).length === 0) continue;
          const classVariants = normalizeClassVariants(requirement.varies_by_class);
          const directNote = combinedNote(requirement);
          requirementIds.push(requirementId);
          requirements.push({
            id: requirementId,
            fka: asString(requirement.fka),
            processId,
            processName: asString(infoRecord.name) ?? processId,
            processShortName: asString(infoRecord.short_name) ?? processId,
            processWebName: webName,
            processSourceUrl: sourceUrl,
            appliesTo,
            labelCode: labelMeta.code,
            labelName: labelMeta.name,
            labelDescription: labelMeta.description,
            name: asString(requirement.name),
            statement: aggregateStatement(requirement, classVariants),
            primaryKeyWord: aggregateKeyword(requirement, classVariants),
            affects: asStringArray(requirement.affects),
            terms: asStringArray(requirement.terms),
            followingInformation: aggregateFollowingInformation(requirement, classVariants),
            note: directNote ?? commonVariantString(classVariants, (variant) => variant.note),
            timeframeType:
              asString(requirement.timeframe_type) ??
              commonVariantString(classVariants, (variant) => variant.timeframeType),
            timeframeNum:
              asFiniteNumber(requirement.timeframe_num) ??
              commonVariantNumber(classVariants, (variant) => variant.timeframeNum),
            updated: asUpdatedNotes(requirement.updated),
            classVariants,
          });
        }
      }
    }

    const commonEffectiveRecord = asRecord(infoRecord.effective);
    const commonEffective = Object.prototype.hasOwnProperty.call(commonEffectiveRecord, "is")
      ? effectiveWindow(commonEffectiveRecord)
      : undefined;
    const legacy20xEffective = effectiveWindow(commonEffectiveRecord["20x"]);
    const legacyRev5Effective = effectiveWindow(commonEffectiveRecord.rev5);
    const typed20xEffective = effectiveWindow(asRecord(infoRecord["20x"]).effective);
    const typedRev5Effective = effectiveWindow(asRecord(infoRecord.rev5).effective);

    processes.push({
      id: processId,
      name: asString(infoRecord.name) ?? processId,
      shortName: asString(infoRecord.short_name) ?? processId,
      webName: asString(infoRecord.web_name) ?? processId.toLowerCase(),
      sourceUrl,
      applicability: applicabilityKeys,
      effective: {
        both: commonEffective,
        "20x": typed20xEffective ?? legacy20xEffective ?? commonEffective,
        rev5: typedRev5Effective ?? legacyRev5Effective ?? commonEffective,
      },
      purpose: asString(infoRecord.purpose) ?? asString(frontMatter.purpose),
      expectedOutcomes: asStringArray(frontMatter.expected_outcomes),
      authority: Array.isArray(frontMatter.authority)
        ? frontMatter.authority
            .map((authority) => {
              if (!authority || typeof authority !== "object") return null;
              const item = authority as Record<string, unknown>;
              return {
                reference: asString(item.reference),
                referenceUrl: asString(item.reference_url),
                description: asString(item.description),
                delegation: asString(item.delegation),
                delegationUrl: asString(item.delegation_url),
              };
            })
            .filter((value): value is FedrampAuthorityRecord => Boolean(value))
        : [],
      labels,
      status: asString(infoRecord.status),
      tag: asString(infoRecord.tag),
      requirementIds: Array.from(new Set(requirementIds)).sort((left, right) => left.localeCompare(right)),
    });
  }

  const ksiDomains: FedrampKsiDomainRecord[] = [];
  const ksiIndicators: FedrampKsiIndicatorRecord[] = [];
  const rawKsi = (raw.KSI ?? {}) as Record<string, unknown>;

  for (const [domainCode, entry] of Object.entries(rawKsi)) {
    if (!entry || typeof entry !== "object") continue;
    const domain = entry as Record<string, unknown>;
    const domainId = asString(domain.id) ?? `KSI-${domainCode}`;
    const domainName = asString(domain.name) ?? domainCode;
    const shortName = asString(domain.short_name) ?? domainCode;
    const webName = asString(domain.web_name) ?? domainCode.toLowerCase();
    const indicatorIds: string[] = [];
    const indicatorsRecord = (domain.indicators ?? {}) as Record<string, unknown>;

    for (const [indicatorId, rawIndicator] of Object.entries(indicatorsRecord)) {
      if (!rawIndicator || typeof rawIndicator !== "object") continue;
      const indicator = rawIndicator as Record<string, unknown>;
      const classVariants = normalizeClassVariants(indicator.varies_by_class);
      indicatorIds.push(indicatorId);
      ksiIndicators.push({
        id: indicatorId,
        fka: asString(indicator.fka),
        domainId,
        domainCode,
        domainName,
        domainShortName: shortName,
        domainWebName: webName,
        name: asString(indicator.name) ?? indicatorId,
        statement: aggregateStatement(indicator, classVariants),
        reference: asString(indicator.reference),
        referenceUrl: asString(indicator.reference_url),
        controls: asStringArray(indicator.controls),
        terms: asStringArray(indicator.terms),
        updated: asUpdatedNotes(indicator.updated),
        appliesTo: "20x",
        classVariants,
      });
    }

    ksiDomains.push({
      id: domainId,
      code: domainCode,
      name: domainName,
      shortName,
      webName,
      theme: asString(domain.theme) ?? "",
      status: asString(domain.status),
      appliesTo: "20x",
      indicatorIds,
    });
  }

  definitions.sort((left, right) => left.id.localeCompare(right.id));
  processes.sort((left, right) => left.id.localeCompare(right.id));
  requirements.sort((left, right) => left.id.localeCompare(right.id));
  ksiDomains.sort((left, right) => left.id.localeCompare(right.id));
  ksiIndicators.sort((left, right) => left.id.localeCompare(right.id));

  return {
    info,
    definitions,
    processes,
    requirements,
    ksiDomains,
    ksiIndicators,
  };
}

/** @deprecated Use normalizeFedrampConsolidatedRules. */
export const normalizeFedrampFrmr = normalizeFedrampConsolidatedRules;

export async function loadFedrampCatalog(options?: {
  refresh?: boolean;
  homeDir?: string;
  ttlMs?: number;
}): Promise<FedrampLoadedCatalog> {
  const homeDir = options?.homeDir ?? getGrclankerHome();
  const ttlMs = options?.ttlMs ?? DAY_MS;
  const cacheKey = resolve(homeDir);

  if (
    !options?.refresh &&
    catalogMemoryCache &&
    catalogMemoryCache.key === cacheKey &&
    Date.now() < catalogMemoryCache.expires
  ) {
    return { ...catalogMemoryCache.value, cacheStatus: "cached" };
  }

  await ensureFedrampStateDir(homeDir);
  const cachePath = catalogCachePath(homeDir);
  const cachedPayload = await readJsonFile<CatalogCachePayload>(cachePath);
  const cached =
    cachedPayload?.schemaVersion === FEDRAMP_CACHE_SCHEMA_VERSION &&
    cachedPayload.provenance.rawUrl === FEDRAMP_RULES_SOURCE.rawUrl
      ? cachedPayload
      : undefined;
  const cachedAge = cached ? Date.now() - Date.parse(cached.fetchedAt) : Number.POSITIVE_INFINITY;

  if (!options?.refresh && cached && Number.isFinite(cachedAge) && cachedAge < ttlMs) {
    const value: FedrampLoadedCatalog = {
      catalog: cached.catalog,
      provenance: cached.provenance,
      cacheStatus: "cached",
      fetchedAt: cached.fetchedAt,
      notes: [],
    };
    catalogMemoryCache = {
      key: cacheKey,
      expires: Date.now() + ttlMs,
      value,
    };
    return value;
  }

  try {
    const live = await fetchPrimarySourceCatalog();
    const fetchedAt = new Date().toISOString();
    const payload: CatalogCachePayload = {
      schemaVersion: FEDRAMP_CACHE_SCHEMA_VERSION,
      fetchedAt,
      catalog: live.catalog,
      provenance: live.provenance,
    };
    await writeCacheFile(cachePath, payload);
    const value: FedrampLoadedCatalog = {
      catalog: live.catalog,
      provenance: live.provenance,
      cacheStatus: "live",
      fetchedAt,
      notes: [],
    };
    catalogMemoryCache = {
      key: cacheKey,
      expires: Date.now() + ttlMs,
      value,
    };
    return value;
  } catch (error) {
    if (cached) {
      const staleValue: FedrampLoadedCatalog = {
        catalog: cached.catalog,
        provenance: cached.provenance,
        cacheStatus: "stale",
        fetchedAt: cached.fetchedAt,
        notes: [
          `Serving stale FedRAMP cache because the live GitHub source could not be refreshed: ${error instanceof Error ? error.message : String(error)}`,
        ],
      };
      catalogMemoryCache = {
        key: cacheKey,
        expires: Date.now() + Math.min(ttlMs, DAY_MS),
        value: staleValue,
      };
      return staleValue;
    }
    throw error;
  }
}

export async function inspectFedrampOfficialSources(options?: {
  refresh?: boolean;
  homeDir?: string;
}): Promise<FedrampSourceStatus> {
  const homeDir = options?.homeDir ?? getGrclankerHome();
  const cacheKey = resolve(homeDir);

  if (
    !options?.refresh &&
    sourceMemoryCache &&
    sourceMemoryCache.key === cacheKey &&
    Date.now() < sourceMemoryCache.expires
  ) {
    return { ...sourceMemoryCache.value, cacheStatus: "cached" };
  }

  await ensureFedrampStateDir(homeDir);
  const cachePath = sourcesCachePath(homeDir);
  const cachedPayload = await readJsonFile<SourceCachePayload>(cachePath);
  const cached =
    cachedPayload?.schemaVersion === FEDRAMP_CACHE_SCHEMA_VERSION &&
    cachedPayload.primary.rawUrl === FEDRAMP_RULES_SOURCE.rawUrl
      ? cachedPayload
      : undefined;
  const cachedAge = cached ? Date.now() - Date.parse(cached.fetchedAt) : Number.POSITIVE_INFINITY;

  if (!options?.refresh && cached && Number.isFinite(cachedAge) && cachedAge < SOURCE_STATUS_TTL_MS) {
    const value: FedrampSourceStatus = {
      primary: cached.primary,
      secondary: cached.secondary,
      cacheStatus: "cached",
      fetchedAt: cached.fetchedAt,
      notes: [...cached.secondary.notes],
    };
    sourceMemoryCache = {
      key: cacheKey,
      expires: Date.now() + SOURCE_STATUS_TTL_MS,
      value,
    };
    return value;
  }

  try {
    const [catalog, secondary] = await Promise.all([
      loadFedrampCatalog({ refresh: options?.refresh, homeDir }),
      fetchSupportingSourceMetadata(),
    ]);
    const fetchedAt = new Date().toISOString();
    const payload: SourceCachePayload = {
      schemaVersion: FEDRAMP_CACHE_SCHEMA_VERSION,
      fetchedAt,
      primary: catalog.provenance,
      secondary,
    };
    await writeCacheFile(cachePath, payload);
    const value: FedrampSourceStatus = {
      primary: catalog.provenance,
      secondary,
      cacheStatus: catalog.cacheStatus === "stale" ? "stale" : "live",
      fetchedAt,
      notes: [...catalog.notes, ...secondary.notes],
    };
    sourceMemoryCache = {
      key: cacheKey,
      expires: Date.now() + SOURCE_STATUS_TTL_MS,
      value,
    };
    return value;
  } catch (error) {
    if (cached) {
      const value: FedrampSourceStatus = {
        primary: cached.primary,
        secondary: cached.secondary,
        cacheStatus: "stale",
        fetchedAt: cached.fetchedAt,
        notes: [
          `Serving stale FedRAMP source metadata because the live GitHub source check failed: ${error instanceof Error ? error.message : String(error)}`,
          ...cached.secondary.notes,
        ],
      };
      sourceMemoryCache = {
        key: cacheKey,
        expires: Date.now() + SOURCE_STATUS_TTL_MS,
        value,
      };
      return value;
    }
    throw error;
  }
}

function matchScore(haystacks: string[], query: string): number {
  const normalizedQuery = query.trim().toLowerCase();
  if (!normalizedQuery) return 0;
  let score = 0;
  for (const value of haystacks) {
    const normalized = value.trim().toLowerCase();
    if (!normalized) continue;
    if (normalized === normalizedQuery) score = Math.max(score, 120);
    else if (normalized.startsWith(normalizedQuery)) score = Math.max(score, 95);
    else if (normalized.includes(normalizedQuery)) score = Math.max(score, 70);
    else {
      const tokens = normalizedQuery.split(/\s+/).filter(Boolean);
      if (tokens.length > 1 && tokens.every((token) => normalized.includes(token))) {
        score = Math.max(score, 55);
      }
    }
  }
  return score;
}

function matchesApplicability(
  recordApplicability: FedrampApplicability,
  filter: FedrampApplicability | "any",
): boolean {
  if (filter === "any") return true;
  if (recordApplicability === filter) return true;
  return (filter === "20x" || filter === "rev5") && recordApplicability === "both";
}

export function searchFedrampCatalog(
  catalog: FedrampCatalog,
  query: string,
  options?: {
    section?: FedrampSearchSection;
    appliesTo?: FedrampApplicability | "any";
    limit?: number;
  },
): FedrampSearchMatch[] {
  const normalizedQuery = query.trim();
  if (!normalizedQuery) return [];
  const section = options?.section ?? "any";
  const appliesTo = options?.appliesTo ?? "any";
  const limit = Math.max(1, Math.min(Math.trunc(options?.limit ?? 10), 50));
  const matches: FedrampSearchMatch[] = [];

  if (section === "any" || section === "definition") {
    for (const definition of catalog.definitions) {
      if (!matchesApplicability(definition.appliesTo, appliesTo)) continue;
      const score = matchScore(
        [definition.id, definition.fka ?? "", definition.term, ...definition.alts, definition.definition],
        normalizedQuery,
      );
      if (score <= 0) continue;
      matches.push({
        section: "definition",
        id: definition.id,
        title: definition.term,
        summary: truncate(definition.definition),
        appliesTo: definition.appliesTo,
        score,
      });
    }
  }

  if (section === "any" || section === "process") {
    for (const process of catalog.processes) {
      const processApplicability =
        process.applicability.includes("both")
          ? "both"
          : process.applicability.includes("20x")
            ? "20x"
            : "rev5";
      if (!matchesApplicability(processApplicability, appliesTo)) continue;
      const score = matchScore(
        [
          process.id,
          process.name,
          process.shortName,
          process.webName,
          process.purpose ?? "",
          ...process.expectedOutcomes,
        ],
        normalizedQuery,
      );
      if (score <= 0) continue;
      matches.push({
        section: "process",
        id: process.id,
        title: process.name,
        summary: truncate(process.purpose ?? process.expectedOutcomes[0] ?? `${process.requirementIds.length} requirements`),
        appliesTo: processApplicability,
        score,
      });
    }
  }

  if (section === "any" || section === "requirement") {
    for (const requirement of catalog.requirements) {
      if (!matchesApplicability(requirement.appliesTo, appliesTo)) continue;
      const score = matchScore(
        [
          requirement.id,
          requirement.fka ?? "",
          requirement.name ?? "",
          requirement.statement,
          requirement.processId,
          requirement.processName,
          requirement.processShortName,
          requirement.labelCode,
          requirement.labelName,
          ...requirement.terms,
          ...requirement.followingInformation,
        ],
        normalizedQuery,
      );
      if (score <= 0) continue;
      matches.push({
        section: "requirement",
        id: requirement.id,
        title: requirement.name ?? requirement.statement,
        summary: truncate(requirement.statement),
        appliesTo: requirement.appliesTo,
        score,
      });
    }
  }

  if (section === "any" || section === "ksi") {
    for (const domain of catalog.ksiDomains) {
      const score = matchScore(
        [domain.id, domain.code, domain.name, domain.shortName, domain.webName, domain.theme],
        normalizedQuery,
      );
      if (score > 0) {
        matches.push({
          section: "ksi",
          id: domain.id,
          title: domain.name,
          summary: truncate(domain.theme),
          appliesTo: "20x",
          score,
        });
      }
    }

    for (const indicator of catalog.ksiIndicators) {
      const score = matchScore(
        [
          indicator.id,
          indicator.fka ?? "",
          indicator.name,
          indicator.statement,
          indicator.domainId,
          indicator.domainCode,
          indicator.domainName,
          indicator.reference ?? "",
          indicator.referenceUrl ?? "",
          ...indicator.controls,
          ...indicator.terms,
        ],
        normalizedQuery,
      );
      if (score <= 0) continue;
      matches.push({
        section: "ksi",
        id: indicator.id,
        title: indicator.name,
        summary: truncate(indicator.statement),
        appliesTo: "20x",
        score,
      });
    }
  }

  return matches
    .sort((left, right) =>
      right.score === left.score ? left.id.localeCompare(right.id) : right.score - left.score,
    )
    .slice(0, limit);
}

function resolveUniqueMatch<T>(
  values: T[],
  query: string,
  candidates: (value: T) => string[],
  label: string,
): T {
  const normalizedQuery = query.trim().toLowerCase();
  if (!normalizedQuery) {
    throw new Error(`A non-empty ${label} query is required.`);
  }

  const exact = values.filter((value) =>
    candidates(value).some((candidate) => candidate.trim().toLowerCase() === normalizedQuery),
  );
  if (exact.length === 1) return exact[0]!;

  const partial = values.filter((value) =>
    candidates(value).some((candidate) => candidate.trim().toLowerCase().includes(normalizedQuery)),
  );
  if (partial.length === 1) return partial[0]!;

  const tokens = normalizedQuery.split(/\s+/).filter(Boolean);
  const tokenMatches = values.filter((value) =>
    candidates(value).some((candidate) => {
      const normalizedCandidate = candidate.trim().toLowerCase();
      return tokens.every((token) => normalizedCandidate.includes(token));
    }),
  );
  if (tokenMatches.length === 1) return tokenMatches[0]!;

  const resultSet = exact.length > 0 ? exact : partial.length > 0 ? partial : tokenMatches;
  if (resultSet.length === 0) {
    throw new Error(`No FedRAMP ${label} matched "${query}".`);
  }

  const examples = resultSet
    .slice(0, 5)
    .map((value) => candidates(value)[0] ?? "(unknown)")
    .join("; ");
  throw new Error(`FedRAMP ${label} query "${query}" matched multiple items. Narrow it down. Examples: ${examples}`);
}

export function resolveFedrampProcess(catalog: FedrampCatalog, query: string): FedrampProcessRecord {
  const aliases: Record<string, string> = {
    ads: "CDS",
    "authorization data sharing": "CDS",
    "authorization-data-sharing": "CDS",
    fsi: "AFC",
    "fedramp security inbox": "AFC",
    "fedramp-security-inbox": "AFC",
    icp: "IEC",
    "incident communications procedures": "IEC",
    "incident-communications-procedures": "IEC",
    pva: "IVV",
    "persistent validation and assessment": "IVV",
    "persistent-validation-and-assessment": "IVV",
    ucm: "CMU",
    "using cryptographic modules": "CMU",
    "using-cryptographic-modules": "CMU",
  };
  const resolvedQuery = aliases[query.trim().toLowerCase()] ?? query;
  return resolveUniqueMatch(
    catalog.processes,
    resolvedQuery,
    (process) => [process.id, process.shortName, process.name, process.webName],
    "process",
  );
}

export function resolveFedrampRequirement(
  catalog: FedrampCatalog,
  query: string,
): FedrampRequirementRecord {
  return resolveUniqueMatch(
    catalog.requirements,
    query,
    (requirement) => [
      requirement.id,
      requirement.fka ?? "",
      requirement.name ?? "",
      requirement.statement,
      `${requirement.processShortName} ${requirement.name ?? ""}`,
    ],
    "requirement",
  );
}

export function resolveFedrampKsi(
  catalog: FedrampCatalog,
  query: string,
): { kind: "domain"; domain: FedrampKsiDomainRecord } | { kind: "indicator"; indicator: FedrampKsiIndicatorRecord } {
  const normalizedQuery = query.trim().toLowerCase();
  if (!normalizedQuery) {
    throw new Error("A non-empty KSI query is required.");
  }

  const exactDomain = catalog.ksiDomains.find((domain) =>
    [domain.id, domain.code, domain.name, domain.shortName, domain.webName]
      .map((candidate) => candidate.toLowerCase())
      .includes(normalizedQuery),
  );
  if (exactDomain) {
    return { kind: "domain", domain: exactDomain };
  }

  const exactIndicator = catalog.ksiIndicators.find((indicator) =>
    [
      indicator.id,
      indicator.fka ?? "",
      indicator.name,
      indicator.reference ?? "",
    ]
      .map((candidate) => candidate.toLowerCase())
      .includes(normalizedQuery),
  );
  if (exactIndicator) {
    return { kind: "indicator", indicator: exactIndicator };
  }

  const domainMatches = catalog.ksiDomains.filter((domain) =>
    [domain.id, domain.code, domain.name, domain.shortName, domain.webName].some((candidate) =>
      candidate.toLowerCase().includes(normalizedQuery),
    ),
  );
  if (domainMatches.length === 1) {
    return { kind: "domain", domain: domainMatches[0]! };
  }

  const indicatorMatches = catalog.ksiIndicators.filter((indicator) =>
    [indicator.id, indicator.fka ?? "", indicator.name, indicator.statement, indicator.reference ?? ""].some(
      (candidate) => candidate.toLowerCase().includes(normalizedQuery),
    ),
  );
  if (indicatorMatches.length === 1) {
    return { kind: "indicator", indicator: indicatorMatches[0]! };
  }

  const ambiguous = [
    ...domainMatches.map((domain) => domain.id),
    ...indicatorMatches.map((indicator) => indicator.id),
  ];
  if (ambiguous.length === 0) {
    throw new Error(`No FedRAMP KSI matched "${query}".`);
  }

  throw new Error(
    `FedRAMP KSI query "${query}" matched multiple items. Narrow it down. Examples: ${ambiguous.slice(0, 5).join("; ")}`,
  );
}

export function requirementCountsByApplicability(
  catalog: FedrampCatalog,
  processId: string,
): Record<FedrampApplicability, number> {
  return {
    both: catalog.requirements.filter(
      (requirement) => requirement.processId === processId && requirement.appliesTo === "both",
    ).length,
    "20x": catalog.requirements.filter(
      (requirement) => requirement.processId === processId && requirement.appliesTo === "20x",
    ).length,
    rev5: catalog.requirements.filter(
      (requirement) => requirement.processId === processId && requirement.appliesTo === "rev5",
    ).length,
  };
}

export function processRequirements(
  catalog: FedrampCatalog,
  processId: string,
): FedrampRequirementRecord[] {
  return catalog.requirements.filter((requirement) => requirement.processId === processId);
}

export function domainIndicators(
  catalog: FedrampCatalog,
  domainId: string,
): FedrampKsiIndicatorRecord[] {
  return catalog.ksiIndicators.filter((indicator) => indicator.domainId === domainId);
}

export function clearFedrampCachesForTests(): void {
  catalogMemoryCache = undefined;
  sourceMemoryCache = undefined;
}

export function normalizeFedrampSearchSection(value: string | null | undefined): FedrampSearchSection {
  return normalizeSearchSection(value);
}

export function normalizeFedrampApplicability(
  value: string | null | undefined,
): FedrampApplicability | "any" {
  return normalizeApplicability(value);
}
