import {
  existsSync,
  lstatSync,
  mkdirSync,
  realpathSync,
  chmodSync,
} from "node:fs";
import { chmod, writeFile } from "node:fs/promises";
import { basename, dirname, join, relative, resolve } from "node:path";
import { Type } from "@sinclair/typebox";

import {
  type FedrampApplicability,
  type FedrampKsiDomainRecord,
  type FedrampKsiIndicatorRecord,
  type FedrampProcessRecord,
  type FedrampRequirementRecord,
  domainIndicators,
  inspectFedrampOfficialSources,
  loadFedrampCatalog,
  normalizeFedrampApplicability,
  normalizeFedrampSearchSection,
  processRequirements,
  requirementCountsByApplicability,
  resolveFedrampKsi,
  resolveFedrampProcess,
  resolveFedrampRequirement,
  searchFedrampCatalog,
} from "./fedramp-source.js";
import { errorResult, formatTable, textResult } from "./shared.js";

type CheckSourcesArgs = { refresh?: boolean };
type SearchArgs = {
  query: string;
  section?: "definition" | "process" | "requirement" | "ksi" | "any";
  applies_to?: FedrampApplicability | "any";
  limit?: number;
};
type QueryArgs = { query: string };
type ReadinessArgs = {
  query: string;
  applies_to?: FedrampApplicability | "any";
  audience?: "provider" | "trust-center" | "any";
  limit?: number;
};
type PlanningArgs = {
  query: string;
  applies_to?: FedrampApplicability | "any";
  audience?: "provider" | "trust-center" | "any";
};
type AdsPackageArgs = {
  applies_to?: FedrampApplicability | "any";
  audience?: "provider" | "trust-center" | "any";
};
type AdsBundleArgs = {
  output_dir?: string;
  applies_to?: FedrampApplicability | "any";
  audience?: "provider" | "trust-center" | "any";
};
type AdsSiteArgs = {
  output_dir?: string;
  applies_to?: FedrampApplicability | "any";
  audience?: "provider" | "trust-center" | "any";
  provider_name?: string;
  offering_name?: string;
  primary_domain?: string;
  support_email?: string;
};

type ArtifactVisibility = "public" | "controlled" | "private";
type ArtifactPhase = "foundation" | "access" | "operations";

type ReadinessChecklistItem = {
  id: string;
  appliesTo: FedrampApplicability;
  keyword: string | null;
  labelCode: string;
  labelName: string;
  statement: string;
};

type ReadinessBrief =
  | {
      kind: "process";
      subject: FedrampProcessRecord;
      linkedProcesses: FedrampProcessRecord[];
      linkedIndicators: FedrampKsiIndicatorRecord[];
      checklist: ReadinessChecklistItem[];
      artifactSuggestions: string[];
      workstreams: string[];
      text: string;
    }
  | {
      kind: "ksi-indicator";
      subject: FedrampKsiIndicatorRecord;
      linkedProcesses: FedrampProcessRecord[];
      linkedIndicators: FedrampKsiIndicatorRecord[];
      checklist: ReadinessChecklistItem[];
      artifactSuggestions: string[];
      workstreams: string[];
      text: string;
    }
  | {
      kind: "ksi-domain";
      subject: FedrampKsiDomainRecord;
      linkedProcesses: FedrampProcessRecord[];
      linkedIndicators: FedrampKsiIndicatorRecord[];
      checklist: ReadinessChecklistItem[];
      artifactSuggestions: string[];
      workstreams: string[];
      text: string;
    };

type ArtifactPlanItem = {
  name: string;
  visibility: ArtifactVisibility;
  phase: ArtifactPhase;
  format: string;
  rationale: string;
  groundedBy: string[];
};

type RolloutPhase = {
  phase: ArtifactPhase;
  title: string;
  objective: string;
  items: string[];
};

type ArtifactPlan =
  | {
      kind: "process";
      subject: FedrampProcessRecord;
      linkedProcesses: FedrampProcessRecord[];
      linkedIndicators: FedrampKsiIndicatorRecord[];
      items: ArtifactPlanItem[];
      rollout: RolloutPhase[];
      text: string;
    }
  | {
      kind: "ksi-indicator";
      subject: FedrampKsiIndicatorRecord;
      linkedProcesses: FedrampProcessRecord[];
      linkedIndicators: FedrampKsiIndicatorRecord[];
      items: ArtifactPlanItem[];
      rollout: RolloutPhase[];
      text: string;
    }
  | {
      kind: "ksi-domain";
      subject: FedrampKsiDomainRecord;
      linkedProcesses: FedrampProcessRecord[];
      linkedIndicators: FedrampKsiIndicatorRecord[];
      items: ArtifactPlanItem[];
      rollout: RolloutPhase[];
      text: string;
    };

type AdsPackagePlan = {
  process: FedrampProcessRecord;
  linkedIndicators: FedrampKsiIndicatorRecord[];
  audience: "provider" | "trust-center" | "any";
  appliesTo: FedrampApplicability | "any";
  publicItems: ArtifactPlanItem[];
  controlledItems: ArtifactPlanItem[];
  privateItems: ArtifactPlanItem[];
  rollout: RolloutPhase[];
  text: string;
};

type BundleTemplateFile = {
  path: string;
  content: string;
};

type AdsStarterBundle = {
  bundleName: string;
  files: BundleTemplateFile[];
  plan: AdsPackagePlan;
};

type AdsStarterBundleResult = {
  outputDir: string;
  files: string[];
  plan: AdsPackagePlan;
};

type AdsSiteMetadata = {
  providerName: string;
  offeringName: string;
  primaryDomain: string;
  supportEmail: string;
  baseUrl: string;
  siteTitle: string;
};

type AdsPublicSite = {
  bundleName: string;
  files: BundleTemplateFile[];
  plan: AdsPackagePlan;
  metadata: AdsSiteMetadata;
};

type AdsPublicSiteResult = {
  outputDir: string;
  files: string[];
  plan: AdsPackagePlan;
  metadata: AdsSiteMetadata;
};

const DEFAULT_FEDRAMP_OUTPUT_DIR = "./export/fedramp";
const ADS_BUNDLE_DIRNAME = "ads-starter-bundle";
const ADS_SITE_DIRNAME = "ads-public-site";

type ArtifactPlanContext =
  | {
      kind: "process";
      subject: FedrampProcessRecord;
      linkedProcesses: FedrampProcessRecord[];
      linkedIndicators: FedrampKsiIndicatorRecord[];
      requirements: FedrampRequirementRecord[];
    }
  | {
      kind: "ksi-indicator";
      subject: FedrampKsiIndicatorRecord;
      linkedProcesses: FedrampProcessRecord[];
      linkedIndicators: FedrampKsiIndicatorRecord[];
      requirements: FedrampRequirementRecord[];
    }
  | {
      kind: "ksi-domain";
      subject: FedrampKsiDomainRecord;
      linkedProcesses: FedrampProcessRecord[];
      linkedIndicators: FedrampKsiIndicatorRecord[];
      requirements: FedrampRequirementRecord[];
    };

function asString(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

function asNumber(value: unknown): number | undefined {
  if (typeof value === "number" && Number.isFinite(value)) {
    return value;
  }
  if (typeof value === "string" && value.trim().length > 0) {
    const parsed = Number(value);
    if (Number.isFinite(parsed)) return parsed;
  }
  return undefined;
}

function clampLimit(value: number | undefined, fallback = 10): number {
  const parsed = value ?? fallback;
  return Math.min(Math.max(Math.trunc(parsed), 1), 50);
}

function normalizeCheckArgs(args: unknown): CheckSourcesArgs {
  if (args && typeof args === "object") {
    const value = args as Record<string, unknown>;
    return { refresh: value.refresh === true };
  }
  return {};
}

function normalizeSearchArgs(args: unknown): SearchArgs {
  if (typeof args === "string" || typeof args === "number") {
    return { query: String(args), section: "any", applies_to: "any", limit: 10 };
  }

  if (args && typeof args === "object") {
    const value = args as Record<string, unknown>;
    return {
      query:
        asString(value.query) ??
        asString(value.term) ??
        asString(value.id) ??
        asString(value.requirement_id) ??
        asString(value.process_id) ??
        "",
      section: normalizeFedrampSearchSection(asString(value.section)),
      applies_to: normalizeFedrampApplicability(
        asString(value.applies_to) ?? asString(value.framework),
      ),
      limit: clampLimit(asNumber(value.limit)),
    };
  }

  return { query: "", section: "any", applies_to: "any", limit: 10 };
}

function normalizeQueryArgs(args: unknown): QueryArgs {
  if (typeof args === "string" || typeof args === "number") {
    return { query: String(args) };
  }

  if (args && typeof args === "object") {
    const value = args as Record<string, unknown>;
    return {
      query:
        asString(value.query) ??
        asString(value.id) ??
        asString(value.process) ??
        asString(value.process_id) ??
        asString(value.requirement_id) ??
        asString(value.ksi) ??
        asString(value.indicator) ??
        asString(value.slug) ??
        "",
    };
  }

  return { query: "" };
}

function normalizeReadinessArgs(args: unknown): ReadinessArgs {
  if (typeof args === "string" || typeof args === "number") {
    return { query: String(args), applies_to: "any", audience: "provider", limit: 8 };
  }

  if (args && typeof args === "object") {
    const value = args as Record<string, unknown>;
    const audienceRaw = asString(value.audience)?.toLowerCase();
    return {
      query:
        asString(value.query) ??
        asString(value.id) ??
        asString(value.process) ??
        asString(value.process_id) ??
        asString(value.ksi) ??
        asString(value.indicator) ??
        "",
      applies_to: normalizeFedrampApplicability(
        asString(value.applies_to) ?? asString(value.framework),
      ),
      audience:
        audienceRaw === "trust-center" || audienceRaw === "any" || audienceRaw === "provider"
          ? audienceRaw
          : "provider",
      limit: clampLimit(asNumber(value.limit), 8),
    };
  }

  return { query: "", applies_to: "any", audience: "provider", limit: 8 };
}

function normalizePlanningArgs(args: unknown): PlanningArgs {
  if (typeof args === "string" || typeof args === "number") {
    return { query: String(args), applies_to: "any", audience: "provider" };
  }

  if (args && typeof args === "object") {
    const value = args as Record<string, unknown>;
    const audienceRaw = asString(value.audience)?.toLowerCase();
    return {
      query:
        asString(value.query) ??
        asString(value.id) ??
        asString(value.process) ??
        asString(value.process_id) ??
        asString(value.ksi) ??
        asString(value.indicator) ??
        "",
      applies_to: normalizeFedrampApplicability(
        asString(value.applies_to) ?? asString(value.framework),
      ),
      audience:
        audienceRaw === "trust-center" || audienceRaw === "any" || audienceRaw === "provider"
          ? audienceRaw
          : "provider",
    };
  }

  return { query: "", applies_to: "any", audience: "provider" };
}

function normalizeAdsPackageArgs(args: unknown): AdsPackageArgs {
  if (args && typeof args === "object") {
    const value = args as Record<string, unknown>;
    const audienceRaw = asString(value.audience)?.toLowerCase();
    return {
      applies_to: normalizeFedrampApplicability(
        asString(value.applies_to) ?? asString(value.framework) ?? "20x",
      ),
      audience:
        audienceRaw === "trust-center" || audienceRaw === "any" || audienceRaw === "provider"
          ? audienceRaw
          : "trust-center",
    };
  }

  return { applies_to: "20x", audience: "trust-center" };
}

function normalizeAdsBundleArgs(args: unknown): AdsBundleArgs {
  if (args && typeof args === "object") {
    const value = args as Record<string, unknown>;
    const audienceRaw = asString(value.audience)?.toLowerCase();
    return {
      output_dir: asString(value.output_dir) ?? asString(value.output) ?? asString(value.dir),
      applies_to: normalizeFedrampApplicability(
        asString(value.applies_to) ?? asString(value.framework) ?? "20x",
      ),
      audience:
        audienceRaw === "trust-center" || audienceRaw === "any" || audienceRaw === "provider"
          ? audienceRaw
          : "trust-center",
    };
  }

  return { output_dir: undefined, applies_to: "20x", audience: "trust-center" };
}

function normalizeAdsSiteArgs(args: unknown): AdsSiteArgs {
  if (args && typeof args === "object") {
    const value = args as Record<string, unknown>;
    const audienceRaw = asString(value.audience)?.toLowerCase();
    return {
      output_dir: asString(value.output_dir) ?? asString(value.output) ?? asString(value.dir),
      applies_to: normalizeFedrampApplicability(
        asString(value.applies_to) ?? asString(value.framework) ?? "20x",
      ),
      audience:
        audienceRaw === "trust-center" || audienceRaw === "any" || audienceRaw === "provider"
          ? audienceRaw
          : "trust-center",
      provider_name:
        asString(value.provider_name) ??
        asString(value.provider) ??
        asString(value.organization) ??
        asString(value.company),
      offering_name:
        asString(value.offering_name) ??
        asString(value.offering) ??
        asString(value.product) ??
        asString(value.service),
      primary_domain:
        asString(value.primary_domain) ?? asString(value.domain) ?? asString(value.base_url),
      support_email:
        asString(value.support_email) ??
        asString(value.email) ??
        asString(value.contact_email),
    };
  }

  return {
    output_dir: undefined,
    applies_to: "20x",
    audience: "trust-center",
    provider_name: undefined,
    offering_name: undefined,
    primary_domain: undefined,
    support_email: undefined,
  };
}

function missingQueryResult(toolName: string, example: string) {
  return errorResult(
    `${toolName} requires a non-empty query. Example: ${example}`,
    { tool: toolName },
  );
}

function formatProvenanceNote(provenance: {
  repo: string;
  path: string;
  branch: string;
  blobSha: string | null;
  version: string;
  upstreamLastUpdated: string;
  cacheStatus: string;
}) {
  return `Source: ${provenance.repo}/${provenance.path} @ ${provenance.branch}${provenance.blobSha ? ` (${provenance.blobSha.slice(0, 12)})` : ""} · FRMR ${provenance.version} · upstream ${provenance.upstreamLastUpdated} · ${provenance.cacheStatus}`;
}

function formatSourceCheckText(status: Awaited<ReturnType<typeof inspectFedrampOfficialSources>>): string {
  const primary = status.primary;
  const secondary = status.secondary;
  const lines = [
    "Official FedRAMP GitHub sources",
    "",
    `Primary source:   ${primary.org}/${primary.repo}`,
    `Source path:      ${primary.path}`,
    `Branch:           ${primary.branch}`,
    `Blob SHA:         ${primary.blobSha ?? "Unavailable"}`,
    `FRMR version:     ${primary.version}`,
    `Upstream updated: ${primary.upstreamLastUpdated}`,
    `Repo updated_at:  ${primary.repoUpdatedAt ?? "Unavailable"}`,
    `Cache status:     ${status.cacheStatus}`,
    "",
    `Secondary source: ${secondary.org}/${secondary.repo}`,
    `State:            ${secondary.state}`,
    `Repo updated_at:  ${secondary.repoUpdatedAt ?? "Unavailable"}`,
    `Root entries:     ${secondary.rootEntries.length > 0 ? secondary.rootEntries.join(", ") : "Unavailable"}`,
  ];

  if (status.notes.length > 0) {
    lines.push("", "Notes:");
    for (const note of status.notes) {
      lines.push(`- ${note}`);
    }
  }

  return lines.join("\n");
}

function formatSearchText(
  matches: ReturnType<typeof searchFedrampCatalog>,
  query: string,
  provenance: Awaited<ReturnType<typeof loadFedrampCatalog>>["provenance"],
  cacheStatus: string,
): string {
  const rows = matches.map((match) => [
    match.section,
    match.id,
    match.appliesTo,
    match.title.length > 48 ? `${match.title.slice(0, 45)}...` : match.title,
  ]);

  return [
    `Found ${matches.length} FedRAMP match(es) for "${query}".`,
    "",
    formatTable(["section", "id", "applies_to", "title"], rows),
    "",
    formatProvenanceNote({
      repo: provenance.repo,
      path: provenance.path,
      branch: provenance.branch,
      blobSha: provenance.blobSha,
      version: provenance.version,
      upstreamLastUpdated: provenance.upstreamLastUpdated,
      cacheStatus,
    }),
  ].join("\n");
}

function formatProcessText(
  process: ReturnType<typeof resolveFedrampProcess>,
  requirements: ReturnType<typeof processRequirements>,
  counts: ReturnType<typeof requirementCountsByApplicability>,
  provenance: Awaited<ReturnType<typeof loadFedrampCatalog>>["provenance"],
  cacheStatus: string,
): string {
  const lines = [
    `${process.name} [${process.shortName}]`,
    `Process ID:       ${process.id}`,
    `Web slug:         ${process.webName}`,
    `Applies to:       ${process.applicability.join(", ")}`,
    `Requirements:     both ${counts.both}, 20x ${counts["20x"]}, rev5 ${counts.rev5}`,
    `Official page:    ${process.sourceUrl ?? "Unavailable"}`,
    "",
  ];

  if (process.purpose) {
    lines.push(`Purpose: ${process.purpose}`, "");
  }

  if (process.expectedOutcomes.length > 0) {
    lines.push("Expected outcomes:");
    for (const outcome of process.expectedOutcomes.slice(0, 5)) {
      lines.push(`- ${outcome}`);
    }
    lines.push("");
  }

  if (process.labels.length > 0) {
    lines.push("Label groups:");
    for (const label of process.labels) {
      lines.push(`- ${label.code}: ${label.name}`);
    }
    lines.push("");
  }

  if (requirements.length > 0) {
    const sampleRows = requirements.slice(0, 8).map((requirement) => [
      requirement.id,
      requirement.appliesTo,
      requirement.primaryKeyWord ?? "",
      requirement.name ?? requirement.labelName,
    ]);
    lines.push("Requirement samples:", formatTable(["id", "applies_to", "keyword", "name"], sampleRows), "");
  }

  lines.push(
    formatProvenanceNote({
      repo: provenance.repo,
      path: provenance.path,
      branch: provenance.branch,
      blobSha: provenance.blobSha,
      version: provenance.version,
      upstreamLastUpdated: provenance.upstreamLastUpdated,
      cacheStatus,
    }),
  );

  return lines.join("\n");
}

function formatRequirementText(
  requirement: FedrampRequirementRecord,
  provenance: Awaited<ReturnType<typeof loadFedrampCatalog>>["provenance"],
  cacheStatus: string,
): string {
  const lines = [
    `${requirement.id}${requirement.fka ? ` (formerly ${requirement.fka})` : ""}`,
    `Process:          ${requirement.processName} [${requirement.processShortName}]`,
    `Applies to:       ${requirement.appliesTo}`,
    `Label group:      ${requirement.labelCode} - ${requirement.labelName}`,
    `Keyword:          ${requirement.primaryKeyWord ?? "Unspecified"}`,
    `Name:             ${requirement.name ?? "Unspecified"}`,
    "",
    requirement.statement,
  ];

  if (requirement.followingInformation.length > 0) {
    lines.push("", "Checklist items:");
    for (const item of requirement.followingInformation) {
      lines.push(`- ${item}`);
    }
  }

  if (requirement.terms.length > 0) {
    lines.push("", `Terms: ${requirement.terms.join(", ")}`);
  }

  if (requirement.affects.length > 0) {
    lines.push("", `Affects: ${requirement.affects.join(", ")}`);
  }

  if (requirement.updated.length > 0) {
    lines.push("", `Recent update: ${requirement.updated[0]!.date} — ${requirement.updated[0]!.comment}`);
  }

  lines.push(
    "",
    formatProvenanceNote({
      repo: provenance.repo,
      path: provenance.path,
      branch: provenance.branch,
      blobSha: provenance.blobSha,
      version: provenance.version,
      upstreamLastUpdated: provenance.upstreamLastUpdated,
      cacheStatus,
    }),
  );

  return lines.join("\n");
}

function formatIndicatorSummary(indicator: FedrampKsiIndicatorRecord): string {
  return [
    `${indicator.id}${indicator.fka ? ` (formerly ${indicator.fka})` : ""} — ${indicator.name}`,
    indicator.statement,
    indicator.reference ? `Reference: ${indicator.reference}${indicator.referenceUrl ? ` (${indicator.referenceUrl})` : ""}` : "",
    indicator.controls.length > 0 ? `Rev5 controls: ${indicator.controls.join(", ")}` : "",
  ]
    .filter(Boolean)
    .join("\n");
}

function filterRequirementsByApplicability(
  requirements: FedrampRequirementRecord[],
  appliesTo: FedrampApplicability | "any",
): FedrampRequirementRecord[] {
  if (appliesTo === "any") return requirements;
  if (appliesTo === "both") {
    return requirements.filter((requirement) => requirement.appliesTo === "both");
  }
  return requirements.filter(
    (requirement) => requirement.appliesTo === appliesTo || requirement.appliesTo === "both",
  );
}

function requirementPriority(
  requirement: FedrampRequirementRecord,
  audience: ReadinessArgs["audience"],
): number {
  let score = 0;
  if (requirement.primaryKeyWord === "MUST") score += 300;
  else if (requirement.primaryKeyWord === "SHOULD") score += 200;
  else if (requirement.primaryKeyWord === "MAY") score += 100;

  if (requirement.appliesTo === "both") score += 40;
  else if (requirement.appliesTo === "20x") score += 30;
  else if (requirement.appliesTo === "rev5") score += 20;

  if (audience === "provider") {
    if (["CSO", "CSX", "CSL", "UTC"].includes(requirement.labelCode)) score += 35;
    if (requirement.labelCode === "TRC") score += 15;
  } else if (audience === "trust-center") {
    if (requirement.labelCode === "TRC") score += 35;
    if (requirement.labelCode === "UTC") score += 20;
  }

  if (/programmatic access|publicly share|persistently|quarterly|notify|log access|inventory/i.test(requirement.statement)) {
    score += 10;
  }

  return score;
}

function toChecklistItems(requirements: FedrampRequirementRecord[]): ReadinessChecklistItem[] {
  return requirements.map((requirement) => ({
    id: requirement.id,
    appliesTo: requirement.appliesTo,
    keyword: requirement.primaryKeyWord,
    labelCode: requirement.labelCode,
    labelName: requirement.labelName,
    statement: requirement.statement,
  }));
}

function dedupeStrings(values: string[]): string[] {
  return Array.from(new Set(values.filter((value) => value.trim().length > 0)));
}

function formatVisibility(value: ArtifactVisibility): string {
  return value === "controlled" ? "controlled-access" : value;
}

function formatPhase(value: ArtifactPhase): string {
  if (value === "foundation") return "foundation";
  if (value === "access") return "access";
  return "operations";
}

function requirementText(requirement: FedrampRequirementRecord): string {
  return [
    requirement.name ?? "",
    requirement.statement,
    ...requirement.followingInformation,
    ...requirement.terms,
  ]
    .filter(Boolean)
    .join(" \n ")
    .toLowerCase();
}

function indicatorText(indicator: FedrampKsiIndicatorRecord): string {
  return [
    indicator.name,
    indicator.statement,
    indicator.reference ?? "",
    ...indicator.terms,
  ]
    .filter(Boolean)
    .join(" \n ")
    .toLowerCase();
}

type ArtifactRule = {
  name: string;
  visibility: ArtifactVisibility;
  phase: ArtifactPhase;
  format: string;
  rationale: string;
  patterns: RegExp[];
};

const ARTIFACT_RULES: ArtifactRule[] = [
  {
    name: "Human-readable authorization summary page",
    visibility: "public",
    phase: "foundation",
    format: "Web page",
    rationale: "Official requirements call for publicly shared human-readable information.",
    patterns: [/human-readable|publicly share|public information|publicly available/i],
  },
  {
    name: "Machine-readable authorization data feed",
    visibility: "public",
    phase: "foundation",
    format: "JSON feed or API payload",
    rationale: "Official requirements call for machine-readable authorization data that can be reused programmatically.",
    patterns: [/machine-readable|structured data|programmatically access/i],
  },
  {
    name: "Service inventory and assessment-scope page",
    visibility: "public",
    phase: "foundation",
    format: "Catalog page",
    rationale: "Official requirements emphasize clear service scope, boundary, and included-service information.",
    patterns: [/service list|service model|specific services|scope|boundary|minimum assessment scope|service inventory/i],
  },
  {
    name: "Controlled authorization-data API and access guide",
    visibility: "controlled",
    phase: "access",
    format: "API docs and access instructions",
    rationale: "Official requirements call for documented programmatic access to deeper authorization data.",
    patterns: [/programmatic access|api|retrieve authorization data|download|all authorization data/i],
  },
  {
    name: "Version history and change-log archive",
    visibility: "controlled",
    phase: "access",
    format: "Version archive",
    rationale: "Official requirements call for historical versions or change deltas to remain available to necessary parties.",
    patterns: [/historical versions|history|delta|change log|versions available/i],
  },
  {
    name: "Secure configuration guide and shared-responsibility guidance",
    visibility: "public",
    phase: "foundation",
    format: "Guide page or PDF",
    rationale: "Official requirements and related indicators expect customers to understand secure configuration and responsibility boundaries.",
    patterns: [/secure configuration|configuration guide|shared responsibility/i],
  },
  {
    name: "Access inventory and authorization-data audit logs",
    visibility: "private",
    phase: "operations",
    format: "Operational records",
    rationale: "Official requirements imply auditable control over who can retrieve authorization data and how that access is tracked.",
    patterns: [/access log|log access|access inventory|inventory of access|who can view/i],
  },
  {
    name: "Notification routing and escalation runbook",
    visibility: "private",
    phase: "operations",
    format: "Runbook",
    rationale: "Official requirements around notifications and inbox operations need an internal execution path even when the public surface is simple.",
    patterns: [/notify|notification|inbox|escalation|communicat/i],
  },
  {
    name: "Continuous validation cadence records",
    visibility: "private",
    phase: "operations",
    format: "Automation evidence",
    rationale: "Official requirements around persistent validation and recurring review need internal cadence evidence.",
    patterns: [/persistently|validation|quarterly review|ongoing authorization report|cadence/i],
  },
  {
    name: "Vulnerability response evidence bundle",
    visibility: "controlled",
    phase: "operations",
    format: "Evidence bundle",
    rationale: "Official requirements around vulnerabilities and remediation usually need a controlled evidence surface plus private workflow records.",
    patterns: [/vulnerability|accepted vulnerability|remediation/i],
  },
  {
    name: "Cryptographic module inventory and references",
    visibility: "controlled",
    phase: "foundation",
    format: "Inventory appendix",
    rationale: "Official requirements around cryptographic modules and CMVP references benefit from a maintained source-of-truth appendix.",
    patterns: [/cryptographic module|fips|cmvp/i],
  },
];

function groupArtifactItemsByVisibility(items: ArtifactPlanItem[]) {
  return {
    publicItems: items.filter((item) => item.visibility === "public"),
    controlledItems: items.filter((item) => item.visibility === "controlled"),
    privateItems: items.filter((item) => item.visibility === "private"),
  };
}

function buildRolloutPhases(items: ArtifactPlanItem[]): RolloutPhase[] {
  const phases: Array<{ phase: ArtifactPhase; title: string; objective: string }> = [
    {
      phase: "foundation",
      title: "Phase 1: Publish the public baseline",
      objective:
        "Make the offering legible without a private request loop by publishing the public trust-center and scope baseline first.",
    },
    {
      phase: "access",
      title: "Phase 2: Enable controlled retrieval",
      objective:
        "Add the controlled-access surfaces that let agencies and necessary parties pull deeper authorization data when needed.",
    },
    {
      phase: "operations",
      title: "Phase 3: Back it with auditable operations",
      objective:
        "Support the published surface with internal runbooks, logs, and recurring evidence so the package stays trustworthy over time.",
    },
  ];

  return phases
    .map((phase) => ({
      ...phase,
      items: items
        .filter((item) => item.phase === phase.phase)
        .map((item) => item.name),
    }))
    .filter((phase) => phase.items.length > 0);
}

function ensurePrivateDir(path: string): void {
  if (existsSync(path)) {
    const info = lstatSync(path);
    if (info.isSymbolicLink()) {
      throw new Error(`Refusing to use symlinked directory: ${path}`);
    }
    if (!info.isDirectory()) {
      throw new Error(`Path is not a directory: ${path}`);
    }
  }

  mkdirSync(path, { recursive: true, mode: 0o700 });

  const info = lstatSync(path);
  if (info.isSymbolicLink()) {
    throw new Error(`Refusing to use symlinked directory: ${path}`);
  }
  if (!info.isDirectory()) {
    throw new Error(`Path is not a directory: ${path}`);
  }

  chmodSync(path, 0o700);
}

function resolveSecureOutputPath(baseDir: string, destPath: string): string {
  const resolvedBase = realpathSync(resolve(baseDir));
  const absoluteDest = resolve(destPath);

  if (existsSync(absoluteDest)) {
    const info = lstatSync(absoluteDest);
    if (info.isSymbolicLink()) {
      throw new Error(`Refusing to write through symlink: ${absoluteDest}`);
    }
  }

  const resolvedDestDir = realpathSync(resolve(dirname(absoluteDest)));
  const resolvedDest = join(resolvedDestDir, basename(absoluteDest));
  const relPath = relative(resolvedBase, resolvedDest);
  if (relPath.startsWith("..")) {
    throw new Error("Invalid output path: path traversal detected");
  }

  return resolvedDest;
}

async function writeSecureTextFile(baseDir: string, destPath: string, data: string): Promise<string> {
  ensurePrivateDir(dirname(destPath));
  const resolvedPath = resolveSecureOutputPath(baseDir, destPath);
  await writeFile(resolvedPath, data, { mode: 0o600 });
  await chmod(resolvedPath, 0o600);
  return resolvedPath;
}

function nextAvailableBundleDir(rootDir: string, baseName: string): string {
  let attempt = 0;
  while (attempt < 100) {
    const candidateName = attempt === 0 ? baseName : `${baseName}-${attempt + 1}`;
    const candidate = resolve(rootDir, candidateName);
    if (!existsSync(candidate)) return candidate;
    attempt += 1;
  }

  throw new Error(`Unable to allocate bundle directory under ${rootDir}`);
}

function findArtifactItem(plan: AdsPackagePlan, name: string): ArtifactPlanItem | undefined {
  return [
    ...plan.publicItems,
    ...plan.controlledItems,
    ...plan.privateItems,
  ].find((item) => item.name === name);
}

function groundedIds(item: ArtifactPlanItem | undefined): string[] {
  return item?.groundedBy ?? [];
}

function buildAdsBundleReadme(plan: AdsPackagePlan): string {
  const lines = [
    "# Authorization Data Sharing Starter Bundle",
    "",
    "This starter bundle was generated by grclanker from the official FedRAMP GitHub-grounded FRMR source layer.",
    "",
    `Audience: ${plan.audience}`,
    `Applies to: ${plan.appliesTo}`,
    `Official process: ${plan.process.name} [${plan.process.shortName}]`,
    `Official page: ${plan.process.sourceUrl ?? "Unavailable"}`,
    "",
    "What this bundle gives you:",
    "- Public trust-center starter pages and machine-readable feed skeletons.",
    "- Controlled-access templates for deeper authorization-data retrieval.",
    "- Private operating templates for access logging, notification routing, and cadence management.",
    "",
    "Recommended rollout:",
  ];

  for (const phase of plan.rollout) {
    lines.push(`- ${phase.title} - ${phase.objective}`);
    for (const item of phase.items) {
      lines.push(`  - ${item}`);
    }
  }

  lines.push(
    "",
    "Generated files:",
    "- public/trust-center-summary.md",
    "- public/authorization-data.json",
    "- public/service-inventory.json",
    "- controlled/access-instructions.md",
    "- controlled/version-history.md",
    "- private/operating-runbook.md",
    "- private/access-log-schema.json",
    "- private/notification-routing.md",
    "- private/continuous-validation.md",
    "- _source.json",
  );

  return `${lines.join("\n")}\n`;
}

function buildSourceMetadataFile(
  loaded: Awaited<ReturnType<typeof loadFedrampCatalog>>,
  plan: AdsPackagePlan,
): string {
  return `${JSON.stringify(
    {
      generated_by: "grclanker",
      bundle: ADS_BUNDLE_DIRNAME,
      process: {
        id: plan.process.id,
        name: plan.process.name,
        short_name: plan.process.shortName,
        source_url: plan.process.sourceUrl,
      },
      applies_to: plan.appliesTo,
      audience: plan.audience,
      linked_indicators: plan.linkedIndicators.map((indicator) => ({
        id: indicator.id,
        name: indicator.name,
        reference: indicator.reference,
      })),
      public_items: plan.publicItems,
      controlled_items: plan.controlledItems,
      private_items: plan.privateItems,
      rollout: plan.rollout,
      provenance: {
        ...loaded.provenance,
        cache_status: loaded.cacheStatus,
        notes: loaded.notes,
      },
    },
    null,
    2,
  )}\n`;
}

function buildTrustCenterSummaryTemplate(plan: AdsPackagePlan): string {
  const pub = findArtifactItem(plan, "Human-readable authorization summary page");
  const inventory = findArtifactItem(plan, "Service inventory and assessment-scope page");
  return `# Trust Center Summary\n\n## Overview\n- Cloud service offering name: TODO\n- FedRAMP status: TODO\n- Marketplace URL: TODO\n- Last updated: TODO\n\n## Public Summary\nDescribe the cloud service offering in plain language for agencies and customers.\n\n## Included Services\nList the services or features in scope using names that match public marketing materials.\n\n## Customer Responsibilities\nDocument the customer-managed responsibilities that affect secure use.\n\n## Scope Notes\nClarify what is in scope, out of scope, and where customers can request deeper authorization data.\n\n## Grounding\n- ${pub ? `${pub.name}: ${groundedIds(pub).join(", ") || "linked official requirements"}` : "Human-readable summary: linked official requirements"}\n- ${inventory ? `${inventory.name}: ${groundedIds(inventory).join(", ") || "linked official requirements"}` : "Service inventory: linked official requirements"}\n`;
}

function buildAuthorizationDataJsonTemplate(plan: AdsPackagePlan): string {
  const machineReadable = findArtifactItem(plan, "Machine-readable authorization data feed");
  return `${JSON.stringify(
    {
      bundle_version: "0.1.0-draft",
      generated_by: "grclanker",
      fedramp_process: plan.process.shortName,
      applies_to: plan.appliesTo,
      offering: {
        name: "TODO",
        fedramp_marketplace_url: "TODO",
        trust_center_url: "TODO",
        overview: "TODO",
      },
      authorization_data: {
        version: "TODO",
        last_updated: "TODO",
        human_readable_url: "TODO",
        machine_readable_url: "TODO",
      },
      included_services: [
        {
          name: "TODO",
          service_model: "TODO",
          security_objectives: ["TODO"],
          in_minimum_assessment_scope: true,
        },
      ],
      customer_responsibilities: ["TODO"],
      grounding: {
        artifact: machineReadable?.name ?? "Machine-readable authorization data feed",
        requirement_ids: groundedIds(machineReadable),
      },
    },
    null,
    2,
  )}\n`;
}

function buildServiceInventoryJsonTemplate(plan: AdsPackagePlan): string {
  const inventory = findArtifactItem(plan, "Service inventory and assessment-scope page");
  return `${JSON.stringify(
    {
      generated_by: "grclanker",
      process: plan.process.shortName,
      services: [
        {
          name: "TODO",
          marketing_name: "TODO",
          included_in_scope: true,
          security_objectives: ["TODO"],
          notes: "TODO",
        },
      ],
      shared_responsibility_summary: "TODO",
      grounding: {
        artifact: inventory?.name ?? "Service inventory and assessment-scope page",
        requirement_ids: groundedIds(inventory),
      },
    },
    null,
    2,
  )}\n`;
}

function buildAccessInstructionsTemplate(plan: AdsPackagePlan): string {
  const access = findArtifactItem(plan, "Controlled authorization-data API and access guide");
  return `# Authorization Data Access Instructions\n\n## Access Model\nDescribe who can retrieve deeper authorization data, under what conditions, and through which interface.\n\n## Endpoints Or Export Paths\n- API base URL: TODO\n- Authentication method: TODO\n- Rate limits or download guidance: TODO\n\n## Request Steps\n1. TODO\n2. TODO\n3. TODO\n\n## Data Returned\nList the authorization-data records or files the requester can retrieve.\n\n## Grounding\n- ${access ? `${access.name}: ${groundedIds(access).join(", ") || "linked official requirements"}` : "Controlled access guidance: linked official requirements"}\n`;
}

function buildVersionHistoryTemplate(plan: AdsPackagePlan): string {
  const history = findArtifactItem(plan, "Version history and change-log archive");
  return `# Authorization Data Version History\n\n| Version | Effective date | Summary of changes | Delta link |\n| --- | --- | --- | --- |\n| TODO | TODO | TODO | TODO |\n\n## Retention Notes\nDocument how long historical authorization-data versions remain available and who can retrieve them.\n\n## Grounding\n- ${history ? `${history.name}: ${groundedIds(history).join(", ") || "linked official requirements"}` : "Version history: linked official requirements"}\n`;
}

function buildOperatingRunbookTemplate(plan: AdsPackagePlan): string {
  return `# ADS Operating Runbook\n\n## Owners\n- Trust-center owner: TODO\n- Security owner: TODO\n- Engineering owner: TODO\n\n## Regular Tasks\n- Publish public summary updates: TODO cadence\n- Refresh machine-readable data: TODO cadence\n- Review access inventory: TODO cadence\n- Review change log and retained versions: TODO cadence\n\n## Escalation Conditions\nList the conditions that require escalation or off-cycle updates.\n\n## Linked Indicators\n${plan.linkedIndicators.map((indicator) => `- ${indicator.id} - ${indicator.name}`).join("\n")}\n`;
}

function buildAccessLogSchemaTemplate(plan: AdsPackagePlan): string {
  const logs = findArtifactItem(plan, "Access inventory and authorization-data audit logs");
  return `${JSON.stringify(
    {
      generated_by: "grclanker",
      schema_name: "authorization_data_access_log",
      fields: [
        "event_time",
        "requester_identity",
        "requester_org",
        "resource",
        "action",
        "decision",
        "ip_address",
        "justification",
      ],
      retention_period: "TODO",
      grounding: {
        artifact: logs?.name ?? "Access inventory and authorization-data audit logs",
        requirement_ids: groundedIds(logs),
      },
    },
    null,
    2,
  )}\n`;
}

function buildNotificationRoutingTemplate(plan: AdsPackagePlan): string {
  const notice = findArtifactItem(plan, "Notification routing and escalation runbook");
  return `# Notification Routing\n\n## Monitored Channels\n- FedRAMP inbox: TODO\n- Internal escalation channel: TODO\n- Pager or on-call rotation: TODO\n\n## Trigger Matrix\n| Trigger | Notify | SLA | Notes |\n| --- | --- | --- | --- |\n| TODO | TODO | TODO | TODO |\n\n## Grounding\n- ${notice ? `${notice.name}: ${groundedIds(notice).join(", ") || "linked official requirements"}` : "Notification routing: linked official requirements"}\n`;
}

function buildContinuousValidationTemplate(plan: AdsPackagePlan): string {
  const cadence = findArtifactItem(plan, "Continuous validation cadence records");
  return `# Continuous Validation Cadence\n\n## Checks\n- Public trust-center page review: TODO\n- Machine-readable feed refresh: TODO\n- Access inventory review: TODO\n- Version-history retention review: TODO\n\n## Evidence Capture\nDocument where logs, job runs, and review records are stored.\n\n## Grounding\n- ${cadence ? `${cadence.name}: ${groundedIds(cadence).join(", ") || "linked official requirements"}` : "Continuous validation: linked official requirements"}\n`;
}

export function buildFedrampAdsStarterBundle(
  loaded: Awaited<ReturnType<typeof loadFedrampCatalog>>,
  args: AdsBundleArgs,
): AdsStarterBundle {
  const plan = buildFedrampAdsPackagePlan(loaded, {
    applies_to: args.applies_to,
    audience: args.audience,
  });

  const files: BundleTemplateFile[] = [
    { path: "README.md", content: buildAdsBundleReadme(plan) },
    { path: "_source.json", content: buildSourceMetadataFile(loaded, plan) },
    { path: "public/trust-center-summary.md", content: buildTrustCenterSummaryTemplate(plan) },
    { path: "public/authorization-data.json", content: buildAuthorizationDataJsonTemplate(plan) },
    { path: "public/service-inventory.json", content: buildServiceInventoryJsonTemplate(plan) },
    { path: "controlled/access-instructions.md", content: buildAccessInstructionsTemplate(plan) },
    { path: "controlled/version-history.md", content: buildVersionHistoryTemplate(plan) },
    { path: "private/operating-runbook.md", content: buildOperatingRunbookTemplate(plan) },
    { path: "private/access-log-schema.json", content: buildAccessLogSchemaTemplate(plan) },
    { path: "private/notification-routing.md", content: buildNotificationRoutingTemplate(plan) },
    { path: "private/continuous-validation.md", content: buildContinuousValidationTemplate(plan) },
  ];

  return {
    bundleName: ADS_BUNDLE_DIRNAME,
    files,
    plan,
  };
}

export async function generateFedrampAdsStarterBundle(
  loaded: Awaited<ReturnType<typeof loadFedrampCatalog>>,
  outputRoot: string,
  args: AdsBundleArgs,
): Promise<AdsStarterBundleResult> {
  ensurePrivateDir(outputRoot);
  const canonicalOutputRoot = realpathSync(outputRoot);
  const bundle = buildFedrampAdsStarterBundle(loaded, args);
  const outputDir = nextAvailableBundleDir(canonicalOutputRoot, bundle.bundleName);
  ensurePrivateDir(outputDir);

  const writtenFiles: string[] = [];
  for (const file of bundle.files) {
    const absolutePath = await writeSecureTextFile(outputDir, resolve(outputDir, file.path), file.content);
    writtenFiles.push(absolutePath);
  }

  return {
    outputDir,
    files: writtenFiles,
    plan: bundle.plan,
  };
}

function normalizePrimaryDomain(value: string | undefined): string {
  const trimmed = value?.trim();
  if (!trimmed) return "trust.example.com";
  return trimmed.replace(/^https?:\/\//i, "").replace(/\/+$/, "");
}

function toBaseUrl(domain: string): string {
  return `https://${domain.replace(/^https?:\/\//i, "").replace(/\/+$/, "")}`;
}

function buildAdsSiteMetadata(args: AdsSiteArgs): AdsSiteMetadata {
  const providerName = args.provider_name ?? "Example Provider";
  const offeringName = args.offering_name ?? "Example Cloud Service";
  const primaryDomain = normalizePrimaryDomain(args.primary_domain);
  const baseUrl = toBaseUrl(primaryDomain);

  return {
    providerName,
    offeringName,
    primaryDomain,
    supportEmail: args.support_email ?? "security@example.com",
    baseUrl,
    siteTitle: `${offeringName} Trust Center`,
  };
}

function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function pageHref(prefix: string, path: string): string {
  return `${prefix}${path}`;
}

function navLink(prefix: string, href: string, label: string, active: boolean): string {
  return `<a href="${escapeHtml(pageHref(prefix, href))}" class="site-nav-link${active ? " is-active" : ""}">${escapeHtml(label)}</a>`;
}

function renderArtifactList(items: ArtifactPlanItem[]): string {
  if (items.length === 0) {
    return "<p class=\"empty-copy\">No public-facing items were inferred from the current official source text for this scope.</p>";
  }

  return `<ul class="artifact-list">${items
    .map(
      (item) =>
        `<li><h3>${escapeHtml(item.name)}</h3><p>${escapeHtml(item.rationale)}</p><p class="artifact-meta">${escapeHtml(item.format)} · Grounded by ${escapeHtml(item.groundedBy.join(", ") || "linked official text")}</p></li>`,
    )
    .join("")}</ul>`;
}

function renderRolloutSummary(plan: AdsPackagePlan): string {
  const relevantPhases = plan.rollout.filter((phase) =>
    phase.items.some((name) =>
      plan.publicItems.some((item) => item.name === name) ||
      plan.controlledItems.some((item) => item.name === name),
    ),
  );

  return `<ol class="rollout-list">${relevantPhases
    .map((phase) => {
      const visibleItems = phase.items.filter((name) =>
        plan.publicItems.some((item) => item.name === name) ||
        plan.controlledItems.some((item) => item.name === name),
      );
      return `<li><h3>${escapeHtml(phase.title)}</h3><p>${escapeHtml(phase.objective)}</p><ul>${visibleItems
        .map((item) => `<li>${escapeHtml(item)}</li>`)
        .join("")}</ul></li>`;
    })
    .join("")}</ol>`;
}

function buildAdsSiteSourceMetadataFile(
  loaded: Awaited<ReturnType<typeof loadFedrampCatalog>>,
  plan: AdsPackagePlan,
  metadata: AdsSiteMetadata,
): string {
  return `${JSON.stringify(
    {
      generated_by: "grclanker",
      bundle: ADS_SITE_DIRNAME,
      site: {
        title: metadata.siteTitle,
        provider_name: metadata.providerName,
        offering_name: metadata.offeringName,
        primary_domain: metadata.primaryDomain,
        base_url: metadata.baseUrl,
        support_email: metadata.supportEmail,
      },
      process: {
        id: plan.process.id,
        name: plan.process.name,
        short_name: plan.process.shortName,
        source_url: plan.process.sourceUrl,
      },
      applies_to: plan.appliesTo,
      audience: plan.audience,
      linked_indicators: plan.linkedIndicators.map((indicator) => ({
        id: indicator.id,
        name: indicator.name,
        reference: indicator.reference,
      })),
      public_items: plan.publicItems,
      controlled_items: plan.controlledItems,
      rollout: plan.rollout,
      provenance: {
        ...loaded.provenance,
        cache_status: loaded.cacheStatus,
        notes: loaded.notes,
      },
    },
    null,
    2,
  )}\n`;
}

function buildAdsSiteAuthorizationDataJson(plan: AdsPackagePlan, metadata: AdsSiteMetadata): string {
  const machineReadable = findArtifactItem(plan, "Machine-readable authorization data feed");
  return `${JSON.stringify(
    {
      version: "0.1.0-draft",
      generated_by: "grclanker",
      trust_center: {
        title: metadata.siteTitle,
        provider_name: metadata.providerName,
        offering_name: metadata.offeringName,
        base_url: metadata.baseUrl,
        support_email: metadata.supportEmail,
      },
      fedramp: {
        process: plan.process.shortName,
        process_name: plan.process.name,
        applies_to: plan.appliesTo,
        marketplace_url: "TODO",
        public_summary_url: `${metadata.baseUrl}/`,
        machine_readable_url: `${metadata.baseUrl}/authorization-data.json`,
        service_inventory_url: `${metadata.baseUrl}/service-inventory.json`,
      },
      offering: {
        name: metadata.offeringName,
        status_summary: "TODO",
        last_updated: "TODO",
        included_services: [
          {
            name: "TODO",
            service_model: "TODO",
            included_in_scope: true,
            notes: "TODO",
          },
        ],
        customer_responsibilities: ["TODO"],
      },
      grounding: {
        artifact: machineReadable?.name ?? "Machine-readable authorization data feed",
        requirement_ids: groundedIds(machineReadable),
      },
    },
    null,
    2,
  )}\n`;
}

function buildAdsSiteServiceInventoryJson(plan: AdsPackagePlan, metadata: AdsSiteMetadata): string {
  const inventory = findArtifactItem(plan, "Service inventory and assessment-scope page");
  return `${JSON.stringify(
    {
      generated_by: "grclanker",
      trust_center: metadata.siteTitle,
      process: plan.process.shortName,
      offering_name: metadata.offeringName,
      services: [
        {
          name: "TODO",
          marketing_name: "TODO",
          service_model: "TODO",
          included_in_scope: true,
          notes: "TODO",
        },
      ],
      shared_responsibility_summary: "TODO",
      boundary_notes: "TODO",
      grounding: {
        artifact: inventory?.name ?? "Service inventory and assessment-scope page",
        requirement_ids: groundedIds(inventory),
      },
    },
    null,
    2,
  )}\n`;
}

function buildAdsSiteReadme(
  loaded: Awaited<ReturnType<typeof loadFedrampCatalog>>,
  plan: AdsPackagePlan,
  metadata: AdsSiteMetadata,
): string {
  const lines = [
    `# ${metadata.siteTitle}`,
    "",
    "This directory is a portable, public-only ADS trust-center scaffold generated by grclanker.",
    "",
    "What is included:",
    "- Static HTML pages for the trust-center summary, services, access guidance, and version history.",
    "- Public machine-readable files: `authorization-data.json` and `service-inventory.json`.",
    "- Shared CSS, `robots.txt`, `sitemap.xml`, and provenance metadata in `_source.json`.",
    "",
    "What is intentionally excluded:",
    "- Controlled-access authorization data.",
    "- Private operating runbooks, logging, routing, or validation records.",
    "- Any backend or cloud-specific runtime.",
    "",
    "Use `fedramp_generate_ads_bundle` if you also need the internal controlled/private scaffolding.",
    "",
    `Provider name: ${metadata.providerName}`,
    `Offering name: ${metadata.offeringName}`,
    `Primary domain: ${metadata.primaryDomain}`,
    `Support email: ${metadata.supportEmail}`,
    `Official process: ${plan.process.name} [${plan.process.shortName}]`,
    `FRMR version: ${loaded.provenance.version}`,
    "",
    "Suggested deployment targets:",
    "- AWS: upload the generated files to S3, front them with CloudFront, and attach your customer-owned ACM certificate.",
    "- Azure: upload the generated files to Azure Storage Static Website, then front them with Front Door or Azure CDN.",
    "- GCP: upload the generated files to Cloud Storage and front them with an HTTPS load balancer or CDN.",
    "",
    "Deployment notes:",
    "- This output is static by design. No application server is required.",
    "- Keep the generated file paths intact so the relative links and `sitemap.xml` remain valid.",
    "- Replace all TODO fields before publishing to a public domain.",
    "- Review `_source.json` and keep it if you want provenance for internal traceability.",
    "",
    "Public files:",
    "- `index.html`",
    "- `services/index.html`",
    "- `access/index.html`",
    "- `history/index.html`",
    "- `authorization-data.json`",
    "- `service-inventory.json`",
    "- `assets/site.css`",
    "",
    "Grounding:",
    `- Source repo: ${loaded.provenance.repo}`,
    `- Source path: ${loaded.provenance.path}`,
    `- Source branch: ${loaded.provenance.branch}`,
    `- Source blob SHA: ${loaded.provenance.blobSha ?? "Unavailable"}`,
    `- Upstream last updated: ${loaded.provenance.upstreamLastUpdated}`,
    `- Cache status during generation: ${loaded.cacheStatus}`,
  ];

  return `${lines.join("\n")}\n`;
}

function buildAdsSiteCss(): string {
  return `:root {
  color-scheme: dark;
  --bg: oklch(0.2 0.022 255);
  --bg-elevated: oklch(0.25 0.026 255);
  --bg-panel: color-mix(in oklch, var(--bg-elevated) 86%, oklch(0.58 0.06 140) 14%);
  --ink: oklch(0.92 0.018 250);
  --muted: oklch(0.78 0.018 250);
  --line: oklch(0.42 0.03 246 / 0.48);
  --accent: oklch(0.8 0.12 145);
  --accent-soft: oklch(0.68 0.07 150);
  --warning: oklch(0.82 0.1 80);
  --shadow: 0 24px 80px oklch(0.06 0.02 250 / 0.42);
  --serif: "Iowan Old Style", "Palatino Linotype", "Book Antiqua", Georgia, serif;
  --sans: "Aptos", "Segoe UI", "Helvetica Neue", Arial, sans-serif;
}

* { box-sizing: border-box; }
html { background: var(--bg); }
body {
  margin: 0;
  min-height: 100vh;
  background:
    radial-gradient(circle at top, oklch(0.36 0.05 150 / 0.18), transparent 0 38rem),
    linear-gradient(180deg, color-mix(in oklch, var(--bg) 84%, oklch(0.28 0.03 150) 16%), var(--bg));
  color: var(--ink);
  font-family: var(--sans);
  line-height: 1.6;
}

body::before {
  content: "";
  position: fixed;
  inset: 0;
  pointer-events: none;
  background:
    linear-gradient(var(--line) 1px, transparent 1px),
    linear-gradient(90deg, var(--line) 1px, transparent 1px);
  background-size: 2.75rem 2.75rem;
  mask-image: linear-gradient(180deg, oklch(0 0 0 / 0.3), transparent 85%);
  opacity: 0.28;
}

a { color: inherit; }

.site-shell {
  width: min(76rem, calc(100vw - 2rem));
  margin: 0 auto;
  padding: 1.25rem 0 3rem;
}

.topbar,
.panel,
.footer-panel {
  border: 1px solid var(--line);
  background: color-mix(in oklch, var(--bg-panel) 88%, black 12%);
  box-shadow: var(--shadow);
}

.topbar {
  display: grid;
  gap: 1rem;
  padding: 1rem 1.1rem;
  border-radius: 1.4rem;
  backdrop-filter: blur(12px);
}

.brand-row {
  display: flex;
  justify-content: space-between;
  gap: 1rem;
  align-items: start;
}

.brand-meta {
  display: grid;
  gap: 0.28rem;
}

.eyebrow {
  text-transform: uppercase;
  letter-spacing: 0.18em;
  font-size: 0.72rem;
  color: var(--accent);
}

.brand-title {
  margin: 0;
  font-family: var(--serif);
  font-size: clamp(2rem, 5vw, 3.6rem);
  line-height: 0.94;
}

.brand-copy {
  max-width: 40rem;
  margin: 0;
  color: var(--muted);
}

.meta-strip {
  display: flex;
  flex-wrap: wrap;
  gap: 0.65rem;
}

.meta-pill,
.site-nav-link,
.action-link {
  display: inline-flex;
  align-items: center;
  gap: 0.45rem;
  min-height: 2.6rem;
  padding: 0.55rem 0.95rem;
  border-radius: 999px;
  border: 1px solid var(--line);
  text-decoration: none;
}

.meta-pill {
  color: var(--muted);
  background: color-mix(in oklch, var(--bg-elevated) 72%, black 28%);
}

.site-nav {
  display: flex;
  flex-wrap: wrap;
  gap: 0.7rem;
}

.site-nav-link {
  color: var(--muted);
  background: transparent;
}

.site-nav-link.is-active,
.action-link.primary {
  color: oklch(0.16 0.015 250);
  background: linear-gradient(135deg, var(--accent), color-mix(in oklch, var(--accent) 66%, white 34%));
  border-color: transparent;
}

.action-link.secondary {
  color: var(--ink);
  background: color-mix(in oklch, var(--bg-elevated) 72%, black 28%);
}

.hero-grid,
.content-grid {
  display: grid;
  gap: 1rem;
  margin-top: 1rem;
}

.hero-grid {
  grid-template-columns: minmax(0, 1.7fr) minmax(18rem, 1fr);
}

.panel {
  border-radius: 1.5rem;
  padding: 1.25rem;
}

.lede {
  margin: 0;
  color: var(--muted);
}

.action-row {
  display: flex;
  flex-wrap: wrap;
  gap: 0.75rem;
  margin-top: 1.2rem;
}

.stats-grid {
  display: grid;
  gap: 0.8rem;
}

.stat {
  padding-bottom: 0.8rem;
  border-bottom: 1px solid color-mix(in oklch, var(--line) 78%, transparent 22%);
}

.stat:last-child { border-bottom: 0; padding-bottom: 0; }

.stat-label {
  display: block;
  font-size: 0.8rem;
  letter-spacing: 0.12em;
  text-transform: uppercase;
  color: var(--accent-soft);
}

.stat-value {
  margin-top: 0.2rem;
  font-size: 1rem;
}

.section-grid {
  display: grid;
  gap: 1rem;
  grid-template-columns: repeat(12, minmax(0, 1fr));
  margin-top: 1rem;
}

.section-grid > section,
.section-grid > aside {
  grid-column: span 6;
}

.section-kicker {
  display: inline-block;
  color: var(--accent-soft);
  text-transform: uppercase;
  letter-spacing: 0.14em;
  font-size: 0.78rem;
}

.section-title {
  margin: 0.3rem 0 0.7rem;
  font-family: var(--serif);
  font-size: clamp(1.5rem, 3vw, 2.15rem);
  line-height: 1;
}

.section-copy,
.footer-copy,
.artifact-list p,
.rollout-list p,
.empty-copy,
.provenance,
.history-table td,
.history-table th {
  color: var(--muted);
}

.artifact-list,
.rollout-list,
.endpoint-list,
.checklist,
.footer-links {
  list-style: none;
  margin: 0;
  padding: 0;
}

.artifact-list,
.endpoint-list,
.checklist {
  display: grid;
  gap: 0.75rem;
}

.artifact-list li,
.endpoint-list li,
.rollout-list li,
.checklist li {
  padding: 0.9rem 1rem;
  border-radius: 1.1rem;
  border: 1px solid color-mix(in oklch, var(--line) 76%, transparent 24%);
  background: color-mix(in oklch, var(--bg-elevated) 78%, black 22%);
}

.artifact-list h3,
.rollout-list h3,
.endpoint-list h3 {
  margin: 0 0 0.3rem;
  font-size: 1rem;
}

.artifact-meta,
.tiny-note {
  font-size: 0.9rem;
}

.rollout-list { display: grid; gap: 0.75rem; }
.rollout-list ul { margin: 0.7rem 0 0; padding-left: 1.15rem; color: var(--muted); }

.provenance {
  margin-top: 1rem;
  padding-top: 1rem;
  border-top: 1px solid color-mix(in oklch, var(--line) 78%, transparent 22%);
  font-size: 0.93rem;
}

.history-table {
  width: 100%;
  border-collapse: collapse;
  overflow: hidden;
  border-radius: 1rem;
}

.history-table th,
.history-table td {
  padding: 0.9rem 0.8rem;
  border-bottom: 1px solid color-mix(in oklch, var(--line) 78%, transparent 22%);
  text-align: left;
}

.history-table thead th {
  color: var(--ink);
  text-transform: uppercase;
  font-size: 0.8rem;
  letter-spacing: 0.12em;
}

.footer-panel {
  margin-top: 1rem;
  border-radius: 1.4rem;
  padding: 1rem 1.1rem 1.2rem;
}

.footer-links {
  display: flex;
  flex-wrap: wrap;
  gap: 0.7rem;
  margin-top: 0.9rem;
}

.footer-links a { color: var(--muted); text-decoration: none; }

.mono-chip {
  display: inline-flex;
  align-items: center;
  gap: 0.45rem;
  min-height: 2rem;
  padding: 0.4rem 0.7rem;
  border-radius: 999px;
  background: color-mix(in oklch, var(--bg-elevated) 76%, black 24%);
  border: 1px solid color-mix(in oklch, var(--line) 76%, transparent 24%);
  color: var(--muted);
  font-size: 0.9rem;
}

.mono-chip strong {
  color: var(--ink);
  font-weight: 600;
}

@media (max-width: 860px) {
  .hero-grid,
  .section-grid {
    grid-template-columns: 1fr;
  }

  .section-grid > section,
  .section-grid > aside {
    grid-column: auto;
  }

  .brand-row {
    flex-direction: column;
  }
}

@media (max-width: 640px) {
  .site-shell {
    width: min(100vw - 1rem, 76rem);
    padding-top: 0.75rem;
    padding-bottom: 2rem;
  }

  .panel,
  .topbar,
  .footer-panel {
    border-radius: 1.1rem;
    padding: 1rem;
  }

  .action-link,
  .site-nav-link,
  .meta-pill {
    width: 100%;
    justify-content: center;
  }

  .footer-links {
    display: grid;
  }
}
`;
}

function buildAdsSiteDocument(
  metadata: AdsSiteMetadata,
  loaded: Awaited<ReturnType<typeof loadFedrampCatalog>>,
  plan: AdsPackagePlan,
  options: {
    title: string;
    description: string;
    prefix: string;
    current: "home" | "services" | "access" | "history";
    main: string;
  },
): string {
  const nav = [
    navLink(options.prefix, "", "Overview", options.current === "home"),
    navLink(options.prefix, "services/", "Services", options.current === "services"),
    navLink(options.prefix, "access/", "Access", options.current === "access"),
    navLink(options.prefix, "history/", "History", options.current === "history"),
  ].join("");
  const sourceNote = formatProvenanceNote({
    repo: loaded.provenance.repo,
    path: loaded.provenance.path,
    branch: loaded.provenance.branch,
    blobSha: loaded.provenance.blobSha,
    version: loaded.provenance.version,
    upstreamLastUpdated: loaded.provenance.upstreamLastUpdated,
    cacheStatus: loaded.cacheStatus,
  });

  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>${escapeHtml(options.title)} · ${escapeHtml(metadata.siteTitle)}</title>
    <meta name="description" content="${escapeHtml(options.description)}" />
    <link rel="stylesheet" href="${escapeHtml(pageHref(options.prefix, "assets/site.css"))}" />
  </head>
  <body>
    <div class="site-shell">
      <header class="topbar">
        <div class="brand-row">
          <div class="brand-meta">
            <span class="eyebrow">Authorization Data Sharing // Public Trust Center</span>
            <h1 class="brand-title">${escapeHtml(metadata.siteTitle)}</h1>
            <p class="brand-copy">A portable public trust-center scaffold grounded in the official FedRAMP GitHub FRMR source. Replace the TODO fields with your customer-facing service posture, scope, and access narrative.</p>
          </div>
          <div class="meta-strip">
            <span class="meta-pill">Provider · ${escapeHtml(metadata.providerName)}</span>
            <span class="meta-pill">Offering · ${escapeHtml(metadata.offeringName)}</span>
            <span class="meta-pill">Applies to · ${escapeHtml(plan.appliesTo.toUpperCase())}</span>
          </div>
        </div>
        <nav class="site-nav" aria-label="Trust center navigation">${nav}</nav>
      </header>
      ${options.main}
      <footer class="footer-panel">
        <p class="footer-copy">This site only covers the public layer. Controlled-access and private operational materials should stay outside the public host and can be scaffolded separately with grclanker's ADS bundle generator.</p>
        <div class="footer-links">
          <a href="${escapeHtml(pageHref(options.prefix, "authorization-data.json"))}">authorization-data.json</a>
          <a href="${escapeHtml(pageHref(options.prefix, "service-inventory.json"))}">service-inventory.json</a>
          <a href="${escapeHtml(pageHref(options.prefix, "_source.json"))}">_source.json</a>
          <a href="mailto:${escapeHtml(metadata.supportEmail)}">${escapeHtml(metadata.supportEmail)}</a>
        </div>
        <p class="provenance">${escapeHtml(sourceNote)}</p>
      </footer>
    </div>
  </body>
</html>
`;
}

function buildAdsOverviewPage(
  metadata: AdsSiteMetadata,
  loaded: Awaited<ReturnType<typeof loadFedrampCatalog>>,
  plan: AdsPackagePlan,
): string {
  const main = `<main>
    <section class="hero-grid">
      <article class="panel">
        <span class="section-kicker">Public summary</span>
        <h2 class="section-title">Publish the minimum agency-facing truth without waiting on a portal rebuild.</h2>
        <p class="lede">Replace this page with your actual offering summary, boundary statement, FedRAMP status, and links to customer-facing authorization materials. The structure is already aligned to the official ADS process, but the facts still need to come from your team.</p>
        <div class="action-row">
          <a class="action-link primary" href="authorization-data.json">Machine-readable data</a>
          <a class="action-link secondary" href="services/">Scope and services</a>
          <a class="action-link secondary" href="access/">Access guidance</a>
        </div>
      </article>
      <aside class="panel stats-grid" aria-label="Trust center facts">
        <div class="stat"><span class="stat-label">Primary domain</span><div class="stat-value">${escapeHtml(metadata.primaryDomain)}</div></div>
        <div class="stat"><span class="stat-label">Support contact</span><div class="stat-value"><a href="mailto:${escapeHtml(metadata.supportEmail)}">${escapeHtml(metadata.supportEmail)}</a></div></div>
        <div class="stat"><span class="stat-label">Official process</span><div class="stat-value">${escapeHtml(plan.process.name)} [${escapeHtml(plan.process.shortName)}]</div></div>
        <div class="stat"><span class="stat-label">Marketplace URL</span><div class="stat-value">TODO</div></div>
      </aside>
    </section>

    <div class="section-grid">
      <section class="panel">
        <span class="section-kicker">Public artifacts</span>
        <h2 class="section-title">What this public site should expose</h2>
        <p class="section-copy">These public-facing surfaces were inferred from the official FedRAMP process text. Keep them customer-readable, current, and stable enough for agencies to cite.</p>
        ${renderArtifactList(plan.publicItems)}
      </section>
      <aside class="panel">
        <span class="section-kicker">Rollout order</span>
        <h2 class="section-title">Suggested publication sequence</h2>
        <p class="section-copy">Start with the public baseline, then add controlled retrieval. The private runbooks stay out of this site.</p>
        ${renderRolloutSummary(plan)}
      </aside>
      <section class="panel">
        <span class="section-kicker">Narrative</span>
        <h2 class="section-title">Replace this with your offering summary</h2>
        <p class="section-copy">TODO: describe the offering in plain language, explain the current authorization posture, and clarify which services and customer responsibilities are included in the public summary.</p>
        <p class="section-copy">TODO: add a short statement about how agencies or customers can retrieve deeper authorization materials without exposing controlled or private content on this host.</p>
      </section>
      <aside class="panel">
        <span class="section-kicker">Public endpoints</span>
        <h2 class="section-title">Machine-readable companion files</h2>
        <ul class="endpoint-list">
          <li><h3><a href="authorization-data.json">authorization-data.json</a></h3><p>Public authorization-data skeleton for machine-readable retrieval.</p></li>
          <li><h3><a href="service-inventory.json">service-inventory.json</a></h3><p>Service inventory and scope skeleton that should stay synchronized with the human-readable services page.</p></li>
          <li><h3><a href="_source.json">_source.json</a></h3><p>Generation provenance tying this scaffold back to the official FRMR source snapshot.</p></li>
        </ul>
      </aside>
    </div>
  </main>`;

  return buildAdsSiteDocument(metadata, loaded, plan, {
    title: "Overview",
    description: `${metadata.siteTitle} public summary and machine-readable ADS endpoints.`,
    prefix: "",
    current: "home",
    main,
  });
}

function buildAdsServicesPage(
  metadata: AdsSiteMetadata,
  loaded: Awaited<ReturnType<typeof loadFedrampCatalog>>,
  plan: AdsPackagePlan,
): string {
  const main = `<main class="content-grid">
    <section class="panel">
      <span class="section-kicker">Scope</span>
      <h2 class="section-title">Services and minimum assessment scope</h2>
      <p class="section-copy">This page is where you publish the public service inventory, included components, and customer-responsibility framing. Keep the language synchronized with <a href="../service-inventory.json">service-inventory.json</a>.</p>
      <table class="history-table">
        <thead>
          <tr><th>Service</th><th>Model</th><th>In scope</th><th>Notes</th></tr>
        </thead>
        <tbody>
          <tr><td>TODO</td><td>TODO</td><td>Yes</td><td>TODO</td></tr>
          <tr><td>TODO</td><td>TODO</td><td>No</td><td>TODO</td></tr>
        </tbody>
      </table>
    </section>
    <div class="section-grid">
      <section class="panel">
        <span class="section-kicker">Shared responsibility</span>
        <h2 class="section-title">Clarify who operates what</h2>
        <p class="section-copy">TODO: explain the provider-managed security boundary, the customer-managed responsibilities, and any assumptions that would affect agency reviewers or customer deployment teams.</p>
        <ul class="checklist">
          <li>TODO: boundary statement</li>
          <li>TODO: customer-managed configurations</li>
          <li>TODO: service dependencies and exclusions</li>
        </ul>
      </section>
      <aside class="panel">
        <span class="section-kicker">Grounding</span>
        <h2 class="section-title">Why this page exists</h2>
        <p class="section-copy">This page is scaffolded from the official ADS process artifacts inferred for public publication. Update it whenever the service inventory, scope, or customer-responsibility model changes.</p>
        ${renderArtifactList(plan.publicItems.filter((item) => item.name.toLowerCase().includes("service inventory")))}
      </aside>
    </div>
  </main>`;

  return buildAdsSiteDocument(metadata, loaded, plan, {
    title: "Services",
    description: `${metadata.siteTitle} service inventory and scope summary.`,
    prefix: "../",
    current: "services",
    main,
  });
}

function buildAdsAccessPage(
  metadata: AdsSiteMetadata,
  loaded: Awaited<ReturnType<typeof loadFedrampCatalog>>,
  plan: AdsPackagePlan,
): string {
  const main = `<main class="content-grid">
    <section class="panel">
      <span class="section-kicker">Access</span>
      <h2 class="section-title">Public endpoints and controlled retrieval</h2>
      <p class="section-copy">Use this page to explain what is openly published, what requires controlled retrieval, and how agencies or necessary parties should request deeper authorization data.</p>
      <ul class="endpoint-list">
        <li><h3><a href="../authorization-data.json">authorization-data.json</a></h3><p>Public machine-readable summary intended for broad retrieval.</p></li>
        <li><h3><a href="../service-inventory.json">service-inventory.json</a></h3><p>Public service and scope summary intended to stay aligned with the public site narrative.</p></li>
        <li><h3>Controlled retrieval path</h3><p>TODO: document the request channel, reviewer expectations, and response model for deeper authorization materials.</p></li>
      </ul>
    </section>
    <div class="section-grid">
      <section class="panel">
        <span class="section-kicker">Request flow</span>
        <h2 class="section-title">Replace this with your real access procedure</h2>
        <ol class="rollout-list">
          <li><h3>Step 1</h3><p>TODO: identify the request intake path and required requester information.</p></li>
          <li><h3>Step 2</h3><p>TODO: describe validation, approval, and delivery expectations.</p></li>
          <li><h3>Step 3</h3><p>TODO: explain expiration, renewal, or follow-up rules.</p></li>
        </ol>
      </section>
      <aside class="panel">
        <span class="section-kicker">Controlled artifacts</span>
        <h2 class="section-title">Not public, but planned</h2>
        <p class="section-copy">These artifact categories belong in the controlled-access lane, not on the public host itself.</p>
        ${renderArtifactList(plan.controlledItems)}
      </aside>
    </div>
  </main>`;

  return buildAdsSiteDocument(metadata, loaded, plan, {
    title: "Access",
    description: `${metadata.siteTitle} public and controlled access guidance.`,
    prefix: "../",
    current: "access",
    main,
  });
}

function buildAdsHistoryPage(
  metadata: AdsSiteMetadata,
  loaded: Awaited<ReturnType<typeof loadFedrampCatalog>>,
  plan: AdsPackagePlan,
): string {
  const main = `<main class="content-grid">
    <section class="panel">
      <span class="section-kicker">History</span>
      <h2 class="section-title">Version history and update notes</h2>
      <p class="section-copy">Use this page to document what changed, when it changed, and where a reviewer should go to compare current and prior public authorization summaries.</p>
      <table class="history-table">
        <thead>
          <tr><th>Version</th><th>Effective date</th><th>Summary</th><th>Delta link</th></tr>
        </thead>
        <tbody>
          <tr><td>TODO</td><td>TODO</td><td>TODO</td><td>TODO</td></tr>
        </tbody>
      </table>
    </section>
    <div class="section-grid">
      <section class="panel">
        <span class="section-kicker">Update policy</span>
        <h2 class="section-title">State the public refresh cadence</h2>
        <ul class="checklist">
          <li>TODO: expected refresh cadence for human-readable summary</li>
          <li>TODO: expected refresh cadence for machine-readable files</li>
          <li>TODO: retention period for prior versions</li>
        </ul>
      </section>
      <aside class="panel">
        <span class="section-kicker">Grounding</span>
        <h2 class="section-title">Why the history surface matters</h2>
        ${renderArtifactList(plan.publicItems.filter((item) => item.name.toLowerCase().includes("version history")))}
      </aside>
    </div>
  </main>`;

  return buildAdsSiteDocument(metadata, loaded, plan, {
    title: "History",
    description: `${metadata.siteTitle} change history and publication retention notes.`,
    prefix: "../",
    current: "history",
    main,
  });
}

function buildAds404Page(metadata: AdsSiteMetadata): string {
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Not found · ${escapeHtml(metadata.siteTitle)}</title>
    <link rel="stylesheet" href="assets/site.css" />
  </head>
  <body>
    <div class="site-shell">
      <main class="panel">
        <span class="section-kicker">404</span>
        <h1 class="section-title">This trust-center path is not published.</h1>
        <p class="section-copy">Return to the overview, then use the public navigation to find the current summary, access guidance, or history pages.</p>
        <div class="action-row">
          <a class="action-link primary" href="./">Back to overview</a>
        </div>
      </main>
    </div>
  </body>
</html>
`;
}

function buildAdsRobotsTxt(metadata: AdsSiteMetadata): string {
  return `User-agent: *\nAllow: /\nSitemap: ${metadata.baseUrl}/sitemap.xml\n`;
}

function buildAdsSitemapXml(metadata: AdsSiteMetadata): string {
  const pages = ["", "/services/", "/access/", "/history/"];
  const urls = pages
    .map(
      (path) =>
        `  <url>\n    <loc>${escapeHtml(`${metadata.baseUrl}${path}`)}</loc>\n  </url>`,
    )
    .join("\n");
  return `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${urls}\n</urlset>\n`;
}

export function buildFedrampAdsSite(
  loaded: Awaited<ReturnType<typeof loadFedrampCatalog>>,
  args: AdsSiteArgs,
): AdsPublicSite {
  const metadata = buildAdsSiteMetadata(args);
  const plan = buildFedrampAdsPackagePlan(loaded, {
    applies_to: args.applies_to,
    audience: args.audience,
  });

  const files: BundleTemplateFile[] = [
    { path: "README.md", content: buildAdsSiteReadme(loaded, plan, metadata) },
    { path: "_source.json", content: buildAdsSiteSourceMetadataFile(loaded, plan, metadata) },
    { path: "assets/site.css", content: buildAdsSiteCss() },
    { path: "index.html", content: buildAdsOverviewPage(metadata, loaded, plan) },
    { path: "services/index.html", content: buildAdsServicesPage(metadata, loaded, plan) },
    { path: "access/index.html", content: buildAdsAccessPage(metadata, loaded, plan) },
    { path: "history/index.html", content: buildAdsHistoryPage(metadata, loaded, plan) },
    { path: "404.html", content: buildAds404Page(metadata) },
    { path: "robots.txt", content: buildAdsRobotsTxt(metadata) },
    { path: "sitemap.xml", content: buildAdsSitemapXml(metadata) },
    {
      path: "authorization-data.json",
      content: buildAdsSiteAuthorizationDataJson(plan, metadata),
    },
    {
      path: "service-inventory.json",
      content: buildAdsSiteServiceInventoryJson(plan, metadata),
    },
  ];

  return {
    bundleName: ADS_SITE_DIRNAME,
    files,
    plan,
    metadata,
  };
}

export async function generateFedrampAdsSite(
  loaded: Awaited<ReturnType<typeof loadFedrampCatalog>>,
  outputRoot: string,
  args: AdsSiteArgs,
): Promise<AdsPublicSiteResult> {
  ensurePrivateDir(outputRoot);
  const canonicalOutputRoot = realpathSync(outputRoot);
  const site = buildFedrampAdsSite(loaded, args);
  const outputDir = nextAvailableBundleDir(canonicalOutputRoot, site.bundleName);
  ensurePrivateDir(outputDir);

  const writtenFiles: string[] = [];
  for (const file of site.files) {
    const absolutePath = await writeSecureTextFile(outputDir, resolve(outputDir, file.path), file.content);
    writtenFiles.push(absolutePath);
  }

  return {
    outputDir,
    files: writtenFiles,
    plan: site.plan,
    metadata: site.metadata,
  };
}

function inferFedrampArtifactPlanItems(
  requirements: FedrampRequirementRecord[],
  indicators: FedrampKsiIndicatorRecord[],
): ArtifactPlanItem[] {
  const items: ArtifactPlanItem[] = [];

  for (const rule of ARTIFACT_RULES) {
    const requirementMatches = requirements.filter((requirement) =>
      rule.patterns.some((pattern) => pattern.test(requirementText(requirement))),
    );
    const indicatorMatches = indicators.filter((indicator) =>
      rule.patterns.some((pattern) => pattern.test(indicatorText(indicator))),
    );

    if (requirementMatches.length === 0 && indicatorMatches.length === 0) continue;

    items.push({
      name: rule.name,
      visibility: rule.visibility,
      phase: rule.phase,
      format: rule.format,
      rationale: rule.rationale,
      groundedBy: dedupeStrings(requirementMatches.map((requirement) => requirement.id)).slice(0, 4),
    });
  }

  return items;
}

function formatArtifactPlanItem(item: ArtifactPlanItem): string {
  const groundedBy = item.groundedBy.length > 0 ? item.groundedBy.join(", ") : "linked KSI or process text";
  return `- ${item.name} [${formatVisibility(item.visibility)} · ${formatPhase(item.phase)} · ${item.format}] — ${item.rationale} Grounded by: ${groundedBy}.`;
}

function buildArtifactPlanContext(
  loaded: Awaited<ReturnType<typeof loadFedrampCatalog>>,
  args: PlanningArgs,
): ArtifactPlanContext {
  const appliesTo = args.applies_to ?? "any";

  try {
    const process = resolveFedrampProcess(loaded.catalog, args.query);
    const requirements = filterRequirementsByApplicability(
      processRequirements(loaded.catalog, process.id),
      appliesTo,
    );
    const linkedIndicators = loaded.catalog.ksiIndicators.filter(
      (indicator) => resolveLinkedProcess(loaded, indicator.reference)?.id === process.id,
    );
    return {
      kind: "process",
      subject: process,
      linkedProcesses: [process],
      linkedIndicators,
      requirements,
    };
  } catch {
    const match = resolveFedrampKsi(loaded.catalog, args.query);
    if (match.kind === "indicator") {
      const linkedProcess = resolveLinkedProcess(loaded, match.indicator.reference);
      const linkedProcesses = linkedProcess ? [linkedProcess] : [];
      const requirements = linkedProcess
        ? filterRequirementsByApplicability(processRequirements(loaded.catalog, linkedProcess.id), appliesTo)
        : [];
      return {
        kind: "ksi-indicator",
        subject: match.indicator,
        linkedProcesses,
        linkedIndicators: [match.indicator],
        requirements,
      };
    }

    const linkedIndicators = domainIndicators(loaded.catalog, match.domain.id);
    const linkedProcesses = dedupeStrings(
      linkedIndicators
        .map((indicator) => resolveLinkedProcess(loaded, indicator.reference)?.id ?? "")
        .filter(Boolean),
    )
      .map((processId) => loaded.catalog.processes.find((process) => process.id === processId))
      .filter((process): process is FedrampProcessRecord => Boolean(process));
    const requirements = linkedProcesses.flatMap((process) =>
      filterRequirementsByApplicability(processRequirements(loaded.catalog, process.id), appliesTo),
    );
    return {
      kind: "ksi-domain",
      subject: match.domain,
      linkedProcesses,
      linkedIndicators,
      requirements,
    };
  }
}

export function inferFedrampArtifactSuggestions(
  processIds: string[],
  requirements: FedrampRequirementRecord[],
  indicators: FedrampKsiIndicatorRecord[],
): string[] {
  const text = [
    ...requirements.map((requirement) => requirement.statement),
    ...requirements.flatMap((requirement) => requirement.followingInformation),
    ...indicators.map((indicator) => indicator.statement),
  ].join(" \n ");

  const suggestions: string[] = [];
  const lower = text.toLowerCase();

  if (/human-readable|machine-readable|publicly share|public webpage/.test(lower)) {
    suggestions.push("Public trust-center or documentation page plus a machine-readable authorization data feed.");
  }
  if (/programmatic access|api|download/.test(lower)) {
    suggestions.push("Documented API or export interface for authorization data, including access instructions.");
  }
  if (/inventory|history/.test(lower)) {
    suggestions.push("Access inventory or history export showing who can view or retrieve authorization data.");
  }
  if (/log access|log access|access log/.test(lower)) {
    suggestions.push("Access-log summaries for authorization data and trust-center activity.");
  }
  if (/plan and process|procedure|methodology/.test(lower)) {
    suggestions.push("Written process or methodology documents for the relevant FedRAMP workflow.");
  }
  if (/report|quarterly review|ongoing authorization report|oar/.test(lower)) {
    suggestions.push("Recurring report artifacts, such as ongoing authorization or quarterly review outputs.");
  }
  if (/notify|notification|inbox/.test(lower)) {
    suggestions.push("Notification runbook, inbox ownership, and escalation routing records.");
  }
  if (/validate|validation|cadence|persistently/.test(lower)) {
    suggestions.push("Automated validation job evidence and cadence records showing continuous checks.");
  }
  if (/secure configuration|configuration guidance|shared responsibility/.test(lower) || processIds.includes("SCG")) {
    suggestions.push("Secure configuration guide plus shared-responsibility guidance for customers.");
  }
  if (/vulnerability|accepted vulnerability|remediation/.test(lower) || processIds.includes("VDR")) {
    suggestions.push("Vulnerability handling evidence, remediation tracking, and accepted-risk records.");
  }
  if (/cryptographic module|fips|cmvp/.test(lower) || processIds.includes("UCM")) {
    suggestions.push("Cryptographic module inventory and CMVP or FIPS references for relevant protections.");
  }
  if (/incident/.test(lower) || processIds.includes("ICP") || processIds.includes("FSI")) {
    suggestions.push("Incident communications procedure, government contact path, and inbox operations evidence.");
  }
  if (/scope|service list|boundary|customer responsibilities/.test(lower) || processIds.includes("MAS")) {
    suggestions.push("Service inventory, boundary description, and minimum assessment scope record.");
  }
  if (/independent assessment|assessor/.test(lower) || processIds.includes("PVA")) {
    suggestions.push("Independent assessment outputs preserved without modification, plus validation linkage to VDR.");
  }

  return dedupeStrings(suggestions).slice(0, 8);
}

export function inferFedrampWorkstreams(
  processIds: string[],
  requirements: FedrampRequirementRecord[],
  indicators: FedrampKsiIndicatorRecord[],
): string[] {
  const workstreams = new Set<string>();

  const mapped = {
    ADS: [
      "authorization data publishing",
      "trust-center operations",
      "programmatic access",
      "access inventory and access logging",
    ],
    CCM: [
      "ongoing authorization reporting",
      "quarterly review operations",
      "continuous monitoring coordination",
    ],
    FSI: ["security inbox operations", "government contact routing"],
    ICP: ["incident communications", "government notification workflow"],
    MAS: ["assessment scope definition", "service inventory and boundary management"],
    PVA: [
      "persistent validation automation",
      "validation cadence tracking",
      "assessment-result intake",
      "VDR linkage",
    ],
    SCG: ["secure-by-default configuration", "customer hardening guidance"],
    SCN: ["change governance", "significant-change notification workflow"],
    UCM: ["cryptographic module inventory", "approved cryptography usage"],
    VDR: ["vulnerability detection", "remediation tracking", "accepted-risk handling"],
  } as const;

  for (const processId of processIds) {
    for (const item of mapped[processId as keyof typeof mapped] ?? []) {
      workstreams.add(item);
    }
  }

  const lower = [
    ...requirements.map((requirement) => requirement.statement),
    ...indicators.map((indicator) => indicator.statement),
  ]
    .join(" \n ")
    .toLowerCase();

  if (/machine-readable|human-readable/.test(lower)) workstreams.add("public documentation and machine-readable publishing");
  if (/programmatic access|api/.test(lower)) workstreams.add("API enablement for authorization data");
  if (/persistently|validation/.test(lower)) workstreams.add("continuous validation and evidence capture");
  if (/log access|inventory/.test(lower)) workstreams.add("access governance and auditability");
  if (/notify|notification/.test(lower)) workstreams.add("notification and escalation management");
  if (/incident/.test(lower)) workstreams.add("incident response coordination");

  return Array.from(workstreams).slice(0, 8);
}

function resolveLinkedProcess(
  loaded: Awaited<ReturnType<typeof loadFedrampCatalog>>,
  reference: string | null,
): FedrampProcessRecord | undefined {
  if (!reference) return undefined;
  const normalized = reference.trim().toLowerCase();
  return loaded.catalog.processes.find((process) =>
    [
      process.id,
      process.name,
      process.shortName,
      process.webName,
    ].some((candidate) => candidate.trim().toLowerCase() === normalized),
  );
}

export function buildFedrampReadinessBrief(
  loaded: Awaited<ReturnType<typeof loadFedrampCatalog>>,
  args: ReadinessArgs,
): ReadinessBrief {
  const audience = args.audience ?? "provider";
  const appliesTo = args.applies_to ?? "any";
  const limit = args.limit ?? 8;

  try {
    const process = resolveFedrampProcess(loaded.catalog, args.query);
    const allRequirements = processRequirements(loaded.catalog, process.id);
    const filteredRequirements = filterRequirementsByApplicability(allRequirements, appliesTo);
    const prioritized = filteredRequirements
      .slice()
      .sort((left, right) => {
        const delta = requirementPriority(right, audience) - requirementPriority(left, audience);
        return delta !== 0 ? delta : left.id.localeCompare(right.id);
      })
      .slice(0, limit);
    const linkedIndicators = loaded.catalog.ksiIndicators.filter(
      (indicator) =>
        resolveLinkedProcess(loaded, indicator.reference)?.id === process.id,
    );
    const artifactSuggestions = inferFedrampArtifactSuggestions([process.id], filteredRequirements, linkedIndicators);
    const workstreams = inferFedrampWorkstreams([process.id], filteredRequirements, linkedIndicators);
    const checklist = toChecklistItems(prioritized);
    const lines = [
      `${process.name} readiness brief`,
      `Audience:        ${audience}`,
      `Applies to:      ${appliesTo}`,
      `Official page:   ${process.sourceUrl ?? "Unavailable"}`,
      "",
      "Priority checklist:",
      ...checklist.map((item) => `- [${item.keyword ?? "INFO"}] ${item.id} (${item.appliesTo}, ${item.labelCode}) — ${item.statement}`),
    ];

    if (artifactSuggestions.length > 0) {
      lines.push("", "Likely artifacts to have ready (inferred from official requirements):");
      for (const artifact of artifactSuggestions) lines.push(`- ${artifact}`);
    }

    if (workstreams.length > 0) {
      lines.push("", "Operational workstreams (inferred from official requirements):");
      for (const workstream of workstreams) lines.push(`- ${workstream}`);
    }

    if (linkedIndicators.length > 0) {
      lines.push("", "Linked KSI indicators:");
      for (const indicator of linkedIndicators.slice(0, 6)) {
        lines.push(`- ${indicator.id} — ${indicator.name}`);
      }
    }

    lines.push(
      "",
      formatProvenanceNote({
        repo: loaded.provenance.repo,
        path: loaded.provenance.path,
        branch: loaded.provenance.branch,
        blobSha: loaded.provenance.blobSha,
        version: loaded.provenance.version,
        upstreamLastUpdated: loaded.provenance.upstreamLastUpdated,
        cacheStatus: loaded.cacheStatus,
      }),
    );

    return {
      kind: "process",
      subject: process,
      linkedProcesses: [process],
      linkedIndicators,
      checklist,
      artifactSuggestions,
      workstreams,
      text: lines.join("\n"),
    };
  } catch {
    const match = resolveFedrampKsi(loaded.catalog, args.query);
    if (match.kind === "indicator") {
      const linkedProcess = resolveLinkedProcess(loaded, match.indicator.reference);
      const linkedProcesses = linkedProcess ? [linkedProcess] : [];
      const processRequirementsList = linkedProcess
        ? filterRequirementsByApplicability(processRequirements(loaded.catalog, linkedProcess.id), appliesTo)
        : [];
      const prioritized = processRequirementsList
        .slice()
        .sort((left, right) => {
          const delta = requirementPriority(right, audience) - requirementPriority(left, audience);
          return delta !== 0 ? delta : left.id.localeCompare(right.id);
        })
        .slice(0, limit);
      const checklist = toChecklistItems(prioritized);
      const artifactSuggestions = inferFedrampArtifactSuggestions(
        linkedProcesses.map((process) => process.id),
        processRequirementsList,
        [match.indicator],
      );
      const workstreams = inferFedrampWorkstreams(
        linkedProcesses.map((process) => process.id),
        processRequirementsList,
        [match.indicator],
      );
      const lines = [
        `${match.indicator.name} readiness brief`,
        `Audience:        ${audience}`,
        `Applies to:      20x${appliesTo !== "any" ? ` (requested filter: ${appliesTo})` : ""}`,
        `Linked process:  ${linkedProcess ? `${linkedProcess.name} [${linkedProcess.shortName}]` : "No direct process match found"}`,
        "",
        formatIndicatorSummary(match.indicator),
      ];

      if (checklist.length > 0) {
        lines.push("", "Priority process checklist:");
        for (const item of checklist) {
          lines.push(`- [${item.keyword ?? "INFO"}] ${item.id} (${item.appliesTo}, ${item.labelCode}) — ${item.statement}`);
        }
      }

      if (artifactSuggestions.length > 0) {
        lines.push("", "Likely artifacts to have ready (inferred from official sources):");
        for (const artifact of artifactSuggestions) lines.push(`- ${artifact}`);
      }

      if (workstreams.length > 0) {
        lines.push("", "Operational workstreams (inferred from official sources):");
        for (const workstream of workstreams) lines.push(`- ${workstream}`);
      }

      lines.push(
        "",
        formatProvenanceNote({
          repo: loaded.provenance.repo,
          path: loaded.provenance.path,
          branch: loaded.provenance.branch,
          blobSha: loaded.provenance.blobSha,
          version: loaded.provenance.version,
          upstreamLastUpdated: loaded.provenance.upstreamLastUpdated,
          cacheStatus: loaded.cacheStatus,
        }),
      );

      return {
        kind: "ksi-indicator",
        subject: match.indicator,
        linkedProcesses,
        linkedIndicators: [match.indicator],
        checklist,
        artifactSuggestions,
        workstreams,
        text: lines.join("\n"),
      };
    }

    const indicators = domainIndicators(loaded.catalog, match.domain.id);
    const linkedProcesses = dedupeStrings(
      indicators
        .map((indicator) => resolveLinkedProcess(loaded, indicator.reference)?.id ?? "")
        .filter(Boolean),
    )
      .map((processId) => loaded.catalog.processes.find((process) => process.id === processId))
      .filter((process): process is FedrampProcessRecord => Boolean(process));
    const linkedRequirements = linkedProcesses.flatMap((process) =>
      filterRequirementsByApplicability(processRequirements(loaded.catalog, process.id), appliesTo),
    );
    const prioritized = linkedRequirements
      .slice()
      .sort((left, right) => {
        const delta = requirementPriority(right, audience) - requirementPriority(left, audience);
        return delta !== 0 ? delta : left.id.localeCompare(right.id);
      })
      .slice(0, limit);
    const checklist = toChecklistItems(prioritized);
    const artifactSuggestions = inferFedrampArtifactSuggestions(
      linkedProcesses.map((process) => process.id),
      linkedRequirements,
      indicators,
    );
    const workstreams = inferFedrampWorkstreams(
      linkedProcesses.map((process) => process.id),
      linkedRequirements,
      indicators,
    );
    const lines = [
      `${match.domain.name} readiness brief`,
      `Audience:        ${audience}`,
      `Applies to:      20x${appliesTo !== "any" ? ` (requested filter: ${appliesTo})` : ""}`,
      "",
      match.domain.theme,
      "",
      "Linked processes:",
      ...linkedProcesses.map((process) => `- ${process.name} [${process.shortName}]`),
      "",
      "Indicators:",
      ...indicators.slice(0, 10).map((indicator) => `- ${indicator.id} — ${indicator.name}`),
    ];

    if (checklist.length > 0) {
      lines.push("", "Priority process checklist:");
      for (const item of checklist) {
        lines.push(`- [${item.keyword ?? "INFO"}] ${item.id} (${item.appliesTo}, ${item.labelCode}) — ${item.statement}`);
      }
    }

    if (artifactSuggestions.length > 0) {
      lines.push("", "Likely artifacts to have ready (inferred from official sources):");
      for (const artifact of artifactSuggestions) lines.push(`- ${artifact}`);
    }

    if (workstreams.length > 0) {
      lines.push("", "Operational workstreams (inferred from official sources):");
      for (const workstream of workstreams) lines.push(`- ${workstream}`);
    }

    lines.push(
      "",
      formatProvenanceNote({
        repo: loaded.provenance.repo,
        path: loaded.provenance.path,
        branch: loaded.provenance.branch,
        blobSha: loaded.provenance.blobSha,
        version: loaded.provenance.version,
        upstreamLastUpdated: loaded.provenance.upstreamLastUpdated,
        cacheStatus: loaded.cacheStatus,
      }),
    );

    return {
      kind: "ksi-domain",
      subject: match.domain,
      linkedProcesses,
      linkedIndicators: indicators,
      checklist,
      artifactSuggestions,
      workstreams,
      text: lines.join("\n"),
    };
  }
}

export function buildFedrampArtifactPlan(
  loaded: Awaited<ReturnType<typeof loadFedrampCatalog>>,
  args: PlanningArgs,
): ArtifactPlan {
  const audience = args.audience ?? "provider";
  const appliesTo = args.applies_to ?? "any";
  const context = buildArtifactPlanContext(loaded, args);
  const items = inferFedrampArtifactPlanItems(context.requirements, context.linkedIndicators);
  const rollout = buildRolloutPhases(items);

  const subjectName =
    context.kind === "process"
      ? context.subject.name
      : context.kind === "ksi-domain"
        ? context.subject.name
        : context.subject.name;
  const subjectLine =
    context.kind === "process"
      ? `Official page:   ${context.subject.sourceUrl ?? "Unavailable"}`
      : `Linked process:  ${context.linkedProcesses[0] ? `${context.linkedProcesses[0].name} [${context.linkedProcesses[0].shortName}]` : "No direct process match found"}`;
  const lines = [
    `${subjectName} artifact plan`,
    `Audience:        ${audience}`,
    `Applies to:      ${appliesTo}`,
    `Subject kind:    ${context.kind}`,
    subjectLine,
    "",
  ];

  const grouped = groupArtifactItemsByVisibility(items);

  const sections: Array<{ title: string; items: ArtifactPlanItem[] }> = [
    { title: "Public artifacts (inferred from official sources):", items: grouped.publicItems },
    { title: "Controlled-access artifacts (inferred from official sources):", items: grouped.controlledItems },
    { title: "Private operating artifacts (inferred from official sources):", items: grouped.privateItems },
  ];

  for (const section of sections) {
    if (section.items.length === 0) continue;
    lines.push(section.title);
    for (const item of section.items) lines.push(formatArtifactPlanItem(item));
    lines.push("");
  }

  if (rollout.length > 0) {
    lines.push("Recommended rollout order:");
    for (const phase of rollout) {
      lines.push(`- ${phase.title} — ${phase.objective}`);
      for (const item of phase.items) {
        lines.push(`  - ${item}`);
      }
    }
    lines.push("");
  }

  if (context.linkedIndicators.length > 0) {
    lines.push("Linked KSI indicators:");
    for (const indicator of context.linkedIndicators.slice(0, 6)) {
      lines.push(`- ${indicator.id} — ${indicator.name}`);
    }
    lines.push("");
  }

  lines.push(
    formatProvenanceNote({
      repo: loaded.provenance.repo,
      path: loaded.provenance.path,
      branch: loaded.provenance.branch,
      blobSha: loaded.provenance.blobSha,
      version: loaded.provenance.version,
      upstreamLastUpdated: loaded.provenance.upstreamLastUpdated,
      cacheStatus: loaded.cacheStatus,
    }),
  );

  const text = lines.join("\n");

  if (context.kind === "process") {
    return {
      kind: "process",
      subject: context.subject,
      linkedProcesses: context.linkedProcesses,
      linkedIndicators: context.linkedIndicators,
      items,
      rollout,
      text,
    };
  }

  if (context.kind === "ksi-indicator") {
    return {
      kind: "ksi-indicator",
      subject: context.subject,
      linkedProcesses: context.linkedProcesses,
      linkedIndicators: context.linkedIndicators,
      items,
      rollout,
      text,
    };
  }

  return {
    kind: "ksi-domain",
    subject: context.subject,
    linkedProcesses: context.linkedProcesses,
    linkedIndicators: context.linkedIndicators,
    items,
    rollout,
    text,
  };
}

export function buildFedrampAdsPackagePlan(
  loaded: Awaited<ReturnType<typeof loadFedrampCatalog>>,
  args: AdsPackageArgs,
): AdsPackagePlan {
  const audience = args.audience ?? "trust-center";
  const appliesTo = args.applies_to ?? "20x";
  const artifactPlan = buildFedrampArtifactPlan(loaded, {
    query: "ADS",
    audience,
    applies_to: appliesTo,
  });

  if (artifactPlan.kind !== "process") {
    throw new Error("ADS package planning requires the ADS process context.");
  }

  const grouped = groupArtifactItemsByVisibility(artifactPlan.items);
  const lines = [
    "Authorization Data Sharing package plan",
    `Audience:        ${audience}`,
    `Applies to:      ${appliesTo}`,
    `Official page:   ${artifactPlan.subject.sourceUrl ?? "Unavailable"}`,
    "",
  ];

  if (artifactPlan.subject.expectedOutcomes.length > 0) {
    lines.push("Expected outcomes:");
    for (const outcome of artifactPlan.subject.expectedOutcomes.slice(0, 5)) {
      lines.push(`- ${outcome}`);
    }
    lines.push("");
  }

  const sections: Array<{ title: string; items: ArtifactPlanItem[]; empty: string }> = [
    {
      title: "Public trust-center layer:",
      items: grouped.publicItems,
      empty: "- No public package items were inferred from the current official source filter.",
    },
    {
      title: "Controlled authorization-data layer:",
      items: grouped.controlledItems,
      empty: "- No controlled-access items were inferred from the current official source filter.",
    },
    {
      title: "Private operating layer:",
      items: grouped.privateItems,
      empty: "- No private operating items were inferred from the current official source filter.",
    },
  ];

  for (const section of sections) {
    lines.push(section.title);
    if (section.items.length === 0) lines.push(section.empty);
    else for (const item of section.items) lines.push(formatArtifactPlanItem(item));
    lines.push("");
  }

  if (artifactPlan.rollout.length > 0) {
    lines.push("Recommended rollout:");
    for (const phase of artifactPlan.rollout) {
      lines.push(`- ${phase.title} — ${phase.objective}`);
      for (const item of phase.items) {
        lines.push(`  - ${item}`);
      }
    }
    lines.push("");
  }

  if (artifactPlan.linkedIndicators.length > 0) {
    lines.push("Linked KSI indicators:");
    for (const indicator of artifactPlan.linkedIndicators.slice(0, 6)) {
      lines.push(`- ${indicator.id} — ${indicator.name}`);
    }
    lines.push("");
  }

  lines.push(
    formatProvenanceNote({
      repo: loaded.provenance.repo,
      path: loaded.provenance.path,
      branch: loaded.provenance.branch,
      blobSha: loaded.provenance.blobSha,
      version: loaded.provenance.version,
      upstreamLastUpdated: loaded.provenance.upstreamLastUpdated,
      cacheStatus: loaded.cacheStatus,
    }),
  );

  return {
    process: artifactPlan.subject,
    linkedIndicators: artifactPlan.linkedIndicators,
    audience,
    appliesTo,
    publicItems: grouped.publicItems,
    controlledItems: grouped.controlledItems,
    privateItems: grouped.privateItems,
    rollout: artifactPlan.rollout,
    text: lines.join("\n"),
  };
}

function formatKsiText(
  match: ReturnType<typeof resolveFedrampKsi>,
  indicators: FedrampKsiIndicatorRecord[],
  provenance: Awaited<ReturnType<typeof loadFedrampCatalog>>["provenance"],
  cacheStatus: string,
): string {
  const lines: string[] = [];

  if (match.kind === "domain") {
    lines.push(
      `${match.domain.name} [${match.domain.shortName}]`,
      `Domain ID:        ${match.domain.id}`,
      `Web slug:         ${match.domain.webName}`,
      "",
      match.domain.theme,
      "",
      "Indicators:",
    );

    for (const indicator of indicators) {
      lines.push(`- ${indicator.id} — ${indicator.name}`);
    }
  } else {
    lines.push(
      `${match.indicator.name}`,
      `Indicator ID:     ${match.indicator.id}${match.indicator.fka ? ` (formerly ${match.indicator.fka})` : ""}`,
      `Domain:           ${match.indicator.domainName} [${match.indicator.domainShortName}]`,
      "",
      match.indicator.statement,
    );

    if (match.indicator.reference) {
      lines.push(
        "",
        `Reference: ${match.indicator.reference}${match.indicator.referenceUrl ? ` (${match.indicator.referenceUrl})` : ""}`,
      );
    }

    if (match.indicator.controls.length > 0) {
      lines.push("", `Mapped Rev5 controls: ${match.indicator.controls.join(", ")}`);
    }

    if (match.indicator.terms.length > 0) {
      lines.push("", `Terms: ${match.indicator.terms.join(", ")}`);
    }
  }

  lines.push(
    "",
    formatProvenanceNote({
      repo: provenance.repo,
      path: provenance.path,
      branch: provenance.branch,
      blobSha: provenance.blobSha,
      version: provenance.version,
      upstreamLastUpdated: provenance.upstreamLastUpdated,
      cacheStatus,
    }),
  );

  return lines.join("\n");
}

export function registerFedrampTools(pi: any): void {
  pi.registerTool({
    name: "fedramp_check_sources",
    label: "Check official FedRAMP sources",
    description:
      "Inspect the official FedRAMP GitHub sources grclanker uses, including FRMR version, source path, cache status, and the current state of FedRAMP/rules.",
    parameters: Type.Object({
      refresh: Type.Optional(
        Type.Boolean({
          description: "Force a live refresh from the official GitHub sources.",
          default: false,
        }),
      ),
    }),
    prepareArguments: normalizeCheckArgs,
    async execute(_toolCallId: string, args: CheckSourcesArgs) {
      try {
        const status = await inspectFedrampOfficialSources({ refresh: args.refresh });
        return textResult(formatSourceCheckText(status), {
          tool: "fedramp_check_sources",
          refresh: args.refresh ?? false,
          fetched_at: status.fetchedAt,
          cache_status: status.cacheStatus,
          primary: status.primary,
          secondary: status.secondary,
          notes: status.notes,
        });
      } catch (error) {
        return errorResult(
          `FedRAMP source check failed: ${error instanceof Error ? error.message : String(error)}`,
          { tool: "fedramp_check_sources", refresh: args.refresh ?? false },
        );
      }
    },
  });

  pi.registerTool({
    name: "fedramp_search_frmr",
    label: "Search official FedRAMP FRMR data",
    description:
      "Search official FedRAMP machine-readable definitions, process docs, requirements, and KSIs grounded in the FedRAMP/docs GitHub repo.",
    parameters: Type.Object({
      query: Type.String({
        description: "Search term such as ADS, Authorization Data Sharing, FRR-ADS-01, KSI-AFR-ADS, or Accepted Vulnerability.",
      }),
      section: Type.Optional(
        Type.Union([
          Type.Literal("definition"),
          Type.Literal("process"),
          Type.Literal("requirement"),
          Type.Literal("ksi"),
          Type.Literal("any"),
        ]),
      ),
      applies_to: Type.Optional(
        Type.Union([
          Type.Literal("20x"),
          Type.Literal("rev5"),
          Type.Literal("both"),
          Type.Literal("any"),
        ]),
      ),
      limit: Type.Optional(
        Type.Number({
          description: "Max results to return (default: 10).",
          default: 10,
        }),
      ),
    }),
    prepareArguments: normalizeSearchArgs,
    async execute(_toolCallId: string, args: SearchArgs) {
      if (!args.query.trim()) {
        return missingQueryResult("fedramp_search_frmr", '{"query":"Authorization Data Sharing"}');
      }

      try {
        const loaded = await loadFedrampCatalog();
        const matches = searchFedrampCatalog(loaded.catalog, args.query, {
          section: args.section ?? "any",
          appliesTo: args.applies_to ?? "any",
          limit: args.limit,
        });

        if (matches.length === 0) {
          return textResult(`No official FedRAMP FRMR matches found for "${args.query}".`, {
            tool: "fedramp_search_frmr",
            query: args.query,
            section: args.section ?? "any",
            applies_to: args.applies_to ?? "any",
            count: 0,
            provenance: loaded.provenance,
          });
        }

        return textResult(formatSearchText(matches, args.query, loaded.provenance, loaded.cacheStatus), {
          tool: "fedramp_search_frmr",
          query: args.query,
          section: args.section ?? "any",
          applies_to: args.applies_to ?? "any",
          count: matches.length,
          matches,
          provenance: loaded.provenance,
          cache_status: loaded.cacheStatus,
          notes: loaded.notes,
        });
      } catch (error) {
        return errorResult(
          `FedRAMP FRMR search failed: ${error instanceof Error ? error.message : String(error)}`,
          { tool: "fedramp_search_frmr", query: args.query },
        );
      }
    },
  });

  pi.registerTool({
    name: "fedramp_get_process",
    label: "Get official FedRAMP process",
    description:
      "Resolve an official FedRAMP process such as ADS, PVA, SCG, VDR, or CCM from the FRMR documentation.",
    parameters: Type.Object({
      query: Type.String({
        description: "Process query such as ADS, authorization-data-sharing, or Persistent Validation and Assessment.",
      }),
    }),
    prepareArguments: normalizeQueryArgs,
    async execute(_toolCallId: string, args: QueryArgs) {
      if (!args.query.trim()) {
        return missingQueryResult("fedramp_get_process", '{"query":"ADS"}');
      }

      try {
        const loaded = await loadFedrampCatalog();
        const process = resolveFedrampProcess(loaded.catalog, args.query);
        const requirements = processRequirements(loaded.catalog, process.id);
        const counts = requirementCountsByApplicability(loaded.catalog, process.id);
        return textResult(
          formatProcessText(process, requirements, counts, loaded.provenance, loaded.cacheStatus),
          {
            tool: "fedramp_get_process",
            query: args.query,
            process,
            requirement_count: requirements.length,
            requirements: requirements.map((requirement) => ({
              id: requirement.id,
              applies_to: requirement.appliesTo,
              label_code: requirement.labelCode,
              keyword: requirement.primaryKeyWord,
              name: requirement.name,
            })),
            counts,
            provenance: loaded.provenance,
            cache_status: loaded.cacheStatus,
            notes: loaded.notes,
          },
        );
      } catch (error) {
        return errorResult(
          `FedRAMP process lookup failed: ${error instanceof Error ? error.message : String(error)}`,
          { tool: "fedramp_get_process", query: args.query },
        );
      }
    },
  });

  pi.registerTool({
    name: "fedramp_get_requirement",
    label: "Get official FedRAMP requirement",
    description:
      "Resolve a single official FedRAMP FRMR requirement or recommendation by current ID, former ID, or unique name.",
    parameters: Type.Object({
      query: Type.String({
        description: "Requirement query such as ADS-CSO-PUB or FRR-ADS-01.",
      }),
    }),
    prepareArguments: normalizeQueryArgs,
    async execute(_toolCallId: string, args: QueryArgs) {
      if (!args.query.trim()) {
        return missingQueryResult("fedramp_get_requirement", '{"query":"ADS-CSO-PUB"}');
      }

      try {
        const loaded = await loadFedrampCatalog();
        const requirement = resolveFedrampRequirement(loaded.catalog, args.query);
        return textResult(
          formatRequirementText(requirement, loaded.provenance, loaded.cacheStatus),
          {
            tool: "fedramp_get_requirement",
            query: args.query,
            requirement,
            provenance: loaded.provenance,
            cache_status: loaded.cacheStatus,
            notes: loaded.notes,
          },
        );
      } catch (error) {
        return errorResult(
          `FedRAMP requirement lookup failed: ${error instanceof Error ? error.message : String(error)}`,
          { tool: "fedramp_get_requirement", query: args.query },
        );
      }
    },
  });

  pi.registerTool({
    name: "fedramp_get_ksi",
    label: "Get official FedRAMP KSI",
    description:
      "Resolve a FedRAMP key security indicator domain or a specific indicator by current ID, former ID, or unique name.",
    parameters: Type.Object({
      query: Type.String({
        description: "KSI query such as AFR, KSI-AFR-ADS, KSI-AFR-03, or Authorization Data Sharing.",
      }),
    }),
    prepareArguments: normalizeQueryArgs,
    async execute(_toolCallId: string, args: QueryArgs) {
      if (!args.query.trim()) {
        return missingQueryResult("fedramp_get_ksi", '{"query":"KSI-AFR-ADS"}');
      }

      try {
        const loaded = await loadFedrampCatalog();
        const match = resolveFedrampKsi(loaded.catalog, args.query);
        const indicators =
          match.kind === "domain"
            ? domainIndicators(loaded.catalog, match.domain.id)
            : domainIndicators(loaded.catalog, match.indicator.domainId);
        return textResult(
          formatKsiText(match, indicators, loaded.provenance, loaded.cacheStatus),
          {
            tool: "fedramp_get_ksi",
            query: args.query,
            kind: match.kind,
            result: match.kind === "domain" ? match.domain : match.indicator,
            indicators: indicators.map((indicator) => ({
              id: indicator.id,
              fka: indicator.fka,
              name: indicator.name,
              reference: indicator.reference,
              controls: indicator.controls,
            })),
            provenance: loaded.provenance,
            cache_status: loaded.cacheStatus,
            notes: loaded.notes,
          },
        );
      } catch (error) {
        return errorResult(
          `FedRAMP KSI lookup failed: ${error instanceof Error ? error.message : String(error)}`,
          { tool: "fedramp_get_ksi", query: args.query },
        );
      }
    },
  });

  pi.registerTool({
    name: "fedramp_assess_readiness",
    label: "Assess FedRAMP readiness",
    description:
      "Turn an official FedRAMP process or KSI into a practical readiness brief with prioritized checklist items, likely artifacts, and inferred workstreams for providers or trust centers.",
    parameters: Type.Object({
      query: Type.String({
        description: "Process or KSI query such as ADS, PVA, KSI-AFR, or KSI-AFR-ADS.",
      }),
      applies_to: Type.Optional(
        Type.Union([
          Type.Literal("20x"),
          Type.Literal("rev5"),
          Type.Literal("both"),
          Type.Literal("any"),
        ]),
      ),
      audience: Type.Optional(
        Type.Union([
          Type.Literal("provider"),
          Type.Literal("trust-center"),
          Type.Literal("any"),
        ]),
      ),
      limit: Type.Optional(
        Type.Number({
          description: "Max checklist items to prioritize (default: 8).",
          default: 8,
        }),
      ),
    }),
    prepareArguments: normalizeReadinessArgs,
    async execute(_toolCallId: string, args: ReadinessArgs) {
      if (!args.query.trim()) {
        return missingQueryResult("fedramp_assess_readiness", '{"query":"ADS"}');
      }

      try {
        const loaded = await loadFedrampCatalog();
        const brief = buildFedrampReadinessBrief(loaded, args);
        return textResult(brief.text, {
          tool: "fedramp_assess_readiness",
          query: args.query,
          audience: args.audience ?? "provider",
          applies_to: args.applies_to ?? "any",
          kind: brief.kind,
          subject:
            brief.kind === "process"
              ? {
                  id: brief.subject.id,
                  name: brief.subject.name,
                  short_name: brief.subject.shortName,
                  web_name: brief.subject.webName,
                }
              : brief.kind === "ksi-domain"
                ? {
                    id: brief.subject.id,
                    name: brief.subject.name,
                    short_name: brief.subject.shortName,
                    web_name: brief.subject.webName,
                  }
                : {
                    id: brief.subject.id,
                    name: brief.subject.name,
                    domain_id: brief.subject.domainId,
                  },
          checklist: brief.checklist,
          linked_processes: brief.linkedProcesses.map((process) => ({
            id: process.id,
            name: process.name,
            short_name: process.shortName,
          })),
          linked_indicators: brief.linkedIndicators.map((indicator) => ({
            id: indicator.id,
            name: indicator.name,
            reference: indicator.reference,
            controls: indicator.controls,
          })),
          artifact_suggestions: brief.artifactSuggestions,
          workstreams: brief.workstreams,
          provenance: loaded.provenance,
          cache_status: loaded.cacheStatus,
          notes: loaded.notes,
        });
      } catch (error) {
        return errorResult(
          `FedRAMP readiness assessment failed: ${error instanceof Error ? error.message : String(error)}`,
          { tool: "fedramp_assess_readiness", query: args.query },
        );
      }
    },
  });

  pi.registerTool({
    name: "fedramp_plan_process_artifacts",
    label: "Plan FedRAMP process artifacts",
    description:
      "Turn an official FedRAMP process or KSI into a practical artifact plan with public, controlled-access, and private operating surfaces plus a rollout order.",
    parameters: Type.Object({
      query: Type.String({
        description: "Process or KSI query such as ADS, SCG, KSI-AFR, or KSI-AFR-ADS.",
      }),
      applies_to: Type.Optional(
        Type.Union([
          Type.Literal("20x"),
          Type.Literal("rev5"),
          Type.Literal("both"),
          Type.Literal("any"),
        ]),
      ),
      audience: Type.Optional(
        Type.Union([
          Type.Literal("provider"),
          Type.Literal("trust-center"),
          Type.Literal("any"),
        ]),
      ),
    }),
    prepareArguments: normalizePlanningArgs,
    async execute(_toolCallId: string, args: PlanningArgs) {
      if (!args.query.trim()) {
        return missingQueryResult("fedramp_plan_process_artifacts", '{"query":"ADS"}');
      }

      try {
        const loaded = await loadFedrampCatalog();
        const plan = buildFedrampArtifactPlan(loaded, args);
        return textResult(plan.text, {
          tool: "fedramp_plan_process_artifacts",
          query: args.query,
          audience: args.audience ?? "provider",
          applies_to: args.applies_to ?? "any",
          kind: plan.kind,
          item_count: plan.items.length,
          items: plan.items,
          rollout: plan.rollout,
          linked_processes: plan.linkedProcesses.map((process) => ({
            id: process.id,
            name: process.name,
            short_name: process.shortName,
          })),
          linked_indicators: plan.linkedIndicators.map((indicator) => ({
            id: indicator.id,
            name: indicator.name,
            reference: indicator.reference,
          })),
          provenance: loaded.provenance,
          cache_status: loaded.cacheStatus,
          notes: loaded.notes,
        });
      } catch (error) {
        return errorResult(
          `FedRAMP artifact planning failed: ${error instanceof Error ? error.message : String(error)}`,
          { tool: "fedramp_plan_process_artifacts", query: args.query },
        );
      }
    },
  });

  pi.registerTool({
    name: "fedramp_plan_ads_package",
    label: "Plan ADS trust-center package",
    description:
      "Build an Authorization Data Sharing package plan grounded in official FedRAMP sources, grouped into public, controlled-access, and private operating layers.",
    parameters: Type.Object({
      applies_to: Type.Optional(
        Type.Union([
          Type.Literal("20x"),
          Type.Literal("rev5"),
          Type.Literal("both"),
          Type.Literal("any"),
        ]),
      ),
      audience: Type.Optional(
        Type.Union([
          Type.Literal("provider"),
          Type.Literal("trust-center"),
          Type.Literal("any"),
        ]),
      ),
    }),
    prepareArguments: normalizeAdsPackageArgs,
    async execute(_toolCallId: string, args: AdsPackageArgs) {
      try {
        const loaded = await loadFedrampCatalog();
        const plan = buildFedrampAdsPackagePlan(loaded, args);
        return textResult(plan.text, {
          tool: "fedramp_plan_ads_package",
          audience: args.audience ?? "trust-center",
          applies_to: args.applies_to ?? "20x",
          process: {
            id: plan.process.id,
            name: plan.process.name,
            short_name: plan.process.shortName,
          },
          public_items: plan.publicItems,
          controlled_items: plan.controlledItems,
          private_items: plan.privateItems,
          rollout: plan.rollout,
          linked_indicators: plan.linkedIndicators.map((indicator) => ({
            id: indicator.id,
            name: indicator.name,
            reference: indicator.reference,
          })),
          provenance: loaded.provenance,
          cache_status: loaded.cacheStatus,
          notes: loaded.notes,
        });
      } catch (error) {
        return errorResult(
          `FedRAMP ADS package planning failed: ${error instanceof Error ? error.message : String(error)}`,
          { tool: "fedramp_plan_ads_package" },
        );
      }
    },
  });

  pi.registerTool({
    name: "fedramp_generate_ads_bundle",
    label: "Generate ADS starter bundle",
    description:
      "Generate an Authorization Data Sharing starter bundle with trust-center, machine-readable feed, access-instructions, and operating-template files grounded in official FedRAMP sources.",
    parameters: Type.Object({
      output_dir: Type.Optional(
        Type.String({
          description: `Optional output root (default: ${DEFAULT_FEDRAMP_OUTPUT_DIR}).`,
        }),
      ),
      applies_to: Type.Optional(
        Type.Union([
          Type.Literal("20x"),
          Type.Literal("rev5"),
          Type.Literal("both"),
          Type.Literal("any"),
        ]),
      ),
      audience: Type.Optional(
        Type.Union([
          Type.Literal("provider"),
          Type.Literal("trust-center"),
          Type.Literal("any"),
        ]),
      ),
    }),
    prepareArguments: normalizeAdsBundleArgs,
    async execute(_toolCallId: string, args: AdsBundleArgs) {
      try {
        const loaded = await loadFedrampCatalog();
        const outputRoot = resolve(process.cwd(), args.output_dir?.trim() || DEFAULT_FEDRAMP_OUTPUT_DIR);
        const bundle = await generateFedrampAdsStarterBundle(loaded, outputRoot, args);
        const relativeFiles = bundle.files.map((filePath) => relative(bundle.outputDir, filePath));
        const lines = [
          "Authorization Data Sharing starter bundle generated.",
          `Output dir: ${bundle.outputDir}`,
          "",
          "Files:",
          ...relativeFiles.map((filePath) => `- ${filePath}`),
          "",
          "This bundle is a starter scaffold. Fill in the TODO fields, then validate the public, controlled-access, and private operating layers against your actual trust-center and authorization-data workflow.",
        ];

        return textResult(lines.join("\n"), {
          tool: "fedramp_generate_ads_bundle",
          output_dir: bundle.outputDir,
          files: relativeFiles,
          public_items: bundle.plan.publicItems,
          controlled_items: bundle.plan.controlledItems,
          private_items: bundle.plan.privateItems,
          rollout: bundle.plan.rollout,
          provenance: loaded.provenance,
          cache_status: loaded.cacheStatus,
          notes: loaded.notes,
        });
      } catch (error) {
        return errorResult(
          `FedRAMP ADS starter bundle generation failed: ${error instanceof Error ? error.message : String(error)}`,
          { tool: "fedramp_generate_ads_bundle" },
        );
      }
    },
  });

  pi.registerTool({
    name: "fedramp_generate_ads_site",
    label: "Generate ADS public trust-center site",
    description:
      "Generate a portable static ADS trust-center site with public HTML pages, machine-readable JSON files, and deploy notes suitable for customer-owned AWS, Azure, or GCP hosting.",
    parameters: Type.Object({
      output_dir: Type.Optional(
        Type.String({
          description: `Optional output root (default: ${DEFAULT_FEDRAMP_OUTPUT_DIR}).`,
        }),
      ),
      applies_to: Type.Optional(
        Type.Union([
          Type.Literal("20x"),
          Type.Literal("rev5"),
          Type.Literal("both"),
          Type.Literal("any"),
        ]),
      ),
      audience: Type.Optional(
        Type.Union([
          Type.Literal("provider"),
          Type.Literal("trust-center"),
          Type.Literal("any"),
        ]),
      ),
      provider_name: Type.Optional(
        Type.String({
          description: "Public provider name to prefill into the generated trust-center site.",
        }),
      ),
      offering_name: Type.Optional(
        Type.String({
          description: "Public offering name to prefill into the generated trust-center site.",
        }),
      ),
      primary_domain: Type.Optional(
        Type.String({
          description: "Primary public trust-center domain, such as trust.example.com.",
        }),
      ),
      support_email: Type.Optional(
        Type.String({
          description: "Public support or security contact email to include in the generated site.",
        }),
      ),
    }),
    prepareArguments: normalizeAdsSiteArgs,
    async execute(_toolCallId: string, args: AdsSiteArgs) {
      try {
        const loaded = await loadFedrampCatalog();
        const outputRoot = resolve(process.cwd(), args.output_dir?.trim() || DEFAULT_FEDRAMP_OUTPUT_DIR);
        const site = await generateFedrampAdsSite(loaded, outputRoot, args);
        const relativeFiles = site.files.map((filePath) => relative(site.outputDir, filePath));
        const lines = [
          "Authorization Data Sharing public trust-center site generated.",
          `Output dir: ${site.outputDir}`,
          `Primary domain: ${site.metadata.primaryDomain}`,
          "",
          "Files:",
          ...relativeFiles.map((filePath) => `- ${filePath}`),
          "",
          "This output is public-only and static by design. Host it in a customer-owned AWS, Azure, or GCP environment, then keep controlled-access and private operational artifacts outside the public site.",
        ];

        return textResult(lines.join("\n"), {
          tool: "fedramp_generate_ads_site",
          output_dir: site.outputDir,
          files: relativeFiles,
          metadata: {
            provider_name: site.metadata.providerName,
            offering_name: site.metadata.offeringName,
            primary_domain: site.metadata.primaryDomain,
            support_email: site.metadata.supportEmail,
            base_url: site.metadata.baseUrl,
            site_title: site.metadata.siteTitle,
          },
          public_items: site.plan.publicItems,
          controlled_items: site.plan.controlledItems,
          rollout: site.plan.rollout,
          provenance: loaded.provenance,
          cache_status: loaded.cacheStatus,
          notes: loaded.notes,
        });
      } catch (error) {
        return errorResult(
          `FedRAMP ADS public site generation failed: ${error instanceof Error ? error.message : String(error)}`,
          { tool: "fedramp_generate_ads_site" },
        );
      }
    },
  });
}
