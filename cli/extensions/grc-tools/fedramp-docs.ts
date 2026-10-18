import type {
  FedrampApplicability,
  FedrampCatalog,
  FedrampKsiDomainRecord,
  FedrampPrimarySourceStatus,
  FedrampProcessRecord,
  FedrampRequirementRecord,
  FedrampRulesSourceStatus,
} from "./fedramp-source.js";
import {
  domainIndicators,
  fedrampUpdateLines,
  formatFedrampNotification,
  processRequirements,
  requirementCountsByApplicability,
} from "./fedramp-source.js";

export interface GeneratedFedrampDoc {
  path: string;
  content: string;
}

function esc(value: string): string {
  return value.replaceAll("|", "\\|");
}

function paragraphs(text: string): string {
  return text
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean)
    .join("\n\n");
}

function markdownList(values: string[], indent = ""): string {
  if (values.length === 0) return `${indent}- None`;
  return values.map((value) => `${indent}- ${value}`).join("\n");
}

function versionNote(primary: FedrampPrimarySourceStatus): string {
  return `> Generated from the official FedRAMP Consolidated Rules \`${primary.version}\`, last updated upstream on ${primary.upstreamLastUpdated}. [Source details](#source)`;
}

function sourceSection(
  primary: FedrampPrimarySourceStatus,
  secondary: FedrampRulesSourceStatus,
): string {
  const blobRef = primary.blobSha ? `\`${primary.blobSha.slice(0, 12)}\`` : "`unknown`";
  const supportingNote =
    secondary.state === "ready"
      ? "Supporting narrative documentation is available from the official `FedRAMP/2026-markdown` repository."
      : secondary.state === "placeholder"
        ? "The official `FedRAMP/2026-markdown` repository exists, but generated narrative content was not found."
        : "The official `FedRAMP/2026-markdown` repository could not be inspected during this sync.";

  return [
    "## Source",
    "",
    `- Generated from the official [${primary.org}/${primary.repo}](${primary.repoUrl}) GitHub repo.`,
    `- Source path: [\`${primary.path}\`](${primary.fileHtmlUrl ?? primary.rawUrl}) on \`${primary.branch}\` at blob ${blobRef}.`,
    `- Consolidated Rules version: \`${primary.version}\` · upstream \`last_updated\`: \`${primary.upstreamLastUpdated}\`.`,
    `- ${supportingNote}`,
  ].join("\n");
}

function frontmatter(title: string, description: string): string {
  return `---\ntitle: ${JSON.stringify(title)}\ndescription: ${JSON.stringify(description)}\n---`;
}

const REQUIREMENT_GROUPS = ["both", "20x", "rev5"] as const;

const REQUIREMENT_GROUP_NAMES: Record<FedrampApplicability, string> = {
  both: "20x and Rev5",
  "20x": "20x only",
  rev5: "Rev5 only",
};

function requirementSummary(counts: Record<FedrampApplicability, number>): string {
  const parts = REQUIREMENT_GROUPS.filter((group) => counts[group] > 0).map(
    (group) => `${counts[group]} for ${REQUIREMENT_GROUP_NAMES[group]}`,
  );
  return parts.length > 0 ? parts.join(", ") : "none";
}

function applicabilitySummary(applicability: readonly FedrampApplicability[]): string {
  const has20x = applicability.includes("20x");
  const hasRev5 = applicability.includes("rev5");
  if (applicability.includes("both") || (has20x && hasRev5)) return REQUIREMENT_GROUP_NAMES.both;
  if (has20x) return REQUIREMENT_GROUP_NAMES["20x"];
  if (hasRev5) return REQUIREMENT_GROUP_NAMES.rev5;
  return "none";
}

function requirementBadge(requirement: FedrampRequirementRecord): string {
  const keyword = requirement.primaryKeyWord ? ` ${requirement.primaryKeyWord}` : "";
  const name = requirement.name ? `: ${requirement.name}` : "";
  const fka = requirement.fka ? ` (formerly \`${requirement.fka}\`)` : "";
  return `### \`${requirement.id}\`${fka}${keyword}${name}`;
}

function requirementMarkdown(requirement: FedrampRequirementRecord): string {
  const lines = [
    requirementBadge(requirement),
    "",
  ];

  if (requirement.classVariants.length > 0) {
    lines.push("Varies by certification class:", "");
    for (const variant of requirement.classVariants) {
      const force = variant.primaryKeyWord ? ` ${variant.primaryKeyWord}` : "";
      lines.push(`- **Class ${variant.class}${force}:** ${variant.statement}`);
    }
  } else {
    lines.push(requirement.statement);
  }

  if (requirement.followingInformation.length > 0) {
    lines.push("", "Checklist items:", markdownList(requirement.followingInformation));
  }

  if (requirement.notifications.length > 0) {
    lines.push(
      "",
      "Notifications:",
      markdownList(requirement.notifications.map(formatFedrampNotification)),
    );
  }

  if (requirement.controls.length > 0) {
    lines.push(
      "",
      `Mapped Rev5 controls: ${requirement.controls.map((control) => `\`${control}\``).join(", ")}`,
    );
  }

  if (requirement.terms.length > 0) {
    lines.push("", `Terms: ${requirement.terms.map((term) => `\`${term}\``).join(", ")}`);
  }

  if (requirement.affects.length > 0) {
    lines.push("", `Affects: ${requirement.affects.join(", ")}`);
  }

  if (requirement.timeframeType && requirement.timeframeNum !== null) {
    lines.push("", `Structured timeframe: \`${requirement.timeframeNum}\` ${requirement.timeframeType}`);
  }

  if (requirement.note) {
    lines.push("", `Note: ${paragraphs(requirement.note)}`);
  }

  if (requirement.updated.length > 0) {
    lines.push("", ...fedrampUpdateLines(requirement.updated));
  }

  return lines.join("\n");
}

function processPage(
  catalog: FedrampCatalog,
  process: FedrampProcessRecord,
  primary: FedrampPrimarySourceStatus,
  secondary: FedrampRulesSourceStatus,
): GeneratedFedrampDoc {
  const requirements = processRequirements(catalog, process.id);
  const grouped = {
    both: requirements.filter((requirement) => requirement.appliesTo === "both"),
    "20x": requirements.filter((requirement) => requirement.appliesTo === "20x"),
    rev5: requirements.filter((requirement) => requirement.appliesTo === "rev5"),
  };
  const counts = requirementCountsByApplicability(catalog, process.id);
  const lines = [
    frontmatter(
      process.name,
      `Official Consolidated Rules summary for the ${process.shortName} FedRAMP process, including applicability and requirements.`,
    ),
    "",
    versionNote(primary),
    "",
  ];

  if (process.purpose) {
    lines.push(paragraphs(process.purpose), "");
  }

  lines.push(
    "## At a Glance",
    "",
    `- Applies to: ${applicabilitySummary(process.applicability)}`,
    `- 20x: ${process.effective["20x"]?.is ?? "n/a"}${process.effective["20x"]?.currentStatus ? ` · ${process.effective["20x"]?.currentStatus}` : ""}${process.effective["20x"]?.startDate ? ` · obtain ${process.effective["20x"]?.startDate}` : ""}${process.effective["20x"]?.graceDate ? ` · grace through ${process.effective["20x"]?.graceDate}` : ""}`,
    `- Rev5: ${process.effective.rev5?.is ?? "n/a"}${process.effective.rev5?.currentStatus ? ` · ${process.effective.rev5?.currentStatus}` : ""}${process.effective.rev5?.startDate ? ` · obtain ${process.effective.rev5?.startDate}` : ""}${process.effective.rev5?.graceDate ? ` · grace through ${process.effective.rev5?.graceDate}` : ""}`,
    `- Requirements: ${requirementSummary(counts)}`,
  );

  if (process.status) {
    lines.push(`- Status: \`${process.status}\``);
  }

  lines.push(`- Short name: \`${process.shortName}\``);
  if (process.id !== process.shortName) {
    lines.push(`- Process ID: \`${process.id}\``);
  }

  if (process.sourceUrl) {
    lines.push(`- Official page: [${process.sourceUrl}](${process.sourceUrl})`);
  }
  lines.push("");

  if (process.expectedOutcomes.length > 0) {
    lines.push("## Expected Outcomes", "", markdownList(process.expectedOutcomes), "");
  }

  if (process.labels.length > 0) {
    lines.push("## Rule Subsets", "");
    for (const label of process.labels) {
      const types = label.types.length > 0 ? ` · types: ${label.types.join(", ")}` : "";
      const classes = label.classes.length > 0 ? ` · classes: ${label.classes.join(", ")}` : "";
      lines.push(`- \`${label.code}\` · ${label.name}: ${label.description}${types}${classes}`);
    }
    lines.push("");
  }

  if (process.authority.length > 0) {
    lines.push("## Authority", "");
    for (const authority of process.authority) {
      const reference = authority.referenceUrl
        ? `[${authority.reference ?? authority.referenceUrl}](${authority.referenceUrl})`
        : authority.reference ?? "Authority";
      const suffix = authority.description ? `: ${authority.description}` : "";
      lines.push(`- ${reference}${suffix}`);
    }
    lines.push("");
  }

  for (const group of REQUIREMENT_GROUPS) {
    if (grouped[group].length === 0) continue;
    lines.push(`## Requirements for ${REQUIREMENT_GROUP_NAMES[group]}`, "");
    for (const requirement of grouped[group]) {
      lines.push(requirementMarkdown(requirement), "");
    }
  }

  lines.push(sourceSection(primary, secondary), "");

  return {
    path: `fedramp/processes/${process.webName}.md`,
    content: `${lines.join("\n").trim()}\n`,
  };
}

function ksiDomainPage(
  catalog: FedrampCatalog,
  domain: FedrampKsiDomainRecord,
  primary: FedrampPrimarySourceStatus,
  secondary: FedrampRulesSourceStatus,
): GeneratedFedrampDoc {
  const indicators = domainIndicators(catalog, domain.id);
  const lines = [
    frontmatter(
      domain.name,
      `Official Consolidated Rules summary for the ${domain.shortName} FedRAMP key security indicator domain.`,
    ),
    "",
    versionNote(primary),
    "",
  ];

  if (domain.theme) {
    lines.push(paragraphs(domain.theme), "");
  }

  lines.push(
    "## At a Glance",
    "",
    `- Applies to: ${applicabilitySummary([domain.appliesTo])}`,
    `- Indicators: ${indicators.length}`,
  );
  if (domain.status) {
    lines.push(`- Status: \`${domain.status}\``);
  }
  lines.push(`- Domain ID: \`${domain.id}\``, "");

  lines.push("## Indicators", "");

  for (const indicator of indicators) {
    const former = indicator.fka ? ` (formerly \`${indicator.fka}\`)` : "";
    lines.push(`### \`${indicator.id}\`${former}: ${indicator.name}`, "");
    if (indicator.classVariants.length > 0) {
      lines.push("Varies by certification class:", "");
      for (const variant of indicator.classVariants) {
        lines.push(`- **Class ${variant.class}:** ${variant.statement}`);
      }
      lines.push("");
    } else {
      lines.push(indicator.statement, "");
    }
    if (indicator.reference && indicator.referenceUrl) {
      lines.push(`Reference: [${indicator.reference}](${indicator.referenceUrl})`, "");
    } else if (indicator.reference) {
      lines.push(`Reference: ${indicator.reference}`, "");
    }
    if (indicator.controls.length > 0) {
      lines.push(`Mapped Rev5 controls: ${indicator.controls.map((control) => `\`${control}\``).join(", ")}`, "");
    }
    if (indicator.terms.length > 0) {
      lines.push(`Terms: ${indicator.terms.map((term) => `\`${term}\``).join(", ")}`, "");
    }
    if (indicator.updated.length > 0) {
      lines.push(...fedrampUpdateLines(indicator.updated), "");
    }
  }

  lines.push(sourceSection(primary, secondary), "");

  return {
    path: `fedramp/ksi/${domain.webName}.md`,
    content: `${lines.join("\n").trim()}\n`,
  };
}

export function buildFedrampDocsSnapshot(
  catalog: FedrampCatalog,
  options: {
    primary: FedrampPrimarySourceStatus;
    secondary: FedrampRulesSourceStatus;
  },
): GeneratedFedrampDoc[] {
  const { primary, secondary } = options;
  const processRows = catalog.processes
    .map((process) => {
      const counts = requirementCountsByApplicability(catalog, process.id);
      return `- [${process.name}](/docs/fedramp/processes/${process.webName}/) · \`${process.shortName}\` · requirements: ${requirementSummary(counts)}`;
    })
    .join("\n");
  const ksiRows = catalog.ksiDomains
    .map((domain) => {
      const indicatorCount = domainIndicators(catalog, domain.id).length;
      return `- [${domain.name}](/docs/fedramp/ksi/${domain.webName}/) · \`${domain.shortName}\` · ${indicatorCount} indicator${indicatorCount === 1 ? "" : "s"}`;
    })
    .join("\n");

  const overview = [
    frontmatter(
      "FedRAMP Official Sources",
      "Official GitHub-grounded FedRAMP 20x and Rev5 reference material generated from the Consolidated Rules.",
    ),
    "",
    versionNote(primary),
    "",
    `These pages are generated from the official FedRAMP GitHub organization. They cover each process in the ${catalog.info.title}, with its requirements for 20x and Rev5, and each key security indicator (KSI) domain for 20x. The grclanker FedRAMP tools read the same rules live, cached for up to a day, so their answers can be newer than these pages.`,
    "",
    "To check readiness against these rules, plan the artifacts, and draft a Certification Data Sharing bundle and trust-center site, follow the [FedRAMP Readiness guide](/docs/guides/fedramp-readiness/).",
    "",
    "## Processes",
    "",
    processRows,
    "",
    "## KSI Domains",
    "",
    ksiRows,
    "",
    sourceSection(primary, secondary),
    "",
  ].join("\n");

  const processCount = catalog.processes.length;
  const processesIndex = [
    frontmatter(
      "FedRAMP Processes",
      "Browse official Consolidated Rules process documents such as CDS, IVV, SCG, VDR, and CCM.",
    ),
    "",
    versionNote(primary),
    "",
    `The ${catalog.info.title} define ${processCount} process${processCount === 1 ? "" : "es"}. Each line gives a process's short name and its requirement counts for 20x and Rev5.`,
    "",
    processRows,
    "",
    sourceSection(primary, secondary),
    "",
  ].join("\n");

  const domainCount = catalog.ksiDomains.length;
  const ksiIndex = [
    frontmatter(
      "FedRAMP KSI Domains",
      "Browse official Consolidated Rules key security indicator domains and indicator summaries.",
    ),
    "",
    versionNote(primary),
    "",
    `The ${catalog.info.title} define ${domainCount} key security indicator (KSI) domain${domainCount === 1 ? "" : "s"} for 20x. Each line gives a domain's short name and its number of indicators.`,
    "",
    ksiRows,
    "",
    sourceSection(primary, secondary),
    "",
  ].join("\n");

  const generated: GeneratedFedrampDoc[] = [
    { path: "fedramp/index.md", content: `${overview.trim()}\n` },
    { path: "fedramp/processes.md", content: `${processesIndex.trim()}\n` },
    { path: "fedramp/ksis.md", content: `${ksiIndex.trim()}\n` },
  ];

  for (const process of catalog.processes) {
    generated.push(processPage(catalog, process, primary, secondary));
  }

  for (const domain of catalog.ksiDomains) {
    generated.push(ksiDomainPage(catalog, domain, primary, secondary));
  }

  return generated.sort((left, right) => left.path.localeCompare(right.path));
}
