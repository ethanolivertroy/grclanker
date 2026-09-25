import type {
  FedrampCatalog,
  FedrampKsiDomainRecord,
  FedrampPrimarySourceStatus,
  FedrampProcessRecord,
  FedrampRequirementRecord,
  FedrampRulesSourceStatus,
} from "./fedramp-source.js";
import {
  domainIndicators,
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

function fenceMultiline(text: string | null | undefined): string {
  if (!text) return "";
  return text.trim();
}

function markdownList(values: string[], indent = ""): string {
  if (values.length === 0) return `${indent}- None`;
  return values.map((value) => `${indent}- ${value}`).join("\n");
}

function sourceBanner(
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
    `> Generated from the official [${primary.org}/${primary.repo}](${primary.repoUrl}) GitHub repo.`,
    `> Source path: [\`${primary.path}\`](${primary.fileHtmlUrl ?? primary.rawUrl}) on \`${primary.branch}\` at blob ${blobRef}.`,
    `> Consolidated Rules version: \`${primary.version}\` · upstream \`last_updated\`: \`${primary.upstreamLastUpdated}\`.`,
    `> ${supportingNote}`,
  ].join("\n");
}

function frontmatter(title: string, description: string): string {
  return `---\ntitle: ${title}\ndescription: ${description}\n---`;
}

function requirementBadge(requirement: FedrampRequirementRecord): string {
  const keyword = requirement.primaryKeyWord ? ` ${requirement.primaryKeyWord}` : "";
  const name = requirement.name ? ` — ${requirement.name}` : "";
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
    lines.push("", `Note: ${requirement.note}`);
  }

  if (requirement.updated.length > 0) {
    lines.push(
      "",
      `Recent update: ${requirement.updated[0]!.date} — ${requirement.updated[0]!.comment}`,
    );
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
      `${process.name} — FedRAMP Process`,
      `Official Consolidated Rules summary for the ${process.shortName} FedRAMP process, including applicability and requirements.`,
    ),
    "",
    sourceBanner(primary, secondary),
    "",
    `# ${process.name}`,
    "",
    `Short name: \`${process.shortName}\` · Process ID: \`${process.id}\` · Web slug: \`${process.webName}\``,
    "",
    `Applies to: ${process.applicability.map((value) => `\`${value}\``).join(", ")}`,
    "",
  ];

  if (process.status) {
    lines.splice(lines.length - 1, 0, `Status: \`${process.status}\``, "");
  }

  if (process.sourceUrl) {
    lines.push(`Official page: [${process.sourceUrl}](${process.sourceUrl})`, "");
  }

  lines.push(
    "## Effective Status",
    "",
    `- 20x: ${process.effective["20x"]?.is ?? "n/a"}${process.effective["20x"]?.currentStatus ? ` · ${process.effective["20x"]?.currentStatus}` : ""}${process.effective["20x"]?.startDate ? ` · obtain ${process.effective["20x"]?.startDate}` : ""}${process.effective["20x"]?.graceDate ? ` · grace through ${process.effective["20x"]?.graceDate}` : ""}`,
    `- Rev5: ${process.effective.rev5?.is ?? "n/a"}${process.effective.rev5?.currentStatus ? ` · ${process.effective.rev5?.currentStatus}` : ""}${process.effective.rev5?.startDate ? ` · obtain ${process.effective.rev5?.startDate}` : ""}${process.effective.rev5?.graceDate ? ` · grace through ${process.effective.rev5?.graceDate}` : ""}`,
    `- Shared requirements: ${counts.both}`,
    "",
  );

  if (process.purpose) {
    lines.push("## Purpose", "", fenceMultiline(process.purpose), "");
  }

  if (process.expectedOutcomes.length > 0) {
    lines.push("## Expected Outcomes", "", markdownList(process.expectedOutcomes), "");
  }

  if (process.labels.length > 0) {
    lines.push("## Rule Subsets", "");
    for (const label of process.labels) {
      const types = label.types.length > 0 ? ` · types: ${label.types.join(", ")}` : "";
      const classes = label.classes.length > 0 ? ` · classes: ${label.classes.join(", ")}` : "";
      lines.push(`- \`${label.code}\` — ${label.name}: ${label.description}${types}${classes}`);
    }
    lines.push("");
  }

  if (process.authority.length > 0) {
    lines.push("## Authority", "");
    for (const authority of process.authority) {
      const reference = authority.referenceUrl
        ? `[${authority.reference ?? authority.referenceUrl}](${authority.referenceUrl})`
        : authority.reference ?? "Authority";
      const suffix = authority.description ? ` — ${authority.description}` : "";
      lines.push(`- ${reference}${suffix}`);
    }
    lines.push("");
  }

  lines.push("## Requirements and Recommendations", "");

  for (const applicability of ["both", "20x", "rev5"] as const) {
    if (grouped[applicability].length === 0) continue;
    lines.push(`## ${applicability.toUpperCase()}`, "");
    for (const requirement of grouped[applicability]) {
      lines.push(requirementMarkdown(requirement), "");
    }
  }

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
      `${domain.name} — FedRAMP KSI Domain`,
      `Official Consolidated Rules summary for the ${domain.shortName} FedRAMP key security indicator domain.`,
    ),
    "",
    sourceBanner(primary, secondary),
    "",
    `# ${domain.name}`,
    "",
    `Domain code: \`${domain.code}\` · Domain ID: \`${domain.id}\` · Web slug: \`${domain.webName}\``,
    "",
    "## Indicators",
    "",
  ];

  if (domain.theme) {
    lines.splice(8, 0, "## Theme", "", fenceMultiline(domain.theme), "");
  }

  for (const indicator of indicators) {
    const former = indicator.fka ? ` (formerly \`${indicator.fka}\`)` : "";
    lines.push(`### \`${indicator.id}\`${former} — ${indicator.name}`, "");
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
      lines.push(
        `Recent update: ${indicator.updated[0]!.date} — ${indicator.updated[0]!.comment}`,
        "",
      );
    }
  }

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
      return `- [${process.name}](/docs/fedramp/processes/${process.webName}/) — \`${process.shortName}\` · applies to ${process.applicability.map((value) => `\`${value}\``).join(", ")} · requirements: \`both ${counts.both}\`, \`20x ${counts["20x"]}\`, \`rev5 ${counts.rev5}\``;
    })
    .join("\n");
  const ksiRows = catalog.ksiDomains
    .map((domain) => {
      const indicatorCount = domainIndicators(catalog, domain.id).length;
      return `- [${domain.name}](/docs/fedramp/ksi/${domain.webName}/) — \`${domain.shortName}\` · ${indicatorCount} indicator${indicatorCount === 1 ? "" : "s"}`;
    })
    .join("\n");

  const overview = [
    frontmatter(
      "FedRAMP Official Sources",
      "Official GitHub-grounded FedRAMP 20x and Rev5 reference material generated from the Consolidated Rules.",
    ),
    "",
    sourceBanner(primary, secondary),
    "",
    "# FedRAMP Official Sources",
    "",
    "This section is generated from the official FedRAMP GitHub organization. grclanker uses these machine-readable materials for both CLI lookups and reviewed docs snapshots so the public site stays fast without drifting away from upstream.",
    "",
    "## Current Grounding",
    "",
    `- Primary source: [${primary.org}/${primary.repo}](${primary.repoUrl}) → [\`${primary.path}\`](${primary.fileHtmlUrl ?? primary.rawUrl}) on \`${primary.branch}\``,
    `- Consolidated Rules version: \`${primary.version}\``,
    `- Upstream \`last_updated\`: \`${primary.upstreamLastUpdated}\``,
    `- Rev5 remains a first-class lane beside 20x in grclanker.`,
    "",
    "## Process Docs",
    "",
    processRows,
    "",
    "## KSI Domains",
    "",
    ksiRows,
    "",
  ].join("\n");

  const processesIndex = [
    frontmatter(
      "FedRAMP Processes",
      "Browse official Consolidated Rules process documents such as CDS, IVV, SCG, VDR, and CCM.",
    ),
    "",
    sourceBanner(primary, secondary),
    "",
    "# FedRAMP Processes",
    "",
    processRows,
    "",
  ].join("\n");

  const ksiIndex = [
    frontmatter(
      "FedRAMP KSI Domains",
      "Browse official Consolidated Rules key security indicator domains and indicator summaries.",
    ),
    "",
    sourceBanner(primary, secondary),
    "",
    "# FedRAMP KSI Domains",
    "",
    ksiRows,
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
