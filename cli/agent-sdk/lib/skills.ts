import { readCliAsset } from "./paths.js";

/** Config accepted by `defineSkill` from `@cursor/july/skills`. */
export interface GrclankerSkillConfig {
  description: string;
  markdown: string;
}

export const WORKFLOW_NAMES = ["investigate", "audit", "assess", "validate"] as const;

export type WorkflowName = (typeof WORKFLOW_NAMES)[number];

/** Routing descriptions for the Pi workflow prompts exposed as SDK skills. */
const WORKFLOW_DESCRIPTIONS: Record<WorkflowName, string> = {
  investigate:
    "Use when asked to investigate a vendor, product, library, or module for FIPS validation status, CISA KEV exposure, EPSS likelihood, or ransomware linkage.",
  audit:
    "Use when asked to run a structured compliance audit or map evidence to framework controls such as NIST 800-53, FedRAMP, SOC 2, CMMC, or ISO 27001.",
  assess:
    "Use when asked for an overall security or compliance posture readout with a Strong, Mixed, At Risk, or Critical classification and ordered next actions.",
  validate:
    "Use when asked a narrow question about whether a cryptographic module, library, or appliance is FIPS 140-2 or 140-3 validated.",
};

export const BUNDLED_SKILL_NAMES = ["crypto-validation"] as const;

export type BundledSkillName = (typeof BUNDLED_SKILL_NAMES)[number];

interface FrontmatterDocument {
  fields: Record<string, string>;
  body: string;
}

/** Split a `---` delimited YAML-style frontmatter block of `key: value` lines from a markdown body. */
export function parseFrontmatter(markdown: string): FrontmatterDocument {
  const match = /^---\r?\n([\s\S]*?)\r?\n---\r?\n?([\s\S]*)$/.exec(markdown);
  if (!match) {
    return { fields: {}, body: markdown };
  }

  const fields: Record<string, string> = {};
  for (const line of match[1].split(/\r?\n/)) {
    const separator = line.indexOf(":");
    if (separator === -1) continue;
    fields[line.slice(0, separator).trim()] = line.slice(separator + 1).trim();
  }
  return { fields, body: match[2] };
}

/** Expose a Pi workflow prompt (`cli/prompts/<name>.md`) as an on-demand skill. */
export function workflowSkillConfig(name: WorkflowName): GrclankerSkillConfig {
  return {
    description: WORKFLOW_DESCRIPTIONS[name],
    markdown: readCliAsset("prompts", `${name}.md`).trim(),
  };
}

/** Expose a bundled Pi skill (`cli/skills/<name>/SKILL.md`) as an SDK skill. */
export function bundledSkillConfig(name: BundledSkillName): GrclankerSkillConfig {
  const { fields, body } = parseFrontmatter(readCliAsset("skills", name, "SKILL.md"));
  const description = fields.description;
  if (!description) {
    throw new Error(`Bundled skill "${name}" is missing a description in its SKILL.md frontmatter.`);
  }
  return { description, markdown: body.trim() };
}
