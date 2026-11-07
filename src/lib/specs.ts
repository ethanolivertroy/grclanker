import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { parseDocument } from 'yaml';
import { z } from 'zod';

export interface SpecCategoryGroup {
  label: string;
  specs: SpecMeta[];
}

export const categoryLabels: Record<string, string> = {
  'cloud-infrastructure': 'Cloud Infrastructure',
  'identity-access-management': 'Identity & Access Management',
  'security-network-infrastructure': 'Security & Network Infrastructure',
  'vulnerability-application-security': 'Vulnerability & Application Security',
  'monitoring-logging-observability': 'Monitoring, Logging & Observability',
  'saas-collaboration': 'SaaS & Collaboration',
  'devops-developer-platforms': 'DevOps & Developer Platforms',
  'community-specs': 'Community Specs',
};

/**
 * Category names that generated specs carry from the CLI registry, mapped to the catalog group each belongs to.
 * Unknown categories fail at the metadata boundary instead of hiding a spec.
 */
export const categoryAliases: Record<string, string> = {
  'application-security': 'vulnerability-application-security',
  cloud: 'cloud-infrastructure',
  'cloud-and-network-security': 'security-network-infrastructure',
  collaboration: 'saas-collaboration',
  'collaboration-and-content': 'saas-collaboration',
  'crm-and-business-applications': 'saas-collaboration',
  'customer-support': 'saas-collaboration',
  'edge-security': 'security-network-infrastructure',
  'endpoint-security': 'security-network-infrastructure',
  'identity-and-access': 'identity-access-management',
  'identity-and-collaboration': 'identity-access-management',
  'it-service-management': 'saas-collaboration',
  'security-awareness': 'vulnerability-application-security',
  'zero-trust-and-secure-web-gateway': 'security-network-infrastructure',
};

/** The catalog group key for a spec's frontmatter category. */
export function getCategoryKey(category: string) {
  const key = categoryAliases[category] ?? category;
  if (!Object.hasOwn(categoryLabels, key)) throw new Error(`Unknown spec category: ${category}`);
  return key;
}

export function getCategoryLabel(category: string) {
  return categoryLabels[getCategoryKey(category)];
}

const nonempty = z.string().trim().min(1);
const httpUrl = z.url().refine((value) => /^https?:\/\//.test(value), 'Expected an HTTP(S) URL');

export const specMetadataSchema = z.object({
  slug: nonempty.regex(/^[a-z0-9]+(?:-[a-z0-9]+)*$/),
  name: nonempty,
  vendor: nonempty,
  category: nonempty.refine((value) => Object.hasOwn(categoryLabels, categoryAliases[value] ?? value), 'Unknown spec category'),
  language: nonempty,
  status: z.enum(['generated', 'implemented', 'spec-only']),
  version: nonempty,
  source_repo: httpUrl,
  source_pr: httpUrl.optional(),
  contributor: nonempty.optional(),
  contributor_url: httpUrl.optional(),
  last_updated: z.iso.date(),
});

export type SpecMeta = z.infer<typeof specMetadataSchema>;
export interface SpecDocument { meta: SpecMeta; content: string }

/** Parse real YAML, including generator-escaped strings, then validate the metadata contract. */
export function parseFrontmatter(raw: string): SpecDocument {
  const match = raw.replace(/\r\n/g, '\n').match(/^---\n([\s\S]*?)\n---(?:\n|$)([\s\S]*)$/);
  if (!match) throw new Error('Invalid spec frontmatter');
  const document = parseDocument(match[1], { uniqueKeys: true });
  if (document.errors.length) throw new Error(`Invalid spec YAML: ${document.errors[0].message}`);
  return { meta: specMetadataSchema.parse(document.toJS({ maxAliasCount: 0 })), content: match[2] };
}

export const RAW_BASE = 'https://raw.githubusercontent.com/ethanolivertroy/grclanker/main/specs';

/** Specs whose guide is not `integrations/<slug without -sec-inspector>`. */
export const specGuideOverrides: Record<string, string> = {
  'grclanker-compute-backends': 'getting-started/compute-backends',
  'gws-inspector-go': 'integrations/gws',
  'gws-operator-bridge': 'integrations/gws-ops',
};

/** The docs slug of the guide that sets up and runs what a spec describes. */
export function getSpecGuideSlug(slug: string) {
  return specGuideOverrides[slug] ?? `integrations/${slug.replace(/-sec-inspector$/, '')}`;
}

const specsDir = join(process.cwd(), 'specs');

/** Load and validate the complete collection before exposing routes or metadata. */
export function loadSpecCatalog(directory: string) {
  const bySlug = new Map<string, SpecDocument>();
  for (const file of readdirSync(directory).filter((name) => name.endsWith('.spec.md'))) {
    let spec: SpecDocument;
    try {
      spec = parseFrontmatter(readFileSync(join(directory, file), 'utf8'));
    } catch (error) {
      throw new Error(`${file}: ${error instanceof Error ? error.message : 'Invalid spec metadata'}`, { cause: error });
    }
    if (bySlug.has(spec.meta.slug)) throw new Error(`${file}: duplicate spec slug ${spec.meta.slug}`);
    if (file !== `${spec.meta.slug}.spec.md`) throw new Error(`${file}: filename does not match spec slug ${spec.meta.slug}`);
    bySlug.set(spec.meta.slug, spec);
  }
  const specs = [...bySlug.values()].sort((a, b) => a.meta.name.localeCompare(b.meta.name));
  return { specs, metadata: specs.map((spec) => spec.meta), bySlug };
}

let catalog: ReturnType<typeof loadSpecCatalog> | undefined;
const getCatalog = () => (catalog ??= loadSpecCatalog(specsDir));

export function readSpecs(): SpecDocument[] {
  return getCatalog().specs.slice();
}

export function loadSpecs(): SpecMeta[] {
  return getCatalog().metadata.slice();
}

export function getSpec(slug: string) {
  return getCatalog().bySlug.get(slug);
}

export function groupSpecsByCategory(specs: SpecMeta[] = loadSpecs()): Record<string, SpecCategoryGroup> {
  const categories: Record<string, SpecCategoryGroup> = {};

  Object.entries(categoryLabels).forEach(([key, label]) => {
    categories[key] = { label, specs: [] };
  });

  specs.forEach((spec) => {
    categories[getCategoryKey(spec.category)].specs.push(spec);
  });

  return categories;
}
