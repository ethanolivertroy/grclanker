import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

export interface SpecMeta {
  slug: string;
  name: string;
  vendor: string;
  category: string;
  language: string;
  status: string;
  version: string;
  source_repo: string;
  source_pr?: string;
  contributor?: string;
  contributor_url?: string;
  last_updated: string;
}

export function parseFrontmatter(raw: string): { meta: SpecMeta; content: string } {
  const normalized = raw.replace(/\r\n/g, '\n');
  const match = normalized.match(/^---\n([\s\S]*?)\n---\n([\s\S]*)$/);
  if (!match) throw new Error('Invalid frontmatter');
  const meta: Record<string, string> = {};
  match[1].split('\n').forEach(line => {
    const colonIdx = line.indexOf(':');
    if (colonIdx === -1) return;
    const key = line.slice(0, colonIdx).trim();
    const val = line.slice(colonIdx + 1).trim().replace(/^["']|["']$/g, '');
    if (key) meta[key] = val;
  });
  return { meta: meta as unknown as SpecMeta, content: match[2] };
}

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

export function readSpecs(): Array<{ meta: SpecMeta; content: string }> {
  return readdirSync(specsDir)
    .filter((file) => file.endsWith('.spec.md'))
    .map((file) => parseFrontmatter(readFileSync(join(specsDir, file), 'utf8')))
    .sort((a, b) => a.meta.name.localeCompare(b.meta.name));
}

export function loadSpecs(): SpecMeta[] {
  return readSpecs().map((spec) => spec.meta);
}

export function getSpec(slug: string) {
  return readSpecs().find((spec) => spec.meta.slug === slug);
}

export function groupSpecsByCategory(specs: SpecMeta[] = loadSpecs()): Record<string, SpecCategoryGroup> {
  const categories: Record<string, SpecCategoryGroup> = {};

  Object.entries(categoryLabels).forEach(([key, label]) => {
    categories[key] = { label, specs: [] };
  });

  specs.forEach((spec) => {
    if (categories[spec.category]) {
      categories[spec.category].specs.push(spec);
    }
  });

  return categories;
}
