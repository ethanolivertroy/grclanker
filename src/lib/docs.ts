export const docsDefaultSlug = 'getting-started/installation';

export const docsSections = [
  {
    title: 'Getting Started',
    items: [
      { label: 'Overview', slug: '' },
      { label: 'Installation', slug: 'getting-started/installation' },
      { label: 'Quick Start', slug: 'getting-started/quick-start' },
      { label: 'Setup', slug: 'getting-started/setup' },
      { label: 'Configuration', slug: 'getting-started/configuration' },
      { label: 'Cursor Agent SDK', slug: 'getting-started/agent-sdk' },
      { label: 'Flue Runtime', slug: 'getting-started/flue-runtime' },
    ],
  },
  {
    title: 'Workflows',
    items: [
      { label: 'Investigate', slug: 'workflows/investigate' },
      { label: 'Audit', slug: 'workflows/audit' },
      { label: 'Assess', slug: 'workflows/assess' },
      { label: 'Validate', slug: 'workflows/validate' },
    ],
  },
  {
    title: 'Tools',
    items: [
      { label: 'Tool Catalog', slug: 'tools/catalog' },
    ],
  },
  {
    title: 'Specs',
    items: [
      { label: 'Using Specs as Inputs', slug: 'specs/using-specs-as-inputs' },
    ],
  },
  {
    title: 'FedRAMP',
    items: [
      { label: 'Official Sources', slug: 'fedramp' },
      { label: 'Processes', slug: 'fedramp/processes' },
      { label: 'KSI Domains', slug: 'fedramp/ksis' },
    ],
  },
];

export interface DocsSectionItem {
  label: string;
  slug: string;
}

export interface DocsSection {
  title: string;
  items: DocsSectionItem[];
}

/**
 * Docs under this prefix are integration guides (one file per grclanker
 * integration, for example `integrations/box.md`). They are picked up
 * automatically, so adding a guide never requires touching this file.
 */
export const integrationsDocsPrefix = 'integrations/';

export function buildDocsSections(
  entries: Array<{ id: string; data: { title: string } }>,
): DocsSection[] {
  const integrations = entries
    .filter((entry) => entry.id.startsWith(integrationsDocsPrefix))
    .map((entry) => ({ label: entry.data.title, slug: entry.id }))
    .sort((a, b) => a.label.localeCompare(b.label));

  if (integrations.length === 0) return docsSections;

  const sections: DocsSection[] = [];
  for (const section of docsSections) {
    sections.push(section);
    if (section.title === 'Tools') {
      sections.push({ title: 'Integrations', items: integrations });
    }
  }
  return sections;
}

export function getDocHref(slug: string) {
  if (!slug || slug === 'index') return '/docs';
  return `/docs/${slug}`;
}
