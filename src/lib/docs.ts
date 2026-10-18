export interface DocsSectionItem {
  label: string;
  slug: string;
  /** Pages listed under this one, such as the FedRAMP processes under their hub. */
  items?: DocsSectionItem[];
}

export interface DocsSection {
  title: string;
  items: DocsSectionItem[];
}

interface DocsSectionEntry extends DocsSectionItem {
  /** Lists every page under this slug prefix beneath the item. */
  childPrefix?: string;
}

export const docsSections: Array<{ title: string; items: DocsSectionEntry[] }> = [
  {
    title: 'Getting Started',
    items: [
      { label: 'Overview', slug: '' },
      { label: "What's New", slug: 'changelog' },
      { label: 'Installation', slug: 'getting-started/installation' },
      { label: 'Quick Start', slug: 'getting-started/quick-start' },
      { label: 'Setup', slug: 'getting-started/setup' },
      { label: 'Configuration', slug: 'getting-started/configuration' },
    ],
  },
  {
    title: 'Runtimes',
    items: [
      { label: 'Compute Backends', slug: 'getting-started/compute-backends' },
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
    title: 'Reference',
    items: [
      { label: 'Tool Catalog', slug: 'tools/catalog' },
      { label: 'Using Specs as Inputs', slug: 'specs/using-specs-as-inputs' },
    ],
  },
  {
    title: 'FedRAMP',
    items: [
      { label: 'Official Sources', slug: 'fedramp' },
      { label: 'Processes', slug: 'fedramp/processes', childPrefix: 'fedramp/processes/' },
      { label: 'KSI Domains', slug: 'fedramp/ksis', childPrefix: 'fedramp/ksi/' },
    ],
  },
];

/**
 * Docs under this prefix are integration guides (one file per grclanker
 * integration, for example `integrations/box.md`). They are picked up
 * automatically, so adding a guide never requires touching this file.
 */
export const integrationsDocsPrefix = 'integrations/';

export function buildDocsSections(
  entries: Array<{ id: string; data: { title: string } }>,
): DocsSection[] {
  const pagesUnder = (prefix: string) =>
    entries
      .filter((entry) => entry.id.startsWith(prefix))
      .map((entry) => ({ label: entry.data.title, slug: entry.id }))
      .sort((a, b) => a.label.localeCompare(b.label));

  const sections: DocsSection[] = docsSections.map((section) => ({
    title: section.title,
    items: section.items.map(({ childPrefix, ...item }) => {
      const items = childPrefix ? pagesUnder(childPrefix) : [];
      return items.length ? { ...item, items } : item;
    }),
  }));
  const integrations = pagesUnder(integrationsDocsPrefix);
  if (integrations.length) sections.push({ title: 'Integrations', items: integrations });
  return sections;
}

export function getDocHref(slug: string) {
  if (!slug || slug === 'index') return '/docs/';
  return `/docs/${slug}/`;
}
