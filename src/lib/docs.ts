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
    title: 'Specs',
    items: [
      { label: 'Using Specs as Inputs', slug: 'specs/using-specs-as-inputs' },
    ],
  },
];

export function getDocHref(slug: string) {
  if (!slug || slug === 'index') return '/docs';
  return `/docs/${slug}`;
}
