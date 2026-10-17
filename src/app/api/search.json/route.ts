import { createSearchAPI } from 'fumadocs-core/search/server';
import { getDocHref } from '../../../lib/docs';
import { getDocSlug, source } from '../../../lib/source';
import { categoryLabels, loadSpecs } from '../../../lib/specs';

export const revalidate = false;

const noContent = { headings: [], contents: [] };

// The docs overview is indexed with the docs, at /docs/.
const sitePages = [
  { url: '/', title: 'CLI', description: 'Install grclanker and see its domain tools, vendor integrations, and runtime paths' },
  { url: '/specs/', title: 'Specs', description: 'Repository specs for shipped integrations and compute backends' },
  { url: '/about/', title: 'About', description: 'What grclanker ships today' },
].map((page) => ({ ...page, id: page.url, breadcrumbs: ['Page'], structuredData: noContent }));

// Titles, descriptions, and headings only: body text would make the static
// index the browser downloads several times larger.
const docs = source.getPages().map((page) => {
  const url = getDocHref(getDocSlug(page));
  return {
    id: url,
    title: page.data.title,
    description: page.data.description,
    url,
    breadcrumbs: ['Docs'],
    structuredData: { headings: page.data.structuredData.headings, contents: [] },
  };
});

const specs = loadSpecs().map((spec) => {
  const url = `/specs/${spec.slug}/`;
  return {
    id: url,
    title: spec.name,
    description: `${spec.vendor} · ${categoryLabels[spec.category] ?? spec.category}`,
    url,
    breadcrumbs: ['Spec'],
    structuredData: noContent,
  };
});

export const { staticGET: GET } = createSearchAPI('advanced', {
  indexes: [...sitePages, ...docs, ...specs],
});
