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

// The integration guides and the generated FedRAMP section hold over 90% of the
// docs text. Their body text would make the static index the browser downloads
// about eight times larger, so they are indexed by title, description, and
// headings only.
const headingsOnlySections = new Set(['integrations', 'fedramp']);

const docs = source.getPages().map((page) => {
  const slug = getDocSlug(page);
  const url = getDocHref(slug);
  const { headings, contents } = page.data.structuredData;
  return {
    id: url,
    title: page.data.title,
    description: page.data.description,
    url,
    breadcrumbs: ['Docs'],
    structuredData: { headings, contents: headingsOnlySections.has(slug.split('/')[0]) ? [] : contents },
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
  // Search never sorts by a field, so the sort index would only add to the download.
  sort: { enabled: false },
});
