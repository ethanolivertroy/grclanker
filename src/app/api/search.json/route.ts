import { readdirSync } from 'node:fs';
import { join } from 'node:path';
import { createSearchAPI } from 'fumadocs-core/search/server';
import { getDocHref } from '../../../lib/docs';
import { identifierContents } from '../../../lib/search-identifiers.mjs';
import { createSearchTokenizer } from '../../../lib/search-tokenizer.mjs';
import { getDocSlug, getDocsSections, source } from '../../../lib/source';
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
// about eight times larger, so they are indexed by title, description,
// headings, and the identifiers each section mentions, such as environment
// variables, tool names, finding IDs, and control IDs.
const identifiersOnlySections = new Set(['integrations', 'fedramp']);

// `sync:agent-sdk-tools` writes one file per registered tool, named after it.
const toolNames = new Set(
  readdirSync(join(process.cwd(), 'cli/agent-sdk/bot/tools')).map((file) => file.replace(/\.ts$/, '')),
);

// A hit shows its sidebar section above the page title. That is what tells a
// FedRAMP KSI domain such as "Incident Response" apart from the guides.
const sectionTrails = new Map<string, string[]>();
for (const section of getDocsSections()) {
  for (const item of section.items) {
    sectionTrails.set(item.slug, [section.title]);
    for (const child of item.items ?? []) sectionTrails.set(child.slug, [section.title, item.label]);
  }
}

const docs = source.getPages().map((page) => {
  const slug = getDocSlug(page);
  const url = getDocHref(slug);
  const { headings, contents } = page.data.structuredData;
  return {
    id: url,
    title: page.data.title,
    description: page.data.description,
    url,
    breadcrumbs: ['Docs', ...(sectionTrails.get(slug) ?? [])],
    structuredData: {
      headings,
      contents: identifiersOnlySections.has(slug.split('/')[0]) ? identifierContents(contents, toolNames) : contents,
    },
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
  tokenizer: createSearchTokenizer(),
  // Search never sorts by a field, so the sort index would only add to the download.
  sort: { enabled: false },
});
