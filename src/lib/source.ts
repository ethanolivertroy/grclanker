import { loader } from 'fumadocs-core/source';
import type * as PageTree from 'fumadocs-core/page-tree';
import { defineDocs } from 'fumadocs-mdx/macro';
import { buildDocsSections, getDocHref, type DocsSectionItem } from './docs';

const docs = defineDocs({ dir: 'src/content/docs/docs' });

export const source = loader({
  baseUrl: '/docs',
  source: docs.toFumadocsSource(),
  url: (slugs) => getDocHref(slugs.join('/')),
});

export type DocsPage = ReturnType<typeof source.getPages>[number];

export function getDocSlug(page: DocsPage) {
  return page.slugs.join('/');
}

export function getDocsSections() {
  return buildDocsSections(
    source.getPages().map((page) => ({ id: getDocSlug(page), data: { title: page.data.title } })),
  );
}

// Fumadocs finds the current page by comparing tree URLs to the pathname with
// its trailing slash removed. Next's Link adds the slash back (`trailingSlash`).
function treePage(item: DocsSectionItem): PageTree.Item {
  return { type: 'page', name: item.label, url: getDocHref(item.slug).replace(/(.)\/$/, '$1') };
}

// The sidebar order comes from src/lib/docs.ts rather than meta.json files, so
// a new integration guide never needs a shared-file edit.
export function getDocsTree(): PageTree.Root {
  return {
    name: 'Docs',
    children: getDocsSections().flatMap((section): PageTree.Node[] => [
      { type: 'separator', name: section.title },
      ...section.items.map((item): PageTree.Node =>
        item.items
          ? { type: 'folder', name: item.label, index: treePage(item), children: item.items.map(treePage) }
          : treePage(item),
      ),
    ]),
  };
}
