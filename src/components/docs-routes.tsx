import Link from 'next/link';
import { Fragment } from 'react';
import type { TOCItemType } from 'fumadocs-core/toc';
import { getDocHref, integrationsDocsPrefix } from '../lib/docs';
import { getDocSlug, getDocsSections, source } from '../lib/source';
import { DocsHeading } from './docs-heading';

interface DocsRoute {
  href: string;
  label: string;
  description?: string;
}

interface DocsRouteGroup {
  id: string;
  title: string;
  routes: DocsRoute[];
  namesOnly: boolean;
}

// Built from the sidebar sections and each page's frontmatter, so a new guide
// needs no edit to the landing page.
function getDocsRouteGroups(): DocsRouteGroup[] {
  const descriptions = new Map(source.getPages().map((page) => [getDocSlug(page), page.data.description]));

  return getDocsSections()
    .map((section) => {
      const items = section.items.filter((item) => item.slug !== '');
      return {
        id: section.title.toLowerCase().replace(/[^a-z0-9]+/g, '-'),
        title: section.title,
        routes: items.map((item) => ({
          href: getDocHref(item.slug),
          label: item.label,
          description: descriptions.get(item.slug),
        })),
        // Integration guides are many and each is named for its product.
        namesOnly: items.every((item) => item.slug.startsWith(integrationsDocsPrefix)),
      };
    })
    .filter((group) => group.routes.length > 0);
}

export function getDocsRoutesToc(): TOCItemType[] {
  return getDocsRouteGroups().map((group) => ({ title: group.title, url: `#${group.id}`, depth: 2 }));
}

export function DocsRoutes() {
  return (
    <nav className="docs-routes" aria-label="Docs sections">
      {getDocsRouteGroups().map((group) => (
        <Fragment key={group.id}>
          <DocsHeading as="h2" id={group.id}>
            {group.title}
          </DocsHeading>
          <ul className="docs-route-list" data-names-only={group.namesOnly || undefined}>
            {group.routes.map((route) => (
              <li key={route.href}>
                <Link href={route.href}>
                  <span className="docs-route-label">{route.label}</span>
                  {!group.namesOnly && route.description && (
                    <>
                      {' '}
                      <span className="docs-route-description">{route.description}</span>
                    </>
                  )}
                </Link>
              </li>
            ))}
          </ul>
        </Fragment>
      ))}
    </nav>
  );
}
