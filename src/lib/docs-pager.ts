import type * as PageTree from 'fumadocs-core/page-tree';

export type PagerLink = Pick<PageTree.Item, 'name' | 'description' | 'url'>;

// What's New stays near the top of the sidebar, but release notes are not a
// step through the docs: the overview leads to Installation.
const offPathUrls = new Set(['/docs/changelog']);

const withoutTrailingSlash = (url: string) => url.replace(/(.)\/$/, '$1');

/**
 * The previous and next pages for the docs page footer, in sidebar order. Each
 * link is described by its sidebar section, which Fumadocs shows in place of
 * "Previous Page" or "Next Page".
 */
export function getPagerLinks(tree: PageTree.Root, url: string): { previous?: PagerLink; next?: PagerLink } {
  const links: PagerLink[] = [];
  let section: PageTree.Separator['name'];
  const visit = (node: PageTree.Node | undefined) => {
    if (!node) return;
    if (node.type === 'separator') section = node.name;
    else if (node.type === 'folder') [node.index, ...node.children].forEach(visit);
    else if (!node.external) links.push({ name: node.name, url: node.url, description: section });
  };
  tree.children.forEach(visit);

  const current = withoutTrailingSlash(url);
  const index = links.findIndex((link) => withoutTrailingSlash(link.url) === current);
  if (index === -1) return {};
  const onPath = (link: PagerLink) => !offPathUrls.has(withoutTrailingSlash(link.url));
  return {
    previous: links.slice(0, index).findLast(onPath),
    next: links.slice(index + 1).find(onPath),
  };
}
