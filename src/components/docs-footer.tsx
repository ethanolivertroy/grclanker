import { getDocHref } from '../lib/docs';
import { getPagerLinks, type PagerLink } from '../lib/docs-pager';
import { getDocsTree } from '../lib/source';

// Each card's chevron shows which way it goes, and screen readers skip it.
function withDirection(direction: string, link: PagerLink | undefined) {
  return (
    link && {
      ...link,
      name: (
        <>
          <span className="sr-only">{direction}: </span>
          {link.name}
        </>
      ),
    }
  );
}

/** The previous and next page links for a docs page, labeled with their sidebar sections. */
export function getDocsFooterItems(slug: string) {
  const { previous, next } = getPagerLinks(getDocsTree(), getDocHref(slug));
  return { previous: withDirection('Previous page', previous), next: withDirection('Next page', next) };
}
