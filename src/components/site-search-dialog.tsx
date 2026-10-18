'use client';

import { type SearchClient, useDocsSearch } from 'fumadocs-core/search/client';
import { staticClient } from 'fumadocs-core/search/client/orama-static';
import {
  SearchDialog,
  SearchDialogClose,
  SearchDialogContent,
  SearchDialogFooter,
  SearchDialogHeader,
  SearchDialogIcon,
  SearchDialogInput,
  SearchDialogList,
  SearchDialogOverlay,
  type SharedProps,
} from 'fumadocs-ui/components/dialog/search';
import { rankTitleMatchesFirst } from '../lib/search-ranking.mjs';
import { primaryLinks } from '../lib/site';

const staticSearch = staticClient({
  from: '/api/search.json',
  // Fumadocs defaults to 60 hits, up to 8 per page, so one long page with many
  // matching sections can crowd the rest out of the list.
  search: { limit: 200, groupBy: { properties: ['page_id'], maxResult: 3 } },
});

const client: SearchClient = {
  deps: staticSearch.deps,
  search: async (query) => rankTitleMatchesFirst(query, await staticSearch.search(query)),
};

const defaultItems = primaryLinks.map((link) => ({
  type: 'page' as const,
  id: link.href,
  content: link.label,
  url: link.href,
}));

function Empty() {
  return (
    <div role="status" className="search-empty">
      <img src="/empty-state.webp" alt="" width={96} height={96} loading="lazy" />
      No pages found
    </div>
  );
}

export default function SiteSearchDialog(props: SharedProps) {
  const search = useDocsSearch({ client });

  return (
    <SearchDialog {...search} {...props}>
      <SearchDialogOverlay className="site-search-overlay" />
      <SearchDialogContent className="site-search">
        <SearchDialogHeader>
          <SearchDialogIcon />
          <SearchDialogInput />
          <SearchDialogClose className="overlay-close">Close</SearchDialogClose>
        </SearchDialogHeader>
        <SearchDialogList defaultItems={defaultItems} Empty={Empty} />
        <SearchDialogFooter className="search-hints">
          <span>
            <kbd>↑</kbd>
            <kbd>↓</kbd> navigate
          </span>
          <span>
            <kbd>Enter</kbd> open
          </span>
          <span>
            <kbd>Esc</kbd> close
          </span>
        </SearchDialogFooter>
      </SearchDialogContent>
    </SearchDialog>
  );
}
