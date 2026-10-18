'use client';

import { useEffect, useState } from 'react';
import {
  type SearchClient,
  type SearchResultItem,
  type UseSearchReturn,
  useDocsSearch,
} from 'fumadocs-core/search/client';
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
import { create } from 'zbsearch';
import { rankTitleMatchesFirst } from '../lib/search-ranking.mjs';
import { createSearchTokenizer, searchWholeIdentifiersFirst } from '../lib/search-tokenizer.mjs';
import { primaryLinks } from '../lib/site';

const staticSearch = staticClient({
  from: '/api/search.json',
  // The exported index brings its own fields, but queries must be tokenized the way it was built.
  initDB: () => create({ schema: { _: 'string' }, components: { tokenizer: createSearchTokenizer() } }),
  // Fumadocs defaults to 60 hits, up to 8 per page, so one long page with many
  // matching sections can crowd the rest out of the list.
  search: { limit: 200, groupBy: { properties: ['page_id'], maxResult: 3 } },
});

const client: SearchClient = {
  deps: staticSearch.deps,
  search: async (query) => rankTitleMatchesFirst(query, await searchWholeIdentifiersFirst(staticSearch.search, query)),
};

const defaultItems = primaryLinks.map((link) => ({
  type: 'page' as const,
  id: link.href,
  content: link.label,
  url: link.href,
}));

function Empty() {
  return (
    <div className="search-empty">
      <img src="/empty-state.webp" alt="" width={96} height={96} loading="lazy" />
      No pages found
    </div>
  );
}

function countResults(items: SearchResultItem[]) {
  return items.reduce((count, item) => count + (item.type === 'table' ? item.rows.length : 1), 0);
}

/**
 * Says how many results the list holds once typing pauses. Fumadocs' own
 * status line in the dialog only reports failed searches.
 */
function ResultCount({ search, isLoading, data, error }: UseSearchReturn) {
  const [message, setMessage] = useState('');

  useEffect(() => {
    // Clearing first lets a refined query with the same count be spoken again.
    setMessage('');
    if (!search || isLoading || error || data?.query !== search) return;
    const count = countResults(data.items);
    const timer = setTimeout(() => {
      setMessage(count === 0 ? 'No pages found' : `${count} ${count === 1 ? 'result' : 'results'}`);
    }, 1000);
    return () => clearTimeout(timer);
  }, [search, isLoading, data, error]);

  return (
    <p role="status" className="sr-only">
      {message}
    </p>
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
          <ResultCount {...search} />
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
