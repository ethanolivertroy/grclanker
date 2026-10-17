'use client';

import { useDocsSearch } from 'fumadocs-core/search/client';
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
import { primaryLinks } from '../lib/site';

const client = staticClient({ from: '/api/search.json' });

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
