'use client';

import { lazy } from 'react';

const loadSiteSearchDialog = () => import('./site-search-dialog');

// Its own chunk, so the search engine stays out of every page's main bundle.
export const SiteSearchDialog = lazy(loadSiteSearchDialog);

// Starts the download when a reader reaches for a search button, so the dialog
// is usually ready by the time it opens.
export function preloadSiteSearchDialog() {
  void loadSiteSearchDialog();
}
