'use client';

import { lazy } from 'react';

// Its own chunk, so the search engine stays out of every page's main bundle.
export const SiteSearchDialog = lazy(() => import('./site-search-dialog'));
