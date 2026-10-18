import { createSearchAPI } from 'fumadocs-core/search/server';
import { searchPages } from '../../../lib/search-pages';
import { createSearchTokenizer, getIndexedProperties } from '../../../lib/search-tokenizer.mjs';

export const revalidate = false;

export const { staticGET: GET } = createSearchAPI('advanced', {
  indexes: searchPages,
  tokenizer: createSearchTokenizer(),
  components: { getDocumentProperties: getIndexedProperties },
  // Search never sorts by a field, so the sort index would only add to the download.
  sort: { enabled: false },
});
