import { createSearchAPI } from 'fumadocs-core/search/server';
import { docsSearchPages, searchPages } from '../../../lib/search-pages';
import { createSearchTokenizer } from '../../../lib/search-tokenizer.mjs';
import { createVocabulary, createWordIndex } from '../../../lib/search-words.mjs';

export const revalidate = false;

const tokenizer = createSearchTokenizer();
const { indexes, getDocumentProperties } = createWordIndex(docsSearchPages, createVocabulary(searchPages, tokenizer), tokenizer);

export const { staticGET: GET } = createSearchAPI('advanced', {
  indexes,
  tokenizer,
  components: { getDocumentProperties },
  sort: { enabled: false },
});
