import assert from 'node:assert/strict';
import { test } from 'node:test';
import { staticClient } from 'fumadocs-core/search/client/orama-static';
import { createSearchAPI } from 'fumadocs-core/search/server';
import { create } from 'zbsearch';

import { createSearchTokenizer, getIndexedProperties, searchWholeIdentifiersFirst } from '../src/lib/search-tokenizer.mjs';
import { correctTypos, correctWord, indexedWordsNear } from '../src/lib/search-typos.mjs';
import { createVocabulary, createWordIndex } from '../src/lib/search-words.mjs';

const words = (...entries) => new Map(entries.map((word) => [word, 1]));

test('one typo is corrected: a missing, extra, or wrong letter, or two letters swapped', () => {
  const vendors = words('crowdstrike', 'tenable', 'qualys', 'splunk', 'datadog', 'grclanker');
  assert.equal(correctWord('crowdstike', vendors), 'crowdstrike');
  assert.equal(correctWord('tennable', vendors), 'tenable');
  assert.equal(correctWord('qualis', vendors), 'qualys');
  assert.equal(correctWord('splnuk', vendors), 'splunk');
  assert.equal(correctWord('datadgo', vendors), 'datadog');
  assert.equal(correctWord('rgclanker', vendors), 'grclanker');
  assert.equal(correctWord('tenabel', vendors), 'tenable');
  // Two typos away, unrelated, or not a typo at all.
  for (const typed of ['crowdstirk', 'tanabel', 'kubernetes', 'datadog']) assert.equal(correctWord(typed, vendors), undefined, typed);
});

test('the first letter stays unless the first two letters are swapped', () => {
  const vendors = words('crowdstrike', 'okta', 'dpr');
  for (const typed of ['rowdstrike', 'xrowdstrike', 'gdpr']) assert.equal(correctWord(typed, vendors), undefined, typed);
  assert.equal(correctWord('rcowdstrike', vendors), 'crowdstrike');
  assert.equal(correctWord('kota', vendors), 'okta');
  // A doubled first letter leaves the first letter as it is.
  assert.equal(correctWord('ccrowdstrike', vendors), 'crowdstrike');
});

test('a four-letter word is corrected only for swapped letters, a dropped letter, or a neighbouring key', () => {
  const known = words('okta', 'vanta', 'soap', 'case', 'cis');
  assert.equal(correctWord('okat', known), 'okta');
  assert.equal(correctWord('vata', known), 'vanta');
  // S is next to A on a keyboard, but P is far from A, and from R in soap.
  assert.equal(correctWord('okts', known), 'okta');
  for (const typed of ['oktp', 'soar', 'casb', 'cjis']) assert.equal(correctWord(typed, known), undefined, typed);
  // Five letters allow any one typo.
  assert.equal(correctWord('oktaa', known), 'okta');
});

test('the word the most search documents use wins, then the first alphabetically', () => {
  assert.equal(correctWord('tokes', new Map([['tokens', 30], ['tones', 50], ['token', 50]])), 'token');
  assert.equal(correctWord('polcy', new Map([['policy', 40], ['pole', 90]])), 'policy');
  // Identifiers and words with digits are never offered.
  assert.equal(correctWord('oktaa', new Map([['okta2', 90], ['#okta', 90], ['okta', 1]])), 'okta');
});

// Pages shaped like the ones search-pages.ts lists. The main index leaves out
// the integration pages' body text, as it does on the site, so a word used only
// there is in the word index.
const docsPages = [
  {
    id: '/docs/integrations/okta/',
    url: '/docs/integrations/okta/',
    title: 'Okta',
    description: 'Assess MFA policies and admin roles',
    breadcrumbs: ['Docs', 'Integrations'],
    structuredData: {
      headings: [
        { id: 'setup', content: 'Setup' },
        { id: 'rate-limits', content: 'Rate limits' },
      ],
      contents: [
        { heading: 'setup', content: 'Create an API token, then run the assessment.' },
        { heading: 'rate-limits', content: 'Okta throttles bursts, so each call retries with backoff.' },
      ],
    },
  },
  {
    id: '/docs/integrations/crowdstrike/',
    url: '/docs/integrations/crowdstrike/',
    title: 'CrowdStrike',
    description: 'Assess Falcon prevention policies',
    breadcrumbs: ['Docs', 'Integrations'],
    structuredData: {
      headings: [{ id: 'setup', content: 'Setup' }],
      contents: [{ heading: 'setup', content: 'Create an API client with read scopes. Findings map to AC-2.' }],
    },
  },
  {
    id: '/docs/getting-started/configuration/',
    url: '/docs/getting-started/configuration/',
    title: 'Configuration',
    description: 'Set up grclanker',
    breadcrumbs: ['Docs'],
    structuredData: {
      headings: [{ id: 'tokens', content: 'Tokens' }],
      contents: [{ heading: 'tokens', content: 'Keep each token in an environment variable.' }],
    },
  },
];

const mainPages = docsPages.map((page) =>
  page.url.startsWith('/docs/integrations/')
    ? { ...page, structuredData: { headings: page.structuredData.headings, contents: [] } }
    : page,
);

async function exportIndex(indexes, options) {
  const api = createSearchAPI('advanced', { indexes, tokenizer: createSearchTokenizer(), sort: { enabled: false }, ...options });
  return JSON.parse(JSON.stringify(await api.export()));
}

const tokenizer = createSearchTokenizer();
const wordIndex = createWordIndex(docsPages, createVocabulary(mainPages, tokenizer), tokenizer);
const exports = {
  main: await exportIndex(mainPages, { components: { getDocumentProperties: getIndexedProperties } }),
  words: await exportIndex(wordIndex.indexes, { components: { getDocumentProperties: wordIndex.getDocumentProperties } }),
};

// Loads both indexes like the search dialog, keeping each index it creates.
const indexes = [];
function loadLikeTheDialog(data) {
  return staticClient({
    from: `data:application/json,${encodeURIComponent(JSON.stringify(data))}`,
    initDB: () => {
      const index = create({ schema: { _: 'string' }, components: { tokenizer: createSearchTokenizer() } });
      indexes.push(index);
      return index;
    },
    search: { limit: 200, groupBy: { properties: ['page_id'], maxResult: 3 } },
  }).search;
}
const searchStatic = loadLikeTheDialog(exports.main);
const searchMain = (query) => searchWholeIdentifiersFirst(searchStatic, query);
const searchWords = loadLikeTheDialog(exports.words);
await searchMain('okta');
await searchWords('throttles');

test('indexed words come from both indexes, swapped letters included', () => {
  assert.ok(indexedWordsNear('okat', indexes).get('okta') > 0);
  assert.ok(indexedWordsNear('throtles', indexes).get('throttles') > 0);
});

test('a query word that neither index finds is corrected, wherever the right word is indexed', async () => {
  const correct = (query) => correctTypos(query, searchMain, searchWords, indexes);
  assert.equal(await correct('okat'), 'okta');
  assert.equal(await correct('Crowdstike'), 'crowdstrike');
  // Body text that only the word index holds.
  assert.equal(await correct('okta throtles'), 'okta throttles');
  assert.equal(await correct('  Okat  setup '), '  okta  setup ');
});

test('words that find something, short words, identifiers, and words without a close match stay as typed', async () => {
  const searched = { main: [], words: [] };
  const record = (search, list) => (query) => {
    list.push(query);
    return search(query);
  };
  const correct = (query) => correctTypos(query, record(searchMain, searched.main), record(searchWords, searched.words), indexes);
  for (const query of ['okta setup', 'thrott', 'oka', 'AC-3', 'okta2', 'xkta', 'kubernetes', 'tokens environment']) {
    assert.equal(await correct(query), query);
  }
  // Only words of four letters or more are checked, and the word index only
  // for those the main index finds nothing for.
  assert.deepEqual(searched.main, ['okta', 'setup', 'thrott', 'xkta', 'kubernetes', 'tokens', 'environment']);
  assert.deepEqual(searched.words, ['thrott', 'xkta', 'kubernetes']);
});

test('nothing is corrected when the word index fails to load', async () => {
  const failing = async () => {
    throw new Error('failed to fetch');
  };
  assert.equal(await correctTypos('okat', searchMain, failing, indexes), 'okat');
});
