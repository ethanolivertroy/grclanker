import assert from 'node:assert/strict';
import { test } from 'node:test';
import { staticClient } from 'fumadocs-core/search/client/orama-static';
import { createSearchAPI } from 'fumadocs-core/search/server';
import { create } from 'zbsearch';

import { createSearchTokenizer, getIndexedProperties } from '../src/lib/search-tokenizer.mjs';
import { createVocabulary, createWordIndex, plainWords, searchUnknownWords } from '../src/lib/search-words.mjs';

const tokenizer = createSearchTokenizer();

test('plain words split compounds and keep short numbers, but not hashes or long IDs', () => {
  assert.deepEqual(plainWords('Set sandbox.allowedDomains and webhooks_read'), ['Set', 'sandbox', 'allowedDomains', 'and', 'webhooks', 'read']);
  assert.deepEqual(plainWords('2FA Log4Shell SHA256 ed25519 v1 429 27017'), ['2FA', 'Log4Shell', 'SHA256', 'ed25519', 'v1', '429', '27017']);
  assert.deepEqual(plainWords('12 123456 4ed99953efa5 u000a 0oa1b2c3d4'), []);
});

// Pages shaped like the ones search-pages.ts lists. The main index leaves out
// the integration pages' body text, as it does on the site.
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
        { heading: undefined, content: 'Reads the org through the management API.' },
        { heading: 'setup', content: 'Create an API token, set okta.orgUrl, then run the assessment.' },
        { heading: 'rate-limits', content: 'Okta throttles bursts, so each call retries a 429 with backoff.' },
      ],
    },
  },
  {
    id: '/docs/integrations/slack/',
    url: '/docs/integrations/slack/',
    title: 'Slack',
    description: 'Assess workspace settings',
    breadcrumbs: ['Docs', 'Integrations'],
    structuredData: {
      headings: [
        { id: 'users', content: 'Users' },
        { id: 'events', content: 'Events' },
      ],
      contents: [
        { heading: 'users', content: 'Lists users through the SCIM API.' },
        { heading: 'events', content: 'Webhook deliveries that get a 429 retry with backoff.' },
      ],
    },
  },
  {
    id: '/docs/getting-started/configuration/',
    url: '/docs/getting-started/configuration/',
    title: 'Configuration',
    description: 'Set up grclanker',
    breadcrumbs: ['Docs'],
    structuredData: {
      headings: [{ id: 'sandbox', content: 'Sandbox' }],
      contents: [{ heading: 'sandbox', content: 'Run npm install, then list hosts in sandbox.allowedDomains to reach an API.' }],
    },
  },
];

const mainPages = docsPages.map((page) =>
  page.url.startsWith('/docs/integrations/')
    ? { ...page, structuredData: { headings: page.structuredData.headings, contents: [] } }
    : page,
);

const found = createVocabulary(mainPages, tokenizer);

test('the vocabulary finds what a main index search would, prefixes included', () => {
  for (const word of ['okta', 'ok', 'rate', 'users', 'sandbox', 'api']) assert.equal(found(word), true, word);
  // Body text left out of the main index, and the inner part of a compound token.
  for (const word of ['throttles', 'scim', 'webhook', 'alloweddomains', 'assessment']) assert.equal(found(word), false, word);
});

async function exportIndex(indexes, options) {
  const api = createSearchAPI('advanced', { indexes, tokenizer: createSearchTokenizer(), sort: { enabled: false }, ...options });
  return JSON.parse(JSON.stringify(await api.export()));
}

function loadLikeTheDialog(data) {
  return staticClient({
    from: `data:application/json,${encodeURIComponent(JSON.stringify(data))}`,
    initDB: () => create({ schema: { _: 'string' }, components: { tokenizer: createSearchTokenizer() } }),
    search: { limit: 200, groupBy: { properties: ['page_id'], maxResult: 3 } },
  }).search;
}

const wordIndex = createWordIndex(docsPages, found, tokenizer);
const wordExport = await exportIndex(wordIndex.indexes, { components: { getDocumentProperties: wordIndex.getDocumentProperties } });
const searchMain = loadLikeTheDialog(await exportIndex(mainPages, { components: { getDocumentProperties: getIndexedProperties } }));
const searchWords = loadLikeTheDialog(wordExport);
const urls = (results) => results.map((result) => result.url);

test('the word index stores page titles and headings, never body text', () => {
  assert.deepEqual(
    Object.values(wordExport.docs.docs).map((doc) => `${doc.type}: ${doc.content}`),
    [
      'page: Okta',
      'heading: Setup',
      'heading: Rate limits',
      'page: Slack',
      'heading: Users',
      'heading: Events',
      'page: Configuration',
      'heading: Sandbox',
    ],
  );
});

test('the word index finds each section by the words the main index lacks', async () => {
  assert.deepEqual(urls(await searchWords('throttles')), ['/docs/integrations/okta/', '/docs/integrations/okta/#rate-limits']);
  // Text above the first heading is found under the page.
  assert.deepEqual(urls(await searchWords('management')), ['/docs/integrations/okta/']);
  assert.deepEqual(urls(await searchWords('allowedDomains')), ['/docs/getting-started/configuration/', '/docs/getting-started/configuration/#sandbox']);
  for (const word of ['okta', 'api', 'users', 'install']) assert.deepEqual(await searchWords(word), [], word);
});

test('a search finds body text and compound parts the main index leaves out', async () => {
  const searched = [];
  const record = async (query) => {
    searched.push(query);
    return searchWords(query);
  };
  const find = async (query) => urls(await searchUnknownWords(query, searchMain, record));

  assert.deepEqual(await find('SCIM'), ['/docs/integrations/slack/', '/docs/integrations/slack/#users']);
  assert.deepEqual((await find('429 backoff')).sort(), [
    '/docs/integrations/okta/',
    '/docs/integrations/okta/#rate-limits',
    '/docs/integrations/slack/',
    '/docs/integrations/slack/#events',
  ]);
  assert.deepEqual(await find('okta throttles'), ['/docs/integrations/okta/', '/docs/integrations/okta/#rate-limits']);
  // A setting named only in an integration guide, and the inner part of a
  // compound the main index holds whole.
  assert.deepEqual(await find('okta.orgUrl'), ['/docs/integrations/okta/', '/docs/integrations/okta/#setup']);
  assert.deepEqual(await find('allowedDomains'), ['/docs/getting-started/configuration/', '/docs/getting-started/configuration/#sandbox']);
  assert.deepEqual(searched, ['SCIM', '429 backoff', 'throttles', 'orgUrl', 'allowedDomains']);

  searched.length = 0;
  for (const query of ['npm install', 'sandbox.allowedDomains']) {
    assert.deepEqual(await searchUnknownWords(query, searchMain, record), await searchMain(query), query);
  }
  assert.deepEqual(searched, []);
});

const page = (url) => ({ type: 'page', url, content: url });
const hit = (url) => ({ type: 'heading', url, content: url });

function fakeSearch(results) {
  const searched = [];
  const search = async (query) => {
    searched.push(query);
    return results[query] ?? [];
  };
  return { search, searched };
}

test('pages with the missing words come first, led by those matching the rest of the query', async () => {
  const main = fakeSearch({
    'okta 429': [page('/a/'), hit('/a/#x'), page('/b/'), hit('/b/#y')],
    okta: [page('/a/'), page('/b/')],
  });
  const words = fakeSearch({ 429: [page('/c/'), hit('/c/#z'), page('/b/'), hit('/b/#w')] });
  const results = await searchUnknownWords('okta 429', main.search, words.search);
  assert.deepEqual(urls(results), ['/b/', '/b/#w', '/c/', '/c/#z', '/a/', '/a/#x']);
  assert.deepEqual(main.searched, ['okta 429', 'okta', '429']);
  assert.deepEqual(words.searched, ['429']);
});

test('main results stand when every term is found, the word index finds nothing, or it fails to load', async () => {
  const results = [page('/a/'), hit('/a/#x')];
  const main = fakeSearch({ okta: results, 'okta zzz': results, 'CM.L2-3.4.1': results });

  const words = fakeSearch({ L2: [page('/b/')] });
  assert.equal(await searchUnknownWords('okta', main.search, words.search), results);
  // The main index finds the ID whole, so L2, which it has no token for, is not missing.
  assert.equal(await searchUnknownWords('CM.L2-3.4.1', main.search, words.search), results);
  assert.deepEqual(main.searched, ['okta', 'CM.L2-3.4.1']);
  assert.deepEqual(words.searched, []);
  assert.deepEqual(await searchUnknownWords('okta zzz', main.search, words.search), results);
  assert.deepEqual(words.searched, ['zzz']);

  const failing = async () => {
    throw new Error('failed to fetch');
  };
  assert.equal(await searchUnknownWords('okta zzz', main.search, failing), results);
});
