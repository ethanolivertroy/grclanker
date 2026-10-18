import assert from 'node:assert/strict';
import { test } from 'node:test';

import { rankTitleMatchesFirst } from '../src/lib/search-ranking.mjs';

const page = (url, content) => ({ type: 'page', url, content });
const hit = (url, content) => ({ type: 'heading', url, content });

test('pages titled with the query move above body matches, with their hits', () => {
  const results = [
    page('/docs/integrations/aws/', 'AWS'),
    hit('/docs/integrations/aws/#fedramp', 'FedRAMP'),
    page('/docs/fedramp/', 'FedRAMP Official Sources'),
    hit('/docs/fedramp/#processes', 'Processes'),
  ];
  assert.deepEqual(rankTitleMatchesFirst('fedramp', results), [results[2], results[3], results[0], results[1]]);
});

test('an exact title beats a title prefix, which beats matching title words', () => {
  const results = [
    page('/docs/workflows/a/', 'Run an Audit'),
    page('/docs/workflows/b/', 'Audit Bundles'),
    page('/docs/workflows/c/', 'Audit'),
  ];
  assert.deepEqual(
    rankTitleMatchesFirst('audit', results).map((result) => result.content),
    ['Audit', 'Audit Bundles', 'Run an Audit'],
  );
});

test('title matches with more results under their URL come first', () => {
  const results = [
    page('/docs/fedramp/processes/vdr/', 'FedRAMP Vulnerability Detection'),
    page('/docs/tools/catalog/', 'Tool Catalog'),
    page('/docs/fedramp/processes/', 'FedRAMP Processes'),
    page('/docs/fedramp/', 'FedRAMP Official Sources'),
    page('/docs/integrations/aws/', 'AWS'),
  ];
  assert.deepEqual(
    rankTitleMatchesFirst('fedramp', results).map((result) => result.url),
    [
      '/docs/fedramp/',
      '/docs/fedramp/processes/',
      '/docs/fedramp/processes/vdr/',
      '/docs/tools/catalog/',
      '/docs/integrations/aws/',
    ],
  );
});

test('equally matching titles keep the search engine order', () => {
  const results = [
    page('/docs/integrations/crowdstrike/', 'CrowdStrike Falcon'),
    page('/specs/crowdstrike-sec-inspector/', 'CrowdStrike Security Inspector'),
  ];
  assert.deepEqual(rankTitleMatchesFirst('crowdstrike', results), results);
});

test('case, punctuation, word order, and plurals do not affect title matches', () => {
  const results = [
    page('/docs/a/', 'Body Match'),
    page('/docs/changelog/', "What's New"),
    page('/docs/b/', 'Start Quick'),
    page('/docs/tools/catalog/', 'Tool Catalog'),
  ];
  assert.equal(rankTitleMatchesFirst("what's NEW", results)[0].url, '/docs/changelog/');
  assert.equal(rankTitleMatchesFirst('quick start', results)[0].url, '/docs/b/');
  assert.equal(rankTitleMatchesFirst('tools', results)[0].url, '/docs/tools/catalog/');
});

test('a query with no words leaves results unchanged', () => {
  const results = [page('/docs/a/', 'A'), page('/docs/b/', 'B')];
  assert.equal(rankTitleMatchesFirst(' ? ', results), results);
});
