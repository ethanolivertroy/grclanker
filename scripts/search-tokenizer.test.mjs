import assert from 'node:assert/strict';
import { test } from 'node:test';
import { staticClient } from 'fumadocs-core/search/client/orama-static';
import { createSearchAPI } from 'fumadocs-core/search/server';
import { components, create, insertMultiple, load, save, search } from 'zbsearch';

import { createSearchTokenizer, getIndexedProperties, searchWholeIdentifiersFirst } from '../src/lib/search-tokenizer.mjs';

const tokenizer = createSearchTokenizer();
const defaultTokenizer = components.tokenizer.createTokenizer({ language: 'multilingual' });

test('a query searches each hyphenated identifier whole', () => {
  assert.deepEqual(tokenizer.tokenize('AWS-IAM-01'), ['#aws-iam-01']);
  assert.deepEqual(tokenizer.tokenize('ac-2.13 root mfa'), ['root', 'mfa', '#ac-2.13']);
  assert.deepEqual(tokenizer.tokenize('AC.L2-3.1.1'), ['#ac.l2-3.1.1']);
  assert.deepEqual(tokenizer.tokenize('KSI-IAM-ELP'), ['#ksi-iam-elp']);
});

test('indexed content keeps every default token, repeats included, and adds each identifier whole', () => {
  const text = 'AWS-IAM-01 maps to ac-2.13. Rerun AWS-IAM-01 after the fix.';
  assert.deepEqual(tokenizer.tokenize(text, undefined, 'content'), [
    ...defaultTokenizer.tokenize(text, undefined, 'content'),
    '#aws-iam-01',
    '#ac-2.13',
    '#aws-iam-01',
  ]);
});

test('hyphenated words, and properties that search ignores, tokenize as before', () => {
  for (const text of ['read-only', 'end-to-end', 'Opt-In', 'ksi-iam-elp']) {
    assert.deepEqual(tokenizer.tokenize(text), defaultTokenizer.tokenize(text));
    assert.deepEqual(tokenizer.tokenize(text, undefined, 'content'), defaultTokenizer.tokenize(text, undefined, 'content'));
  }
  const url = '/docs/integrations/aws/#aws-iam-01-root-mfa';
  assert.deepEqual(tokenizer.tokenize(url, undefined, 'url'), defaultTokenizer.tokenize(url, undefined, 'url'));
});

// The search route builds and exports the index, and the dialog loads it into a
// database created with only the tokenizer.
async function exportAndLoad(contents) {
  const built = create({ schema: { content: 'string' }, components: { tokenizer: createSearchTokenizer() } });
  await insertMultiple(built, contents.map((content) => ({ content })));
  const loaded = create({ schema: { _: 'string' }, components: { tokenizer: createSearchTokenizer() } });
  load(loaded, JSON.parse(JSON.stringify(save(built))));
  return async (term) => (await search(loaded, { term, properties: ['content'] })).hits.map((hit) => hit.document.content);
}

test('the loaded index finds an identifier only where it appears, exact matches first', async () => {
  const find = await exportAndLoad([
    'IAM roles for AWS accounts, 01 per account',
    'AWS-IAM-01 requires MFA on the root account',
    'AC-20 governs external systems',
    'AC-2.1 automates account management',
    'AC-2 covers account management',
  ]);
  assert.deepEqual(await find('AWS-IAM-01'), ['AWS-IAM-01 requires MFA on the root account']);
  assert.equal((await find('IAM')).length, 2);
  assert.equal((await find('AC-2'))[0], 'AC-2 covers account management');
  assert.equal((await find('ac-2')).length, 3);
});

test('a hyphenated query that finds nothing whole searches its parts', async () => {
  const find = await exportAndLoad(['Map controls to SOC 2 criteria', 'Export ISO-9001 evidence']);
  const searched = [];
  const record = async (query) => {
    searched.push(query);
    return find(query);
  };
  assert.deepEqual(await searchWholeIdentifiersFirst(record, 'ISO-9001'), ['Export ISO-9001 evidence']);
  assert.deepEqual(await searchWholeIdentifiersFirst(record, 'SOC-2'), ['Map controls to SOC 2 criteria']);
  assert.deepEqual(await searchWholeIdentifiersFirst(record, 'HIPAA'), []);
  assert.deepEqual(searched, ['ISO-9001', 'SOC-2', 'SOC 2', 'HIPAA']);
});

test('an identifier that finds nothing whole searches its parts even when other words find pages', async () => {
  const find = await exportAndLoad([
    'Audit logs export nightly',
    'Audit trails record each change',
    'Map controls to SOC 2 audit criteria',
    'Export ISO-9001 audit evidence',
  ]);
  const searched = [];
  const record = async (query) => {
    searched.push(query);
    return find(query);
  };
  assert.equal((await searchWholeIdentifiersFirst(record, 'SOC-2 audit'))[0], 'Map controls to SOC 2 audit criteria');
  assert.equal((await searchWholeIdentifiersFirst(record, 'ISO-9001 audit'))[0], 'Export ISO-9001 audit evidence');
  await searchWholeIdentifiersFirst(record, 'ISO-9001 or SOC-2');
  assert.deepEqual(searched, ['SOC-2', 'SOC 2 audit', 'ISO-9001', 'ISO-9001 audit', 'ISO-9001', 'SOC-2', 'ISO-9001 or SOC 2']);
});

// Pages shaped like the ones the search route indexes. Integrations appears
// only in URLs and section trails, never in page text.
const pages = [
  {
    id: '/docs/integrations/aws/',
    url: '/docs/integrations/aws/',
    title: 'AWS',
    description: 'Assess IAM and logging',
    breadcrumbs: ['Docs', 'Integrations'],
    structuredData: {
      headings: [{ id: 'aws-iam-01-root-mfa', content: 'AWS-IAM-01 root MFA' }],
      contents: [{ heading: 'aws-iam-01-root-mfa', content: 'Requires MFA on the root account' }],
    },
  },
  {
    id: '/docs/integrations/okta/',
    url: '/docs/integrations/okta/',
    title: 'Okta',
    description: 'Assess MFA policies and admin roles',
    breadcrumbs: ['Docs', 'Integrations'],
    structuredData: {
      headings: [{ id: 'okta-mfa-01', content: 'OKTA-MFA-01 phishing-resistant MFA' }],
      contents: [{ heading: 'okta-mfa-01', content: 'Checks that admins enroll a FIDO2 factor' }],
    },
  },
  {
    id: '/docs/quick-start/',
    url: '/docs/quick-start/',
    title: 'Quick start',
    description: 'Install grclanker and run a first assessment',
    breadcrumbs: ['Docs'],
    structuredData: { headings: [], contents: [{ content: 'Run npm install, then grclanker' }] },
  },
];

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

test('the index holds only the content field, and searches return what a full index returns', async () => {
  const full = await exportIndex(pages);
  const trimmed = await exportIndex(pages, { components: { getDocumentProperties: getIndexedProperties } });
  const empty = await exportIndex([]);
  assert.deepEqual(trimmed.docs, full.docs);
  for (const part of ['indexes', 'frequencies', 'avgFieldLength', 'fieldLengths']) {
    for (const field of Object.keys(full.index[part])) {
      const expected = field === 'content' ? full : empty;
      assert.deepEqual(trimmed.index[part][field], expected.index[part][field], `${part}.${field}`);
    }
  }

  const searchFull = loadLikeTheDialog(full);
  const searchTrimmed = loadLikeTheDialog(trimmed);
  for (const query of ['AWS-IAM-01', 'root mfa', 'mfa', 'assess', 'install grclanker', 'integrations']) {
    assert.deepEqual(await searchTrimmed(query), await searchFull(query), query);
  }
  assert.deepEqual(
    (await searchTrimmed('AWS-IAM-01')).map((result) => result.url),
    ['/docs/integrations/aws/', '/docs/integrations/aws/#aws-iam-01-root-mfa'],
  );
  assert.deepEqual(await searchTrimmed('integrations'), []);
});
