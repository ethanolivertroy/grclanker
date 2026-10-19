import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createMarkdownRenderer } from 'fumadocs-core/content/md';
import { remarkGfm } from 'fumadocs-core/mdx-plugins';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';

import { siteRehypePlugins } from '../src/lib/markdown-options.ts';

const { Markdown } = createMarkdownRenderer({ remarkPlugins: [remarkGfm], rehypePlugins: siteRehypePlugins });

const row = (cells) => `| ${cells.join(' | ')} |\n`;
const tableTag = (labels, rows) => {
  const markdown = row(labels) + row(labels.map(() => '---')) + rows.map(row).join('');
  return renderToStaticMarkup(createElement(Markdown, {}, markdown)).match(/<table[^>]*>/)[0];
};

test('a table of sentences four or more columns wide stacks', () => {
  const sentence = 'The collector reads this setting before evidence export.';
  assert.equal(tableTag(['A', 'B', 'C', 'D'], [[sentence, sentence, sentence, sentence]]), '<table role="table" data-layout="stacked">');
});

test('a table of short cells stacks when its columns cannot all fit in the docs column', () => {
  const labels = ['ID', 'Interface', 'Read operation', 'Service or client', 'IAM action', 'Intent', 'Projection stage', 'Fields consumed', 'Reference'];
  const cells = [
    '`sign-on-policies`',
    'HTTP',
    '`GET /api/v1/policies?type=OKTA_SIGN_ON`',
    'Okta Management API',
    'N/A',
    'read',
    'Projected before export.',
    '`conditions`',
    '[Official documentation](https://developer.okta.com/)',
  ];
  assert.equal(tableTag(labels, [cells]), '<table role="table" data-layout="stacked">');
});

test('a table of short cells that fits keeps its columns', () => {
  assert.equal(tableTag(['ID', 'Interface', 'Intent', 'Stage'], [['`users`', 'HTTP', 'read', 'Projected']]), '<table role="table">');
});

test('a table keeps its columns when its inline code fits at the break points it gets', () => {
  const path = '`/api/v1/organizations/{organizationId}/settings/security`';
  assert.equal(tableTag(['Endpoint', 'Description', 'Permission', 'Projection'], [[path, 'Reads org settings', 'read', 'Fields']]), '<table role="table">');
});
