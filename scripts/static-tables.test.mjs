import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createMarkdownRenderer } from 'fumadocs-core/content/md';
import { remarkGfm } from 'fumadocs-core/mdx-plugins';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';

import staticTables, { STATIC_TABLE } from '../src/lib/static-tables.mjs';
import tableLabels from '../src/lib/table-labels.mjs';
import { estimateTableHeights } from '../src/lib/table-heights.mjs';

const text = (value) => ({ type: 'text', value });
const el = (tagName, children = [], properties = {}) => ({ type: 'element', tagName, properties, children });

test('each table, however deep, becomes one element holding its HTML and estimated heights', () => {
  const head = el('thead', [el('tr', [el('th', [text('Auth')])])]);
  const cell = el('td', [text('Bearer <token> & key')], { dataLabel: 'Auth' });
  const table = el('table', [head, text('\n'), el('tbody', [text('\n'), el('tr', [text('\n'), cell, text('\n')])])], { role: 'table' });
  const intro = el('p', [text('Intro')]);
  const tree = { type: 'root', children: [intro, el('li', [table])] };
  staticTables()(tree);
  assert.equal(tree.children[0], intro);
  assert.deepEqual(tree.children[1].children, [
    el(STATIC_TABLE, [], {
      html: '<table role="table"><thead><tr><th>Auth</th></tr></thead><tbody><tr><td data-label="Auth">Bearer &#x3C;token> &#x26; key</td></tr></tbody></table>',
      ...estimateTableHeights(table),
    }),
  ]);
});

test('the rendered table keeps the markup the table plugins gave it', () => {
  const { Markdown } = createMarkdownRenderer({ remarkPlugins: [remarkGfm], rehypePlugins: [tableLabels, staticTables] });
  const components = {
    [STATIC_TABLE]: ({ html }) => createElement('div', { className: 'docs-table-scroll', dangerouslySetInnerHTML: { __html: html } }),
  };
  const html = renderToStaticMarkup(
    createElement(Markdown, { components }, '## Endpoints\n\n| Endpoint | Auth |\n| --- | --- |\n| `/scan` | Bearer |\n'),
  );
  assert.match(html, /^<h2>Endpoints<\/h2>\s*<div class="docs-table-scroll"><table role="table">/);
  assert.match(html, /<td role="cell" data-label="Auth">Bearer<\/td><\/tr><\/tbody><\/table><\/div>$/);
});
