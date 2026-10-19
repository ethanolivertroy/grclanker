import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createMarkdownRenderer } from 'fumadocs-core/content/md';
import { getTableOfContents } from 'fumadocs-core/content/toc';
import { remarkGfm, remarkHeading } from 'fumadocs-core/mdx-plugins';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';

import remarkSpecSource from '../src/lib/spec-markdown.mjs';

const plugins = [remarkGfm, [remarkSpecSource, { linkBase: 'https://github.com/example/repo/blob/main/specs/' }]];
const { Markdown } = createMarkdownRenderer({ remarkPlugins: [...plugins, remarkHeading] });

const render = (markdown) => renderToStaticMarkup(createElement(Markdown, null, markdown));

test('drops the title heading that the page header already shows', () => {
  const html = render('<!-- generated integration spec -->\n\n# AWS Security Inspector\n\nIntro.\n\n## Scope\n');
  assert.doesNotMatch(html, /<h1/);
  assert.match(html, /<h2 id="scope">Scope<\/h2>/);
});

test('keeps a heading 1 that does not open the spec', () => {
  assert.match(render('## Overview\n\n# Appendix\n'), /<h1 id="appendix">Appendix<\/h1>/);
});

test('keeps placeholders as text and drops comments', () => {
  const html = render(
    [
      '<!-- generated integration spec -->',
      '',
      'Write to <allocated-directory>.',
      '',
      '| Endpoint | Auth |',
      '| --- | --- |',
      '| `/scan` | Bearer <access token> |',
      '',
      '<instance>',
      '',
    ].join('\n'),
  );
  assert.match(html, /<p>Write to &lt;allocated-directory&gt;\.<\/p>/);
  assert.match(html, /<td>Bearer &lt;access token&gt;<\/td>/);
  assert.match(html, /<p>&lt;instance&gt;<\/p>/);
  assert.doesNotMatch(html, /generated/);
});

test('points relative links at the spec folder on GitHub', () => {
  const html = render(
    'See the [contract](./integration-contract.md#evidence), the [narratives][n], [scope](#scope), and [Okta](https://developer.okta.com/).\n\n[n]: narratives/',
  );
  assert.match(html, /href="https:\/\/github.com\/example\/repo\/blob\/main\/specs\/integration-contract.md#evidence"/);
  assert.match(html, /href="https:\/\/github.com\/example\/repo\/blob\/main\/specs\/narratives\/"/);
  assert.match(html, /href="#scope"/);
  assert.match(html, /href="https:\/\/developer.okta.com\/"/);
});

test('table of contents links match the rendered heading ids', async () => {
  const markdown = '# Title\n\n## Scope\n\n### Scope\n\n## Evidence <bundle>\n';
  const toc = await getTableOfContents(markdown, plugins);
  const html = render(markdown);
  assert.deepEqual(
    toc.map((item) => item.url),
    ['#scope', '#scope-1', '#evidence-bundle'],
  );
  for (const { url } of toc) assert.match(html, new RegExp(`id="${url.slice(1)}"`));
});
