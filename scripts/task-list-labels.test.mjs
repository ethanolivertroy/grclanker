import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createMarkdownRenderer } from 'fumadocs-core/content/md';
import { remarkGfm } from 'fumadocs-core/mdx-plugins';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';

import taskListLabels from '../src/lib/task-list-labels.mjs';

const { Markdown } = createMarkdownRenderer({ remarkPlugins: [remarkGfm], rehypePlugins: [taskListLabels] });
const render = (markdown) => renderToStaticMarkup(createElement(Markdown, null, markdown));

test('each checkbox is labeled by the text of its item', () => {
  const html = render('- [ ] Project scaffolding: `go.mod`, [CI](https://example.com/ci)\n- [x] JSON reporter\n');
  assert.match(
    html,
    /<li class="task-list-item"><label><input type="checkbox" disabled=""\/> Project scaffolding: <code>go\.mod<\/code>, <a href="https:\/\/example\.com\/ci">CI<\/a><\/label><\/li>/,
  );
  assert.match(html, /<label><input type="checkbox" disabled="" checked=""\/> JSON reporter<\/label>/);
});

test('a nested list stays outside the label', () => {
  const html = render('- [ ] Phase 1\n  - Scaffolding\n');
  assert.match(html, /<label><input type="checkbox" disabled=""\/> Phase 1<\/label>\s*<ul>\s*<li>Scaffolding<\/li>/);
});

test('in a loose list the label sits in the first paragraph', () => {
  const html = render('- [ ] First\n\n  More about it.\n\n- [ ] Second\n');
  assert.match(html, /<p><label><input type="checkbox" disabled=""\/> First<\/label><\/p>\s*<p>More about it\.<\/p>/);
  assert.match(html, /<p><label><input type="checkbox" disabled=""\/> Second<\/label><\/p>/);
});

test('lists without checkboxes are left alone', () => {
  assert.doesNotMatch(render('- Plain item\n\n1. Ordered item\n'), /<label/);
});
