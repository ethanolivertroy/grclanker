import assert from 'node:assert/strict';
import { test } from 'node:test';

import codeBreaks from '../src/lib/code-breaks.mjs';

const text = (value) => ({ type: 'text', value });
const el = (tagName, children = [], properties = {}) => ({ type: 'element', tagName, properties, children });

function run(node) {
  codeBreaks()({ type: 'root', children: [node] });
}

// `|` marks a break opportunity and `[...]` a span that never wraps.
function render(node) {
  if (node.type === 'text') return node.value;
  if (node.tagName === 'wbr') return '|';
  const inner = node.children.map(render).join('');
  return node.tagName === 'span' && 'dataNowrap' in node.properties ? `[${inner}]` : inner;
}

function table(columns, cell) {
  const header = el('tr', Array.from({ length: columns }, (_, index) => el('th', [text(`Column ${index}`)])));
  const row = el('tr', [el('td', [cell]), ...Array.from({ length: columns - 1 }, () => el('td', [text('value')]))]);
  return el('table', [el('thead', [text('\n'), header]), el('tbody', [row])]);
}

test('short inline code never wraps', () => {
  for (const value of ['agent-sdk', 'Set-Cookie', '2026-10-13']) {
    const code = el('code', [text(value)]);
    run(el('p', [code]));
    assert.equal(code.properties.dataNowrap, '');
    assert.equal(render(code), value);
  }
});

test('long paths wrap after slashes and keep hyphenated segments whole', () => {
  const code = el('code', [text('cli/skills/crypto-validation/SKILL.md')]);
  run(el('p', [code]));
  assert.equal(code.properties.dataNowrap, undefined);
  assert.equal(render(code), 'cli/|skills/|[crypto-validation/]|SKILL.md');
});

test('multi-word code wraps at spaces and keeps flags whole', () => {
  const code = el('code', [text('npm --prefix cli run test:cli')]);
  run(el('p', [code]));
  assert.equal(render(code), 'npm [--prefix] cli run test:cli');
});

test('identifiers stay whole in running text and narrow tables', () => {
  for (const wrap of [(code) => el('p', [code]), (code) => table(2, code)]) {
    const code = el('code', [text('fedramp_check_sources')]);
    run(wrap(code));
    assert.equal(render(code), 'fedramp_check_sources');
  }
});

test('dense tables wrap long identifiers at word boundaries and hyphens', () => {
  const identifier = el('code', [text('fedramp_check_sources')]);
  run(table(5, identifier));
  assert.equal(render(identifier), 'fedramp_|check_|sources');

  const hyphenated = el('code', [text('sandbox-runtime')]);
  run(table(5, hyphenated));
  assert.equal(hyphenated.properties.dataNowrap, undefined);
  assert.equal(render(hyphenated), 'sandbox-runtime');
});

test('link text wraps after slashes', () => {
  const link = el('a', [text('cli/extensions/grc-tools.ts')], { href: '/' });
  run(el('p', [link]));
  assert.equal(render(link), 'cli/|extensions/|grc-tools.ts');
});

test('code blocks are left alone', () => {
  const code = el('code', [text('cli/extensions/grc-tools/')]);
  run(el('pre', [code]));
  assert.equal(code.properties.dataNowrap, undefined);
  assert.equal(render(code), 'cli/extensions/grc-tools/');
});
