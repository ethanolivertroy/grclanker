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

test('hyphenated numbers stay whole in running text', () => {
  const cell = el('td', [text('Grace through 2027-01-01 under 800-53, M-24-15, and SHA-256.')]);
  const item = el('li', [el('strong', [text('1-300')]), text(' rows, 30-day window, Rev5-Specific')]);
  run(el('table', [el('tbody', [el('tr', [cell])])]));
  run(el('ul', [item]));
  assert.equal(render(cell), 'Grace through [2027-01-01] under [800-53], [M-24-15], and [SHA-256].');
  assert.equal(render(item), '[1-300] rows, 30-day window, Rev5-Specific');
});

test('inline code with no letters or digits is marked as symbols', () => {
  const marked = (value) => {
    const code = el('code', [text(value)]);
    run(el('p', [code]));
    return 'dataSymbol' in code.properties;
  };
  assert.deepEqual([';', ': ', '[]', '->', '\\"'].map(marked), [true, true, true, true, true]);
  assert.deepEqual(['a', 'x;', '0', '--debug', 'é'].map(marked), [false, false, false, false, false]);
});

test('code blocks are left alone', () => {
  const code = el('code', [text('cli/extensions/grc-tools/')]);
  run(el('pre', [code]));
  assert.equal(code.properties.dataNowrap, undefined);
  assert.equal(render(code), 'cli/extensions/grc-tools/');
});
