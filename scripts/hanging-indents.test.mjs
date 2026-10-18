import assert from 'node:assert/strict';
import { test } from 'node:test';

import hangingIndents from '../src/lib/hanging-indents.mjs';

const text = (value) => ({ type: 'text', value });
const el = (tagName, children = [], properties = {}) => ({ type: 'element', tagName, properties, children });
const line = (value, properties = { class: 'line' }) => el('span', [el('span', [text(value)])], properties);

// A Shiki code block: one span.line per source line, joined by newlines.
function block(...values) {
  const lines = values.map((value) => line(value));
  const children = lines.flatMap((node, index) => (index ? [text('\n'), node] : [node]));
  return { pre: el('pre', [el('code', children)]), lines };
}

function styles(...values) {
  const { pre, lines } = block(...values);
  hangingIndents()({ type: 'root', children: [pre] });
  return lines.map((node) => node.properties.style);
}

test('rows hang 2ch past the line indentation', () => {
  assert.deepEqual(styles('grclanker setup --provider ollama', '  --model llama3 \\', '    nested: true'), [
    '--word:10ch;--word-2:6ch',
    '--hang:4ch;--word:6ch;--word-2:1ch',
    '--hang:6ch;--word:4ch',
  ]);
});

test('other lines carry their two longest words after the first, split after a hyphen between letters', () => {
  assert.deepEqual(styles('export URL=https://your-org.okta.com', 'grclanker cve CVE-2021-44228', 'https://grclanker.com/install'), [
    '--word:17ch;--word-2:12ch',
    '--word:14ch;--word-2:3ch',
    undefined,
  ]);
});

test('the second word is the next longer than the first, so it can fit where the first cannot', () => {
  assert.deepEqual(
    styles('curl -fsSL https://grclanker.com/install | GRCLANKER_INSTALL_DIR="$HOME/opt/grclanker" GRCLANKER_BIN_DIR="$HOME/bin" bash'),
    ['--word:43ch;--word-2:29ch'],
  );
});

test('rows of a file listing hang under its description column', () => {
  assert.deepEqual(
    styles(
      'bundle/',
      '  core_data/'.padEnd(22) + 'raw API snapshots',
      '    status.json'.padEnd(22) + 'one row per snapshot',
      '  analysis/',
      '  a_much_longer_name.json one row per finding',
    ),
    [
      undefined,
      '--hang:22ch;--word:9ch;--word-2:8ch',
      '--hang:22ch;--word:9ch;--word-2:8ch',
      '--hang:4ch',
      '--hang:4ch;--word:7ch;--word-2:3ch',
    ],
  );
});

test('description lines carry the longest words in any of the descriptions', () => {
  assert.deepEqual(
    styles(
      '<api-host>_<timestamp>/',
      '  core_data/'.padEnd(22) + 'Admin API payloads plus collection_status.json',
      '  compliance/'.padEnd(22) + 'executive_summary.md, unified_compliance_matrix.md',
      '  _errors.log'.padEnd(22) + 'only when a read failed',
    ),
    [
      undefined,
      '--hang:22ch;--word:28ch;--word-2:22ch',
      '--hang:22ch;--word:28ch;--word-2:22ch',
      '--hang:22ch;--word:28ch;--word-2:22ch',
    ],
  );
});

test('a name as wide as the gap aligns with a single space', () => {
  assert.deepEqual(
    styles(
      '_errors.log'.padEnd(33) + '(only when a read fails)',
      'core_data/collection_status.json (one row per inventory: endpoint,',
      ' '.repeat(34) + 'truncated, seen, total)',
    ),
    [
      '--hang:33ch;--word:10ch;--word-2:9ch',
      '--hang:33ch;--word:10ch;--word-2:9ch',
      '--hang:34ch;--indent:34ch;--word:10ch;--word-2:9ch',
    ],
  );
});

test('description columns past column 40 hang from the indentation', () => {
  assert.deepEqual(
    styles(
      'export AWS_SMOKE_REGIONS="us-east-1,us-west-2"   # optional: pin the scope',
      '    fedramp/, cmmc/, soc2/, cis/, pci_dss/, disa_stig/, irap/   one report each',
    ),
    ['--word:22ch;--word-2:10ch', '--hang:6ch;--word:11ch;--word-2:9ch'],
  );
});

test('blank lines are left alone', () => {
  assert.deepEqual(styles('first', '', '   ', 'last'), [undefined, undefined, undefined, undefined]);
});

const indent = (value, style) => el('span', [text(value)], style ? { className: ['indent'], style } : { className: ['indent'] });

test('indentation goes in a span of its own, whichever token holds it, with the first word after it', () => {
  const { pre, lines } = block('  compliance/unified_compliance_matrix.md', 'flat');
  const ownToken = el('span', [el('span', [text('    ')]), el('span', [text('key-name: value')])], { class: 'line' });
  hangingIndents()({ type: 'root', children: [pre, el('pre', [el('code', [ownToken])])] });
  assert.deepEqual(lines[0].children[0].children, [
    indent('  ', '--spaces:2ch;--first:39ch'),
    text('compliance/unified_compliance_matrix.md'),
  ]);
  assert.deepEqual(lines[1].children[0].children, [text('flat')]);
  assert.deepEqual(ownToken.children[0].children, [indent('    ', '--spaces:4ch;--first:4ch')]);
  assert.deepEqual(ownToken.children[1].children, [text('key-name: value')]);
});

test('a continued description keeps its indentation, which narrow screens pull in instead', () => {
  const { pre, lines } = block('_errors.log'.padEnd(13) + 'only when a', ' '.repeat(13) + 'read fails');
  hangingIndents()({ type: 'root', children: [pre] });
  assert.equal(lines[1].properties.style, '--hang:13ch;--indent:13ch;--word:5ch;--word-2:4ch');
  assert.deepEqual(lines[1].children[0].children, [indent(' '.repeat(13)), text('read fails')]);
});

test('a name too long for the column puts its description on the next line', () => {
  assert.deepEqual(
    styles(
      '  core_data/'.padEnd(22) + 'raw API snapshots',
      '  core_data/collection_status.json',
      ' '.repeat(22) + 'one row per inventory: readable, truncated',
    ),
    [
      '--hang:22ch;--word:10ch;--word-2:9ch',
      '--hang:4ch',
      '--hang:22ch;--indent:22ch;--word:10ch;--word-2:9ch',
    ],
  );
});

test('a deeper line continues a description only when the line above has one', () => {
  assert.deepEqual(styles('foo: 1  # comment', 'bar:', '        nested: true'), [
    '--hang:8ch;--word:7ch;--word-2:1ch',
    undefined,
    '--hang:10ch;--word:4ch',
  ]);
});

test('a line of several words that runs into the column puts no description on the next line', () => {
  assert.deepEqual(styles('foo: 1  # comment', 'if condition:', '        long_variable_identifier'), [
    '--hang:8ch;--word:7ch;--word-2:1ch',
    '--word:10ch',
    '--hang:10ch',
  ]);
});

test('lines are found by className as well as class, inside any wrapper', () => {
  const node = line('  indented', { className: ['line'] });
  const pre = el('pre', [el('code', [node])]);
  hangingIndents()({ type: 'root', children: [{ type: 'mdxJsxFlowElement', children: [el('div', [pre])] }] });
  assert.equal(node.properties.style, '--hang:4ch');
});

test('code outside a pre is left alone', () => {
  const node = line('  indented');
  hangingIndents()({ type: 'root', children: [el('p', [el('code', [node])])] });
  assert.equal(node.properties.style, undefined);
});
