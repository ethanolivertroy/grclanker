import assert from 'node:assert/strict';
import { test } from 'node:test';

import { estimateTableHeights, overflowsDocsColumn } from '../src/lib/table-heights.mjs';

const text = (value) => ({ type: 'text', value });
const el = (tagName, children = [], properties = {}) => ({ type: 'element', tagName, properties, children });
const words = (count) => Array(count).fill('word').join(' ');

function table(labels, rows, properties = {}) {
  const cell = (content) => el('td', typeof content === 'string' ? [text(content)] : content);
  return el(
    'table',
    [el('thead', [el('tr', labels.map((label) => el('th', [text(label)])))]), el('tbody', rows.map((cells) => el('tr', cells.map(cell))))],
    properties,
  );
}

test('a header line over a line per row, or where rows stack, a labeled line per cell', () => {
  assert.deepEqual(estimateTableHeights(table(['Name', 'Value'], [['a', 'b'], ['c', 'd']])), { narrow: 253, wide: 129 });
});

test('a <br> starts a line', () => {
  assert.deepEqual(estimateTableHeights(table(['Steps'], [[[text('one'), el('br'), text('two')]]])), { narrow: 98, wide: 103 });
});

test('prose fills each line with as many words as fit: 10 on a phone, 21 across the docs column', () => {
  assert.deepEqual(estimateTableHeights(table(['Notes'], [[words(60)]])), { narrow: 194, wide: 127 });
});

test('columns share the spare width by how much text each holds', () => {
  assert.deepEqual(estimateTableHeights(table(['Short', 'Long'], [[words(30), words(90)]])), { narrow: 367, wide: 199 });
});

test('a word longer than a line breaks where rows stack, and widens its column where they do not', () => {
  assert.deepEqual(estimateTableHeights(table(['Pattern'], [[[el('code', [text('x'.repeat(100))])]]])), { narrow: 122, wide: 79 });
});

test('from 721px a table of sentences sets each cell beside a 10rem label', () => {
  const fields = table(['Field', 'Meaning'], [['x', words(60)]], { dataLayout: 'stacked' });
  assert.deepEqual(estimateTableHeights(fields), { narrow: 247, wide: 167 });
});

test('tables of seven or more columns are set at 14px', () => {
  const matrix = table(['A', 'B', 'C', 'D', 'E', 'F', 'G'], [['1', '2', '3', '4', '5', '6', '7']]);
  assert.deepEqual(estimateTableHeights(matrix), { narrow: 380, wide: 77 });
});

test('a column can narrow to a break after a hyphen, even where the next element starts', () => {
  // As in SRG-APP-000148, whose number src/lib/code-breaks.mjs keeps whole.
  const nowrap = (value) => el('span', [text(value)], { dataNowrap: '' });
  const labels = ['A', 'B', 'C', 'D', 'E', 'F', 'G'];
  assert.equal(overflowsDocsColumn(table(labels, [labels.map(() => [text('SRG-'), nowrap('APP-000148')])])), false);
  assert.equal(overflowsDocsColumn(table(labels, [labels.map(() => [nowrap('SRG-APP-000148')])])), true);
});
