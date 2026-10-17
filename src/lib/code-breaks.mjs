// Line-break control for inline code and link text. Browsers fill each line
// greedily, so any break point inside an identifier gets used whenever the
// identifier reaches a line end; each context gets only the break points it
// needs.

// After a slash, or after a dot that does not start a file extension.
const PATH_BREAK = String.raw`(?<=[^\s./_][/])(?=[^\s./_])|(?<=[^\s./_][.])(?=[^\s./_])(?![A-Za-z0-9]{1,4}$)`;
// Also after an underscore and between camelCase words.
const WORD_BREAK = String.raw`${PATH_BREAK}|(?<=[^\s./_]_)(?=[^\s./_])|(?<=[a-z])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])`;
const PATH_BREAKS = new RegExp(PATH_BREAK);
const WORD_BREAKS = new RegExp(WORD_BREAK);

// Tokens shorter than `shortLength` never wrap, so `agent-sdk`, `Set-Cookie`,
// and `2026-10-13` always stay whole. Longer tokens wrap at path breaks, and
// from `wordLength` at word breaks too. Hyphenated pieces shorter than
// LONG_LENGTH stay whole unless `breakHyphens` is set; longer ones may still
// wrap at their hyphens, so they cannot overflow a phone screen. Running text
// keeps identifiers whole; table columns are narrower, dense ones narrower still.
const LONG_LENGTH = 24;
const PROSE = { shortLength: 16, wordLength: Infinity, breakHyphens: false };
const TABLE = { shortLength: 16, wordLength: LONG_LENGTH, breakHyphens: false };
const DENSE_COLUMNS = 4;
const DENSE_TABLE = { shortLength: 12, wordLength: 12, breakHyphens: true };

const text = (value) => ({ type: 'text', value });
const wbr = () => ({ type: 'element', tagName: 'wbr', properties: {}, children: [] });
const nowrap = (value) => ({ type: 'element', tagName: 'span', properties: { dataNowrap: '' }, children: [text(value)] });

function textContent(node) {
  if (node.type === 'text') return node.value;
  return node.children ? node.children.map(textContent).join('') : '';
}

function firstRow(node) {
  if (node.type !== 'element') return undefined;
  if (node.tagName === 'tr') return node;
  for (const child of node.children) {
    const row = firstRow(child);
    if (row) return row;
  }
  return undefined;
}

function columnCount(table) {
  return firstRow(table)?.children.filter((cell) => cell.type === 'element').length ?? 0;
}

function breakToken(token, mode, isCode) {
  const short = token.length < mode.shortLength;
  const pieces = short ? [token] : token.split(token.length >= mode.wordLength ? WORD_BREAKS : PATH_BREAKS);
  return pieces.flatMap((piece, index) => {
    const keepWhole = isCode && piece.includes('-') && (short || (!mode.breakHyphens && piece.length < LONG_LENGTH));
    const node = keepWhole ? nowrap(piece) : text(piece);
    return index ? [wbr(), node] : [node];
  });
}

function breakText(value, mode, isCode) {
  return value.split(/(\s+)/).flatMap((token) => {
    if (!token) return [];
    return /^\s/.test(token) ? [text(token)] : breakToken(token, mode, isCode);
  });
}

function visit(node, mode) {
  if (node.type !== 'element' || node.tagName === 'pre') return;
  if (node.tagName === 'table') mode = columnCount(node) >= DENSE_COLUMNS ? DENSE_TABLE : TABLE;
  if (node.tagName === 'code') {
    const value = textContent(node);
    if (value.length < mode.shortLength && !/\s/.test(value)) {
      node.properties.dataNowrap = '';
      return;
    }
  }
  if (node.tagName === 'code' || node.tagName === 'a') {
    const isCode = node.tagName === 'code';
    node.children = node.children.flatMap((child) =>
      child.type === 'text' ? breakText(child.value, mode, isCode) : [child],
    );
  }
  for (const child of node.children) visit(child, mode);
}

export default function codeBreaks() {
  return (tree) => tree.children.forEach((child) => visit(child, PROSE));
}
