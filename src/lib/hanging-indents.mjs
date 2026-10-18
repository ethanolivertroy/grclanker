// Hanging indents for code blocks, which wrap long lines instead of scrolling
// sideways. Each line's --hang is the column its wrapped rows start at, so a
// wrapped row never starts where a source line could. Rows hang under a line's
// description when the block aligns descriptions in a column, as file listings
// do, and otherwise 2ch past the line's own indentation. Each line also gets
// --word and --word-2, the two longest words that could start one of its
// wrapped rows, so narrow screens can hang the rows less until a word fits:
// --word, or --word-2 where --word is too long for any row. For description
// lines, these are the longest words in any of the block's descriptions, which
// moves the column as one; for other lines, the longest after their first. A
// line that continues the description above it also gets --indent, so narrow
// screens can pull it in to the column where the other descriptions wrap.
//
// Each line's indentation goes in an .indent span that must not wrap, which
// keeps a long first word on the indented row instead of a row of its own.
// Except on a continued description, the span also gets --spaces, its width,
// and --first, the length of that first word, so narrow screens can shrink the
// indentation until the word fits beside it.

// Further right than this, a description column leaves too little room for
// the rows that hang under it, so the line hangs from its indentation instead.
const MAX_DESCRIPTION_COLUMN = 40;
const DEFAULT_HANG = 2;

function textContent(node) {
  if (node.type === 'text') return node.value;
  return node.children ? node.children.map(textContent).join('') : '';
}

function isLine(node) {
  if (node.type !== 'element') return false;
  const classes = node.properties.className ?? node.properties.class ?? [];
  return (Array.isArray(classes) ? classes : String(classes).split(' ')).includes('line');
}

// Where text resumes after two or more spaces that follow the line's first text.
function descriptionColumn(text) {
  const match = /^\s*\S.*?\s{2,}(?=\S)/.exec(text);
  return match && match[0].length <= MAX_DESCRIPTION_COLUMN ? match[0].length : undefined;
}

// `description` is where the line's description starts, if it has one.
function lineHang(text, columns) {
  const own = descriptionColumn(text);
  if (own !== undefined) return { hang: own, description: own };
  // A name as wide as the gap keeps a single space before its description.
  const single = /^\s*\S+ (?=\S)/.exec(text);
  if (single && columns.includes(single[0].length)) return { hang: single[0].length, description: single[0].length };
  const indent = /^\s*/.exec(text)[0].length;
  if (columns.length > 0 && indent >= columns[0]) return { hang: indent, description: indent, indent };
  return { hang: indent + DEFAULT_HANG };
}

// Browsers can also break after a hyphen between letters, as in your-org.
function words(text) {
  return text.split(/\s+|(?<=[A-Za-z]-)(?=[A-Za-z])/).filter(Boolean);
}

// The lengths of the two longest words, without repeating a length.
function longestWords(...texts) {
  const lengths = [...new Set(texts.flatMap((text) => words(text).map((word) => word.length)))];
  const [first = 0, second = 0] = lengths.sort((a, b) => b - a);
  return [first, second];
}

function holdIndent(node, first) {
  for (const [index, child] of (node.children ?? []).entries()) {
    if (child.type === 'text') {
      const indentation = /^\s*/.exec(child.value)[0];
      if (indentation) {
        const rest = child.value.slice(indentation.length);
        const properties = { className: ['indent'] };
        if (first) properties.style = `--spaces:${indentation.length}ch;--first:${first}ch`;
        const span = { type: 'element', tagName: 'span', properties, children: [{ type: 'text', value: indentation }] };
        node.children.splice(index, 1, span, ...(rest ? [{ type: 'text', value: rest }] : []));
      }
      return true;
    }
    if (holdIndent(child, first)) return true;
  }
  return false;
}

function setHangs(lines) {
  const texts = lines.map(textContent);
  const columns = [...new Set(texts.map(descriptionColumn))]
    .filter((column) => column !== undefined)
    .sort((a, b) => a - b);
  const hangs = texts.map((text) => (text.trim() ? lineHang(text, columns) : undefined));
  const descriptionWords = longestWords(
    ...hangs.map((line, index) => (line?.description === undefined ? '' : texts[index].slice(line.description))),
  );
  lines.forEach((line, index) => {
    if (!hangs[index]) return;
    const { hang, description, indent } = hangs[index];
    const [word, word2] = description === undefined ? longestWords(texts[index].replace(/^\s*\S+/, '')) : descriptionWords;
    const style = [];
    if (hang !== DEFAULT_HANG) style.push(`--hang:${hang}ch`);
    if (indent !== undefined) style.push(`--indent:${indent}ch`);
    if (word) style.push(`--word:${word}ch`);
    if (word2) style.push(`--word-2:${word2}ch`);
    if (style.length) line.properties.style = [line.properties.style, ...style].filter(Boolean).join(';');
    if (/^\s/.test(texts[index])) holdIndent(line, indent === undefined ? words(texts[index])[0].length : undefined);
  });
}

function visit(node) {
  if (node.type === 'element' && node.tagName === 'pre') {
    for (const child of node.children) {
      if (child.type === 'element' && child.tagName === 'code') setHangs(child.children.filter(isLine));
    }
    return;
  }
  node.children?.forEach(visit);
}

export default function hangingIndents() {
  return (tree) => visit(tree);
}
