const TABLE_ROLES = {
  table: 'table',
  thead: 'rowgroup',
  tbody: 'rowgroup',
  tr: 'row',
  th: 'columnheader',
  td: 'cell',
};

function childElements(node, tagName) {
  return node.children.filter((child) => child.type === 'element' && child.tagName === tagName);
}

function textContent(node) {
  if (node.type === 'text') return node.value;
  return node.children ? node.children.map(textContent).join('') : '';
}

function setRoles(node) {
  if (node.type !== 'element') return;
  if (node.tagName in TABLE_ROLES) node.properties.role = TABLE_ROLES[node.tagName];
  for (const child of node.children) setRoles(child);
}

// Tables of sentences at least this wide read better as one labeled line per
// cell than as columns squeezed into the docs column.
const STACKED_MIN_COLUMNS = 4;
const STACKED_MIN_AVERAGE_CELL_LENGTH = 30;

function bodyCells(table) {
  return childElements(table, 'tbody')
    .flatMap((body) => childElements(body, 'tr'))
    .map((row) => childElements(row, 'td'));
}

function labelBodyCells(table, labels) {
  for (const cells of bodyCells(table)) {
    cells.forEach((cell, index) => {
      if (labels[index]) cell.properties.dataLabel = labels[index];
    });
  }
}

// The stacked layout makes each cell a two-column grid, so the cell's inline
// content needs one wrapper to stay a single grid item next to the label.
function markStacked(table, columns) {
  const cells = bodyCells(table).flat();
  if (columns < STACKED_MIN_COLUMNS || cells.length === 0) return;
  const total = cells.reduce((sum, cell) => sum + textContent(cell).trim().length, 0);
  if (total / cells.length < STACKED_MIN_AVERAGE_CELL_LENGTH) return;
  table.properties.dataLayout = 'stacked';
  for (const cell of cells) {
    cell.children = [{ type: 'element', tagName: 'span', properties: {}, children: cell.children }];
  }
}

// Long identifiers and URLs have no spaces, so each would set its column's
// minimum width. Break opportunities after their dots, slashes, and
// underscores, and between camelCase words, let the table fit the docs column
// without splitting words. Browsers take any break opportunity that fills a
// line, so short identifiers get none and wrap whole.
const LONG_TOKEN = /(\S{12,})/;
const BREAK_POINT = /(?<=[^\s./_][./_])(?=[^\s./_])|(?<=[a-z])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])/;

function splitAtBreakPoints(child) {
  if (child.type !== 'text') return [child];
  const nodes = [];
  child.value.split(LONG_TOKEN).forEach((part, partIndex) => {
    const pieces = partIndex % 2 ? part.split(BREAK_POINT) : [part];
    pieces.forEach((value, pieceIndex) => {
      if (pieceIndex > 0) nodes.push({ type: 'element', tagName: 'wbr', properties: {}, children: [] });
      if (value) nodes.push({ type: 'text', value });
    });
  });
  return nodes;
}

function addBreakPoints(node) {
  if (node.type !== 'element') return;
  if (node.tagName === 'code' || node.tagName === 'a') node.children = node.children.flatMap(splitAtBreakPoints);
  node.children.forEach(addBreakPoints);
}

function visitTables(node) {
  if (node.type === 'element' && node.tagName === 'table') {
    setRoles(node);
    bodyCells(node).flat().forEach(addBreakPoints);
    const headerRow = childElements(node, 'thead').flatMap((head) => childElements(head, 'tr'))[0];
    if (!headerRow) return;
    const labels = childElements(headerRow, 'th').map((cell) => textContent(cell).trim());
    labelBodyCells(node, labels);
    markStacked(node, labels.length);
    return;
  }
  if (node.children) node.children.forEach(visitTables);
}

// Narrow CSS stacks table cells as blocks, which drops native table semantics,
// so tables get explicit ARIA roles and each body cell carries its column header.
export default function tableLabels() {
  return visitTables;
}
