import { overflowsDocsColumn } from './table-heights.mjs';

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
// cell than as columns squeezed into the docs column. So do tables whose
// columns cannot all fit in it: on screen they would scroll sideways, and on
// paper their last columns would be cut off.
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
  if (total / cells.length < STACKED_MIN_AVERAGE_CELL_LENGTH && !overflowsDocsColumn(table)) return;
  table.properties.dataLayout = 'stacked';
  for (const cell of cells) {
    cell.children = [{ type: 'element', tagName: 'span', properties: {}, children: cell.children }];
  }
}

function visitTables(node) {
  if (node.type === 'element' && node.tagName === 'table') {
    setRoles(node);
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
