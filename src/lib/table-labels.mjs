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

function labelBodyCells(table) {
  const headerRow = childElements(table, 'thead').flatMap((head) => childElements(head, 'tr'))[0];
  if (!headerRow) return;
  const labels = childElements(headerRow, 'th').map((cell) => textContent(cell).trim());
  for (const row of childElements(table, 'tbody').flatMap((body) => childElements(body, 'tr'))) {
    childElements(row, 'td').forEach((cell, index) => {
      if (labels[index]) cell.properties.dataLabel = labels[index];
    });
  }
}

function visitTables(node) {
  if (node.type === 'element' && node.tagName === 'table') {
    setRoles(node);
    labelBodyCells(node);
    return;
  }
  if (node.children) node.children.forEach(visitTables);
}

// Narrow CSS stacks table cells as blocks, which drops native table semantics,
// so tables get explicit ARIA roles and each body cell carries its column header.
export default function tableLabels() {
  return visitTables;
}
