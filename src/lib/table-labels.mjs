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

function setRoles(node, ctx) {
  if (node.type !== 'element') return;
  if (node.tagName in TABLE_ROLES) ctx.setProperty(node, 'role', TABLE_ROLES[node.tagName]);
  for (const child of node.children) setRoles(child, ctx);
}

function labelBodyCells(table, ctx) {
  const headerRow = childElements(table, 'thead').flatMap((head) => childElements(head, 'tr'))[0];
  if (!headerRow) return;
  const labels = childElements(headerRow, 'th').map((cell) => ctx.textContent(cell).trim());
  for (const row of childElements(table, 'tbody').flatMap((body) => childElements(body, 'tr'))) {
    childElements(row, 'td').forEach((cell, index) => {
      if (labels[index]) ctx.setProperty(cell, 'dataLabel', labels[index]);
    });
  }
}

// Phone CSS stacks table cells as blocks, which drops native table semantics,
// so tables get explicit ARIA roles and each body cell carries its column header.
export default {
  name: 'table-labels',
  element: {
    filter: ['table'],
    visit(table, ctx) {
      setRoles(table, ctx);
      labelBodyCells(table, ctx);
    },
  },
};
