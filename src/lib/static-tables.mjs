// Spec tables run to thousands of cells. React would send each cell to the
// browser a second time as an element to hydrate, more than doubling a spec
// page, so each table becomes one element holding its finished HTML instead,
// along with its estimated height in each layout. Runs after the plugins that
// shape tables.
import { toHtml } from 'hast-util-to-html';
import { estimateTableHeights } from './table-heights.mjs';

export const STATIC_TABLE = 'static-table';

const TABLE_SECTIONS = new Set(['table', 'thead', 'tbody', 'tfoot', 'tr']);

// Whitespace between rows and cells renders nothing, and React drops it too.
function dropLayoutWhitespace(node) {
  if (node.type !== 'element') return;
  if (TABLE_SECTIONS.has(node.tagName)) {
    node.children = node.children.filter((child) => child.type !== 'text' || child.value.trim());
  }
  node.children.forEach(dropLayoutWhitespace);
}

function replaceTables(node) {
  if (!node.children) return;
  node.children = node.children.map((child) => {
    if (child.type !== 'element') return child;
    if (child.tagName === 'table') {
      dropLayoutWhitespace(child);
      return { type: 'element', tagName: STATIC_TABLE, properties: { html: toHtml(child), ...estimateTableHeights(child) }, children: [] };
    }
    replaceTables(child);
    return child;
  });
}

export default function staticTables() {
  return (tree) => replaceTables(tree);
}
