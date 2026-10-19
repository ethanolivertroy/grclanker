// Elements a label can hold. Anything else, such as a nested list or a code
// block, ends the text that names the checkbox.
const PHRASING = new Set([
  'a', 'abbr', 'b', 'bdi', 'bdo', 'br', 'cite', 'code', 'data', 'del', 'dfn', 'em', 'i', 'img', 'ins', 'kbd',
  'mark', 'q', 's', 'samp', 'small', 'span', 'strong', 'sub', 'sup', 'time', 'u', 'var', 'wbr',
]);

const isElement = (node, tagName) => node.type === 'element' && node.tagName === tagName;
const isCheckbox = (node) => isElement(node, 'input') && node.properties.type === 'checkbox';
const isBlank = (node) => node.type === 'text' && !node.value.trim();

function wrapInLabel(parent) {
  const start = parent.children.findIndex(isCheckbox);
  if (start === -1) return;
  let end = start + 1;
  while (end < parent.children.length) {
    const node = parent.children[end];
    if (node.type === 'element' && !PHRASING.has(node.tagName)) break;
    end++;
  }
  while (end > start + 1 && isBlank(parent.children[end - 1])) end--;
  const label = { type: 'element', tagName: 'label', properties: {}, children: parent.children.slice(start, end) };
  parent.children.splice(start, end - start, label);
}

function visit(node) {
  if (!node.children) return;
  if (isElement(node, 'li') && node.properties.className?.includes('task-list-item')) {
    // A tight list item holds the checkbox itself, a loose one in its first paragraph.
    wrapInLabel(node.children.some(isCheckbox) ? node : (node.children.find((child) => isElement(child, 'p')) ?? node));
  }
  node.children.forEach(visit);
}

// GitHub task lists render each item's checkbox with no name, so the item's
// first line becomes the checkbox's label.
export default function taskListLabels() {
  return visit;
}
