function textOf(node) {
  if (node == null || typeof node === 'boolean') return '';
  if (typeof node === 'string' || typeof node === 'number') return String(node);
  if (Array.isArray(node)) return node.map(textOf).join('');
  if (typeof node === 'object' && 'props' in node) return textOf(node.props?.children);
  return '';
}

/**
 * The text a heading's children render, such as "Use aws_check_access first"
 * for a heading with inline code, for naming the heading's anchor link.
 *
 * @param {unknown} children React children of the heading
 * @returns {string}
 */
export function headingText(children) {
  return textOf(children).replace(/\s+/g, ' ').trim();
}
