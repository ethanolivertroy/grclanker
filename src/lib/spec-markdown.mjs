const URL_SCHEME = /^[a-z][a-z0-9+.-]*:/i;
// Text can't sit directly in these nodes, whose children are blocks.
const BLOCK_PARENTS = new Set(['root', 'blockquote', 'listItem']);

function isRelative(url) {
  return !URL_SCHEME.test(url) && !url.startsWith('#') && !url.startsWith('/');
}

function prepare(parent, linkBase) {
  parent.children = parent.children.flatMap((node) => {
    if (node.type === 'html') {
      if (node.value.trimStart().startsWith('<!--')) return [];
      const text = { type: 'text', value: node.value };
      return [BLOCK_PARENTS.has(parent.type) ? { type: 'paragraph', children: [text] } : text];
    }
    if ((node.type === 'link' || node.type === 'definition') && isRelative(node.url)) {
      node.url = new URL(node.url, linkBase).href;
    }
    if (node.children) prepare(node, linkBase);
    return [node];
  });
}

/**
 * Prepares a spec's markdown, written to be read on GitHub, for its page on
 * the site. The page header already shows the spec's name, so a leading title
 * heading is dropped. Raw HTML would be stripped, losing placeholders such as
 * `<instance>`, so it is kept as text, except for comments. Relative links
 * resolve against `linkBase`, the spec folder on GitHub.
 */
export default function remarkSpecSource({ linkBase }) {
  return (tree) => {
    const first = tree.children.find((node) => node.type === 'heading');
    if (first?.depth === 1) tree.children.splice(tree.children.indexOf(first), 1);
    prepare(tree, linkBase);
  };
}
