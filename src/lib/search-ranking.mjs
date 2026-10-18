function normalize(text) {
  return text.toLowerCase().replace(/[^\p{L}\p{N}_]+/gu, ' ').trim();
}

// Title words match by prefix, so dropping a plural s lets "tools" find "Tool Catalog".
function stem(word) {
  return word.length > 3 && word.endsWith('s') ? word.slice(0, -1) : word;
}

// 0: the title is the query. 1: the title starts with it. 2: every query word
// starts a title word. 3: the query matched only headings or body text.
function titleRank(query, title) {
  if (title === query) return 0;
  if (title.startsWith(query)) return 1;
  const titleWords = title.split(' ');
  return query.split(' ').every((word) => titleWords.some((titleWord) => titleWord.startsWith(stem(word)))) ? 2 : 3;
}

/**
 * Moves pages whose title matches the query above pages that matched only in
 * their headings or body text, keeping each page's hits under it. Among title
 * matches, a page with other results under its URL, such as a section hub,
 * comes first. Otherwise the search engine's order holds.
 *
 * @template {{ type: string, url: string, content: string }} Result
 * @param {string} query
 * @param {Result[]} results each page followed by its heading and text hits
 * @returns {Result[]}
 */
export function rankTitleMatchesFirst(query, results) {
  const normalizedQuery = normalize(query);
  if (!normalizedQuery) return results;

  /** @type {Result[][]} */
  const groups = [];
  for (const result of results) {
    const group = groups.at(-1);
    if (result.type === 'page' || !group) groups.push([result]);
    else group.push(result);
  }

  const urls = groups.map((group) => group[0].url);
  return groups
    .map((group, index) => {
      const { url, content } = group[0];
      const rank = titleRank(normalizedQuery, normalize(content));
      const pagesUnder = rank < 3 ? urls.filter((other) => other !== url && other.startsWith(url)).length : 0;
      return { group, index, rank, pagesUnder };
    })
    .sort((a, b) => a.rank - b.rank || b.pagesUnder - a.pagesUnder || a.index - b.index)
    .flatMap(({ group }) => group);
}
