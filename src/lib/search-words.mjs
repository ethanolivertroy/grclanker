/** @import { AdvancedIndex } from 'fumadocs-core/search/server' */

/**
 * The main search index leaves out the body text of the integration guides and
 * the FedRAMP pages, which hold most of the docs text (see search-pages.ts).
 * The word index lists, for each docs section, the words it uses that the main
 * index has nothing for, so a search for such a word, like webhook or SCIM,
 * still finds the sections that use it. The search dialog downloads it only
 * for a query with such a word.
 *
 * @typedef {{ tokenize(input: string, language?: string, prop?: string): string[] }} Tokenizer
 */

// Everything but letters and digits splits words, so sandbox.allowedDomains
// holds sandbox and allowedDomains, and webhooks_read holds webhooks and read.
const run = /[\p{L}\p{N}]+/gu;

// A run with at most two digits counts, as in 2FA or Log4Shell, and so does
// one that ends in its digits, as in SHA256, or a number of three to five
// digits, such as 429 or 27017. Longer numbers and runs with more digits
// inside are mostly hashes and example IDs.
function isWord(text) {
  const digits = text.match(/\p{N}/gu)?.length ?? 0;
  if (digits <= 2) return digits < text.length;
  return /^\p{L}+\p{N}+$/u.test(text) || /^\p{N}{3,5}$/u.test(text);
}

/**
 * @param {string} text
 * @returns {string[]} the words in `text`, repeats included
 */
export function plainWords(text) {
  return (text.match(run) ?? []).filter(isWord);
}

/**
 * Returns a test for whether a search of the main index finds a word. A search
 * matches every token that starts with the word it is given.
 *
 * @param {AdvancedIndex[]} pages what the main index lists
 * @param {Tokenizer} tokenizer the one the main index is built with
 * @returns {(word: string) => boolean} given a word tokenized the same way
 */
export function createVocabulary(pages, tokenizer) {
  const tokens = new Set();
  const add = (text) => {
    if (text) for (const token of tokenizer.tokenize(text, undefined, 'content')) tokens.add(token);
  };
  for (const page of pages) {
    add(page.title);
    add(page.description);
    for (const heading of page.structuredData.headings) add(heading.content);
    for (const content of page.structuredData.contents) add(content.content);
  }
  const sorted = [...tokens].sort();
  return (word) => {
    let low = 0;
    let high = sorted.length;
    while (low < high) {
      const middle = (low + high) >>> 1;
      if (sorted[middle] < word) low = middle + 1;
      else high = middle;
    }
    return low < sorted.length && sorted[low].startsWith(word);
  };
}

/**
 * Builds the word index from every docs page. Each section's words that the
 * main index cannot find are indexed under its heading, or under the page for
 * the text above its first heading. Hits show only the heading or page title,
 * so the index stores no body text. Repeats stay in, so a section that uses a
 * word more often ranks higher.
 *
 * @param {AdvancedIndex[]} pages every docs page with all of its text
 * @param {(word: string) => boolean} found whether the main index finds a word
 * @param {Tokenizer} tokenizer the one the word index is built with
 * @returns {{ indexes: AdvancedIndex[], getDocumentProperties: (doc: { url: string }) => { content: string } }}
 *   the pages to index, and the words to index for each search document
 */
export function createWordIndex(pages, found, tokenizer) {
  /** @type {Map<string, string[]>} */
  const words = new Map();
  /** @type {AdvancedIndex[]} */
  const indexes = [];
  for (const page of pages) {
    const { headings, contents } = page.structuredData;
    const headingIds = new Set(headings.map((heading) => heading.id));
    /** @type {Set<string>} */
    const sections = new Set();
    for (const { heading, content } of contents) {
      const unknown = tokenizer.tokenize(plainWords(content).join(' '), undefined, 'content').filter((word) => !found(word));
      if (unknown.length === 0) continue;
      const url = heading && headingIds.has(heading) ? `${page.url}#${heading}` : page.url;
      words.set(url, [...(words.get(url) ?? []), ...unknown]);
      sections.add(url);
    }
    if (sections.size === 0) continue;
    indexes.push({
      id: page.id,
      title: page.title,
      url: page.url,
      breadcrumbs: page.breadcrumbs,
      structuredData: {
        headings: headings.filter((heading) => sections.has(`${page.url}#${heading.id}`)),
        contents: [],
      },
    });
  }
  return {
    indexes,
    getDocumentProperties: (doc) => ({ content: words.get(doc.url)?.join(' ') ?? '' }),
  };
}

/**
 * @template {{ type: string, url: string }} Result
 * @param {Result[]} results each page followed by its hits
 * @returns {Result[][]}
 */
function groupByPage(results) {
  /** @type {Result[][]} */
  const groups = [];
  for (const result of results) {
    if (result.type === 'page' || groups.length === 0) groups.push([result]);
    else groups.at(-1)?.push(result);
  }
  return groups;
}

/**
 * Runs a search, and searches the word index too for the words the main index
 * finds nothing for. Those words come only from the query's space-separated
 * terms that the main index finds nothing for, so the parts of an ID like
 * CM.L2-3.4.1, which it finds whole, never count. Pages that use the missing
 * words come first: the ones that also match the rest of the query, in the
 * main order, then the others. The pages that match only the rest of the query
 * follow. A page is listed once, so its hits all come from one index. A query
 * whose terms the main index all finds returns the main results unchanged, and
 * so does any query when the word index fails to load.
 *
 * @template {{ type: string, url: string }} Result
 * @param {string} query
 * @param {(query: string) => Result[] | PromiseLike<Result[]>} search searches the main index
 * @param {(query: string) => Result[] | PromiseLike<Result[]>} searchWords searches the word index
 * @returns {Promise<Result[]>}
 */
export async function searchUnknownWords(query, search, searchWords) {
  const results = await search(query);
  /** @type {Set<string>} */
  const unknown = new Set();
  for (const term of new Set(query.split(/\s+/).filter(Boolean))) {
    const termResults = term === query.trim() ? results : await search(term);
    if (termResults.length > 0) continue;
    for (const word of new Set(plainWords(term))) {
      if (word === term || (await search(word)).length === 0) unknown.add(word);
    }
  }
  if (unknown.size === 0) return results;

  let wordResults;
  try {
    wordResults = await searchWords([...unknown].join(' '));
  } catch {
    return results;
  }
  const wordGroups = new Map(groupByPage(wordResults).map((group) => [group[0].url, group]));
  const mainGroups = groupByPage(results);
  const mainUrls = new Set(mainGroups.map((group) => group[0].url));
  return [
    ...mainGroups.flatMap((group) => wordGroups.get(group[0].url) ?? []),
    ...[...wordGroups.values()].filter((group) => !mainUrls.has(group[0].url)).flat(),
    ...mainGroups.filter((group) => !wordGroups.has(group[0].url)).flat(),
  ];
}
