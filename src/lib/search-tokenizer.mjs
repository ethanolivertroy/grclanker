import { components } from 'zbsearch';

// A run of words joined by hyphens, where a word may hold inner dots and
// underscores: AWS-IAM-01, ac-2.13, AC.L2-3.1.1, KSI-IAM-ELP.
const hyphenated = /[\p{L}\p{N}]+(?:[._][\p{L}\p{N}]+)*(?:-[\p{L}\p{N}]+(?:[._][\p{L}\p{N}]+)*)+/gu;

// Identifiers have a digit or are all capitals. Words like read-only do not,
// and neither does a lowercase query such as ksi-iam-elp, which searches its parts.
function isIdentifier(text) {
  return /\d/.test(text) || (text === text.toUpperCase() && /\p{Lu}/u.test(text));
}

// No word token starts with this, so searching for a word such as veracode
// does not prefix-match VERACODE-11 and favor sections that list many IDs.
const identifierMark = '#';

/**
 * The default tokenizer splits on hyphens, so a search for AWS-IAM-01 is a
 * search for aws, iam, and 01, and it lists every page that mentions IAM.
 * This tokenizer also indexes each hyphenated identifier whole, and a query
 * searches a hyphenated identifier only whole. Prefix matching still applies,
 * so AC-2 lists ac-2 first and then ac-2.1 and ac-20. The parts stay indexed,
 * so a search for IAM still finds AWS-IAM-01.
 *
 * The search route and the search dialog must use the same tokenizer.
 */
export function createSearchTokenizer() {
  const words = components.tokenizer.createTokenizer({ language: 'multilingual' });
  return {
    ...words,
    tokenize(input, language, prop, withCache) {
      // zbsearch passes the property it indexes, and none for a query. Docs
      // search matches only the content property.
      const query = prop === undefined;
      if (typeof input !== 'string' || !(query || prop === 'content')) {
        return words.tokenize(input, language, prop, withCache);
      }
      const identifiers = [];
      const rest = input.replace(hyphenated, (match) => {
        if (!isIdentifier(match)) return match;
        identifiers.push(identifierMark + match.toLowerCase());
        return ' ';
      });
      // Repeats stay in, as with the default tokenizer, since they count toward relevance.
      return [...words.tokenize(query ? rest : input, language, prop, withCache), ...identifiers];
    },
  };
}

/**
 * Runs a search that matches hyphenated identifiers whole. When that finds
 * nothing, such as SOC-2 where the docs write SOC 2, it searches the query's
 * parts instead, as the default tokenizer would.
 *
 * @template Result
 * @param {(query: string) => Result[] | PromiseLike<Result[]>} search
 * @param {string} query
 * @returns {Promise<Result[]>}
 */
export async function searchWholeIdentifiersFirst(search, query) {
  const results = await search(query);
  if (results.length > 0 || !query.includes('-')) return results;
  return search(query.replaceAll('-', ' '));
}
