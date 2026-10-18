import { suggest } from 'zbsearch';

/** @import { AnyZBSearch } from 'zbsearch' */

/**
 * A query word that neither search index finds anything for is mostly a typo,
 * like okat or crowdstike, since a search matches every indexed word that
 * starts with what was typed. The search dialog then searches for the indexed
 * word one typo away instead, if there is one, and says so.
 */

const keyboardRows = ['qwertyuiop', 'asdfghjkl', 'zxcvbnm'];
const keyPositions = new Map(keyboardRows.flatMap((row, y) => [...row].map((key, x) => [key, { x, y }])));

// Keys next to each other on a QWERTY keyboard, diagonals included.
function neighbouringKeys(a, b) {
  const first = keyPositions.get(a);
  const second = keyPositions.get(b);
  return first !== undefined && second !== undefined && Math.abs(first.x - second.x) <= 1 && Math.abs(first.y - second.y) <= 1;
}

/**
 * Finds the one typo that turns what was typed into a word: a missing letter,
 * an extra letter, a wrong letter, or two neighbouring letters swapped.
 *
 * @param {string} typed
 * @param {string} word
 * @returns {{ kind: 'missing' | 'extra' | 'wrong' | 'swapped', at: number } | undefined}
 *   the typo and where the typed word first differs, or undefined when the
 *   words are the same or more than one typo apart
 */
function findTypo(typed, word) {
  let at = 0;
  while (at < typed.length && typed[at] === word[at]) at++;
  if (typed.length === word.length) {
    if (at === typed.length) return undefined;
    if (typed.slice(at + 1) === word.slice(at + 1)) return { kind: 'wrong', at };
    if (typed[at] === word[at + 1] && typed[at + 1] === word[at] && typed.slice(at + 2) === word.slice(at + 2)) {
      return { kind: 'swapped', at };
    }
    return undefined;
  }
  if (word.length === typed.length + 1 && typed.slice(at) === word.slice(at + 1)) return { kind: 'missing', at };
  if (typed.length === word.length + 1 && typed.slice(at + 1) === word.slice(at)) return { kind: 'extra', at };
  return undefined;
}

/**
 * @param {string} typed
 * @param {string} word
 */
function isLikelyTypo(typed, word) {
  const typo = findTypo(typed, word);
  if (!typo) return false;
  // People seldom mistype a first letter, and words that differ in theirs are
  // mostly unrelated, such as gdpr and dpr.
  if (typo.at === 0 && typo.kind !== 'swapped') return false;
  // One typo changes a quarter of a four-letter word, so any edit often lands
  // on an unrelated word, as soar does on soap and casb on case. Only the
  // common slips count there: swapped letters, a dropped letter, or a key
  // next to the right one.
  if (typed.length === 4) {
    return typo.kind === 'swapped' || typo.kind === 'missing' || (typo.kind === 'wrong' && neighbouringKeys(typed[typo.at], word[typo.at]));
  }
  return true;
}

/**
 * Picks the correction for a typed word: of the indexed words it is a likely
 * typo of, the one the most search documents use, then the first
 * alphabetically. Words with digits never count, so an identifier is never
 * offered.
 *
 * @param {string} typed a lowercase word
 * @param {Map<string, number>} words indexed words, each with how many search documents use it
 * @returns {string | undefined}
 */
export function correctWord(typed, words) {
  /** @type {{ word: string, documents: number } | undefined} */
  let best;
  for (const [word, documents] of words) {
    if (!/^[a-z]+$/.test(word) || !isLikelyTypo(typed, word)) continue;
    if (!best || documents > best.documents || (documents === best.documents && word < best.word)) best = { word, documents };
  }
  return best?.word;
}

/**
 * Lists the words the indexes hold within two edits of a typed word, each with
 * how many search documents use it. zbsearch counts two swapped letters as two
 * edits.
 *
 * @param {string} typed
 * @param {AnyZBSearch[]} indexes loaded indexes
 * @returns {Map<string, number>}
 */
export function indexedWordsNear(typed, indexes) {
  /** @type {Map<string, number>} */
  const words = new Map();
  for (const index of indexes) {
    const { suggestions } = suggest(index, { term: typed, properties: ['content'], prefix: false, tolerance: 2, limit: Infinity });
    for (const { suggestion, count } of suggestions) words.set(suggestion, (words.get(suggestion) ?? 0) + count);
  }
  return words;
}

/**
 * Corrects the typos in a query. Each space-separated word of at least four
 * plain letters that neither index finds anything for is replaced with its
 * correction, if it has one. Shorter words are mostly abbreviations, and words
 * with digits or punctuation mostly identifiers, so they stay as typed, and so
 * does a word when the word index fails to load.
 *
 * @param {string} query
 * @param {(query: string) => unknown[] | PromiseLike<unknown[]>} search searches the main index
 * @param {(query: string) => unknown[] | PromiseLike<unknown[]>} searchWords searches the word index
 * @param {AnyZBSearch[]} indexes both indexes, loaded by the searches
 * @returns {Promise<string>} the corrected query, or the query itself when nothing needed correcting
 */
export async function correctTypos(query, search, searchWords, indexes) {
  const parts = query.split(/(\s+)/);
  let corrected = false;
  for (let i = 0; i < parts.length; i += 2) {
    const typed = parts[i].toLowerCase();
    if (!/^[a-z]{4,}$/.test(typed) || (await search(typed)).length > 0) continue;
    try {
      if ((await searchWords(typed)).length > 0) continue;
    } catch {
      continue;
    }
    const correction = correctWord(typed, indexedWordsNear(typed, indexes));
    if (correction) {
      parts[i] = correction;
      corrected = true;
    }
  }
  return corrected ? parts.join('') : query;
}
