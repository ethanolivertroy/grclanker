const identifierPatterns = [
  // Upper snake case names, such as environment variables: ZIA_CLOUD
  /[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+/,
  // CMMC practices: AC.L2-3.1.1
  /[A-Z]{2}\.L[1-3]-\d+(?:\.\d+)+/,
  // Check, finding, and control IDs, with a digit after the first hyphen:
  // AWS-IAM-01, ZS-07, AC-2, QUALYS-C01, NR-05-API-KEY-AGE
  /[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)*-[A-Z]*\d[A-Z0-9]*(?:-[A-Z0-9]+)*/,
  // FedRAMP rule, indicator, and domain IDs, never part of a longer ID:
  // FRC-CSO-POP, KSI-IAM-AAM, KSI-IAM
  /(?<!-)[A-Z]{3}-[A-Z]{3}(?:-[A-Z]{3})?(?!-)/,
  // Rev5 control IDs as the FedRAMP rules write them: ac-2.13
  /(?:ac|at|au|ca|cm|cp|ia|ir|ma|mp|pe|pl|pm|ps|pt|ra|sa|sc|si|sr)-\d+(?:\.\d+)?/,
  // Tool names: zscaler_check_access
  /[a-z][a-z0-9]*(?:_[a-z0-9]+)+/,
];

const identifier = new RegExp(`\\b(?:${identifierPatterns.map((pattern) => pattern.source).join('|')})\\b`, 'g');
const snakeCase = /^[a-z][a-z0-9]*(?:_[a-z0-9]+)+$/;

/**
 * Replaces a page's text blocks with the identifiers they mention, listed once
 * per section in the order they first appear. Snake case names count only when
 * they name a tool, since parameter and API field names would add more to the
 * index than they are worth. Long lists are split so that no search hit shows
 * more than `perBlock` identifiers.
 *
 * @param {{ heading: string | undefined, content: string }[]} contents
 * @param {ReadonlySet<string>} toolNames
 * @param {number} [perBlock]
 * @returns {{ heading: string | undefined, content: string }[]}
 */
export function identifierContents(contents, toolNames, perBlock = 8) {
  /** @type {Map<string | undefined, Set<string>>} */
  const sections = new Map();
  for (const { heading, content } of contents) {
    const ids = sections.get(heading) ?? new Set();
    for (const [id] of content.matchAll(identifier)) {
      if (!snakeCase.test(id) || toolNames.has(id)) ids.add(id);
    }
    sections.set(heading, ids);
  }

  return [...sections].flatMap(([heading, ids]) => {
    const list = [...ids];
    const blocks = [];
    for (let start = 0; start < list.length; start += perBlock) {
      const content = list
        .slice(start, start + perBlock)
        .map((id) => `\`${id}\``)
        .join(' ');
      blocks.push({ heading, content });
    }
    return blocks;
  });
}
