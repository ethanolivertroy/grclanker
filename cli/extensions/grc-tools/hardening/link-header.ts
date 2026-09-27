/**
 * RFC 8288 Link header parsing for pagination.
 *
 * The parser validates every link-value, including quoted strings and escaped
 * characters, before returning a next relation. A present but malformed header
 * is distinct from a valid header without a next relation so callers can mark
 * the collection partial instead of silently claiming exhaustion.
 */

export type ParsedNextLink =
  | { kind: "absent" }
  | { kind: "next"; target: string }
  | { kind: "unparseable" };

const TOKEN_CHARACTER = /^[!#$%&'*+\-.^_`|~A-Za-z0-9]$/;

function splitLinkValues(header: string): string[] | undefined {
  const values: string[] = [];
  let start = 0;
  let inTarget = false;
  let inQuote = false;
  let escaped = false;

  for (let index = 0; index < header.length; index += 1) {
    const character = header[index];
    if (escaped) {
      escaped = false;
      continue;
    }
    if (inQuote && character === "\\") {
      escaped = true;
      continue;
    }
    if (!inQuote && character === "<") {
      if (inTarget) return undefined;
      inTarget = true;
      continue;
    }
    if (!inQuote && character === ">") {
      if (!inTarget) return undefined;
      inTarget = false;
      continue;
    }
    if (!inTarget && character === '"') {
      inQuote = !inQuote;
      continue;
    }
    if (!inTarget && !inQuote && character === ",") {
      const value = header.slice(start, index).trim();
      if (!value) return undefined;
      values.push(value);
      start = index + 1;
    }
  }

  if (escaped || inTarget || inQuote) return undefined;
  const last = header.slice(start).trim();
  if (!last) return undefined;
  values.push(last);
  return values;
}

function skipWhitespace(value: string, start: number): number {
  let cursor = start;
  while (cursor < value.length && (value[cursor] === " " || value[cursor] === "\t")) cursor += 1;
  return cursor;
}

function parseLinkValue(value: string): { target: string; relations: string[] } | undefined {
  let cursor = skipWhitespace(value, 0);
  if (value[cursor] !== "<") return undefined;
  const targetEnd = value.indexOf(">", cursor + 1);
  if (targetEnd === -1) return undefined;
  const target = value.slice(cursor + 1, targetEnd);
  if (!target || target.includes("<")) return undefined;
  cursor = targetEnd + 1;
  const relations: string[] = [];
  let sawRelation = false;

  while (true) {
    cursor = skipWhitespace(value, cursor);
    if (cursor >= value.length) break;
    if (value[cursor] !== ";") return undefined;
    cursor = skipWhitespace(value, cursor + 1);
    const nameStart = cursor;
    while (cursor < value.length && TOKEN_CHARACTER.test(value[cursor])) cursor += 1;
    if (cursor === nameStart) return undefined;
    const name = value.slice(nameStart, cursor).toLowerCase();
    cursor = skipWhitespace(value, cursor);
    if (value[cursor] !== "=") return undefined;
    cursor = skipWhitespace(value, cursor + 1);

    let parameterValue = "";
    if (value[cursor] === '"') {
      cursor += 1;
      let closed = false;
      while (cursor < value.length) {
        const character = value[cursor];
        if (character === "\\") {
          cursor += 1;
          if (cursor >= value.length) return undefined;
          parameterValue += value[cursor];
          cursor += 1;
          continue;
        }
        if (character === '"') {
          cursor += 1;
          closed = true;
          break;
        }
        parameterValue += character;
        cursor += 1;
      }
      if (!closed) return undefined;
    } else {
      const parameterStart = cursor;
      while (cursor < value.length && TOKEN_CHARACTER.test(value[cursor])) cursor += 1;
      if (cursor === parameterStart) return undefined;
      parameterValue = value.slice(parameterStart, cursor);
    }

    if (name === "rel" && !sawRelation) {
      sawRelation = true;
      const relationTypes = parameterValue.split(/[ \t]+/).filter(Boolean);
      if (relationTypes.length === 0) return undefined;
      relations.push(...relationTypes.map((relation) => relation.toLowerCase()));
    }
  }

  if (!sawRelation) return undefined;
  return { target, relations };
}

export function parseNextLinkHeader(header: string | null | undefined): ParsedNextLink {
  if (header === null || header === undefined) return { kind: "absent" };
  const values = splitLinkValues(header);
  if (!values) return { kind: "unparseable" };

  let nextTarget: string | undefined;
  for (const value of values) {
    const parsed = parseLinkValue(value);
    if (!parsed) return { kind: "unparseable" };
    if (nextTarget === undefined && parsed.relations.includes("next")) nextTarget = parsed.target;
  }
  return nextTarget === undefined ? { kind: "absent" } : { kind: "next", target: nextTarget };
}
