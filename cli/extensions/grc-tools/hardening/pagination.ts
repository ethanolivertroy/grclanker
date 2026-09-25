/**
 * Uniform pagination stop reporting (rule 10).
 *
 * Every pagination or collection loop that can exit on an item limit, a page cap, a time budget, a
 * cursor that does not advance, an empty page that still reports a cursor, a listing that reports
 * no total, or a server-supplied next link that may not be followed (`resolveSameOriginUrl` in
 * `next-link.ts`) must report the dataset truncated so the rule 5 partial-inventory demotion
 * applies. Only `exhausted` (no next cursor, and every reported item seen) yields a complete
 * listing. Distilled from the New Relic `describePagination` (#30). This module describes the stop;
 * it does not walk pages, because every client has its own page shape.
 */

/**
 * Why a walk stopped. Every kind other than `exhausted` is a cap or an anomaly. `rejected_next_link`
 * carries the rejection reason and, for a foreign origin, the rejected link's origin (scheme, host,
 * and port; never its path, query, fragment, or userinfo), which the note names beside the fixed
 * text. Build it with `nextLinkStop` from the thrown `NextLinkError`.
 */
export type PaginationStop =
  | { kind: "exhausted" }
  | { kind: "limit"; limit: number }
  | { kind: "page_cap"; pages: number }
  | { kind: "repeated_cursor" }
  | { kind: "empty_page_with_cursor" }
  | { kind: "time_budget"; budgetMs: number }
  | { kind: "missing_total" }
  | { kind: "rejected_next_link"; reason: "foreign_origin" | "userinfo" | "unparseable"; origin?: string };

export type PaginationStopKind = PaginationStop["kind"];

export interface PaginationOutcome {
  complete: boolean;
  truncated: boolean;
  /** Why the listing is incomplete, in the rule 10 phrasing; absent when it is complete. */
  note?: string;
}

function progress(seen: number, total: number | null | undefined): string {
  return `${seen}${total === null || total === undefined ? "" : ` of ${total}`} items`;
}

function nextLinkRejectionText(stop: Extract<PaginationStop, { kind: "rejected_next_link" }>): string {
  switch (stop.reason) {
    case "foreign_origin":
      return `named ${stop.origin ?? "another origin"} rather than the configured origin`;
    case "userinfo":
      return "carried userinfo";
    case "unparseable":
      return "could not be parsed";
    default: {
      const unhandled: never = stop.reason;
      throw new Error(`Unhandled next link rejection ${String(unhandled)}`);
    }
  }
}

/**
 * The outcome of a walk: complete only for `exhausted` with no reported total left unseen; every other
 * stop is truncated with a note that names the seen count, the total when known, and the reason.
 */
export function describePagination(seen: number, total: number | null | undefined, stop: PaginationStop): PaginationOutcome {
  const seenText = progress(seen, total);
  switch (stop.kind) {
    case "exhausted":
      if (total !== null && total !== undefined && seen < total) {
        return { complete: false, truncated: true, note: `${seenText} seen before the listing ended without a next cursor` };
      }
      return { complete: true, truncated: false };
    case "limit":
      return { complete: false, truncated: true, note: `stopped after ${seenText} with more pages available (${stop.limit} item limit)` };
    case "page_cap":
      return { complete: false, truncated: true, note: `stopped after ${seenText} with more pages available (${stop.pages} page maximum)` };
    case "repeated_cursor":
      return { complete: false, truncated: true, note: `stopped after ${seenText} because the next cursor did not advance` };
    case "empty_page_with_cursor":
      return { complete: false, truncated: true, note: `stopped after ${seenText} because a page returned no items while a next cursor was reported` };
    case "time_budget":
      return { complete: false, truncated: true, note: `stopped after ${seenText} when the ${stop.budgetMs} ms time budget ran out` };
    case "missing_total":
      return { complete: false, truncated: true, note: `stopped after ${seenText} because the listing reported no total, so the population size is unproven` };
    case "rejected_next_link":
      return { complete: false, truncated: true, note: `stopped after ${seenText} because the next link ${nextLinkRejectionText(stop)} and was not followed` };
    default: {
      const unhandled: never = stop;
      throw new Error(`Unhandled pagination stop ${String(unhandled)}`);
    }
  }
}
