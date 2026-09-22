import test from "node:test";
import assert from "node:assert/strict";

import { describePagination } from "../dist/extensions/grc-tools/hardening/pagination.js";

test("only an exhausted walk that saw every reported item is complete", () => {
  assert.deepEqual(describePagination(120, 120, { kind: "exhausted" }), { complete: true, truncated: false });
  assert.deepEqual(describePagination(7, null, { kind: "exhausted" }), { complete: true, truncated: false });
  assert.deepEqual(describePagination(0, undefined, { kind: "exhausted" }), { complete: true, truncated: false });
  assert.deepEqual(describePagination(40, 120, { kind: "exhausted" }), {
    complete: false,
    truncated: true,
    note: "40 of 120 items seen before the listing ended without a next cursor",
  });
});

test("every cap and anomaly is truncated with a note naming the seen count, the total when known, and the reason", () => {
  const cases = [
    [{ kind: "limit", limit: 500 }, "stopped after 500 of 1200 items with more pages available (500 item limit)"],
    [{ kind: "page_cap", pages: 20 }, "stopped after 500 of 1200 items with more pages available (20 page maximum)"],
    [{ kind: "repeated_cursor" }, "stopped after 500 of 1200 items because the next cursor did not advance"],
    [{ kind: "empty_page_with_cursor" }, "stopped after 500 of 1200 items because a page returned no items while a next cursor was reported"],
    [{ kind: "time_budget", budgetMs: 30000 }, "stopped after 500 of 1200 items when the 30000 ms time budget ran out"],
    [{ kind: "missing_total" }, "stopped after 500 of 1200 items because the listing reported no total, so the population size is unproven"],
    [
      { kind: "rejected_next_link", reason: "foreign_origin", origin: "https://evil.example" },
      "stopped after 500 of 1200 items because the next link named https://evil.example rather than the configured origin and was not followed",
    ],
    [
      { kind: "rejected_next_link", reason: "foreign_origin" },
      "stopped after 500 of 1200 items because the next link named another origin rather than the configured origin and was not followed",
    ],
    [{ kind: "rejected_next_link", reason: "userinfo" }, "stopped after 500 of 1200 items because the next link carried userinfo and was not followed"],
    [{ kind: "rejected_next_link", reason: "unparseable" }, "stopped after 500 of 1200 items because the next link could not be parsed and was not followed"],
  ];
  for (const [stop, note] of cases) {
    assert.deepEqual(describePagination(500, 1200, stop), { complete: false, truncated: true, note }, stop.kind);
  }
  assert.equal(describePagination(500, null, { kind: "limit", limit: 500 }).note, "stopped after 500 items with more pages available (500 item limit)");
  assert.equal(describePagination(0, undefined, { kind: "missing_total" }).note, "stopped after 0 items because the listing reported no total, so the population size is unproven");
});

test("an unknown stop kind or next-link rejection reason is rejected", () => {
  assert.throws(() => describePagination(1, 1, { kind: "other" }), /Unhandled pagination stop/);
  assert.throws(() => describePagination(1, 1, { kind: "rejected_next_link", reason: "other" }), /Unhandled next link rejection/);
});
