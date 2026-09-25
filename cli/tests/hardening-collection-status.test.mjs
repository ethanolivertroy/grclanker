import test from "node:test";
import assert from "node:assert/strict";

import {
  coreDataValue,
  countIfReadable,
  datasetMarker,
  datasetState,
  datasetStatus,
  derived,
  derivedFlag,
  gatedPrincipals,
  ifComplete,
  ifRead,
  isAbsenceValue,
  isComplete,
  isReadable,
  notCollected,
  notRequested,
  notRequestedDataset,
  readDataset,
  seenVersusTotal,
  unreadableDataset,
  withoutAbsenceClaims,
} from "../dist/extensions/grc-tools/hardening/collection-status.js";

const complete = readDataset([{ id: "u1" }, { id: "u2" }], { total: 2, status: 200, endpoint: "/v1/users" });
const emptyComplete = readDataset([], { total: 0, status: 200, endpoint: "/v1/groups" });
const truncated = readDataset([{ id: "u1" }], { truncated: true, total: 40, status: 200, endpoint: "/v1/users?limit=1" });
const unreadable = unreadableDataset("GET /v1/roles failed with 403 Forbidden: non-JSON body (text/html, 512 bytes)", { status: 403, endpoint: "/v1/roles" });
const notIssued = notRequestedDataset("roles", unreadable.error);

test("dataset constructors produce exactly one state each", () => {
  assert.equal(datasetState(complete), "complete");
  assert.equal(datasetState(emptyComplete), "complete");
  assert.equal(datasetState(truncated), "truncated");
  assert.equal(datasetState(unreadable), "unreadable");
  assert.equal(datasetState(notIssued), "not_requested");

  assert.deepEqual(complete, { items: [{ id: "u1" }, { id: "u2" }], complete: true, truncated: false, total: 2, status: 200, endpoint: "/v1/users", error: null });
  assert.deepEqual(readDataset([]), { items: [], complete: true, truncated: false, total: null, status: null, endpoint: null, error: null });
  assert.deepEqual(unreadable, { items: [], complete: false, truncated: false, total: null, status: 403, endpoint: "/v1/roles", error: unreadable.error });
  assert.deepEqual(notIssued, {
    items: [],
    complete: false,
    truncated: false,
    total: null,
    status: null,
    endpoint: null,
    error: null,
    notRequested: `Not requested: roles was not readable (${unreadable.error})`,
  });
  assert.equal(notRequestedDataset("roles").notRequested, "Not requested: roles was not readable");

  assert.equal(isReadable(complete) && isReadable(truncated) && isReadable(emptyComplete), true);
  assert.equal(isReadable(unreadable) || isReadable(notIssued), false);
  assert.equal(isComplete(complete) && isComplete(emptyComplete), true);
  assert.equal(isComplete(truncated) || isComplete(unreadable) || isComplete(notIssued), false);

  const handRolledPartial = { items: [{ id: "x" }], complete: false, truncated: false, total: null, status: 200, endpoint: "/x", error: null };
  assert.equal(datasetState(handRolledPartial), "truncated", "a read that is not complete is partial even without the flag");
});

test("core_data renders a readable dataset as its list and an unread one as a marker", () => {
  assert.deepEqual(coreDataValue(complete), complete.items);
  assert.deepEqual(coreDataValue(emptyComplete), [], "a readable empty inventory keeps its list shape");
  assert.deepEqual(coreDataValue(truncated), truncated.items);
  assert.deepEqual(coreDataValue(unreadable), { collected: false, status: 403, endpoint: "/v1/roles", error: unreadable.error });
  assert.deepEqual(coreDataValue(notIssued), { collected: false, status: null, endpoint: null, error: notIssued.notRequested });

  assert.equal(datasetMarker(complete), undefined);
  assert.equal(datasetMarker(truncated), undefined);
  assert.deepEqual(datasetMarker(unreadable), notCollected(unreadable.error, 403, "/v1/roles"));
  assert.deepEqual(datasetMarker(notIssued), notRequested("roles", unreadable.error));
  assert.deepEqual(notCollected("denied"), { collected: false, status: null, endpoint: null, error: "denied" });
  assert.deepEqual(notRequested("users"), { collected: false, status: null, endpoint: null, error: "Not requested: users was not readable" });
  assert.deepEqual(notRequested("users", null), notRequested("users"));
});

test("datasetStatus reports counts and totals only for answered reads", () => {
  assert.deepEqual(datasetStatus(complete), { state: "complete", count: 2, total: 2, truncated: false, status: 200, endpoint: "/v1/users", error: null });
  assert.deepEqual(datasetStatus(emptyComplete), { state: "complete", count: 0, total: 0, truncated: false, status: 200, endpoint: "/v1/groups", error: null });
  assert.deepEqual(datasetStatus(truncated), { state: "truncated", count: 1, total: 40, truncated: true, status: 200, endpoint: "/v1/users?limit=1", error: null });
  assert.deepEqual(datasetStatus(unreadable), { state: "unreadable", count: null, total: null, truncated: null, status: 403, endpoint: "/v1/roles", error: unreadable.error });
  assert.deepEqual(datasetStatus(notIssued), { state: "not_requested", count: null, total: null, truncated: null, status: null, endpoint: null, error: notIssued.notRequested });
});

test("derived values render null under an unread source and null for absence claims under a partial source", () => {
  assert.equal(derived(2, complete), 2);
  assert.equal(derived(0, complete), 0, "a complete read proves a zero");
  assert.deepEqual(derived([], emptyComplete), []);
  assert.equal(derived(1, truncated), 1, "a positive sighting under a partial read stands");
  assert.equal(derived(0, truncated), null, "a partial read cannot prove a zero");
  assert.equal(derived([], truncated), null);
  assert.deepEqual(derived({}, truncated), null);
  assert.deepEqual(derived({ a: 1 }, truncated), { a: 1 });
  assert.equal(derived(5, unreadable), null);
  assert.equal(derived(5, notIssued), null);
  assert.equal(derived(5, complete, unreadable), null, "one unread source nulls the whole derivation");
  assert.equal(derived(0, complete, truncated), null);
  assert.equal(derived(3, complete, truncated), 3);
  assert.equal(derived(7), 7, "no sources means nothing withheld");

  assert.equal(derivedFlag(true, truncated), true);
  assert.equal(derivedFlag(false, truncated), null);
  assert.equal(derivedFlag(false, complete), false);
  assert.equal(derivedFlag(true, unreadable), null);
  assert.equal(derivedFlag(false, complete, notIssued), null);

  assert.equal(countIfReadable(0, emptyComplete), 0);
  assert.equal(countIfReadable(1, truncated), 1, "a count of what was seen is a fact about the read");
  assert.equal(countIfReadable(0, unreadable), null);
  assert.equal(countIfReadable(4, complete, notIssued), null);

  assert.equal(ifRead(truncated, "seen"), "seen");
  assert.equal(ifRead(unreadable, "seen"), null);
  assert.equal(ifComplete("all", complete, emptyComplete), "all");
  assert.equal(ifComplete("all", complete, truncated), null);
});

test("isAbsenceValue names the values that claim nothing exists", () => {
  for (const value of [0, [], {}]) assert.equal(isAbsenceValue(value), true);
  for (const value of [1, -1, [0], { a: null }, "", null, undefined, false, "0"]) assert.equal(isAbsenceValue(value), false, `${JSON.stringify(value)} is not an absence claim`);
});

test("seenVersusTotal phrases progress for known and unknown totals", () => {
  assert.equal(seenVersusTotal(40, 120), "seen 40 of 120");
  assert.equal(seenVersusTotal(0, 0), "seen 0 of 0");
  assert.equal(seenVersusTotal(40, null), "40 seen, total unknown");
  assert.equal(seenVersusTotal(40, undefined), "40 seen, total unknown");
});

test("withoutAbsenceClaims nulls absence values under a partial read and passes a complete one through", () => {
  const evidence = { admins: 0, groups: [], policies: {}, users: 3, names: ["a"], enabled: false, note: "x" };
  assert.deepEqual(withoutAbsenceClaims(evidence, true), evidence);
  assert.deepEqual(withoutAbsenceClaims(evidence, false), { admins: null, groups: null, policies: null, users: 3, names: ["a"], enabled: false, note: "x" });
  assert.deepEqual(withoutAbsenceClaims(undefined, false), {});
  assert.deepEqual(withoutAbsenceClaims(undefined, true), {});
});

test("gatedPrincipals emits named principals only for a complete read", () => {
  const principals = { admins_without_mfa: ["alice", "bob"], admin_count: 2, stale_accounts: [] };
  assert.deepEqual(gatedPrincipals(principals, true, []), { ...principals, principals_withheld: null });
  assert.deepEqual(gatedPrincipals(principals, false, ["users: seen 40 of 120", "roles: not collected"]), {
    admins_without_mfa: null,
    admin_count: null,
    stale_accounts: null,
    principals_withheld: "users: seen 40 of 120; roles: not collected",
  });
  assert.deepEqual(gatedPrincipals(undefined, false, ["users: seen 40 of 120"]), {});
});
