import test from "node:test";
import assert from "node:assert/strict";
import { completeCollection, partialCollection, unavailableCollection, skippedCollection, collectionReadable, collectionComplete, collectionError, mapCollection, observedValue, populationValue } from "../dist/extensions/grc-tools/hardening/collection-status.js";
const complete = completeCollection("users", [{ id: "u1" }], { status: 200, endpoint: "/users" });
const empty = completeCollection("groups", []);
const partial = partialCollection("users", [{ id: "u1" }], "page cap reached", { status: 206, endpoint: "/users?page=2" });
const unavailable = unavailableCollection("roles", "403 Forbidden", { status: 403, endpoint: "/roles" });
const skipped = skippedCollection("memberships", "roles were unavailable", unavailable.key);

test("explicit outcomes distinguish partial, unreadable, skipped, and genuinely empty inventories", () => {
  assert.equal(complete.state, "complete");
  assert.equal(empty.state, "complete");
  assert.equal(partial.state, "partial");
  assert.equal(partial.reason, "page cap reached");
  assert.equal(unavailable.state, "unavailable");
  assert.equal(skipped.state, "skipped");
  assert.equal(skipped.dependency, unavailable.key);
  for (const outcome of [unavailable, skipped]) {
    assert.equal("value" in outcome, false, "unread data must not become a placeholder empty list");
    assert.equal(collectionReadable(outcome), false);
    assert.equal(collectionComplete(outcome), false);
  }
  assert.equal(collectionReadable(partial), true);
  assert.equal(collectionComplete(partial), false);
  assert.equal(collectionComplete(empty), true);
  assert.equal(collectionError(unavailable), "403 Forbidden");
  assert.match(collectionError(skipped), /roles were unavailable/);
  assert.equal(collectionError(complete), undefined);
});

test("projection preserves dependency identity and cannot fabricate data for an unavailable collection", () => {
  assert.notEqual(completeCollection("users", []).key, complete.key);
  const projected = mapCollection(partial, (users) => users.map((user) => user.id));
  assert.equal(projected.key, partial.key);
  assert.equal(projected.state, "partial");
  assert.equal(projected.reason, partial.reason);
  assert.equal(projected.status, 206);
  assert.equal(projected.endpoint, "/users?page=2");
  assert.deepEqual(projected.value, ["u1"]);
  for (const outcome of [unavailable, skipped]) assert.equal(mapCollection(outcome, () => assert.fail("unread data must not be projected")), outcome);
});

test("observations under partial reads remain sightings, including zero seen records and observed flags", () => {
  for (const value of [0, 1, false, true, [], ["u1"], {}, { count: 1 }]) assert.equal(observedValue(value, partial), value);
  assert.equal(observedValue(5, complete, unavailable), null);
  assert.equal(observedValue(5, skipped), null);
});

test("population claims require every dependency to be complete regardless of the JavaScript value shape", () => {
  for (const value of [0, 1, false, true, [], ["u1"], {}, { count: 1 }]) {
    assert.equal(populationValue(value, partial), null);
    assert.equal(populationValue(value, complete, unavailable), null);
    assert.equal(populationValue(value, skipped), null);
    assert.equal(populationValue(value, complete, empty), value);
  }
});

test("security evidence distinguishes a spotted inactive account from an exhaustive list", () => {
  assert.deepEqual(observedValue(["u1"], partial), ["u1"]);
  assert.equal(populationValue(["u1"], partial), null);
  assert.equal(populationValue(0, empty), 0, "a complete empty inventory proves absence");
  assert.equal(populationValue(false, partial), null, "a negative security claim needs complete evidence");
});
