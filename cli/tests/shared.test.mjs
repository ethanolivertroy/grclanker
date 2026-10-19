import test from "node:test";
import assert from "node:assert/strict";
import { setTimeout as sleep } from "node:timers/promises";

import { mapWithConcurrency } from "../dist/extensions/grc-tools/shared.js";

test("mapWithConcurrency returns results in input order and runs at most `limit` items at once", async () => {
  let running = 0;
  let peak = 0;
  const results = await mapWithConcurrency([30, 5, 20, 10, 1, 15], 3, async (delay, index) => {
    running += 1;
    peak = Math.max(peak, running);
    await sleep(delay);
    running -= 1;
    return `${index}:${delay}`;
  });

  assert.deepEqual(results, ["0:30", "1:5", "2:20", "3:10", "4:1", "5:15"]);
  assert.equal(peak, 3);
  assert.deepEqual(await mapWithConcurrency([], 3, async () => assert.fail("there is no item to run")), []);
});

test("once a worker fails, mapWithConcurrency starts no further item and rejects with the first failure after the running items settle", async () => {
  const started = [];
  const settled = [];
  const failure = new Error("item 1 failed");
  const mapping = mapWithConcurrency([0, 1, 2, 3, 4, 5, 6, 7], 3, async (item) => {
    started.push(item);
    await sleep(item === 1 ? 5 : 25);
    settled.push(item);
    if (item === 1) throw failure;
    if (item === 2) throw new Error("item 2 failed later");
    return item;
  });

  await assert.rejects(mapping, (error) => error === failure);
  assert.deepEqual(started, [0, 1, 2]);
  assert.deepEqual(settled.sort((left, right) => left - right), [0, 1, 2]);
});
