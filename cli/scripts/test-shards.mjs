#!/usr/bin/env node
// Splits the test:cli files into CI shards that take about as long as each other, and runs one.
//
//   node scripts/test-shards.mjs --shard 2/3     run shard 2 of 3
//   node scripts/test-shards.mjs --list 3        show each shard's files and expected seconds
//   gh run view RUN_ID --log | node scripts/test-shards.mjs --update-weights
//                                                record each file's seconds from a ci run
//
// node --test --test-shard deals the files out in name order, so how much slow work a shard gets
// depends on where the slow files happen to sort. Here each shard gets a similar total weight,
// starts its slowest files first, and prints a "[test-shards] 12.3s tests/x.test.mjs" line per file
// for --update-weights. A file without a weight counts as the median, so a new test file needs no
// entry in the weights file.
import { globSync, readFileSync, writeFileSync } from "node:fs";
import { relative, resolve } from "node:path";
import { text } from "node:stream/consumers";
import { run } from "node:test";
import { spec } from "node:test/reporters";
import { fileURLToPath } from "node:url";

export const TEST_FILE_PATTERN = "tests/*.test.mjs";

const CLI_DIR = resolve(import.meta.dirname, "..");
const WEIGHTS_PATH = resolve(import.meta.dirname, "test-shard-weights.json");
const WEIGHT_LINE = /\[test-shards\] (\d+(?:\.\d+)?)s (tests\/\S+\.test\.mjs)/g;

export function listTestFiles() {
  return globSync(TEST_FILE_PATTERN, { cwd: CLI_DIR })
    .map((file) => file.replaceAll("\\", "/"))
    .sort();
}

export function readShardWeights() {
  return JSON.parse(readFileSync(WEIGHTS_PATH, "utf8"));
}

function byName(a, b) {
  return a < b ? -1 : a > b ? 1 : 0;
}

// Slowest first, each file to the lightest shard so far, so every shard lists its slowest files first.
export function assignShards(files, weights, total) {
  const known = Object.values(weights).sort((a, b) => a - b);
  const fallback = known.length > 0 ? known[Math.floor(known.length / 2)] : 1;
  const shards = Array.from({ length: total }, () => ({ files: [], seconds: 0 }));
  const weighted = files
    .map((file) => ({ file, seconds: weights[file] ?? fallback }))
    .sort((a, b) => b.seconds - a.seconds || byName(a.file, b.file));
  for (const { file, seconds } of weighted) {
    const lightest = shards.reduce((best, shard) => (shard.seconds < best.seconds ? shard : best));
    lightest.files.push(file);
    lightest.seconds += seconds;
  }
  return shards;
}

function parseShard(value) {
  const match = /^(\d+)\/(\d+)$/.exec(value ?? "");
  const index = Number(match?.[1]);
  const total = Number(match?.[2]);
  if (!match || index < 1 || index > total) {
    throw new Error(`--shard takes INDEX/TOTAL with 1 <= INDEX <= TOTAL, not ${value}`);
  }
  return { index, total };
}

function describeShard(index, total, { files, seconds }) {
  return `Shard ${index}/${total}: ${files.length} test files, about ${Math.round(seconds)}s of work`;
}

function runShard(value) {
  const { index, total } = parseShard(value);
  const shard = assignShards(listTestFiles(), readShardWeights(), total)[index - 1];
  console.log(describeShard(index, total, shard));
  // node --test would sort the files by name; run() keeps them slowest first. concurrency: true
  // and the exit code on a failed summary match what node --test does.
  run({ cwd: CLI_DIR, files: shard.files.map((file) => resolve(CLI_DIR, file)), concurrency: true })
    .on("test:summary", ({ file, duration_ms: ms, success }) => {
      if (file) console.log(`[test-shards] ${(ms / 1000).toFixed(1)}s ${relative(CLI_DIR, file).replaceAll("\\", "/")}`);
      if (!success) process.exitCode = 1;
    })
    .compose(spec)
    .pipe(process.stdout);
}

function listShards(value) {
  const total = Number(value);
  if (!Number.isInteger(total) || total < 1) throw new Error(`--list takes a shard count, not ${value}`);
  assignShards(listTestFiles(), readShardWeights(), total).forEach((shard, index) => {
    console.log(describeShard(index + 1, total, shard));
    for (const file of shard.files) console.log(`  ${file}`);
  });
}

async function updateWeights() {
  const weights = readShardWeights();
  let recorded = 0;
  for (const [, seconds, file] of (await text(process.stdin)).matchAll(WEIGHT_LINE)) {
    weights[file] = Number(seconds);
    recorded += 1;
  }
  if (recorded === 0) {
    throw new Error("No [test-shards] lines on stdin. Pipe in a ci run's log: gh run view RUN_ID --log");
  }
  const files = new Set(listTestFiles());
  const kept = Object.entries(weights).filter(([file]) => files.has(file)).sort(([a], [b]) => byName(a, b));
  writeFileSync(WEIGHTS_PATH, `${JSON.stringify(Object.fromEntries(kept), null, 2)}\n`);
  console.log(`Recorded ${recorded} file times. ${kept.length} test files now have a weight.`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [flag, value] = process.argv.slice(2);
  if (flag === "--shard") runShard(value);
  else if (flag === "--list") listShards(value);
  else if (flag === "--update-weights") await updateWeights();
  else throw new Error("Usage: test-shards.mjs --shard INDEX/TOTAL | --list TOTAL | --update-weights < ci-log");
}
