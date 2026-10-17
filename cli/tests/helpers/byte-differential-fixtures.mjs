import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { readBundleFiles, readZipEntries } from "./bundle-contents.mjs";

const fixtureRoot = process.env.GRC_BYTE_FIXTURE_DIR;
const exportRoot = process.env.GRC_BYTE_EXPORT_ROOT;

export const byteDifferentialEnabled = Boolean(fixtureRoot && exportRoot);

/** True while `test:batch-byte-differential` replays these tests against a baseline runtime. */
export const differentialRunActive = Boolean(fixtureRoot || process.env.GRC_CORPUS_FIXTURE_DIR);

/**
 * Registers a test that asserts the portable spec contract. Differential runs copy
 * branch tests onto a baseline that may predate the spec, so they skip these tests
 * on both sides; use spec exports and conformance helpers only inside them.
 */
export const portableContractTest = differentialRunActive ? test.skip : test;

// mkdtemp appends six random characters to the prefix of a directory under tmpdir().
const temporaryDirectory = new RegExp(`${tmpdir().replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}/([^/"\\\\]*?)[A-Za-z0-9]{6}(?=[/"]|$)`, "g");

function sortedEntries(entries) {
  return [...entries].sort(([left], [right]) => left.localeCompare(right));
}

export function writeByteDifferentialFixture(integration, fixtureClass, value) {
  if (!fixtureRoot) return;
  const directory = join(fixtureRoot, integration);
  mkdirSync(directory, { recursive: true });
  const serialized = JSON.stringify(value, null, 2).replace(temporaryDirectory, "<tmpdir>/$1<random>");
  writeFileSync(join(directory, `${fixtureClass}.json`), `${serialized}\n`);
}

export function prepareByteDifferentialExportRoot(integration) {
  if (!exportRoot) throw new Error("GRC_BYTE_EXPORT_ROOT is required for byte differential fixtures");
  const directory = join(exportRoot, integration);
  rmSync(directory, { recursive: true, force: true });
  mkdirSync(directory, { recursive: true });
  return directory;
}

export function snapshotExportBundle(result) {
  return {
    result,
    files: sortedEntries(readBundleFiles(result.outputDir)),
    archiveEntries: sortedEntries(readZipEntries(result.zipPath)),
  };
}
