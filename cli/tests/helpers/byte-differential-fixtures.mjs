import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { readBundleFiles, readZipEntries } from "./bundle-contents.mjs";

const fixtureRoot = process.env.GRC_BYTE_FIXTURE_DIR;
const exportRoot = process.env.GRC_BYTE_EXPORT_ROOT;

export const byteDifferentialEnabled = Boolean(fixtureRoot && exportRoot);

function sortedEntries(entries) {
  return [...entries].sort(([left], [right]) => left.localeCompare(right));
}

export function writeByteDifferentialFixture(integration, fixtureClass, value) {
  if (!fixtureRoot) return;
  const directory = join(fixtureRoot, integration);
  mkdirSync(directory, { recursive: true });
  writeFileSync(join(directory, `${fixtureClass}.json`), `${JSON.stringify(value, null, 2)}\n`);
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
