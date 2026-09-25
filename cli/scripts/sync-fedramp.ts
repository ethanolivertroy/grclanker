import { mkdir, rm, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { buildFedrampDocsSnapshot } from "../extensions/grc-tools/fedramp-docs.js";
import { inspectFedrampOfficialSources, loadFedrampCatalog } from "../extensions/grc-tools/fedramp-source.js";

async function writeGeneratedFiles(
  baseDir: string,
  files: ReturnType<typeof buildFedrampDocsSnapshot>,
) {
  await rm(baseDir, { recursive: true, force: true });
  for (const file of files) {
    const targetPath = resolve(baseDir, file.path.replace(/^fedramp\//, ""));
    await mkdir(dirname(targetPath), { recursive: true });
    await writeFile(targetPath, file.content, "utf8");
  }
}

async function main() {
  const repoRoot = resolve(fileURLToPath(new URL("../..", import.meta.url)));
  const targetDir = resolve(repoRoot, "src/content/docs/docs/fedramp");

  const [loaded, sourceStatus] = await Promise.all([
    loadFedrampCatalog({ refresh: true }),
    inspectFedrampOfficialSources({ refresh: true }),
  ]);

  const files = buildFedrampDocsSnapshot(loaded.catalog, {
    primary: sourceStatus.primary,
    secondary: sourceStatus.secondary,
  });
  await writeGeneratedFiles(targetDir, files);

  process.stdout.write(
    [
      `Wrote ${files.length} generated FedRAMP docs file(s) to ${targetDir}.`,
      `Source: ${sourceStatus.primary.repoUrl}/${sourceStatus.primary.path}`,
      `Consolidated Rules version: ${sourceStatus.primary.version}`,
      `Upstream last_updated: ${sourceStatus.primary.upstreamLastUpdated}`,
      `Narrative source state: ${sourceStatus.secondary.state}`,
    ].join("\n") + "\n",
  );
}

await main();
