import { mkdir, rm, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { buildFedrampDocsSnapshot } from "../extensions/grc-tools/fedramp-docs.js";
import { fetchFedrampDocsSources } from "../extensions/grc-tools/fedramp-source.js";

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

  const { catalog, primary, secondary } = await fetchFedrampDocsSources();
  const files = buildFedrampDocsSnapshot(catalog, { primary, secondary });
  await writeGeneratedFiles(targetDir, files);

  process.stdout.write(
    [
      `Wrote ${files.length} generated FedRAMP docs file(s) to ${targetDir}.`,
      `Source: ${primary.repoUrl}/${primary.path}`,
      `Consolidated Rules version: ${primary.version}`,
      `Upstream last_updated: ${primary.upstreamLastUpdated}`,
      `Narrative source state: ${secondary.state}`,
    ].join("\n") + "\n",
  );
}

try {
  await main();
} catch (error) {
  process.stderr.write(`FedRAMP sync failed: ${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
}
