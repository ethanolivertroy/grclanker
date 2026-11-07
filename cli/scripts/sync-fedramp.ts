import { mkdir, writeFile } from "node:fs/promises";
import { dirname, isAbsolute, relative, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { recoverDirectorySnapshot, replaceDirectoryAtomically } from "../core/atomic-files.ts";

/** Replace the generated tree only after every file has been staged successfully. */
export async function writeGeneratedFiles(
  baseDir: string,
  files: readonly { path: string; content: string }[],
  options: Parameters<typeof replaceDirectoryAtomically>[2] = {},
) {
  if (!files.length) throw new Error("Refusing to publish an empty FedRAMP documentation snapshot.");
  await replaceDirectoryAtomically(baseDir, async (staging) => {
    const paths = new Set<string>();
    for (const file of files) {
      const targetPath = resolve(staging, file.path.replace(/^fedramp\//, ""));
      const within = relative(staging, targetPath);
      if (!file.path.startsWith("fedramp/") || !within || within.startsWith("..") || isAbsolute(within)) {
        throw new Error(`Invalid generated FedRAMP path: ${file.path}`);
      }
      if (paths.has(targetPath)) throw new Error(`Duplicate generated FedRAMP path: ${file.path}`);
      paths.add(targetPath);
      await mkdir(dirname(targetPath), { recursive: true });
      await writeFile(targetPath, file.content, "utf8");
    }
  }, options);
}

async function main() {
  const repoRoot = resolve(fileURLToPath(new URL("../..", import.meta.url)));
  const targetDir = resolve(repoRoot, "src/content/docs/docs/fedramp");
  await recoverDirectorySnapshot(targetDir);
  const { buildFedrampDocsSnapshot } = await import("../extensions/grc-tools/fedramp-docs.js");
  const { fetchFedrampDocsSources } = await import("../extensions/grc-tools/fedramp-source.js");

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

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error: unknown) => {
    process.stderr.write(`FedRAMP sync failed: ${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
