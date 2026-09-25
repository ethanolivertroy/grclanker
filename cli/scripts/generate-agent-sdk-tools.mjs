import { mkdir, readdir, rm, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { listRegisteredGrcToolNames } from "../dist/agent-sdk/lib/registry.js";

const scriptDir = dirname(fileURLToPath(import.meta.url));
export const defaultToolsDir = resolve(scriptDir, "../agent-sdk/agent/tools");

/**
 * Source of one `agent/tools/<name>.ts` entry. The Cursor Agent SDK derives the
 * tool name from the filename, so each file only binds that name to the shared
 * grclanker adapter.
 */
export function buildAgentSdkToolSource(toolName) {
  return [
    'import { defineTool } from "@cursor/july/tools";',
    'import { grclankerToolConfig } from "../../lib/tools.js";',
    "",
    `export default defineTool(grclankerToolConfig(${JSON.stringify(toolName)}));`,
    "",
  ].join("\n");
}

/** Sorted tool names that currently have an entry file in `toolsDir`. */
export async function listAgentSdkToolFiles(toolsDir = defaultToolsDir) {
  const entries = await readdir(toolsDir, { withFileTypes: true }).catch(() => []);
  return entries
    .filter((entry) => entry.isFile() && entry.name.endsWith(".ts"))
    .map((entry) => entry.name.slice(0, -".ts".length))
    .sort();
}

/**
 * Write one entry file per registered grclanker domain tool and remove entry
 * files for tools that are no longer registered.
 */
export async function writeAgentSdkTools(toolsDir = defaultToolsDir) {
  const toolNames = listRegisteredGrcToolNames();
  const existing = await listAgentSdkToolFiles(toolsDir);
  const stale = existing.filter((name) => !toolNames.includes(name));

  await mkdir(toolsDir, { recursive: true });
  for (const toolName of toolNames) {
    await writeFile(resolve(toolsDir, `${toolName}.ts`), buildAgentSdkToolSource(toolName), "utf8");
  }
  for (const toolName of stale) {
    await rm(resolve(toolsDir, `${toolName}.ts`));
  }

  return { written: toolNames, removed: stale };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const toolsDir = process.argv[2] ? resolve(process.cwd(), process.argv[2]) : defaultToolsDir;
  const { written, removed } = await writeAgentSdkTools(toolsDir);
  console.log(`Wrote ${written.length} Agent SDK tool entries to ${toolsDir}`);
  if (removed.length > 0) {
    console.log(`Removed stale entries: ${removed.join(", ")}`);
  }
}
