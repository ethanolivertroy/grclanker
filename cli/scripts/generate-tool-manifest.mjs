import { readdir, readFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { buildToolManifest, serializeToolManifest } from "../dist/core/tool-manifest.js";
import { writeFileAtomically } from "../dist/core/atomic-files.js";

const repositoryRoot = fileURLToPath(new URL("../..", import.meta.url));
const excludedDirectories = new Set(["tests", "node_modules", "dist", "release", "coverage"]);
const environmentName = /^[A-Z][A-Z0-9_]*$/;

/** Names only: never read a configured environment value while producing metadata. */
export function environmentReferences(source, { shell = false } = {}) {
  const names = new Set();
  const add = (name) => { if (environmentName.test(name)) names.add(name); };
  for (const match of source.matchAll(/\b(?:process\.)?env\s*\.\s*([A-Z][A-Z0-9_]*)|\b(?:process\.)?env\s*\[\s*["']([A-Z][A-Z0-9_]*)["']\s*\]|\$env:([A-Z][A-Z0-9_]*)/g)) {
    for (const name of match.slice(1)) if (name) add(name);
  }
  if (shell) {
    for (const match of source.matchAll(/\$\{([A-Z][A-Z0-9_]*)(?::[-+?=]|\})/g)) add(match[1]);
  }
  // Auth contracts and ENV-named constants/maps own identifiers used through
  // computed env[key] lookups; looking at those declarations avoids inventing
  // environment variables from arbitrary uppercase error codes or API enums.
  const declarations = [
    ...source.matchAll(/\benvironment\s*:\s*\[([\s\S]*?)\]/g),
    ...source.matchAll(/\b(?:const|let)\s+\w*(?:ENV|Env|env)\w*\s*(?::[^=\n]+)?=\s*([\s\S]*?);/g),
    // Legacy configuration resolvers pass uppercase environment aliases to pick().
    ...source.matchAll(/\bpick\s*\(([\s\S]*?)\)/g),
  ];
  for (const declaration of declarations) {
    for (const match of declaration[1].matchAll(/["']([A-Z][A-Z0-9_]*)["']/g)) add(match[1]);
  }
  return [...names].sort();
}

async function productionFiles(directory) {
  const entries = await readdir(directory, { withFileTypes: true }).catch((error) => {
    if (error.code === "ENOENT") return [];
    throw error;
  });
  const files = [];
  for (const entry of entries) {
    if (entry.name.startsWith(".")) continue;
    const path = join(directory, entry.name);
    if (entry.isDirectory() && !excludedDirectories.has(entry.name)) files.push(...await productionFiles(path));
    else if (entry.isFile() && /\.(?:[cm]?js|ts|tsx|sh|ps1)$/.test(entry.name)) files.push(path);
  }
  return files;
}

export async function collectEnvironmentVariables(repoRoot = repositoryRoot) {
  const files = await productionFiles(join(repoRoot, "cli"));
  const installers = await readdir(join(repoRoot, "public"), { withFileTypes: true }).catch((error) => {
    if (error.code === "ENOENT") return [];
    throw error;
  });
  files.push(...installers.filter((entry) => entry.isFile() && /^install(?:[-.]|$)/.test(entry.name)).map((entry) => join(repoRoot, "public", entry.name)));
  const references = await Promise.all(files.sort().map(async (path) => environmentReferences(await readFile(path, "utf8"), {
    shell: /\.(?:sh|ps1)$/.test(path) || path.startsWith(join(repoRoot, "public", "install")),
  })));
  return [...new Set(references.flat())].sort();
}

export async function synchronizeToolManifest({ repoRoot = repositoryRoot, tools, toolPrefixes, check = false }) {
  const manifest = buildToolManifest({ tools, toolPrefixes, environmentVariables: await collectEnvironmentVariables(repoRoot) });
  const content = serializeToolManifest(manifest);
  const destination = join(repoRoot, "cli/tool-manifest.json");
  if (check) {
    const current = await readFile(destination, "utf8").catch((error) => {
      if (error.code === "ENOENT") return undefined;
      throw error;
    });
    if (current !== content) throw new Error("cli/tool-manifest.json is stale. Run npm --prefix cli run sync:tool-manifest.");
  } else {
    await writeFileAtomically(destination, content);
  }
  return manifest;
}

export async function generateToolManifest(options = {}) {
  const [{ getRegisteredToolSummaries }, { TOOL_PREFIXES }] = await Promise.all([
    import("../dist/pi/tool-catalog.js"),
    import("../dist/core/tool-catalog.js"),
  ]);
  return synchronizeToolManifest({ ...options, tools: getRegisteredToolSummaries(), toolPrefixes: TOOL_PREFIXES });
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const args = process.argv.slice(2);
  if (args.some((argument) => argument !== "--check")) throw new Error("Usage: generate-tool-manifest.mjs [--check]");
  const manifest = await generateToolManifest({ check: args.includes("--check") });
  console.log(`Tool manifest ${args.includes("--check") ? "verified" : "generated"}: ${manifest.tools.length} tools, ${manifest.environmentVariables.length} environment identifiers.`);
}
