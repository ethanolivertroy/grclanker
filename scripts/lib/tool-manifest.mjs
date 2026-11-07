import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

/** @typedef {{name:string,label:string,description:string,group:string,kind:'domain'|'compute',parameters:Record<string,unknown>,effect:'read'|'write'}} ManifestTool */
/** @typedef {{schemaVersion:1,toolPrefixes:string[],tools:ManifestTool[],environmentVariables:string[]}} ToolManifest */

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
export const TOOL_MANIFEST_PATH = 'cli/tool-manifest.json';
const isRecord = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const nonempty = (value) => typeof value === 'string' && value.trim().length > 0;

function uniqueStrings(value, pattern, field) {
  if (!Array.isArray(value) || value.some((entry) => typeof entry !== 'string' || !pattern.test(entry)) || new Set(value).size !== value.length) {
    throw new Error(`Invalid tool manifest ${field}`);
  }
  return value;
}

/** Validate a checked-in build artifact without loading an SDK or reverse-parsing source code. */
export function parseToolManifest(value) {
  if (!isRecord(value) || value.schemaVersion !== 1) throw new Error('Unsupported tool manifest schemaVersion');
  const toolPrefixes = uniqueStrings(value.toolPrefixes, /^[a-z][a-z0-9_]*_$/, 'toolPrefixes');
  const environmentVariables = uniqueStrings(value.environmentVariables, /^[A-Z][A-Z0-9_]*$/, 'environmentVariables');
  if (!toolPrefixes.length || !Array.isArray(value.tools) || !value.tools.length) throw new Error('Tool manifest has no tool inventory');
  const names = new Set();
  for (const tool of value.tools) {
    if (!isRecord(tool) || !nonempty(tool.name) || !/^[a-z][a-z0-9_]*$/.test(tool.name)
      || !['label', 'description', 'group'].every((key) => nonempty(tool[key]))
      || !['domain', 'compute'].includes(tool.kind) || !['read', 'write'].includes(tool.effect)
      || !isRecord(tool.parameters) || tool.parameters.type !== 'object') {
      throw new Error('Invalid tool manifest tool definition');
    }
    if (names.has(tool.name)) throw new Error(`Duplicate tool manifest name: ${tool.name}`);
    if (tool.kind === 'domain' && !toolPrefixes.some((prefix) => tool.name.startsWith(prefix))) {
      throw new Error(`Missing tool manifest prefix for ${tool.name}`);
    }
    names.add(tool.name);
  }
  return /** @type {ToolManifest} */ ({ ...value, toolPrefixes, environmentVariables });
}

/** @returns {ToolManifest} */
export function readToolManifest(repoDir = repositoryRoot) {
  const path = resolve(repoDir, TOOL_MANIFEST_PATH);
  try {
    return parseToolManifest(JSON.parse(readFileSync(path, 'utf8')));
  } catch (error) {
    throw new Error(`${TOOL_MANIFEST_PATH}: ${error instanceof Error ? error.message : 'Invalid manifest'}. Run npm --prefix cli run sync:tool-manifest.`, { cause: error });
  }
}
