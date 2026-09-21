import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";

const CLI_PACKAGE_NAME = "@grclanker/cli";
const MAX_ANCESTOR_DEPTH = 6;

let cachedCliRoot: string | undefined;

function readPackageName(packageJsonPath: string): string | undefined {
  try {
    const contents = JSON.parse(readFileSync(packageJsonPath, "utf8")) as { name?: unknown };
    return typeof contents.name === "string" ? contents.name : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Walk upward from `startDir` to the grclanker CLI package root. Works from
 * the source tree (`cli/agent-sdk/lib`) and the compiled output
 * (`cli/dist/agent-sdk/lib`), and skips the nested Agent SDK project manifest
 * because only the CLI package is named `@grclanker/cli`.
 */
export function resolveCliRoot(startDir: string = import.meta.dirname): string {
  let current = resolve(startDir);

  for (let depth = 0; depth < MAX_ANCESTOR_DEPTH; depth += 1) {
    const packageJsonPath = resolve(current, "package.json");
    if (existsSync(packageJsonPath) && readPackageName(packageJsonPath) === CLI_PACKAGE_NAME) {
      return current;
    }

    const parent = dirname(current);
    if (parent === current) break;
    current = parent;
  }

  throw new Error(`Unable to locate the ${CLI_PACKAGE_NAME} package root from ${startDir}.`);
}

/** Resolve a path inside the CLI package (for example `.grclanker/SYSTEM.md`). */
export function resolveCliPath(...segments: string[]): string {
  cachedCliRoot ??= resolveCliRoot();
  return resolve(cachedCliRoot, ...segments);
}

/** Read a UTF-8 text asset bundled with the CLI package. */
export function readCliAsset(...segments: string[]): string {
  return readFileSync(resolveCliPath(...segments), "utf8");
}
