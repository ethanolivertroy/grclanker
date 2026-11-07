/** Filesystem policy shared by every evidence exporter. */
import { chmodSync, lstatSync, mkdirSync, realpathSync } from "node:fs";
import { chmod, readdir, writeFile } from "node:fs/promises";
import { dirname, isAbsolute, relative, resolve, sep } from "node:path";

export class OutputPathError extends Error {
  constructor(readonly kind: "directory" | "traversal" | "symlink", message: string) {
    super(message);
    this.name = "OutputPathError";
  }
}

/** Inspect the caller's path before resolving aliases: realpath would hide a symlink root. */
export function assertOutputDirectory(pathname: string): void {
  const entry = lstatSync(pathname, { throwIfNoEntry: false });
  if (entry && (!entry.isDirectory() || entry.isSymbolicLink())) {
    throw new OutputPathError(entry.isSymbolicLink() ? "symlink" : "directory", `Refusing to use non-directory or symlink path: ${pathname}`);
  }
}

/** Create missing directories privately, and refuse a symlink at the requested root. */
export function ensurePrivateDir(pathname: string): void {
  assertOutputDirectory(pathname);
  mkdirSync(pathname, { recursive: true, mode: 0o700 });
  assertOutputDirectory(pathname);
}

/** Resolve a contained destination and refuse every symlink beneath the selected root. */
export function resolveSecureOutputPath(baseDir: string, targetPath: string): string {
  ensurePrivateDir(baseDir);
  const base = realpathSync(baseDir);
  const target = resolve(base, targetPath.replace(/[\\/]/g, sep));
  const within = relative(base, target);
  if (within === ".." || within.startsWith(`..${sep}`) || isAbsolute(within)) {
    throw new OutputPathError("traversal", `Refusing to write outside ${base}: ${targetPath}`);
  }
  let current = base;
  for (const segment of within.split(sep).filter(Boolean)) {
    current = resolve(current, segment);
    const entry = lstatSync(current, { throwIfNoEntry: false });
    if (!entry) break;
    if (entry.isSymbolicLink()) {
      throw new OutputPathError("symlink", `Refusing to use symlinked parent directory: ${current}`);
    }
  }
  ensurePrivateDir(dirname(target));
  return target;
}

/** Write inside a private staged bundle using the same containment policy as its publisher. */
export async function writeSecureFile(root: string, pathname: string, content: string | Uint8Array): Promise<string> {
  const target = resolveSecureOutputPath(root, pathname);
  await writeFile(target, content, { encoding: "utf8", mode: 0o600 });
  await chmod(target, 0o600);
  return target;
}

export async function writeSecureTextFile(root: string, pathname: string, content: string): Promise<void> {
  await writeSecureFile(root, pathname, content);
}

/** A vendor's write-boundary redaction policy without duplicating filesystem plumbing. */
export function createSecureTextWriter(scrub: (text: string, secrets: ReadonlyArray<string | undefined>) => string) {
  return (root: string, pathname: string, content: string, secrets: ReadonlyArray<string | undefined> = []) =>
    writeSecureTextFile(root, pathname, scrub(content, secrets));
}

/** Preserve a caller's root spelling when a platform directory above it is an alias. */
export function resolveLexicalOutputPath(root: string, pathname: string): string {
  try {
    const target = resolveSecureOutputPath(root, pathname);
    return resolve(root, relative(realpathSync(root), target));
  } catch (error) {
    if (error instanceof OutputPathError && error.kind === "traversal") {
      throw new OutputPathError(error.kind, `Refusing to write outside output root: ${pathname}`);
    }
    if (error instanceof OutputPathError && error.kind === "symlink") {
      throw new OutputPathError(error.kind, `Refusing to use symlinked output path: ${pathname}`);
    }
    throw error;
  }
}

/** Existing absolute-destination exports also tighten previously created directory permissions. */
export const absoluteOwnerOnlyOutput = {
  ensurePrivateDir(pathname: string): void {
    ensurePrivateDir(pathname);
    chmodSync(pathname, 0o700);
  },
  resolveSecureOutputPath(root: string, pathname: string): string {
    try {
      const target = resolveSecureOutputPath(root, resolve(pathname));
      if (target === realpathSync(root)) throw new OutputPathError("traversal", "The output must name a child of the selected root.");
      return target;
    } catch (error) {
      if (error instanceof OutputPathError && error.kind === "traversal") {
        throw new OutputPathError(error.kind, "Invalid output path: path traversal detected");
      }
      if (error instanceof OutputPathError && error.kind === "symlink") {
        throw new OutputPathError(error.kind, `Refusing to write through symlink: ${pathname}`);
      }
      throw error;
    }
  },
  async writeSecureTextFile(root: string, pathname: string, content: string): Promise<string> {
    const target = absoluteOwnerOnlyOutput.resolveSecureOutputPath(root, pathname);
    absoluteOwnerOnlyOutput.ensurePrivateDir(dirname(target));
    return writeSecureFile(root, target, content);
  },
};

export async function countFilesRecursively(root: string): Promise<number> {
  let count = 0;
  for (const entry of await readdir(root, { withFileTypes: true })) {
    const path = resolve(root, entry.name);
    if (entry.isDirectory()) count += await countFilesRecursively(path);
    else if (entry.isFile()) count += 1;
  }
  return count;
}
