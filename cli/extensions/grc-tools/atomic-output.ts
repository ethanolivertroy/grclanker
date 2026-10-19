import { createHash, randomBytes } from "node:crypto";
import { lstatSync, readdirSync, rmSync } from "node:fs";
import { chmod, mkdir, rename, rm, writeFile } from "node:fs/promises";
import { hostname } from "node:os";
import { dirname, join } from "node:path";

/**
 * Where a bundle lands: the directory that receives it and the names to try in order. The first
 * name whose directory (and archive, for zipped bundles) does not exist yet is the one used.
 */
export interface BundleTarget {
  root: string;
  names: Iterable<string>;
  /** Thrown when every name is taken. */
  exhaustedMessage?: string;
}

export interface AtomicBundleOptions extends BundleTarget {
  /** Commit the `<name>.zip` the writer produced next to the directory. */
  zip?: boolean;
  /** Aborting discards the staged bundle, so nothing is committed. */
  signal?: AbortSignal;
}

export interface CommittedBundle {
  outputDir: string;
  /** `<outputDir>.zip`, present when the writer produced an archive. */
  zipPath: string;
}

/** The private staging paths a writer fills before the bundle is committed. */
export interface StagedBundle {
  /** The bundle directory; its basename is the name the bundle is expected to commit under. */
  dir: string;
  /** The archive path, next to `dir` rather than inside it. */
  zipPath: string;
  /**
   * Where the bundle is expected to land, for writers that record their own location. It differs
   * from the committed paths only if another process takes the name before the commit.
   */
  target: CommittedBundle;
}

const STAGING_PREFIX = ".grclanker-staging-";
const STAGING_ENTRY = /^\.grclanker-staging-([0-9a-f]{8})-([1-9]\d*)-[0-9a-f]+$/;
const HOST_TOKEN = createHash("sha256").update(hostname()).digest("hex").slice(0, 8);

const activeStaging = new Set<string>();
/** Final paths claimed by writes still in flight in this process, so concurrent writes pick different names. */
const claimedTargets = new Set<string>();
let exitCleanupRegistered = false;

/** `base`, then `base-2` through `base-<count>`: the rerun naming the audit exporters share. */
export function numberedNames(base: string, count: number): string[] {
  return Array.from({ length: count }, (_, index) => (index === 0 ? base : `${base}-${index + 1}`));
}

function pathEntryExists(path: string): boolean {
  return lstatSync(path, { throwIfNoEntry: false }) !== undefined;
}

function assertBundleName(name: string): void {
  if (!name || name === "." || name === ".." || /[\\/\0]/.test(name) || name.startsWith(STAGING_PREFIX)) {
    throw new Error(`Refusing to use bundle name: ${JSON.stringify(name)}`);
  }
}

// The staging name carries the host and pid so a later run can tell a dead writer's leftovers from a live one.
function stagingName(): string {
  return `${STAGING_PREFIX}${HOST_TOKEN}-${process.pid}-${randomBytes(6).toString("hex")}`;
}

function trackStaging(path: string): void {
  activeStaging.add(path);
  if (exitCleanupRegistered) return;
  exitCleanupRegistered = true;
  process.once("exit", () => {
    for (const staged of activeStaging) rmSync(staged, { recursive: true, force: true });
  });
}

async function releaseStaging(path: string): Promise<void> {
  await rm(path, { recursive: true, force: true });
  activeStaging.delete(path);
}

function processIsAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === "EPERM";
  }
}

/** Removes staging entries a process on this host left behind when it died mid-write. */
async function sweepAbandonedStaging(dir: string): Promise<void> {
  let names: string[];
  try {
    names = readdirSync(dir);
  } catch {
    return;
  }
  for (const name of names) {
    const match = STAGING_ENTRY.exec(name);
    if (!match || match[1] !== HOST_TOKEN) continue;
    const pid = Number(match[2]);
    if (pid === process.pid || processIsAlive(pid)) continue;
    const entry = lstatSync(join(dir, name), { throwIfNoEntry: false });
    if (!entry || (!entry.isDirectory() && !entry.isFile())) continue;
    await rm(join(dir, name), { recursive: true, force: true });
  }
}

async function renameUnlessTaken(from: string, to: string): Promise<boolean> {
  try {
    await rename(from, to);
    return true;
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === "EEXIST" || code === "ENOTEMPTY") return false;
    throw error;
  }
}

/**
 * Writes a bundle into a private staging directory under `root` and renames it into place only
 * after the writer finishes, so a failure, an abort, or a crash never leaves a partial bundle at
 * the final path. The staging directory is removed on every exit path; one left by a process that
 * died is removed by the next write under the same root.
 */
export async function writeBundleAtomically(
  options: AtomicBundleOptions,
  write: (staged: StagedBundle) => Promise<void>,
): Promise<CommittedBundle> {
  const { root, zip = false, signal } = options;
  signal?.throwIfAborted();

  const candidates = options.names[Symbol.iterator]();
  const takenOnDisk = (name: string) =>
    pathEntryExists(join(root, name)) || (zip && pathEntryExists(join(root, `${name}.zip`)));
  const nextFreeName = (): string | undefined => {
    for (let step = candidates.next(); !step.done; step = candidates.next()) {
      assertBundleName(step.value);
      if (!claimedTargets.has(join(root, step.value)) && !takenOnDisk(step.value)) return step.value;
    }
    return undefined;
  };
  const exhausted = () => new Error(options.exhaustedMessage ?? `Unable to allocate output directory under ${root}`);

  await mkdir(root, { recursive: true, mode: 0o700 });
  await sweepAbandonedStaging(root);
  let name = nextFreeName();
  if (name === undefined) throw exhausted();
  let claimed = join(root, name);
  claimedTargets.add(claimed);

  const stagingRoot = join(root, stagingName());
  trackStaging(stagingRoot);
  try {
    await mkdir(stagingRoot, { mode: 0o700 });
    const staged: StagedBundle = {
      dir: join(stagingRoot, name),
      zipPath: join(stagingRoot, `${name}.zip`),
      target: { outputDir: claimed, zipPath: `${claimed}.zip` },
    };
    await mkdir(staged.dir, { mode: 0o700 });
    await chmod(staged.dir, 0o700);
    await write(staged);
    signal?.throwIfAborted();

    const archived = zip && pathEntryExists(staged.zipPath);
    for (;;) {
      const outputDir = join(root, name);
      const zipPath = `${outputDir}.zip`;
      if (!takenOnDisk(name) && (await renameUnlessTaken(staged.dir, outputDir))) {
        if (!archived) return { outputDir, zipPath };
        if (!pathEntryExists(zipPath)) {
          try {
            await rename(staged.zipPath, zipPath);
          } catch (error) {
            await rename(outputDir, staged.dir);
            throw error;
          }
          return { outputDir, zipPath };
        }
        await rename(outputDir, staged.dir);
      }
      // Another process took the name while this write ran, so the bundle lands under the next free one.
      claimedTargets.delete(claimed);
      name = nextFreeName();
      if (name === undefined) throw exhausted();
      claimed = join(root, name);
      claimedTargets.add(claimed);
    }
  } finally {
    claimedTargets.delete(claimed);
    await releaseStaging(stagingRoot);
  }
}

/** Writes a file through a temporary sibling and a rename, so readers never see a partial file. */
export async function writeFileAtomically(
  path: string,
  data: string | Uint8Array,
  options: { encoding?: BufferEncoding; mode?: number } = {},
): Promise<void> {
  const dir = dirname(path);
  await sweepAbandonedStaging(dir);
  const temporary = join(dir, stagingName());
  trackStaging(temporary);
  try {
    await writeFile(temporary, data, { encoding: options.encoding, mode: options.mode, flag: "wx" });
    await rename(temporary, path);
  } finally {
    await releaseStaging(temporary);
  }
}
