import { createHash, randomBytes } from "node:crypto";
import { linkSync, lstatSync, readFileSync, readdirSync, renameSync, rmSync, rmdirSync } from "node:fs";
import { chmod, link, lstat, mkdir, rename, rm, writeFile } from "node:fs/promises";
import { hostname } from "node:os";
import { dirname, join, resolve } from "node:path";

/**
 * Where a bundle lands: the directory that receives it and the names to try in order. The first
 * name whose directory (and archive, for zipped bundles) does not exist yet is the one used.
 */
export interface BundleTarget {
  root: string;
  /**
   * Creates `root` with the caller's own checks, in place of a plain recursive mkdir, and returns the
   * path the bundle lands under, such as the root's real path.
   */
  createRoot?: (root: string) => string;
  names: Iterable<string>;
  /** Runs on each candidate name before it is considered; throwing refuses the export instead of moving on. */
  checkName?: (name: string) => void;
  /** Thrown when every name is taken; a function gets the path the bundle would have landed under. */
  exhaustedMessage?: string | ((root: string) => string);
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
  /** The bundle directory; its basename is the name the bundle commits under. */
  dir: string;
  /** The archive path, next to `dir` rather than inside it. */
  zipPath: string;
  /** Where the bundle lands, for writers that record their own location. */
  target: CommittedBundle;
}

/** Names the bundle directory a commit is moving, so recovery never moves another writer's directory. */
interface CommitRecord {
  name: string;
  dev: string;
  ino: string;
}

const STAGING_PREFIX = ".grclanker-staging-";
const STAGING_ENTRY = /^\.grclanker-staging-([0-9a-f]{8})-([1-9]\d*)-[0-9a-f]+$/;
// Bundle names may not start with the staging prefix, so the record never collides with a staged bundle.
const COMMIT_RECORD = `${STAGING_PREFIX}commit.json`;
const HOST_TOKEN = createHash("sha256").update(hostname()).digest("hex").slice(0, 8);

const activeStaging = new Set<string>();
/** Commits in flight in this process, by staging directory, for the exit handler to finish. */
const pendingCommits = new Map<string, { root: string; record: CommitRecord }>();
/** Final paths claimed by writes still in flight in this process, so concurrent writes pick different names. */
const claimedTargets = new Set<string>();
/**
 * Directories that writes in flight in this process created on the way to their roots, with how many of
 * those writes still need each. The last of them to finish removes the directory if nothing landed in it.
 */
const createdDirectories = new Map<string, number>();
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

function registerExitCleanup(): void {
  if (exitCleanupRegistered) return;
  exitCleanupRegistered = true;
  process.once("exit", () => {
    for (const staged of activeStaging) {
      try {
        const pending = pendingCommits.get(staged);
        if (pending) finishCommit(pending.root, staged, pending.record);
        rmSync(staged, { recursive: true, force: true });
      } catch {
        // The next write under the same root sweeps whatever is left.
      }
    }
    // Deepest first, so removing a directory can leave its parent empty.
    for (const dir of [...createdDirectories.keys()].sort((a, b) => b.length - a.length)) removeIfEmpty(dir);
  });
}

function trackStaging(path: string): void {
  activeStaging.add(path);
  registerExitCleanup();
}

function removeIfEmpty(dir: string): boolean {
  try {
    rmdirSync(dir);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === "ENOENT";
  }
}

/**
 * Claims, deepest first, the directories on the way to `root` that do not exist yet or that another
 * write in flight created. Claiming before the root is created is what tells the directories a write
 * creates from the ones that were already there, which are never removed.
 */
function claimNewDirectories(root: string): string[] {
  registerExitCleanup();
  const claimed: string[] = [];
  for (let dir = resolve(root); createdDirectories.has(dir) || !pathEntryExists(dir); dir = dirname(dir)) {
    claimed.push(dir);
    createdDirectories.set(dir, (createdDirectories.get(dir) ?? 0) + 1);
    if (dirname(dir) === dir) break;
  }
  return claimed;
}

/** Drops a write's claims, removing each directory that no other write in flight claims while it is empty. */
function releaseNewDirectories(claimed: readonly string[]): void {
  let removing = true;
  for (const dir of claimed) {
    const remaining = (createdDirectories.get(dir) ?? 1) - 1;
    if (remaining > 0) createdDirectories.set(dir, remaining);
    else createdDirectories.delete(dir);
    // A directory that stays keeps every directory above it from being empty.
    removing &&= remaining === 0 && removeIfEmpty(dir);
  }
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

function identityOf(path: string): { dev: string; ino: string } | undefined {
  const entry = lstatSync(path, { bigint: true, throwIfNoEntry: false });
  return entry && { dev: String(entry.dev), ino: String(entry.ino) };
}

function sameEntry(first: string, second: string): boolean {
  const a = identityOf(first);
  const b = identityOf(second);
  return a !== undefined && b !== undefined && a.dev === b.dev && a.ino === b.ino;
}

function tryRenameSync(from: string, to: string): void {
  try {
    renameSync(from, to);
  } catch {
    // finishCommit re-reads the paths after every move, so a failed one only changes which branch it takes.
  }
}

function linkUnlessTakenSync(from: string, to: string): void {
  try {
    linkSync(from, to);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "EEXIST" && !pathEntryExists(to)) tryRenameSync(from, to);
  }
}

/**
 * Finishes a commit its process left partway: from the exit handler, or after a crash from the next
 * write under the same root. The directory and its archive both end up at their final paths, or
 * neither does. A move the interrupted commit still has in flight is harmless, because whichever
 * of the two runs second finds its source gone or its target taken.
 */
function finishCommit(root: string, stagingRoot: string, record: CommitRecord): void {
  const stagedDir = join(stagingRoot, record.name);
  const stagedZip = `${stagedDir}.zip`;
  const outputDir = join(root, record.name);
  const zipPath = `${outputDir}.zip`;
  const published = () => {
    const identity = identityOf(outputDir);
    return identity !== undefined && identity.dev === record.dev && identity.ino === record.ino;
  };

  if (!published()) {
    const zipTaken = pathEntryExists(stagedZip) && pathEntryExists(zipPath);
    if (!pathEntryExists(outputDir) && !zipTaken) tryRenameSync(stagedDir, outputDir);
    if (!published()) return;
  }
  if (pathEntryExists(stagedZip) && !pathEntryExists(zipPath)) linkUnlessTakenSync(stagedZip, zipPath);
  // A linked archive keeps its staged name too, until the staging directory is removed.
  if (pathEntryExists(stagedZip) && !sameEntry(stagedZip, zipPath)) tryRenameSync(outputDir, stagedDir);
}

function readCommitRecord(stagingRoot: string): CommitRecord | undefined {
  try {
    const path = join(stagingRoot, COMMIT_RECORD);
    if (!lstatSync(path).isFile()) return undefined;
    const record = JSON.parse(readFileSync(path, "utf8")) as Partial<CommitRecord>;
    if (typeof record.name !== "string" || typeof record.dev !== "string" || typeof record.ino !== "string") return undefined;
    assertBundleName(record.name);
    return { name: record.name, dev: record.dev, ino: record.ino };
  } catch {
    return undefined;
  }
}

/**
 * Removes staging entries a process on this host left behind when it died mid-write, first
 * finishing any commit it had started.
 */
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
    const path = join(dir, name);
    const entry = lstatSync(path, { throwIfNoEntry: false });
    if (!entry || (!entry.isDirectory() && !entry.isFile())) continue;
    try {
      const record = entry.isDirectory() ? readCommitRecord(path) : undefined;
      if (record) finishCommit(dir, path, record);
      await rm(path, { recursive: true, force: true });
    } catch {
      // A dead writer's leftovers never fail a new write; a later sweep tries again.
    }
  }
}

async function renameUnlessTaken(from: string, to: string): Promise<boolean> {
  try {
    await rename(from, to);
    return true;
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === "EEXIST" || code === "ENOTEMPTY") return false;
    // Windows refuses a rename onto an existing directory with EPERM or EACCES instead.
    if ((code === "EPERM" || code === "EACCES") && pathEntryExists(to)) return false;
    throw error;
  }
}

/**
 * Publishes a staged archive under `to` unless that name is taken. A hard link fails with EEXIST
 * where a rename would silently replace an archive another writer just created; on a filesystem
 * without hard links, a rename after an existence check stands in.
 */
async function linkUnlessTaken(from: string, to: string): Promise<boolean> {
  try {
    await link(from, to);
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "EEXIST" || pathEntryExists(to)) return false;
  }
  await rename(from, to);
  return true;
}

/**
 * Moves a finished bundle from staging to its final paths, the directory and then its archive. A
 * record written first lets the exit handler or a later write finish the commit if this process
 * stops between the two moves. Returns undefined, with the bundle back in staging, when another
 * process took the name first.
 */
async function commitStaged(
  root: string,
  stagingRoot: string,
  name: string,
  taken: () => boolean,
  archived: boolean,
  signal: AbortSignal | undefined,
): Promise<CommittedBundle | undefined> {
  const stagedDir = join(stagingRoot, name);
  const outputDir = join(root, name);
  const zipPath = `${outputDir}.zip`;
  if (taken()) return undefined;

  const identity = await lstat(stagedDir, { bigint: true });
  const record: CommitRecord = { name, dev: String(identity.dev), ino: String(identity.ino) };
  const recordPath = join(stagingRoot, COMMIT_RECORD);
  await writeFile(recordPath, JSON.stringify(record), { mode: 0o600 });
  pendingCommits.set(stagingRoot, { root, record });
  try {
    // The last point an abort can stop the commit: once the directory moves, the archive follows it.
    signal?.throwIfAborted();
    if (await renameUnlessTaken(stagedDir, outputDir)) {
      if (!archived) return { outputDir, zipPath };
      try {
        if (await linkUnlessTaken(`${stagedDir}.zip`, zipPath)) return { outputDir, zipPath };
      } catch (error) {
        await rename(outputDir, stagedDir);
        throw error;
      }
      await rename(outputDir, stagedDir);
    }
    await rm(recordPath, { force: true });
    return undefined;
  } finally {
    pendingCommits.delete(stagingRoot);
  }
}

/**
 * Writes a bundle into a private staging directory under `root` and moves it into place only after
 * the writer finishes, so a failure, an abort, or a crash never leaves a partial bundle at the final
 * path. If another process takes the name before the commit, the writer runs again into a fresh
 * staged directory under the next free name, so files that record the bundle's location stay
 * accurate; keep the writer's state local to each run. The staging directory is removed on every
 * exit path; one left by a process that died is removed by the next write under the same root.
 * Directories created on the way to the root are removed again, while empty, when nothing commits.
 */
export async function writeBundleAtomically(
  options: AtomicBundleOptions,
  write: (staged: StagedBundle) => Promise<void>,
): Promise<CommittedBundle> {
  options.signal?.throwIfAborted();
  const created = claimNewDirectories(options.root);
  try {
    const root = options.createRoot ? options.createRoot(options.root) : options.root;
    return await stageAndCommit(root, options, write);
  } finally {
    releaseNewDirectories(created);
  }
}

async function stageAndCommit(
  root: string,
  options: AtomicBundleOptions,
  write: (staged: StagedBundle) => Promise<void>,
): Promise<CommittedBundle> {
  const { zip = false, signal, checkName, exhaustedMessage } = options;
  const candidates = options.names[Symbol.iterator]();
  const takenOnDisk = (name: string) =>
    pathEntryExists(join(root, name)) || (zip && pathEntryExists(join(root, `${name}.zip`)));
  const nextFreeName = (): string | undefined => {
    for (let step = candidates.next(); !step.done; step = candidates.next()) {
      assertBundleName(step.value);
      checkName?.(step.value);
      if (!claimedTargets.has(join(root, step.value)) && !takenOnDisk(step.value)) return step.value;
    }
    return undefined;
  };
  const exhausted = () => new Error(
    typeof exhaustedMessage === "function"
      ? exhaustedMessage(root)
      : exhaustedMessage ?? `Unable to allocate output directory under ${root}`,
  );

  await mkdir(root, { recursive: true, mode: 0o700 });
  await sweepAbandonedStaging(root);
  let name = nextFreeName();
  if (name === undefined) throw exhausted();
  let claimed = join(root, name);
  claimedTargets.add(claimed);

  const stagingRoot = join(root, stagingName());
  trackStaging(stagingRoot);
  try {
    // Recursive: a failed write in another process removes a root it created, even while this one starts.
    await mkdir(stagingRoot, { recursive: true, mode: 0o700 });
    for (;;) {
      const current = name;
      const staged: StagedBundle = {
        dir: join(stagingRoot, current),
        zipPath: join(stagingRoot, `${current}.zip`),
        target: { outputDir: claimed, zipPath: `${claimed}.zip` },
      };
      await mkdir(staged.dir, { mode: 0o700 });
      await chmod(staged.dir, 0o700);
      await write(staged);
      signal?.throwIfAborted();

      const archived = zip && pathEntryExists(staged.zipPath);
      if (!archived) await rm(staged.zipPath, { force: true });
      const committed = await commitStaged(root, stagingRoot, current, () => takenOnDisk(current), archived, signal);
      if (committed) return committed;

      await rm(staged.dir, { recursive: true, force: true });
      await rm(staged.zipPath, { force: true });
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
  options: { encoding?: BufferEncoding; mode?: number; signal?: AbortSignal } = {},
): Promise<void> {
  options.signal?.throwIfAborted();
  const dir = dirname(path);
  await sweepAbandonedStaging(dir);
  const temporary = join(dir, stagingName());
  trackStaging(temporary);
  try {
    await writeFile(temporary, data, { encoding: options.encoding, mode: options.mode, flag: "wx" });
    options.signal?.throwIfAborted();
    await rename(temporary, path);
  } finally {
    await releaseStaging(temporary);
  }
}
