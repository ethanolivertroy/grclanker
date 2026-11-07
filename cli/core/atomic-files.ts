/** Atomic file publication and recoverable groups of file replacements. */
import { randomUUID } from "node:crypto";
import { chmodSync, closeSync, copyFileSync, existsSync, fsyncSync, linkSync, lstatSync, mkdirSync, mkdtempSync, openSync, readFileSync, realpathSync, renameSync, rmSync, statSync, unlinkSync, writeFileSync } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { createRequire } from "node:module";
import type { DatabaseSync as SqliteDatabase } from "node:sqlite";


const require = createRequire(import.meta.url);
const activePublications = new Set<string>();

function publicationKey(path: string): string {
  let parent = dirname(resolve(path));
  const suffix = [basename(path)];
  while (!existsSync(parent)) {
    suffix.unshift(basename(parent));
    parent = dirname(parent);
  }
  return join(realpathSync(parent), ...suffix);
}

/** A permanent adjacent lock gives every process the same filesystem identity. */
function acquirePublicationLock(journalPath: string): () => void {
  const key = publicationKey(journalPath);
  if (activePublications.has(key)) throw new Error(`Publication is in progress: ${key}`);
  mkdirSync(dirname(key), { recursive: true });
  const path = join(dirname(key), `.${basename(key).replace(/^\./, "")}.lock.sqlite`);
  try {
    closeSync(openSync(path, "wx", 0o600));
  } catch (error) {
    if (!(error !== null && typeof error === "object" && (error as { code?: unknown }).code === "EEXIST")) throw error;
  }
  const existing = lstatSync(path);
  const uid = process.getuid?.();
  if (!existing.isFile() || existing.isSymbolicLink() || existing.nlink !== 1 ||
      (uid !== undefined && (existing.uid !== uid || (existing.mode & 0o077) !== 0))) {
    throw new Error("Unsafe publication lock file.");
  }
  // Loading SQLite lazily keeps ordinary core imports free of host/runtime work.
  const { DatabaseSync } = require("node:sqlite") as typeof import("node:sqlite");
  const database: SqliteDatabase = new DatabaseSync(path, { timeout: 0 });
  try {
    if (uid !== undefined) chmodSync(path, 0o600);
    database.exec("PRAGMA locking_mode = EXCLUSIVE");
    database.exec("BEGIN EXCLUSIVE");
    database.exec("CREATE TABLE IF NOT EXISTS holder (id INTEGER PRIMARY KEY CHECK (id = 1), pid INTEGER NOT NULL)");
    database.prepare("INSERT OR REPLACE INTO holder (id, pid) VALUES (1, ?)").run(process.pid);
    database.exec("COMMIT");
  } catch (error) {
    database.close();
    if (error !== null && typeof error === "object" && (error as { errcode?: unknown }).errcode === 5) {
      throw new Error(`Publication is in progress: ${key}`);
    }
    throw error;
  }
  activePublications.add(key);
  let released = false;
  // Never unlink this DB: a stable inode prevents two owners after a race.
  return () => {
    if (released) return;
    released = true;
    try { database.close(); } finally { activePublications.delete(key); }
  };
}

export interface AtomicFileOptions {
  encoding?: BufferEncoding;
  mode?: number;
}

function writeDurably(path: string, data: string | Uint8Array, options: AtomicFileOptions = {}): void {
  const fd = openSync(path, "wx", options.mode ?? 0o600);
  try {
    writeFileSync(fd, data, { encoding: options.encoding ?? "utf8" });
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

/** Readers see the previous complete file or the new complete file. */
export function writeFileAtomicallySync(path: string, data: string | Uint8Array, options: AtomicFileOptions = {}): void {
  if (existsSync(path) && lstatSync(path).isSymbolicLink()) path = realpathSync(path);
  mkdirSync(dirname(path), { recursive: true });
  const temporary = join(dirname(path), `.${basename(path)}.${randomUUID()}.tmp`);
  const mode = options.mode ?? (existsSync(path) ? statSync(path).mode & 0o777 : 0o666 & ~process.umask());
  try {
    writeDurably(temporary, data, { ...options, mode });
    renameSync(temporary, path);
  } finally {
    rmSync(temporary, { force: true });
  }
}

export async function writeFileAtomically(path: string, data: string | Uint8Array, options: AtomicFileOptions = {}): Promise<void> {
  writeFileAtomicallySync(path, data, options);
}

export interface FileReplacement {
  path: string;
  /** null removes the old file at commit. */
  data: string | Uint8Array | null;
  mode?: number;
}

export interface FileTransactionOptions {
  journalPath: string;
  /** Fault injection at a publication boundary; production callers omit this. */
  beforeCommit?: (index: number, path: string) => void;
}

interface JournalEntry {
  path: string;
  previous: string | null;
  next: string | null;
}

interface FileJournal {
  version: 1;
  pid: number;
  phase: "staging" | "prepared" | "committed";
  staging: string;
  entries: JournalEntry[];
}

function entryExists(path: string): boolean {
  return lstatSync(path, { throwIfNoEntry: false }) !== undefined;
}

/** Publish a complete initial journal exclusively; readers never encounter partial JSON. */
function reserveJournal(path: string, journal: unknown, staging: string): void {
  const seed = join(staging, ".journal");
  writeDurably(seed, JSON.stringify(journal), { mode: 0o600 });
  try {
    linkSync(seed, path);
  } finally {
    rmSync(seed, { force: true });
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isJournalEntry(value: unknown): value is JournalEntry {
  return isRecord(value) && typeof value.path === "string" &&
    (value.previous === null || typeof value.previous === "string") &&
    (value.next === null || typeof value.next === "string");
}

function readJournal(path: string): FileJournal {
  const value: unknown = JSON.parse(readFileSync(path, "utf8"));
  if (!isRecord(value) || value.version !== 1 || typeof value.pid !== "number" || !Number.isInteger(value.pid) || value.pid <= 0 ||
      typeof value.staging !== "string" || !["staging", "prepared", "committed"].includes(String(value.phase)) ||
      !Array.isArray(value.entries) || !value.entries.every(isJournalEntry)) {
    throw new Error(`Invalid file transaction journal: ${path}`);
  }
  return { version: 1, pid: value.pid, staging: value.staging, phase: value.phase as FileJournal["phase"], entries: value.entries };
}

function rollback(journal: FileJournal): void {
  for (const entry of [...journal.entries].reverse()) {
    if (entry.previous === null) {
      rmSync(entry.path, { force: true });
    } else {
      writeFileAtomicallySync(entry.path, readFileSync(entry.previous), { mode: statSync(entry.previous).mode & 0o777 });
    }
  }
}

function finishJournal(path: string, journal: FileJournal): void {
  // Remove the durable pointer first: a crash during cleanup must not expose a
  // journal whose backups have already been removed.
  unlinkSync(path);
  rmSync(journal.staging, { recursive: true, force: true });
}

/** Roll back a crashed writer before reading any member of its file set. */
function recoverFileTransactionUnlocked(journalPath: string): void {
  if (!existsSync(journalPath)) return;
  const journal = readJournal(journalPath);
  if (journal.phase === "prepared") rollback(journal);
  finishJournal(journalPath, journal);
}

export function recoverFileTransactionSync(journalPath: string): void {
  if (!existsSync(journalPath)) return;
  const release = acquirePublicationLock(journalPath);
  try {
    recoverFileTransactionUnlocked(journalPath);
  } finally {
    release();
  }
}

export async function recoverFileTransaction(journalPath: string): Promise<void> {
  recoverFileTransactionSync(journalPath);
}

/**
 * Stage every file before publishing any. A durable journal retains originals
 * until the whole set commits; caught failures roll back immediately, and a
 * crashed writer is rolled back by the next journal-aware reader/writer.
 */
function commitFileTransactionUnlocked(replacements: readonly FileReplacement[], options: FileTransactionOptions): void {
  const journalPath = resolve(options.journalPath);
  mkdirSync(dirname(journalPath), { recursive: true });
  recoverFileTransactionUnlocked(journalPath);
  const paths = replacements.map((entry) => existsSync(entry.path) && lstatSync(entry.path).isSymbolicLink() ? realpathSync(entry.path) : resolve(entry.path));
  if (new Set(paths).size !== paths.length) throw new Error("A file transaction cannot replace the same path twice.");
  const staging = mkdtempSync(join(dirname(journalPath), ".file-transaction-"));
  const journal: FileJournal = { version: 1, pid: process.pid, phase: "staging", staging, entries: [] };
  let published = false;
  try {
    reserveJournal(journalPath, journal, staging);
    published = true;
    for (const [index, replacement] of replacements.entries()) {
      const path = paths[index]!;
      mkdirSync(dirname(path), { recursive: true });
      const previous = existsSync(path) ? join(staging, `${index}.previous`) : null;
      if (previous !== null) copyFileSync(path, previous);
      const next = replacement.data === null ? null : join(staging, `${index}.next`);
      if (next !== null) {
        const mode = replacement.mode ?? (previous !== null ? statSync(path).mode & 0o777 : 0o666 & ~process.umask());
        writeDurably(next, replacement.data!, { mode });
      }
      journal.entries.push({ path, previous, next });
    }
    // Backups become recovery material only once every original is staged.
    journal.phase = "prepared";
    writeFileAtomicallySync(journalPath, JSON.stringify(journal), { mode: 0o600 });
    for (const [index, entry] of journal.entries.entries()) {
      options.beforeCommit?.(index, entry.path);
      if (entry.next === null) rmSync(entry.path, { force: true });
      else renameSync(entry.next, entry.path);
    }
    journal.phase = "committed";
    writeFileAtomicallySync(journalPath, JSON.stringify(journal), { mode: 0o600 });
  } catch (error) {
    if (published) {
      try {
        if (journal.phase !== "staging") rollback(journal);
        finishJournal(journalPath, journal);
      } catch (recoveryError) {
        throw new AggregateError([error, recoveryError], `File transaction failed; recovery journal retained at ${journalPath}`);
      }
    } else {
      rmSync(staging, { recursive: true, force: true });
    }
    throw error;
  }
  finishJournal(journalPath, journal);
}

export function commitFileTransactionSync(replacements: readonly FileReplacement[], options: FileTransactionOptions): void {
  const release = acquirePublicationLock(options.journalPath);
  try {
    commitFileTransactionUnlocked(replacements, options);
  } finally {
    release();
  }
}

export async function commitFileTransaction(replacements: readonly FileReplacement[], options: FileTransactionOptions): Promise<void> {
  commitFileTransactionSync(replacements, options);
}

interface DirectoryJournal {
  pid: number;
  destination: string;
  staging: string;
  backup: string;
  existed: boolean;
  phase: "staging" | "prepared" | "committed";
  identity: { dev: string; ino: string };
}

function directoryIdentity(path: string): { dev: string; ino: string } {
  const entry = lstatSync(path, { bigint: true });
  if (!entry.isDirectory() || entry.isSymbolicLink()) throw new Error(`Snapshot staging path is not a directory: ${path}`);
  return { dev: String(entry.dev), ino: String(entry.ino) };
}

function ownsDestination(journal: DirectoryJournal): boolean {
  const entry = lstatSync(journal.destination, { bigint: true, throwIfNoEntry: false });
  return entry !== undefined && String(entry.dev) === journal.identity.dev && String(entry.ino) === journal.identity.ino;
}

function finishDirectoryJournal(path: string, journal: DirectoryJournal): void {
  // Remove the pointer before its recovery material, just as for file sets.
  unlinkSync(path);
  rmSync(journal.staging, { recursive: true, force: true });
  rmSync(journal.backup, { recursive: true, force: true });
}

function recoverDirectoryJournal(journalPath: string, destination: string): void {
  if (!existsSync(journalPath)) return;
  const value: unknown = JSON.parse(readFileSync(journalPath, "utf8"));
  if (!isRecord(value) || typeof value.pid !== "number" || !Number.isInteger(value.pid) || value.pid <= 0 || value.destination !== destination ||
      typeof value.staging !== "string" || dirname(value.staging) !== dirname(destination) || !basename(value.staging).startsWith(`.${basename(destination)}.stage-`) ||
      value.backup !== `${value.staging}.previous` || typeof value.existed !== "boolean" ||
      !["staging", "prepared", "committed"].includes(String(value.phase)) ||
      !isRecord(value.identity) || typeof value.identity.dev !== "string" || typeof value.identity.ino !== "string") {
    throw new Error(`Invalid directory publication journal: ${journalPath}`);
  }
  const journal: DirectoryJournal = { pid: value.pid, destination, staging: value.staging, backup: value.backup,
    existed: value.existed, phase: value.phase as DirectoryJournal["phase"], identity: { dev: value.identity.dev, ino: value.identity.ino } };
  if (journal.phase === "prepared") restoreDirectory(journal);
  finishDirectoryJournal(journalPath, journal);
}

function restoreDirectory(journal: DirectoryJournal): void {
  if (entryExists(journal.backup)) {
    if (entryExists(journal.destination)) {
      if (!ownsDestination(journal)) throw new Error(`Snapshot destination changed outside its publication: ${journal.destination}`);
      rmSync(journal.destination, { recursive: true, force: true });
    }
    renameSync(journal.backup, journal.destination);
  } else if (!journal.existed && ownsDestination(journal)) {
    // An external writer may have installed another tree despite the lock.
    // Its data is never ours to remove.
    rmSync(journal.destination, { recursive: true, force: true });
  }
}

/** Recover an interrupted directory publication before inspecting its previous output. */
export async function recoverDirectorySnapshot(target: string): Promise<void> {
  const destination = resolve(target);
  const journalPath = join(dirname(destination), `.${basename(destination)}.snapshot-transaction.json`);
  if (!existsSync(journalPath)) return;
  const release = acquirePublicationLock(journalPath);
  try {
    recoverDirectoryJournal(journalPath, destination);
  } finally {
    release();
  }
}

async function replaceDirectoryUnlocked(
  destination: string,
  journalPath: string,
  build: (staging: string) => Promise<void>,
  options: { beforePublish?: () => void; beforeInstall?: () => void },
): Promise<void> {
  mkdirSync(dirname(destination), { recursive: true });
  recoverDirectoryJournal(journalPath, destination);
  const staging = mkdtempSync(join(dirname(destination), `.${basename(destination)}.stage-`));
  const journal: DirectoryJournal = {
    pid: process.pid, destination, staging, backup: `${staging}.previous`, existed: false,
    phase: "staging", identity: directoryIdentity(staging),
  };
  let reserved = false;
  try {
    // Reservation precedes every asynchronous builder: another writer or
    // recovery reader cannot inspect or replace this snapshot until release.
    reserveJournal(journalPath, journal, staging);
    reserved = true;
    await build(staging);
    options.beforePublish?.();
    journal.existed = entryExists(destination);
    journal.identity = directoryIdentity(staging);
    journal.phase = "prepared";
    writeFileAtomicallySync(journalPath, JSON.stringify(journal), { mode: 0o600 });
    if (journal.existed) renameSync(destination, journal.backup);
    options.beforeInstall?.();
    renameSync(staging, destination);
    journal.phase = "committed";
    writeFileAtomicallySync(journalPath, JSON.stringify(journal), { mode: 0o600 });
  } catch (error) {
    if (reserved) {
      try {
        if (journal.phase !== "staging") restoreDirectory(journal);
        finishDirectoryJournal(journalPath, journal);
      } catch (recoveryError) {
        throw new AggregateError([error, recoveryError], `Directory publication failed; recovery journal retained at ${journalPath}`);
      }
    } else {
      rmSync(staging, { recursive: true, force: true });
    }
    throw error;
  }
  finishDirectoryJournal(journalPath, journal);
}

/** Publish a complete staged tree with exclusive ownership and crash recovery. */
export async function replaceDirectoryAtomically(
  target: string,
  build: (staging: string) => Promise<void>,
  options: { beforePublish?: () => void; beforeInstall?: () => void } = {},
): Promise<void> {
  const destination = resolve(target);
  const journalPath = join(dirname(destination), `.${basename(destination)}.snapshot-transaction.json`);
  const release = acquirePublicationLock(journalPath);
  try {
    await replaceDirectoryUnlocked(destination, journalPath, build, options);
  } finally {
    release();
  }
}
