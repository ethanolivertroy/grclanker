/**
 * One process per durable session.
 *
 * Pi Durable's SQLite storage expects a single process to own the session
 * database. The lock is an exclusive SQLite lock on a separate file in the
 * session directory, held until the process releases it or exits: the kernel
 * drops it on any exit, SIGKILL included, so a crash never leaves a stale
 * lock behind. It cannot live on the session database itself, because POSIX
 * locks belong to the process and closing any handle to that file, as the
 * storage adapter does, would drop them.
 */
import { DatabaseSync } from "node:sqlite";
import { DurableUserError } from "./errors.js";

const SQLITE_BUSY = 5;

export class DurableSessionLockedError extends DurableUserError {
  readonly lockPath: string;

  constructor(lockPath: string) {
    super(
      "Another grclanker durable process is using this session. Wait for it to finish or stop it, then run the command again.",
    );
    this.name = "DurableSessionLockedError";
    this.lockPath = lockPath;
  }
}

export interface DurableSessionLock {
  readonly path: string;
  /** Idempotent. */
  release(): void;
}

function isBusy(error: unknown): boolean {
  return typeof error === "object" && error !== null && (error as { errcode?: unknown }).errcode === SQLITE_BUSY;
}

/** Take the session lock without waiting; throws `DurableSessionLockedError` when another process holds it. */
export function acquireSessionLock(lockPath: string): DurableSessionLock {
  const database = new DatabaseSync(lockPath, { timeout: 0 });
  try {
    // In exclusive locking mode the first write takes the lock, and the connection keeps it until it closes.
    database.exec("PRAGMA locking_mode = EXCLUSIVE");
    database.exec("BEGIN EXCLUSIVE");
    database.exec("CREATE TABLE IF NOT EXISTS holder (id INTEGER PRIMARY KEY CHECK (id = 1), pid INTEGER NOT NULL)");
    database.prepare("INSERT OR REPLACE INTO holder (id, pid) VALUES (1, ?)").run(process.pid);
    database.exec("COMMIT");
  } catch (error) {
    database.close();
    if (isBusy(error)) throw new DurableSessionLockedError(lockPath);
    throw error;
  }

  let released = false;
  return {
    path: lockPath,
    release() {
      if (released) return;
      released = true;
      database.close();
    },
  };
}
