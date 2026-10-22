/**
 * The session database, `session.sqlite`.
 *
 * Pi Durable migrates an older session forward when it opens it. It refuses a
 * session written by a newer release only after it has opened the file for
 * writing and set its journal mode, and then with a bare error. grclanker
 * reads the schema version first, over a read-only connection, so a session
 * this release cannot read is refused with a message before Pi Durable
 * touches it.
 */
import { existsSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import { CURRENT_SQLITE_SCHEMA_VERSION, type SqliteStorage } from "@earendil-works/pi-durable/storage/sqlite";
import { openNodeSqliteStorage } from "@earendil-works/pi-durable/storage/sqlite/node";
import { DurableUserError } from "./errors.js";
import type { DurableSessionPaths } from "./session.js";

const SQLITE_NOTADB = 26;
/** Pi Durable's own busy timeout, for a reader that meets a writer outside grclanker. */
const BUSY_TIMEOUT_MS = 5_000;

export class DurableSessionVersionError extends DurableUserError {
  readonly version: number;
  readonly supportedVersion: number;

  constructor(sessionId: string, version: number, supportedVersion: number) {
    super(
      `Session "${sessionId}" was written by a newer grclanker: its database is at schema version ${version}, and this grclanker reads up to version ${supportedVersion}. Open it with the newer grclanker, or start a new session. The session was not changed.`,
    );
    this.name = "DurableSessionVersionError";
    this.version = version;
    this.supportedVersion = supportedVersion;
  }
}

function sqliteErrorCode(error: unknown): unknown {
  return typeof error === "object" && error !== null ? (error as { errcode?: unknown }).errcode : undefined;
}

/** The Pi Durable schema version of an existing database, or `undefined` when Pi Durable has not set one up in it. */
function readSessionSchemaVersion(path: string): number | undefined {
  const database = new DatabaseSync(path, { readOnly: true, timeout: BUSY_TIMEOUT_MS });
  try {
    const table = database.prepare("SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'durable_schema'").get();
    if (table === undefined) return undefined;
    const row = database.prepare("SELECT version FROM durable_schema WHERE singleton = 1").get();
    return typeof row?.version === "number" ? row.version : undefined;
  } finally {
    database.close();
  }
}

/** Open the session's Pi Durable storage. A session from a newer release, or a file that is not a database, throws a `DurableUserError` and is left as it was. */
export async function openDurableSessionStorage(session: DurableSessionPaths): Promise<SqliteStorage> {
  if (existsSync(session.database)) {
    let version: number | undefined;
    try {
      version = readSessionSchemaVersion(session.database);
    } catch (error) {
      if (sqliteErrorCode(error) !== SQLITE_NOTADB) throw error;
      throw new DurableUserError(
        `Session "${session.id}" cannot be opened: ${session.database} is not a SQLite database. Move it aside to start the session over, or use another --session.`,
      );
    }
    if (version !== undefined && version > CURRENT_SQLITE_SCHEMA_VERSION) {
      throw new DurableSessionVersionError(session.id, version, CURRENT_SQLITE_SCHEMA_VERSION);
    }
  }
  return openNodeSqliteStorage(session.database);
}
