/**
 * Durable session directories: `~/.grclanker/durable/sessions/<id>/`, holding
 * the Pi Durable database (`session.sqlite`) and the process lock
 * (`session.lock`).
 */
import { randomBytes } from "node:crypto";
import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { getGrclankerHome } from "../config/paths.js";
import { DurableUsageError } from "./errors.js";

/** One path segment: no separators, and it cannot be `.` or `..`. */
const SESSION_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

export interface DurableSessionPaths {
  id: string;
  dir: string;
  database: string;
  lock: string;
}

export function durableSessionsDir(home = getGrclankerHome()): string {
  return resolve(home, "durable", "sessions");
}

export function isValidDurableSessionId(id: string): boolean {
  return SESSION_ID_PATTERN.test(id);
}

export function resolveDurableSession(id: string, home = getGrclankerHome()): DurableSessionPaths {
  if (!isValidDurableSessionId(id)) {
    throw new DurableUsageError(
      `Invalid session id "${id}": use up to 64 letters, digits, dots, dashes, or underscores, starting with a letter or digit.`,
    );
  }
  const dir = resolve(durableSessionsDir(home), id);
  return { id, dir, database: resolve(dir, "session.sqlite"), lock: resolve(dir, "session.lock") };
}

/** A sortable id such as `20261019-143012-a1b2c3`. */
export function newDurableSessionId(now = new Date()): string {
  const stamp = now.toISOString().replace(/[-:]/g, "").replace("T", "-").slice(0, 15);
  return `${stamp}-${randomBytes(3).toString("hex")}`;
}

export function durableSessionExists(session: DurableSessionPaths): boolean {
  return existsSync(session.database);
}
