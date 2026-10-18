/**
 * Sensitive values from a persisted Flue conversation.
 *
 * `flue run --id` resumes a conversation whose earlier tool calls are already
 * stored. The new turn's event stream does not replay those calls, so the
 * redaction list has to be rebuilt from the conversation file before the
 * reply is returned.
 */
import { existsSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import { collectSensitiveValues } from "./redact.js";

const BATCHES_TABLE = "flue_conversation_stream_batches";
const CHUNKS_TABLE = "flue_conversation_stream_batch_chunks";

export interface PriorSensitiveValuesRequest {
  /** Filesystem path of the Flue SQLite database. `:memory:` has nothing to read. */
  dbPath: string;
  /** Canonical stream path, `agents/<agent>/<instance>`. */
  streamPath: string;
  /** Tool name to JSON Schema parameters, so schema-marked fields are included. */
  schemas?: ReadonlyMap<string, unknown>;
}

/** Stream path Flue uses for one agent instance (`agentStreamPath`). */
export function flueConversationStreamPath(agentName: string, instanceId: string): string {
  return `agents/${agentName}/${instanceId}`;
}

/**
 * Sensitive scalars from canonical `assistant_tool_call` records. `arguments`
 * is the object Flue stored; a JSON string is parsed first.
 */
export function sensitiveValuesFromConversationRecords(
  records: readonly unknown[],
  schemas?: ReadonlyMap<string, unknown>,
): string[] {
  const values: string[] = [];
  for (const record of records) {
    if (!isRecord(record) || record.type !== "assistant_tool_call") continue;
    const toolName = typeof record.name === "string" ? record.name : undefined;
    values.push(...collectSensitiveValues(toolCallArguments(record.arguments), toolName ? schemas?.get(toolName) : undefined));
  }
  return values;
}

/**
 * Read one conversation's earlier tool inputs and return the sensitive values
 * they carried. A missing database or a database that has not created Flue's
 * batch table yet means there is no prior turn. A spill sentinel whose chunks
 * are missing throws, so a half-read history cannot skip a credential.
 */
export function readPriorSensitiveValues(request: PriorSensitiveValuesRequest): string[] {
  if (request.dbPath === ":memory:" || !existsSync(request.dbPath)) return [];

  const db = new DatabaseSync(request.dbPath, { readOnly: true });
  try {
    let batches: Record<string, unknown>[];
    try {
      batches = db.prepare(`SELECT seq, data FROM ${BATCHES_TABLE} WHERE path = ? ORDER BY seq`).all(request.streamPath);
    } catch (error) {
      if (isMissingTable(error, BATCHES_TABLE)) return [];
      throw error;
    }

    const values: string[] = [];
    for (const batch of batches) {
      const seq = readSeq(batch.seq);
      const stored = readText(batch.data);
      const serialized = materializeBatch(db, request.streamPath, seq, stored);
      let records: unknown;
      try {
        records = JSON.parse(serialized) as unknown;
      } catch {
        throw new Error(`Flue conversation batch ${seq} on ${request.streamPath} is not JSON.`);
      }
      if (!Array.isArray(records)) {
        throw new Error(`Flue conversation batch ${seq} on ${request.streamPath} is not a record list.`);
      }
      values.push(...sensitiveValuesFromConversationRecords(records, request.schemas));
    }
    return values;
  } finally {
    db.close();
  }
}

function materializeBatch(db: DatabaseSync, streamPath: string, seq: number, stored: string): string {
  // Real batch data is a JSON array and starts with `[`. A `{` value is Flue's
  // spill sentinel `{"$flueChunkCount":N}` (see materializeBatchData).
  if (!stored.startsWith("{")) return stored;

  let count: unknown;
  try {
    count = (JSON.parse(stored) as { $flueChunkCount?: unknown }).$flueChunkCount;
  } catch {
    throw new Error(`Flue conversation batch ${seq} on ${streamPath} has a malformed spill sentinel.`);
  }
  if (typeof count !== "number" || !Number.isSafeInteger(count) || count <= 0) {
    throw new Error(`Flue conversation batch ${seq} on ${streamPath} has a malformed spill sentinel.`);
  }

  const chunks = db
    .prepare(`SELECT chunk_index, data FROM ${CHUNKS_TABLE} WHERE path = ? AND seq = ? ORDER BY chunk_index`)
    .all(streamPath, seq);
  if (chunks.length !== count) {
    throw new Error(`Flue conversation batch ${seq} on ${streamPath} is missing spilled chunks.`);
  }
  const parts: string[] = [];
  for (const [index, chunk] of chunks.entries()) {
    if (readSeq(chunk.chunk_index) !== index) {
      throw new Error(`Flue conversation batch ${seq} on ${streamPath} is missing spilled chunks.`);
    }
    parts.push(readText(chunk.data));
  }
  return parts.join("");
}

function toolCallArguments(value: unknown): unknown {
  if (typeof value !== "string") return value;
  try {
    return JSON.parse(value) as unknown;
  } catch {
    return undefined;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function readSeq(value: unknown): number {
  if (typeof value === "number" && Number.isSafeInteger(value)) return value;
  if (typeof value === "bigint" && value >= 0n && value <= BigInt(Number.MAX_SAFE_INTEGER)) return Number(value);
  throw new Error("Flue conversation batch sequence is not an integer.");
}

function readText(value: unknown): string {
  if (typeof value !== "string") throw new Error("Flue conversation batch data is not text.");
  return value;
}

function isMissingTable(error: unknown, table: string): boolean {
  return error instanceof Error && error.message.includes(`no such table: ${table}`);
}
