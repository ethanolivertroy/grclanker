/**
 * Collection-status markers and null rendering (rule 5 partial-inventory demotion, rule 10, coordinator
 * addenda 3 and 5, the rule 1 corollary).
 *
 * A denied, errored, or never-requested inventory must never look like an empty one. Bundle files and
 * snapshot summaries write a `NotCollectedMarker` in place of the dataset, counts and flags derived from
 * an unread inventory render as null (never 0, [], {}, or false), a value that asserts absence needs a
 * complete read, and lists that name principals as holding or lacking a property are withheld unless
 * every input was read to completion. Distilled from the ServiceNow reference implementation (#62), the
 * Qualys `Collected` and `countIfReadable` helpers (#32), and the Webex `countIfReadable` (#48). The
 * module has no dependencies so integrations can adopt it one helper at a time.
 */

type JsonRecord = Record<string, unknown>;

/**
 * One inventory as a collector returns it. Exactly one state holds (see `datasetState`): complete,
 * truncated (read, but the walk stopped before the end), unreadable (`error` set), or not requested
 * (`notRequested` set: the request was never issued because its parent was unreadable or left nothing
 * to query). `items` is a placeholder `[]` in the last two states and must be rendered through
 * `coreDataValue`, never directly.
 */
export interface Dataset<T> {
  items: T[];
  /** True only when every item was read: no cap, no error, no skipped request. */
  complete: boolean;
  /** True when the walk stopped before exhausting the listing (limit, page cap, time budget, stalled cursor). */
  truncated: boolean;
  /** The total the service reported, or null when it reported none. */
  total: number | null;
  /** The HTTP status observed on the request that produced or denied the dataset; null when none was answered. */
  status: number | null;
  /** The request path issued; null when no request was made. */
  endpoint: string | null;
  /** The scrubbed error text when the dataset is unreadable; null when it was read. */
  error: string | null;
  /** The reason no request was issued, already phrased as `Not requested: ...`. */
  notRequested?: string;
}

export type DatasetState = "complete" | "truncated" | "unreadable" | "not_requested";

/**
 * Written to core_data and snapshot summaries in place of a dataset that was denied, errored, or never
 * requested, so a consumer cannot mistake a denial for an empty inventory. A readable dataset with no
 * items keeps its list shape (`[]`).
 */
export interface NotCollectedMarker {
  collected: false;
  status: number | null;
  endpoint: string | null;
  error: string;
}

/** Collection metadata for one dataset; every count and flag is null unless the read was answered. */
export interface DatasetStatus {
  state: DatasetState;
  count: number | null;
  total: number | null;
  truncated: boolean | null;
  status: number | null;
  endpoint: string | null;
  error: string | null;
}

export interface ReadDatasetDetails {
  truncated?: boolean;
  total?: number | null;
  status?: number | null;
  endpoint?: string | null;
}

export interface UnreadDatasetDetails {
  status?: number | null;
  endpoint?: string | null;
}

const NOT_REQUESTED_PREFIX = "Not requested: ";

/** A dataset that was read: complete unless `truncated` is set. */
export function readDataset<T>(items: T[], details: ReadDatasetDetails = {}): Dataset<T> {
  const truncated = details.truncated ?? false;
  return {
    items,
    complete: !truncated,
    truncated,
    total: details.total ?? null,
    status: details.status ?? null,
    endpoint: details.endpoint ?? null,
    error: null,
  };
}

/** A dataset whose request was denied or failed; `error` is the scrubbed error text. */
export function unreadableDataset<T = never>(error: string, details: UnreadDatasetDetails = {}): Dataset<T> {
  return { items: [], complete: false, truncated: false, total: null, status: details.status ?? null, endpoint: details.endpoint ?? null, error };
}

/**
 * A dataset whose request was never issued because `parentLabel` (the inventory it depends on) was not
 * readable, or because that inventory left nothing to query.
 */
export function notRequestedDataset<T = never>(parentLabel: string, parentError?: string | null): Dataset<T> {
  return { items: [], complete: false, truncated: false, total: null, status: null, endpoint: null, error: null, notRequested: notRequestedReason(parentLabel, parentError) };
}

/** Which of the four states a dataset is in. */
export function datasetState(dataset: Dataset<unknown>): DatasetState {
  if (dataset.notRequested !== undefined) return "not_requested";
  if (dataset.error !== null) return "unreadable";
  if (dataset.truncated || !dataset.complete) return "truncated";
  return "complete";
}

/** True when a request was answered with items (possibly none): complete or truncated. */
export function isReadable(dataset: Dataset<unknown>): boolean {
  const state = datasetState(dataset);
  return state === "complete" || state === "truncated";
}

/** True when every item was read. */
export function isComplete(dataset: Dataset<unknown>): boolean {
  return datasetState(dataset) === "complete";
}

function notRequestedReason(parentLabel: string, parentError?: string | null): string {
  return `${NOT_REQUESTED_PREFIX}${parentLabel} was not readable${parentError ? ` (${parentError})` : ""}`;
}

/** The marker for a dataset that was denied or failed, naming the status and endpoint that were observed. */
export function notCollected(error: string, status: number | null = null, endpoint: string | null = null): NotCollectedMarker {
  return { collected: false, status, endpoint, error };
}

/** The marker for a child dataset whose parent was unreadable: `Not requested: <parent> was not readable (<parent error>)`, with no status or endpoint because no request was made. */
export function notRequested(parentLabel: string, parentError?: string | null): NotCollectedMarker {
  return { collected: false, status: null, endpoint: null, error: notRequestedReason(parentLabel, parentError) };
}

/** The marker a dataset renders as when it was not read, or undefined when it was. */
export function datasetMarker(dataset: Dataset<unknown>): NotCollectedMarker | undefined {
  const state = datasetState(dataset);
  switch (state) {
    case "complete":
    case "truncated":
      return undefined;
    case "unreadable":
      return notCollected(dataset.error ?? "unreadable", dataset.status, dataset.endpoint);
    case "not_requested":
      return { collected: false, status: null, endpoint: null, error: dataset.notRequested ?? `${NOT_REQUESTED_PREFIX}parent inventory was not readable` };
    default: {
      const unhandled: never = state;
      throw new Error(`Unhandled dataset state ${String(unhandled)}`);
    }
  }
}

/** What core_data records for a dataset: its items when it was read (`[]` only when readable and empty), the marker otherwise. */
export function coreDataValue<T>(dataset: Dataset<T>): T[] | NotCollectedMarker {
  return datasetMarker(dataset) ?? dataset.items;
}

/** The collection metadata of one dataset; counts, total, and the truncated flag are null unless the read was answered. */
export function datasetStatus(dataset: Dataset<unknown>): DatasetStatus {
  const state = datasetState(dataset);
  const readable = state === "complete" || state === "truncated";
  return {
    state,
    count: readable ? dataset.items.length : null,
    total: readable ? dataset.total : null,
    truncated: readable ? dataset.truncated : null,
    status: dataset.status,
    endpoint: dataset.endpoint,
    error: state === "not_requested" ? dataset.notRequested ?? null : dataset.error,
  };
}

/** True for the values that claim nothing exists: 0, an empty array, an empty object. */
export function isAbsenceValue(value: unknown): boolean {
  if (value === 0) return true;
  if (Array.isArray(value)) return value.length === 0;
  if (value !== null && typeof value === "object") return Object.keys(value).length === 0;
  return false;
}

/** A value observed from one dataset: itself when the dataset was read, null when it was not. */
export function ifRead<V>(dataset: Dataset<unknown>, value: V): V | null {
  return isReadable(dataset) ? value : null;
}

/** A value that needs every item of one dataset: itself when the dataset is complete, null otherwise. */
export function ifComplete<V>(value: V, ...datasets: Dataset<unknown>[]): V | null {
  return datasets.every(isComplete) ? value : null;
}

/**
 * A count, list, or map derived from one or more datasets. It renders null when any source was not
 * read, and null when a source is partial and the value would assert absence (0, [], {}), because a
 * partly read inventory cannot prove that nothing exists.
 */
export function derived<V>(value: V, ...datasets: Dataset<unknown>[]): V | null {
  if (!datasets.every(isReadable)) return null;
  if (!datasets.every(isComplete) && isAbsenceValue(value)) return null;
  return value;
}

/** A boolean observation: true is a positive sighting from any read; false is an absence claim that needs complete reads. */
export function derivedFlag(value: boolean, ...datasets: Dataset<unknown>[]): boolean | null {
  if (!datasets.every(isReadable)) return null;
  if (!value && !datasets.every(isComplete)) return null;
  return value;
}

/** A count of an inventory, or of records inside it, is unknown (null, never 0) unless every source inventory was read. */
export function countIfReadable(count: number, ...datasets: Dataset<unknown>[]): number | null {
  return datasets.every(isReadable) ? count : null;
}

/** The rule 10 progress phrase: `seen 40 of 120` when the total is known, `40 seen, total unknown` when it is not. */
export function seenVersusTotal(seen: number, total: number | null | undefined): string {
  return total === null || total === undefined ? `${seen} seen, total unknown` : `seen ${seen} of ${total}`;
}

/** Under a partial read, evidence values that assert absence (0, [], {}) render null because the missing rows could hold the item. */
export function withoutAbsenceClaims(evidence: JsonRecord | undefined, complete: boolean): JsonRecord {
  if (!evidence) return {};
  if (complete) return evidence;
  return Object.fromEntries(Object.entries(evidence).map(([key, value]) => [key, isAbsenceValue(value) ? null : value]));
}

/**
 * The named-principal rule (addendum 3): lists that name users, accounts, or integrations as holding or
 * lacking a property, and counts of such principals, are emitted only when every input was read to
 * completion. Under a partial or denied read each renders null and `principals_withheld` names the
 * inventories that were not fully read; when complete, `principals_withheld` is null.
 */
export function gatedPrincipals(principals: Record<string, unknown[] | number> | undefined, complete: boolean, partialNotes: readonly string[]): JsonRecord {
  if (!principals) return {};
  const gated: JsonRecord = {};
  for (const [key, value] of Object.entries(principals)) gated[key] = complete ? value : null;
  gated.principals_withheld = complete ? null : partialNotes.join("; ");
  return gated;
}
