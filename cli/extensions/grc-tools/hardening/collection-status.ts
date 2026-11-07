/**
 * Explicit collection outcomes and evidence requirements.
 * Unavailable/skipped reads carry their cause and dependency, never placeholder records. Consumers
 * choose observedValue for a sighting or populationValue for claims about the entire inventory.
 */

interface CollectionIdentity {
  /** Internal dependency identity; display labels and redaction never change it. */
  readonly key: symbol;
  readonly label: string;
  readonly status: number | null;
  readonly endpoint: string | null;
  readonly dependency?: symbol;
}

export interface CollectionDetails {
  key?: symbol;
  status?: number | null;
  endpoint?: string | null;
  dependency?: symbol;
}

export type ReadCollection<T> = CollectionIdentity & (
  | { readonly state: "complete"; readonly value: T }
  | { readonly state: "partial"; readonly value: T; readonly reason: string }
);

export type CollectionOutcome<T> = ReadCollection<T> | CollectionIdentity & (
  | { readonly state: "unavailable"; readonly error: string }
  | { readonly state: "skipped"; readonly reason: string; readonly dependency?: symbol }
);

export type CollectionState = CollectionOutcome<unknown>["state"];

function collectionIdentity(label: string, details: CollectionDetails = {}): CollectionIdentity {
  return { key: details.key ?? Symbol(label), label, status: details.status ?? null, endpoint: details.endpoint ?? null, ...(details.dependency === undefined ? {} : { dependency: details.dependency }) };
}

export function completeCollection<T>(label: string, value: T, details?: CollectionDetails): CollectionOutcome<T> {
  return { ...collectionIdentity(label, details), state: "complete", value };
}

export function partialCollection<T>(label: string, value: T, reason: string, details?: CollectionDetails): CollectionOutcome<T> {
  return { ...collectionIdentity(label, details), state: "partial", value, reason };
}

export function unavailableCollection<T = never>(label: string, error: string, details?: CollectionDetails): CollectionOutcome<T> {
  return { ...collectionIdentity(label, details), state: "unavailable", error };
}

export function skippedCollection<T = never>(label: string, reason: string, dependency?: symbol): CollectionOutcome<T> {
  return { ...collectionIdentity(label), state: "skipped", reason, ...(dependency === undefined ? {} : { dependency }) };
}

export function collectionReadable<T>(outcome: CollectionOutcome<T>): outcome is ReadCollection<T> {
  return outcome.state === "complete" || outcome.state === "partial";
}

export function collectionComplete<T>(outcome: CollectionOutcome<T>): outcome is CollectionIdentity & { readonly state: "complete"; readonly value: T } {
  return outcome.state === "complete";
}

export function collectionError(outcome: CollectionOutcome<unknown>): string | undefined {
  return outcome.state === "unavailable" ? outcome.error : outcome.state === "skipped" ? `not requested: ${outcome.reason}` : undefined;
}

export function mapCollection<T, U>(outcome: CollectionOutcome<T>, project: (value: T) => U): CollectionOutcome<U> {
  return collectionReadable(outcome) ? { ...outcome, value: project(outcome.value) } : outcome;
}

/** A computation may use a neutral input; the unavailable outcome itself never carries invented records. */
export function collectionValueOr<T>(outcome: CollectionOutcome<T>, fallback: T): T {
  return collectionReadable(outcome) ? outcome.value : fallback;
}

/** A sighting is meaningful under a partial read; a population claim requires every dependency. */
export function observedValue<T>(value: T, ...sources: CollectionOutcome<unknown>[]): T | null {
  return sources.every(collectionReadable) ? value : null;
}

export function populationValue<T>(value: T, ...sources: CollectionOutcome<unknown>[]): T | null {
  return sources.every(collectionComplete) ? value : null;
}

/** Progress text: `seen 40 of 120` when the total is known, `40 seen, total unknown` when it is not. */
export function seenVersusTotal(seen: number, total: number | null | undefined): string {
  return total === null || total === undefined ? `${seen} seen, total unknown` : `seen ${seen} of ${total}`;
}
