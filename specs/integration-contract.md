---
slug: "integration-contract"
name: "Shared Integration Contract"
vendor: "grclanker"
category: "community-specs"
language: "language-neutral"
status: "generated"
version: "1.0"
last_updated: "2026-09-27"
source_repo: "https://github.com/ethanolivertroy/grclanker"
---

<!-- generated shared integration contract -->
> Generated from the shared hardening vocabulary and credential scrubber contract by `npm --prefix cli run sync:integration-specs`. Edit those sources, not this file.

# Shared integration contract

Every portable integration implementation must reproduce these rules. Integration specifications list only additions and reviewed exceptions.

Contract version: 1.0

## Collection and null semantics

- Denied, errored, and never-requested data is not an empty inventory.
- Unavailable counts, lists, maps, and negative flags render as null, not 0, [], {}, or false.
- A denied request records its endpoint and observed status. A request that was never issued names its unreadable parent and invents no status.

## Pagination and truncation

- A listing is complete only when exhaustion is proven.
- Every other exit is truncated and records items seen, the reported total when known, and a stable stop reason.
- Item caps, page caps, time budgets, repeated cursors, empty pages with cursors, missing totals, totals larger than the returned population, and rejected next links are explicit truncation reasons.
- A server-supplied next link may be followed only when its scheme, host, and port equal the configured origin and it carries no user information.
- A rejected next link is not logged with its path, query, fragment, or user information.

## Verdict integrity

- A finding may pass only when every inventory needed for that pass is complete.
- An unreadable or partial secondary inventory demotes every dependent finding below pass while leaving unrelated findings evidence-based.
- A setting with no documented read interface produces a manual finding with exact evidence instructions. A write interface is never used as a substitute.

## Credential and error scrubbing

- Scrub configured credentials and their encoded forms from configured values, errors, response descriptions, collected objects, rendered reports, and archives.
- Scrub authorization headers, cookies, credential assignments, URL user information and credential query values, private-key material, vendor token formats, long token-like strings, and credential-named object subtrees.
- Describe a non-JSON error body by status, media type, and byte length. Never copy the body.
- Project collected records to fields consumed by verdicts before export, then scrub again at the write boundary.

## Safe evidence bundles

- Reject path traversal, unsafe parent paths, and symbolic-link output roots.
- Allocate a new bundle name on every rerun and never overwrite an earlier bundle.
- Pair each archive with the exact allocated bundle directory name.
- Write normalized analysis, projected core data, framework reports, a quick reference, and a conditional error log.

## Collection-state vocabulary

- `complete`
- `truncated`
- `unreadable`
- `denied`
- `not requested`
- `not configured`
