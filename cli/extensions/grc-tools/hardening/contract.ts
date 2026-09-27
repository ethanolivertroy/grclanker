import {
  DEFAULT_DATA_SCRUB_DEPTH,
  LONG_TOKEN_MIN_LENGTH,
  MIN_CONFIGURED_SECRET_LENGTH,
  REDACTED,
} from "../credential-scrub.js";
import type { DatasetState } from "./collection-status.js";
import type { PaginationStopKind } from "./pagination.js";

export const SHARED_INTEGRATION_CONTRACT_VERSION = "1.1";

export const SHARED_COLLECTION_STATES = [
  "complete",
  "truncated",
  "unreadable",
  "denied",
  "not_requested",
  "not_configured",
] as const;

export const SHARED_DATASET_STATES: readonly DatasetState[] = [
  "complete",
  "truncated",
  "unreadable",
  "not_requested",
];

export const SHARED_PAGINATION_STOP_KINDS: readonly PaginationStopKind[] = [
  "exhausted",
  "limit",
  "page_cap",
  "repeated_cursor",
  "empty_page_with_cursor",
  "time_budget",
  "missing_total",
  "rejected_next_link",
];

export const SHARED_INTEGRATION_REQUIREMENTS = {
  collection: [
    "Denied, errored, and never-requested data is not an empty inventory.",
    "Unavailable counts, lists, maps, and negative flags render as null, not 0, [], {}, or false.",
    "A denied request records its endpoint and observed status. A request that was never issued names its unreadable parent and invents no status.",
  ],
  pagination: [
    "A listing is complete only when exhaustion is proven.",
    "Every other exit is truncated and records items seen, the reported total when known, and a stable stop reason.",
    "Item caps, page caps, time budgets, repeated cursors, empty pages with cursors, missing totals, totals larger than the returned population, and rejected next links are explicit truncation reasons.",
    "A server-supplied next link may be followed only when its scheme, host, and port equal the configured origin and it carries no user information.",
    "A rejected next link is not logged with its path, query, fragment, or user information.",
  ],
  verdicts: [
    "A finding may pass only when every inventory needed for that pass is complete.",
    "An unreadable or partial secondary inventory demotes every dependent finding below pass while leaving unrelated findings evidence-based.",
    "A setting with no documented read interface produces a manual finding with exact evidence instructions. A write interface is never used as a substitute.",
  ],
  scrubbing: [
    "Scrub configured credentials and their encoded forms from configured values, errors, response descriptions, collected objects, rendered reports, and archives.",
    "Scrub authorization headers, cookies, credential assignments, URL user information and credential query values, private-key material, vendor token formats, long token-like strings, and credential-named object subtrees.",
    "Describe a non-JSON error body by status, media type, and byte length. Never copy the body.",
    "Project collected records to fields consumed by verdicts before export, then scrub again at the write boundary.",
  ],
  exports: [
    "Reject path traversal, unsafe parent paths, and symbolic-link output roots.",
    "Allocate a new bundle name on every rerun and never overwrite an earlier bundle.",
    "Pair each archive with the exact allocated bundle directory name.",
    "Write normalized analysis, projected core data, framework reports, a quick reference, and a conditional error log.",
  ],
} as const;

export const SHARED_REDACTION_RULES = [
  {
    id: "configured-values",
    match: `Every configured credential value of at least ${MIN_CONFIGURED_SECRET_LENGTH} characters, plus its base64, base64url, URL-encoded, form-encoded and JSON-escaped forms. Values of 4 to 7 characters match only as whole tokens; values of 8 or more match wherever embedded.`,
    replacement: REDACTED,
    preserve: "Configured values shorter than 4 characters are not value-matched; carrier rules still remove them when they appear as a credential value.",
  },
  {
    id: "credential-carriers",
    match: "Case-insensitive Authorization and Proxy-Authorization headers; Bearer, Basic, Token and ApiKey schemes; Cookie and Set-Cookie values; x-api-key and similar credential headers; credential-named assignments and JSON/YAML pairs; command flags; Java property assignments; and credential-named path segments.",
    replacement: `Keep the carrier key and, for authorization headers, the scheme word; replace the credential value with ${REDACTED}.`,
    preserve: "Header names, separators and sentence punctuation remain so the error stays diagnosable.",
  },
  {
    id: "urls",
    match: "Any absolute URL user information, query or fragment credential value; any webhook or callback URL stored as data; and credential-named parameters in relative URLs.",
    replacement: `Remove user information. Replace credential query/fragment values with ${REDACTED}. Exported webhook/callback URLs retain only scheme and host.`,
    preserve: "Scheme, host, port and noncredential path remain. A rejected next link records only its origin.",
  },
  {
    id: "bare-token-shapes",
    match: `JWTs, PEM blocks, hexadecimal digests, AWS key/secret shapes, known vendor prefixes, and token-character runs of at least ${LONG_TOKEN_MIN_LENGTH} characters when their letter/digit/casing composition is token-like.`,
    replacement: REDACTED,
    preserve: "Identifier-shaped values under id, uuid, hash, digest, fingerprint, etag and checksum keys skip the generic shape test but still lose registered secrets, carriers, JWTs, PEM and vendor-prefixed credentials.",
  },
  {
    id: "credential-subtrees",
    match: "Any non-null, non-boolean subtree under a key whose final segment names token, secret, password, credential, authorization, bearer, private key, or a qualified api/app/client/session/access key. secret_id, token_id and session-id variants are bearer credentials even when UUID-shaped.",
    replacement: `Replace the complete value or subtree with ${REDACTED}.`,
    preserve: "Null and booleans remain. A bare key/keys/id names an identifier unless a credential qualifier or bearer-id rule applies.",
  },
  {
    id: "name-value-records",
    match: "An object containing name or key plus value when the name/key value itself is credential-shaped.",
    replacement: `Replace only value with ${REDACTED}.`,
    preserve: "Keep the setting name and sibling metadata.",
  },
  {
    id: "depth-cap",
    match: `Any object or array container deeper than ${DEFAULT_DATA_SCRUB_DEPTH} levels in the shared data scrubber.`,
    replacement: `Replace the over-depth container whole with ${REDACTED}.`,
    preserve: "Strings are scrubbed before the depth test, and scalars at retained depths keep their type.",
  },
  {
    id: "error-bodies",
    match: "A non-JSON response body, or a JSON error object without a reviewed message field.",
    replacement: "Record HTTP status, normalized media type and exact UTF-8 byte length only.",
    preserve: "A reviewed JSON message is still passed through all credential rules and fixed length limits before use.",
  },
  {
    id: "two-pass-sink",
    match: "All configured values, error text, normalized records, finding evidence, reports and archive inputs.",
    replacement: "Scrub on collection and scrub the complete serialized data structure again immediately before writing.",
    preserve: `The operation is idempotent: a second pass leaves ${REDACTED} and all reviewed must-keep text unchanged.`,
  },
] as const;
