/**
 * Shared hardening helpers for integration tools: the error-text sink and `IntegrationError` base class,
 * the safe config-file loaders, the collection-status markers and null-rendering helpers, the
 * pagination stop descriptions, and the same-origin guard for server-supplied next links. The
 * integrations under `cli/extensions/grc-tools/` import this index; the export surface only grows.
 */
export {
  IntegrationError,
  LONG_TOKEN_MIN_LENGTH,
  MAX_ERROR_MESSAGE_LENGTH,
  MAX_VENDOR_MESSAGE_LENGTH,
  MIN_CONFIGURED_SECRET_LENGTH,
  REDACTED,
  describeErrorBody,
  describeFailedResponse,
  errorMessage,
  isCredentialKey,
  mediaTypeOf,
  redactSecretValues,
  scrubDataText,
  scrubError,
  scrubErrorText,
} from "./error-text.js";
export type { FailedResponse, IntegrationErrorDetails, RedactSecretValuesOptions, ScrubErrorTextOptions, ScrubbedError } from "./error-text.js";

export {
  CONFIG_FILE_MAX_BYTES,
  ConfigFileError,
  PARSER_CODE_PATTERN,
  SYSTEM_ERROR_CODE_PATTERN,
  configFileErrorMessage,
  jsonErrorPosition,
  parseJsonConfigText,
  parseYamlConfigText,
  readConfigText,
  readJsonConfig,
  readYamlConfig,
  systemErrorCode,
  yamlErrorCode,
  yamlErrorPosition,
} from "./config-file.js";
export type { ConfigFileErrorDetails, ConfigFileFailureKind, ConfigFileOptions, ConfigFileResult, ParserPosition } from "./config-file.js";

export {
  collectionComplete,
  collectionError,
  collectionReadable,
  collectionValueOr,
  completeCollection,
  mapCollection,
  observedValue,
  partialCollection,
  populationValue,
  seenVersusTotal,
  skippedCollection,
  unavailableCollection,
} from "./collection-status.js";
export type { CollectionDetails, CollectionOutcome, CollectionState, ReadCollection } from "./collection-status.js";

export { describePagination } from "./pagination.js";
export type { PaginationOutcome, PaginationStop, PaginationStopKind } from "./pagination.js";

export { INVALID_CONFIGURED_ORIGIN_CODE, NEXT_LINK_REJECTED_CODE, NextLinkError, nextLinkStop, originOf, resolveSameOriginUrl } from "./next-link.js";
export type { NextLinkRejection } from "./next-link.js";

export {
  SHARED_COLLECTION_STATES,
  SHARED_DATASET_STATES,
  SHARED_INTEGRATION_CONTRACT_VERSION,
  SHARED_INTEGRATION_REQUIREMENTS,
  SHARED_PAGINATION_STOP_KINDS,
  SHARED_REDACTION_RULES,
} from "./contract.js";

export { parseNextLinkHeader } from "./link-header.js";
export type { ParsedNextLink } from "./link-header.js";
