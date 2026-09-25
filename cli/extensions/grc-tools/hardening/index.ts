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
  coreDataValue,
  countIfReadable,
  datasetMarker,
  datasetState,
  datasetStatus,
  derived,
  derivedFlag,
  gatedPrincipals,
  ifComplete,
  ifRead,
  isAbsenceValue,
  isComplete,
  isReadable,
  notCollected,
  notRequested,
  notRequestedDataset,
  readDataset,
  seenVersusTotal,
  unreadableDataset,
  withoutAbsenceClaims,
} from "./collection-status.js";
export type { Dataset, DatasetState, DatasetStatus, NotCollectedMarker, ReadDatasetDetails, UnreadDatasetDetails } from "./collection-status.js";

export { describePagination } from "./pagination.js";
export type { PaginationOutcome, PaginationStop, PaginationStopKind } from "./pagination.js";

export { INVALID_CONFIGURED_ORIGIN_CODE, NEXT_LINK_REJECTED_CODE, NextLinkError, nextLinkStop, originOf, resolveSameOriginUrl } from "./next-link.js";
export type { NextLinkRejection } from "./next-link.js";
