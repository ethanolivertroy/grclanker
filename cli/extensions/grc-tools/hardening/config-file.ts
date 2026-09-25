/**
 * Safe config-file loaders.
 *
 * A malformed config file whose bad line carries a credential puts that credential into the parser's
 * message: the `yaml` package quotes the offending source line (`key: <token>: Bearer <token>`),
 * `JSON.parse` quotes a 10-character window around the failure (the whole source at 21 characters or
 * fewer), and the YAML alias shape `key: *VALUE` throws a plain `ReferenceError` whose message starts
 * with the value and carries no key name at all. Read failures add the filesystem's wording and, for
 * some codes, the path. None of that text is ever interpolated here.
 *
 * Every loader runs two guards with fixed text per step. Step 1 reads: any thrown value becomes a
 * `ConfigFileError` of kind `read` carrying the path and the errno code when it matches
 * `^E[A-Z0-9_]{1,30}$` (EISDIR, EACCES, ENOTDIR, ERR_...), never the fs message; ENOENT is not an
 * error but the explicit missing-file result, because most integrations treat a missing file as no
 * overlay. Step 2 parses: any thrown value, parser error class or not, becomes a `ConfigFileError` of
 * kind `parse` carrying the path, the format, the line and column from the parser's structured
 * position only (`YAMLError.linePos`; for `JSON.parse` the offset matched by a strict regex over the
 * message, converted against the source), and a validated code (the `YAMLParseError` code, or the
 * fixed `INVALID_YAML` / `INVALID_JSON`). A key-word scrub at the tool boundary is no
 * substitute for these fixed-text errors, because the exported resolvers throw before any boundary is
 * reached and a scrub cannot recognise a bare value with no key in front of it; the error message is
 * therefore built from fixed text plus path, position, and code, and nothing else.
 */
import { readFileSync } from "node:fs";
import { YAMLError, parseDocument } from "yaml";

/** Which guard failed: the filesystem read or the parse of the text it returned. */
export type ConfigFileFailureKind = "read" | "parse";

/** Node system and internal error codes (`EISDIR`, `EACCES`, `ENOTDIR`, `ERR_FS_FILE_TOO_LARGE`). Anything else is not a code and is dropped. */
export const SYSTEM_ERROR_CODE_PATTERN = /^E[A-Z0-9_]{1,30}$/;

/** Parser codes (`BLOCK_AS_IMPLICIT_KEY`, `DUPLICATE_KEY`) and the fixed codes of this module. */
export const PARSER_CODE_PATTERN = /^[A-Z][A-Z0-9_]{1,40}$/;

const FORMAT_PATTERN = /^[A-Za-z][A-Za-z0-9+.-]{0,15}$/;
const LABEL_PATTERN = /^[A-Za-z0-9][A-Za-z0-9 ._-]{0,40}$/;
const JSON_POSITION_PATTERN = /\bat position (\d{1,9})\b/;
const BYTE_ORDER_MARK = "\uFEFF";

export interface ConfigFileErrorDetails {
  kind: ConfigFileFailureKind;
  /** The path the caller asked for; the only free text in the message. */
  path: string;
  /** Parse failures: the format the text was expected to be in (`YAML`, `JSON`, `TOML`, `INI`). */
  format?: string;
  /** A validated code: errno for reads, parser code or fixed `INVALID_<FORMAT>` for parses. */
  code?: string;
  line?: number;
  column?: number;
  /** The integration's display name ("New Relic"), so the message reads `Unable to read New Relic config file ...`. */
  label?: string;
}

export interface ConfigFileOptions {
  /** The integration's display name for the error message; kept only when it is a short plain name. */
  label?: string;
}

/** A loaded file, or the explicit missing-file result. */
export type ConfigFileResult<T> = { ok: true; path: string; value: T } | { ok: false; path: string; reason: "missing" };

function positiveInteger(value: unknown): number | undefined {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0 ? value : undefined;
}

function validatedCode(kind: ConfigFileFailureKind, code: string | undefined, format: string): string | undefined {
  if (kind === "read") return code !== undefined && SYSTEM_ERROR_CODE_PATTERN.test(code) ? code : undefined;
  if (code !== undefined && PARSER_CODE_PATTERN.test(code)) return code;
  return `INVALID_${format.toUpperCase().replace(/[^A-Z0-9]/g, "_")}`;
}

function validatedFormat(format: string | undefined): string {
  return format !== undefined && FORMAT_PATTERN.test(format) ? format : "config";
}

function labelPrefix(label: string | undefined): string {
  return label !== undefined && LABEL_PATTERN.test(label) ? `${label.trim()} ` : "";
}

function positionText(line: number | undefined, column: number | undefined): string {
  if (line === undefined) return "";
  return ` at line ${line}${column === undefined ? "" : `, column ${column}`}`;
}

/**
 * The fixed-text message: `Unable to read <Label> config file <path> (<CODE>)` or `Unable to parse
 * <Label> config file: invalid <FORMAT> in <path> at line N, column M (<CODE>)`. Built from the
 * validated fields only, so a caller cannot route library text through it by mistake.
 */
export function configFileErrorMessage(details: ConfigFileErrorDetails): string {
  const format = validatedFormat(details.format);
  const code = validatedCode(details.kind, details.code, format);
  const codeText = code === undefined ? "" : ` (${code})`;
  const prefix = labelPrefix(details.label);
  switch (details.kind) {
    case "read":
      return `Unable to read ${prefix}config file ${details.path}${codeText}`;
    case "parse":
      return `Unable to parse ${prefix}config file: invalid ${format} in ${details.path}${positionText(positiveInteger(details.line), positiveInteger(details.column))}${codeText}`;
    default: {
      const unhandled: never = details.kind;
      throw new Error(`Unhandled config file failure kind ${String(unhandled)}`);
    }
  }
}

/**
 * The error every loader throws. Its message is `configFileErrorMessage` over the validated fields
 * and its properties expose them for callers that branch on the code or report the position. The
 * constructor takes structured details, not a message, so a custom parser (TOML, INI, dogrc) that
 * throws it cannot pass library text through.
 */
export class ConfigFileError extends Error {
  readonly kind: ConfigFileFailureKind;
  readonly path: string;
  readonly format: string | undefined;
  readonly code: string | undefined;
  readonly line: number | undefined;
  readonly column: number | undefined;

  constructor(details: ConfigFileErrorDetails) {
    super(configFileErrorMessage(details));
    this.name = "ConfigFileError";
    this.kind = details.kind;
    this.path = details.path;
    this.format = details.kind === "parse" ? validatedFormat(details.format) : undefined;
    this.code = validatedCode(details.kind, details.code, validatedFormat(details.format));
    this.line = details.kind === "parse" ? positiveInteger(details.line) : undefined;
    this.column = this.line === undefined ? undefined : positiveInteger(details.column);
  }
}

/** The `code` of a Node system or internal error when it is shaped like one; never the message. */
export function systemErrorCode(error: unknown): string | undefined {
  if (!error || typeof error !== "object") return undefined;
  const code = (error as { code?: unknown }).code;
  return typeof code === "string" && SYSTEM_ERROR_CODE_PATTERN.test(code) ? code : undefined;
}

export interface ParserPosition {
  line: number;
  column?: number;
}

/** The first position a `YAMLError` points at; undefined for any other thrown value (the alias `ReferenceError` has none). */
export function yamlErrorPosition(error: unknown): ParserPosition | undefined {
  if (!(error instanceof YAMLError)) return undefined;
  const first = error.linePos?.[0];
  const line = positiveInteger(first?.line);
  if (line === undefined) return undefined;
  const column = positiveInteger(first?.col);
  return column === undefined ? { line } : { line, column };
}

/** The `YAMLError` code when it is shaped like one; undefined for any other thrown value. */
export function yamlErrorCode(error: unknown): string | undefined {
  return error instanceof YAMLError && PARSER_CODE_PATTERN.test(error.code) ? error.code : undefined;
}

/**
 * The line and column of a `JSON.parse` failure, derived from the offset a strict regex finds in the
 * `SyntaxError` message (`at position N`) and the source text; undefined when the message carries no
 * offset (the `Unexpected token` family, which is the one that quotes the source).
 */
export function jsonErrorPosition(error: unknown, text: string): ParserPosition | undefined {
  if (!(error instanceof SyntaxError)) return undefined;
  const match = JSON_POSITION_PATTERN.exec(error.message);
  if (!match) return undefined;
  const offset = Number(match[1]);
  if (!Number.isSafeInteger(offset) || offset > text.length) return undefined;
  const before = text.slice(0, offset);
  const lineStart = before.lastIndexOf("\n") + 1;
  return { line: before.split("\n").length, column: offset - lineStart + 1 };
}

function stripByteOrderMark(text: string): string {
  return text.startsWith(BYTE_ORDER_MARK) ? text.slice(1) : text;
}

/**
 * Step 1 of every loader: reads the file as UTF-8 inside its own guard. ENOENT is the explicit
 * missing-file result; every other thrown value becomes a `ConfigFileError` of kind `read` with the
 * validated errno code and nothing from the filesystem message. Callers that parse a format this
 * module does not (TOML, INI, dogrc) use this and throw their own `ConfigFileError` of kind `parse`.
 */
export function readConfigText(path: string, options: ConfigFileOptions = {}): ConfigFileResult<string> {
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch (error) {
    const code = systemErrorCode(error);
    if (code === "ENOENT") return { ok: false, path, reason: "missing" };
    throw new ConfigFileError({ kind: "read", path, code, label: options.label });
  }
  return { ok: true, path, value: text };
}

/**
 * Step 2 for YAML: parses the text inside a guard that catches every thrown value. The document is
 * composed with warnings silenced (a `YAMLWarning` for an unknown tag quotes the source line and
 * `yaml.parse` would emit it to stderr), its first parse error is raised with its structured
 * position and code, and alias resolution runs inside the same guard so the `ReferenceError` of an
 * unresolved alias or of the alias-count limit becomes a positionless `INVALID_YAML` failure.
 */
export function parseYamlConfigText(text: string, path: string, options: ConfigFileOptions = {}): unknown {
  try {
    const document = parseDocument(stripByteOrderMark(text), { logLevel: "error" });
    const [firstError] = document.errors;
    if (firstError) throw firstError;
    return document.toJS();
  } catch (error) {
    const position = yamlErrorPosition(error);
    throw new ConfigFileError({ kind: "parse", path, format: "YAML", code: yamlErrorCode(error), line: position?.line, column: position?.column, label: options.label });
  }
}

/**
 * Step 2 for JSON: parses the text inside a guard that catches every thrown value and reports the
 * position only through `jsonErrorPosition`, so the quoted-window family of messages contributes
 * nothing but the fixed `INVALID_JSON` code.
 */
export function parseJsonConfigText(text: string, path: string, options: ConfigFileOptions = {}): unknown {
  const source = stripByteOrderMark(text);
  try {
    return JSON.parse(source);
  } catch (error) {
    const position = jsonErrorPosition(error, source);
    throw new ConfigFileError({ kind: "parse", path, format: "JSON", line: position?.line, column: position?.column, label: options.label });
  }
}

/** Reads and parses a YAML config file: `readConfigText` then `parseYamlConfigText`, each in its own guard. */
export function readYamlConfig(path: string, options: ConfigFileOptions = {}): ConfigFileResult<unknown> {
  const read = readConfigText(path, options);
  if (!read.ok) return read;
  return { ok: true, path, value: parseYamlConfigText(read.value, path, options) };
}

/** Reads and parses a JSON config file: `readConfigText` then `parseJsonConfigText`, each in its own guard. */
export function readJsonConfig(path: string, options: ConfigFileOptions = {}): ConfigFileResult<unknown> {
  const read = readConfigText(path, options);
  if (!read.ok) return read;
  return { ok: true, path, value: parseJsonConfigText(read.value, path, options) };
}
