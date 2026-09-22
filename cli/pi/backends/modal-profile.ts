import { homedir } from "node:os";
import { join } from "node:path";
import {
  ConfigFileError,
  readConfigText,
} from "../../extensions/grc-tools/hardening/config-file.js";
import { ExecutionBackendError, redactSecrets } from "../execution-backend.js";

// Modal reads credentials from the active profile in `.modal.toml`: by default `~/.modal.toml`,
// overridable with MODAL_CONFIG_PATH; one TOML table per profile holding `token_id` and
// `token_secret`; MODAL_PROFILE selects the table and otherwise the table marked active by
// `modal profile activate` (or `modal token set --activate`) is used, falling back to `default`.
// Each value can be overridden by its MODAL_* environment variable. `modal setup` and
// `modal token set` write this file.
// https://modal.com/docs/reference/modal.config
// https://modal.com/docs/reference/cli/token
// https://modal.com/docs/reference/cli/setup
// https://modal.com/docs/reference/cli/profile
export const MODAL_CONFIG_FILE_NAME = ".modal.toml";
export const MODAL_DEFAULT_PROFILE = "default";
export const MODAL_TOKEN_ENV = ["MODAL_TOKEN_ID", "MODAL_TOKEN_SECRET"] as const;

const MODAL_CONFIG_LABEL = "Modal";
const TOML_FORMAT = "TOML";
const TABLE_HEADER_PATTERN = /^\[\s*(?:([A-Za-z0-9_-]+)|"([^"\\]*)"|'([^']*)')\s*\]$/;
const KEY_VALUE_PATTERN = /^(?:([A-Za-z0-9_-]+)|"([^"\\]*)"|'([^']*)')\s*=\s*(.*)$/;
const BASIC_STRING_PATTERN = /^"(?:[^"\\]|\\.)*"$/;
const LITERAL_STRING_PATTERN = /^'[^']*'$/;
const NUMBER_PATTERN = /^[+-]?(?:\d[\d_]*(?:\.\d[\d_]*)?(?:[eE][+-]?\d+)?|inf|nan|0x[0-9A-Fa-f_]+|0o[0-7_]+|0b[01_]+)$/;
const DATE_TIME_PATTERN = /^\d{4}-\d{2}-\d{2}(?:[Tt ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:[Zz]|[+-]\d{2}:\d{2})?)?$|^\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?$/;
// An array or inline table that opens and closes on the same line; never a credential key's shape.
const SINGLE_LINE_COLLECTION_PATTERN = /^(?:\[.*\]|\{.*\})$/;

type CredentialKey = "token_id" | "token_secret";

/** What a profile table contains. Values are never kept, only whether the credential keys hold a non-empty string. */
export type ModalProfileTable = {
  credentials: Set<CredentialKey>;
  active: boolean;
};

export type ModalProfileFile = {
  path: string;
  /** Profile tables in file order, keyed by table name. */
  profiles: Map<string, ModalProfileTable>;
};

export type ModalCredentialSource =
  | { kind: "environment" }
  | { kind: "profile"; path: string; profile: string }
  | { kind: "missing"; path: string; profile: string; detail: string }
  | { kind: "invalid"; path: string; message: string };

export function resolveModalConfigPath(env: NodeJS.ProcessEnv = process.env, homeDirectory: string = homedir()): string {
  const override = env.MODAL_CONFIG_PATH?.trim();
  return override ? override : join(homeDirectory, MODAL_CONFIG_FILE_NAME);
}

function parseFailure(path: string, line: number, code?: string): ConfigFileError {
  return new ConfigFileError({ kind: "parse", path, format: TOML_FORMAT, code, line, label: MODAL_CONFIG_LABEL });
}

// The documented shape is tables of `key = "value"` lines, so only scalar values are accepted
// here. A value is classified, never kept: the parser needs to know whether a credential key
// holds a non-empty string and whether `active` is `true`, and nothing else. A bare word where
// TOML requires a quoted string (the way a token pasted without quotes lands) is a parse
// failure reported by line number only.
function classifyValue(raw: string): { kind: "string"; empty: boolean } | { kind: "boolean"; value: boolean } | { kind: "other" } | undefined {
  const value = stripTrailingComment(raw).trim();
  if (value.length === 0) return undefined;
  if (BASIC_STRING_PATTERN.test(value) || LITERAL_STRING_PATTERN.test(value)) {
    return { kind: "string", empty: value.length === 2 };
  }
  if (value === "true" || value === "false") return { kind: "boolean", value: value === "true" };
  if (NUMBER_PATTERN.test(value) || DATE_TIME_PATTERN.test(value)) return { kind: "other" };
  if (SINGLE_LINE_COLLECTION_PATTERN.test(value)) return { kind: "other" };
  return undefined;
}

function stripTrailingComment(raw: string): string {
  let quote: '"' | "'" | undefined;
  for (let index = 0; index < raw.length; index += 1) {
    const char = raw[index]!;
    if (quote) {
      if (char === "\\" && quote === '"') index += 1;
      else if (char === quote) quote = undefined;
      continue;
    }
    if (char === '"' || char === "'") quote = char;
    else if (char === "#") return raw.slice(0, index);
  }
  return raw;
}

/**
 * Step 2 of the loader: parses the documented `.modal.toml` shape inside a guard. Every failure is
 * a `ConfigFileError` of kind `parse` built from the path, the line number, and a fixed code; the
 * offending line's text, and therefore any token on it, never reaches the message.
 */
export function parseModalProfileText(text: string, path: string): ModalProfileFile {
  const profiles = new Map<string, ModalProfileTable>();
  let current: { name: string; keys: Set<string> } | undefined;
  const lines = text.replace(/^\uFEFF/, "").split(/\r?\n/);
  for (let index = 0; index < lines.length; index += 1) {
    const lineNumber = index + 1;
    const line = stripTrailingComment(lines[index]!).trim();
    if (line.length === 0) continue;

    const header = TABLE_HEADER_PATTERN.exec(line);
    if (header) {
      const name = header[1] ?? header[2] ?? header[3] ?? "";
      if (name.length === 0) throw parseFailure(path, lineNumber);
      if (profiles.has(name)) throw parseFailure(path, lineNumber, "DUPLICATE_KEY");
      profiles.set(name, { credentials: new Set(), active: false });
      current = { name, keys: new Set() };
      continue;
    }
    if (line.startsWith("[")) throw parseFailure(path, lineNumber);

    const pair = KEY_VALUE_PATTERN.exec(line);
    if (!pair) throw parseFailure(path, lineNumber);
    const key = pair[1] ?? pair[2] ?? pair[3] ?? "";
    const value = classifyValue(pair[4] ?? "");
    if (key.length === 0 || value === undefined) throw parseFailure(path, lineNumber);
    if (!current) continue;
    if (current.keys.has(key)) throw parseFailure(path, lineNumber, "DUPLICATE_KEY");
    current.keys.add(key);
    const table = profiles.get(current.name)!;
    if ((key === "token_id" || key === "token_secret") && value.kind === "string" && !value.empty) {
      table.credentials.add(key);
    }
    if (key === "active" && value.kind === "boolean") table.active = value.value;
  }
  return { path, profiles };
}

/**
 * Reads and parses the profile file, `readConfigText` then `parseModalProfileText`, each in its
 * own guard. ENOENT is the explicit missing result; any other read failure is
 * `Unable to read Modal config file <path> (<CODE>)` with the errno code only.
 */
export function readModalProfileFile(path: string): { ok: true; value: ModalProfileFile } | { ok: false; reason: "missing" } {
  const read = readConfigText(path, { label: MODAL_CONFIG_LABEL });
  if (!read.ok) return { ok: false, reason: "missing" };
  return { ok: true, value: parseModalProfileText(read.value, path) };
}

// Mirrors the client's own resolution (`MODAL_PROFILE`, else the table with `active = true`,
// else "default"), so grclanker never rejects a profile the modal CLI would accept.
export function selectModalProfile(file: ModalProfileFile, env: NodeJS.ProcessEnv = process.env): string {
  const requested = env.MODAL_PROFILE?.trim();
  if (requested) return requested;
  for (const [name, table] of file.profiles) {
    if (table.active) return name;
  }
  return MODAL_DEFAULT_PROFILE;
}

function hasEnvValue(env: NodeJS.ProcessEnv, name: string): boolean {
  return Boolean(env[name]?.trim());
}

/**
 * Where Modal credentials come from, resolved per key the way the client does (environment first,
 * then the selected profile). Only presence is reported; no token value is read into the result.
 */
export function detectModalCredentials(env: NodeJS.ProcessEnv = process.env, homeDirectory: string = homedir()): ModalCredentialSource {
  const envTokenId = hasEnvValue(env, "MODAL_TOKEN_ID");
  const envTokenSecret = hasEnvValue(env, "MODAL_TOKEN_SECRET");
  if (envTokenId && envTokenSecret) return { kind: "environment" };

  const path = resolveModalConfigPath(env, homeDirectory);
  let file: ModalProfileFile;
  try {
    const read = readModalProfileFile(path);
    if (!read.ok) {
      return {
        kind: "missing",
        path,
        profile: env.MODAL_PROFILE?.trim() || MODAL_DEFAULT_PROFILE,
        detail: "the file does not exist",
      };
    }
    file = read.value;
  } catch (error) {
    // Only the loader's fixed-text message is carried; anything else thrown is reported as the
    // fixed unreadable-file text so no filesystem or parser wording leaks through.
    const message = error instanceof ConfigFileError ? error.message : `Unable to read ${MODAL_CONFIG_LABEL} config file ${path}`;
    return { kind: "invalid", path, message };
  }

  const profile = selectModalProfile(file, env);
  const table = file.profiles.get(profile);
  const tokenId = envTokenId || table?.credentials.has("token_id") === true;
  const tokenSecret = envTokenSecret || table?.credentials.has("token_secret") === true;
  if (tokenId && tokenSecret) return { kind: "profile", path, profile };
  const missingKeys = [!tokenId && "token_id", !tokenSecret && "token_secret"].filter(Boolean).join(" and ");
  return {
    kind: "missing",
    path,
    profile,
    detail: table ? `profile "${profile}" has no ${missingKeys}` : `the file has no "${profile}" profile`,
  };
}

export function isModalCredentialSourceUsable(source: ModalCredentialSource): boolean {
  switch (source.kind) {
    case "environment":
    case "profile":
      return true;
    case "missing":
    case "invalid":
      return false;
    default: {
      const unhandled: never = source;
      throw new Error(`Unhandled Modal credential source ${String(unhandled)}`);
    }
  }
}

/** A one-line, value-free description for `env list` and `env doctor`; paths and profile names are scrubbed. */
export function describeModalCredentialSource(source: ModalCredentialSource): string {
  switch (source.kind) {
    case "environment":
      return `Found ${MODAL_TOKEN_ENV.join(", ")} in the environment.`;
    case "profile":
      return redactSecrets(`Found Modal CLI profile "${source.profile}" in ${source.path}.`);
    case "missing":
      return redactSecrets(`Set ${MODAL_TOKEN_ENV.join(" and ")} in the environment, or run \`modal setup\` / \`modal token set\` to write ${source.path} (${source.detail}).`);
    case "invalid":
      return redactSecrets(`${source.message}. Fix the file or set ${MODAL_TOKEN_ENV.join(" and ")} in the environment.`);
    default: {
      const unhandled: never = source;
      throw new Error(`Unhandled Modal credential source ${String(unhandled)}`);
    }
  }
}

/** The adapter's guard: passes when the modal CLI will find credentials, otherwise throws the value-free description. */
export function requireModalCredentials(env: NodeJS.ProcessEnv = process.env, homeDirectory: string = homedir()): ModalCredentialSource {
  const source = detectModalCredentials(env, homeDirectory);
  if (!isModalCredentialSourceUsable(source)) {
    throw new ExecutionBackendError(describeModalCredentialSource(source));
  }
  return source;
}
