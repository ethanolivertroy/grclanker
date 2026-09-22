import test from "node:test";
import assert from "node:assert/strict";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { YAMLError, parse as parseYaml, parseDocument } from "yaml";

import {
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
} from "../dist/extensions/grc-tools/hardening/config-file.js";

/**
 * Credential-shaped values planted on the malformed line of each fixture (coordinator addendum 6b).
 * Alphanumeric only, so no window of one can sit inside a temp path, and distinct in every
 * 8-character window, so the fragment assertion cannot pass by accident: a shared prefix would let
 * one canary's absence mask another's leak.
 */
const CANARY = Object.freeze({
  yamlNestedKey: "Kq7Zx2Vw9Lm4Tp8R",
  yamlNestedBearer: "Hb3Ny6Qc1Fd5Js0W",
  yamlAlias: "Rt4Ug8Ex2Vo6Zk1M",
  yamlTag: "Zt8Kp3Wn6Rq1Yc4V",
  jsonUnquoted: "Wp9Ha3Ze7Kc2Ru5Y",
  jsonShort: "Lz3v8Qw2Xn",
  jsonTrailingComma: "Qm6Bd2Ty9Vf4Xs1P",
  lockedFile: "Gx5Jc9Wq3Ln7Ez2T",
});

/** The parser and filesystem wording the batch 2 canary report saw in agent-visible output. */
const LIBRARY_WORDING = Object.freeze([
  "Nested mappings",
  "is not valid JSON",
  "Unexpected token",
  "Unresolved alias",
  "illegal operation",
  "permission denied",
  "no such file",
]);

const FRAGMENT_LENGTH = 8;
const RUNNING_AS_ROOT = typeof process.getuid === "function" && process.getuid() === 0;

function tempBase() {
  return mkdtempSync(join(tmpdir(), "hardening-config-"));
}

function windows(value, size = FRAGMENT_LENGTH) {
  const out = [];
  for (let index = 0; index + size <= value.length; index += 1) out.push(value.slice(index, index + size));
  return out;
}

function carriesFragment(text, canary) {
  return windows(canary).some((fragment) => text.includes(fragment));
}

function capture(fn) {
  try {
    fn();
  } catch (error) {
    return error;
  }
  return assert.fail("expected the call to throw");
}

/** Positive control: the library's own message quotes the planted value (or the window the library quotes of it). */
function assertLibraryMessageCarries(message, canary, label) {
  assert.ok(carriesFragment(message, canary), `${label}: positive control failed, the library message does not quote the canary: ${message}`);
}

/**
 * The fixed-text contract: a `ConfigFileError` whose fields are the validated values and whose
 * message carries the path, the code, and the line where the parser gave one, and carries neither a
 * canary, nor any 8-character fragment of one, nor library wording.
 */
function assertFixedTextError(error, expected, canaries, label) {
  assert.ok(error instanceof ConfigFileError, `${label}: expected ConfigFileError, got ${error?.constructor?.name}: ${error?.message}`);
  assert.ok(error instanceof Error);
  assert.equal(error.name, "ConfigFileError");
  assert.equal(error.kind, expected.kind);
  assert.equal(error.path, expected.path);
  assert.equal(error.format, expected.format);
  assert.equal(error.code, expected.code);
  assert.equal(error.line, expected.line);
  assert.equal(error.column, expected.column);
  const { message } = error;
  for (const canary of canaries) {
    assert.ok(!message.includes(canary), `${label}: canary ${canary} leaked into "${message}"`);
    for (const fragment of windows(canary)) {
      assert.ok(!message.includes(fragment), `${label}: fragment ${fragment} of ${canary} leaked into "${message}"`);
    }
  }
  for (const wording of LIBRARY_WORDING) {
    assert.ok(!message.includes(wording), `${label}: library wording "${wording}" leaked into "${message}"`);
  }
  assert.ok(message.includes(expected.path), `${label}: message does not name the path: "${message}"`);
  if (expected.code !== undefined) assert.ok(message.includes(`(${expected.code})`), `${label}: message does not carry the code: "${message}"`);
  if (expected.line !== undefined) assert.ok(message.includes(`at line ${expected.line}`), `${label}: message does not carry the line: "${message}"`);
  else assert.doesNotMatch(message, /\bat line \d/, `${label}: message claims a line the parser did not give`);
  assert.doesNotMatch(message, /[\r\n]/, `${label}: message must be one line`);
  assert.equal(message, configFileErrorMessage(error));
  return message;
}

test("config-file canaries are alphanumeric and distinct in every 8-character window", () => {
  const fragments = Object.values(CANARY).flatMap((canary) => windows(canary));
  assert.equal(new Set(fragments).size, fragments.length, "two canaries share an 8-character window");
  for (const canary of Object.values(CANARY)) assert.match(canary, /^[A-Za-z0-9]{10,}$/);
});

test("YAML nested mapping: yaml quotes the line; ConfigFileError carries the path, line, column, and parser code only", () => {
  const path = join(tempBase(), "config.yaml");
  const text = `name: demo\nkey: ${CANARY.yamlNestedKey}: Bearer ${CANARY.yamlNestedBearer}\n`;
  writeFileSync(path, text);

  const libraryError = capture(() => parseYaml(text));
  assert.ok(libraryError instanceof YAMLError);
  assert.match(libraryError.code, PARSER_CODE_PATTERN);
  assert.ok(libraryError.message.includes("Nested mappings"));
  assertLibraryMessageCarries(libraryError.message, CANARY.yamlNestedKey, "yaml nested mapping");
  assertLibraryMessageCarries(libraryError.message, CANARY.yamlNestedBearer, "yaml nested mapping");
  const [{ line, col }] = libraryError.linePos;

  const error = capture(() => readYamlConfig(path));
  const message = assertFixedTextError(
    error,
    { kind: "parse", path, format: "YAML", code: libraryError.code, line, column: col },
    [CANARY.yamlNestedKey, CANARY.yamlNestedBearer],
    "yaml nested mapping",
  );
  assert.equal(message, `Unable to parse config file: invalid YAML in ${path} at line ${line}, column ${col} (${libraryError.code})`);
  assert.equal(line, 2);
});

test("YAML alias: the ReferenceError names the value; ConfigFileError is a positionless INVALID_YAML", () => {
  const path = join(tempBase(), "config.yaml");
  const text = `name: demo\nkey: *${CANARY.yamlAlias}\n`;
  writeFileSync(path, text);

  const libraryError = capture(() => parseYaml(text));
  assert.ok(libraryError instanceof ReferenceError);
  assert.ok(!(libraryError instanceof YAMLError));
  assert.equal(libraryError.linePos, undefined);
  assert.ok(libraryError.message.includes("Unresolved alias"));
  assertLibraryMessageCarries(libraryError.message, CANARY.yamlAlias, "yaml alias");
  assert.equal(parseDocument(text).errors.length, 0, "the alias is not a composition error; it throws at resolution");

  const error = capture(() => readYamlConfig(path));
  const message = assertFixedTextError(error, { kind: "parse", path, format: "YAML", code: "INVALID_YAML", line: undefined, column: undefined }, [CANARY.yamlAlias], "yaml alias");
  assert.equal(message, `Unable to parse config file: invalid YAML in ${path} (INVALID_YAML)`);
});

test("JSON unquoted value: JSON.parse quotes a 10-character window; ConfigFileError is a positionless INVALID_JSON", () => {
  const path = join(tempBase(), "config.json");
  const text = `{\n  "name": "demo",\n  "token": ${CANARY.jsonUnquoted}\n}\n`;
  assert.ok(text.length > 21);
  writeFileSync(path, text);

  const libraryError = capture(() => JSON.parse(text));
  assert.ok(libraryError instanceof SyntaxError);
  assert.ok(libraryError.message.includes("is not valid JSON"));
  assert.doesNotMatch(libraryError.message, /at position \d+/, "the quoted-window family carries no offset");
  assertLibraryMessageCarries(libraryError.message, CANARY.jsonUnquoted, "json unquoted");

  const error = capture(() => readJsonConfig(path));
  const message = assertFixedTextError(error, { kind: "parse", path, format: "JSON", code: "INVALID_JSON", line: undefined, column: undefined }, [CANARY.jsonUnquoted], "json unquoted");
  assert.equal(message, `Unable to parse config file: invalid JSON in ${path} (INVALID_JSON)`);
});

test("JSON short file: JSON.parse quotes the whole source at 21 characters or fewer; ConfigFileError is fixed text", () => {
  const path = join(tempBase(), "config.json");
  const text = `{"token":${CANARY.jsonShort}}`;
  assert.ok(text.length <= 21, `fixture must be 21 characters or fewer, is ${text.length}`);
  writeFileSync(path, text);

  const libraryError = capture(() => JSON.parse(text));
  assert.ok(libraryError instanceof SyntaxError);
  assert.ok(libraryError.message.includes(text), "positive control: the whole source is quoted");
  assertLibraryMessageCarries(libraryError.message, CANARY.jsonShort, "json short");

  const error = capture(() => readJsonConfig(path));
  const message = assertFixedTextError(error, { kind: "parse", path, format: "JSON", code: "INVALID_JSON", line: undefined, column: undefined }, [CANARY.jsonShort], "json short");
  assert.equal(message, `Unable to parse config file: invalid JSON in ${path} (INVALID_JSON)`);
});

test("JSON offset family: the line and column are derived from the offset and agree with the engine's own", () => {
  const path = join(tempBase(), "config.json");
  const text = `{\n  "token": "${CANARY.jsonTrailingComma}",\n}\n`;
  writeFileSync(path, text);

  const libraryError = capture(() => JSON.parse(text));
  const offsetMatch = /at position (\d+) \(line (\d+) column (\d+)\)/.exec(libraryError.message);
  assert.ok(offsetMatch, `positive control: expected an offset in "${libraryError.message}"`);
  const line = Number(offsetMatch[2]);
  const column = Number(offsetMatch[3]);

  const error = capture(() => readJsonConfig(path));
  const message = assertFixedTextError(error, { kind: "parse", path, format: "JSON", code: "INVALID_JSON", line, column }, [CANARY.jsonTrailingComma], "json offset");
  assert.equal(message, `Unable to parse config file: invalid JSON in ${path} at line ${line}, column ${column} (INVALID_JSON)`);
  assert.equal(line, 3);
});

test("EISDIR: a directory at the path is a read failure carrying the path and the errno code, never the fs wording", () => {
  const path = join(tempBase(), "config.yaml");
  mkdirSync(path);

  const libraryError = capture(() => readFileSync(path, "utf8"));
  assert.equal(libraryError.code, "EISDIR");
  assert.ok(libraryError.message.includes("illegal operation"));

  for (const loader of [readYamlConfig, readJsonConfig, readConfigText]) {
    const error = capture(() => loader(path));
    const message = assertFixedTextError(error, { kind: "read", path, format: undefined, code: "EISDIR", line: undefined, column: undefined }, [], loader.name);
    assert.equal(message, `Unable to read config file ${path} (EISDIR)`);
  }
});

test("EACCES: an unreadable file is a read failure carrying the path and the errno code, never the fs wording", { skip: RUNNING_AS_ROOT ? "running as root, mode 000 is still readable" : false }, () => {
  const path = join(tempBase(), "config.yaml");
  writeFileSync(path, `token: ${CANARY.lockedFile}\n`);
  chmodSync(path, 0o000);
  try {
    const libraryError = capture(() => readFileSync(path, "utf8"));
    assert.equal(libraryError.code, "EACCES");
    assert.ok(libraryError.message.includes("permission denied"));

    for (const loader of [readYamlConfig, readJsonConfig, readConfigText]) {
      const error = capture(() => loader(path));
      const message = assertFixedTextError(error, { kind: "read", path, format: undefined, code: "EACCES", line: undefined, column: undefined }, [CANARY.lockedFile], loader.name);
      assert.equal(message, `Unable to read config file ${path} (EACCES)`);
    }
  } finally {
    chmodSync(path, 0o600);
  }
});

test("ENOENT: a missing file is the explicit missing-file result, not an error", () => {
  const path = join(tempBase(), "missing.yaml");

  const libraryError = capture(() => readFileSync(path, "utf8"));
  assert.equal(libraryError.code, "ENOENT");
  assert.ok(libraryError.message.includes("no such file"));

  for (const loader of [readYamlConfig, readJsonConfig, readConfigText]) {
    assert.deepEqual(loader(path), { ok: false, path, reason: "missing" });
  }
});

test("well-formed files load; a byte order mark is tolerated", () => {
  const base = tempBase();
  const yamlPath = join(base, "config.yaml");
  const jsonPath = join(base, "config.json");
  writeFileSync(yamlPath, "\uFEFFname: demo\nregion: us\nlist:\n  - 1\n  - 2\n");
  writeFileSync(jsonPath, '\uFEFF{"name":"demo","list":[1,2]}');

  assert.deepEqual(readYamlConfig(yamlPath), { ok: true, path: yamlPath, value: { name: "demo", region: "us", list: [1, 2] } });
  assert.deepEqual(readJsonConfig(jsonPath), { ok: true, path: jsonPath, value: { name: "demo", list: [1, 2] } });
  assert.deepEqual(readConfigText(jsonPath), { ok: true, path: jsonPath, value: '\uFEFF{"name":"demo","list":[1,2]}' });
});

test("an unknown YAML tag loads without a process warning, while yaml.parse would emit one that quotes the line", async () => {
  const text = `key: !custom ${CANARY.yamlTag}\n`;
  const warnings = [];
  const onWarning = (warning) => warnings.push(warning);
  process.on("warning", onWarning);
  try {
    assert.deepEqual(parseYaml(text), { key: CANARY.yamlTag });
    await new Promise((resolve) => setImmediate(resolve));
    assert.ok(warnings.length >= 1, "positive control: yaml.parse emits the unresolved-tag warning");
    assert.ok(warnings.some((warning) => carriesFragment(String(warning.message), CANARY.yamlTag)), "positive control: the warning quotes the source line");
    const emitted = warnings.length;

    assert.deepEqual(parseYamlConfigText(text, "/tmp/config.yaml"), { key: CANARY.yamlTag });
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(warnings.length, emitted, "the loader must not emit the warning");
  } finally {
    process.off("warning", onWarning);
  }
});

test("the label option names the integration in both fixed messages and is dropped when it is not a short plain name", () => {
  const base = tempBase();
  const directory = join(base, "config.yaml");
  mkdirSync(directory);
  const readError = capture(() => readYamlConfig(directory, { label: "New Relic" }));
  assert.equal(readError.message, `Unable to read New Relic config file ${directory} (EISDIR)`);

  const parseError = capture(() => parseJsonConfigText("x", "/tmp/config.json", { label: "Zoom" }));
  assert.equal(parseError.message, "Unable to parse Zoom config file: invalid JSON in /tmp/config.json (INVALID_JSON)");

  for (const label of ["two\nlines", "x".repeat(60), "<script>", ""]) {
    const error = capture(() => parseJsonConfigText("x", "/tmp/config.json", { label }));
    assert.equal(error.message, "Unable to parse config file: invalid JSON in /tmp/config.json (INVALID_JSON)", `label ${JSON.stringify(label)} must be dropped`);
  }
});

test("ConfigFileError validates every field it is constructed from", () => {
  const read = new ConfigFileError({ kind: "read", path: "/etc/demo.yaml", code: "ENOENT: no such file or directory, open '/etc/demo.yaml'" });
  assert.equal(read.code, undefined);
  assert.equal(read.format, undefined);
  assert.equal(read.line, undefined);
  assert.equal(read.message, "Unable to read config file /etc/demo.yaml");

  for (const code of ["EISDIR", "EACCES", "ENOTDIR", "ERR_FS_FILE_TOO_LARGE", "ERR_INVALID_ARG_TYPE"]) {
    assert.match(code, SYSTEM_ERROR_CODE_PATTERN);
    assert.equal(new ConfigFileError({ kind: "read", path: "/p", code }).message, `Unable to read config file /p (${code})`);
  }
  for (const code of ["eacces", "E", "ELOWERcase", "INVALID_YAML", "permission denied", `E${"X".repeat(31)}`]) {
    assert.equal(new ConfigFileError({ kind: "read", path: "/p", code }).code, undefined, `${code} is not an errno code`);
  }

  const toml = new ConfigFileError({ kind: "parse", path: "/p", format: "TOML", code: "bad code with spaces", line: 4, column: 2 });
  assert.equal(toml.format, "TOML");
  assert.equal(toml.code, "INVALID_TOML");
  assert.equal(toml.message, "Unable to parse config file: invalid TOML in /p at line 4, column 2 (INVALID_TOML)");

  const parserCode = new ConfigFileError({ kind: "parse", path: "/p", format: "YAML", code: "DUPLICATE_KEY", line: 7 });
  assert.equal(parserCode.code, "DUPLICATE_KEY");
  assert.equal(parserCode.column, undefined);
  assert.equal(parserCode.message, "Unable to parse config file: invalid YAML in /p at line 7 (DUPLICATE_KEY)");

  const badFormat = new ConfigFileError({ kind: "parse", path: "/p", format: "not a format!" });
  assert.equal(badFormat.format, "config");
  assert.equal(badFormat.code, "INVALID_CONFIG");
  assert.equal(badFormat.message, "Unable to parse config file: invalid config in /p (INVALID_CONFIG)");

  for (const position of [{ line: 0, column: 5 }, { line: -1 }, { line: 2.5 }, { line: Number.NaN }, { column: 9 }]) {
    const error = new ConfigFileError({ kind: "parse", path: "/p", format: "JSON", ...position });
    assert.equal(error.line, undefined, `${JSON.stringify(position)} must not yield a line`);
    assert.equal(error.column, undefined);
    assert.equal(error.message, "Unable to parse config file: invalid JSON in /p (INVALID_JSON)");
  }
  const lineOnly = new ConfigFileError({ kind: "parse", path: "/p", format: "JSON", line: 2, column: -1 });
  assert.equal(lineOnly.line, 2);
  assert.equal(lineOnly.column, undefined);
  assert.equal(lineOnly.message, "Unable to parse config file: invalid JSON in /p at line 2 (INVALID_JSON)");

  assert.throws(() => configFileErrorMessage({ kind: "other", path: "/p" }), /Unhandled config file failure kind other/);
});

test("systemErrorCode keeps only errno-shaped codes and never reads a message", () => {
  assert.equal(systemErrorCode(undefined), undefined);
  assert.equal(systemErrorCode(null), undefined);
  assert.equal(systemErrorCode("EACCES"), undefined);
  assert.equal(systemErrorCode({ code: 13 }), undefined);
  assert.equal(systemErrorCode({ code: "eacces" }), undefined);
  assert.equal(systemErrorCode({ code: "EACCES: permission denied" }), undefined);
  assert.equal(systemErrorCode({ message: "EACCES: permission denied" }), undefined);
  assert.equal(systemErrorCode({ code: "EACCES" }), "EACCES");
  assert.equal(systemErrorCode({ code: "ERR_FS_FILE_TOO_LARGE" }), "ERR_FS_FILE_TOO_LARGE");
});

test("yamlErrorPosition and yamlErrorCode answer only for a YAMLError", () => {
  const [libraryError] = parseDocument("a: 1\na: 2\n").errors;
  assert.ok(libraryError instanceof YAMLError);
  assert.deepEqual(yamlErrorPosition(libraryError), { line: 2, column: 1 });
  assert.equal(yamlErrorCode(libraryError), libraryError.code);

  const alias = capture(() => parseYaml("key: *missing\n"));
  assert.equal(yamlErrorPosition(alias), undefined);
  assert.equal(yamlErrorCode(alias), undefined);
  assert.equal(yamlErrorPosition({ linePos: [{ line: 3, col: 4 }] }), undefined, "a foreign object with a linePos is not a YAMLError");
  assert.equal(yamlErrorPosition(new Error("at line 3")), undefined);
});

test("jsonErrorPosition derives the position only from a strict offset match", () => {
  assert.deepEqual(jsonErrorPosition(new SyntaxError("Unexpected non-whitespace character after JSON at position 5"), "12345 6"), { line: 1, column: 6 });
  assert.deepEqual(jsonErrorPosition(new SyntaxError("Expected ',' or '}' after property value in JSON at position 10 (line 3 column 3)"), '{\n"a":1\n  x'), { line: 3, column: 3 });
  assert.equal(jsonErrorPosition(new SyntaxError("Unexpected token 'x', \"x\" is not valid JSON"), "x"), undefined);
  assert.equal(jsonErrorPosition(new SyntaxError("at position 99"), "short"), undefined, "an offset past the end of the source is dropped");
  assert.equal(jsonErrorPosition(new SyntaxError("at position 1234567890"), "x".repeat(20)), undefined, "an implausibly long offset does not match");
  assert.equal(jsonErrorPosition(new Error("at position 1"), "ab"), undefined, "only a SyntaxError is read");
  assert.equal(jsonErrorPosition("at position 1", "ab"), undefined);
});

test("parse helpers accept text from a caller's own read and wrap every thrown value", () => {
  assert.deepEqual(parseYamlConfigText("a: 1\n", "/p"), { a: 1 });
  assert.deepEqual(parseJsonConfigText('{"a":1}', "/p"), { a: 1 });
  assert.equal(parseYamlConfigText("", "/p"), null);

  const yamlError = capture(() => parseYamlConfigText("a: 1\na: 2\n", "/p"));
  assert.ok(yamlError instanceof ConfigFileError);
  assert.equal(yamlError.kind, "parse");
  assert.equal(yamlError.line, 2);

  const jsonError = capture(() => parseJsonConfigText("", "/p"));
  assert.ok(jsonError instanceof ConfigFileError);
  assert.equal(jsonError.code, "INVALID_JSON");
  assert.equal(jsonError.message, "Unable to parse config file: invalid JSON in /p (INVALID_JSON)");
});
