/**
 * Config loader error matrix (coordinator addendum 6 and 6b).
 *
 * A config or credentials file loader must never interpolate the parser's or the filesystem's
 * message: the yaml package quotes the offending source line (and an unresolved alias throws a plain
 * ReferenceError that starts with the alias value), V8's JSON.parse quotes a 10-character window
 * around the failure (or the whole source when it is 21 characters or shorter), and Node's fs errors
 * carry their own wording and path. Every case here runs the library directly first as a positive
 * control, then asserts the loader's thrown message and the check_access tool result carry the
 * fixed text (path, code, line where available) and none of the planted canaries, no 8-character
 * fragment of them, and none of the library wording.
 */
import assert from "node:assert/strict";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parse as parseYaml } from "yaml";

export const LIBRARY_WORDING = [
  "Nested mappings",
  "is not valid JSON",
  "Unresolved alias",
  "illegal operation",
  "permission denied",
  "no such file",
  "Unexpected token",
  "Expected double-quoted",
];

/** Distinct in every 8-character window across the whole set (asserted below at import time). */
export const CONFIG_CANARIES = {
  yamlNestedKey: "QWJHXVZPKMTRYU1",
  yamlNestedBearer: "GBDLNSCFWOAE2XZ",
  yamlAlias: "MZTXQ9RLPVWBHKD",
  jsonUnquoted: "KVRPWLXTHBQNZMY",
  jsonShort: "HXQWZTPRVKL",
  jsonTrailingComma: "NBVCXZLKJHGFDSA",
};

const WINDOW = 8;

function windowsOf(text) {
  const windows = [];
  for (let index = 0; index + WINDOW <= text.length; index += 1) windows.push(text.slice(index, index + WINDOW));
  return windows;
}

(() => {
  const seen = new Map();
  for (const [name, canary] of Object.entries(CONFIG_CANARIES)) {
    for (const window of windowsOf(canary)) {
      const owner = seen.get(window);
      assert.equal(owner, undefined, `canary window ${window} appears in both ${owner} and ${name}`);
      seen.set(window, name);
    }
  }
})();

const FS_CODE = /^E[A-Z0-9_]{1,30}$/;

/** Asserts a rendered string carries no canary, no 8-character fragment of one, and no library wording. */
export function assertConfigErrorTextClean(text, label) {
  assert.equal(typeof text, "string", `${label} is a string`);
  for (const [name, canary] of Object.entries(CONFIG_CANARIES)) {
    assert.equal(text.includes(canary), false, `${label} carries canary ${name}: ${text}`);
    for (const window of windowsOf(canary)) {
      assert.equal(text.includes(window), false, `${label} carries fragment ${window} of canary ${name}: ${text}`);
    }
  }
  for (const wording of LIBRARY_WORDING) {
    assert.equal(text.includes(wording), false, `${label} carries library wording "${wording}": ${text}`);
  }
}

function captureError(run) {
  try {
    run();
  } catch (error) {
    return error;
  }
  assert.fail("expected the positive control to throw");
}

function lineOfPosition(text, position) {
  return text.slice(0, position).split("\n").length;
}

/**
 * Builds the matrix for one loader in a fresh scratch directory.
 *
 * @param {object} options
 * @param {"yaml" | "json" | "toml"} options.format the loader's file format
 * @param {string} options.displayName the integration name used in the fixed text ("ServiceNow")
 * @param {string} options.fileNoun "config file" or "credentials file"
 * @param {string} options.extension file extension including the dot
 * @returns {Array<{ name: string, path: string, expectedMessage: string, expectedCode: string, skip?: string }>}
 */
export function configLoaderCases({ format, displayName, fileNoun, extension }) {
  const scratch = mkdtempSync(join(tmpdir(), `grclanker-${displayName.toLowerCase()}-loader-`));
  const readMessage = (path, code) => `Unable to read ${displayName} ${fileNoun} ${path} (${code})`;
  const parseMessage = (path, line) => `Unable to parse ${displayName} ${fileNoun}: invalid ${format.toUpperCase()} in ${path}${line ? ` at line ${line}` : ""}`;
  const parseCode = `INVALID_${format.toUpperCase()}`;
  const cases = [];

  if (format === "yaml") {
    const nestedPath = join(scratch, `nested-mapping${extension}`);
    const nestedText = `servicenow:\n  token: ${CONFIG_CANARIES.yamlNestedKey}: Bearer ${CONFIG_CANARIES.yamlNestedBearer}\n`;
    writeFileSync(nestedPath, nestedText);
    const nestedControl = captureError(() => parseYaml(nestedText));
    assert.match(nestedControl.message, /Nested mappings/, "positive control: yaml quotes the nested mapping");
    assert.ok(nestedControl.message.includes(CONFIG_CANARIES.yamlNestedKey), "positive control: yaml quotes the source line with the canary");
    assert.ok(nestedControl.message.includes(CONFIG_CANARIES.yamlNestedBearer), "positive control: yaml quotes the bearer canary");
    cases.push({ name: "yaml nested mapping", path: nestedPath, expectedMessage: parseMessage(nestedPath, nestedControl.linePos[0].line), expectedCode: parseCode });

    const aliasPath = join(scratch, `alias${extension}`);
    const aliasText = `servicenow:\n  token: *${CONFIG_CANARIES.yamlAlias}\n`;
    writeFileSync(aliasPath, aliasText);
    const aliasControl = captureError(() => parseYaml(aliasText));
    assert.equal(aliasControl instanceof ReferenceError, true, "positive control: an unresolved alias is a plain ReferenceError");
    assert.equal(aliasControl.linePos, undefined, "positive control: the ReferenceError has no linePos");
    assert.ok(aliasControl.message.includes(CONFIG_CANARIES.yamlAlias), "positive control: the alias message starts with the alias value");
    cases.push({ name: "yaml unresolved alias", path: aliasPath, expectedMessage: parseMessage(aliasPath, undefined), expectedCode: parseCode });
  }

  if (format === "json") {
    const unquotedPath = join(scratch, `unquoted${extension}`);
    const unquotedText = `{\n  "token": ${CONFIG_CANARIES.jsonUnquoted}\n}\n`;
    writeFileSync(unquotedPath, unquotedText);
    const unquotedControl = captureError(() => JSON.parse(unquotedText));
    assert.match(unquotedControl.message, /is not valid JSON/, "positive control: JSON.parse quotes a window of the source");
    assert.ok(unquotedControl.message.includes(CONFIG_CANARIES.jsonUnquoted.slice(0, 8)), "positive control: the window carries the first characters of the canary");
    const unquotedPosition = /at position (\d+)/.exec(unquotedControl.message);
    cases.push({
      name: "json unquoted value",
      path: unquotedPath,
      expectedMessage: parseMessage(unquotedPath, unquotedPosition ? lineOfPosition(unquotedText, Number(unquotedPosition[1])) : undefined),
      expectedCode: parseCode,
    });

    const shortPath = join(scratch, `short${extension}`);
    const shortText = `{"token":${CONFIG_CANARIES.jsonShort}}`;
    assert.ok(shortText.length <= 21, "the short file is 21 characters or fewer so JSON.parse quotes the whole source");
    writeFileSync(shortPath, shortText);
    const shortControl = captureError(() => JSON.parse(shortText));
    assert.ok(shortControl.message.includes(CONFIG_CANARIES.jsonShort.slice(0, 8)), "positive control: JSON.parse quotes the short source");
    cases.push({ name: "json short source", path: shortPath, expectedMessage: parseMessage(shortPath, undefined), expectedCode: parseCode });

    const trailingPath = join(scratch, `trailing-comma${extension}`);
    const trailingText = `{\n  "token": "${CONFIG_CANARIES.jsonTrailingComma}",\n}\n`;
    writeFileSync(trailingPath, trailingText);
    const trailingControl = captureError(() => JSON.parse(trailingText));
    const trailingPosition = /at position (\d+)/.exec(trailingControl.message);
    assert.ok(trailingPosition, "positive control: this JSON.parse family reports a position");
    cases.push({
      name: "json trailing comma with position",
      path: trailingPath,
      expectedMessage: parseMessage(trailingPath, lineOfPosition(trailingText, Number(trailingPosition[1]))),
      expectedCode: parseCode,
    });
  }

  const directoryPath = join(scratch, `directory${extension}`);
  mkdirSync(directoryPath);
  const eisdirControl = captureError(() => readFileSync(directoryPath, "utf8"));
  assert.equal(eisdirControl.code, "EISDIR");
  assert.match(eisdirControl.message, /illegal operation/, "positive control: fs wording for EISDIR");
  cases.push({ name: "EISDIR", path: directoryPath, expectedMessage: readMessage(directoryPath, "EISDIR"), expectedCode: "EISDIR" });

  const lockedPath = join(scratch, `locked${extension}`);
  writeFileSync(lockedPath, format === "json" ? "{}\n" : "");
  chmodSync(lockedPath, 0);
  const eaccesControl = captureError(() => readFileSync(lockedPath, "utf8"));
  if (eaccesControl.code === "EACCES") {
    assert.match(eaccesControl.message, /permission denied/, "positive control: fs wording for EACCES");
    cases.push({ name: "EACCES", path: lockedPath, expectedMessage: readMessage(lockedPath, "EACCES"), expectedCode: "EACCES" });
  } else {
    cases.push({ name: "EACCES", path: lockedPath, skip: "mode 000 is readable by this user (root)", expectedMessage: "", expectedCode: "EACCES" });
  }

  const missingPath = join(scratch, `missing${extension}`);
  const enoentControl = captureError(() => readFileSync(missingPath, "utf8"));
  assert.equal(enoentControl.code, "ENOENT");
  assert.ok(enoentControl.message.includes(missingPath), "positive control: fs quotes the path for ENOENT");
  cases.push({ name: "ENOENT on an explicit path", path: missingPath, expectedMessage: readMessage(missingPath, "ENOENT"), expectedCode: "ENOENT" });

  for (const item of cases) {
    if (!item.skip) assert.match(item.expectedCode, FS_CODE.test(item.expectedCode) ? FS_CODE : /^INVALID_(YAML|JSON|TOML)$/);
  }
  return cases;
}

/**
 * Runs the matrix: `resolve(path)` must throw the fixed-text error; `checkAccess(path)` must return
 * the tool result whose text carries the same fixed text and nothing from the file or the library.
 */
export async function assertConfigLoaderMatrix(cases, { resolve, checkAccess }) {
  for (const item of cases) {
    if (item.skip) continue;
    const label = `${item.name} (${item.path})`;
    let thrown;
    try {
      resolve(item.path);
    } catch (error) {
      thrown = error;
    }
    assert.ok(thrown, `${label}: the resolver throws`);
    assert.equal(thrown.message, item.expectedMessage, `${label}: fixed text`);
    assert.equal(thrown.code, item.expectedCode, `${label}: code`);
    assertConfigErrorTextClean(thrown.message, `${label}: resolver message`);
    assertConfigErrorTextClean(String(thrown), `${label}: resolver String(error)`);

    const result = await checkAccess(item.path);
    assert.equal(result.isError, true, `${label}: check_access reports an error`);
    const text = result.content.map((part) => part.text ?? "").join("\n");
    assert.ok(text.includes(item.expectedMessage), `${label}: check_access carries the fixed text: ${text}`);
    assertConfigErrorTextClean(text, `${label}: check_access text`);
    assertConfigErrorTextClean(JSON.stringify(result.details ?? {}), `${label}: check_access details`);
  }
}
