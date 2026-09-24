/**
 * Helpers for asserting what an exported evidence bundle would reveal once
 * shared: every file written under the bundle directory, and every entry of
 * the paired zip archive after inflation (archiver deflates entries, so the
 * raw zip bytes never contain plaintext and cannot be searched directly).
 */
import { readdirSync, readFileSync } from "node:fs";
import { join, relative } from "node:path";
import { inflateRawSync } from "node:zlib";

const END_OF_CENTRAL_DIRECTORY = 0x06054b50;
const CENTRAL_DIRECTORY_HEADER = 0x02014b50;
const LOCAL_FILE_HEADER = 0x04034b50;
const STORED = 0;
const DEFLATED = 8;

/** Returns a Map of bundle-relative path to UTF-8 contents for every file under rootDir. */
export function readBundleFiles(rootDir) {
  const files = new Map();
  const walk = (dir) => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const pathname = join(dir, entry.name);
      if (entry.isDirectory()) walk(pathname);
      else if (entry.isFile()) files.set(relative(rootDir, pathname), readFileSync(pathname, "utf8"));
    }
  };
  walk(rootDir);
  return files;
}

function findEndOfCentralDirectory(buffer) {
  for (let offset = buffer.length - 22; offset >= 0; offset -= 1) {
    if (buffer.readUInt32LE(offset) === END_OF_CENTRAL_DIRECTORY) return offset;
  }
  throw new Error("zip: end of central directory record not found");
}

/** Returns a Map of entry name to inflated UTF-8 contents for every file entry in the zip. */
export function readZipEntries(zipPath) {
  const buffer = readFileSync(zipPath);
  const endRecord = findEndOfCentralDirectory(buffer);
  const entryCount = buffer.readUInt16LE(endRecord + 10);
  let offset = buffer.readUInt32LE(endRecord + 16);
  const entries = new Map();
  for (let index = 0; index < entryCount; index += 1) {
    if (buffer.readUInt32LE(offset) !== CENTRAL_DIRECTORY_HEADER) throw new Error(`zip: bad central directory header at ${offset}`);
    const method = buffer.readUInt16LE(offset + 10);
    const compressedSize = buffer.readUInt32LE(offset + 20);
    const nameLength = buffer.readUInt16LE(offset + 28);
    const extraLength = buffer.readUInt16LE(offset + 30);
    const commentLength = buffer.readUInt16LE(offset + 32);
    const localHeaderOffset = buffer.readUInt32LE(offset + 42);
    const name = buffer.toString("utf8", offset + 46, offset + 46 + nameLength);
    if (buffer.readUInt32LE(localHeaderOffset) !== LOCAL_FILE_HEADER) throw new Error(`zip: bad local file header for ${name}`);
    const dataStart = localHeaderOffset + 30 + buffer.readUInt16LE(localHeaderOffset + 26) + buffer.readUInt16LE(localHeaderOffset + 28);
    const data = buffer.subarray(dataStart, dataStart + compressedSize);
    if (!name.endsWith("/")) {
      if (method === STORED) entries.set(name, data.toString("utf8"));
      else if (method === DEFLATED) entries.set(name, inflateRawSync(data).toString("utf8"));
      else throw new Error(`zip: unsupported compression method ${method} for ${name}`);
    }
    offset += 46 + nameLength + extraLength + commentLength;
  }
  return entries;
}

/** Asserts through the supplied assert module that no secret appears whole in any file or zip entry. */
export function assertSecretsAbsent(assert, contents, secrets, label) {
  for (const [name, text] of contents) {
    for (const secret of secrets) {
      assert.ok(!text.includes(secret), `${label}: ${secret} appears in ${name}`);
    }
  }
}

/**
 * The fragment-window form of the scan: no substring of any planted secret at lengths 6 through 24
 * appears in any file or zip entry. Planted secrets must be alphanumeric and random-looking (see
 * planted-values.mjs) so no window can coincide with a legitimate value.
 */
export { assertSecretFragmentsAbsent } from "./planted-values.mjs";
