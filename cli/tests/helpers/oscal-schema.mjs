/**
 * Validates OSCAL documents against the NIST OSCAL JSON schemas vendored under
 * tests/fixtures/oscal/<version>/, using the version each document declares in
 * metadata.oscal-version. Every schema file must match the SHA-256 pinned next to
 * its source URL in that version's manifest.json. Schemas load on first use, so a
 * test file can import this helper where the fixtures are not checked out.
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import Ajv from "ajv";
import addFormats from "ajv-formats";

export const OSCAL_SCHEMA_ROOT = fileURLToPath(new URL("../fixtures/oscal/", import.meta.url));

const validatorsByVersion = new Map();

export function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

/** The manifest of the schemas vendored for one OSCAL version, or null when that version has none. */
export function readOscalSchemaManifest(version) {
  const pathname = join(OSCAL_SCHEMA_ROOT, version, "manifest.json");
  return existsSync(pathname) ? JSON.parse(readFileSync(pathname, "utf8")) : null;
}

function compileVersion(version) {
  const manifest = /^\d+\.\d+\.\d+$/.test(version) ? readOscalSchemaManifest(version) : null;
  if (!manifest) {
    throw new Error(`No NIST OSCAL schemas are vendored for oscal-version ${JSON.stringify(version)}; add them under tests/fixtures/oscal/<version>/ with a manifest.json`);
  }
  const ajv = new Ajv({ allErrors: true, strict: true });
  addFormats(ajv);
  const validators = new Map();
  for (const entry of manifest.schemas) {
    const bytes = readFileSync(join(OSCAL_SCHEMA_ROOT, version, entry.file));
    const digest = sha256(bytes);
    if (digest !== entry.sha256) {
      throw new Error(`${version}/${entry.file} has SHA-256 ${digest}, not the ${entry.sha256} pinned for ${entry.url}`);
    }
    validators.set(entry.model, ajv.compile(JSON.parse(bytes.toString("utf8"))));
  }
  return validators;
}

function validatorFor(model, version) {
  if (!validatorsByVersion.has(version)) validatorsByVersion.set(version, compileVersion(version));
  const validate = validatorsByVersion.get(version).get(model);
  if (!validate) throw new Error(`No NIST OSCAL ${version} schema is vendored for the ${model} model`);
  return validate;
}

/**
 * Schema errors for the JSON serialization of an OSCAL document, as "<instance path>: <message>"
 * lines, or [] when the document is valid for its model and declared OSCAL version.
 */
export function oscalSchemaErrors(document) {
  const serialized = JSON.parse(JSON.stringify(document));
  const model = Object.keys(serialized).find((key) => key !== "$schema");
  const validate = validatorFor(model, serialized[model]?.metadata?.["oscal-version"]);
  if (validate(serialized)) return [];
  return validate.errors.map((error) => {
    const detail = error.keyword === "additionalProperties" ? ` (${error.params.additionalProperty})` : "";
    return `${error.instancePath || "/"}: ${error.message}${detail}`;
  });
}

export function assertValidOscal(document, label) {
  assert.deepEqual(oscalSchemaErrors(document), [], `${label} is not valid against the NIST OSCAL JSON schema`);
}
