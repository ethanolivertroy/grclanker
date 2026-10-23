import test from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { basename, join } from "node:path";
import { fileURLToPath } from "node:url";

import { OSCAL_SCHEMA_ROOT, oscalSchemaErrors, readOscalSchemaManifest, sha256 } from "./helpers/oscal-schema.mjs";

function minimalAssessmentResults() {
  return {
    "assessment-results": {
      uuid: "6f1c2a0e-3b4d-4e5f-8a6b-7c8d9e0f1a2b",
      metadata: {
        title: "Minimal assessment results",
        "last-modified": "2026-10-23T00:00:00.000Z",
        version: "1.0.0",
        "oscal-version": "1.1.2",
      },
      "import-ap": { href: "#assessment-plan" },
      results: [
        {
          uuid: "0a1b2c3d-4e5f-4a6b-9c8d-7e6f5a4b3c2d",
          title: "Result",
          description: "One observation and one finding.",
          start: "2026-10-23T00:00:00.000Z",
          "reviewed-controls": { "control-selections": [{ "include-controls": [{ "control-id": "ia-2.11" }] }] },
          observations: [
            {
              uuid: "1b2c3d4e-5f6a-4b7c-8d9e-0f1a2b3c4d5e",
              description: "Observed.",
              methods: ["TEST"],
              collected: "2026-10-23T00:00:00.000Z",
            },
          ],
          findings: [
            {
              uuid: "2c3d4e5f-6a7b-4c8d-9e0f-1a2b3c4d5e6f",
              title: "Finding",
              description: "Found.",
              target: { type: "objective-id", "target-id": "ia-2.11_obj", status: { state: "satisfied" } },
            },
          ],
        },
      ],
    },
  };
}

test("vendored NIST OSCAL schemas are byte-identical to the release assets pinned in each manifest", () => {
  const versions = readdirSync(OSCAL_SCHEMA_ROOT).sort();
  assert.ok(versions.includes("1.1.2"), "the OSCAL version the Okta export declares is vendored");
  for (const version of versions) {
    const manifest = readOscalSchemaManifest(version);
    assert.ok(manifest, `${version}/manifest.json exists`);
    assert.equal(manifest.oscalVersion, version);
    assert.equal(manifest.release, `https://github.com/usnistgov/OSCAL/releases/tag/v${version}`);
    assert.match(manifest.commit, /^[0-9a-f]{40}$/);

    const vendored = readdirSync(join(OSCAL_SCHEMA_ROOT, version)).filter((name) => name !== "manifest.json").sort();
    assert.deepEqual(vendored, manifest.schemas.map((entry) => entry.file).sort(), `${version}: every vendored file is pinned`);
    for (const entry of manifest.schemas) {
      assert.equal(entry.url, `https://github.com/usnistgov/OSCAL/releases/download/v${version}/${entry.file}`);
      const bytes = readFileSync(join(OSCAL_SCHEMA_ROOT, version, entry.file));
      assert.equal(sha256(bytes), entry.sha256, `${version}/${entry.file} matches the SHA-256 pinned for ${entry.url}`);
      const schema = JSON.parse(bytes.toString("utf8"));
      assert.equal(schema.$schema, "http://json-schema.org/draft-07/schema#");
      assert.ok(schema.$id.startsWith(`http://csrc.nist.gov/ns/oscal/${version}/`), `${entry.file} is the ${version} schema`);
      assert.deepEqual(schema.required, [entry.model]);
    }
  }
});

test("the vendored OSCAL schema rejects documents that break the NIST constraints", () => {
  assert.deepEqual(oscalSchemaErrors(minimalAssessmentResults()), []);

  const cases = [
    ["an empty findings list", (result) => { result.findings = []; }, "/assessment-results/results/0/findings: must NOT have fewer than 1 items"],
    ["an empty observations list", (result) => { result.observations = []; }, "/assessment-results/results/0/observations: must NOT have fewer than 1 items"],
    ["an empty relevant-evidence list", (result) => { result.observations[0]["relevant-evidence"] = []; }, "/assessment-results/results/0/observations/0/relevant-evidence: must NOT have fewer than 1 items"],
    ["a snake_case key", (result) => { result.observations[0].relevant_evidence = [{ description: "x" }]; }, "/assessment-results/results/0/observations/0: must NOT have additional properties (relevant_evidence)"],
    ["a finding state outside the enumeration", (result) => { result.findings[0].target.status.state = "partial"; }, "/assessment-results/results/0/findings/0/target/status/state: must be equal to one of the allowed values"],
    ["a control id with a space", (result) => { result["reviewed-controls"]["control-selections"][0]["include-controls"][0]["control-id"] = "ia-2 11"; }, "/assessment-results/results/0/reviewed-controls/control-selections/0/include-controls/0/control-id: must match pattern \"^(\\p{L}|_)(\\p{L}|\\p{N}|[.\\-_])*$\""],
    ["a timestamp without a timezone", (result) => { result.start = "2026-10-23T00:00:00"; }, "/assessment-results/results/0/start: must match format \"date-time\""],
    ["a missing result description", (result) => { delete result.description; }, "/assessment-results/results/0: must have required property 'description'"],
  ];
  for (const [label, mutate, expected] of cases) {
    const document = minimalAssessmentResults();
    mutate(document["assessment-results"].results[0]);
    assert.ok(oscalSchemaErrors(document).includes(expected), `${label}: ${oscalSchemaErrors(document).join("; ")}`);
  }

  const badUuid = minimalAssessmentResults();
  badUuid["assessment-results"].uuid = "not-a-uuid";
  assert.ok(oscalSchemaErrors(badUuid).some((error) => error.startsWith("/assessment-results/uuid: must match pattern")));

  const undeclared = minimalAssessmentResults();
  undeclared["assessment-results"].metadata["oscal-version"] = "1.0.0";
  assert.throws(() => oscalSchemaErrors(undeclared), /No NIST OSCAL schemas are vendored for oscal-version "1\.0\.0"/);
});

test("every module that writes an oscal-version validates its output against the vendored NIST schema in its tests", () => {
  const extensionsRoot = fileURLToPath(new URL("../extensions/", import.meta.url));
  const generators = readdirSync(extensionsRoot, { recursive: true })
    .filter((name) => name.endsWith(".ts"))
    .filter((name) => /["']oscal-version["']/.test(readFileSync(join(extensionsRoot, name), "utf8")))
    .sort();
  assert.ok(generators.includes(join("grc-tools", "okta.ts")), `the scan finds the Okta OSCAL export: ${generators.join(", ")}`);
  for (const generator of generators) {
    const testFile = fileURLToPath(new URL(`./${basename(generator, ".ts")}.test.mjs`, import.meta.url));
    assert.match(
      readFileSync(testFile, "utf8"),
      /assertValidOscal\(/,
      `${generator} writes OSCAL, so tests/${basename(testFile)} must validate it with assertValidOscal from tests/helpers/oscal-schema.mjs`,
    );
  }
});
