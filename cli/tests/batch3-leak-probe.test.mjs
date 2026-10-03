import test from "node:test";
import assert from "node:assert/strict";

import {
  scrubSecretText as scrubCrowdStrikeError,
} from "../dist/extensions/grc-tools/crowdstrike.js";
import { scrubErrorText as scrubKnowBe4Error } from "../dist/extensions/grc-tools/knowbe4.js";
import { scrubErrorText as scrubQualysError } from "../dist/extensions/grc-tools/qualys.js";
import { redactSecrets as scrubTenableError } from "../dist/extensions/grc-tools/tenable.js";
import { scrubErrorText as scrubVeracodeError } from "../dist/extensions/grc-tools/veracode.js";
import { runLeakProbe } from "./helpers/leak-probe-harness.mjs";

const CONFIGURED_SECRET = "B3pR7vQ2xL9mN4kT8sW6yH1cJ5dF0aZ";

const integrations = [
  {
    name: "CrowdStrike",
    scrub: (text) => scrubCrowdStrikeError(text, [CONFIGURED_SECRET]),
    credentialKeys: ["FALCON_CLIENT_SECRET", "client_secret"],
  },
  {
    name: "Tenable",
    scrub: (text) => scrubTenableError(text, [CONFIGURED_SECRET]),
    credentialKeys: ["TENABLE_ACCESS_KEY", "TENABLE_SECRET_KEY"],
  },
  {
    name: "Qualys",
    scrub: (text) => scrubQualysError(text, [CONFIGURED_SECRET]),
    credentialKeys: ["QUALYS_PASSWORD", "password"],
  },
  {
    name: "Veracode",
    scrub: (text) => scrubVeracodeError(text, [CONFIGURED_SECRET]),
    credentialKeys: ["VERACODE_API_KEY_ID", "VERACODE_API_KEY_SECRET"],
  },
  {
    name: "KnowBe4",
    scrub: scrubKnowBe4Error,
    credentialKeys: ["KNOWBE4_API_TOKEN", "PHISHER_API_TOKEN"],
  },
];

test("batch 3 integration error sinks execute the shared credential leak probe", async () => {
  for (const integration of integrations) {
    const result = await runLeakProbe({
      integration: integration.name,
      textScrubbers: {
        error: [{ name: `${integration.name} error scrubber`, fn: integration.scrub }],
      },
      headerNames: ["Authorization", "Cookie", "X-Api-Key"],
      schemeWords: ["Bearer", "Basic", "Token"],
      credentialKeys: integration.credentialKeys,
      configuredSecrets: [CONFIGURED_SECRET],
    });
    for (const classId of [1, 2, 3, 4, 5, 10]) {
      const outcome = result.classes.find((candidate) => candidate.id === classId);
      assert.ok(outcome && outcome.skipped === null && outcome.cells > 0, `${integration.name}: class ${classId} executed`);
    }
    assert.equal(
      result.leaks.filter((leak) => leak.label.startsWith("configured secret")).length,
      0,
      `${integration.name}: configured secret escaped its error sink`,
    );
  }
});
