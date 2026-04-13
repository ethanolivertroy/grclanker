import test from "node:test";
import assert from "node:assert/strict";

import { clearGrcSharedCachesForTests } from "../dist/extensions/grc-tools/shared.js";
import {
  findMatchingScfControls,
  loadScfControlBundle,
  loadScfFrameworkCrosswalk,
  resolveScfFrameworkMatch,
} from "../dist/extensions/grc-tools/scf.js";

function jsonResponse(payload) {
  return new Response(JSON.stringify(payload), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
}

test("findMatchingScfControls matches IDs, evidence refs, and crosswalk values", () => {
  const controls = [
    {
      control_id: "GOV-01",
      title: "Security, Compliance & Resilience Program",
      family: "GOV",
      family_name: "Governance",
      description: "Governance control",
      evidence_requests: ["E-GOV-01"],
      crosswalks: { "general-nist-800-53-r5-2": ["PM-01"] },
    },
    {
      control_id: "IAM-02",
      title: "Identity proofing",
      family: "IAM",
      family_name: "Identity",
      description: "Identity control",
      evidence_requests: ["E-IAM-01"],
      crosswalks: { "general-nist-800-53-r5-2": ["IA-02"] },
    },
  ];

  assert.deepEqual(
    findMatchingScfControls(controls, "PM-01").map((control) => control.control_id),
    ["GOV-01"],
  );
  assert.deepEqual(
    findMatchingScfControls(controls, "E-IAM-01").map((control) => control.control_id),
    ["IAM-02"],
  );
  assert.deepEqual(
    findMatchingScfControls(controls, "governance").map((control) => control.control_id),
    ["GOV-01"],
  );
});

test("resolveScfFrameworkMatch supports exact and unique partial matches", () => {
  const frameworks = [
    {
      framework_id: "general-nist-800-53-r5-2",
      display_name: "NIST SP 800-53 R5",
      scf_controls_mapped: 100,
      framework_controls_mapped: 200,
    },
    {
      framework_id: "general-nist-800-171-r3",
      display_name: "NIST SP 800-171 R3",
      scf_controls_mapped: 90,
      framework_controls_mapped: 150,
    },
    {
      framework_id: "general-iso-27001-2022",
      display_name: "ISO 27001:2022",
      scf_controls_mapped: 150,
      framework_controls_mapped: 120,
    },
  ];

  assert.equal(
    resolveScfFrameworkMatch(frameworks, "general-nist-800-53-r5-2").framework_id,
    "general-nist-800-53-r5-2",
  );
  assert.equal(
    resolveScfFrameworkMatch(frameworks, "iso 27001").framework_id,
    "general-iso-27001-2022",
  );
  assert.throws(
    () => resolveScfFrameworkMatch(frameworks, "nist"),
    /multiple SCF frameworks/i,
  );
});

test("loadScfControlBundle assembles control details, objectives, evidence requests, and framework mappings", async () => {
  const originalFetch = globalThis.fetch;
  const calls = [];

  globalThis.fetch = async (input) => {
    const url = typeof input === "string" ? input : input.toString();
    calls.push(url);

    if (url.endsWith("/controls/GOV-01.json")) {
      return jsonResponse({
        control_id: "GOV-01",
        title: "Security, Compliance & Resilience Program",
        family: "GOV",
        family_name: "Governance",
        description: "Governance control",
        evidence_requests: ["E-GOV-01"],
        crosswalks: { "general-nist-800-53-r5-2": ["PM-01"] },
      });
    }

    if (url.endsWith("/assessment-objectives/GOV-01.json")) {
      return jsonResponse({
        scf_control_id: "GOV-01",
        total: 1,
        assessment_objectives: [
          {
            scf_control_id: "GOV-01",
            ao_id: "GOV-01_A01",
            objective: "An organization-wide governance program is developed.",
          },
        ],
      });
    }

    if (url.endsWith("/evidence-requests/E-GOV-01.json")) {
      return jsonResponse({
        erl_id: "E-GOV-01",
        area: "Cybersecurity & Data Protection Management",
        artifact_name: "Charter - Cybersecurity Program",
        artifact_description: "Documented evidence of a charter.",
        scf_controls: ["GOV-01"],
        cmmc_mapping: "",
      });
    }

    if (url.endsWith("/crosswalks.json")) {
      return jsonResponse({
        total_frameworks: 1,
        frameworks: [
          {
            framework_id: "general-nist-800-53-r5-2",
            display_name: "NIST SP 800-53 R5",
            scf_controls_mapped: 100,
            framework_controls_mapped: 200,
          },
        ],
      });
    }

    return new Response("not found", { status: 404, statusText: "Not Found" });
  };

  clearGrcSharedCachesForTests();

  try {
    const bundle = await loadScfControlBundle("GOV-01", "nist 800-53");
    assert.equal(bundle.control.control_id, "GOV-01");
    assert.equal(bundle.assessment_objectives.length, 1);
    assert.equal(bundle.evidence_requests.length, 1);
    assert.equal(bundle.framework?.framework_id, "general-nist-800-53-r5-2");
    assert.deepEqual(bundle.framework_mappings, ["PM-01"]);
    assert.ok(calls.some((url) => url.endsWith("/controls/GOV-01.json")));
    assert.ok(calls.some((url) => url.endsWith("/crosswalks.json")));
  } finally {
    globalThis.fetch = originalFetch;
    clearGrcSharedCachesForTests();
  }
});

test("loadScfFrameworkCrosswalk resolves framework query and fetches mapping file", async () => {
  const originalFetch = globalThis.fetch;

  globalThis.fetch = async (input) => {
    const url = typeof input === "string" ? input : input.toString();

    if (url.endsWith("/crosswalks.json")) {
      return jsonResponse({
        total_frameworks: 1,
        frameworks: [
          {
            framework_id: "general-nist-800-53-r5-2",
            display_name: "NIST SP 800-53 R5",
            scf_controls_mapped: 100,
            framework_controls_mapped: 200,
          },
        ],
      });
    }

    if (url.endsWith("/crosswalks/general-nist-800-53-r5-2.json")) {
      return jsonResponse({
        display_name: "NIST SP 800-53 R5",
        framework_id: "general-nist-800-53-r5-2",
        scf_to_framework: {
          total_mappings: 1,
          mappings: {
            "GOV-01": ["PM-01"],
          },
        },
        framework_to_scf: {
          total_mappings: 1,
          mappings: {
            "PM-01": ["GOV-01", "GOV-02"],
          },
        },
      });
    }

    return new Response("not found", { status: 404, statusText: "Not Found" });
  };

  clearGrcSharedCachesForTests();

  try {
    const result = await loadScfFrameworkCrosswalk("NIST 800-53");
    assert.equal(result.framework.framework_id, "general-nist-800-53-r5-2");
    assert.deepEqual(result.crosswalk.scf_to_framework.mappings["GOV-01"], ["PM-01"]);
    assert.deepEqual(result.crosswalk.framework_to_scf.mappings["PM-01"], ["GOV-01", "GOV-02"]);
  } finally {
    globalThis.fetch = originalFetch;
    clearGrcSharedCachesForTests();
  }
});
