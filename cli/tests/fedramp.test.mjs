import test from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  clearFedrampCachesForTests,
  inspectFedrampOfficialSources,
  loadFedrampCatalog,
  normalizeFedrampApplicability,
  normalizeFedrampConsolidatedRules,
  resolveFedrampKsi,
  resolveFedrampProcess,
  resolveFedrampRequirement,
  searchFedrampCatalog,
} from "../dist/extensions/grc-tools/fedramp-source.js";
import { buildFedrampDocsSnapshot } from "../dist/extensions/grc-tools/fedramp-docs.js";
import {
  persistentCachesEnabled,
  runWithoutPersistentCaches,
} from "../dist/extensions/grc-tools/shared.js";
import {
  buildFedrampAdsSite,
  buildFedrampAdsStarterBundle,
  buildFedrampAdsPackagePlan,
  buildFedrampArtifactPlan,
  buildFedrampReadinessBrief,
  generateFedrampAdsSite,
  generateFedrampAdsStarterBundle,
  inferFedrampArtifactSuggestions,
  inferFedrampWorkstreams,
} from "../dist/extensions/grc-tools/fedramp.js";

function jsonResponse(payload) {
  return new Response(JSON.stringify(payload), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
}

const consolidatedRulesFixture = {
  info: {
    title: "FedRAMP Consolidated Rules for 2026",
    description: "Fixture consolidated rules payload",
    version: "2026.07.02.02",
    last_updated: "2026-07-02",
  },
  FRD: {
    data: {
      all: {
        "FRD-ACV": {
          term: "Accepted Vulnerability",
          alts: ["accepted vulnerability", "accepted vulnerabilities"],
          definition: "A vulnerability the provider does not intend to remediate within the recommended period.",
          updated: [{ date: "2026-06-24", comment: "Official consolidated rules launch." }],
        },
      },
    },
  },
  FRR: {
    CDS: {
      info: {
        name: "Certification Data Sharing",
        short_name: "CDS",
        web_name: "certification-data-sharing",
        purpose: "Providers share certification data in human-readable and machine-readable form.",
        status: "stable",
        tag: "transparency",
        subsets: {
          CSO: {
            name: "General Provider Responsibilities",
            description: "Applies to all providers.",
            applicability: {
              types: ["20x", "Rev5"],
              paths: ["Program", "Agency"],
              classes: ["B", "C", "D"],
              affects: ["Providers"],
            },
          },
        },
        "20x": {
          subsets: {
            TRC: {
              name: "Trust Center Responsibilities",
              description: "Applies to provider trust centers.",
              applicability: {
                types: ["20x"],
                paths: ["Program"],
                classes: ["B", "C"],
                affects: ["Providers"],
              },
            },
          },
          effective: {
            is: "required",
            current_status: "Consolidated Rules for 2026",
            date: {
              obtain: "2026-01-05",
              maintain: "2026-01-05",
              grace: { default: "2026-07-01", until_next_assessment: false },
            },
          },
        },
        rev5: {
          effective: {
            is: "optional",
            current_status: "Public Preview",
            date: { optional_adoption: "2026-06-24" },
          },
        },
      },
      data: {
        all: {
          CSO: {
            "CDS-CSO-PUB": {
              name: "Public Information",
              statement:
                "Providers MUST publicly share up-to-date information about the cloud service offering in both human-readable and machine-readable formats.",
              force: "MUST",
              affects: ["Providers"],
              terms: ["Cloud Service Offering", "Machine-Readable"],
              following_information: ["Direct link to the FedRAMP Marketplace", "Service Model"],
              updated: [{ date: "2026-06-24", comment: "Official consolidated rules launch." }],
            },
          },
        },
        "20x": {
          TRC: {
            "CDS-TRC-API": {
              name: "Programmatic Access",
              statement:
                "Providers MUST provide documented programmatic access to all certification data.",
              force: "MUST",
              affects: ["Providers"],
              terms: ["Certification data", "Machine-Readable"],
              updated: [{ date: "2026-06-24", comment: "Official consolidated rules launch." }],
            },
          },
        },
        rev5: {
          CSO: {
            "CDS-CSO-BETA": {
              name: "Rev5 Preview Adoption",
              statement: "Rev5 providers SHOULD notify FedRAMP before adopting preview rules.",
              force: "SHOULD",
              affects: ["Providers"],
              terms: ["Certification data"],
              timeframe_type: "days",
              timeframe_num: 7,
              updated: [{ date: "2026-06-24", comment: "Official consolidated rules launch." }],
            },
          },
        },
      },
    },
    CCM: {
      info: {
        name: "Collaborative Continuous Monitoring",
        short_name: "CCM",
        web_name: "collaborative-continuous-monitoring",
        purpose: "Providers and agencies review ongoing certification evidence.",
        status: "stable",
        effective: {
          is: "required",
          current_status: "Consolidated Rules for 2026",
          date: { obtain: "2026-01-05", maintain: "2026-01-05" },
        },
        subsets: {
          QTR: {
            name: "Quarterly Review",
            description: "Quarterly review requirements.",
            applicability: {
              types: ["20x", "Rev5"],
              paths: ["Program", "Agency"],
              classes: ["A", "B", "C", "D"],
              affects: ["Providers"],
            },
          },
        },
      },
      data: {
        all: {
          QTR: {
            "CCM-QTR-MTG": {
              name: "Quarterly Review Meeting",
              varies_by_class: {
                a: {
                  statement: "Class A providers MAY host a quarterly review.",
                  force: "MAY",
                },
                b: {
                  statement: "Class B providers SHOULD host a quarterly review.",
                  force: "SHOULD",
                },
                c: {
                  statement: "Class C providers MUST host a quarterly review.",
                  force: "MUST",
                },
                d: {
                  statement: "Class D providers MUST host a quarterly review.",
                  force: "MUST",
                },
              },
              affects: ["Providers"],
              updated: [{ date: "2026-06-24", comment: "Official consolidated rules launch." }],
            },
          },
        },
      },
    },
  },
  KSI: {
    CNA: {
      id: "KSI-CNA",
      name: "Cloud Native Architecture",
      short_name: "CNA",
      web_name: "cloud-native-architecture",
      status: "stable",
      indicators: {
        "KSI-CNA-CDS": {
          name: "Certification Data Sharing",
          statement:
            "Determine how certification data will be shared with all necessary parties in alignment with the CDS process.",
          reference: "Certification Data Sharing",
          reference_url: "https://www.fedramp.gov/2026/reference/certification-data-sharing/",
          controls: ["ac-3", "au-2", "ra-5"],
          terms: ["Certification data", "All Necessary Parties"],
          updated: [{ date: "2026-06-24", comment: "Official consolidated rules launch." }],
        },
        "KSI-CNA-EIS": {
          name: "Enforcing Intended State",
          varies_by_class: {
            b: { statement: "Optional automated enforcement is available for Class B." },
            c: { statement: "Automated enforcement is required for Class C." },
          },
          controls: ["cm-3"],
          updated: [{ date: "2026-06-24", comment: "Official consolidated rules launch." }],
        },
      },
    },
  },
};

test("normalizeFedrampConsolidatedRules flattens 2026 rules and preserves class variants", () => {
  const catalog = normalizeFedrampConsolidatedRules(consolidatedRulesFixture);

  assert.equal(catalog.info.version, "2026.07.02.02");
  assert.equal(catalog.definitions.length, 1);
  assert.equal(catalog.processes.length, 2);
  assert.equal(catalog.requirements.length, 4);
  assert.equal(catalog.ksiDomains.length, 1);
  assert.equal(catalog.ksiIndicators.length, 2);
  assert.equal(catalog.requirements.find((item) => item.id === "CDS-CSO-PUB")?.appliesTo, "both");
  assert.equal(catalog.processes.find((item) => item.id === "CDS")?.labels.length, 2);
  const classRule = catalog.requirements.find((item) => item.id === "CCM-QTR-MTG");
  assert.equal(classRule?.primaryKeyWord, "VARIES BY CLASS");
  assert.equal(classRule?.classVariants.length, 4);
  assert.match(classRule?.statement ?? "", /Class C providers MUST/);
  assert.equal(
    catalog.ksiIndicators.find((item) => item.id === "KSI-CNA-EIS")?.classVariants.length,
    2,
  );
});

test("search and resolvers support current IDs, unique names, and legacy process aliases", () => {
  const catalog = normalizeFedrampConsolidatedRules(consolidatedRulesFixture);

  const fkaMatch = searchFedrampCatalog(catalog, "CDS-CSO-PUB", {
    section: "requirement",
    appliesTo: normalizeFedrampApplicability("any"),
    limit: 10,
  });
  assert.equal(fkaMatch[0]?.id, "CDS-CSO-PUB");

  assert.equal(resolveFedrampProcess(catalog, "certification-data-sharing").id, "CDS");
  assert.equal(resolveFedrampProcess(catalog, "ADS").id, "CDS");
  assert.equal(resolveFedrampRequirement(catalog, "CDS-CSO-PUB").id, "CDS-CSO-PUB");

  const ksiMatch = resolveFedrampKsi(catalog, "KSI-CNA-EIS");
  assert.equal(ksiMatch.kind, "indicator");
  if (ksiMatch.kind === "indicator") {
    assert.equal(ksiMatch.indicator.id, "KSI-CNA-EIS");
  }
});

test("loadFedrampCatalog writes cache and falls back to stale disk data if refresh fails", async () => {
  const originalFetch = globalThis.fetch;
  const homeDir = mkdtempSync(join(tmpdir(), "grclanker-fedramp-home-"));
  const calls = [];

  globalThis.fetch = async (input) => {
    const url = typeof input === "string" ? input : input.toString();
    calls.push(url);

    if (url === "https://raw.githubusercontent.com/FedRAMP/rules/main/fedramp-consolidated-rules.json") {
      return jsonResponse(consolidatedRulesFixture);
    }

    if (url === "https://api.github.com/repos/FedRAMP/rules") {
      return jsonResponse({
        html_url: "https://github.com/FedRAMP/rules",
        updated_at: "2026-04-13T17:52:17Z",
        default_branch: "main",
      });
    }

    if (
      url ===
      "https://api.github.com/repos/FedRAMP/rules/contents/fedramp-consolidated-rules.json?ref=main"
    ) {
      return jsonResponse({
        sha: "abcdef1234567890abcdef1234567890abcdef12",
        html_url:
          "https://github.com/FedRAMP/rules/blob/main/fedramp-consolidated-rules.json",
      });
    }

    return new Response("not found", { status: 404, statusText: "Not Found" });
  };

  clearFedrampCachesForTests();

  try {
    const live = await loadFedrampCatalog({ refresh: true, homeDir });
    assert.equal(live.cacheStatus, "live");
    assert.equal(live.provenance.blobSha, "abcdef1234567890abcdef1234567890abcdef12");
    assert.ok(calls.some((url) => url.includes("fedramp-consolidated-rules.json")));

    clearFedrampCachesForTests();
    globalThis.fetch = async () => {
      throw new Error("network unavailable");
    };

    const stale = await loadFedrampCatalog({ refresh: true, homeDir });
    assert.equal(stale.cacheStatus, "stale");
    assert.match(stale.notes[0] ?? "", /stale FedRAMP cache/i);
    assert.equal(stale.catalog.info.version, "2026.07.02.02");
  } finally {
    globalThis.fetch = originalFetch;
    clearFedrampCachesForTests();
    rmSync(homeDir, { recursive: true, force: true });
  }
});

test("loadFedrampCatalog and inspectFedrampOfficialSources keep caches in memory when persistent caches are disabled", async () => {
  const originalFetch = globalThis.fetch;
  const homeDir = join(mkdtempSync(join(tmpdir(), "grclanker-fedramp-nopersist-")), ".grclanker");
  const fedrampStateDir = join(homeDir, ".state", "fedramp");

  globalThis.fetch = async (input) => {
    const url = typeof input === "string" ? input : input.toString();
    if (url === "https://raw.githubusercontent.com/FedRAMP/rules/main/fedramp-consolidated-rules.json") {
      return jsonResponse(consolidatedRulesFixture);
    }
    return new Response("not found", { status: 404, statusText: "Not Found" });
  };

  clearFedrampCachesForTests();

  try {
    assert.equal(persistentCachesEnabled(), true);

    const status = await runWithoutPersistentCaches(async () => {
      assert.equal(persistentCachesEnabled(), false);
      const catalog = await loadFedrampCatalog({ refresh: true, homeDir });
      assert.equal(catalog.cacheStatus, "live");
      return inspectFedrampOfficialSources({ refresh: true, homeDir });
    });

    assert.equal(status.cacheStatus, "live");
    assert.equal(persistentCachesEnabled(), true);
    assert.equal(existsSync(homeDir), false, "dry runs must not create the grclanker home");

    clearFedrampCachesForTests();
    await loadFedrampCatalog({ refresh: true, homeDir });
    assert.equal(existsSync(join(fedrampStateDir, "catalog.json")), true);
  } finally {
    globalThis.fetch = originalFetch;
    clearFedrampCachesForTests();
    rmSync(join(homeDir, ".."), { recursive: true, force: true });
  }
});

test("inspectFedrampOfficialSources reports rules as primary and narrative Markdown as supporting", async () => {
  const originalFetch = globalThis.fetch;
  const homeDir = mkdtempSync(join(tmpdir(), "grclanker-fedramp-sources-"));

  globalThis.fetch = async (input) => {
    const url = typeof input === "string" ? input : input.toString();

    if (url === "https://raw.githubusercontent.com/FedRAMP/rules/main/fedramp-consolidated-rules.json") {
      return jsonResponse(consolidatedRulesFixture);
    }

    if (url === "https://api.github.com/repos/FedRAMP/rules") {
      return jsonResponse({
        html_url: "https://github.com/FedRAMP/rules",
        updated_at: "2026-04-13T17:52:17Z",
        default_branch: "main",
      });
    }

    if (
      url ===
      "https://api.github.com/repos/FedRAMP/rules/contents/fedramp-consolidated-rules.json?ref=main"
    ) {
      return jsonResponse({
        sha: "abcdef1234567890abcdef1234567890abcdef12",
        html_url:
          "https://github.com/FedRAMP/rules/blob/main/fedramp-consolidated-rules.json",
      });
    }

    if (url === "https://api.github.com/repos/FedRAMP/2026-markdown") {
      return jsonResponse({
        html_url: "https://github.com/FedRAMP/2026-markdown",
        updated_at: "2026-07-02T15:15:27Z",
        default_branch: "main",
      });
    }

    if (url === "https://api.github.com/repos/FedRAMP/2026-markdown/contents/?ref=main") {
      return jsonResponse([
        { name: "README.md", type: "file" },
        { name: "_sources.json", type: "file" },
        { name: "providers", type: "dir" },
      ]);
    }

    return new Response("not found", { status: 404, statusText: "Not Found" });
  };

  clearFedrampCachesForTests();

  try {
    const status = await inspectFedrampOfficialSources({ refresh: true, homeDir });
    assert.equal(status.primary.version, "2026.07.02.02");
    assert.equal(status.primary.repo, "rules");
    assert.equal(status.secondary.repo, "2026-markdown");
    assert.equal(status.secondary.state, "ready");
    assert.deepEqual(status.notes, []);
  } finally {
    globalThis.fetch = originalFetch;
    clearFedrampCachesForTests();
    rmSync(homeDir, { recursive: true, force: true });
  }
});

test("buildFedrampDocsSnapshot is deterministic and includes provenance banners", () => {
  const catalog = normalizeFedrampConsolidatedRules(consolidatedRulesFixture);
  const primary = {
    org: "FedRAMP",
    repo: "rules",
    branch: "main",
    repoUrl: "https://github.com/FedRAMP/rules",
    path: "fedramp-consolidated-rules.json",
    rawUrl: "https://raw.githubusercontent.com/FedRAMP/rules/main/fedramp-consolidated-rules.json",
    blobSha: "abcdef1234567890abcdef1234567890abcdef12",
    fileHtmlUrl: "https://github.com/FedRAMP/rules/blob/main/fedramp-consolidated-rules.json",
    repoUpdatedAt: "2026-04-13T17:52:17Z",
    version: "2026.07.02.02",
    upstreamLastUpdated: "2026-07-02",
  };
  const secondary = {
    org: "FedRAMP",
    repo: "2026-markdown",
    branch: "main",
    repoUrl: "https://github.com/FedRAMP/2026-markdown",
    repoUpdatedAt: "2026-07-02T15:15:27Z",
    state: "ready",
    rootEntries: ["README.md", "_sources.json", "providers"],
    notes: [],
  };

  const first = buildFedrampDocsSnapshot(catalog, { primary, secondary });
  const second = buildFedrampDocsSnapshot(catalog, { primary, secondary });

  assert.deepEqual(first, second);
  assert.ok(first.some((file) => file.path === "fedramp/index.md"));
  assert.ok(first.some((file) => file.path === "fedramp/processes/certification-data-sharing.md"));
  assert.ok(first.some((file) => file.path === "fedramp/ksi/cloud-native-architecture.md"));

  const overview = first.find((file) => file.path === "fedramp/index.md")?.content ?? "";
  assert.match(overview, /official FedRAMP GitHub organization/i);
  assert.match(overview, /2026.07.02.02/);
  assert.match(overview, /fedramp-consolidated-rules\.json/);
});

test("readiness helper prioritizes official MUST items and infers provider-facing artifacts", () => {
  const catalog = normalizeFedrampConsolidatedRules(consolidatedRulesFixture);
  const loaded = {
    catalog,
    provenance: {
      repo: "rules",
      path: "fedramp-consolidated-rules.json",
      branch: "main",
      blobSha: "abcdef1234567890abcdef1234567890abcdef12",
      version: "2026.07.02.02",
      upstreamLastUpdated: "2026-07-02",
    },
    cacheStatus: "live",
  };

  const brief = buildFedrampReadinessBrief(loaded, {
    query: "CDS",
    audience: "provider",
    applies_to: "20x",
    limit: 3,
  });

  assert.equal(brief.kind, "process");
  assert.equal(brief.checklist.length, 2);
  assert.equal(brief.checklist[0]?.id, "CDS-CSO-PUB");
  assert.ok(
    brief.artifactSuggestions.some((item) => item.toLowerCase().includes("machine-readable")),
  );
  assert.ok(
    brief.workstreams.some((item) => item.toLowerCase().includes("programmatic access")),
  );
  assert.match(brief.text, /Priority checklist:/);
  assert.match(brief.text, /Likely artifacts to have ready/i);
});

test("readiness helper links KSI indicators back to their process obligations", () => {
  const catalog = normalizeFedrampConsolidatedRules(consolidatedRulesFixture);
  const loaded = {
    catalog,
    provenance: {
      repo: "rules",
      path: "fedramp-consolidated-rules.json",
      branch: "main",
      blobSha: "abcdef1234567890abcdef1234567890abcdef12",
      version: "2026.07.02.02",
      upstreamLastUpdated: "2026-07-02",
    },
    cacheStatus: "live",
  };

  const brief = buildFedrampReadinessBrief(loaded, {
    query: "KSI-CNA-CDS",
    audience: "provider",
    applies_to: "20x",
    limit: 2,
  });

  assert.equal(brief.kind, "ksi-indicator");
  assert.equal(brief.linkedProcesses[0]?.id, "CDS");
  assert.ok(brief.checklist.some((item) => item.id === "CDS-CSO-PUB"));
  assert.match(brief.text, /Linked process:\s+Certification Data Sharing \[CDS\]/);
});

test("artifact and workstream inference stays grounded in official requirement language", () => {
  const catalog = normalizeFedrampConsolidatedRules(consolidatedRulesFixture);
  const requirements = catalog.requirements;
  const indicators = catalog.ksiIndicators;

  const artifacts = inferFedrampArtifactSuggestions(["CDS"], requirements, indicators);
  const workstreams = inferFedrampWorkstreams(["CDS"], requirements, indicators);

  assert.ok(artifacts.some((item) => item.toLowerCase().includes("trust-center")));
  assert.ok(workstreams.some((item) => item.toLowerCase().includes("certification data publishing")));
  assert.ok(workstreams.some((item) => item.toLowerCase().includes("trust-center operations")));
});

test("artifact planner turns CDS into public and controlled package items", () => {
  const catalog = normalizeFedrampConsolidatedRules(consolidatedRulesFixture);
  const loaded = {
    catalog,
    provenance: {
      repo: "rules",
      path: "fedramp-consolidated-rules.json",
      branch: "main",
      blobSha: "abcdef1234567890abcdef1234567890abcdef12",
      version: "2026.07.02.02",
      upstreamLastUpdated: "2026-07-02",
    },
    cacheStatus: "live",
  };

  const plan = buildFedrampArtifactPlan(loaded, {
    query: "CDS",
    audience: "trust-center",
    applies_to: "20x",
  });

  assert.equal(plan.kind, "process");
  assert.ok(plan.items.some((item) => item.name.includes("Human-readable authorization summary")));
  assert.ok(plan.items.some((item) => item.name.includes("Machine-readable authorization data feed")));
  assert.ok(plan.items.some((item) => item.name.includes("Controlled authorization-data API")));
  assert.ok(plan.rollout.some((phase) => phase.phase === "foundation"));
  assert.ok(plan.rollout.some((phase) => phase.phase === "access"));
  assert.match(plan.text, /Public artifacts/i);
  assert.match(plan.text, /Controlled-access artifacts/i);
});

test("artifact planner resolves KSI queries back to linked process artifacts", () => {
  const catalog = normalizeFedrampConsolidatedRules(consolidatedRulesFixture);
  const loaded = {
    catalog,
    provenance: {
      repo: "rules",
      path: "fedramp-consolidated-rules.json",
      branch: "main",
      blobSha: "abcdef1234567890abcdef1234567890abcdef12",
      version: "2026.07.02.02",
      upstreamLastUpdated: "2026-07-02",
    },
    cacheStatus: "live",
  };

  const plan = buildFedrampArtifactPlan(loaded, {
    query: "KSI-CNA-CDS",
    audience: "provider",
    applies_to: "20x",
  });

  assert.equal(plan.kind, "ksi-indicator");
  assert.equal(plan.linkedProcesses[0]?.id, "CDS");
  assert.ok(plan.items.some((item) => item.groundedBy.includes("CDS-CSO-PUB")));
  assert.match(plan.text, /Linked process:\s+Certification Data Sharing \[CDS\]/);
});

test("CDS package planner groups artifacts into package layers", () => {
  const catalog = normalizeFedrampConsolidatedRules(consolidatedRulesFixture);
  const loaded = {
    catalog,
    provenance: {
      repo: "rules",
      path: "fedramp-consolidated-rules.json",
      branch: "main",
      blobSha: "abcdef1234567890abcdef1234567890abcdef12",
      version: "2026.07.02.02",
      upstreamLastUpdated: "2026-07-02",
    },
    cacheStatus: "live",
  };

  const plan = buildFedrampAdsPackagePlan(loaded, {
    audience: "trust-center",
    applies_to: "20x",
  });

  assert.equal(plan.process.id, "CDS");
  assert.ok(plan.publicItems.length >= 2);
  assert.ok(plan.controlledItems.length >= 1);
  assert.match(plan.text, /Public trust-center layer:/);
  assert.match(plan.text, /Controlled authorization-data layer:/);
  assert.match(plan.text, /Recommended rollout:/);
});

test("CDS starter bundle builder includes trust-center and feed templates", () => {
  const catalog = normalizeFedrampConsolidatedRules(consolidatedRulesFixture);
  const loaded = {
    catalog,
    provenance: {
      repo: "rules",
      path: "fedramp-consolidated-rules.json",
      branch: "main",
      blobSha: "abcdef1234567890abcdef1234567890abcdef12",
      version: "2026.07.02.02",
      upstreamLastUpdated: "2026-07-02",
    },
    cacheStatus: "live",
    notes: [],
  };

  const bundle = buildFedrampAdsStarterBundle(loaded, {
    audience: "trust-center",
    applies_to: "20x",
  });

  assert.equal(bundle.bundleName, "ads-starter-bundle");
  assert.ok(bundle.files.some((file) => file.path === "README.md"));
  assert.ok(bundle.files.some((file) => file.path === "public/trust-center-summary.md"));
  assert.ok(bundle.files.some((file) => file.path === "public/authorization-data.json"));
  assert.ok(bundle.files.some((file) => file.path === "controlled/access-instructions.md"));
  assert.ok(bundle.files.some((file) => file.path === "private/operating-runbook.md"));

  const readme = bundle.files.find((file) => file.path === "README.md")?.content ?? "";
  assert.match(readme, /Certification Data Sharing Starter Bundle/);
  assert.match(readme, /public\/authorization-data\.json/);
});

test("CDS starter bundle generator writes scaffold files under the requested root", async () => {
  const catalog = normalizeFedrampConsolidatedRules(consolidatedRulesFixture);
  const loaded = {
    catalog,
    provenance: {
      repo: "rules",
      path: "fedramp-consolidated-rules.json",
      branch: "main",
      blobSha: "abcdef1234567890abcdef1234567890abcdef12",
      version: "2026.07.02.02",
      upstreamLastUpdated: "2026-07-02",
    },
    cacheStatus: "live",
    notes: [],
  };
  const outputRoot = mkdtempSync(join(tmpdir(), "grclanker-fedramp-bundle-"));

  try {
    const result = await generateFedrampAdsStarterBundle(loaded, outputRoot, {
      audience: "trust-center",
      applies_to: "20x",
    });

    assert.ok(result.outputDir.startsWith(realpathSync(outputRoot)));
    assert.ok(existsSync(join(result.outputDir, "README.md")));
    assert.ok(existsSync(join(result.outputDir, "public", "authorization-data.json")));
    assert.ok(existsSync(join(result.outputDir, "controlled", "access-instructions.md")));
    assert.ok(existsSync(join(result.outputDir, "private", "continuous-validation.md")));

    const metadata = readFileSync(join(result.outputDir, "_source.json"), "utf8");
    assert.match(metadata, /"process":/);
    assert.match(metadata, /"CDS"/);
  } finally {
    rmSync(outputRoot, { recursive: true, force: true });
  }
});

test("CDS site builder includes public pages, JSON artifacts, and cloud deploy notes", () => {
  const catalog = normalizeFedrampConsolidatedRules(consolidatedRulesFixture);
  const loaded = {
    catalog,
    provenance: {
      repo: "rules",
      path: "fedramp-consolidated-rules.json",
      branch: "main",
      blobSha: "abcdef1234567890abcdef1234567890abcdef12",
      version: "2026.07.02.02",
      upstreamLastUpdated: "2026-07-02",
    },
    cacheStatus: "live",
    notes: [],
  };

  const site = buildFedrampAdsSite(loaded, {
    audience: "trust-center",
    applies_to: "20x",
    provider_name: "Example Security",
    offering_name: "Example Cloud",
    primary_domain: "trust.example.com",
    support_email: "trust@example.com",
  });

  assert.equal(site.bundleName, "ads-public-site");
  assert.equal(site.metadata.baseUrl, "https://trust.example.com");
  assert.equal(site.metadata.approvalStatus, "draft-unapproved");
  assert.ok(site.files.some((file) => file.path === "index.html"));
  assert.ok(site.files.some((file) => file.path === "APPROVAL_REQUIRED.md"));
  assert.ok(site.files.some((file) => file.path === "services/index.html"));
  assert.ok(site.files.some((file) => file.path === "access/index.html"));
  assert.ok(site.files.some((file) => file.path === "history/index.html"));
  assert.ok(site.files.some((file) => file.path === "authorization-data.json"));
  assert.ok(site.files.some((file) => file.path === "service-inventory.json"));
  assert.ok(site.files.some((file) => file.path === "query-index.json"));
  assert.ok(site.files.some((file) => file.path === "trust-center.md"));
  assert.ok(site.files.some((file) => file.path === "llms.txt"));
  assert.ok(site.files.some((file) => file.path === "llms-full.txt"));
  assert.ok(site.files.some((file) => file.path === "documentation/api/api.yaml"));
  assert.ok(site.files.some((file) => file.path === "assets/site.css"));

  const readme = site.files.find((file) => file.path === "README.md")?.content ?? "";
  assert.match(readme, /AWS: upload the generated files to S3/i);
  assert.match(readme, /Azure: upload the generated files to Azure Storage Static Website/i);
  assert.match(readme, /GCP: upload the generated files to Cloud Storage/i);
  assert.match(readme, /Approval status: draft-unapproved/i);
  assert.match(readme, /Review and approve every public statement/i);

  const index = site.files.find((file) => file.path === "index.html")?.content ?? "";
  assert.match(index, /Example Cloud Trust Center/);
  assert.match(index, /authorization-data\.json/);
  assert.match(index, /query-index\.json/);
  assert.match(index, /llms\.txt/);
  assert.match(index, /documentation\/api\/api\.yaml/);
  assert.match(index, /Draft scaffold\. Review before publication\./);
  assert.match(index, /noindex,nofollow,noarchive/);
  assert.match(index, /public trust center/i);

  const llms = site.files.find((file) => file.path === "llms.txt")?.content ?? "";
  assert.match(llms, /Machine-readable resources/i);
  assert.match(llms, /query-index\.json/);

  const queryIndex = site.files.find((file) => file.path === "query-index.json")?.content ?? "";
  assert.match(queryIndex, /"resources": \[/);
  assert.match(queryIndex, /"llms-txt"/);
  assert.match(queryIndex, /"openapi-yaml"/);
  assert.match(queryIndex, /"draft-unapproved"/);

  const openapi = site.files.find((file) => file.path === "documentation/api/api.yaml")?.content ?? "";
  assert.match(openapi, /openapi: 3\.0\.3/);
  assert.match(openapi, /\/authorization-data\.json:/);
  assert.match(openapi, /\/llms\.txt:/);
  assert.match(openapi, /requires human approval before publication/i);

  const robots = site.files.find((file) => file.path === "robots.txt")?.content ?? "";
  assert.match(robots, /Disallow: \//);

  const approval = site.files.find((file) => file.path === "APPROVAL_REQUIRED.md")?.content ?? "";
  assert.match(approval, /Approval Required Before Publication/);
  assert.match(approval, /Reviewer: TODO/);
});

test("CDS site generator writes a portable static trust-center bundle under the requested root", async () => {
  const catalog = normalizeFedrampConsolidatedRules(consolidatedRulesFixture);
  const loaded = {
    catalog,
    provenance: {
      repo: "rules",
      path: "fedramp-consolidated-rules.json",
      branch: "main",
      blobSha: "abcdef1234567890abcdef1234567890abcdef12",
      version: "2026.07.02.02",
      upstreamLastUpdated: "2026-07-02",
    },
    cacheStatus: "live",
    notes: [],
  };
  const outputRoot = mkdtempSync(join(tmpdir(), "grclanker-fedramp-site-"));

  try {
    const result = await generateFedrampAdsSite(loaded, outputRoot, {
      audience: "trust-center",
      applies_to: "20x",
      provider_name: "Example Security",
      offering_name: "Example Cloud",
      primary_domain: "trust.example.com",
      support_email: "trust@example.com",
    });

    assert.ok(result.outputDir.startsWith(realpathSync(outputRoot)));
    assert.equal(result.metadata.siteTitle, "Example Cloud Trust Center");
    assert.ok(existsSync(join(result.outputDir, "index.html")));
    assert.ok(existsSync(join(result.outputDir, "APPROVAL_REQUIRED.md")));
    assert.ok(existsSync(join(result.outputDir, "services", "index.html")));
    assert.ok(existsSync(join(result.outputDir, "access", "index.html")));
    assert.ok(existsSync(join(result.outputDir, "history", "index.html")));
    assert.ok(existsSync(join(result.outputDir, "authorization-data.json")));
    assert.ok(existsSync(join(result.outputDir, "service-inventory.json")));
    assert.ok(existsSync(join(result.outputDir, "query-index.json")));
    assert.ok(existsSync(join(result.outputDir, "trust-center.md")));
    assert.ok(existsSync(join(result.outputDir, "llms.txt")));
    assert.ok(existsSync(join(result.outputDir, "llms-full.txt")));
    assert.ok(existsSync(join(result.outputDir, "documentation", "api", "api.yaml")));
    assert.ok(existsSync(join(result.outputDir, "assets", "site.css")));

    const source = readFileSync(join(result.outputDir, "_source.json"), "utf8");
    assert.match(source, /"bundle": "ads-public-site"/);
    assert.match(source, /"primary_domain": "trust\.example\.com"/);
    assert.match(source, /"approval_status": "draft-unapproved"/);

    const llms = readFileSync(join(result.outputDir, "llms.txt"), "utf8");
    assert.match(llms, /trust-center\.md/);
    assert.match(llms, /llms-full\.txt/);
    assert.match(llms, /documentation\/api\/api\.yaml/);

    const robots = readFileSync(join(result.outputDir, "robots.txt"), "utf8");
    assert.match(robots, /Disallow: \//);
  } finally {
    rmSync(outputRoot, { recursive: true, force: true });
  }
});
