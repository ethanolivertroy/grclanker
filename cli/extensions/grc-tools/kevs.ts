/**
 * CISA Known Exploited Vulnerabilities (KEV) and EPSS tools.
 *
 * Wraps the same APIs as kevs-tui:
 * - CISA KEV catalog (raw GitHub JSON)
 * - FIRST EPSS scoring API
 *
 * Enables vulnerability prioritization with exploit intelligence.
 */
import { Type } from "@sinclair/typebox";
import { cachedFetch, errorResult, formatTable, textResult, throttledFetch } from "./shared.js";

const KEV_URL =
  "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json";
const EPSS_URL = "https://api.first.org/data/v1/epss";

// 4-hour cache for KEV (updates about weekly), 1-hour for EPSS.
const KEV_TTL = 4 * 60 * 60 * 1000;

interface KevVulnerability {
  cveID: string;
  vendorProject: string;
  product: string;
  vulnerabilityName: string;
  dateAdded: string;
  shortDescription: string;
  requiredAction: string;
  dueDate: string;
  knownRansomwareCampaignUse: string;
  notes: string;
  cwes?: string[];
}

interface KevCatalog {
  title: string;
  catalogVersion: string;
  dateReleased: string;
  count: number;
  vulnerabilities: KevVulnerability[];
}

interface EpssEntry {
  cve: string;
  epss: string;
  percentile: string;
  date: string;
}

interface EpssResponse {
  status: string;
  total: number;
  data: EpssEntry[];
}

type SearchArgs = { query: string; limit?: number };
type EpssArgs = { cve_ids: string[] };
type RecentArgs = { days?: number; limit?: number };
type RansomwareArgs = { vendor?: string; limit?: number };

function asString(value: unknown): string | undefined {
  if (typeof value === "string") {
    const trimmed = value.trim();
    return trimmed.length > 0 ? trimmed : undefined;
  }

  if (typeof value === "number" && Number.isFinite(value)) {
    return String(value);
  }

  return undefined;
}

function asNumber(value: unknown): number | undefined {
  if (typeof value === "number" && Number.isFinite(value)) {
    return value;
  }

  if (typeof value === "string" && value.trim().length > 0) {
    const parsed = Number(value);
    if (Number.isFinite(parsed)) {
      return parsed;
    }
  }

  return undefined;
}

function asStringArray(value: unknown): string[] {
  if (Array.isArray(value)) {
    return value
      .map((entry) => asString(entry))
      .filter((entry): entry is string => entry !== undefined);
  }

  const single = asString(value);
  if (!single) {
    return [];
  }

  return single
    .split(/[\s,]+/)
    .map((entry) => entry.trim())
    .filter(Boolean);
}

function normalizeSearchArgs(args: unknown): SearchArgs {
  if (typeof args === "string" || typeof args === "number") {
    return { query: String(args) };
  }

  if (args && typeof args === "object") {
    const value = args as Record<string, unknown>;
    const query =
      asString(value.query) ??
      asString(value.cve) ??
      asString(value.vendor) ??
      asString(value.product) ??
      asString(value.keyword) ??
      "";
    const limit = asNumber(value.limit);
    return limit === undefined ? { query } : { query, limit };
  }

  return { query: "" };
}

function normalizeEpssArgs(args: unknown): EpssArgs {
  if (typeof args === "string" || typeof args === "number") {
    return { cve_ids: asStringArray(String(args)) };
  }

  if (args && typeof args === "object") {
    const value = args as Record<string, unknown>;
    const cveIds =
      asStringArray(value.cve_ids).length > 0
        ? asStringArray(value.cve_ids)
        : asStringArray(value.cve ?? value.query);
    return { cve_ids: cveIds };
  }

  return { cve_ids: [] };
}

function normalizeRecentArgs(args: unknown): RecentArgs {
  if (typeof args === "number" || typeof args === "string") {
    const days = asNumber(args);
    return days === undefined ? {} : { days };
  }

  if (args && typeof args === "object") {
    const value = args as Record<string, unknown>;
    const days = asNumber(value.days);
    const limit = asNumber(value.limit);
    return {
      ...(days === undefined ? {} : { days }),
      ...(limit === undefined ? {} : { limit }),
    };
  }

  return {};
}

function normalizeRansomwareArgs(args: unknown): RansomwareArgs {
  if (typeof args === "string" || typeof args === "number") {
    return { vendor: String(args) };
  }

  if (args && typeof args === "object") {
    const value = args as Record<string, unknown>;
    const vendor = asString(value.vendor) ?? asString(value.query);
    const limit = asNumber(value.limit);
    return {
      ...(vendor === undefined ? {} : { vendor }),
      ...(limit === undefined ? {} : { limit }),
    };
  }

  return {};
}

function formatKev(vulnerability: KevVulnerability, epss?: EpssEntry): string {
  const lines = [
    `${vulnerability.cveID} - ${vulnerability.vulnerabilityName}`,
    `  Vendor:      ${vulnerability.vendorProject}`,
    `  Product:     ${vulnerability.product}`,
    `  Added:       ${vulnerability.dateAdded}`,
    `  Due:         ${vulnerability.dueDate}`,
    `  Ransomware:  ${vulnerability.knownRansomwareCampaignUse}`,
    `  Action:      ${vulnerability.requiredAction}`,
  ];

  if (vulnerability.shortDescription) {
    lines.push(`  Description: ${vulnerability.shortDescription.slice(0, 200)}`);
  }

  if (epss) {
    const score = (parseFloat(epss.epss) * 100).toFixed(1);
    const percentile = (parseFloat(epss.percentile) * 100).toFixed(1);
    lines.push(`  EPSS:        ${score}% probability (${percentile}th percentile)`);
  }

  if (vulnerability.notes) {
    lines.push(`  Notes:       ${vulnerability.notes.slice(0, 150)}`);
  }

  return lines.join("\n");
}

async function fetchEpss(cveIds: string[]): Promise<Map<string, EpssEntry>> {
  const scores = new Map<string, EpssEntry>();
  if (cveIds.length === 0) {
    return scores;
  }

  for (let index = 0; index < cveIds.length; index += 100) {
    const batch = cveIds.slice(index, index + 100);
    const url = `${EPSS_URL}?cve=${batch.join(",")}`;

    try {
      const data = await throttledFetch<EpssResponse>(url, 100);
      for (const entry of data.data) {
        scores.set(entry.cve, entry);
      }
    } catch {
      // EPSS enrichment is best-effort. Keep the base KEV response working.
    }
  }

  return scores;
}

export function registerKevsTools(pi: any): void {
  pi.registerTool({
    name: "kevs_search",
    label: "Search Known Exploited Vulnerabilities",
    description:
      "Search the CISA KEV catalog for known exploited vulnerabilities by CVE ID, vendor, product, or keyword. Results include EPSS exploit probability scores.",
    parameters: Type.Object({
      query: Type.String({
        description:
          "Search term: CVE ID (for example: 'CVE-2024-1234'), vendor, product name, or keyword.",
      }),
      limit: Type.Optional(Type.Number({ default: 10 })),
    }),
    prepareArguments: normalizeSearchArgs,
    async execute(_toolCallId: string, args: SearchArgs) {
      if (!args.query.trim()) {
        return errorResult(
          'kevs_search requires a non-empty query. Example: {"query":"CVE-2024-3400"}.',
          { tool: "kevs_search" },
        );
      }

      try {
        const catalog = await cachedFetch<KevCatalog>(KEV_URL, KEV_TTL);
        const normalizedQuery = args.query.toLowerCase();
        const limit = args.limit ?? 10;

        const matches = catalog.vulnerabilities
          .filter(
            (vulnerability) =>
              vulnerability.cveID.toLowerCase().includes(normalizedQuery) ||
              vulnerability.vendorProject.toLowerCase().includes(normalizedQuery) ||
              vulnerability.product.toLowerCase().includes(normalizedQuery) ||
              vulnerability.vulnerabilityName.toLowerCase().includes(normalizedQuery) ||
              vulnerability.shortDescription.toLowerCase().includes(normalizedQuery),
          )
          .slice(0, limit);

        if (matches.length === 0) {
          return textResult(
            `No KEV entries found matching "${args.query}". The CISA KEV catalog currently has ${catalog.count} total entries.`,
            { query: args.query, count: 0 },
          );
        }

        const epssScores = await fetchEpss(matches.map((vulnerability) => vulnerability.cveID));
        return textResult(
          `Found ${matches.length} KEV entr${matches.length === 1 ? "y" : "ies"} matching "${args.query}" ` +
            `(catalog size: ${catalog.count}):\n\n` +
            matches
              .map((vulnerability) => formatKev(vulnerability, epssScores.get(vulnerability.cveID)))
              .join("\n\n"),
          {
            query: args.query,
            count: matches.length,
          },
        );
      } catch (error) {
        return errorResult(
          `KEV search error: ${error instanceof Error ? error.message : String(error)}`,
          { query: args.query },
        );
      }
    },
  });

  pi.registerTool({
    name: "kevs_get_epss",
    label: "Get EPSS Exploit Probability",
    description:
      "Get the EPSS (Exploit Prediction Scoring System) probability score for one or more CVE IDs. Higher score means higher likelihood of exploitation in the next 30 days.",
    parameters: Type.Object({
      cve_ids: Type.Array(Type.String(), {
        description:
          "List of CVE IDs to score (for example: ['CVE-2024-1234', 'CVE-2024-5678']).",
      }),
    }),
    prepareArguments: normalizeEpssArgs,
    async execute(_toolCallId: string, args: EpssArgs) {
      if (args.cve_ids.length === 0) {
        return errorResult(
          'kevs_get_epss requires at least one CVE ID. Example: {"cve_ids":["CVE-2024-3400"]}.',
          { tool: "kevs_get_epss" },
        );
      }

      try {
        const epssScores = await fetchEpss(args.cve_ids);

        if (epssScores.size === 0) {
          return textResult(
            "No EPSS scores found for the provided CVE IDs. They may be too new or not yet scored.",
            { cve_ids: args.cve_ids, count: 0 },
          );
        }

        const rows = args.cve_ids.map((cveId) => {
          const entry = epssScores.get(cveId);
          if (!entry) {
            return [cveId, "Not scored", "N/A"];
          }

          const score = (parseFloat(entry.epss) * 100).toFixed(2);
          const percentile = (parseFloat(entry.percentile) * 100).toFixed(1);
          return [cveId, `${score}%`, `${percentile}th`];
        });

        return textResult(
          "EPSS Exploit Probability Scores:\n\n" +
            formatTable(["CVE ID", "EPSS Score", "Percentile"], rows) +
            "\n\nEPSS estimates exploitation likelihood in the next 30 days. Scores above 10% are usually worth fast triage.",
          {
            cve_ids: args.cve_ids,
            count: rows.length,
          },
        );
      } catch (error) {
        return errorResult(
          `EPSS API error: ${error instanceof Error ? error.message : String(error)}`,
          { cve_ids: args.cve_ids },
        );
      }
    },
  });

  pi.registerTool({
    name: "kevs_recent",
    label: "List Recently Added KEV Entries",
    description:
      "List the most recently added entries to the CISA Known Exploited Vulnerabilities catalog, with EPSS scores.",
    parameters: Type.Object({
      days: Type.Optional(
        Type.Number({
          description: "Look back this many days (default: 30).",
          default: 30,
        }),
      ),
      limit: Type.Optional(Type.Number({ default: 10 })),
    }),
    prepareArguments: normalizeRecentArgs,
    async execute(_toolCallId: string, args: RecentArgs) {
      try {
        const catalog = await cachedFetch<KevCatalog>(KEV_URL, KEV_TTL);
        const days = args.days ?? 30;
        const limit = args.limit ?? 10;
        const cutoff = new Date();
        cutoff.setDate(cutoff.getDate() - days);
        const cutoffString = cutoff.toISOString().split("T")[0];

        const recent = catalog.vulnerabilities
          .filter((vulnerability) => vulnerability.dateAdded >= cutoffString)
          .sort((left, right) => right.dateAdded.localeCompare(left.dateAdded))
          .slice(0, limit);

        if (recent.length === 0) {
          return textResult(`No new KEV entries in the last ${days} days.`, {
            days,
            count: 0,
          });
        }

        const epssScores = await fetchEpss(recent.map((vulnerability) => vulnerability.cveID));
        return textResult(
          `${recent.length} KEV entr${recent.length === 1 ? "y" : "ies"} added in the last ${days} days:\n\n` +
            recent
              .map((vulnerability) => formatKev(vulnerability, epssScores.get(vulnerability.cveID)))
              .join("\n\n"),
          {
            days,
            count: recent.length,
          },
        );
      } catch (error) {
        return errorResult(
          `KEV fetch error: ${error instanceof Error ? error.message : String(error)}`,
          { days: args.days ?? 30 },
        );
      }
    },
  });

  pi.registerTool({
    name: "kevs_check_ransomware",
    label: "Check Ransomware-Linked Vulnerabilities",
    description:
      "Find KEV entries with known ransomware campaign use. Critical for prioritizing patches against ransomware threats.",
    parameters: Type.Object({
      vendor: Type.Optional(Type.String({ description: "Filter by vendor or product name." })),
      limit: Type.Optional(Type.Number({ default: 20 })),
    }),
    prepareArguments: normalizeRansomwareArgs,
    async execute(_toolCallId: string, args: RansomwareArgs) {
      try {
        const catalog = await cachedFetch<KevCatalog>(KEV_URL, KEV_TTL);

        let ransomwareEntries = catalog.vulnerabilities.filter(
          (vulnerability) => vulnerability.knownRansomwareCampaignUse === "Known",
        );

        if (args.vendor) {
          const normalizedVendor = args.vendor.toLowerCase();
          ransomwareEntries = ransomwareEntries.filter(
            (vulnerability) =>
              vulnerability.vendorProject.toLowerCase().includes(normalizedVendor) ||
              vulnerability.product.toLowerCase().includes(normalizedVendor),
          );
        }

        const results = ransomwareEntries
          .sort((left, right) => right.dateAdded.localeCompare(left.dateAdded))
          .slice(0, args.limit ?? 20);

        if (results.length === 0) {
          return textResult(
            args.vendor
              ? `No ransomware-linked KEV entries found for "${args.vendor}".`
              : "No ransomware-linked KEV entries found.",
            {
              vendor: args.vendor,
              count: 0,
            },
          );
        }

        return textResult(
          `${results.length} ransomware-linked vulnerabilit${results.length === 1 ? "y" : "ies"}` +
            `${args.vendor ? ` for "${args.vendor}"` : ""} ` +
            `(of ${ransomwareEntries.length} total ransomware-linked KEVs):\n\n` +
            formatTable(
              ["CVE", "Vendor", "Product", "Added", "Due Date"],
              results.map((vulnerability) => [
                vulnerability.cveID,
                vulnerability.vendorProject.slice(0, 20),
                vulnerability.product.slice(0, 25),
                vulnerability.dateAdded,
                vulnerability.dueDate,
              ]),
            ),
          {
            vendor: args.vendor,
            count: results.length,
          },
        );
      } catch (error) {
        return errorResult(
          `KEV fetch error: ${error instanceof Error ? error.message : String(error)}`,
          { vendor: args.vendor },
        );
      }
    },
  });
}
