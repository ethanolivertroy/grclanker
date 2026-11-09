import type { GrcToolRegistrar } from "../../core/tool-definition.js";
/**
 * NIST Cryptographic Module Validation Program (CMVP) tools.
 *
 * Wraps the static JSON API at ethanolivertroy.github.io/nist-cmvp-api
 * (same data source as cmvp-tui). Enables searching validated, historical,
 * and in-process cryptographic modules for FIPS 140-2/140-3 compliance.
 */
import { Type } from "typebox";
import { cachedFetch, errorResult, formatTable, textResult } from "./shared.js";

const DEFAULT_BASE = "https://ethanolivertroy.github.io/nist-cmvp-api/api";
const BASE = process.env.CMVP_API_BASE_URL?.trim().replace(/\/+$/, "") || DEFAULT_BASE;

// 24-hour cache. CMVP data updates weekly via GitHub Actions.
const TTL = 24 * 60 * 60 * 1000;
const DEFAULT_SEARCH_LIMIT = 10;

interface CmvpMetadata {
  generated_at: string;
  total_modules: number;
  total_historical_modules: number;
  total_modules_in_process: number;
  source: string;
  version: string;
}

interface CmvpModule {
  "Certificate Number": string;
  "Certificate Number_url"?: string;
  "Vendor Name": string;
  "Module Name": string;
  "Module Type": string;
  "Validation Date": string;
  standard: string;
  status: string;
  overall_level: number;
  sunset_date?: string;
  caveat?: string;
  description?: string;
  algorithms?: string[];
  security_policy_url?: string;
  certificate_detail_url?: string;
}

interface ModulesResponse {
  metadata: CmvpMetadata;
  modules: CmvpModule[];
}

interface ModuleInProcess {
  "Module Name": string;
  "Vendor Name": string;
  Standard: string;
  Status: string;
}

interface InProcessResponse {
  metadata: CmvpMetadata;
  modules_in_process: ModuleInProcess[];
}

type SearchArgs = { query: string; limit?: number };
type CertArgs = { cert_number: string };

function searchLimit(value: number | undefined): number {
  if (value === undefined || !Number.isFinite(value) || value < 1) return DEFAULT_SEARCH_LIMIT;
  return Math.trunc(value);
}

function searchSummary(
  source: "active" | "historical" | "in_process",
  query: string,
  count: number,
  totalMatches: number,
  catalogCount: number,
): string {
  const catalog = source === "in_process" ? "in-process" : source;
  const label = source === "active"
    ? "active FIPS module(s)"
    : source === "historical"
      ? "historical module(s)"
      : "module(s) in the CMVP validation pipeline";
  const heading = totalMatches === 0
    ? `No ${catalog} CMVP modules found matching phrase "${query}".`
    : count < totalMatches
      ? `Showing ${count} of ${totalMatches} ${label} matching "${query}".`
      : `Found ${count} ${label} matching "${query}".`;
  const totals = `Catalog size: ${catalogCount} modules across all vendors; matching this query: ${totalMatches}; returned: ${count}.`;
  const emptyHint = totalMatches === 0
    ? "\nNo matches for this phrase do not establish that a module or vendor has no validation history. Try a broader vendor or module name, or an exact certificate number in the active and historical catalogs."
    : "";
  return `${heading}\n${totals}${emptyHint}`;
}

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

function normalizeSearchArgs(args: unknown): SearchArgs {
  if (typeof args === "string" || typeof args === "number") {
    return { query: String(args) };
  }

  if (args && typeof args === "object") {
    const value = args as Record<string, unknown>;
    const query =
      asString(value.query) ??
      asString(value.module) ??
      asString(value.vendor) ??
      asString(value.name) ??
      asString(value.cert_number) ??
      "";
    const limit = asNumber(value.limit);
    return limit === undefined ? { query } : { query, limit };
  }

  return { query: "" };
}

function normalizeCertArgs(args: unknown): CertArgs {
  if (typeof args === "string" || typeof args === "number") {
    return { cert_number: String(args) };
  }

  if (args && typeof args === "object") {
    const value = args as Record<string, unknown>;
    return {
      cert_number:
        asString(value.cert_number) ??
        asString(value.certificate) ??
        asString(value.certificate_number) ??
        asString(value.query) ??
        "",
    };
  }

  return { cert_number: "" };
}

function matchesQuery(module: CmvpModule, query: string): boolean {
  const normalizedQuery = query.toLowerCase();
  return (
    module["Module Name"].toLowerCase().includes(normalizedQuery) ||
    module["Vendor Name"].toLowerCase().includes(normalizedQuery) ||
    module["Certificate Number"].toLowerCase().includes(normalizedQuery) ||
    (module.description ?? "").toLowerCase().includes(normalizedQuery)
  );
}

function formatModule(module: CmvpModule): string {
  const lines = [
    `Certificate #${module["Certificate Number"]} - ${module["Module Name"]}`,
    `  Vendor:     ${module["Vendor Name"]}`,
    `  Type:       ${module["Module Type"]}`,
    `  Standard:   ${module.standard}`,
    `  Level:      ${module.overall_level}`,
    `  Status:     ${module.status}`,
    `  Validated:  ${module["Validation Date"]}`,
  ];

  if (module.sunset_date) {
    lines.push(`  Sunset:     ${module.sunset_date}`);
  }

  if (module.algorithms?.length) {
    const suffix =
      module.algorithms.length > 5
        ? ` (+${module.algorithms.length - 5} more)`
        : "";
    lines.push(`  Algorithms: ${module.algorithms.slice(0, 5).join(", ")}${suffix}`);
  }

  if (module.caveat) {
    lines.push(`  Caveat:     ${module.caveat.slice(0, 120)}`);
  }

  if (module.certificate_detail_url) {
    lines.push(`  URL:        ${module.certificate_detail_url}`);
  }

  return lines.join("\n");
}

function missingQueryResult(toolName: string) {
  return errorResult(
    `${toolName} requires a non-empty query. Example: {"query":"BoringCrypto"}.`,
    { tool: toolName },
  );
}

export function registerCmvpTools(pi: GrcToolRegistrar): void {
  pi.registerTool({
    name: "cmvp_search_modules",
    label: "Search FIPS Validated Modules",
    description:
      "Search NIST CMVP for currently validated cryptographic modules by vendor, module name, or certificate number. Returns FIPS 140-2/140-3 certification details.",
    parameters: Type.Object({
      query: Type.String({
        description:
          "Search term: vendor name, module name, or certificate number (for example: 'OpenSSL', 'AWS', or '4282')",
      }),
      limit: Type.Optional(
        Type.Number({
          description: "Max results to return (default: 10). Values below 1 use 10; fractions are truncated.",
          default: 10,
        }),
      ),
    }),
    prepareArguments: normalizeSearchArgs,
    async execute(_toolCallId: string, args: SearchArgs, signal?: AbortSignal) {
      if (!args.query.trim()) {
        return missingQueryResult("cmvp_search_modules");
      }

      try {
        const data = await cachedFetch<ModulesResponse>(`${BASE}/modules.json`, TTL, signal);
        const allMatches = data.modules.filter((module) => matchesQuery(module, args.query));
        const matches = allMatches.slice(0, searchLimit(args.limit));
        const summary = searchSummary("active", args.query, matches.length, allMatches.length, data.metadata.total_modules);
        return textResult(summary + (matches.length ? `\n\n${matches.map(formatModule).join("\n\n")}` : ""), {
          query: args.query,
          count: matches.length,
          total_matches: allMatches.length,
          catalog_count: data.metadata.total_modules,
          source: "active",
        });
      } catch (error) {
        return errorResult(
          `CMVP API error: ${error instanceof Error ? error.message : String(error)}`,
          { query: args.query, source: "active" },
        );
      }
    },
  });

  pi.registerTool({
    name: "cmvp_search_historical",
    label: "Search Historical/Expired FIPS Modules",
    description:
      "Search NIST CMVP historical list for expired or revoked cryptographic module certifications.",
    parameters: Type.Object({
      query: Type.String({
        description: "Search term: vendor name, module name, or certificate number.",
      }),
      limit: Type.Optional(
        Type.Number({
          description: "Max results to return (default: 10). Values below 1 use 10; fractions are truncated.",
          default: 10,
        }),
      ),
    }),
    prepareArguments: normalizeSearchArgs,
    async execute(_toolCallId: string, args: SearchArgs, signal?: AbortSignal) {
      if (!args.query.trim()) {
        return missingQueryResult("cmvp_search_historical");
      }

      try {
        const data = await cachedFetch<ModulesResponse>(
          `${BASE}/historical-modules.json`,
          TTL,
          signal,
        );
        const allMatches = data.modules.filter((module) => matchesQuery(module, args.query));
        const matches = allMatches.slice(0, searchLimit(args.limit));
        const summary = searchSummary("historical", args.query, matches.length, allMatches.length, data.metadata.total_historical_modules);
        return textResult(summary + (matches.length ? `\n\n${matches.map(formatModule).join("\n\n")}` : ""), {
          query: args.query,
          count: matches.length,
          total_matches: allMatches.length,
          catalog_count: data.metadata.total_historical_modules,
          source: "historical",
        });
      } catch (error) {
        return errorResult(
          `CMVP API error: ${error instanceof Error ? error.message : String(error)}`,
          { query: args.query, source: "historical" },
        );
      }
    },
  });

  pi.registerTool({
    name: "cmvp_search_in_process",
    label: "Search FIPS Modules In Process",
    description:
      "Search for cryptographic modules currently in the NIST CMVP validation pipeline (not yet certified).",
    parameters: Type.Object({
      query: Type.String({
        description: "Search term: vendor name or module name.",
      }),
      limit: Type.Optional(
        Type.Number({
          description: "Max results to return (default: 10). Values below 1 use 10; fractions are truncated.",
          default: 10,
        }),
      ),
    }),
    prepareArguments: normalizeSearchArgs,
    async execute(_toolCallId: string, args: SearchArgs, signal?: AbortSignal) {
      if (!args.query.trim()) {
        return missingQueryResult("cmvp_search_in_process");
      }

      try {
        const data = await cachedFetch<InProcessResponse>(
          `${BASE}/modules-in-process.json`,
          TTL,
          signal,
        );
        const normalizedQuery = args.query.toLowerCase();
        const allMatches = data.modules_in_process
          .filter(
            (module) =>
              module["Module Name"].toLowerCase().includes(normalizedQuery) ||
              module["Vendor Name"].toLowerCase().includes(normalizedQuery),
          );
        const matches = allMatches.slice(0, searchLimit(args.limit));

        const table = formatTable(
          ["Module", "Vendor", "Standard", "Status"],
          matches.map((module) => [
            module["Module Name"].slice(0, 50),
            module["Vendor Name"].slice(0, 30),
            module.Standard,
            module.Status,
          ]),
        );

        const summary = searchSummary("in_process", args.query, matches.length, allMatches.length, data.metadata.total_modules_in_process);
        return textResult(
          summary + (matches.length ? `\n\n${table}` : ""),
          {
            query: args.query,
            count: matches.length,
            total_matches: allMatches.length,
            catalog_count: data.metadata.total_modules_in_process,
            source: "in_process",
          },
        );
      } catch (error) {
        return errorResult(
          `CMVP API error: ${error instanceof Error ? error.message : String(error)}`,
          { query: args.query, source: "in_process" },
        );
      }
    },
  });

  pi.registerTool({
    name: "cmvp_get_module",
    label: "Get FIPS Module by Certificate Number",
    description:
      "Retrieve detailed information about a specific FIPS validated module by its certificate number.",
    parameters: Type.Object({
      cert_number: Type.String({
        description: "CMVP certificate number (for example: '4282').",
      }),
    }),
    prepareArguments: normalizeCertArgs,
    async execute(_toolCallId: string, args: CertArgs, signal?: AbortSignal) {
      if (!args.cert_number.trim()) {
        return errorResult(
          'cmvp_get_module requires a certificate number. Example: {"cert_number":"4953"}.',
          { tool: "cmvp_get_module" },
        );
      }

      try {
        const active = await cachedFetch<ModulesResponse>(`${BASE}/modules.json`, TTL, signal);
        let module = active.modules.find(
          (entry) => entry["Certificate Number"] === args.cert_number,
        );
        let source = "active";

        if (!module) {
          const historical = await cachedFetch<ModulesResponse>(
            `${BASE}/historical-modules.json`,
            TTL,
            signal,
          );
          module = historical.modules.find(
            (entry) => entry["Certificate Number"] === args.cert_number,
          );
          source = "historical";
        }

        if (!module) {
          return textResult(`No CMVP module found with certificate #${args.cert_number} in the active or historical catalogs read. This does not establish that the vendor has no other validated modules.`, {
            cert_number: args.cert_number,
            count: 0,
          });
        }

        return textResult(formatModule(module), {
          cert_number: args.cert_number,
          source,
        });
      } catch (error) {
        return errorResult(
          `CMVP API error: ${error instanceof Error ? error.message : String(error)}`,
          { cert_number: args.cert_number },
        );
      }
    },
  });
}
