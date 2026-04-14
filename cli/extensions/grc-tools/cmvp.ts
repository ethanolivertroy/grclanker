/**
 * NIST Cryptographic Module Validation Program (CMVP) tools.
 *
 * Wraps the static JSON API at hackidle.github.io/nist-cmvp-api
 * (same data source as cmvp-tui). Enables searching validated, historical,
 * and in-process cryptographic modules for FIPS 140-2/140-3 compliance.
 */
import { Type } from "@sinclair/typebox";
import { cachedFetch, errorResult, formatTable, textResult } from "./shared.js";

const DEFAULT_BASE = "https://hackidle.github.io/nist-cmvp-api/api";
const BASE = process.env.CMVP_API_BASE_URL?.trim().replace(/\/+$/, "") || DEFAULT_BASE;

// 24-hour cache. CMVP data updates weekly via GitHub Actions.
const TTL = 24 * 60 * 60 * 1000;

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

export function registerCmvpTools(pi: any): void {
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
          description: "Max results to return (default: 10).",
          default: 10,
        }),
      ),
    }),
    prepareArguments: normalizeSearchArgs,
    async execute(_toolCallId: string, args: SearchArgs) {
      if (!args.query.trim()) {
        return missingQueryResult("cmvp_search_modules");
      }

      try {
        const data = await cachedFetch<ModulesResponse>(`${BASE}/modules.json`, TTL);
        const limit = args.limit ?? 10;
        const matches = data.modules
          .filter((module) => matchesQuery(module, args.query))
          .slice(0, limit);

        if (matches.length === 0) {
          return textResult(
            `No active CMVP modules found matching "${args.query}". Try cmvp_search_historical or cmvp_search_in_process.`,
            { query: args.query, count: 0, source: "active" },
          );
        }

        const header =
          `Found ${matches.length} active FIPS module(s) matching "${args.query}" ` +
          `(of ${data.metadata.total_modules} total):\n`;
        return textResult(header + matches.map(formatModule).join("\n\n"), {
          query: args.query,
          count: matches.length,
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
      limit: Type.Optional(Type.Number({ default: 10 })),
    }),
    prepareArguments: normalizeSearchArgs,
    async execute(_toolCallId: string, args: SearchArgs) {
      if (!args.query.trim()) {
        return missingQueryResult("cmvp_search_historical");
      }

      try {
        const data = await cachedFetch<ModulesResponse>(
          `${BASE}/historical-modules.json`,
          TTL,
        );
        const limit = args.limit ?? 10;
        const matches = data.modules
          .filter((module) => matchesQuery(module, args.query))
          .slice(0, limit);

        if (matches.length === 0) {
          return textResult(`No historical CMVP modules found matching "${args.query}".`, {
            query: args.query,
            count: 0,
            source: "historical",
          });
        }

        const header =
          `Found ${matches.length} historical module(s) matching "${args.query}" ` +
          `(of ${data.metadata.total_historical_modules} total):\n`;
        return textResult(header + matches.map(formatModule).join("\n\n"), {
          query: args.query,
          count: matches.length,
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
      limit: Type.Optional(Type.Number({ default: 10 })),
    }),
    prepareArguments: normalizeSearchArgs,
    async execute(_toolCallId: string, args: SearchArgs) {
      if (!args.query.trim()) {
        return missingQueryResult("cmvp_search_in_process");
      }

      try {
        const data = await cachedFetch<InProcessResponse>(
          `${BASE}/modules-in-process.json`,
          TTL,
        );
        const normalizedQuery = args.query.toLowerCase();
        const limit = args.limit ?? 10;
        const matches = data.modules_in_process
          .filter(
            (module) =>
              module["Module Name"].toLowerCase().includes(normalizedQuery) ||
              module["Vendor Name"].toLowerCase().includes(normalizedQuery),
          )
          .slice(0, limit);

        if (matches.length === 0) {
          return textResult(`No in-process CMVP modules found matching "${args.query}".`, {
            query: args.query,
            count: 0,
            source: "in_process",
          });
        }

        const table = formatTable(
          ["Module", "Vendor", "Standard", "Status"],
          matches.map((module) => [
            module["Module Name"].slice(0, 50),
            module["Vendor Name"].slice(0, 30),
            module.Standard,
            module.Status,
          ]),
        );

        return textResult(
          `Found ${matches.length} module(s) in the CMVP validation pipeline matching "${args.query}" ` +
            `(of ${data.metadata.total_modules_in_process} total):\n\n${table}`,
          {
            query: args.query,
            count: matches.length,
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
    async execute(_toolCallId: string, args: CertArgs) {
      if (!args.cert_number.trim()) {
        return errorResult(
          'cmvp_get_module requires a certificate number. Example: {"cert_number":"4953"}.',
          { tool: "cmvp_get_module" },
        );
      }

      try {
        const active = await cachedFetch<ModulesResponse>(`${BASE}/modules.json`, TTL);
        let module = active.modules.find(
          (entry) => entry["Certificate Number"] === args.cert_number,
        );
        let source = "active";

        if (!module) {
          const historical = await cachedFetch<ModulesResponse>(
            `${BASE}/historical-modules.json`,
            TTL,
          );
          module = historical.modules.find(
            (entry) => entry["Certificate Number"] === args.cert_number,
          );
          source = "historical";
        }

        if (!module) {
          return textResult(`No CMVP module found with certificate #${args.cert_number}.`, {
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
