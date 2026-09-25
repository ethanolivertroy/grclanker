/**
 * Register grclanker's custom model providers with the Flue runtime.
 *
 * `grclanker setup` in local-first mode writes a Pi `models.json` entry (an
 * OpenAI-compatible endpoint such as Ollama) that the Pi CLI loads on start.
 * Flue registers only Pi's built-in providers, so this module rebuilds those
 * entries with Pi's own `createProvider()` and hands them to Flue's
 * `setProvider()`.
 */
import { createProvider, type Api, type Model, type Provider } from "@earendil-works/pi-ai";
import { anthropicMessagesApi } from "@earendil-works/pi-ai/api/anthropic-messages.lazy";
import { openAICompletionsApi } from "@earendil-works/pi-ai/api/openai-completions.lazy";
import { openAIResponsesApi } from "@earendil-works/pi-ai/api/openai-responses.lazy";
import { setProvider as flueSetProvider } from "@flue/runtime";
import { getGrclankerModelsPath, getGrclankerSettingsPath } from "../config/paths.js";
import { readGrclankerSettings, readJson, type GrclankerSettings } from "../pi/settings.js";
import { GrclankerFlueConfigError } from "./render.js";

export interface CustomModelConfig {
  id: string;
  name?: string;
  api?: string;
  baseUrl?: string;
  reasoning?: boolean;
  input?: Array<"text" | "image">;
  cost?: Model<Api>["cost"];
  contextWindow?: number;
  maxTokens?: number;
  compat?: Record<string, unknown>;
}

export interface CustomProviderConfig {
  id: string;
  baseUrl?: string;
  api?: string;
  apiKey?: string;
  headers?: Record<string, string>;
  compat?: Record<string, unknown>;
  models: CustomModelConfig[];
}

/**
 * Flue types `setProvider()` against its own nested pi-ai (0.83) while this
 * package builds providers with grclanker's pi-ai (0.80). The static provider
 * contract Flue reads (`id`, `auth.apiKey.resolve()`, `getModels()`, the
 * stream functions) is the same in both; only the declaration files differ.
 */
export type FlueProvider = Parameters<typeof flueSetProvider>[0];

export interface RegisterProvidersInput {
  env: NodeJS.ProcessEnv;
  settings?: GrclankerSettings;
  modelsConfig?: Record<string, unknown>;
  setProvider?: (provider: FlueProvider) => void;
}

export interface RegisterProvidersResult {
  providerIds: string[];
  warnings: string[];
}

type ProviderStreamsFactory = () => ReturnType<typeof openAICompletionsApi>;

const API_FACTORIES: Record<string, ProviderStreamsFactory> = {
  "openai-completions": openAICompletionsApi,
  "openai-responses": openAIResponsesApi,
  "anthropic-messages": anthropicMessagesApi,
};

const DEFAULT_CONTEXT_WINDOW = 128_000;
const DEFAULT_MAX_TOKENS = 16_384;
const ZERO_COST: Model<Api>["cost"] = { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 };
const ENV_TEMPLATE = /\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)/g;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function optionalString(value: unknown): string | undefined {
  return typeof value === "string" && value.trim().length > 0 ? value.trim() : undefined;
}

function optionalNumber(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) && value > 0 ? value : undefined;
}

function stringRecord(value: unknown): Record<string, string> | undefined {
  if (!isRecord(value)) return undefined;
  const entries = Object.entries(value).filter((entry): entry is [string, string] => typeof entry[1] === "string");
  return entries.length > 0 ? Object.fromEntries(entries) : undefined;
}

function parseModelConfig(value: unknown): CustomModelConfig | undefined {
  if (!isRecord(value)) return undefined;
  const id = optionalString(value.id);
  if (!id) return undefined;
  const input = Array.isArray(value.input)
    ? value.input.filter((entry): entry is "text" | "image" => entry === "text" || entry === "image")
    : undefined;
  return {
    id,
    name: optionalString(value.name),
    api: optionalString(value.api),
    baseUrl: optionalString(value.baseUrl),
    reasoning: typeof value.reasoning === "boolean" ? value.reasoning : undefined,
    input: input && input.length > 0 ? input : undefined,
    cost: isRecord(value.cost) ? (value.cost as unknown as Model<Api>["cost"]) : undefined,
    contextWindow: optionalNumber(value.contextWindow),
    maxTokens: optionalNumber(value.maxTokens),
    compat: isRecord(value.compat) ? value.compat : undefined,
  };
}

/** Read the `providers` entries of a Pi `models.json` document that declare their own models. */
export function listCustomProviderConfigs(modelsConfig: Record<string, unknown>): CustomProviderConfig[] {
  if (!isRecord(modelsConfig.providers)) return [];

  return Object.entries(modelsConfig.providers).flatMap(([id, raw]) => {
    if (!isRecord(raw) || !Array.isArray(raw.models)) return [];
    const models = raw.models.map(parseModelConfig).filter((model): model is CustomModelConfig => Boolean(model));
    if (models.length === 0) return [];
    return [
      {
        id,
        baseUrl: optionalString(raw.baseUrl),
        api: optionalString(raw.api),
        apiKey: optionalString(raw.apiKey),
        headers: stringRecord(raw.headers),
        compat: isRecord(raw.compat) ? raw.compat : undefined,
        models,
      },
    ];
  });
}

/**
 * A local-first `grclanker setup` also records `providerBaseUrl` and the model in
 * settings.json; rebuild the provider from those when models.json lacks the entry.
 */
export function localProviderConfigFromSettings(settings: GrclankerSettings): CustomProviderConfig | undefined {
  if (settings.modelMode !== "local") return undefined;
  const id = optionalString(settings.defaultProvider);
  const modelId = optionalString(settings.defaultModel);
  const baseUrl = optionalString(settings.providerBaseUrl);
  if (!id || !modelId || !baseUrl) return undefined;
  return { id, baseUrl, api: "openai-completions", models: [{ id: modelId, name: `${modelId} (Local)` }] };
}

/** Resolve a Pi `models.json` `apiKey` value: a literal, or `$VAR` / `${VAR}` environment templates. */
export function resolveApiKeyValue(value: string, env: NodeJS.ProcessEnv): string | undefined {
  if (value.startsWith("!")) {
    throw new GrclankerFlueConfigError(
      `models.json apiKey values that run a shell command ("!...") are not supported under Flue. Store the key literally or reference an environment variable with $NAME.`,
    );
  }

  let missing = false;
  const resolved = value.replace(ENV_TEMPLATE, (_match, braced: string | undefined, bare: string | undefined) => {
    const name = braced ?? bare ?? "";
    const found = env[name];
    if (found === undefined || found.length === 0) missing = true;
    return found ?? "";
  });
  return missing ? undefined : resolved;
}

function buildModels(config: CustomProviderConfig, warnings: string[]): Model<Api>[] {
  const models: Model<Api>[] = [];

  for (const model of config.models) {
    const api = model.api ?? config.api;
    const baseUrl = model.baseUrl ?? config.baseUrl;
    if (!api || !API_FACTORIES[api]) {
      warnings.push(
        `Skipping ${config.id}/${model.id} for Flue: api "${api ?? "(none)"}" is not one of ${Object.keys(API_FACTORIES).join(", ")}.`,
      );
      continue;
    }
    if (!baseUrl) {
      warnings.push(`Skipping ${config.id}/${model.id} for Flue: no baseUrl on the model or provider.`);
      continue;
    }
    const compat = { ...config.compat, ...model.compat };
    models.push({
      id: model.id,
      name: model.name ?? model.id,
      api,
      provider: config.id,
      baseUrl,
      reasoning: model.reasoning ?? false,
      input: model.input ?? ["text"],
      cost: model.cost ?? ZERO_COST,
      contextWindow: model.contextWindow ?? DEFAULT_CONTEXT_WINDOW,
      maxTokens: model.maxTokens ?? DEFAULT_MAX_TOKENS,
      ...(Object.keys(compat).length > 0 ? { compat: compat as Model<Api>["compat"] } : {}),
    });
  }

  return models;
}

/** Build a Pi provider for one `models.json` entry; undefined when none of its models can be served. */
export function createCustomProvider(
  config: CustomProviderConfig,
  env: NodeJS.ProcessEnv,
  warnings: string[] = [],
): Provider | undefined {
  const models = buildModels(config, warnings);
  if (models.length === 0) return undefined;

  const apiIds = [...new Set(models.map((model) => model.api))];
  const api =
    apiIds.length === 1
      ? API_FACTORIES[apiIds[0]]()
      : Object.fromEntries(apiIds.map((id) => [id, API_FACTORIES[id]()]));
  const apiKey = config.apiKey;
  const headers = config.headers;

  return createProvider({
    id: config.id,
    name: config.id,
    baseUrl: config.baseUrl,
    headers,
    auth: {
      apiKey: {
        name: `${config.id} API key (grclanker models.json)`,
        async resolve() {
          const resolvedKey = apiKey === undefined ? undefined : resolveApiKeyValue(apiKey, env);
          if (apiKey !== undefined && resolvedKey === undefined) return undefined;
          return {
            auth: { ...(resolvedKey === undefined ? {} : { apiKey: resolvedKey }), ...(headers ? { headers } : {}) },
            source: "grclanker models.json",
          };
        },
      },
    },
    models,
    api,
  });
}

/**
 * Register every custom provider grclanker knows about with Flue. Reads
 * `~/.grclanker/agent/models.json` and settings.json unless given explicitly.
 */
export function registerGrclankerProviders(input: RegisterProvidersInput): RegisterProvidersResult {
  const settings = input.settings ?? readGrclankerSettings(getGrclankerSettingsPath());
  const modelsConfig = input.modelsConfig ?? readJson(getGrclankerModelsPath());
  const setProvider = input.setProvider ?? flueSetProvider;
  const warnings: string[] = [];

  const configs = listCustomProviderConfigs(modelsConfig);
  const fallback = localProviderConfigFromSettings(settings);
  if (fallback && !configs.some((config) => config.id === fallback.id)) configs.push(fallback);

  const providerIds: string[] = [];
  for (const config of configs) {
    const provider = createCustomProvider(config, input.env, warnings);
    if (!provider) continue;
    setProvider(asFlueProvider(provider));
    providerIds.push(config.id);
  }

  return { providerIds, warnings };
}

/** Cross the pi-ai declaration-file boundary described on {@link FlueProvider}. */
export function asFlueProvider(provider: Provider): FlueProvider {
  return provider as unknown as FlueProvider;
}
