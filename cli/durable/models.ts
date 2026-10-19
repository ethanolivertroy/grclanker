/**
 * Model access for durable runs, taken from grclanker's existing setup.
 *
 * The model is `--model`, else GRCLANKER_DURABLE_MODEL, else the provider and
 * model `grclanker setup` saved. Credentials and custom providers come from
 * the `auth.json` and `models.json` the interactive CLI uses, loaded through
 * Pi's own model runtime, so any model the interactive CLI can reach works here.
 */
import { resolve } from "node:path";
import type { Models, ModelThinkingLevel } from "@earendil-works/pi-ai";
import { ModelRuntime } from "@earendil-works/pi-coding-agent";
import type { ModelRef } from "@earendil-works/pi-durable";
import { getGrclankerAgentDir } from "../config/paths.js";
import { readJson, type GrclankerSettings } from "../pi/settings.js";
import { DurableUserError } from "./errors.js";

export const DURABLE_MODEL_ENV = "GRCLANKER_DURABLE_MODEL";

const THINKING_LEVELS: readonly ModelThinkingLevel[] = ["off", "minimal", "low", "medium", "high", "xhigh", "max"];

export interface DurableModelChoice {
  model: ModelRef;
  /** The `defaultThinkingLevel` setting; absent leaves the model's own default. */
  thinkingLevel?: ModelThinkingLevel;
}

export interface ResolveDurableModelInput {
  flag?: string;
  env: NodeJS.ProcessEnv;
  settings: GrclankerSettings;
}

function optionalString(value: unknown): string | undefined {
  return typeof value === "string" && value.trim().length > 0 ? value.trim() : undefined;
}

function isThinkingLevel(value: unknown): value is ModelThinkingLevel {
  return typeof value === "string" && (THINKING_LEVELS as readonly string[]).includes(value);
}

export function formatModelRef(model: ModelRef): string {
  return `${model.provider}/${model.modelId}`;
}

/** Split `provider/model` at the first slash; model ids may contain more slashes. */
export function parseModelSpecifier(specifier: string, origin: string): ModelRef {
  const trimmed = specifier.trim();
  const slash = trimmed.indexOf("/");
  if (slash <= 0 || slash === trimmed.length - 1) {
    throw new DurableUserError(
      `${origin} must look like <provider>/<model>, for example anthropic/claude-sonnet-4-6 (got "${trimmed}").`,
    );
  }
  return { provider: trimmed.slice(0, slash), modelId: trimmed.slice(slash + 1) };
}

export function resolveDurableModelChoice(input: ResolveDurableModelInput): DurableModelChoice {
  const thinkingLevel = isThinkingLevel(input.settings.defaultThinkingLevel)
    ? input.settings.defaultThinkingLevel
    : undefined;
  const choose = (model: ModelRef): DurableModelChoice => (thinkingLevel ? { model, thinkingLevel } : { model });

  if (input.flag !== undefined) return choose(parseModelSpecifier(input.flag, "--model"));

  const fromEnv = optionalString(input.env[DURABLE_MODEL_ENV]);
  if (fromEnv) return choose(parseModelSpecifier(fromEnv, DURABLE_MODEL_ENV));

  const provider = optionalString(input.settings.defaultProvider);
  const modelId = optionalString(input.settings.defaultModel);
  if (provider && modelId) return choose({ provider, modelId });

  throw new DurableUserError(
    `No model is configured. Run grclanker setup, or pass --model <provider>/<model> (or set ${DURABLE_MODEL_ENV}).`,
  );
}

/** Pi's model runtime over grclanker's `auth.json` and `models.json`, with no network catalog refresh. */
export async function loadGrclankerModels(agentDir = getGrclankerAgentDir()): Promise<Models> {
  const modelsPath = resolve(agentDir, "models.json");
  // Pi's own JSON parse error can quote the malformed line, which may hold an API key; grclanker's reader never does.
  readJson(modelsPath);
  return ModelRuntime.create({ authPath: resolve(agentDir, "auth.json"), modelsPath });
}

export function assertModelAvailable(models: Models, model: ModelRef): void {
  if (models.getModel(model.provider, model.modelId)) return;
  const configError = models instanceof ModelRuntime ? models.getError() : undefined;
  throw new DurableUserError(
    [
      `Unknown model ${formatModelRef(model)}.`,
      configError ? `models.json: ${configError}` : undefined,
      "Check the provider and model id, or rerun grclanker setup.",
    ]
      .filter((part) => part !== undefined)
      .join(" "),
  );
}
