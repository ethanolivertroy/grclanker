/**
 * Compose the grclanker Flue agent render from injected hooks.
 *
 * `agent.ts` passes the real `@flue/runtime` hooks; tests pass recorders.
 * Everything expensive (tool bridging, prompt loading) happens once in
 * `loadGrclankerFlueAgentOptions()`, while `renderGrclankerAgent()` stays a
 * cheap per-render declaration pass, matching Flue's re-render model.
 */
import type { SandboxFactory, SkillDefinition, SubagentDefinition, ToolDefinition } from "@flue/runtime";
import type { LocalSandboxOptions } from "@flue/runtime/node";
import { getGrclankerSettingsPath } from "../config/paths.js";
import { readGrclankerSettings, type GrclankerSettings } from "../pi/settings.js";
import {
  loadGrclankerAgentContent,
  resolveFlueAppRoot,
  type GrclankerAgentContent,
  type GrclankerSubagentRole,
} from "./content.js";
import { createGrclankerFlueTools } from "./tools.js";

export interface FlueAgentHooks {
  useModel(model: string): void;
  useTool(tool: ToolDefinition): void;
  useSkill(skill: SkillDefinition): void;
  useSubagent(subagent: SubagentDefinition): void;
  useSandbox(sandbox: SandboxFactory): void;
}

export type FlueSandboxMode = "local" | "none";

export type CreateLocalSandbox = (options?: LocalSandboxOptions) => SandboxFactory;

export interface GrclankerFlueAgentOptions {
  model: string;
  sandbox: FlueSandboxMode;
  cwd: string;
  content: GrclankerAgentContent;
  tools: ToolDefinition[];
  createLocalSandbox: CreateLocalSandbox;
}

export interface LoadGrclankerFlueAgentOptionsInput {
  currentDir: string;
  env: NodeJS.ProcessEnv;
  cwd: string;
  createLocalSandbox: CreateLocalSandbox;
  settings?: GrclankerSettings;
  /** Provider ids registered with Flue's `setProvider()` on top of Pi's built-ins. */
  customProviderIds?: readonly string[];
}

export const DEFAULT_FLUE_MODEL = "anthropic/claude-sonnet-4-6";
export const FLUE_MODEL_ENV = "GRCLANKER_FLUE_MODEL";
export const FLUE_SANDBOX_ENV = "GRCLANKER_FLUE_SANDBOX";

/** A user-facing configuration problem in the Flue adapter (no stack trace needed). */
export class GrclankerFlueConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "GrclankerFlueConfigError";
  }
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

/**
 * Pick the `provider/model` specifier Flue should run with. Explicit env wins,
 * then the `grclanker setup` choice (hosted, or local-first when the adapter
 * registered that provider from models.json), then Flue's documented default.
 * A local-first setup whose provider could not be registered is rejected
 * instead of silently switching providers.
 */
export function resolveFlueModel(
  env: NodeJS.ProcessEnv,
  settings: GrclankerSettings,
  customProviderIds: readonly string[] = [],
): string {
  const explicit = env[FLUE_MODEL_ENV]?.trim();
  if (explicit) return explicit;

  const provider = isNonEmptyString(settings.defaultProvider) ? settings.defaultProvider.trim() : undefined;
  const configured =
    provider && isNonEmptyString(settings.defaultModel) ? `${provider}/${settings.defaultModel.trim()}` : undefined;

  if (settings.modelMode === "local" && !(provider && customProviderIds.includes(provider))) {
    throw new GrclankerFlueConfigError(
      [
        `grclanker is configured for a local model${configured ? ` (${configured})` : ""}, but this adapter found no usable provider entry for "${provider ?? "(unset)"}" in models.json to register with Flue.`,
        `Rerun grclanker setup, or set ${FLUE_MODEL_ENV}=<provider/model> (for example ${DEFAULT_FLUE_MODEL}) with that provider's API key in the environment.`,
      ].join(" "),
    );
  }

  return configured ?? DEFAULT_FLUE_MODEL;
}

export function resolveFlueSandboxMode(env: NodeJS.ProcessEnv): FlueSandboxMode {
  const raw = env[FLUE_SANDBOX_ENV]?.trim().toLowerCase();
  if (!raw || raw === "local") return "local";
  if (raw === "none") return "none";
  throw new GrclankerFlueConfigError(`${FLUE_SANDBOX_ENV} must be "local" or "none" (got "${raw}").`);
}

function listSkillNames(skills: SkillDefinition[]): string {
  return skills.map((skill) => `\`${skill.name}\``).join(", ");
}

/** The instruction document: the shipped SYSTEM.md plus a short note on the Flue-specific surface. */
export function buildFlueInstructions(content: GrclankerAgentContent, sandbox: FlueSandboxMode): string {
  const lines = ["## Flue Runtime", "", "You are running as a Flue agent with the grclanker domain tools mounted directly."];

  if (content.workflows.length > 0) {
    lines.push(
      `Workflow skills mirror the grclanker slash commands: activate ${listSkillNames(content.workflows)} before starting that workflow.`,
    );
  }
  if (content.skills.length > 0) {
    lines.push(`Additional skills: ${listSkillNames(content.skills)}.`);
  }
  if (content.roles.length > 0) {
    lines.push(
      `The ${content.roles.map((role) => `\`${role.name}\``).join(" and ")} roles are available as subagents through the \`task\` tool.`,
    );
  }

  switch (sandbox) {
    case "local":
      lines.push("A local sandbox provides file and shell tools for the current working directory.");
      break;
    case "none":
      lines.push("No sandbox is attached, so there are no file or shell tools; rely on the domain tools.");
      break;
    default: {
      const exhaustive: never = sandbox;
      throw new Error(`Unhandled sandbox mode: ${String(exhaustive)}`);
    }
  }

  return `${content.systemPrompt.trimEnd()}\n\n${lines.join("\n")}\n`;
}

/** Turn a persona file into a Flue subagent that mounts only its allowed tools. */
export function createSubagentDefinition(
  role: GrclankerSubagentRole,
  tools: ToolDefinition[],
  hooks: Pick<FlueAgentHooks, "useTool">,
): SubagentDefinition {
  const allowed = new Set(role.allowedTools);
  const roleTools = tools.filter((tool) => allowed.has(tool.name));

  return {
    name: role.name,
    description: role.description,
    agent: () => {
      for (const tool of roleTools) hooks.useTool(tool);
      return role.instructions;
    },
  };
}

export function loadGrclankerFlueAgentOptions(input: LoadGrclankerFlueAgentOptionsInput): GrclankerFlueAgentOptions {
  const settings = input.settings ?? readGrclankerSettings(getGrclankerSettingsPath());
  const appRoot = resolveFlueAppRoot(input.currentDir);

  return {
    model: resolveFlueModel(input.env, settings, input.customProviderIds),
    sandbox: resolveFlueSandboxMode(input.env),
    cwd: input.cwd,
    content: loadGrclankerAgentContent(appRoot),
    tools: createGrclankerFlueTools(),
    createLocalSandbox: input.createLocalSandbox,
  };
}

/** One agent render: declare model, sandbox, tools, skills, and subagents, then return the instructions. */
export function renderGrclankerAgent(hooks: FlueAgentHooks, options: GrclankerFlueAgentOptions): string {
  hooks.useModel(options.model);

  switch (options.sandbox) {
    case "local":
      hooks.useSandbox(options.createLocalSandbox({ cwd: options.cwd }));
      break;
    case "none":
      break;
    default: {
      const exhaustive: never = options.sandbox;
      throw new Error(`Unhandled sandbox mode: ${String(exhaustive)}`);
    }
  }

  for (const tool of options.tools) hooks.useTool(tool);
  for (const skill of [...options.content.workflows, ...options.content.skills]) hooks.useSkill(skill);
  for (const role of options.content.roles) hooks.useSubagent(createSubagentDefinition(role, options.tools, hooks));

  return buildFlueInstructions(options.content, options.sandbox);
}
