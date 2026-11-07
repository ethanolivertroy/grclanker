import Anthropic from "@anthropic-ai/sdk";
import { betaTool } from "@anthropic-ai/sdk/helpers/beta/json-schema";
import type { BetaRunnableTool } from "@anthropic-ai/sdk/lib/tools/BetaRunnableTool";
import { ToolError } from "@anthropic-ai/sdk/lib/tools/ToolError";
import type { BetaToolRunnerParams } from "@anthropic-ai/sdk/lib/tools/BetaToolRunner";
import type { BetaToolResultContentBlockParam } from "@anthropic-ai/sdk/resources/beta";
import { isGrcWriteTool } from "../../core/effects.js";
import { buildGrclankerInstructions } from "../../core/instructions.js";
import { personaAgentConfig, PERSONA_NAMES, type PersonaName } from "../../core/personas.js";
import { getRegisteredGrcTool, type RegisteredGrcTool } from "../../core/registry.js";
import type { GrcToolEnvelope } from "../../core/results.js";
import { toJsonSchema } from "../../core/schema.js";
import { bundledSkillConfig, WORKFLOW_NAMES, workflowSkillConfig, type WorkflowName } from "../../core/skills.js";
import { executeGrcTool } from "../../core/tools.js";
import { toSdkToolResult } from "../../core/results.js";

type ToolResultContent = BetaToolResultContentBlockParam;

export const DEFAULT_CLAUDE_API_GRC_TOOLS = [
  "cmvp_search_modules",
  "cmvp_get_module",
  "kevs_search",
  "kevs_get_epss",
] as const;

export const CLAUDE_API_MODEL_ENV_VAR = "GRCLANKER_CLAUDE_API_MODEL";
export const DEFAULT_CLAUDE_API_MODEL = "claude-opus-5-5";
export const SERVER_SIDE_FALLBACK_BETA = "server-side-fallback-2026-07-01";
export const MAX_ITERATIONS = 30;
const MAX_TOKENS = 16000;

export const CLAUDE_API_RUNTIME_NOTE = `## Claude API tool runner runtime

The registered tools are the selected grclanker domain tools plus grclanker_load_workflow, grclanker_load_skill, auditor, and verifier. Only use tools actually present in this run. Before a structured investigation, audit, assessment, or validation, load the matching workflow with grclanker_load_workflow. grclanker_load_skill loads the crypto-validation methodology.

The auditor and verifier are evidence-review tools backed by a separate model call: supply collected evidence and source references in their evidence input. They cannot gather new evidence or run tenant tools. Ask auditor to map evidence to controls, and verifier to check the final evidence chain. You remain responsible for the final answer.

A tool result marked as an error is a failure; never describe a failed access check as a compliant system. A missing tool or credential means evidence is unavailable. Support governance, risk analysis, control mapping, remediation planning, and compliance engineering using available evidence; proposed policies or risk acceptance decisions are drafts for the organization's owners.

Write tools ask a human operator to approve each call before executing; a declined call did not run. Explain what will be written. Paths resolve against this Node process's working directory; prefer absolute output_dir, workspace_dir, or zip_path values and report the returned paths. No shell, file, web, or code-editing tools, Pi compute backend, slash commands, or terminal setup wizard are installed in this agent.
`;

export interface WriteApprovalRequest {
  toolName: string;
  input: Record<string, unknown>;
}

export interface GrclankerClaudeApiOptions {
  /** Choose only tools relevant to this deployment; defaults to public-data lookups. */
  toolNames?: readonly string[];
  model?: string;
  /** Ask an authenticated operator about one write call. Without it, every write is declined. */
  approveWrite?: (request: WriteApprovalRequest) => Promise<boolean>;
  /** Re-run a declined turn on Anthropic's fallback model (Claude API only). Default true. */
  serverSideFallback?: boolean;
}

function toToolResultContent(envelope: GrcToolEnvelope): ToolResultContent[] {
  return envelope.content.map((entry): ToolResultContent => entry.type === "text"
    ? { type: "text", text: entry.text }
    : {
      type: "image",
      source: { type: "base64", media_type: entry.mimeType as "image/png", data: entry.data },
    });
}

/** Adapt one native tool. Native TypeBox validation runs in the shared executor. */
export function createClaudeApiGrcTool(
  nativeTool: RegisteredGrcTool,
  approveWrite?: GrclankerClaudeApiOptions["approveWrite"],
): BetaRunnableTool {
  const schema = toJsonSchema(nativeTool.parameters) as { type: "object" };
  const writes = isGrcWriteTool(nativeTool.name);
  return betaTool({
    name: nativeTool.name,
    description: nativeTool.description,
    inputSchema: { ...schema, type: "object" },
    async run(input, context) {
      if (!input || typeof input !== "object" || Array.isArray(input)) {
        throw new ToolError("Expected a JSON object for the tool arguments.");
      }
      const args = input as Record<string, unknown>;
      // The gate runs inside run(), so a writer executes only after approval
      // of these exact arguments.
      if (writes && !(approveWrite && await approveWrite({ toolName: nativeTool.name, input: args }))) {
        throw new ToolError("The operator did not approve this write; it did not run.");
      }
      const envelope = toSdkToolResult(await executeGrcTool(nativeTool, args, {
        toolCallId: context?.toolUse.id,
        signal: context?.signal ?? undefined,
      }));
      const content = toToolResultContent(envelope);
      if (envelope.isError) throw new ToolError(content);
      return content;
    },
  }) as BetaRunnableTool;
}

function reviewerTool(client: Anthropic, model: string, name: PersonaName): BetaRunnableTool {
  const persona = personaAgentConfig(name);
  const system = `${persona.instructions}\n\nYou have no external tools. Review only the supplied evidence and explicitly identify missing evidence.`;
  return betaTool({
    name,
    description: persona.description,
    inputSchema: {
      type: "object",
      properties: {
        evidence: { type: "string", description: "Collected evidence, source references, and the question to review" },
      },
      required: ["evidence"],
      additionalProperties: false,
    },
    async run({ evidence }, context) {
      if (typeof evidence !== "string" || !evidence.trim()) throw new ToolError("Supply the evidence to review.");
      const response = await client.messages.create({
        model,
        max_tokens: MAX_TOKENS,
        system,
        messages: [{ role: "user", content: evidence }],
      }, { signal: context?.signal ?? undefined });
      if (response.stop_reason === "refusal") throw new ToolError(`The ${name} review was declined.`);
      const text = response.content.flatMap((block) => block.type === "text" ? [block.text] : []).join("\n").trim();
      if (!text) throw new ToolError(`The ${name} review returned no text.`);
      return text;
    },
  }) as BetaRunnableTool;
}

export interface GrclankerClaudeApiAgent {
  model: string;
  tools: BetaRunnableTool[];
  /** Tool runner parameters without messages; add them per run. */
  params: Omit<BetaToolRunnerParams, "messages">;
}

/** Build tool runner parameters from the provider-neutral registry. */
export function createGrclankerClaudeApiAgent(
  client: Anthropic,
  options: GrclankerClaudeApiOptions = {},
): GrclankerClaudeApiAgent {
  const toolNames = [...new Set(options.toolNames ?? DEFAULT_CLAUDE_API_GRC_TOOLS)];
  if (toolNames.length === 0 || toolNames.some((name) => !name)) {
    throw new Error("Select at least one grclanker tool name.");
  }
  const model = options.model ?? (process.env[CLAUDE_API_MODEL_ENV_VAR]?.trim() || DEFAULT_CLAUDE_API_MODEL);
  const domainTools = toolNames.map((name) => createClaudeApiGrcTool(getRegisteredGrcTool(name), options.approveWrite));
  const workflowLoader = betaTool({
    name: "grclanker_load_workflow",
    description: "Load the grclanker investigate, audit, assess, or validate workflow before a structured GRC task.",
    inputSchema: {
      type: "object",
      properties: { name: { type: "string", enum: [...WORKFLOW_NAMES] } },
      required: ["name"],
      additionalProperties: false,
    },
    run({ name }) {
      if (typeof name !== "string" || !WORKFLOW_NAMES.includes(name as WorkflowName)) {
        throw new ToolError("Choose investigate, audit, assess, or validate.");
      }
      return workflowSkillConfig(name as WorkflowName).markdown;
    },
  }) as BetaRunnableTool;
  const skillLoader = betaTool({
    name: "grclanker_load_skill",
    description: "Load the bundled crypto-validation methodology for cryptographic module validation.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
    run: () => bundledSkillConfig("crypto-validation").markdown,
  }) as BetaRunnableTool;
  const tools = [
    ...domainTools,
    workflowLoader,
    skillLoader,
    ...PERSONA_NAMES.map((name) => reviewerTool(client, model, name)),
  ];
  const fallback = options.serverSideFallback ?? true;
  return {
    model,
    tools,
    params: {
      model,
      max_tokens: MAX_TOKENS,
      max_iterations: MAX_ITERATIONS,
      // Keep evidence out of server-kept message threads; resend history each turn.
      thread: false,
      thinking: { type: "adaptive" },
      output_config: { effort: "high" },
      // The instructions and tool list are stable, so cache them as the prefix.
      system: [{ type: "text", text: buildGrclankerInstructions(CLAUDE_API_RUNTIME_NOTE), cache_control: { type: "ephemeral" } }],
      tools,
      ...(fallback ? { betas: [SERVER_SIDE_FALLBACK_BETA], fallbacks: "default" as const } : {}),
    },
  };
}
