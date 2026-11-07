import { Agent, tool, type Model, type ToolInputParameters } from "@openai/agents";
import { isGrcWriteTool } from "../runtime/effects.js";
import { buildGrclankerInstructions } from "../runtime/instructions.js";
import { personaAgentConfig, PERSONA_NAMES } from "../runtime/personas.js";
import { getRegisteredGrcTool, type RegisteredGrcTool } from "../runtime/registry.js";
import { errorEnvelope } from "../runtime/results.js";
import { toJsonSchema } from "../runtime/schema.js";
import { bundledSkillConfig, WORKFLOW_NAMES, workflowSkillConfig, type WorkflowName } from "../runtime/skills.js";
import { executeGrcTool } from "../runtime/tools.js";

export const DEFAULT_OPENAI_GRC_TOOLS = [
  "cmvp_search_modules",
  "cmvp_get_module",
  "kevs_search",
  "kevs_get_epss",
] as const;

export const OPENAI_MODEL_ENV_VAR = "GRCLANKER_OPENAI_MODEL";
export const DEFAULT_OPENAI_MODEL = "gpt-5.4";
// Leave space for the workflow, skill, and two evidence-review agent tools.
export const MAX_OPENAI_GRC_TOOLS = 124;

export const OPENAI_RUNTIME_NOTE = `## OpenAI Agents SDK runtime

The registered tools are the selected grclanker domain tools plus grclanker_load_workflow, grclanker_load_skill, auditor, and verifier. Only use tools actually present in this run. Before a structured investigation, audit, assessment, or validation, load the matching workflow with grclanker_load_workflow. grclanker_load_skill loads the crypto-validation methodology.

The auditor and verifier are evidence-review agents: supply collected evidence and source references in their input. They cannot gather new evidence or run tenant tools. Ask auditor to map evidence to controls, and verifier to check the final evidence chain. You remain responsible for the final answer.

Native tools return a JSON envelope with content and an optional isError flag. Treat isError as failure, and never describe a failed access check as a compliant system. A missing tool or credential means evidence is unavailable. Support governance, risk analysis, control mapping, remediation planning, and compliance engineering using available evidence; proposed policies or risk acceptance decisions are drafts for the organization's owners.

Write tools pause for per-call human approval through the OpenAI SDK before executing. Explain what will be written. Paths resolve against this Node process's working directory; prefer absolute output_dir, workspace_dir, or zip_path values and report the returned paths. No generic shell or file tools, Pi compute backend, slash commands, or terminal setup wizard are installed in this agent.
`;

type NonStrictParameters = Extract<ToolInputParameters, { additionalProperties: true }>;

/** Adapt one native tool; the OpenAI runner enforces needsApproval before invoke. */
export function createOpenAIGrcTool(nativeTool: RegisteredGrcTool) {
  const schema = toJsonSchema(nativeTool.parameters);
  // Retain optional native arguments. Native TypeBox validation runs below,
  // rather than rewriting every optional property into a required nullable one.
  const parameters = {
    ...schema,
    type: "object",
    properties: schema.properties,
    required: Array.isArray(schema.required) ? schema.required : [],
    additionalProperties: true,
  } as NonStrictParameters;
  return tool({
    name: nativeTool.name,
    description: nativeTool.description,
    parameters,
    strict: false,
    needsApproval: isGrcWriteTool(nativeTool.name),
    async execute(input, _context, details) {
      if (!input || typeof input !== "object" || Array.isArray(input)) {
        return errorEnvelope("Expected a JSON object for the tool arguments.");
      }
      return executeGrcTool(nativeTool, input as Record<string, unknown>, {
        toolCallId: details?.toolCall?.callId,
        signal: details?.signal,
      });
    },
  });
}

export interface GrclankerOpenAIAgentOptions {
  /** Choose only tools relevant to this deployment; defaults to public-data lookups. */
  toolNames?: readonly string[];
  model?: string | Model;
}

/** Build an independent OpenAI Agents SDK agent from the provider-neutral registry. */
export function createGrclankerOpenAIAgent(options: GrclankerOpenAIAgentOptions = {}) {
  const toolNames = [...new Set(options.toolNames ?? DEFAULT_OPENAI_GRC_TOOLS)];
  if (toolNames.length > MAX_OPENAI_GRC_TOOLS) {
    throw new Error(`Select at most ${MAX_OPENAI_GRC_TOOLS} domain tools for one OpenAI agent; split larger deployments by scope.`);
  }
  const model = options.model ?? (process.env[OPENAI_MODEL_ENV_VAR]?.trim() || DEFAULT_OPENAI_MODEL);
  const domainTools = toolNames.map((name) => createOpenAIGrcTool(getRegisteredGrcTool(name)));
  const workflowLoader = tool({
    name: "grclanker_load_workflow",
    description: "Load the grclanker investigate, audit, assess, or validate workflow before a structured GRC task.",
    parameters: {
      type: "object",
      properties: { name: { type: "string", enum: [...WORKFLOW_NAMES] } },
      required: ["name"],
      additionalProperties: false,
    },
    execute(input: unknown) {
      const name = (input as { name?: unknown })?.name;
      if (typeof name !== "string" || !WORKFLOW_NAMES.includes(name as WorkflowName)) {
        return errorEnvelope("Choose investigate, audit, assess, or validate.");
      }
      return workflowSkillConfig(name as WorkflowName).markdown;
    },
  });
  const skillLoader = tool({
    name: "grclanker_load_skill",
    description: "Load the bundled crypto-validation methodology for cryptographic module validation.",
    parameters: { type: "object", properties: {}, required: [], additionalProperties: false },
    execute: () => bundledSkillConfig("crypto-validation").markdown,
  });
  const reviewAgents = PERSONA_NAMES.map((name) => {
    const persona = personaAgentConfig(name);
    return new Agent({
      name,
      model,
      instructions: `${persona.instructions}\n\nYou have no external tools. Review only the supplied evidence and explicitly identify missing evidence.`,
    }).asTool({ toolName: name, toolDescription: persona.description });
  });
  return new Agent({
    name: "grclanker",
    model,
    instructions: buildGrclankerInstructions(OPENAI_RUNTIME_NOTE),
    modelSettings: { parallelToolCalls: false },
    tools: [...domainTools, workflowLoader, skillLoader, ...reviewAgents],
  });
}
