import { isGrcWriteTool } from "../../dist/core/effects.js";
import { buildGrclankerInstructions } from "../../dist/core/instructions.js";
import { personaAgentConfig, PERSONA_NAMES } from "../../dist/core/personas.js";
import {
  createGrclankerMcpServer,
  MCP_SERVER_NAME,
  MCP_TOOL_PREFIX,
  SKILL_LOADER,
  WORKFLOW_LOADER,
  WriteApprovals,
} from "./server.mjs";
import { selectTools } from "./tools.mjs";

export const CLAUDE_MODEL_ENV_VAR = "GRCLANKER_CLAUDE_MODEL";
export const DEFAULT_CLAUDE_MODEL = "claude-opus-5-5";
/** The only built-in Claude Code tool enabled: it launches the reviewer subagents. */
export const SUBAGENT_TOOL = "Agent";

export const CLAUDE_RUNTIME_NOTE = `## Claude Agent SDK runtime

The registered tools are the selected grclanker domain tools plus ${WORKFLOW_LOADER} and ${SKILL_LOADER}, served by the in-process "${MCP_SERVER_NAME}" MCP server, and the ${SUBAGENT_TOOL} tool for the auditor and verifier subagents. Only use tools actually present in this run. Before a structured investigation, audit, assessment, or validation, load the matching workflow with ${WORKFLOW_LOADER}. ${SKILL_LOADER} loads the crypto-validation methodology.

The auditor and verifier are evidence-review subagents with no tools: supply collected evidence and source references in their prompt. They cannot gather new evidence or run tenant tools. Ask auditor to map evidence to controls, and verifier to check the final evidence chain. You remain responsible for the final answer.

Native tools return content and an optional isError flag. Treat isError as failure, and never describe a failed access check as a compliant system. A missing tool or credential means evidence is unavailable. Support governance, risk analysis, control mapping, remediation planning, and compliance engineering using available evidence; proposed policies or risk acceptance decisions are drafts for the organization's owners.

Write tools pause for per-call human approval before executing; a denied call did not run. Explain what will be written. Paths resolve against the host Node process's working directory; prefer absolute output_dir, workspace_dir, or zip_path values and report the returned paths. No shell, file, web, or code-editing tools, Pi compute backend, slash commands, or terminal setup wizard are installed in this agent.
`;

/** @param {string} name */
export const mcpToolName = (name) => `${MCP_TOOL_PREFIX}${name}`;

/** Agent is automatically permitted by Claude Code, so enforce reviewer scope in a hook. */
export async function restrictReviewerAgents(input) {
  if (input.tool_name !== SUBAGENT_TOOL) return {};
  if (PERSONA_NAMES.includes(input.tool_input?.subagent_type) && input.tool_input?.isolation === undefined) return {};
  return {
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: "deny",
      permissionDecisionReason: "Only the auditor and verifier evidence-review agents are enabled, without worktree or remote isolation.",
    },
  };
}

/** Stop waiting immediately when a permission request is cancelled, including a slow UI. */
async function requestApproval(approveWrite, request) {
  const { signal } = request;
  if (signal.aborted) return false;
  let onAbort;
  const cancelled = new Promise((resolve) => {
    onAbort = () => resolve(false);
    signal.addEventListener("abort", onAbort, { once: true });
  });
  try {
    const approved = await Promise.race([
      Promise.resolve().then(() => signal.aborted ? false : approveWrite(request)).catch(() => false),
      cancelled,
    ]);
    return approved === true && !signal.aborted;
  } finally {
    signal.removeEventListener("abort", onAbort);
  }
}

/**
 * Build Claude Agent SDK `query()` options for grclanker.
 *
 * The SDK runs in isolation mode: no user, project, or local Claude settings,
 * CLAUDE.md files, skills, plugins, or other MCP servers are loaded, and every
 * built-in Claude Code tool except the subagent launcher is removed.
 *
 * @param {object} [options]
 * @param {readonly string[]} [options.toolNames] Domain tools for this deployment; defaults to public-data lookups.
 * @param {string} [options.model] Claude model ID or alias; defaults to GRCLANKER_CLAUDE_MODEL, then DEFAULT_CLAUDE_MODEL.
 * @param {(request: { toolName: string; input: Record<string, unknown>; signal: AbortSignal }) => Promise<boolean>} [options.approveWrite]
 *   Ask an authenticated operator about one write call. Without it, every write is denied.
 * @param {boolean} [options.persistSession] Save the transcript under ~/.claude/projects for resume (default false).
 * @param {Record<string, string | undefined>} [options.env] Environment for the Claude Code process (default process.env).
 * @param {string} [options.cwd] Working directory for the Claude Code process (default process.cwd()).
 */
export function createGrclankerClaudeOptions(options = {}) {
  const tools = selectTools(options.toolNames);
  const approvals = new WriteApprovals();
  const model = options.model ?? (process.env[CLAUDE_MODEL_ENV_VAR]?.trim() || DEFAULT_CLAUDE_MODEL);
  const writers = new Set(tools.filter((tool) => isGrcWriteTool(tool.name)).map((tool) => mcpToolName(tool.name)));
  const readers = new Set([
    ...tools.filter((tool) => !isGrcWriteTool(tool.name)).map((tool) => mcpToolName(tool.name)),
    mcpToolName(WORKFLOW_LOADER),
    mcpToolName(SKILL_LOADER),
  ]);
  const agents = Object.fromEntries(PERSONA_NAMES.map((name) => {
    const persona = personaAgentConfig(name);
    return [name, {
      description: persona.description,
      prompt: `${persona.instructions}\n\nYou have no external tools. Review only the supplied evidence and explicitly identify missing evidence.`,
      tools: [],
      disallowedTools: [`mcp__${MCP_SERVER_NAME}`],
      model: "inherit",
    }];
  }));

  // Native calls have no allowedTools/settings pre-approvals. Agent itself is
  // automatically permitted by the SDK; its hook enforces the reviewer scope.
  /** @type {import("@anthropic-ai/claude-agent-sdk").CanUseTool} */
  const canUseTool = async (toolName, input, { signal, mcpServer }) => {
    // Key trust on the server's provenance, not on the tool-name prefix.
    const ours = toolName.startsWith(MCP_TOOL_PREFIX) ? mcpServer?.source === undefined || mcpServer.source === "sdk" : true;
    if (ours && (toolName === SUBAGENT_TOOL || readers.has(toolName))) {
      return { behavior: "allow", updatedInput: input };
    }
    if (!ours || !writers.has(toolName)) {
      return { behavior: "deny", message: `${toolName} is not enabled in this grclanker deployment.` };
    }
    const approved = options.approveWrite
      ? await requestApproval(options.approveWrite, { toolName: toolName.slice(MCP_TOOL_PREFIX.length), input, signal })
      : false;
    if (!approved) {
      return { behavior: "deny", message: "The operator did not approve this write; it did not run." };
    }
    if (signal.aborted) return { behavior: "deny", message: "Write approval was cancelled; it did not run." };
    approvals.grant(toolName.slice(MCP_TOOL_PREFIX.length), input, signal);
    return { behavior: "allow", updatedInput: input };
  };

  /** @type {import("@anthropic-ai/claude-agent-sdk").Options} */
  const queryOptions = {
    model,
    systemPrompt: buildGrclankerInstructions(CLAUDE_RUNTIME_NOTE),
    mcpServers: { [MCP_SERVER_NAME]: createGrclankerMcpServer(tools, approvals) },
    strictMcpConfig: true,
    tools: [SUBAGENT_TOOL],
    agents,
    hooks: { PreToolUse: [{ matcher: SUBAGENT_TOOL, hooks: [restrictReviewerAgents] }] },
    canUseTool,
    permissionMode: "default",
    settingSources: [],
    skills: [],
    persistSession: options.persistSession ?? false,
    maxTurns: 30,
    cwd: options.cwd ?? process.cwd(),
    env: {
      ...(options.env ?? process.env),
      CLAUDE_AGENT_SDK_CLIENT_APP: "grclanker-claude-agent-sdk/0.1.0",
    },
  };
  return {
    options: queryOptions,
    tools,
    model,
    readTools: [SUBAGENT_TOOL, ...readers],
    approvalTools: [...writers],
  };
}
