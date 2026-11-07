#!/usr/bin/env node
import { realpathSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  GetPromptRequestSchema,
  ListPromptsRequestSchema,
  ListToolsRequestSchema,
  McpError,
  ErrorCode,
} from "@modelcontextprotocol/sdk/types.js";
import { isGrcWriteTool } from "../../dist/core/effects.js";
import { buildGrclankerInstructions } from "../../dist/core/instructions.js";
import { personaAgentConfig, PERSONA_NAMES } from "../../dist/core/personas.js";
import { errorEnvelope } from "../../dist/core/results.js";
import { toJsonSchema } from "../../dist/core/schema.js";
import { bundledSkillConfig, WORKFLOW_NAMES, workflowSkillConfig } from "../../dist/core/skills.js";
import { executeRegisteredGrcTool } from "../../dist/core/tools.js";
import { renderWorkflowPrompt } from "../../dist/core/workflow-prompt.js";
import { readCliAsset } from "../../dist/core/paths.js";
import { parseServerArgs, selectTools } from "./tools.mjs";

export const ROLE_LOADER = "grclanker_load_instructions";
export const WORKFLOW_LOADER = "grclanker_load_workflow";
export const SKILL_LOADER = "grclanker_load_skill";
export const PERSONA_LOADER = "grclanker_load_reviewer";

const RUNTIME_NOTE = `## Claude Code runtime

grclanker is connected to Claude Code as a local MCP server. Its tools are the selected grclanker domain tools plus ${ROLE_LOADER}, ${WORKFLOW_LOADER}, ${SKILL_LOADER}, and ${PERSONA_LOADER}. Only use tools actually present in this session. Claude Code's own tools remain available; gather compliance evidence with the grclanker tools rather than inferring it from local files.

Native tools return content and an optional isError flag. Treat isError as failure, and never describe a failed access check as a compliant system. A missing tool or credential means evidence is unavailable. Proposed policies or risk acceptance decisions are drafts for the organization's owners.

Write tools are exposed only when the operator started the server with --allow-writes, and Claude Code asks before each call unless the operator allowed it. Paths resolve against the server's working directory; prefer absolute output_dir, workspace_dir, or zip_path values and report the returned paths.`;

/** Short initialize instructions; the full role comes from ROLE_LOADER or a prompt. */
const SERVER_INSTRUCTIONS = `grclanker provides GRC engineering tools for evidence collection, control assessments, and risk analysis. Before governance, risk, compliance, audit, vulnerability, or FIPS work, call ${ROLE_LOADER} once for the grclanker role, then ${WORKFLOW_LOADER} for a structured investigate, audit, assess, or validate task. Treat a tool result with isError as missing evidence, never as a passing control.`;

const text = (value) => ({ content: [{ type: "text", text: value }] });
const instructions = () => buildGrclankerInstructions(RUNTIME_NOTE);

const loaders = [
  {
    name: ROLE_LOADER,
    description: "Load the grclanker GRC engineering role and evidence rules. Call once before GRC work.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
    run: () => text(instructions()),
  },
  {
    name: WORKFLOW_LOADER,
    description: "Load the grclanker investigate, audit, assess, or validate workflow before a structured GRC task.",
    inputSchema: {
      type: "object",
      properties: { name: { type: "string", enum: [...WORKFLOW_NAMES] } },
      required: ["name"],
      additionalProperties: false,
    },
    run: (input) => WORKFLOW_NAMES.includes(input?.name)
      ? text(workflowSkillConfig(input.name).markdown)
      : errorEnvelope("Choose investigate, audit, assess, or validate."),
  },
  {
    name: SKILL_LOADER,
    description: "Load the bundled crypto-validation methodology for cryptographic module validation.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
    run: () => text(bundledSkillConfig("crypto-validation").markdown),
  },
  {
    name: PERSONA_LOADER,
    description: "Load the auditor (maps evidence to controls) or verifier (checks the evidence chain) review instructions, to apply yourself or hand to a subagent with the collected evidence.",
    inputSchema: {
      type: "object",
      properties: { name: { type: "string", enum: [...PERSONA_NAMES] } },
      required: ["name"],
      additionalProperties: false,
    },
    run: (input) => PERSONA_NAMES.includes(input?.name)
      ? text(personaAgentConfig(input.name).instructions)
      : errorEnvelope("Choose auditor or verifier."),
  },
];

/**
 * Build the grclanker MCP server for Claude Code.
 * @param {import("../../dist/core/registry.js").RegisteredGrcTool[]} tools
 */
export function createServer(tools) {
  const byName = new Map(tools.map((tool) => [tool.name, tool]));
  const loaderByName = new Map(loaders.map((loader) => [loader.name, loader]));
  const server = new Server(
    { name: "grclanker", version: "0.1.0" },
    { capabilities: { tools: {}, prompts: {} }, instructions: SERVER_INSTRUCTIONS },
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [
      ...tools.map((tool) => ({
        name: tool.name,
        description: tool.description,
        inputSchema: toJsonSchema(tool.parameters),
        annotations: { readOnlyHint: !isGrcWriteTool(tool.name), destructiveHint: false, openWorldHint: true },
      })),
      ...loaders.map(({ run, ...loader }) => ({
        ...loader,
        annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
      })),
    ],
  }));

  server.setRequestHandler(CallToolRequestSchema, async (request, extra) => {
    const { name, arguments: input = {} } = request.params;
    const loader = loaderByName.get(name);
    if (loader) return loader.run(input);
    if (!byName.has(name)) return errorEnvelope("Tool is not enabled in this grclanker server.");
    // Writers are in byName only when the operator passed --allow-writes;
    // Claude Code's permission prompt then decides each call.
    return { ...(await executeRegisteredGrcTool(name, input, { signal: extra.signal, allowWrites: isGrcWriteTool(name) })) };
  });

  // Workflows as prompts: Claude Code lists them as /mcp__grclanker__<name>.
  server.setRequestHandler(ListPromptsRequestSchema, async () => ({
    prompts: WORKFLOW_NAMES.map((name) => ({
      name,
      description: workflowSkillConfig(name).description,
      arguments: [{ name: "subject", description: "What to investigate, audit, assess, or validate", required: false }],
    })),
  }));

  server.setRequestHandler(GetPromptRequestSchema, async (request) => {
    const { name, arguments: args = {} } = request.params;
    if (!WORKFLOW_NAMES.includes(name)) throw new McpError(ErrorCode.InvalidParams, `Unknown prompt: ${name}`);
    const workflow = renderWorkflowPrompt(readCliAsset("prompts", `${name}.md`), args.subject ?? "").trim();
    return {
      description: workflowSkillConfig(name).description,
      messages: [{ role: "user", content: { type: "text", text: `${instructions()}\n\n${workflow}` } }],
    };
  });

  return server;
}

const isMain = Boolean(process.argv[1]) && import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href;
if (isMain) {
  try {
    const { names, allowWrites } = parseServerArgs(process.argv.slice(2));
    await createServer(selectTools(names, { allowWrites })).connect(new StdioServerTransport());
  } catch (error) {
    // stdout carries the MCP protocol; report startup errors on stderr only.
    process.stderr.write(`grclanker MCP server: ${error instanceof Error ? error.message : String(error)}\n`);
    process.exit(1);
  }
}
