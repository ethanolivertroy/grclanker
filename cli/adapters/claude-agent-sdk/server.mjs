import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { isGrcWriteTool } from "../../dist/core/effects.js";
import { errorEnvelope } from "../../dist/core/results.js";
import { toJsonSchema } from "../../dist/core/schema.js";
import { bundledSkillConfig, WORKFLOW_NAMES, workflowSkillConfig } from "../../dist/core/skills.js";
import { executeRegisteredGrcTool } from "../../dist/core/tools.js";

export const MCP_SERVER_NAME = "grclanker";
export const MCP_TOOL_PREFIX = `mcp__${MCP_SERVER_NAME}__`;
export const WORKFLOW_LOADER = "grclanker_load_workflow";
export const SKILL_LOADER = "grclanker_load_skill";

const loaderDefinitions = [
  {
    name: WORKFLOW_LOADER,
    description: "Load the grclanker investigate, audit, assess, or validate workflow before a structured GRC task.",
    inputSchema: {
      type: "object",
      properties: { name: { type: "string", enum: [...WORKFLOW_NAMES] } },
      required: ["name"],
      additionalProperties: false,
    },
  },
  {
    name: SKILL_LOADER,
    description: "Load the bundled crypto-validation methodology for cryptographic module validation.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
  },
];

/** Key one call by tool name and canonical arguments so approval binds to exact input. */
export function approvalKey(name, input) {
  const canonical = (value) => {
    if (Array.isArray(value)) return value.map(canonical);
    if (value && typeof value === "object") {
      return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonical(value[key])]));
    }
    return value;
  };
  return `${name}\u0000${JSON.stringify(canonical(input ?? {}))}`;
}

/**
 * One-shot approvals recorded by the host's canUseTool callback and consumed
 * by the MCP handler, so a writer runs only for the exact arguments approved.
 */
export class WriteApprovals {
  #pending = new Map();

  grant(name, input, signal) {
    if (signal?.aborted) return;
    const key = approvalKey(name, input);
    const pending = this.#pending.get(key) ?? new Set();
    const token = { revoke: () => {
      signal?.removeEventListener("abort", token.revoke);
      pending.delete(token);
      if (pending.size === 0) this.#pending.delete(key);
    } };
    pending.add(token);
    this.#pending.set(key, pending);
    signal?.addEventListener("abort", token.revoke, { once: true });
  }

  consume(name, input) {
    const token = this.#pending.get(approvalKey(name, input))?.values().next().value;
    if (!token) return false;
    token.revoke();
    return true;
  }
}

function textResult(text) {
  return { content: [{ type: "text", text }] };
}

/**
 * Build an in-process MCP server exposing the selected native GRC tools with
 * their shared JSON schemas. The Claude Agent SDK connects to `instance` over
 * its own transport; no separate process or port is opened.
 * @param {import("../../dist/core/registry.js").RegisteredGrcTool[]} tools
 * @param {WriteApprovals} approvals
 */
export function createGrclankerMcpServer(tools, approvals) {
  const byName = new Map(tools.map((tool) => [tool.name, tool]));
  const server = new Server(
    { name: MCP_SERVER_NAME, version: "0.1.0" },
    { capabilities: { tools: {} } },
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [
      ...tools.map((tool) => {
        const writes = isGrcWriteTool(tool.name);
        return {
          name: tool.name,
          description: tool.description,
          inputSchema: toJsonSchema(tool.parameters),
          annotations: { readOnlyHint: !writes, destructiveHint: false, openWorldHint: true },
        };
      }),
      ...loaderDefinitions.map((loader) => ({
        ...loader,
        annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
      })),
    ],
  }));

  server.setRequestHandler(CallToolRequestSchema, async (request, extra) => {
    const { name, arguments: input = {} } = request.params;
    if (name === WORKFLOW_LOADER) {
      const workflow = input?.name;
      if (typeof workflow !== "string" || !WORKFLOW_NAMES.includes(workflow)) {
        return errorEnvelope("Choose investigate, audit, assess, or validate.");
      }
      return textResult(workflowSkillConfig(workflow).markdown);
    }
    if (name === SKILL_LOADER) return textResult(bundledSkillConfig("crypto-validation").markdown);
    if (!byName.has(name)) return errorEnvelope("Tool is not enabled in this Claude Agent SDK deployment.");
    const writes = isGrcWriteTool(name);
    if (writes && !approvals.consume(name, input)) {
      return errorEnvelope(`Tool "${name}" requires operator approval for these exact arguments.`);
    }
    return { ...(await executeRegisteredGrcTool(name, input, { signal: extra.signal, allowWrites: writes })) };
  });

  // The SDK only calls instance.connect(transport); a low-level Server keeps
  // the native JSON schemas instead of re-describing them in Zod.
  return {
    type: "sdk",
    name: MCP_SERVER_NAME,
    timeout: 300_000,
    instance: /** @type {any} */ (server),
  };
}
