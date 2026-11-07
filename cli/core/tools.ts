import { validateToolArguments, type Tool, type ToolCall } from "@earendil-works/pi-ai";
import { runWithoutPersistentCaches } from "../extensions/grc-tools/shared.js";
import { redactToolErrorText } from "./redact.js";
import { isGrcWriteTool } from "./effects.js";
import { getRegisteredGrcTool, type RegisteredGrcTool } from "./registry.js";
import { errorEnvelope, type GrcToolEnvelope, toSdkToolResult } from "./results.js";

export interface ExecuteGrcToolOptions {
  toolCallId?: string;
  /** Keep dry-run catalog mirrors out of the persistent state directory. */
  dryRun?: boolean;
  /** Cancels the tool's in-flight API requests; the call then returns an error envelope. */
  signal?: AbortSignal;
}

function describeError(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function sanitizeErrorText(tool: RegisteredGrcTool, input: Record<string, unknown>, errorText: string): string {
  return redactToolErrorText(errorText, input, tool.parameters);
}

function safeErrorEnvelope(tool: RegisteredGrcTool, input: Record<string, unknown>, errorText: string): GrcToolEnvelope {
  return errorEnvelope(sanitizeErrorText(tool, input, errorText));
}

function sanitizeErrorResult(
  tool: RegisteredGrcTool,
  input: Record<string, unknown>,
  result: GrcToolEnvelope,
): GrcToolEnvelope {
  if (result.isError !== true) return result;
  return {
    ...result,
    content: result.content.map((entry) =>
      entry.type === "text" ? { ...entry, text: sanitizeErrorText(tool, input, entry.text) } : entry,
    ),
  };
}

/**
 * Mirror the Pi runtime: run the tool's `prepareArguments` shim, then coerce
 * and validate against the TypeBox schema with Pi's own validator.
 */
export function prepareGrcToolArguments(tool: RegisteredGrcTool, toolCallId: string, input: unknown): unknown {
  const prepared = tool.prepareArguments ? tool.prepareArguments(input) : input;
  const piTool = { name: tool.name, description: tool.description, parameters: tool.parameters } as unknown as Tool;
  const toolCall: ToolCall = {
    type: "toolCall",
    id: toolCallId,
    name: tool.name,
    arguments: prepared as ToolCall["arguments"],
  };
  return validateToolArguments(piTool, toolCall) as unknown;
}

export async function executeGrcTool(
  tool: RegisteredGrcTool,
  input: Record<string, unknown>,
  options: ExecuteGrcToolOptions = {},
): Promise<GrcToolEnvelope> {
  const toolCallId = options.toolCallId ?? `grclanker_${tool.name}`;
  let args: unknown;
  try {
    options.signal?.throwIfAborted();
    args = prepareGrcToolArguments(tool, toolCallId, input);
  } catch (error) {
    return safeErrorEnvelope(tool, input, describeError(error));
  }

  const run = () => {
    options.signal?.throwIfAborted();
    return tool.execute(toolCallId, args, options.signal);
  };
  try {
    const result = options.dryRun === true ? await runWithoutPersistentCaches(run) : await run();
    return sanitizeErrorResult(tool, input, toSdkToolResult(result));
  } catch (error) {
    return safeErrorEnvelope(tool, input, `${tool.name} failed: ${describeError(error)}`);
  }
}

/** Host-controlled execution options. Writers are denied unless explicitly enabled. */
export interface ExecuteRegisteredGrcToolOptions extends ExecuteGrcToolOptions {
  allowWrites?: boolean;
}

/** Execute a named domain tool with a default-deny write gate. */
export async function executeRegisteredGrcTool(
  name: string,
  input: Record<string, unknown>,
  options: ExecuteRegisteredGrcToolOptions = {},
): Promise<GrcToolEnvelope> {
  let tool: RegisteredGrcTool;
  try {
    tool = getRegisteredGrcTool(name);
  } catch {
    return errorEnvelope(`Unknown grclanker tool "${name}". List the registered GRC tools before selecting one.`);
  }
  if (isGrcWriteTool(name) && options.allowWrites !== true) {
    return errorEnvelope(`Tool "${name}" requires explicit host authorization for writes.`);
  }
  return executeGrcTool(tool, input, options);
}
