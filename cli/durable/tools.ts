/**
 * grclanker domain tools as Pi Durable tools.
 *
 * The tools come from the same registry the Agent SDK adapter uses and keep
 * their names, descriptions, parameter schemas, and argument repair. This
 * adapter adds the replay policy, turns the Pi result into a durable result
 * with strict-JSON details, redacts credentials from error text, and records
 * each finished call in the assessment document.
 */
import type { Context, JsonValue } from "@earendil-works/chord";
import { awaitWithContext } from "@earendil-works/chord/context";
import type { TSchema } from "@earendil-works/pi-ai";
import { defineTool, type ToolExecutionResult, type ToolRegistration } from "@earendil-works/pi-durable";
import { collectRegisteredGrcTools, type GrcToolResult, type RegisteredGrcTool } from "../agent-sdk/lib/registry.js";
import { redactSensitiveArguments, redactToolErrorText } from "../flue/redact.js";
import { Assessment, recordToolOutcome } from "./document.js";
import { toStrictJson } from "./json.js";
import { durableReplayPolicy } from "./replay.js";

type DurableToolOutput = NonNullable<ToolExecutionResult["output"]>;

/** The slice of a registry tool the adapter needs. */
export type DurableBridgeableTool = Pick<
  RegisteredGrcTool,
  "name" | "description" | "parameters" | "prepareArguments" | "execute"
>;

function describeError(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function toDurableOutput(result: GrcToolResult): DurableToolOutput {
  if (!Array.isArray(result?.content)) {
    return [{ type: "text", text: JSON.stringify(toStrictJson(result) ?? null) }];
  }
  return result.content.map((block) => {
    switch (block.type) {
      case "text":
        return { type: "text", text: block.text };
      case "image":
        return { type: "image", data: block.data, mimeType: block.mimeType };
      default: {
        const exhaustive: never = block;
        throw new Error(`Unsupported grclanker tool content: ${JSON.stringify(exhaustive)}`);
      }
    }
  });
}

/** Map a native tool result to a durable one; error text and details lose credential-bearing arguments. */
export function toDurableToolResult(
  tool: Pick<DurableBridgeableTool, "name" | "parameters">,
  args: unknown,
  result: GrcToolResult,
): ToolExecutionResult {
  const isError = result?.isError === true;
  let output = toDurableOutput(result);
  let details: JsonValue | undefined = toStrictJson(result?.details);

  if (isError) {
    output = output.map((block) =>
      block.type === "text" ? { ...block, text: redactToolErrorText(block.text, args, tool.parameters) } : block,
    );
    if (output.length === 0) output = [{ type: "text", text: `${tool.name} failed without a message.` }];
    details = toStrictJson(redactSensitiveArguments(details, tool.parameters));
  }

  return {
    output,
    ...(isError ? { isError: true } : {}),
    ...(details === undefined ? {} : { details }),
  };
}

export function toolFailureResult(
  tool: Pick<DurableBridgeableTool, "name" | "parameters">,
  args: unknown,
  error: unknown,
): ToolExecutionResult {
  const text = redactToolErrorText(`${tool.name} failed: ${describeError(error)}`, args, tool.parameters);
  return { output: [{ type: "text", text }], isError: true };
}

/**
 * Run the native tool. Registry tools take no abort signal, so a cancelled
 * invocation (an abort, or the Harness closing) stops waiting at once and
 * leaves the call to the Harness: closing keeps it pending for resume.
 */
async function runNativeTool(
  tool: DurableBridgeableTool,
  args: unknown,
  callId: string,
  context: Context,
): Promise<ToolExecutionResult> {
  context.abortSignal?.throwIfAborted();
  try {
    const running = tool.execute(callId, args);
    running.catch(() => undefined);
    return toDurableToolResult(tool, args, await awaitWithContext(running, context));
  } catch (error) {
    if (context.abortSignal?.aborted) throw error;
    return toolFailureResult(tool, args, error);
  }
}

export function toDurableTool(tool: DurableBridgeableTool): ToolRegistration {
  const replay = durableReplayPolicy(tool.name);
  const prepareArguments = tool.prepareArguments;

  return defineTool({
    name: tool.name,
    description: tool.description,
    parameters: tool.parameters as unknown as TSchema,
    replay,
    // The Harness may run the repair again on retry and requires it not to mutate its input.
    ...(prepareArguments ? { prepareArguments: (args: unknown) => prepareArguments(structuredClone(args)) } : {}),
    async execute(args, api, context) {
      const result = await runNativeTool(tool, args, api.callId, context);
      await api.commit(async (tx) => {
        recordToolOutcome(await tx.doc(Assessment, api.conversationId), {
          callId: api.callId,
          tool: tool.name,
          replay,
          isError: result.isError === true,
          details: result.details,
          recordedAt: new Date().toISOString(),
        });
      }, context);
      return result;
    },
  });
}

/** Every grclanker domain tool as a durable tool, in registry order. */
export function createDurableGrcTools(
  tools: readonly DurableBridgeableTool[] = collectRegisteredGrcTools(),
): ToolRegistration[] {
  return tools.map(toDurableTool);
}
