import type { ToolResultContent } from "@cursor/july/tools";
import type { GrcToolContent, GrcToolResult } from "./registry.js";

/** The envelope form of the Agent SDK `ToolExecuteResult`. */
export interface SdkToolEnvelope {
  content: ToolResultContent[];
  isError?: boolean;
}

function toSdkContent(content: GrcToolContent): ToolResultContent {
  switch (content.type) {
    case "text":
      return { type: "text", text: content.text };
    case "image":
      return { type: "image", data: content.data, mimeType: content.mimeType };
    default: {
      const exhaustive: never = content;
      throw new Error(`Unsupported grclanker tool content: ${JSON.stringify(exhaustive)}`);
    }
  }
}

/**
 * Map a native grc-tools result onto the Agent SDK envelope. Pi shows only
 * `content` to the model, so `details` (UI and log metadata) is dropped and
 * `isError` is carried over when set.
 */
export function toSdkToolResult(result: GrcToolResult): SdkToolEnvelope {
  const content = Array.isArray(result.content)
    ? result.content.map(toSdkContent)
    : [{ type: "text" as const, text: JSON.stringify(result) }];
  const envelope: SdkToolEnvelope = { content };
  if (result.isError === true) {
    envelope.isError = true;
  }
  return envelope;
}

export function errorEnvelope(text: string): SdkToolEnvelope {
  return { content: [{ type: "text", text }], isError: true };
}
