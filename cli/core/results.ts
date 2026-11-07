import type { GrcToolContent, GrcToolResult } from "./registry.js";

/** Model-visible tool envelope shared by all supported runtimes. */
export interface GrcToolEnvelope {
  content: GrcToolContent[];
  isError?: boolean;
}

function toSdkContent(content: GrcToolContent): GrcToolContent {
  switch (content.type) {
    case "text":
      return { type: "text", text: content.text };
    case "image":
      return { type: "image", data: content.data, mimeType: content.mimeType };
    default: {
      const exhaustive: never = content;
      void exhaustive;
      throw new Error("Unsupported native tool content block.");
    }
  }
}

/**
 * Map a native grc-tools result onto the portable envelope. Pi shows only
 * `content` to the model, so `details` (UI and log metadata) is dropped and
 * `isError` is carried over when set.
 */
export function toSdkToolResult(result: GrcToolResult): GrcToolEnvelope {
  if (!Array.isArray(result?.content)) return errorEnvelope("The native tool returned invalid content.");
  const content = result.content.map(toSdkContent);
  const envelope: GrcToolEnvelope = { content };
  if (result.isError === true) {
    envelope.isError = true;
  }
  return envelope;
}

export function errorEnvelope(text: string): GrcToolEnvelope {
  return { content: [{ type: "text", text }], isError: true };
}
