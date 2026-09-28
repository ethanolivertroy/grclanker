export type InitialPromptPayload = {
  kind: "prompt" | "workflow";
  content: string;
};

export type InitialPromptInputResult =
  | { action: "continue" }
  | { action: "transform"; text: string };

const INITIAL_PROMPT_PREFIX = "grclanker:initial-prompt:v1:";

export function serializeInitialPrompt(payload: InitialPromptPayload): string {
  return `${INITIAL_PROMPT_PREFIX}${Buffer.from(JSON.stringify(payload), "utf8").toString("base64url")}`;
}

export function extractInitialPrompt(
  text: string,
): { pipedInput: string; payload: InitialPromptPayload } | undefined {
  const offset = text.lastIndexOf(INITIAL_PROMPT_PREFIX);
  if (offset === -1) return undefined;

  const encoded = text.slice(offset + INITIAL_PROMPT_PREFIX.length);
  let parsed: unknown;
  try {
    parsed = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8"));
  } catch {
    return undefined;
  }

  if (
    !parsed ||
    typeof parsed !== "object" ||
    !("kind" in parsed) ||
    !("content" in parsed) ||
    (parsed.kind !== "prompt" && parsed.kind !== "workflow") ||
    typeof parsed.content !== "string"
  ) {
    return undefined;
  }

  const payload = parsed as { kind: InitialPromptPayload["kind"]; content: string };
  return {
    pipedInput: text.slice(0, offset),
    payload,
  };
}

export function materializeInitialPrompt(
  payload: InitialPromptPayload,
  pipedInput: string,
): string {
  if (payload.kind === "workflow") {
    if (!pipedInput) return payload.content;
    return `${payload.content}\n\n## Piped input\n\n${pipedInput}`;
  }

  const literalPrompt = payload.content.startsWith("/")
    ? `## CLI prompt\n\n${payload.content}`
    : payload.content;
  return pipedInput ? `${pipedInput}\n\n${literalPrompt}` : literalPrompt;
}

export function resolveSerializedInitialPrompt(
  text: string,
  source: "interactive" | "rpc" | "extension",
): string | undefined {
  if (source !== "interactive") return undefined;

  const initialPrompt = extractInitialPrompt(text);
  if (!initialPrompt) return undefined;

  return materializeInitialPrompt(initialPrompt.payload, initialPrompt.pipedInput);
}

export function initialPromptInputResult(
  text: string,
  source: "interactive" | "rpc" | "extension",
): InitialPromptInputResult {
  const transformed = resolveSerializedInitialPrompt(text, source);
  return transformed === undefined
    ? { action: "continue" }
    : { action: "transform", text: transformed };
}
