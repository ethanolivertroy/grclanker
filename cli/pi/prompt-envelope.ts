export type InitialPromptPayload = {
  kind: "prompt" | "workflow";
  content: string;
};

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
  if (!pipedInput) return payload.content;

  if (payload.kind === "workflow") {
    return `${payload.content}\n\n## Piped input\n\n${pipedInput}`;
  }

  return `${pipedInput}\n\n${payload.content}`;
}
