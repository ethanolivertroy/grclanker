import Anthropic from "@anthropic-ai/sdk";
import { ToolCallAbortedError } from "../../extensions/grc-tools/abort.js";

type CompletionSubject = "run" | "auditor review" | "verifier review";

/** Only known terminal responses with printable text can count as a completed answer. */
export function claudeCompletionFailure(stopReason: unknown, text: string, subject: CompletionSubject): string | undefined {
  const label = `Claude API ${subject}`;
  switch (stopReason) {
    case "end_turn":
    case "stop_sequence":
      return text.trim() ? undefined : `${label} returned no final text.`;
    case "refusal":
      return `${label} declined this request.`;
    case "max_tokens":
    case "model_context_window_exceeded":
    case "tool_use":
    case "pause_turn":
      return `${label} ended before a final answer (${stopReason}).`;
    default:
      // An unknown provider value can itself contain private text.
      return `${label} ended before a final answer (unknown stop reason).`;
  }
}

/** Provider bodies, transport messages, headers, URLs, and abort reasons are never public diagnostics. */
export function claudeApiFailureMessage(error: unknown, signal?: AbortSignal): string {
  if (signal?.aborted || error instanceof Anthropic.APIUserAbortError || error instanceof ToolCallAbortedError
    || error instanceof Error && error.name === "AbortError") {
    return "Claude API run cancelled.";
  }
  if (error instanceof Anthropic.AuthenticationError) return "Claude API authentication failed; set ANTHROPIC_API_KEY or configure an auth profile.";
  if (error instanceof Anthropic.RateLimitError) return "Claude API rate limit reached; retry later.";
  if (error instanceof Anthropic.APIConnectionTimeoutError) return "Claude API request timed out.";
  if (error instanceof Anthropic.APIConnectionError) return "Claude API connection failed.";
  if (error instanceof Anthropic.APIError && typeof error.status === "number" && Number.isInteger(error.status)
    && error.status >= 100 && error.status <= 599) {
    return `Claude API request failed (HTTP ${error.status}).`;
  }
  return "Claude API request failed.";
}
