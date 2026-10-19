/**
 * Replay policy for grclanker tools under Pi Durable.
 *
 * A call interrupted by a crash reruns on resume only when its tool is
 * replay-safe. The policy comes from the Agent SDK effect classifier, so the
 * tools a dry run may execute for real are exactly the ones that may replay,
 * and anything with a write verb in its name never does.
 */
import { classifyGrcToolEffect } from "../agent-sdk/lib/effects.js";

export type DurableReplayPolicy = "safe" | "unsafe";

export function durableReplayPolicy(toolName: string): DurableReplayPolicy {
  return classifyGrcToolEffect(toolName) === "read" ? "safe" : "unsafe";
}
