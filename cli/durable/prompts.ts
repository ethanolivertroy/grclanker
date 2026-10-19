/**
 * The grclanker extension for Pi Durable: the domain tools plus two system
 * prompt sections, the shared grclanker prompt with a note on this runtime,
 * and the assessment state recorded so far in the conversation.
 */
import { defineExtension, section, type Extension, type ToolRegistration } from "@earendil-works/pi-durable";
import { readGrclankerSystemPrompt } from "../agent-sdk/lib/instructions.js";
import { Assessment, renderAssessmentSummary } from "./document.js";
import { createDurableGrcTools } from "./tools.js";

export const DURABLE_EXTENSION_NAME = "grclanker";

export const DURABLE_RUNTIME_NOTE = `## Durable Runtime (experimental)

You are running under the Pi Durable runtime through \`grclanker durable\`. The session is stored on disk, so a run that stops partway can be resumed.

- The grclanker domain tools are available under their native names. There are no compute backend, file, or shell tools in this mode.
- After a crash, read-only tools may run again. Tools that export, write, or change anything are never rerun: their result says the call was interrupted. Report an interrupted call to the user and do not call that tool again unless the user asks.
- Tools that accept \`output_dir\`, \`workspace_dir\`, or \`zip_path\` resolve relative paths against the directory \`grclanker durable\` was started in. Report the absolute paths the tool returns.
- The assessment state section lists what earlier tool calls in this conversation recorded. Use it instead of repeating a finished assessment.`;

export function buildDurableSystemPrompt(): string {
  return `${readGrclankerSystemPrompt()}\n\n${DURABLE_RUNTIME_NOTE}`;
}

export function createGrclankerDurableExtension(
  tools: readonly ToolRegistration[] = createDurableGrcTools(),
): Extension {
  const systemPrompt = buildDurableSystemPrompt();
  return defineExtension({
    name: DURABLE_EXTENSION_NAME,
    tools,
    sections: [
      section("grclanker", () => systemPrompt, { tag: false }),
      section("assessment_state", async (input, context) =>
        renderAssessmentSummary(await input.read.snapshot(Assessment, input.conversationId, context)),
      ),
    ],
  });
}
