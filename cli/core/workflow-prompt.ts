import { readFileSync } from "node:fs";
import { resolve } from "node:path";

export function renderWorkflowPrompt(markdown: string, subject = ""): string {
  return markdown.replace(/\$ARGUMENTS/g, () => subject);
}

export function readWorkflowPrompt(
  appRoot: string,
  workflow: string,
  subject?: string,
): string {
  const path = resolve(appRoot, "prompts", `${workflow}.md`);
  return renderWorkflowPrompt(readFileSync(path, "utf8"), subject);
}
