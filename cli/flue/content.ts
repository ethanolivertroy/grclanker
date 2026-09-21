/**
 * Load grclanker's shipped prompt assets in the shapes Flue consumes.
 *
 * - `.grclanker/SYSTEM.md` becomes the agent's instruction document.
 * - Prompt templates under `prompts/` (behind `/investigate`, `/audit`,
 *   `/assess`, `/validate` in the Pi CLI) become Flue skills the model
 *   activates on demand.
 * - `SKILL.md` directories under `skills/` (Agent Skills format) become Flue
 *   skills as well.
 * - Persona files under `.grclanker/agents/` (auditor and verifier) become
 *   subagent roles the model can delegate to through Flue's `task` tool.
 */
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { basename, extname, resolve } from "node:path";
import { defineSkill, type SkillDefinition } from "@flue/runtime";
import { parse as parseYaml } from "yaml";

export interface GrclankerSubagentRole {
  name: string;
  description: string;
  instructions: string;
  allowedTools: string[];
  source: string;
}

export interface GrclankerAgentContent {
  appRoot: string;
  systemPrompt: string;
  workflows: SkillDefinition[];
  skills: SkillDefinition[];
  roles: GrclankerSubagentRole[];
}

const MAX_SKILL_DESCRIPTION_LENGTH = 1024;

const SKILL_FRONTMATTER_PATTERN = /^---\r?\n([\s\S]*?)\r?\n---\r?\n?([\s\S]*)$/;

export function resolveFlueAppRoot(currentDir: string): string {
  const candidates = [resolve(currentDir, ".."), resolve(currentDir, "../..")];
  const appRoot = candidates.find((candidate) => existsSync(resolve(candidate, ".grclanker", "SYSTEM.md")));
  if (!appRoot) {
    throw new Error(`Unable to locate the grclanker CLI root (checked ${candidates.join(", ")}).`);
  }
  return appRoot;
}

function listMarkdownFiles(dir: string): string[] {
  if (!existsSync(dir)) return [];
  return readdirSync(dir, { withFileTypes: true })
    .filter((entry) => entry.isFile() && extname(entry.name) === ".md")
    .map((entry) => resolve(dir, entry.name))
    .sort();
}

function truncateDescription(text: string): string {
  const normalized = text.replace(/\s+/g, " ").trim();
  if (normalized.length <= MAX_SKILL_DESCRIPTION_LENGTH) return normalized;
  return `${normalized.slice(0, MAX_SKILL_DESCRIPTION_LENGTH - 3).trimEnd()}...`;
}

function stripMarkdownHeading(line: string): string {
  return line.replace(/^#+\s*/, "").trim();
}

/** Split `# Title` and the first prose paragraph out of a prompt template. */
export function summarizeMarkdownPrompt(markdown: string): { title: string; summary: string } {
  const lines = markdown.split(/\r?\n/);
  const headingIndex = lines.findIndex((line) => /^#\s+/.test(line));
  const title = headingIndex >= 0 ? stripMarkdownHeading(lines[headingIndex]) : "";

  const paragraph: string[] = [];
  for (const line of lines.slice(headingIndex + 1)) {
    const trimmed = line.trim();
    if (trimmed.length === 0) {
      if (paragraph.length > 0) break;
      continue;
    }
    if (/^#/.test(trimmed)) break;
    paragraph.push(trimmed);
  }

  return { title, summary: paragraph.join(" ") };
}

export function workflowSkillFromPrompt(name: string, markdown: string): SkillDefinition {
  const { title, summary } = summarizeMarkdownPrompt(markdown);
  const lead = [title ? `${title} workflow.` : "", summary].filter(Boolean).join(" ");
  const description = truncateDescription(
    `${lead} Use when the user asks for the grclanker /${name} workflow or equivalent work.`,
  );
  return defineSkill({ name, description, instructions: markdown.trim() });
}

export function loadWorkflowSkills(appRoot: string): SkillDefinition[] {
  return listMarkdownFiles(resolve(appRoot, "prompts")).map((path) =>
    workflowSkillFromPrompt(basename(path, ".md"), readFileSync(path, "utf8")),
  );
}

/** Parse Agent Skills `SKILL.md` frontmatter (`---` delimited YAML) and body. */
export function parseSkillMarkdown(markdown: string): { frontmatter: Record<string, unknown>; body: string } {
  const match = markdown.match(SKILL_FRONTMATTER_PATTERN);
  if (!match) return { frontmatter: {}, body: markdown.trim() };

  const parsed = parseYaml(match[1]) as unknown;
  const frontmatter =
    parsed && typeof parsed === "object" && !Array.isArray(parsed) ? (parsed as Record<string, unknown>) : {};
  return { frontmatter, body: match[2].trim() };
}

export function skillFromSkillMarkdown(fallbackName: string, markdown: string): SkillDefinition {
  const { frontmatter, body } = parseSkillMarkdown(markdown);
  const name = typeof frontmatter.name === "string" && frontmatter.name.trim() ? frontmatter.name.trim() : fallbackName;
  const description =
    typeof frontmatter.description === "string" && frontmatter.description.trim()
      ? truncateDescription(frontmatter.description)
      : summarizeMarkdownPrompt(body).summary || `${name} skill.`;
  return defineSkill({
    name,
    description,
    instructions: body,
    ...(typeof frontmatter.license === "string" ? { license: frontmatter.license } : {}),
  });
}

export function loadBundledSkills(appRoot: string): SkillDefinition[] {
  const skillsDir = resolve(appRoot, "skills");
  if (!existsSync(skillsDir)) return [];

  return readdirSync(skillsDir, { withFileTypes: true })
    .filter((entry) => entry.isDirectory() && existsSync(resolve(skillsDir, entry.name, "SKILL.md")))
    .map((entry) => skillFromSkillMarkdown(entry.name, readFileSync(resolve(skillsDir, entry.name, "SKILL.md"), "utf8")))
    .sort((left, right) => left.name.localeCompare(right.name));
}

/** The text after `<label>:` on the first line that starts with it, or undefined when absent or empty. */
export function readLabeledLine(markdown: string, label: string): string | undefined {
  const prefix = `${label}:`;
  const line = markdown.split(/\r?\n/).find((candidate) => candidate.startsWith(prefix));
  const value = line?.slice(prefix.length).trim();
  return value ? value : undefined;
}

/** Parse one `.grclanker/agents/<role>.md` persona file. */
export function parseSubagentRole(fallbackName: string, markdown: string, source = `${fallbackName}.md`): GrclankerSubagentRole {
  const name = readLabeledLine(markdown, "Name") ?? fallbackName;
  const description = readLabeledLine(markdown, "Purpose") ?? `${name} subagent.`;
  const allowedTools = (readLabeledLine(markdown, "Allowed") ?? "")
    .split(/[\s,]+/)
    .map((tool) => tool.trim())
    .filter(Boolean);

  return { name, description: truncateDescription(description), instructions: markdown.trim(), allowedTools, source };
}

export function loadSubagentRoles(appRoot: string): GrclankerSubagentRole[] {
  return listMarkdownFiles(resolve(appRoot, ".grclanker", "agents")).map((path) =>
    parseSubagentRole(basename(path, ".md"), readFileSync(path, "utf8"), path),
  );
}

export function loadGrclankerSystemPrompt(appRoot: string): string {
  return readFileSync(resolve(appRoot, ".grclanker", "SYSTEM.md"), "utf8").trim();
}

export function loadGrclankerAgentContent(appRoot: string): GrclankerAgentContent {
  return {
    appRoot,
    systemPrompt: loadGrclankerSystemPrompt(appRoot),
    workflows: loadWorkflowSkills(appRoot),
    skills: loadBundledSkills(appRoot),
    roles: loadSubagentRoles(appRoot),
  };
}
