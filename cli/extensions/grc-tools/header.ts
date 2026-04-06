import { homedir } from "node:os";
import type { ExtensionAPI, ExtensionContext } from "@mariozechner/pi-coding-agent";
import { GRCLANKER_ASCII_LOGO } from "../../logo.js";
import { getGrclankerSettingsPath } from "../../config/paths.js";
import { formatSystemResources, resolveComputeBackend } from "../../pi/compute.js";
import { readGrclankerSettings } from "../../pi/settings.js";

const ANSI_RE = /\x1b\[[0-9;]*m/g;

const WORKFLOW_DESCRIPTIONS = [
  {
    name: "/investigate",
    description: "trace crypto status, KEV exposure, EPSS likelihood, and ransomware linkage.",
  },
  {
    name: "/audit",
    description: "map evidence to a requested framework and classify controls.",
  },
  {
    name: "/assess",
    description: "produce a posture readout with top risks, confidence notes, and remediation order.",
  },
  {
    name: "/validate",
    description: "answer the FIPS question cleanly: active, historical, in process, or absent.",
  },
];

function shortDescription(description: string): string {
  const lower = description.toLowerCase();
  for (const prefix of [
    "run a ",
    "run an ",
    "set up a ",
    "build a ",
    "build the ",
    "turn ",
    "design the ",
    "produce a ",
    "compare ",
    "simulate ",
    "inspect ",
    "write a ",
    "plan or execute a ",
    "prepare a ",
  ]) {
    if (lower.startsWith(prefix)) return description.slice(prefix.length);
  }
  return description;
}

function visibleLength(text: string): number {
  return text.replace(ANSI_RE, "").length;
}

function formatHeaderPath(path: string): string {
  const home = homedir();
  return path.startsWith(home) ? `~${path.slice(home.length)}` : path;
}

function wrapWords(text: string, maxW: number): string[] {
  const words = text.split(" ");
  const lines: string[] = [];
  let current = "";

  for (let word of words) {
    if (word.length > maxW) {
      if (current) {
        lines.push(current);
        current = "";
      }
      word = maxW > 3 ? `${word.slice(0, maxW - 1)}…` : word.slice(0, maxW);
    }

    const test = current ? `${current} ${word}` : word;
    if (current && test.length > maxW) {
      lines.push(current);
      current = word;
    } else {
      current = test;
    }
  }

  if (current) lines.push(current);
  return lines.length > 0 ? lines : [""];
}

function padRight(text: string, width: number): string {
  const gap = Math.max(0, width - visibleLength(text));
  return `${text}${" ".repeat(gap)}`;
}

function truncateVisible(text: string, maxVisible: number): string {
  const raw = text.replace(ANSI_RE, "");
  if (raw.length <= maxVisible) return text;
  if (maxVisible <= 3) return ".".repeat(maxVisible);
  return `${raw.slice(0, maxVisible - 3)}...`;
}

function getCurrentModelLabel(ctx: ExtensionContext): string {
  if (ctx.model) return `${ctx.model.provider}/${ctx.model.id}`;
  const branch = ctx.sessionManager.getBranch();
  for (let index = branch.length - 1; index >= 0; index -= 1) {
    const entry = branch[index]!;
    if (entry.type === "model_change") {
      return `${(entry as { provider: string }).provider}/${(entry as { modelId: string }).modelId}`;
    }
  }
  return "not set";
}

function extractMessageText(message: unknown): string {
  if (!message || typeof message !== "object") return "";
  const content = (message as { content?: unknown }).content;
  if (typeof content === "string") return content;
  if (!Array.isArray(content)) return "";

  return content
    .map((item) => {
      if (!item || typeof item !== "object") return "";
      const record = item as { type?: string; text?: unknown; name?: unknown };
      if (record.type === "text" && typeof record.text === "string") return record.text;
      if (record.type === "toolCall") return `[${typeof record.name === "string" ? record.name : "tool"}]`;
      return "";
    })
    .filter(Boolean)
    .join(" ");
}

function getRecentActivitySummary(ctx: ExtensionContext): string {
  const branch = ctx.sessionManager.getBranch();
  for (let index = branch.length - 1; index >= 0; index -= 1) {
    const entry = branch[index]!;
    if (entry.type !== "message") continue;
    const messageEntry = entry as { message: { role: string; content?: unknown } };
    const text = extractMessageText(messageEntry.message).replace(/\s+/g, " ").trim();
    if (!text) continue;
    const role = messageEntry.message.role === "assistant"
      ? "agent"
      : messageEntry.message.role === "user"
        ? "you"
        : messageEntry.message.role;
    return `${role}: ${text}`;
  }
  return "";
}

function detectSystemResources(): string {
  const settings = readGrclankerSettings(getGrclankerSettingsPath());
  return formatSystemResources(resolveComputeBackend(settings));
}

async function buildAgentCatalogSummary(): Promise<string[]> {
  return ["auditor", "verifier"];
}

export async function installGrclankerHeader(
  pi: ExtensionAPI,
  ctx: ExtensionContext,
  cache: { agentsPromise?: Promise<string[]> },
  cliVersion: string,
): Promise<void> {
  if (!ctx.hasUI) return;

  cache.agentsPromise ??= buildAgentCatalogSummary();
  const agents = await cache.agentsPromise;

  const toolCount = pi.getAllTools().length;
  const modelLabel = getCurrentModelLabel(ctx);
  const sessionId = ctx.sessionManager.getSessionName()?.trim() || ctx.sessionManager.getSessionId();
  const dirLabel = formatHeaderPath(ctx.cwd);
  const activity = getRecentActivitySummary(ctx);
  const resources = detectSystemResources();

  ctx.ui.setHeader?.((_tui, theme) => ({
    render(width: number): string[] {
      const maxW = Math.max(width - 2, 1);
      const cardW = Math.min(maxW, 120);
      const innerW = cardW - 2;
      const contentW = innerW - 2;
      const outerPad = " ".repeat(Math.max(0, Math.floor((width - cardW) / 2)));
      const lines: string[] = [];

      const push = (line: string) => { lines.push(`${outerPad}${line}`); };
      const border = (value: string) => theme.fg("borderMuted", value);

      const row = (content: string): string =>
        `${border("│")} ${padRight(content, contentW)} ${border("│")}`;
      const emptyRow = (): string => `${border("│")}${" ".repeat(innerW)}${border("│")}`;
      const divider = (): string => `${border("├")}${border("─".repeat(innerW))}${border("┤")}`;

      const useWideLayout = contentW >= 70;
      const leftW = useWideLayout ? Math.min(38, Math.floor(contentW * 0.35)) : 0;
      const divColW = useWideLayout ? 3 : 0;
      const rightW = useWideLayout ? contentW - leftW - divColW : contentW;

      const twoCol = (left: string, right: string): string => {
        if (!useWideLayout) return row(left || right);
        return row(`${padRight(left, leftW)}${border(" │ ")}${padRight(right, rightW)}`);
      };

      push("");

      if (cardW >= 70) {
        const maxLogoW = Math.max(...GRCLANKER_ASCII_LOGO.map((line) => line.length));
        const logoOffset = " ".repeat(Math.max(0, Math.floor((cardW - maxLogoW) / 2)));
        for (const logoLine of GRCLANKER_ASCII_LOGO) {
          push(theme.fg("accent", theme.bold(`${logoOffset}${truncateVisible(logoLine, cardW)}`)));
        }
        push("");
      }

      const versionTag = ` v${cliVersion} `;
      const gap = Math.max(0, innerW - versionTag.length);
      const gapL = Math.floor(gap / 2);
      push(
        border(`╭${"─".repeat(gapL)}`) +
        theme.fg("dim", versionTag) +
        border(`${"─".repeat(gap - gapL)}╮`),
      );

      if (useWideLayout) {
        const labelW = 10;
        const leftValueW = Math.max(1, leftW - labelW - 1);
        const leftLines: string[] = [""];
        const rightLines: string[] = ["", theme.fg("accent", theme.bold("GRC Workflows"))];
        const indent = " ".repeat(labelW + 1);

        const pushLabeled = (label: string, value: string, color: "text" | "dim") => {
          const wrapped = wrapWords(value, leftValueW);
          leftLines.push(`${theme.fg("dim", label.padEnd(labelW))} ${theme.fg(color, wrapped[0]!)}`);
          for (let i = 1; i < wrapped.length; i += 1) {
            leftLines.push(`${indent}${theme.fg(color, wrapped[i]!)}`);
          }
        };

        pushLabeled("model", modelLabel, "text");
        pushLabeled("directory", dirLabel, "text");
        pushLabeled("session", sessionId, "dim");
        leftLines.push("");
        pushLabeled("system", resources, "dim");
        leftLines.push("");
        leftLines.push(theme.fg("dim", `${toolCount} tools · ${agents.length} agents`));
        leftLines.push("");
        leftLines.push(theme.fg("accent", theme.bold("Agents")));
        for (const line of wrapWords(agents.join(", "), leftW)) {
          leftLines.push(theme.fg("dim", line));
        }
        if (activity) {
          leftLines.push("");
          leftLines.push(theme.fg("accent", theme.bold("Last Activity")));
          for (const line of wrapWords(activity, leftW)) {
            leftLines.push(theme.fg("dim", line));
          }
        }

        const commandNameW = 16;
        const descW = Math.max(10, rightW - commandNameW - 2);
        for (const workflow of WORKFLOW_DESCRIPTIONS) {
          const wrapped = wrapWords(shortDescription(workflow.description), descW);
          rightLines.push(`${theme.fg("accent", workflow.name.padEnd(commandNameW))}${theme.fg("dim", wrapped[0]!)}`);
          for (let i = 1; i < wrapped.length; i += 1) {
            rightLines.push(`${" ".repeat(commandNameW)}${theme.fg("dim", wrapped[i]!)}`);
          }
        }

        const totalRows = Math.max(leftLines.length, rightLines.length);
        for (let index = 0; index < totalRows; index += 1) {
          push(twoCol(leftLines[index] ?? "", rightLines[index] ?? ""));
        }
      } else {
        push(row(`${theme.fg("dim", "model".padEnd(10))} ${theme.fg("text", truncateVisible(modelLabel, contentW - 11))}`));
        push(row(`${theme.fg("dim", "directory".padEnd(10))} ${theme.fg("text", truncateVisible(dirLabel, contentW - 11))}`));
        push(row(`${theme.fg("dim", "session".padEnd(10))} ${theme.fg("dim", truncateVisible(sessionId, contentW - 11))}`));
        push(emptyRow());
        push(row(theme.fg("dim", truncateVisible(resources, contentW))));
        push(row(theme.fg("dim", `${toolCount} tools · ${agents.length} agents`)));
        push(emptyRow());
        push(row(theme.fg("accent", theme.bold("GRC Workflows"))));
        for (const workflow of WORKFLOW_DESCRIPTIONS) {
          push(row(`${theme.fg("accent", workflow.name.padEnd(16))}${theme.fg("dim", truncateVisible(workflow.description, contentW - 16))}`));
        }
      }

      push(border(`╰${"─".repeat(innerW)}╯`));
      push("");

      return lines;
    },
    invalidate() {},
  }));
}
