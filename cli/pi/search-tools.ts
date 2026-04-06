import { readFile } from "node:fs/promises";
import { isAbsolute, relative, resolve, sep } from "node:path";
import { homedir } from "node:os";
import {
  DEFAULT_MAX_BYTES,
  formatSize,
  truncateHead,
  truncateLine,
  type GrepToolDetails,
  type GrepToolInput,
} from "@mariozechner/pi-coding-agent";
import type { ResolvedComputeBackendExecution } from "./backend-exec.js";

const DEFAULT_GREP_LIMIT = 100;
const GREP_MAX_LINE_LENGTH = 500;

function resolveToolPath(filePath: string, cwd: string): string {
  if (filePath === "~") return homedir();
  if (filePath.startsWith("~/")) return resolve(homedir(), filePath.slice(2));
  return isAbsolute(filePath) ? filePath : resolve(cwd, filePath);
}

function toUtf8(contents: Buffer | string): string {
  return Buffer.isBuffer(contents) ? contents.toString("utf8") : contents;
}

async function readTextFile(
  execution: ResolvedComputeBackendExecution,
  absolutePath: string,
): Promise<string> {
  if (execution.readOperations) {
    return toUtf8(await execution.readOperations.readFile(absolutePath));
  }
  return readFile(absolutePath, "utf8");
}

function formatMatchedPath(filePath: string, searchPath: string, isDirectory: boolean): string {
  if (!isDirectory) {
    const segments = filePath.split(sep);
    return segments.at(-1) ?? filePath;
  }

  const relativePath = relative(searchPath, filePath);
  if (relativePath.length > 0 && !relativePath.startsWith("..")) {
    return relativePath.split(sep).join("/");
  }

  return filePath.split(sep).join("/");
}

export async function executeComputeAwareGrep(
  execution: ResolvedComputeBackendExecution,
  cwd: string,
  input: GrepToolInput,
): Promise<{
  content: Array<{ type: "text"; text: string }>;
  details: GrepToolDetails | undefined;
}> {
  if (!execution.grepOperations) {
    throw new Error("Selected backend does not provide grep operations.");
  }

  const searchPath = resolveToolPath(input.path ?? ".", cwd);
  const contextValue = input.context && input.context > 0 ? input.context : 0;
  const limit = Math.max(1, input.limit ?? DEFAULT_GREP_LIMIT);
  const result = await execution.grepOperations.searchMatches({
    pattern: input.pattern,
    searchPath,
    glob: input.glob,
    ignoreCase: input.ignoreCase,
    literal: input.literal,
    limit,
  });

  if (result.matches.length === 0) {
    return {
      content: [{ type: "text", text: "No matches found" }],
      details: undefined,
    };
  }

  const fileCache = new Map<string, string[]>();
  let linesTruncated = false;
  const outputLines: string[] = [];

  for (const match of result.matches) {
    const formattedPath = formatMatchedPath(match.filePath, searchPath, result.isDirectory);

    let lines = fileCache.get(match.filePath);
    if (!lines) {
      const contents = await readTextFile(execution, match.filePath);
      lines = contents.replace(/\r\n/g, "\n").replace(/\r/g, "\n").split("\n");
      fileCache.set(match.filePath, lines);
    }

    const start = contextValue > 0 ? Math.max(1, match.lineNumber - contextValue) : match.lineNumber;
    const end = contextValue > 0
      ? Math.min(lines.length, match.lineNumber + contextValue)
      : match.lineNumber;

    for (let current = start; current <= end; current += 1) {
      const rawText = lines[current - 1] ?? "";
      const { text, wasTruncated } = truncateLine(rawText.replace(/\r/g, ""));
      if (wasTruncated) linesTruncated = true;
      if (current === match.lineNumber) {
        outputLines.push(`${formattedPath}:${current}: ${text}`);
      } else {
        outputLines.push(`${formattedPath}-${current}- ${text}`);
      }
    }
  }

  const rawOutput = outputLines.join("\n");
  const truncation = truncateHead(rawOutput, { maxLines: Number.MAX_SAFE_INTEGER });
  const details: GrepToolDetails = {};
  const notices: string[] = [];
  let text = truncation.content;

  if (result.matchLimitReached) {
    notices.push(`${limit} matches limit reached. Use limit=${limit * 2} for more, or refine pattern`);
    details.matchLimitReached = limit;
  }

  if (truncation.truncated) {
    notices.push(`${formatSize(DEFAULT_MAX_BYTES)} limit reached`);
    details.truncation = truncation;
  }

  if (linesTruncated) {
    notices.push(`Some lines truncated to ${GREP_MAX_LINE_LENGTH} chars. Use read tool to see full lines`);
    details.linesTruncated = true;
  }

  if (notices.length > 0) {
    text += `\n\n[${notices.join(". ")}]`;
  }

  return {
    content: [{ type: "text", text }],
    details: Object.keys(details).length > 0 ? details : undefined,
  };
}
