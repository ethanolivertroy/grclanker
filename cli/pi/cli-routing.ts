import { extractComputeFlag } from "./env.js";
import type { ComputeBackendKind } from "./compute.js";

export type CliInvocation =
  | {
    kind: "command";
    command: string;
    compute?: ComputeBackendKind;
    prompt?: string;
  }
  | {
    kind: "prompt";
    compute?: ComputeBackendKind;
    prompt?: string;
  }
  | {
    kind: "unknown-option";
    command: string;
  }
  | {
    kind: "unknown-command";
    command: string;
  };

function joinPrompt(args: string[]): string | undefined {
  return args.length > 0 ? args.join(" ") : undefined;
}

function withPromptOptions(
  result: Pick<CliInvocation, "kind"> & Partial<Extract<CliInvocation, { kind: "command" | "prompt" }>>,
  compute: ComputeBackendKind | undefined,
  prompt: string | undefined,
): CliInvocation {
  return {
    ...result,
    ...(compute ? { compute } : {}),
    ...(prompt ? { prompt } : {}),
  } as CliInvocation;
}

function isOneEditAway(left: string, right: string): boolean {
  if (left === right) return false;
  if (Math.abs(left.length - right.length) > 1) return false;
  if (left.length === right.length) {
    for (let index = 0; index < left.length - 1; index += 1) {
      if (
        left[index] === right[index + 1] &&
        left[index + 1] === right[index] &&
        left.slice(index + 2) === right.slice(index + 2) &&
        left.slice(0, index) === right.slice(0, index)
      ) {
        return true;
      }
    }
  }

  let leftIndex = 0;
  let rightIndex = 0;
  let edits = 0;
  while (leftIndex < left.length && rightIndex < right.length) {
    if (left[leftIndex] === right[rightIndex]) {
      leftIndex += 1;
      rightIndex += 1;
      continue;
    }

    edits += 1;
    if (edits > 1) return false;
    if (left.length > right.length) {
      leftIndex += 1;
    } else if (right.length > left.length) {
      rightIndex += 1;
    } else {
      leftIndex += 1;
      rightIndex += 1;
    }
  }

  return true;
}

export function routeCliInvocation(
  args: string[],
  commands: readonly string[],
): CliInvocation {
  const command = args[0];

  if (!command) {
    return { kind: "prompt" };
  }

  if (commands.includes(command)) {
    const { compute, rest } = extractComputeFlag(args.slice(1));
    if (command === "setup" && rest.length > 0) {
      return { kind: "unknown-command", command };
    }
    return withPromptOptions({ kind: "command", command }, compute, joinPrompt(rest));
  }

  if (["env", "flue", "tools", "help", "version"].includes(command)) {
    return { kind: "unknown-command", command };
  }

  if (
    command === command.toLowerCase() &&
    commands.some((known) => known !== "setup" && isOneEditAway(command, known))
  ) {
    return { kind: "unknown-command", command };
  }

  if (command !== "--" && command.startsWith("-")) {
    return { kind: "unknown-option", command };
  }

  const { compute, rest } = extractComputeFlag(args);
  return withPromptOptions({ kind: "prompt" }, compute, joinPrompt(rest));
}
