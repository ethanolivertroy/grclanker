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
    return withPromptOptions({ kind: "command", command }, compute, joinPrompt(rest));
  }

  if (command !== "--" && command.startsWith("-")) {
    return { kind: "unknown-option", command };
  }

  const { compute, rest } = extractComputeFlag(args);
  return withPromptOptions({ kind: "prompt" }, compute, joinPrompt(rest));
}
