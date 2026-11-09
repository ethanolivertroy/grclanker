import { COMPUTE_BACKEND_KINDS, parseComputeBackendKind, type ComputeBackendKind } from "./compute.js";
import { GrclankerUserError } from "./setup.js";

export function parseComputeFlag(value: string): ComputeBackendKind {
  const kind = parseComputeBackendKind(value);
  if (!kind) {
    throw new GrclankerUserError(
      `Unknown compute backend: ${value}. Expected one of: ${COMPUTE_BACKEND_KINDS.join(", ")}.`,
    );
  }
  return kind;
}

export function extractComputeFlag(args: string[]): { compute?: ComputeBackendKind; rest: string[] } {
  const rest: string[] = [];
  let compute: ComputeBackendKind | undefined;
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index]!;
    if (arg === "--") {
      rest.push(...args.slice(index + 1));
      break;
    }
    if (arg === "--compute") {
      const value = args[index + 1];
      if (!value) throw new GrclankerUserError("Missing value for --compute.");
      compute = parseComputeFlag(value);
      index += 1;
      continue;
    }
    if (arg.startsWith("--compute=")) {
      compute = parseComputeFlag(arg.slice("--compute=".length));
      continue;
    }
    rest.push(arg);
  }
  return { compute, rest };
}
