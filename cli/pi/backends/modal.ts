import { basename, posix, resolve } from "node:path";
import {
  buildShellCommand,
  createExecutionOutputGuard,
  createProcessCommandRunner,
  ExecutionBackendError,
  ExecutionBackendUnsupportedError,
  normalizeExitCode,
  type CommandRunner,
  type ExecutionBackend,
  type ExecutionRequest,
  type ExecutionResult,
  type StagedWorkspace,
  type StageWorkspaceInput,
} from "../execution-backend.js";
import { quoteForBash } from "../shell.js";
import { requireModalCredentials } from "./modal-profile.js";

// Modal exposes Sandbox lifecycle through its SDKs; the documented non-SDK surface for
// one-shot command execution is the `modal shell` CLI command:
// https://modal.com/docs/reference/cli/shell
// Credentials are documented at https://modal.com/docs/reference/modal.config: MODAL_TOKEN_ID
// and MODAL_TOKEN_SECRET in the environment, or the active profile of `.modal.toml` written by
// `modal setup` / `modal token set` (see modal-profile.ts); optional MODAL_ENVIRONMENT and
// MODAL_PROFILE. The CLI resolves the credentials itself; the guard only confirms one source
// exists so a missing token fails here with a clear message instead of inside `modal shell`.

export const DEFAULT_MODAL_IMAGE = "debian:bookworm-slim";

export type ModalBackendOptions = {
  image?: string;
  gpu?: string;
  environment?: string;
  region?: string;
  runner?: CommandRunner;
};

type ModalSession = {
  localPath: string;
  remotePath: string;
};

// The modal client runs `shlex.split(f'/bin/bash -c "{cmd}"')` on the --cmd value
// (modal/cli/shell.py), so any double quote, backslash, or shell metacharacter in the raw
// command would be re-split by shlex. The wrapper below contains only [A-Za-z0-9+/=],
// spaces, and characters shlex treats literally inside double quotes; the real command
// travels as base64 and is decoded into a temp file so the script keeps its own stdin.
export function buildModalCommandWrapper(command: string): string {
  const encoded = Buffer.from(command, "utf8").toString("base64");
  return `f=$(mktemp) && printf %s ${encoded} | base64 -d > $f && bash $f; s=$?; rm -f $f; exit $s`;
}

export function decodeModalCommandWrapper(wrapper: string): string | undefined {
  const match = /printf %s ([A-Za-z0-9+/=]+) \| base64 -d/.exec(wrapper);
  return match ? Buffer.from(match[1]!, "base64").toString("utf8") : undefined;
}

export function buildModalShellArgs(input: {
  image: string;
  command: string;
  localPath?: string;
  gpu?: string;
  environment?: string;
  region?: string;
}): string[] {
  const args = ["shell", "--no-pty", "--image", input.image];
  if (input.localPath) args.push("--add-local", input.localPath);
  if (input.gpu) args.push("--gpu", input.gpu);
  if (input.environment) args.push("--env", input.environment);
  if (input.region) args.push("--region", input.region);
  args.push("--cmd", buildModalCommandWrapper(input.command));
  return args;
}

export function createModalBackend(options: ModalBackendOptions = {}): ExecutionBackend {
  const runner = options.runner ?? createProcessCommandRunner();
  const image = options.image ?? DEFAULT_MODAL_IMAGE;
  const sessions = new Map<string, ModalSession>();

  return {
    kind: "modal",
    capabilities: {
      snapshot: false,
      restore: false,
      gpu: true,
      stageWorkspace: true,
      artifactSync: false,
      interactive: false,
      oneShot: true,
    },
    async healthcheck() {
      requireModalCredentials();
      const result = await runner("modal", ["--version"]);
      if (result.exitCode !== 0) {
        throw new ExecutionBackendError("The modal CLI is not installed or not on PATH. Install it with `pip install modal`.");
      }
    },
    async stageWorkspace(input: StageWorkspaceInput): Promise<StagedWorkspace> {
      const localPath = resolve(input.localPath);
      const remotePath = posix.join("/mnt", basename(localPath));
      sessions.set(input.sessionId, { localPath, remotePath });
      return {
        sessionId: input.sessionId,
        remotePath,
        detail: `modal shell --add-local copies ${localPath} into the container at ${remotePath} for each command; changes are not synced back`,
      };
    },
    async exec(request: ExecutionRequest): Promise<ExecutionResult> {
      requireModalCredentials();
      const session = sessions.get(request.sessionId);
      const envPrefix = Object.entries(request.env ?? {})
        .map(([key, value]) => `export ${key}=${quoteForBash(value)};`)
        .join(" ");
      const command = `${envPrefix} cd -- ${quoteForBash(request.cwd)} && ${buildShellCommand(request.command)}`.trim();
      const args = buildModalShellArgs({
        image,
        command,
        localPath: session?.localPath,
        gpu: options.gpu,
        environment: options.environment,
        region: options.region,
      });
      const guard = createExecutionOutputGuard(request);
      try {
        const result = await runner("modal", args, {
          timeoutMs: request.timeoutMs,
          onData: guard.onData,
          signal: request.signal,
        });
        return guard.finish({
          exitCode: normalizeExitCode(result.exitCode),
          stdout: result.stdout,
          stderr: result.stderr,
          artifacts: [],
        });
      } finally {
        guard.end();
      }
    },
    async snapshot() {
      throw new ExecutionBackendUnsupportedError("modal", "snapshot through the modal CLI");
    },
    async restore() {
      throw new ExecutionBackendUnsupportedError("modal", "restore through the modal CLI");
    },
    async teardown(sessionId: string) {
      sessions.delete(sessionId);
    },
  };
}
