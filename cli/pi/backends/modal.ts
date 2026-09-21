import { basename, posix, resolve } from "node:path";
import {
  buildShellCommand,
  createProcessCommandRunner,
  ExecutionBackendError,
  ExecutionBackendUnsupportedError,
  normalizeExitCode,
  redactSecrets,
  requireEnv,
  type CommandRunner,
  type ExecutionBackend,
  type ExecutionRequest,
  type ExecutionResult,
  type StagedWorkspace,
  type StageWorkspaceInput,
} from "../execution-backend.js";
import { quoteForBash } from "../shell.js";

// Modal exposes Sandbox lifecycle through its SDKs; the documented non-SDK surface for
// one-shot command execution is the `modal shell` CLI command:
// https://modal.com/docs/reference/cli/shell
// Credentials are documented at https://modal.com/docs/reference/modal.config
// (MODAL_TOKEN_ID, MODAL_TOKEN_SECRET, optional MODAL_ENVIRONMENT and MODAL_PROFILE).

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
  args.push("--cmd", input.command);
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
    },
    async healthcheck() {
      requireEnv("MODAL_TOKEN_ID");
      requireEnv("MODAL_TOKEN_SECRET");
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
      requireEnv("MODAL_TOKEN_ID");
      requireEnv("MODAL_TOKEN_SECRET");
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
      const result = await runner("modal", args, {
        timeoutMs: request.timeoutMs,
        onData: request.onData,
        signal: request.signal,
      });
      return {
        exitCode: normalizeExitCode(result.exitCode),
        stdout: redactSecrets(result.stdout),
        stderr: redactSecrets(result.stderr),
        artifacts: [],
      };
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
