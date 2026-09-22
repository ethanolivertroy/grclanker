import { resolve } from "node:path";
import {
  buildShellCommand,
  createExecutionOutputGuard,
  createProcessCommandRunner,
  ExecutionBackendUnsupportedError,
  normalizeExitCode,
  type CommandRunner,
  type ExecutionBackend,
  type ExecutionBackendKind,
  type ExecutionRequest,
  type ExecutionResult,
  type StagedWorkspace,
  type StageWorkspaceInput,
} from "../execution-backend.js";

export type LocalBackendOptions = {
  runner?: CommandRunner;
  wrapCommand?: (command: string, cwd: string) => Promise<string>;
};

function createLocalBackend(
  kind: Extract<ExecutionBackendKind, "host" | "sandbox-runtime">,
  options: LocalBackendOptions,
): ExecutionBackend {
  const runner = options.runner ?? createProcessCommandRunner();
  const wrap = options.wrapCommand ?? (async (command: string) => command);

  return {
    kind,
    capabilities: {
      snapshot: false,
      restore: false,
      gpu: false,
      stageWorkspace: false,
      artifactSync: true,
      interactive: true,
      oneShot: false,
    },
    async healthcheck() {
      return;
    },
    async stageWorkspace(input: StageWorkspaceInput): Promise<StagedWorkspace> {
      return {
        sessionId: input.sessionId,
        remotePath: resolve(input.localPath),
        detail: "workspace is used in place on the host",
      };
    },
    async exec(request: ExecutionRequest): Promise<ExecutionResult> {
      const command = await wrap(buildShellCommand(request.command), request.cwd);
      const guard = createExecutionOutputGuard(request);
      try {
        const result = await runner("bash", ["-lc", command], {
          cwd: request.cwd,
          env: request.env,
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
      throw new ExecutionBackendUnsupportedError(kind, "snapshot");
    },
    async restore() {
      throw new ExecutionBackendUnsupportedError(kind, "restore");
    },
    async teardown() {
      return;
    },
  };
}

export function createHostBackend(options: LocalBackendOptions = {}): ExecutionBackend {
  return createLocalBackend("host", options);
}

export function createSandboxRuntimeBackend(options: LocalBackendOptions = {}): ExecutionBackend {
  return createLocalBackend("sandbox-runtime", options);
}
