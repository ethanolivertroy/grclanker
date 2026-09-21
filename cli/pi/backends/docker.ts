import { resolve } from "node:path";
import {
  buildShellCommand,
  createProcessCommandRunner,
  ExecutionBackendError,
  ExecutionBackendUnsupportedError,
  normalizeExitCode,
  type CommandRunner,
  type ExecutionBackend,
  type ExecutionRequest,
  type ExecutionResult,
  type NetworkPolicy,
  type StagedWorkspace,
  type StageWorkspaceInput,
  type WorkspaceMountMode,
} from "../execution-backend.js";

export type DockerRunSpec = {
  image: string;
  hostWorkspace: string;
  workspaceRoot: string;
  workdir: string;
  command: string;
  mountMode?: WorkspaceMountMode;
  networkPolicy?: NetworkPolicy;
  env?: Record<string, string>;
  identity?: { uid: number; gid: number };
};

export type DockerBackendOptions = {
  image: string;
  workspaceRoot: string;
  localRoot: string;
  mountMode?: WorkspaceMountMode;
  networkPolicy?: NetworkPolicy;
  runner?: CommandRunner;
  identity?: { uid: number; gid: number } | null;
};

export function resolveDockerIdentity(): { uid: number; gid: number } | undefined {
  if (typeof process.getuid !== "function" || typeof process.getgid !== "function") {
    return undefined;
  }
  return { uid: process.getuid(), gid: process.getgid() };
}

export function buildDockerRunArgs(spec: DockerRunSpec): string[] {
  const volume = `${spec.hostWorkspace}:${spec.workspaceRoot}${spec.mountMode === "ro" ? ":ro" : ""}`;
  const args = [
    "run",
    "--rm",
    "-i",
    "--init",
    "--volume",
    volume,
    "--workdir",
    spec.workdir,
  ];
  if (spec.networkPolicy === "deny-all") {
    args.push("--network", "none");
  }
  if (spec.identity) {
    args.push("--user", `${spec.identity.uid}:${spec.identity.gid}`);
  }
  args.push("--env", "GRCLANKER_COMPUTE_BACKEND=docker");
  if (spec.identity) {
    args.push("--env", "HOME=/tmp");
  }
  for (const [key, value] of Object.entries(spec.env ?? {})) {
    args.push("--env", `${key}=${value}`);
  }
  args.push(spec.image, "bash", "-lc", spec.command);
  return args;
}

export function createDockerBackend(options: DockerBackendOptions): ExecutionBackend {
  const runner = options.runner ?? createProcessCommandRunner();
  const identity = options.identity === null ? undefined : options.identity ?? resolveDockerIdentity();
  const hostWorkspace = resolve(options.localRoot);

  return {
    kind: "docker",
    capabilities: {
      snapshot: false,
      restore: false,
      gpu: false,
      stageWorkspace: true,
      artifactSync: true,
      interactive: true,
    },
    async healthcheck() {
      const result = await runner("docker", ["info"]);
      if (result.exitCode !== 0) {
        throw new ExecutionBackendError("Docker is installed, but the Docker daemon is not reachable.");
      }
    },
    async stageWorkspace(input: StageWorkspaceInput): Promise<StagedWorkspace> {
      return {
        sessionId: input.sessionId,
        remotePath: options.workspaceRoot,
        detail: `bind mount ${resolve(input.localPath)} at ${options.workspaceRoot} (${input.mountMode ?? options.mountMode ?? "rw"})`,
      };
    },
    async exec(request: ExecutionRequest): Promise<ExecutionResult> {
      const args = buildDockerRunArgs({
        image: options.image,
        hostWorkspace,
        workspaceRoot: options.workspaceRoot,
        workdir: request.cwd,
        command: buildShellCommand(request.command),
        mountMode: options.mountMode,
        networkPolicy: request.networkPolicy ?? options.networkPolicy,
        env: request.env,
        identity,
      });
      const result = await runner("docker", args, {
        timeoutMs: request.timeoutMs,
        onData: request.onData,
        signal: request.signal,
      });
      return {
        exitCode: normalizeExitCode(result.exitCode),
        stdout: result.stdout,
        stderr: result.stderr,
        artifacts: [],
      };
    },
    async snapshot() {
      throw new ExecutionBackendUnsupportedError("docker", "snapshot (containers run with --rm)");
    },
    async restore() {
      throw new ExecutionBackendUnsupportedError("docker", "restore");
    },
    async teardown() {
      return;
    },
  };
}
