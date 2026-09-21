import { resolve } from "node:path";
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
  type FetchLike,
  type StagedWorkspace,
  type StageWorkspaceInput,
} from "../execution-backend.js";
import { quoteForBash } from "../shell.js";

// RunPod serverless queue-based endpoint operations (base URL, auth header, request body,
// job status values, and the `id`, `status`, `output` response fields):
// https://docs.runpod.io/serverless/endpoints/send-requests
// https://docs.runpod.io/serverless/endpoints/operation-reference
export const RUNPOD_SERVERLESS_BASE_URL = "https://api.runpod.ai/v2";

// RunPod REST API v1 for pods (Bearer auth, GET /pods/{podId}, `publicIp`, `portMappings`,
// `desiredStatus` response fields). v1 is documented as deprecated with retirement on
// 2026-11-15; the adapter isolates the base URL so a v2 move is a single constant change.
// https://docs.runpod.io/api-reference/overview
// https://docs.runpod.io/api-reference/pods/GET/pods/podId
export const RUNPOD_REST_BASE_URL = "https://rest.runpod.io/v1";

export const DEFAULT_RUNPOD_WORKSPACE_PATH = "/workspace";

type RunpodJobStatus = "IN_QUEUE" | "IN_PROGRESS" | "COMPLETED" | "FAILED" | "CANCELLED" | "TIMED_OUT";

type RunpodJobResponse = {
  id?: string;
  status?: RunpodJobStatus | string;
  output?: unknown;
  error?: unknown;
};

export type RunpodWorkerOutput = {
  exitCode: number;
  stdout: string;
  stderr: string;
  artifacts?: string[];
};

export type RunpodServerlessOptions = {
  fetch?: FetchLike;
  sleep?: (milliseconds: number) => Promise<void>;
  pollIntervalMs?: number;
  workspacePath?: string;
};

export type RunpodPodOptions = {
  fetch?: FetchLike;
  runner?: CommandRunner;
  workspacePath?: string;
  sshUser?: string;
};

function authHeaders(apiKey: string): Record<string, string> {
  return {
    authorization: `Bearer ${apiKey}`,
    "content-type": "application/json",
    accept: "application/json",
  };
}

async function readJson<T>(response: Response, apiKey: string, action: string): Promise<T> {
  if (!response.ok) {
    const body = redactSecrets(await response.text(), [apiKey]);
    throw new ExecutionBackendError(`${action} failed with HTTP ${response.status}. ${body.slice(0, 400)}`);
  }
  return (await response.json()) as T;
}

export function parseRunpodWorkerOutput(output: unknown): RunpodWorkerOutput {
  const record = output && typeof output === "object" ? (output as Record<string, unknown>) : {};
  return {
    exitCode: typeof record.exitCode === "number" ? record.exitCode : 1,
    stdout: typeof record.stdout === "string" ? record.stdout : "",
    stderr: typeof record.stderr === "string" ? record.stderr : "",
    artifacts: Array.isArray(record.artifacts)
      ? record.artifacts.filter((entry): entry is string => typeof entry === "string")
      : [],
  };
}

export function createRunpodServerlessBackend(options: RunpodServerlessOptions = {}): ExecutionBackend {
  const fetchImpl: FetchLike = options.fetch ?? ((input, init) => fetch(input, init));
  const sleep = options.sleep ?? ((milliseconds: number) => new Promise<void>((done) => setTimeout(done, milliseconds)));
  const pollIntervalMs = options.pollIntervalMs ?? 2_000;
  const workspacePath = options.workspacePath ?? DEFAULT_RUNPOD_WORKSPACE_PATH;

  function endpointUrl(path: string): string {
    return `${RUNPOD_SERVERLESS_BASE_URL}/${requireEnv("RUNPOD_ENDPOINT_ID")}${path}`;
  }

  return {
    kind: "runpod-serverless",
    capabilities: {
      snapshot: false,
      restore: false,
      gpu: true,
      stageWorkspace: false,
      artifactSync: false,
      interactive: false,
    },
    async healthcheck() {
      const apiKey = requireEnv("RUNPOD_API_KEY");
      const response = await fetchImpl(endpointUrl("/health"), { method: "GET", headers: authHeaders(apiKey) });
      await readJson<Record<string, unknown>>(response, apiKey, "RunPod endpoint health check");
    },
    async stageWorkspace(input: StageWorkspaceInput): Promise<StagedWorkspace> {
      return {
        sessionId: input.sessionId,
        remotePath: workspacePath,
        detail: `serverless jobs receive JSON input only; the worker image must already contain the workspace at ${workspacePath}`,
      };
    },
    async exec(request: ExecutionRequest): Promise<ExecutionResult> {
      const apiKey = requireEnv("RUNPOD_API_KEY");
      const body = {
        input: {
          command: buildShellCommand(request.command),
          cwd: request.cwd,
          env: request.env ?? {},
        },
        policy: request.timeoutMs ? { executionTimeout: Math.max(5_000, request.timeoutMs) } : undefined,
      };
      const submitted = await readJson<RunpodJobResponse>(
        await fetchImpl(endpointUrl("/run"), {
          method: "POST",
          headers: authHeaders(apiKey),
          body: JSON.stringify(body),
        }),
        apiKey,
        "RunPod job submission",
      );
      if (!submitted.id) {
        throw new ExecutionBackendError("RunPod /run did not return a job id.");
      }

      const deadline = request.timeoutMs ? Date.now() + request.timeoutMs + 60_000 : undefined;
      let job = submitted;
      try {
        while (job.status === "IN_QUEUE" || job.status === "IN_PROGRESS" || job.status === undefined) {
          if (request.signal?.aborted) throw new ExecutionBackendError("aborted");
          if (deadline && Date.now() > deadline) {
            throw new ExecutionBackendError(`RunPod job ${submitted.id} did not finish within the timeout.`);
          }
          await sleep(pollIntervalMs);
          job = await readJson<RunpodJobResponse>(
            await fetchImpl(endpointUrl(`/status/${submitted.id}`), { method: "GET", headers: authHeaders(apiKey) }),
            apiKey,
            "RunPod job status",
          );
        }
      } catch (error) {
        await fetchImpl(endpointUrl(`/cancel/${submitted.id}`), { method: "POST", headers: authHeaders(apiKey) }).catch(() => undefined);
        throw error;
      }

      if (job.status !== "COMPLETED") {
        const detail = redactSecrets(typeof job.error === "string" ? job.error : JSON.stringify(job.error ?? ""), [apiKey]);
        throw new ExecutionBackendError(`RunPod job ${submitted.id} ended with status ${job.status}. ${detail}`.trim());
      }

      const output = parseRunpodWorkerOutput(job.output);
      request.onData?.(Buffer.from(output.stdout + output.stderr, "utf8"));
      return {
        exitCode: normalizeExitCode(output.exitCode),
        stdout: output.stdout,
        stderr: output.stderr,
        artifacts: output.artifacts ?? [],
      };
    },
    async snapshot() {
      throw new ExecutionBackendUnsupportedError("runpod-serverless", "snapshot");
    },
    async restore() {
      throw new ExecutionBackendUnsupportedError("runpod-serverless", "restore");
    },
    async teardown() {
      return;
    },
  };
}

type RunpodPod = {
  id?: string;
  desiredStatus?: string;
  publicIp?: string;
  portMappings?: Record<string, number>;
};

export function resolvePodSshTarget(pod: RunpodPod, user: string): { host: string; port: number; user: string } {
  const port = pod.portMappings?.["22"];
  if (!pod.publicIp || typeof port !== "number") {
    throw new ExecutionBackendError(
      "The RunPod pod does not expose public SSH (publicIp and portMappings[\"22\"] are required). Expose TCP port 22 on the pod.",
    );
  }
  return { host: pod.publicIp, port, user };
}

export function buildPodSshArgs(target: { host: string; port: number; user: string }, remoteCommand: string): string[] {
  return [
    "-o",
    "BatchMode=yes",
    "-o",
    "StrictHostKeyChecking=accept-new",
    "-p",
    String(target.port),
    `${target.user}@${target.host}`,
    remoteCommand,
  ];
}

export function createRunpodPodBackend(options: RunpodPodOptions = {}): ExecutionBackend {
  const fetchImpl: FetchLike = options.fetch ?? ((input, init) => fetch(input, init));
  const runner = options.runner ?? createProcessCommandRunner();
  const workspacePath = options.workspacePath ?? DEFAULT_RUNPOD_WORKSPACE_PATH;
  const sshUser = options.sshUser ?? "root";
  let cachedPod: RunpodPod | undefined;

  async function fetchPod(): Promise<RunpodPod> {
    const apiKey = requireEnv("RUNPOD_API_KEY");
    const podId = requireEnv("RUNPOD_POD_ID");
    const response = await fetchImpl(`${RUNPOD_REST_BASE_URL}/pods/${encodeURIComponent(podId)}`, {
      method: "GET",
      headers: authHeaders(apiKey),
    });
    cachedPod = await readJson<RunpodPod>(response, apiKey, `RunPod pod ${podId} lookup`);
    return cachedPod;
  }

  async function sshTarget(): Promise<{ host: string; port: number; user: string }> {
    return resolvePodSshTarget(cachedPod ?? await fetchPod(), sshUser);
  }

  return {
    kind: "runpod-pod",
    capabilities: {
      snapshot: false,
      restore: false,
      gpu: true,
      stageWorkspace: true,
      artifactSync: true,
      interactive: false,
    },
    async healthcheck() {
      const pod = await fetchPod();
      if (pod.desiredStatus && pod.desiredStatus !== "RUNNING") {
        throw new ExecutionBackendError(`RunPod pod is ${pod.desiredStatus}; start it before running work on it.`);
      }
      resolvePodSshTarget(pod, sshUser);
    },
    async stageWorkspace(input: StageWorkspaceInput): Promise<StagedWorkspace> {
      const target = await sshTarget();
      const localRoot = resolve(input.localPath);
      const remotePath = `${workspacePath}/${input.sessionId}`;
      const prepare = await runner("ssh", buildPodSshArgs(target, `mkdir -p -- ${quoteForBash(remotePath)}`));
      if (prepare.exitCode !== 0) {
        throw new ExecutionBackendError(`Could not prepare ${remotePath} on the pod. ${redactSecrets(prepare.stderr)}`);
      }
      const copy = await runner("scp", [
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=accept-new",
        "-P",
        String(target.port),
        "-r",
        `${localRoot}/.`,
        `${target.user}@${target.host}:${remotePath}`,
      ]);
      if (copy.exitCode !== 0) {
        throw new ExecutionBackendError(`Could not copy the workspace to the pod. ${redactSecrets(copy.stderr)}`);
      }
      return { sessionId: input.sessionId, remotePath, detail: `copied ${localRoot} to ${target.host}:${remotePath} over scp` };
    },
    async exec(request: ExecutionRequest): Promise<ExecutionResult> {
      const target = await sshTarget();
      const envPrefix = Object.entries(request.env ?? {})
        .map(([key, value]) => `export ${key}=${quoteForBash(value)};`)
        .join(" ");
      const remoteCommand = `${envPrefix} cd -- ${quoteForBash(request.cwd)} && ${buildShellCommand(request.command)}`.trim();
      const result = await runner("ssh", buildPodSshArgs(target, remoteCommand), {
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
      throw new ExecutionBackendUnsupportedError("runpod-pod", "snapshot");
    },
    async restore() {
      throw new ExecutionBackendUnsupportedError("runpod-pod", "restore");
    },
    async teardown(sessionId: string) {
      const target = await sshTarget();
      const remotePath = `${workspacePath}/${sessionId}`;
      await runner("ssh", buildPodSshArgs(target, `rm -rf -- ${quoteForBash(remotePath)}`));
    },
  };
}
