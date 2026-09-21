import { resolve } from "node:path";
import {
  assertSafeSessionId,
  buildShellCommand,
  createExecutionOutputGuard,
  createProcessCommandRunner,
  createProcessCommandRunnerSync,
  describeEndpoint,
  ExecutionBackendError,
  ExecutionBackendTimeoutError,
  ExecutionBackendUnsupportedError,
  normalizeExitCode,
  readProviderBody,
  requireEnv,
  summarizeJsonBody,
  type CommandRunner,
  type CommandRunnerSync,
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

// RunPod documents 600000 ms as the default `executionTimeout` for serverless jobs
// (https://docs.runpod.io/serverless/endpoints/send-requests, "Execution policies"); the
// adapter uses the same ceiling when the caller passes no timeoutMs, plus a polling grace
// window so the endpoint gets to report TIMED_OUT itself before the client gives up.
export const DEFAULT_RUNPOD_JOB_TIMEOUT_MS = 600_000;
export const RUNPOD_POLL_GRACE_MS = 60_000;

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
  now?: () => number;
  pollIntervalMs?: number;
  defaultTimeoutMs?: number;
  workspacePath?: string;
};

export type RunpodPodOptions = {
  fetch?: FetchLike;
  runner?: CommandRunner;
  syncRunner?: CommandRunnerSync;
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

// Every RunPod response goes through here. A non-JSON body (a gateway's 502 page, a login page
// on a 200) is never quoted: the message carries status, endpoint, content type, and length.
// JSON error bodies contribute only their message-bearing fields, and the ExecutionBackendError
// constructor scrubs whatever those fields carry.
async function readJson<T>(response: Response, action: string, url: string): Promise<T> {
  const body = await readProviderBody(response);
  const endpoint = describeEndpoint(url);
  if (!response.ok) {
    throw new ExecutionBackendError(`${action} failed with HTTP ${response.status} from ${endpoint}: ${body.detail}`);
  }
  if (body.json === undefined) {
    throw new ExecutionBackendError(`${action} returned HTTP ${response.status} from ${endpoint} with a ${body.detail}; expected JSON.`);
  }
  return body.json as T;
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
  const now = options.now ?? (() => Date.now());
  const pollIntervalMs = options.pollIntervalMs ?? 2_000;
  const defaultTimeoutMs = options.defaultTimeoutMs ?? DEFAULT_RUNPOD_JOB_TIMEOUT_MS;
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
      const url = endpointUrl("/health");
      const response = await fetchImpl(url, { method: "GET", headers: authHeaders(apiKey) });
      await readJson<Record<string, unknown>>(response, "RunPod endpoint health check", url);
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
      const timeoutMs = request.timeoutMs ?? defaultTimeoutMs;
      const body = {
        input: {
          command: buildShellCommand(request.command),
          cwd: request.cwd,
          env: request.env ?? {},
        },
        policy: request.timeoutMs ? { executionTimeout: Math.max(5_000, request.timeoutMs) } : undefined,
      };
      const runUrl = endpointUrl("/run");
      const submitted = await readJson<RunpodJobResponse>(
        await fetchImpl(runUrl, {
          method: "POST",
          headers: authHeaders(apiKey),
          body: JSON.stringify(body),
        }),
        "RunPod job submission",
        runUrl,
      );
      if (!submitted.id) {
        throw new ExecutionBackendError("RunPod /run did not return a job id.");
      }

      const deadline = now() + timeoutMs + RUNPOD_POLL_GRACE_MS;
      let job = submitted;
      try {
        while (job.status === "IN_QUEUE" || job.status === "IN_PROGRESS" || job.status === undefined) {
          if (request.signal?.aborted) throw new ExecutionBackendError("aborted");
          if (now() > deadline) {
            throw new ExecutionBackendTimeoutError(
              "runpod-serverless",
              `job ${submitted.id} was still ${job.status ?? "pending"}; the adapter cancelled it`,
              timeoutMs,
            );
          }
          await sleep(pollIntervalMs);
          const statusUrl = endpointUrl(`/status/${submitted.id}`);
          job = await readJson<RunpodJobResponse>(
            await fetchImpl(statusUrl, { method: "GET", headers: authHeaders(apiKey) }),
            "RunPod job status",
            statusUrl,
          );
        }
      } catch (error) {
        await fetchImpl(endpointUrl(`/cancel/${submitted.id}`), { method: "POST", headers: authHeaders(apiKey) }).catch(() => undefined);
        throw error;
      }

      if (job.status !== "COMPLETED") {
        // The job error is provider text: a string is quoted (the constructor scrubs it), an
        // object is described by its message fields and key names, never serialized whole.
        throw new ExecutionBackendError(`RunPod job ${submitted.id} ended with status ${job.status}. ${summarizeJsonBody(job.error)}`);
      }

      // Worker output is untrusted remote text: it can echo the worker's own environment,
      // so it is redacted before it reaches onData, the tool result, or any evidence file.
      const output = parseRunpodWorkerOutput(job.output);
      const guard = createExecutionOutputGuard(request, [apiKey]);
      const result = guard.finish({
        exitCode: normalizeExitCode(output.exitCode),
        stdout: output.stdout,
        stderr: output.stderr,
        artifacts: output.artifacts ?? [],
      });
      guard.onData?.(Buffer.from(result.stdout + result.stderr, "utf8"));
      guard.end();
      return result;
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

export function buildPodSessionPath(workspacePath: string, sessionId: string): string {
  return `${workspacePath.replace(/\/+$/, "")}/${assertSafeSessionId(sessionId)}`;
}

export function createRunpodPodBackend(options: RunpodPodOptions = {}): ExecutionBackend {
  const fetchImpl: FetchLike = options.fetch ?? ((input, init) => fetch(input, init));
  const runner = options.runner ?? createProcessCommandRunner();
  const syncRunner = options.syncRunner ?? createProcessCommandRunnerSync();
  const workspacePath = options.workspacePath ?? DEFAULT_RUNPOD_WORKSPACE_PATH;
  const sshUser = options.sshUser ?? "root";
  const stagedSessions = new Set<string>();
  let cachedPod: RunpodPod | undefined;

  async function fetchPod(): Promise<RunpodPod> {
    const apiKey = requireEnv("RUNPOD_API_KEY");
    const podId = requireEnv("RUNPOD_POD_ID");
    const url = `${RUNPOD_REST_BASE_URL}/pods/${encodeURIComponent(podId)}`;
    const response = await fetchImpl(url, {
      method: "GET",
      headers: authHeaders(apiKey),
    });
    cachedPod = await readJson<RunpodPod>(response, `RunPod pod ${podId} lookup`, url);
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
      const remotePath = buildPodSessionPath(workspacePath, input.sessionId);
      const target = await sshTarget();
      const localRoot = resolve(input.localPath);
      const prepare = await runner("ssh", buildPodSshArgs(target, `mkdir -p -- ${quoteForBash(remotePath)}`));
      if (prepare.exitCode !== 0) {
        throw new ExecutionBackendError(`Could not prepare ${remotePath} on the pod. ${prepare.stderr}`);
      }
      stagedSessions.add(input.sessionId);
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
        await runner("ssh", buildPodSshArgs(target, `rm -rf -- ${quoteForBash(remotePath)}`)).catch(() => undefined);
        stagedSessions.delete(input.sessionId);
        throw new ExecutionBackendError(`Could not copy the workspace to the pod. ${copy.stderr}`);
      }
      return { sessionId: input.sessionId, remotePath, detail: `copied ${localRoot} to ${target.host}:${remotePath} over scp` };
    },
    async exec(request: ExecutionRequest): Promise<ExecutionResult> {
      const target = await sshTarget();
      const envPrefix = Object.entries(request.env ?? {})
        .map(([key, value]) => `export ${key}=${quoteForBash(value)};`)
        .join(" ");
      const remoteCommand = `${envPrefix} cd -- ${quoteForBash(request.cwd)} && ${buildShellCommand(request.command)}`.trim();
      const guard = createExecutionOutputGuard(request);
      try {
        const result = await runner("ssh", buildPodSshArgs(target, remoteCommand), {
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
      throw new ExecutionBackendUnsupportedError("runpod-pod", "snapshot");
    },
    async restore() {
      throw new ExecutionBackendUnsupportedError("runpod-pod", "restore");
    },
    async teardown(sessionId: string) {
      const remotePath = buildPodSessionPath(workspacePath, sessionId);
      if (!stagedSessions.has(sessionId)) return;
      const target = await sshTarget();
      try {
        await runner("ssh", buildPodSshArgs(target, `rm -rf -- ${quoteForBash(remotePath)}`));
      } finally {
        stagedSessions.delete(sessionId);
      }
    },
    teardownSync(sessionId: string) {
      const remotePath = buildPodSessionPath(workspacePath, sessionId);
      if (!stagedSessions.has(sessionId) || !cachedPod) return;
      stagedSessions.delete(sessionId);
      syncRunner("ssh", buildPodSshArgs(resolvePodSshTarget(cachedPod, sshUser), `rm -rf -- ${quoteForBash(remotePath)}`));
    },
  };
}
