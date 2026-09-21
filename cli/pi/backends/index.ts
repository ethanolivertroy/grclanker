import {
  assertExhaustive,
  ExecutionBackendNotAvailableError,
  type CommandRunner,
  type ExecutionBackend,
  type ExecutionBackendKind,
  type FetchLike,
  type StagedWorkspace,
  type StageWorkspaceInput,
} from "../execution-backend.js";
import {
  resolveComputeBackend,
  resolveComputeDefaults,
  resolveDockerImage,
  resolveDockerWorkspacePath,
  resolveParallelsBaseVmName,
  resolveParallelsClonePrefix,
  resolveParallelsSourceKind,
  resolveParallelsTemplateName,
  resolveParallelsWorkspacePath,
} from "../compute.js";
import { wrapCommandWithSandbox } from "../sandbox.js";
import type { GrclankerSettings } from "../settings.js";
import { createDockerBackend } from "./docker.js";
import { createHostBackend, createSandboxRuntimeBackend } from "./local.js";
import { createModalBackend } from "./modal.js";
import { createParallelsBackend } from "./parallels.js";
import { createRunpodPodBackend, createRunpodServerlessBackend } from "./runpod.js";

export type ExecutionBackendDependencies = {
  runner?: CommandRunner;
  fetch?: FetchLike;
};

const STUB_DETAILS: Record<Extract<ExecutionBackendKind, "cloudflare-sandbox" | "vercel-sandbox">, string> = {
  "cloudflare-sandbox":
    "Cloudflare Sandbox is only exposed through the @cloudflare/sandbox Workers SDK inside a deployed Worker (https://developers.cloudflare.com/sandbox/); there is no documented public HTTP lifecycle API for grclanker to call.",
  "vercel-sandbox":
    "Vercel Sandbox is exposed through the @vercel/sandbox SDK and the Vercel CLI (https://vercel.com/docs/vercel-sandbox); grclanker does not add npm dependencies for it yet.",
};

function createStubBackend(
  kind: Extract<ExecutionBackendKind, "cloudflare-sandbox" | "vercel-sandbox">,
): ExecutionBackend {
  const fail = () => {
    throw new ExecutionBackendNotAvailableError(kind, STUB_DETAILS[kind]);
  };
  return {
    kind,
    capabilities: {
      snapshot: false,
      restore: false,
      gpu: false,
      stageWorkspace: false,
      artifactSync: false,
      interactive: false,
    },
    async healthcheck() {
      fail();
    },
    async stageWorkspace(_input: StageWorkspaceInput): Promise<StagedWorkspace> {
      return fail();
    },
    async exec() {
      return fail();
    },
    async snapshot() {
      return fail();
    },
    async restore() {
      fail();
    },
    async teardown() {
      return;
    },
  };
}

export function createExecutionBackend(
  localCwd: string,
  settings: GrclankerSettings,
  deps: ExecutionBackendDependencies = {},
  kind: ExecutionBackendKind = resolveComputeBackend(settings),
): ExecutionBackend {
  const defaults = resolveComputeDefaults(settings);
  switch (kind) {
    case "host":
      return createHostBackend({ runner: deps.runner });
    case "sandbox-runtime":
      return createSandboxRuntimeBackend({
        runner: deps.runner,
        wrapCommand: (command) => wrapCommandWithSandbox(command, localCwd),
      });
    case "docker":
      return createDockerBackend({
        image: resolveDockerImage(settings),
        workspaceRoot: resolveDockerWorkspacePath(settings),
        localRoot: localCwd,
        mountMode: defaults.workspaceMountMode,
        networkPolicy: defaults.networkPolicy,
        runner: deps.runner,
      });
    case "parallels-vm": {
      const sourceKind = resolveParallelsSourceKind(settings);
      return createParallelsBackend({
        sourceKind,
        sourceName: (sourceKind === "template"
          ? resolveParallelsTemplateName(settings)
          : resolveParallelsBaseVmName(settings)) ?? "",
        clonePrefix: resolveParallelsClonePrefix(settings),
        workspacePathOverride: resolveParallelsWorkspacePath(settings),
        runner: deps.runner,
      });
    }
    case "modal":
      return createModalBackend({
        image: typeof settings.modalImage === "string" ? settings.modalImage : undefined,
        gpu: typeof settings.modalGpu === "string" ? settings.modalGpu : undefined,
        environment: process.env.MODAL_ENVIRONMENT,
        runner: deps.runner,
      });
    case "runpod-pod":
      return createRunpodPodBackend({
        fetch: deps.fetch,
        runner: deps.runner,
        workspacePath: typeof settings.runpodWorkspacePath === "string" ? settings.runpodWorkspacePath : undefined,
      });
    case "runpod-serverless":
      return createRunpodServerlessBackend({
        fetch: deps.fetch,
        workspacePath: typeof settings.runpodWorkspacePath === "string" ? settings.runpodWorkspacePath : undefined,
      });
    case "cloudflare-sandbox":
    case "vercel-sandbox":
      return createStubBackend(kind);
    default:
      return assertExhaustive(kind);
  }
}
