---
slug: "grclanker-compute-backends"
name: "grclanker Compute Backends"
vendor: "grclanker"
category: "devops-developer-platforms"
language: "typescript"
status: "spec-only"
version: "0.1"
last_updated: "2026-04-05"
source_repo: "https://github.com/hackIDLE/grclanker"
---

# grclanker Compute Backends — Architecture Specification

## Overview

`grclanker` should support multiple execution environments for tool calls and heavier workloads without forcing the entire Pi runtime into one fixed hosting model.

The recommended architecture is:

- Keep the Pi process local by default.
- Route selected tool executions through a pluggable execution backend.
- Support both sandboxing backends and burst compute backends.
- Treat GPU backends and secure code-execution backends as separate lanes.

This matches the current `grclanker` runtime shape: a local wrapper around Pi with custom prompts, extensions, settings, and bundled assets.

## Goals

1. Run risky tool calls in isolated local containers.
2. Burst stateless jobs to managed compute when local resources are not enough.
3. Support long-running GPU workloads without forcing the local machine to host them.
4. Preserve a local-first default path.
5. Make backend choice explicit in settings, headers, logs, and workflow output.

## Non-Goals

- Do not move the full `grclanker` TUI to a remote provider by default.
- Do not conflate model-provider selection with compute backend selection.
- Do not claim support for providers until staging, execution, sync-back, and cleanup are implemented end-to-end.

## Current State

Today `grclanker`:

- launches Pi locally from `cli/pi/launch.ts`
- configures only model access in `grclanker setup`
- hardcodes `local shell` in the header

There is no Dockerfile, no remote execution adapter, and no compute backend abstraction yet.

## Recommended Runtime Model

Use a split control-plane / execution-plane design.

- Control plane: local `grclanker` process, prompts, extensions, UI, settings, orchestration.
- Execution plane: backend-specific environment used for selected tool calls, build/test steps, or compute-heavy analyzers.

This is a better fit than “run everything remotely” because it preserves the current local Pi ergonomics while making isolation and remote compute opt-in per workflow or per tool class.

This also follows the pattern used by Feynman: keep model/provider choice separate from execution environment choice, and present environments like Docker, Modal, and RunPod as explicit execution lanes rather than hidden runtime behavior.

## Core Abstractions

### `ExecutionBackend`

Create an execution interface with a narrow contract:

```ts
type ExecutionBackendKind =
  | "host"
  | "sandbox-runtime"
  | "docker"
  | "parallels-vm"
  | "modal"
  | "runpod-pod"
  | "runpod-serverless"
  | "cloudflare-sandbox"
  | "vercel-sandbox";

type ExecutionRequest = {
  command: string[];
  cwd: string;
  env?: Record<string, string>;
  mounts?: Array<{ localPath: string; remotePath: string; mode: "ro" | "rw" }>;
  networkPolicy?: "default" | "deny-all" | { allowDomains: string[] };
  timeoutMs?: number;
  interactive?: boolean;
};

type ExecutionResult = {
  exitCode: number;
  stdout: string;
  stderr: string;
  artifacts?: string[];
};

interface ExecutionBackend {
  kind: ExecutionBackendKind;
  healthcheck(): Promise<void>;
  stageWorkspace?(input: { localPath: string; sessionId: string }): Promise<void>;
  exec(request: ExecutionRequest): Promise<ExecutionResult>;
  snapshot?(): Promise<string>;
  restore?(snapshotId: string): Promise<void>;
  cleanup(sessionId: string): Promise<void>;
}
```

### Routing Policy

Backends should be selected by policy, not by ad hoc command strings.

Suggested routing buckets:

- `host`: lightweight local reads and normal CLI behavior
- `sandboxed`: shell, package install, build, test, codegen, repo mutation
- `gpu-burst`: model inference, data-heavy transforms, long-running analyzers
- `persistent-remote`: jobs that need SSH, resumability, or large custom images

### Session State

Every remote or sandboxed execution should carry:

- session ID
- working directory or mounted repo root
- backend kind
- snapshot or image reference when supported
- artifact manifest for files copied back

## Backend Matrix

| Backend | Best Use | Strengths | Risks / Limits | Recommendation |
| --- | --- | --- | --- | --- |
| `sandbox-runtime` | Local per-tool confinement | Lowest integration cost, keeps Pi local, explicit FS/network policy | Host OS dependency, not a true VM boundary | MVP |
| `docker` | Local isolated containers | Familiar workflow, reproducible images, good repo mounting story | Local Docker dependency, image management overhead | MVP |
| `parallels-vm` | Local coarse-grained VM isolation | Strong isolation, snapshots, rollback, CLI lifecycle control | Heavier startup cost, macOS/Parallels dependency, more staging complexity | MVP |
| `modal` | Burst remote compute and secure remote sandboxes | Strong isolation, custom images, snapshots, broad GPU platform | Another platform surface, account/auth needed | Phase 2 |
| `runpod-pod` | Persistent GPU or long-running remote envs | SSH, custom containers, storage, VS Code/Jupyter access | Operational statefulness, credit management | Phase 2 |
| `runpod-serverless` | Stateless burst jobs | Pay for active compute, custom worker images | Endpoint-oriented, less ergonomic for interactive shell workflows | Phase 2 |
| `vercel-sandbox` | Remote CPU-only secure command execution | Strong agent-oriented UX, snapshots, CLI, network policies | No GPU, runtime presets, regional/runtime limits | Phase 3 |
| `cloudflare-sandbox` | Remote CPU-only code execution embedded into a service | VM-backed isolation, command/file/process APIs, edge-oriented architecture | Beta, Workers integration overhead, subrequest model | Phase 3 |

## Provider-Specific Guidance

### 1. `sandbox-runtime`

This is the cleanest first step if the Pi extension layer can intercept tool calls and wrap them in a sandbox policy.

Use it for:

- restricting file writes outside the repo
- restricting outbound network access
- containing bash/edit/test tools without requiring Docker

Design notes:

- Backend stays local.
- Policy should default to repo write access plus `/tmp`.
- Secrets and dotfiles should be deny-read or deny-write by default.

### 2. Docker

Docker is the best first “real environment switch” for `grclanker`.

Use it for:

- isolated builds and tests
- running generated analyzers
- validating spec-built projects in a clean image
- reproducing a known local environment

Design notes:

- Mount repo into `/workspace`.
- Mount a writable artifact directory separately.
- Support both generic base images and repo-specific Dockerfiles.
- Expose an interactive mode for debugging.

### 3. Parallels

Parallels is the best coarse-grained local VM backend for users who want a stronger boundary than Docker or OS-level tool sandboxing.

Use it for:

- disposable development sandboxes
- high-risk shell or build workflows
- repo work that should not touch the host beyond an explicit shared folder or SSH channel
- snapshot-and-rollback validation runs

Design notes:

- Manage lifecycle with `prlctl` and `prlsrvctl`.
- Support a dedicated Linux VM first; Windows can come later.
- Prefer SSH into the guest for command execution even if `prlctl exec` is available.
- Support two workspace modes:
  - shared-folder mount from host into guest
  - git-native checkout inside the VM
- Support snapshot creation and rollback for disposable sessions.

Typical flow:

```bash
prlctl start grclanker-sandbox
prlctl exec grclanker-sandbox -- sudo systemctl start ssh
ssh grclanker@<vm-ip> 'cd /workspace && grclanker investigate "..."'
prlctl snapshot grclanker-sandbox --name pre-run
prlctl rollback grclanker-sandbox --id <snapshot-id>
```

### 4. Modal

Modal fits two roles:

- secure remote sandboxes for arbitrary code execution
- burst GPU execution for heavier jobs

Use it for:

- parallel analysis jobs
- burst training or inference
- expensive validation pipelines
- reusable snapshot-backed environments

Design notes:

- Prefer Sandboxes for secure arbitrary command execution.
- Prefer Functions for GPU-oriented batch analyzers and service endpoints.
- Treat Docker-in-Sandbox as optional and non-MVP.

### 5. RunPod

RunPod should be split into two backends.

#### `runpod-pod`

Use for:

- long-running GPU jobs
- persistent SSH sessions
- custom container images with larger state
- workloads that need human inspection or manual repair

#### `runpod-serverless`

Use for:

- request/response burst jobs
- endpoint-oriented GPU tasks
- stateless worker-image execution

Design notes:

- Pods are better for “remote workstation” workflows.
- Serverless is better for “dispatch a job and collect output”.

### 6. Vercel Sandbox

Vercel Sandbox is a strong CPU-only sandbox option for agentic code execution.

Use it for:

- isolated builds and tests
- running untrusted code remotely
- snapshotting dependency-heavy environments
- previewing services from a sandbox

Do not treat it as a GPU backend.

### 7. Cloudflare Sandbox

Cloudflare Sandbox is also a CPU-only sandbox option, but it is more opinionated around being embedded inside a Worker/Durable Object architecture.

Use it for:

- multi-tenant sandbox services
- browser-based execution products
- code interpreter features
- edge-adjacent orchestration where the Worker is part of the product

Do not treat it as a drop-in replacement for Modal or RunPod GPUs.

## Product Recommendation

Build this in three phases.

### Phase 1 — Local Sandboxing

Ship:

- `host`
- `sandbox-runtime`
- `docker`
- `parallels-vm`

Why:

- least operational overhead
- fits local-first release strategy
- immediately improves safety and reproducibility
- aligns with Pi extension interception patterns
- gives users a stronger local isolation option without introducing a hosted control plane

### Phase 2 — Remote Compute

Ship:

- `modal`
- `runpod-pod`
- `runpod-serverless`

Why:

- covers burst GPU and long-running GPU lanes
- separates “secure code execution” from “heavy compute”
- provides both stateless and persistent remote options

### Phase 3 — Hosted CPU Sandboxes

Ship one first, not both at once:

- `vercel-sandbox` first if the goal is simple remote code execution with a good CLI/SDK workflow
- `cloudflare-sandbox` first if the goal is to build a multi-tenant sandbox service directly into a hosted `grclanker` platform

Why:

- both are valuable
- both add platform complexity
- neither replaces the GPU lane

## CLI and Settings Surface

Extend settings with compute configuration separate from model configuration.

```json
{
  "defaultProvider": "ollama",
  "defaultModel": "gemma4",
  "modelMode": "local",
  "providerKind": "ollama",
  "computeBackend": "docker",
  "computeProfile": "isolated-local",
  "computeDefaults": {
    "networkPolicy": "default",
    "workspaceMountMode": "rw"
  }
}
```

Recommended CLI additions:

```bash
grclanker setup
grclanker setup --compute docker
grclanker investigate "..." --compute docker
grclanker audit "..." --compute modal
grclanker env list
grclanker env doctor
```

## Implementation Checklist

### Foundation

- Add `computeBackend` and backend-specific config to settings.
- Replace hardcoded `local shell` header text with backend-aware runtime surface text.
- Add backend health checks and diagnostics.
- Add artifact sync and session cleanup primitives.

### Docker MVP

- Build Docker backend adapter.
- Support repo mount, env pass-through, stdout/stderr capture, exit codes.
- Add a base image strategy and optional repo Dockerfile path.

### `sandbox-runtime` MVP

- Add policy file generation.
- Wrap shell/edit/build/test tools through sandbox runtime.
- Add allowlist/denylist defaults for repo work.

### Parallels MVP

- Add Parallels backend adapter with `prlctl` health checks.
- Support VM start, stop, snapshot, rollback, and cleanup.
- Support SSH-based command execution in the guest.
- Support host shared-folder mode and guest-local checkout mode.
- Add a `grclanker env doctor` check for Parallels Desktop CLI availability.

### Modal

- Add Modal auth and environment detection.
- Add sandbox exec adapter.
- Add snapshot support for reusable environments.
- Add separate GPU job runner for heavy workflows.

### RunPod

- Add Pod lifecycle adapter with SSH or CLI exec path.
- Add Serverless job adapter for endpoint-style workloads.
- Add workspace upload/download and artifact retrieval.

### Hosted CPU Sandboxes

- Add a thin provider adapter for Vercel or Cloudflare.
- Support copy-in, command exec, snapshot, network policy, and cleanup.
- Gate behind explicit config because both are external hosted services.

## Acceptance Criteria

1. A user can choose `host`, `sandbox-runtime`, or `docker` during `grclanker setup`.
2. A user can choose `parallels-vm` during `grclanker setup` when `prlctl` is available.
3. The header and logs reflect the actual selected compute backend.
4. `grclanker investigate` can run a shell-heavy subtask in Docker or Parallels and return synced artifacts.
5. Remote providers stage the workspace, execute commands, and sync artifacts back reliably.
6. GPU-oriented workflows can target Modal or RunPod without changing the local control plane.

## Decision Summary

- Start with local tool sandboxing, Docker, and Parallels.
- Add Modal and RunPod for real remote compute.
- Treat Cloudflare Sandbox and Vercel Sandbox as hosted CPU sandbox options, not GPU backends.
- Keep `grclanker` local-first, with pluggable execution backends rather than a single monolithic runtime location.
