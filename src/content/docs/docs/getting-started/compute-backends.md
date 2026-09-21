---
title: Compute Backends
description: Configure host, sandbox-runtime, Docker, Parallels, Modal, or RunPod execution for grclanker and validate each backend with env list, env doctor, and smoke-test.
---

grclanker separates model choice from execution environment on purpose.

That part is similar to how Feynman presents model/provider setup separately from compute choices. The difference is that grclanker does not stop at a badge. Use `env doctor` and `env smoke-test` to verify the selected backend can actually execute the tool surface you expect.

## What a compute backend controls

The compute backend is where tool execution happens.

- `host`: run directly in the current shell on this machine.
- `sandbox-runtime`: keep the runtime local, but wrap `bash`, `grep`, and `find` in a local sandbox and enforce matching filesystem policy for `read`, `write`, `edit`, and `ls`.
- `docker`: run `bash`, `read`, `write`, `edit`, `ls`, `grep`, and `find` inside a local container with the repo bind-mounted into it.
- `parallels-vm`: deploy a disposable Parallels sandbox from either a dedicated template or a stopped base VM, attach the repo share, and run the same tool surface inside that sandbox via `prlctl exec`.
- `modal`: run each command one-shot inside a Modal container through the `modal shell` CLI, optionally with a GPU.
- `runpod-pod`: copy the repo into a persistent RunPod pod you already own and run the tool surface over SSH.
- `runpod-serverless`: dispatch each command as a job to a RunPod serverless endpoint that runs the grclanker worker contract.
- `vercel-sandbox` and `cloudflare-sandbox`: reserved kinds that fail fast today (see the backend matrix below).

Model/provider settings still decide which LLM answers questions. Compute backend settings decide where code execution and file operations happen.

## Backend matrix

| Kind | Bucket | State | Snapshot / restore | GPU | Workspace staging | Artifact sync-back |
| --- | --- | --- | --- | --- | --- | --- |
| `host` | host | shipped | no | no | in place | in place |
| `sandbox-runtime` | sandboxed | shipped | no | no | in place | in place |
| `docker` | sandboxed | shipped | no | no | bind mount | bind mount |
| `parallels-vm` | sandboxed | shipped | yes (`prlctl snapshot`, `prlctl snapshot-switch`) | no | shared folder | shared folder |
| `modal` | gpu-burst | shipped (CLI) | no | yes | `--add-local` copy per command | not available |
| `runpod-pod` | persistent-remote | shipped | no | yes | `scp` into a per-session directory | `scp` (manual) |
| `runpod-serverless` | gpu-burst | shipped | no | yes | worker image must contain the workspace | artifact paths reported by the worker |
| `vercel-sandbox` | sandboxed | stub | no | no | no | no |
| `cloudflare-sandbox` | sandboxed | stub | no | no | no | no |

`grclanker env list` prints the same matrix for your machine, including which backends are detected right now.

## The ExecutionBackend contract

Every adapter implements one TypeScript interface in `cli/pi/execution-backend.ts`:

```ts
interface ExecutionBackend {
  readonly kind: ExecutionBackendKind;
  readonly capabilities: { snapshot: boolean; restore: boolean; gpu: boolean; stageWorkspace: boolean; artifactSync: boolean; interactive: boolean };
  healthcheck(): Promise<void>;
  stageWorkspace(input: { localPath: string; sessionId: string; mountMode?: "ro" | "rw" }): Promise<{ remotePath: string }>;
  exec(request: ExecutionRequest): Promise<ExecutionResult>;
  snapshot(sessionId: string): Promise<string>;
  restore(sessionId: string, snapshotId: string): Promise<void>;
  teardown(sessionId: string): Promise<void>;
}
```

Adapters that do not support an operation throw a clear "does not support" error instead of pretending. Every adapter takes an injected command runner or `fetch`, which is how the unit tests exercise Docker, Parallels, Modal, and RunPod without touching real binaries or the network.

## Validate the backend

These are the first commands to run after setup:

```bash
grclanker env list
grclanker env doctor
grclanker env smoke-test
grclanker env exec -- pwd
```

`env list` prints every backend kind with its routing bucket (`host`, `sandboxed`, `gpu-burst`, `persistent-remote`), its readiness (`ready`, `not detected`, `needs configuration`, `not available`), and marks the preferred backend. Add `--json` for machine-readable output.

## Pick a backend per run

```bash
grclanker setup --compute docker
grclanker investigate --compute docker
grclanker audit --compute modal
grclanker env smoke-test --compute runpod-serverless
```

`setup --compute <kind>` saves the kind (and its default `computeProfile`) without running the interactive wizard. `investigate --compute` and `audit --compute` override the saved backend for that run only; grclanker passes the override to the in-process Pi extension through `GRCLANKER_COMPUTE_BACKEND_OVERRIDE`. `--compute` is also accepted as an alias for `--backend` on `env exec` and `env smoke-test`.

Useful targeted checks:

```bash
grclanker env smoke-test --backend docker
grclanker env smoke-test --backend sandbox-runtime
grclanker env smoke-test --backend parallels-vm
grclanker env exec --backend docker -- pwd
```

`env doctor` answers "is this backend configured and detectable?"

`env smoke-test` answers "can this backend actually run `bash`, file tools, and backend-native search right now?"

That validation step is not optional once you move beyond `host`.

## settings.json fields

Backend preferences live in:

```text
~/.grclanker/agent/settings.json
```

Example:

```json
{
  "computeBackend": "docker",
  "computeProfile": "isolated-local",
  "computeDefaults": {
    "networkPolicy": "default",
    "workspaceMountMode": "rw"
  },
  "dockerImage": "ubuntu:24.04",
  "dockerWorkspacePath": "/workspace",
  "parallelsSourceKind": "template",
  "parallelsTemplateName": "grclanker-macos-template",
  "parallelsClonePrefix": "grclanker-sandbox",
  "parallelsWorkspacePath": "/media/psf/grclanker-workspace-repo",
  "parallelsAutoStart": true,
  "modalImage": "debian:bookworm-slim",
  "modalGpu": "a10g",
  "runpodWorkspacePath": "/workspace"
}
```

Only the fields for the backend you actually use need to be set.

- `computeProfile`: `local-host`, `isolated-local`, `gpu-burst`, or `persistent-remote`. Each profile maps to one routing bucket; `env list` and `env doctor` warn when the selected backend belongs to a different bucket than the profile. When unset, the profile is derived from the backend.
- `computeDefaults.networkPolicy`: `"default"`, `"deny-all"`, or `{ "allowDomains": [...] }`. Docker honors `deny-all` with `--network none`. `sandbox-runtime` keeps using its own `sandbox.json` allowlist. Remote providers record the policy but cannot enforce it through their documented surfaces yet.
- `computeDefaults.workspaceMountMode`: `"rw"` or `"ro"`. Docker appends `:ro` to the bind mount and Parallels attaches the repo share read-only when set to `ro`.

## Host

`host` is the default and requires no extra configuration.

Use it when:

- you want the fastest local iteration path
- you trust the current repo and commands
- you are still setting up the rest of the environment

Select it in setup:

```bash
grclanker setup
```

Then choose `host` when prompted for the compute backend.

## sandbox-runtime

Use this when you want local execution, but you want filesystem and network policy around the tool surface.

The config merge order is:

- global: `~/.grclanker/sandbox.json`
- project: `<repo>/.grclanker/sandbox.json`

Project config is the right place for repo-specific rules.

Example project config:

```json
{
  "enabled": true,
  "network": {
    "allowedDomains": [
      "github.com",
      "api.github.com",
      "registry.npmjs.org"
    ]
  },
  "filesystem": {
    "allowWrite": [".", "/tmp"],
    "denyRead": ["~/.ssh", "~/.aws", "~/.gnupg"],
    "denyWrite": [".env", ".env.*", "*.pem", "*.key"]
  }
}
```

Notes:

- `bash`, `grep`, and `find` run through the sandbox wrapper.
- `read`, `write`, `edit`, and `ls` are enforced against the same policy locally.
- This is the fastest isolation path when you do not need a full container or VM.

Verify it:

```bash
grclanker env smoke-test --backend sandbox-runtime
```

## Docker

Use Docker when you want an isolated local container with a reproducible image.

The main settings are:

- `dockerImage`: the image to run
- `dockerWorkspacePath`: where the host repo is mounted inside the container

The default documented path is:

```json
{
  "computeBackend": "docker",
  "dockerImage": "ubuntu:24.04",
  "dockerWorkspacePath": "/workspace"
}
```

What grclanker expects:

- Docker Desktop or the Docker daemon is running
- the configured image can run `bash`
- the bind mount path is writeable in the container

The current Docker adapter mounts the repo into the container, sets the container working directory to the matching repo path, and runs with your current uid/gid when available so file ownership does not come back as root-owned on the host.

Examples:

```bash
grclanker env doctor
grclanker env smoke-test --backend docker
grclanker env exec --backend docker -- pwd
```

Expected `pwd` output for the default config:

```text
/workspace
```

Notes:

- grclanker prefers `rg` inside the container when it is available.
- if `rg` is missing, backend search falls back to POSIX `grep` and `find`
- the smoke test validates `bash`, `read`, `write`, `edit`, `ls`, `find`, and `grep`

## Parallels

Use Parallels when you want a full guest OS instead of a container, but you do not want grclanker touching one of your real working VMs directly.

The main settings are:

- `parallelsSourceKind`: `template` or `base-vm`
- `parallelsTemplateName`: the dedicated Parallels template grclanker should deploy sandboxes from
- `parallelsBaseVmName`: the exact stopped base VM grclanker should clone when you use the fallback path
- `parallelsClonePrefix`: prefix used for disposable clone names
- `parallelsWorkspacePath`: optional guest path override if your guest mounts the repo share somewhere custom
- `parallelsAutoStart`: must be `true` so grclanker can boot the fresh clone it just created

The setup flow is intended to reduce guesswork:

- it lists detected templates and VMs separately
- it recommends templates first for Windows, Linux, and macOS sandbox automation
- it lets you choose between `template` and `base-vm`
- it lets you select a template or stopped base by number or exact name
- it saves a disposable clone prefix
- it defaults the guest workspace path to auto-detect instead of forcing you to guess

Example:

```json
{
  "computeBackend": "parallels-vm",
  "parallelsSourceKind": "template",
  "parallelsTemplateName": "grclanker-windows-template",
  "parallelsClonePrefix": "grclanker-sandbox",
  "parallelsWorkspacePath": "/media/psf/grclanker-workspace-repo",
  "parallelsAutoStart": true
}
```

How the disposable sandbox path works:

1. grclanker deploys a fresh disposable sandbox from the configured source.
2. If `parallelsSourceKind=template`, it uses `prlctl create <sandbox> --ostemplate <template>`.
3. If `parallelsSourceKind=base-vm`, it clones a stopped base VM as a fallback path.
4. It disables default host sharing on that sandbox, attaches only the current repo as a named shared folder, and boots the sandbox.
5. It auto-detects the guest-visible mount path for that repo share unless you set `parallelsWorkspacePath`.
6. It runs `bash`, `read`, `write`, `edit`, `ls`, `grep`, and `find` inside the sandbox.
7. It deletes the sandbox on shutdown or after one-off `env exec` / `env smoke-test` runs.

That is safer than the older direct-VM model because grclanker never executes inside the template or base image itself.

Recommended guest strategy:

- Windows: use a dedicated Parallels template with Parallels Tools and guest login automation already working, but note that grclanker’s current in-guest tool adapter still assumes a POSIX shell. Windows-native command support is not complete yet.
- Linux: use a dedicated Parallels template with Parallels Tools and shell access working.
- macOS: use a dedicated Parallels template if `prlctl exec` works reliably in that guest. If it does not, expect more friction than Windows/Linux and validate with `env smoke-test` before trusting it.

Examples:

```bash
grclanker env doctor
grclanker env smoke-test --backend parallels-vm
grclanker env exec --backend parallels-vm -- pwd
```

Parallels is the right option when you want stronger isolation than Docker, or when the target environment needs to look like a full workstation or guest OS, but you still want the session to be disposable.

Snapshot and rollback are available through the contract (`prlctl snapshot <clone> --name <name>` and `prlctl snapshot-switch <clone> --id <id>`). The adapter only rolls back to snapshots it created in the same session, and it still deletes the disposable clone on teardown.

## Modal

State: shipped through the `modal` CLI. Modal exposes Sandbox lifecycle through its Python and JavaScript SDKs, so grclanker drives the documented CLI surface instead of adding an SDK dependency.

Credentials: `MODAL_TOKEN_ID` and `MODAL_TOKEN_SECRET` (optionally `MODAL_ENVIRONMENT` and `MODAL_PROFILE`), as documented at [modal.com/docs/reference/modal.config](https://modal.com/docs/reference/modal.config). Run `modal setup` or `modal token set` once, or export the variables.

Setup:

```bash
pip install modal
export MODAL_TOKEN_ID=... MODAL_TOKEN_SECRET=...
grclanker setup --compute modal
grclanker env smoke-test --backend modal
```

What runs where: each `bash`, `read`, `write`, `edit`, `ls`, `grep`, and `find` call becomes one `modal shell --no-pty --image <modalImage> --add-local <repo> [--gpu <modalGpu>] --cmd "<command>"` invocation, following the flags documented at [modal.com/docs/reference/cli/shell](https://modal.com/docs/reference/cli/shell). The repo is copied into the container at `/mnt/<repo-name>` for every command.

Limits:

- Every command starts a fresh container, so state does not persist between commands and file writes are not synced back to the host. Treat Modal as a read-mostly burst lane (analyzers, inference, validation) rather than a place to edit the repo.
- Snapshots are not exposed through the CLI, so `snapshot` and `restore` report "not supported".
- Settings: `modalImage` (default `debian:bookworm-slim`), `modalGpu` (for example `a10g` or `a100:4`).

## RunPod Serverless

State: shipped against the documented queue-based endpoint API.

Credentials: `RUNPOD_API_KEY` and `RUNPOD_ENDPOINT_ID`.

Requests, in order, with every field taken from [Send API requests](https://docs.runpod.io/serverless/endpoints/send-requests) and the [operation reference](https://docs.runpod.io/serverless/endpoints/operation-reference):

- `GET https://api.runpod.ai/v2/{endpointId}/health` for `env doctor` style health checks.
- `POST https://api.runpod.ai/v2/{endpointId}/run` with `{ "input": { "command", "cwd", "env" }, "policy": { "executionTimeout" } }`. The `authorization: Bearer <RUNPOD_API_KEY>` header follows the documented example.
- `GET https://api.runpod.ai/v2/{endpointId}/status/{id}` polled until `status` leaves `IN_QUEUE` / `IN_PROGRESS`.
- `POST https://api.runpod.ai/v2/{endpointId}/cancel/{id}` if grclanker aborts or times out while waiting.

Worker contract: RunPod documents that `input` is defined by your worker, so grclanker defines a small one. Your handler receives `input.command`, `input.cwd`, and `input.env`, runs the command with `bash -lc`, and returns `{ "exitCode": number, "stdout": string, "stderr": string, "artifacts": string[] }` as the job `output`. The worker image must already contain the workspace at `runpodWorkspacePath` (default `/workspace`); serverless jobs cannot receive files.

Limits: no workspace upload, no snapshots, and artifact sync-back is limited to the paths the worker reports. Results expire after 30 minutes per the RunPod docs.

## RunPod Pod

State: shipped for pods you already created. grclanker never creates, stops, or deletes pods; it only reads pod metadata and works inside a per-session directory that it removes on teardown.

Credentials: `RUNPOD_API_KEY` and `RUNPOD_POD_ID`, plus an SSH key that the pod accepts and a local `ssh`/`scp` client.

Requests: `GET https://rest.runpod.io/v1/pods/{podId}` with `Authorization: Bearer <RUNPOD_API_KEY>`, reading `desiredStatus`, `publicIp`, and `portMappings["22"]` as documented at [Find a Pod by ID](https://docs.runpod.io/api-reference/pods/GET/pods/podId). RunPod marks REST API v1 as deprecated with retirement on 2026-11-15 ([API overview](https://docs.runpod.io/api-reference/overview)); the base URL lives in one constant so the v2 move is a one-line change.

What runs where: `stageWorkspace` runs `scp -r <repo>/. root@<publicIp>:<runpodWorkspacePath>/<sessionId>`, every command runs as `ssh -p <port> root@<publicIp> "cd -- <cwd> && <command>"`, and teardown removes the session directory. The pod must expose TCP port 22 publicly.

Limits: no snapshots through the API, and sync-back means copying the session directory back with `scp` yourself.

## Vercel Sandbox and Cloudflare Sandbox

State: stubs. Both kinds exist in settings and `env list`, but selecting them fails fast:

- Vercel Sandbox is exposed through the `@vercel/sandbox` SDK and the Vercel CLI ([vercel.com/docs/vercel-sandbox](https://vercel.com/docs/vercel-sandbox)). grclanker does not add that dependency yet.
- Cloudflare Sandbox is exposed through the `@cloudflare/sandbox` Workers SDK running inside a deployed Worker ([developers.cloudflare.com/sandbox](https://developers.cloudflare.com/sandbox/)). There is no public HTTP lifecycle API for a CLI to call directly.

`env list` reports both as `not available`.

## Live smoke

```bash
npm --prefix cli run test:compute-backends:live
```

The script runs `env doctor`, then `env smoke-test --backend <kind>` for every non-host backend whose binaries or credentials are present (Docker daemon, `prlctl`, `modal` with `MODAL_TOKEN_*`, `RUNPOD_API_KEY` with `RUNPOD_ENDPOINT_ID` or `RUNPOD_POD_ID`). It exits 0 with a skip message when nothing is available. Set `GRCLANKER_LIVE_BACKENDS=docker,modal` to restrict the run, or include `sandbox-runtime` to exercise the local sandbox.

## Choose the right backend

Use `host` when you want speed.

Use `sandbox-runtime` when you want local-first execution with policy.

Use `docker` when you want reproducible container isolation and easy reset.

Use `parallels-vm` when you want a full guest OS and coarse-grained isolation without risking one of your existing VMs.

Use `modal` or `runpod-serverless` when a step needs a GPU or more compute than the laptop has and does not need to write back into the repo.

Use `runpod-pod` when you want a persistent remote workstation with SSH that you can inspect and repair by hand.

## Troubleshooting

- If `env doctor` says Docker is unavailable, make sure the daemon is actually running, not just the CLI.
- If `env smoke-test --backend docker` fails immediately, check the image name and confirm the image can run `bash`.
- If Parallels fails before sandbox creation, confirm either `parallelsTemplateName` exists in `prlctl list -a -t` or `parallelsBaseVmName` points at a stopped VM, and confirm `parallelsAutoStart` is `true`.
- If Parallels fails after the sandbox starts, confirm the template/base image has Parallels Tools plus `prlctl exec` guest access working, and set `parallelsWorkspacePath` if your guest does not mount shared folders at one of the common auto-detected paths.
- If `sandbox-runtime` blocks something unexpectedly, inspect both `~/.grclanker/sandbox.json` and `<repo>/.grclanker/sandbox.json`.
- If you want to switch back to a simpler path, rerun `grclanker setup` and choose `host`.

## Recommended operator flow

1. Run `grclanker setup`.
2. Pick the model/provider path you want.
3. Pick the compute backend you want.
4. Run `grclanker env doctor`.
5. Run `grclanker env smoke-test`.
6. Only then start relying on that backend for normal work.
