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

| Kind | Bucket | State | Runtime path | Snapshot / restore | GPU | Workspace staging | Artifact sync-back |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `host` | host | shipped | Pi's native local shell operations wrapped in the output redaction guard (the `createHostBackend` contract adapter is exercised by tests and `env list` only) | no | no | in place | in place |
| `sandbox-runtime` | sandboxed | shipped | contract adapter for bash, grep, and find; file tools stay local with the same FS policy | no | no | in place | in place |
| `docker` | sandboxed | shipped | contract adapter (`docker run` args unchanged from phase 1) | no | no | bind mount | bind mount |
| `parallels-vm` | sandboxed | shipped | contract adapter (disposable clone, `prlctl exec`) | yes (`prlctl snapshot`, `prlctl snapshot-switch`), exercised by `env smoke-test` | no | shared folder | shared folder |
| `modal` | gpu-burst | shipped (CLI) | contract adapter over `modal shell` | no | yes | `--add-local` copy per command | not available |
| `runpod-pod` | persistent-remote | shipped | contract adapter over the REST API plus `ssh`/`scp` | no | yes | `scp` into a per-session directory | `scp` (manual) |
| `runpod-serverless` | gpu-burst | shipped | contract adapter over the serverless HTTP API | no | yes | worker image must contain the workspace | artifact paths reported by the worker |
| `vercel-sandbox` | sandboxed | stub | fails fast | no | no | no | no |
| `cloudflare-sandbox` | sandboxed | stub | fails fast | no | no | no | no |

`grclanker env list` prints the same matrix for your machine, including which backends are detected right now.

### Session lifecycle and teardown

Every backend except `host` stages a session lazily on the first command and owns a teardown. `grclanker env smoke-test` and `grclanker env exec` await that teardown in a `finally` block, on success and on failure, so a RunPod pod session directory or a Parallels clone is removed before the command returns. The interactive agent session tears every active backend session down on `session_shutdown` through `shutdownComputeSessions`, regardless of which backend `settings.json` prefers, so a run started with a per-run `--compute runpod-pod` override is cleaned up even when the saved preference is `host` (the sandbox-runtime reset still runs only when that backend is preferred). As a last resort, a synchronous `process.on("exit")` hook runs each adapter's `teardownSync` (a blocking `ssh rm -rf` for RunPod pods, `prlctl stop --kill` and `prlctl delete` for Parallels); Node cannot await asynchronous work in exit handlers, so this hook is only a fallback for hard exits, not the primary cleanup path.

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

### Credential hygiene in output

Command output is untrusted text: a container, VM, worker, or pod can echo its own environment, and the host shell inherits yours. Every adapter therefore routes its output through one redaction guard before anything is streamed, returned, printed, or persisted:

- Exact values of `RUNPOD_API_KEY`, `MODAL_TOKEN_ID`, `MODAL_TOKEN_SECRET`, `VERCEL_TOKEN`, and `CLOUDFLARE_API_TOKEN` from your environment are replaced with `[REDACTED]`.
- Format-based patterns catch the same credentials when they arrive from the remote without being set locally: `Bearer <token>` headers, RunPod keys (`rpa_...`), Modal token ids and secrets (`ak-...`, `as-...`), `NAME=value` assignments of those variables (quoted or not), and PEM private key blocks (`-----BEGIN ... PRIVATE KEY-----` through `-----END ...-----`, replaced with `[REDACTED PRIVATE KEY]`).
- Generic shapes that carry credentials without announcing a provider: in any `scheme://...` URL, the userinfo, every query value, and the fragment are replaced (`https://x/callback?access_token=[REDACTED]&state=[REDACTED]`; the path and parameter names stay so the URL is still recognizable, and a URL without a query is untouched); `Cookie:` and `Set-Cookie:` header values; and credential-named fields in header, assignment, or JSON form (`X-Api-Key: v`, `session_id=v`, `"token": "v"`, also `api_key`, `access_token`, `refresh_token`, `client_secret`, `password`, `sid`, `signature`, and similar names) with values of four or more characters. Query values are redacted regardless of name because a session token does not label itself, so a `curl -v` of a URL with a harmless query also shows `[REDACTED]` values in bash output.
- Streamed output is scrubbed per completed line, so a credential split across two chunks is still caught; the trailing partial line is held until the next newline or the end of the command. The stream is the only channel the bash tool and `env exec` surface, so the sink also refuses to flush through an open PEM block: from a `-----BEGIN ... PRIVATE KEY-----` marker onward, output is held until the matching `END` marker arrives, which is what stops a line-at-a-time producer (a tty-attached `docker exec -t`, a script that flushes per line, a slow remote) from leaking the header and body one line at a time. A line that ends in `Bearer` is held for the token on the next line for the same reason. A block whose `END` never arrives (a truncated key file, a command killed by its timeout mid-key, or a held buffer that reaches the 256 KiB cap) is flushed at that point with the `BEGIN` marker and the contiguous run of body-shaped lines after it (base64, 16 or more characters, plus a trailing base64 fragment cut off by the end of the output) replaced by `[REDACTED PRIVATE KEY: unterminated block, body withheld]` (or `[REDACTED PRIVATE KEY: unterminated block]` when nothing followed the marker). The replacement names the withholding because that truncation would otherwise be invisible in the stream. Ordinary output after the body survives: a short line such as `ok` or a log line is not body shaped and ends the run, so `cat` of a truncated key followed by `done` streams as `[REDACTED PRIVATE KEY: unterminated block, body withheld]` then `done`. The cap exists so a never-closed block cannot pin memory; a block still open at 256 KiB is not a real key (those are a few KB), and only its body-shaped lines are withheld.
- Error messages have their own choke point. Thrown errors do not pass through the output guard (the bash tool rethrows them to the agent, `env exec` prints them), so every `ExecutionBackendError` scrubs its message in its constructor with `redactErrorMessage`: the same values and patterns as command output, plus an HTML document anywhere in the message is replaced wholesale with `[HTML document withheld (N chars)]`, and a truncated PEM block is neutralized. Every adapter error (`prlctl`, `ssh`, and `scp` stderr quoted into a failure, the file tools' failing remote command, RunPod job errors) is constructed through it, and `env exec` applies it again to whatever it re-throws.
- A provider body that is not JSON is never quoted into an error message at all. RunPod responses go through one `readJson` that reports a non-JSON body (a gateway's 502 page, a login page returned with HTTP 200) as `failed with HTTP 502 from api.runpod.ai/v2/<endpoint>/health: non-JSON text/html body (166 bytes) withheld`, so the message carries status, endpoint, content type, and length and nothing from the page. A 200 with a non-JSON body becomes the same kind of typed error instead of a raw `SyntaxError` quoting body characters. A JSON error body contributes only its message-bearing fields (`error`, `message`, `detail`, `reason`, and similar), scrubbed by the constructor; other fields are named, never serialized (`JSON body with keys upstream, session`). A `FAILED` job's `error` is summarized the same way.
- `env exec` scrubs the command line it echoes.

This covers `env smoke-test`, `env exec`, the agent's bash tool on every backend including `host`, the RunPod serverless worker output that `/status` returns, and every error the adapters throw. `env list` and `env doctor` print variable names only, never values. Session records in `compute-sessions.ts` hold teardown handles, not credentials.

File operations are the one deliberate exception: `read`, `edit`, `write`, `ls`, `grep`, and `find` on a non-host backend fetch file content through the same adapter with `redactOutput: false`. The reason is the edit round trip: Pi's edit tool reads a file and writes it back, and a redaction marker must never be written into a file. `grep`, `find`, and `ls` never write anything back, but they inherit the exception so file content reads the same whether it reaches the model through `read`, a grep match, a directory listing, or a find result. Their failure text is still scrubbed.

### Deadlines and caps are never reported as success

Every loop in the backends that can stop early says why:

- The RunPod serverless status poll raises `ExecutionBackendTimeoutError` (`runpod-serverless timed out after Ns: ...`) when its deadline passes, after cancelling the job; an aborted request raises an explicit `aborted` error; any terminal status other than `COMPLETED` (`FAILED`, `CANCELLED`, `TIMED_OUT`) raises with that status.
- The Parallels mount wait raises `ExecutionBackendTimeoutError` (`parallels-vm timed out after Ns: could not locate the repo share ... before the mount deadline. Tried: ...`) and destroys the clone it created.
- Backend `grep` returns `matchLimitReached: true` when more matches exist than the limit, and backend `find` returns exactly the limit so Pi's find tool prints its results-limit warning.

The adapters never call the RunPod pod or endpoint list APIs or `prlctl snapshot-list`, so there is no paginated listing that could stop on a missing total. `env list` enumerates every kind.

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
- `computeDefaults.workspaceMountMode`: `"rw"` or `"ro"`. Docker appends `:ro` to the bind mount and Parallels passes `--mode ro` when it attaches the repo share (`prlctl set <clone> --shf-host-add <share> --path <repo> --mode ro`). Both paths read the same setting, so a read-only workspace means write, edit, and the smoke test's write probe fail inside the sandbox by design.

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

Snapshot and rollback run through the contract adapter (`prlctl snapshot <clone> --name <name>` and `prlctl snapshot-switch <clone> --id {<uuid>}`). The adapter never synthesizes a snapshot id: it round-trips the id that `prlctl snapshot` printed back into `snapshot-switch --id` verbatim, accepting both the braced form seen in practice and a bare uuid (the Parallels command-line reference documents the flag without showing a concrete id form), and it only rolls back to snapshots it created in the same session. `grclanker env smoke-test --backend parallels-vm` is the CLI surface that exercises this path today: it snapshots the fresh clone after the bash probe, runs the tool probes, restores the snapshot, and reports `snapshot=ok` and `restore=ok`. The agent session does not yet snapshot per tool call; it still deletes the disposable clone on teardown.

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

What runs where: each `bash`, `read`, `write`, `edit`, `ls`, `grep`, and `find` call becomes one `modal shell --no-pty --image <modalImage> --add-local <repo> [--gpu <modalGpu>] --cmd "<wrapper>"` invocation, following the flags documented at [modal.com/docs/reference/cli/shell](https://modal.com/docs/reference/cli/shell). The repo is copied into the container at `/mnt/<repo-name>` for every command.

Command quoting: the modal client runs `shlex.split(f'/bin/bash -c "{cmd}"')` on the `--cmd` value, so a raw command containing double quotes would be re-split. grclanker therefore never passes the command itself; it passes a wrapper made only of characters shlex leaves alone (`f=$(mktemp) && printf %s <base64> | base64 -d > $f && bash $f; s=$?; rm -f $f; exit $s`). The real command travels as base64, is decoded into a temp file inside the container, runs with its own stdin, and its exit status is preserved.

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
- `GET https://api.runpod.ai/v2/{endpointId}/status/{id}` polled every 2 seconds until `status` leaves `IN_QUEUE` / `IN_PROGRESS`.
- `POST https://api.runpod.ai/v2/{endpointId}/cancel/{id}` if grclanker aborts or times out while waiting.

Polling deadline: the loop always has a ceiling. It uses the tool's timeout when one is given, otherwise 600000 ms, which is the default `executionTimeout` RunPod documents for serverless jobs, plus a 60 second grace window so the endpoint can report `TIMED_OUT` itself first. When the deadline passes, the adapter cancels the job and raises an `ExecutionBackendTimeoutError` (message `runpod-serverless timed out after 600s: ...`).

Worker contract: RunPod documents that `input` is defined by your worker, so grclanker defines a small one. Your handler receives `input.command`, `input.cwd`, and `input.env`, runs the command with `bash -lc`, and returns `{ "exitCode": number, "stdout": string, "stderr": string, "artifacts": string[] }` as the job `output`. The worker image must already contain the workspace at `runpodWorkspacePath` (default `/workspace`); serverless jobs cannot receive files.

Limits: no workspace upload, no snapshots, and artifact sync-back is limited to the paths the worker reports. Results expire after 30 minutes per the RunPod docs.

## RunPod Pod

State: shipped for pods you already created. grclanker never creates, stops, or deletes pods; it only reads pod metadata and works inside a per-session directory that it removes on teardown.

Credentials: `RUNPOD_API_KEY` and `RUNPOD_POD_ID`, plus an SSH key that the pod accepts and a local `ssh`/`scp` client.

Requests: `GET https://rest.runpod.io/v1/pods/{podId}` with `Authorization: Bearer <RUNPOD_API_KEY>`, reading `desiredStatus`, `publicIp`, and `portMappings["22"]` as documented at [Find a Pod by ID](https://docs.runpod.io/api-reference/pods/GET/pods/podId). RunPod marks REST API v1 as deprecated with retirement on 2026-11-15 ([API overview](https://docs.runpod.io/api-reference/overview)); the base URL lives in one constant so the v2 move is a one-line change.

What runs where: `stageWorkspace` runs `ssh ... mkdir -p -- <runpodWorkspacePath>/<sessionId>` followed by `scp -r <repo>/. root@<publicIp>:<runpodWorkspacePath>/<sessionId>`; if the copy fails, the adapter removes the directory it just created before raising. Every command runs as `ssh -p <port> root@<publicIp> "cd -- <cwd> && <command>"`, and teardown removes the session directory (`rm -rf -- <runpodWorkspacePath>/<sessionId>`). Session ids are validated at the adapter boundary (letters, digits, `.`, `_`, `-`, no `..`), so no caller can turn the removal into a traversal. The pod must expose TCP port 22 publicly.

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
