---
title: Compute Backends
description: Configure host, sandbox-runtime, Docker, or Parallels execution for grclanker and validate each backend with env doctor and smoke-test.
---

grclanker separates model choice from execution environment on purpose.

That part is similar to how Feynman presents model/provider setup separately from compute choices. The difference is that grclanker does not stop at a badge. Use `env doctor` and `env smoke-test` to verify the selected backend can actually execute the tool surface you expect.

## What a compute backend controls

The compute backend is where tool execution happens.

- `host`: run directly in the current shell on this machine.
- `sandbox-runtime`: keep the runtime local, but wrap `bash`, `grep`, and `find` in a local sandbox and enforce matching filesystem policy for `read`, `write`, `edit`, and `ls`.
- `docker`: run `bash`, `read`, `write`, `edit`, `ls`, `grep`, and `find` inside a local container with the repo bind-mounted into it.
- `parallels-vm`: deploy a disposable Parallels sandbox from either a dedicated template or a stopped base VM, attach the repo share, and run the same tool surface inside that sandbox via `prlctl exec`.

Model/provider settings still decide which LLM answers questions. Compute backend settings decide where code execution and file operations happen.

## Validate the backend

These are the first commands to run after setup:

```bash
grclanker env doctor
grclanker env smoke-test
grclanker env exec -- pwd
```

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
  "dockerImage": "ubuntu:24.04",
  "dockerWorkspacePath": "/workspace",
  "parallelsSourceKind": "template",
  "parallelsTemplateName": "grclanker-macos-template",
  "parallelsClonePrefix": "grclanker-sandbox",
  "parallelsWorkspacePath": "/media/psf/grclanker-workspace-repo",
  "parallelsAutoStart": true
}
```

Only the fields for the backend you actually use need to be set.

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

## Choose the right backend

Use `host` when you want speed.

Use `sandbox-runtime` when you want local-first execution with policy.

Use `docker` when you want reproducible container isolation and easy reset.

Use `parallels-vm` when you want a full guest OS and coarse-grained isolation without risking one of your existing VMs.

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
