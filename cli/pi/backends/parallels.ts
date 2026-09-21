import { randomBytes } from "node:crypto";
import { basename, resolve } from "node:path";
import {
  buildShellCommand,
  createProcessCommandRunner,
  createProcessCommandRunnerSync,
  ExecutionBackendError,
  normalizeExitCode,
  type CommandRunner,
  type CommandRunnerResult,
  type CommandRunnerSync,
  type ExecutionBackend,
  type ExecutionRequest,
  type ExecutionResult,
  type StagedWorkspace,
  type StageWorkspaceInput,
  type WorkspaceMountMode,
} from "../execution-backend.js";
import { quoteForBash } from "../shell.js";

export type ParallelsBackendOptions = {
  sourceKind: "template" | "base-vm";
  sourceName: string;
  clonePrefix: string;
  workspacePathOverride?: string;
  mountMode?: WorkspaceMountMode;
  runner?: CommandRunner;
  syncRunner?: CommandRunnerSync;
  sleep?: (milliseconds: number) => Promise<void>;
  mountTimeoutMs?: number;
};

type ParallelsSession = {
  cloneName: string;
  shareName: string;
  workspacePath?: string;
  snapshots: string[];
};

const GUEST_MOUNT_CANDIDATES = [
  (share: string) => `/media/psf/${share}`,
  (share: string) => `/mnt/psf/${share}`,
  (share: string) => `/Volumes/${share}`,
  (share: string) => `/Volumes/psf/${share}`,
] as const;

function sanitizeToken(value: string): string {
  return value
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 40) || "sandbox";
}

function formatFailure(action: string, result: CommandRunnerResult): ExecutionBackendError {
  const detail = [result.stdout, result.stderr].filter(Boolean).join("\n").trim();
  return new ExecutionBackendError(`${action}. ${detail || "Check Parallels Desktop and the guest configuration."}`);
}

// prlctl prints and accepts snapshot ids in braced form ({uuid}); `prlctl snapshot-list` output
// and the `snapshot-switch <vm> --id <snapshot_id>` examples in the Parallels Desktop
// command-line reference both use the braces, so the id is kept verbatim.
export function parseParallelsSnapshotId(output: string): string | undefined {
  const match = /\{[0-9a-fA-F-]{8,}\}/.exec(output);
  return match?.[0];
}

export function buildParallelsExecArgs(cloneName: string, cwd: string, command: string): string[] {
  return ["exec", cloneName, "--current-user", "bash", "-lc", `cd -- ${quoteForBash(cwd)} && ${command}`];
}

export function buildParallelsShareArgs(
  cloneName: string,
  shareName: string,
  localRoot: string,
  mountMode: WorkspaceMountMode,
): string[] {
  return ["set", cloneName, "--shf-host-add", shareName, "--path", localRoot, "--mode", mountMode];
}

export function buildParallelsDestroyArgs(cloneName: string): string[][] {
  return [
    ["stop", cloneName, "--kill"],
    ["delete", cloneName],
  ];
}

export function createParallelsBackend(options: ParallelsBackendOptions): ExecutionBackend {
  const runner = options.runner ?? createProcessCommandRunner();
  const syncRunner = options.syncRunner ?? createProcessCommandRunnerSync();
  const sleep = options.sleep ?? ((milliseconds: number) => new Promise<void>((done) => setTimeout(done, milliseconds)));
  const sessions = new Map<string, ParallelsSession>();

  function requireSession(sessionId: string): ParallelsSession {
    const session = sessions.get(sessionId);
    if (!session?.workspacePath) {
      throw new ExecutionBackendError(`Session ${sessionId} has no staged Parallels sandbox. Call stageWorkspace first.`);
    }
    return session;
  }

  async function prlctl(args: string[]): Promise<CommandRunnerResult> {
    return runner("prlctl", args);
  }

  async function waitForMount(cloneName: string, candidates: string[]): Promise<string> {
    const deadline = Date.now() + (options.mountTimeoutMs ?? 45_000);
    do {
      for (const candidate of candidates) {
        const check = await prlctl([
          "exec",
          cloneName,
          "--current-user",
          "bash",
          "-lc",
          `if test -d ${quoteForBash(candidate)}; then printf ok; else printf missing; fi`,
        ]);
        if (check.exitCode === 0 && check.stdout.trim() === "ok") return candidate;
      }
      await sleep(1_500);
    } while (Date.now() < deadline);

    throw new ExecutionBackendError(
      `Could not locate the repo share inside Parallels clone "${cloneName}". Tried: ${candidates.join(", ")}. Set parallelsWorkspacePath if the guest mounts host shares elsewhere.`,
    );
  }

  async function destroyClone(cloneName: string): Promise<void> {
    for (const args of buildParallelsDestroyArgs(cloneName)) {
      await prlctl(args);
    }
  }

  return {
    kind: "parallels-vm",
    capabilities: {
      snapshot: true,
      restore: true,
      gpu: false,
      stageWorkspace: true,
      artifactSync: true,
      interactive: false,
    },
    async healthcheck() {
      const result = await prlctl(["list", "-a", "--json"]);
      if (result.exitCode !== 0) {
        throw new ExecutionBackendError("`prlctl list -a --json` failed. Install Parallels Desktop and confirm prlctl works.");
      }
    },
    async stageWorkspace(input: StageWorkspaceInput): Promise<StagedWorkspace> {
      const localRoot = resolve(input.localPath);
      const repoToken = sanitizeToken(basename(localRoot));
      const cloneName = `${sanitizeToken(options.clonePrefix)}-${repoToken}-${Date.now()}-${randomBytes(3).toString("hex")}`;
      const shareName = sanitizeToken(`grclanker-workspace-${repoToken}`);
      const session: ParallelsSession = { cloneName, shareName, snapshots: [] };

      const create = options.sourceKind === "template"
        ? await prlctl(["create", cloneName, "--ostemplate", options.sourceName])
        : await prlctl(["clone", options.sourceName, "--name", cloneName]);
      if (create.exitCode !== 0) {
        throw formatFailure(`Could not create disposable Parallels sandbox "${cloneName}" from ${options.sourceKind} "${options.sourceName}"`, create);
      }
      sessions.set(input.sessionId, session);

      try {
        const sharing = await prlctl(["set", cloneName, "--shf-host", "on", "--shf-host-defined", "off", "--shf-host-automount", "on"]);
        if (sharing.exitCode !== 0) throw formatFailure(`Could not configure host folder sharing for "${cloneName}"`, sharing);
        const share = await prlctl(
          buildParallelsShareArgs(cloneName, shareName, localRoot, input.mountMode ?? options.mountMode ?? "rw"),
        );
        if (share.exitCode !== 0) throw formatFailure(`Could not attach repo share "${shareName}" to "${cloneName}"`, share);
        await prlctl(["set", cloneName, "--smart-mount", "off"]);
        await prlctl(["set", cloneName, "--shared-clipboard", "off", "--shared-cloud", "off"]);
        const start = await prlctl(["start", cloneName]);
        if (start.exitCode !== 0) throw formatFailure(`Could not start disposable Parallels sandbox "${cloneName}"`, start);

        const candidates = [
          options.workspacePathOverride,
          ...GUEST_MOUNT_CANDIDATES.map((candidate) => candidate(shareName)),
        ].filter((candidate): candidate is string => Boolean(candidate));
        session.workspacePath = await waitForMount(cloneName, [...new Set(candidates)]);
        return {
          sessionId: input.sessionId,
          remotePath: session.workspacePath,
          detail: `disposable clone ${cloneName} with repo share ${shareName}`,
        };
      } catch (error) {
        await destroyClone(cloneName);
        sessions.delete(input.sessionId);
        throw error;
      }
    },
    async exec(request: ExecutionRequest): Promise<ExecutionResult> {
      const session = requireSession(request.sessionId);
      const result = await runner(
        "prlctl",
        buildParallelsExecArgs(session.cloneName, request.cwd, buildShellCommand(request.command)),
        { timeoutMs: request.timeoutMs, onData: request.onData, signal: request.signal },
      );
      return {
        exitCode: normalizeExitCode(result.exitCode),
        stdout: result.stdout,
        stderr: result.stderr,
        artifacts: [],
      };
    },
    async snapshot(sessionId: string): Promise<string> {
      const session = requireSession(sessionId);
      const name = `grclanker-${Date.now()}`;
      const result = await prlctl(["snapshot", session.cloneName, "--name", name]);
      if (result.exitCode !== 0) throw formatFailure(`Could not snapshot Parallels sandbox "${session.cloneName}"`, result);
      const snapshotId = parseParallelsSnapshotId(`${result.stdout}\n${result.stderr}`) ?? name;
      session.snapshots.push(snapshotId);
      return snapshotId;
    },
    async restore(sessionId: string, snapshotId: string): Promise<void> {
      const session = requireSession(sessionId);
      if (!session.snapshots.includes(snapshotId)) {
        throw new ExecutionBackendError(`Snapshot ${snapshotId} was not created by this session; refusing to roll back to it.`);
      }
      const result = await prlctl(["snapshot-switch", session.cloneName, "--id", snapshotId]);
      if (result.exitCode !== 0) throw formatFailure(`Could not roll back Parallels sandbox "${session.cloneName}" to ${snapshotId}`, result);
    },
    async teardown(sessionId: string): Promise<void> {
      const session = sessions.get(sessionId);
      if (!session) return;
      try {
        await destroyClone(session.cloneName);
      } finally {
        sessions.delete(sessionId);
      }
    },
    teardownSync(sessionId: string): void {
      const session = sessions.get(sessionId);
      if (!session) return;
      sessions.delete(sessionId);
      for (const args of buildParallelsDestroyArgs(session.cloneName)) {
        syncRunner("prlctl", args);
      }
    },
  };
}
