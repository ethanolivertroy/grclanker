import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  COMPUTE_BACKEND_KINDS,
  getComputeBackendConfigurationIssues,
  getComputeBackendCredentialState,
  getComputeBackendSurfaceLabel,
  getComputeProfileIssues,
  getDefaultComputeProfile,
  getRoutingBucket,
  normalizeComputeBackend,
  normalizeComputeDefaults,
  parseComputeBackendKind,
  resolveComputeProfile,
} from "../dist/pi/compute.js";
import {
  buildComputeBackendSystemPromptNote,
  buildDockerToolRunArgs,
  resolveComputeBackendExecution,
  withComputeBackendExecution,
} from "../dist/pi/backend-exec.js";
import { buildDockerRunArgs, createDockerBackend } from "../dist/pi/backends/docker.js";
import { createExecutionBackend } from "../dist/pi/backends/index.js";
import {
  buildModalCommandWrapper,
  buildModalShellArgs,
  createModalBackend,
  decodeModalCommandWrapper,
} from "../dist/pi/backends/modal.js";
import {
  describeModalCredentialSource,
  detectModalCredentials,
  MODAL_CONFIG_FILE_NAME,
  parseModalProfileText,
  resolveModalConfigPath,
} from "../dist/pi/backends/modal-profile.js";
import {
  buildParallelsShareArgs,
  createParallelsBackend,
  parseParallelsSnapshotId,
} from "../dist/pi/backends/parallels.js";
import {
  buildPodSessionPath,
  buildPodSshArgs,
  createRunpodPodBackend,
  createRunpodServerlessBackend,
  DEFAULT_RUNPOD_JOB_TIMEOUT_MS,
  isSensitiveStagingPath,
  parseRunpodWorkerOutput,
  planPodWorkspaceStaging,
  RUNPOD_CLEANUP_ATTEMPTS,
  RUNPOD_STAGING_DENYLIST,
} from "../dist/pi/backends/runpod.js";
import { activeComputeSessionCount } from "../dist/pi/compute-sessions.js";
import { shutdownComputeSessions } from "../dist/pi/compute-shutdown.js";
import {
  buildComputeBackendList,
  extractComputeFlag,
  formatComputeBackendList,
  ONE_SHOT_SMOKE_NOTE,
  runBackendSearchSmokeTest,
  runBackendToolSmokeTest,
} from "../dist/pi/env.js";
import { createHostBackend, createSandboxRuntimeBackend } from "../dist/pi/backends/local.js";
import {
  assertSafeSessionId,
  createExecutionOutputGuard,
  createProcessCommandRunner,
  createRedactingSink,
  describeEndpoint,
  ExecutionBackendCleanupError,
  ExecutionBackendError,
  ExecutionBackendTimeoutError,
  REDACTING_SINK_MAX_HELD_CHARS,
  redactErrorMessage,
  redactExecutionResult,
  redactSecrets,
  redactUnterminatedPemBlocks,
  summarizeJsonBody,
} from "../dist/pi/execution-backend.js";
import { normalizeGrclankerSettings, readGrclankerSettings } from "../dist/pi/settings.js";
import { quoteForBash } from "../dist/pi/shell.js";

const RUNPOD_POD_JSON = JSON.stringify({
  id: "pod42",
  desiredStatus: "RUNNING",
  publicIp: "203.0.113.10",
  portMappings: { "22": 22022 },
});

// A profile path that never exists, so a real ~/.modal.toml on the test host cannot change
// what the "no Modal credentials" cases observe.
const MISSING_MODAL_CONFIG_PATH = join(tmpdir(), "grclanker-no-modal-profile-3f9c1a", ".modal.toml");

// This repository's own ignore rules, copied into the temp repos so the planted secrets are
// ignored files that were force-added, exactly the case the deny list exists for.
const REPO_GITIGNORE = join(dirname(fileURLToPath(import.meta.url)), "..", "..", ".gitignore");

function createFakeRunner(handler) {
  const calls = [];
  const runner = async (executable, args, options = {}) => {
    calls.push({ executable, args, options });
    const result = { exitCode: 0, stdout: "", stderr: "", ...(await handler(executable, args, options)) };
    if (options.onData && result.stdout) options.onData(Buffer.from(result.stdout, "utf8"));
    return result;
  };
  return { runner, calls };
}

function withEnv(values, fn) {
  const previous = {};
  for (const [key, value] of Object.entries(values)) {
    previous[key] = process.env[key];
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
  const restore = () => {
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  };
  try {
    const result = fn();
    if (result && typeof result.then === "function") {
      return result.finally(restore);
    }
    restore();
    return result;
  } catch (error) {
    restore();
    throw error;
  }
}

test("every spec kind normalizes, has a routing bucket, a profile, and a surface label", () => {
  assert.equal(COMPUTE_BACKEND_KINDS.length, 9);
  for (const kind of COMPUTE_BACKEND_KINDS) {
    assert.equal(normalizeComputeBackend(kind), kind);
    assert.ok(["host", "sandboxed", "gpu-burst", "persistent-remote"].includes(getRoutingBucket(kind)));
    assert.ok(getDefaultComputeProfile(kind));
    assert.ok(getComputeBackendSurfaceLabel(kind).length > 0);
    assert.equal(parseComputeBackendKind(kind), kind);
  }
  assert.equal(normalizeComputeBackend("nope"), "host");
  assert.equal(getRoutingBucket("modal"), "gpu-burst");
  assert.equal(getRoutingBucket("runpod-pod"), "persistent-remote");
  assert.equal(getRoutingBucket("runpod-serverless"), "gpu-burst");
  assert.equal(getRoutingBucket("vercel-sandbox"), "sandboxed");
});

test("every adapter implements the ExecutionBackend contract with capability flags", () => {
  const settings = { computeBackend: "host", parallelsTemplateName: "tpl" };
  for (const kind of COMPUTE_BACKEND_KINDS) {
    const backend = createExecutionBackend("/tmp/repo", settings, { runner: async () => ({ exitCode: 0, stdout: "", stderr: "" }) }, kind);
    assert.equal(backend.kind, kind);
    for (const method of ["healthcheck", "stageWorkspace", "exec", "snapshot", "restore", "teardown"]) {
      assert.equal(typeof backend[method], "function", `${kind}.${method}`);
    }
    for (const flag of ["snapshot", "restore", "gpu", "stageWorkspace", "artifactSync", "interactive", "oneShot"]) {
      assert.equal(typeof backend.capabilities[flag], "boolean", `${kind}.capabilities.${flag}`);
    }
  }
  assert.equal(createExecutionBackend("/tmp/repo", settings, {}, "parallels-vm").capabilities.snapshot, true);
  assert.equal(createExecutionBackend("/tmp/repo", settings, {}, "modal").capabilities.gpu, true);
  assert.equal(createExecutionBackend("/tmp/repo", settings, {}, "docker").capabilities.gpu, false);
  assert.equal(createExecutionBackend("/tmp/repo", settings, {}, "modal").capabilities.oneShot, true);
  assert.equal(createExecutionBackend("/tmp/repo", settings, {}, "runpod-serverless").capabilities.oneShot, true);
  assert.equal(createExecutionBackend("/tmp/repo", settings, {}, "runpod-pod").capabilities.oneShot, false);
});

test("computeProfile and computeDefaults validate against the spec JSON shape", () => {
  const settings = {
    computeBackend: "docker",
    computeProfile: "isolated-local",
    computeDefaults: { networkPolicy: "default", workspaceMountMode: "rw" },
  };
  assert.deepEqual(getComputeProfileIssues(settings), []);
  assert.equal(resolveComputeProfile(settings), "isolated-local");
  assert.deepEqual(normalizeComputeDefaults(settings.computeDefaults), {
    networkPolicy: "default",
    workspaceMountMode: "rw",
  });
  assert.deepEqual(normalizeComputeDefaults({ networkPolicy: { allowDomains: ["github.com", " "] }, workspaceMountMode: "ro" }), {
    networkPolicy: { allowDomains: ["github.com"] },
    workspaceMountMode: "ro",
  });
  assert.deepEqual(normalizeComputeDefaults("garbage"), { networkPolicy: "default", workspaceMountMode: "rw" });

  const mismatch = getComputeProfileIssues({ computeBackend: "modal", computeProfile: "isolated-local" });
  assert.equal(mismatch.length, 1);
  assert.match(mismatch[0], /gpu-burst/);
  assert.equal(resolveComputeProfile({ computeBackend: "runpod-pod" }), "persistent-remote");
  assert.match(getComputeProfileIssues({ computeBackend: "host", computeProfile: "weird" })[0], /Unknown computeProfile/);
});

test("normalizeGrclankerSettings keeps remote kinds and drops invalid profile values", () => {
  const dir = mkdtempSync(join(tmpdir(), "grclanker-compute-settings-"));
  const settingsPath = join(dir, "settings.json");
  const bundledPath = join(dir, "bundled.json");
  writeFileSync(bundledPath, "{}\n");
  writeFileSync(settingsPath, JSON.stringify({
    computeBackend: "runpod-serverless",
    computeProfile: "not-a-profile",
    computeDefaults: { networkPolicy: "deny-all", workspaceMountMode: "ro" },
  }));
  normalizeGrclankerSettings(settingsPath, bundledPath);
  const saved = JSON.parse(readFileSync(settingsPath, "utf8"));
  assert.equal(saved.computeBackend, "runpod-serverless");
  assert.equal(saved.computeProfile, undefined);
  assert.deepEqual(saved.computeDefaults, { networkPolicy: "deny-all", workspaceMountMode: "ro" });

  withEnv({ GRCLANKER_COMPUTE_BACKEND_OVERRIDE: "docker" }, () => {
    assert.equal(readGrclankerSettings(settingsPath).computeBackend, "docker");
  });
  withEnv({ GRCLANKER_COMPUTE_BACKEND_OVERRIDE: "bogus" }, () => {
    assert.equal(readGrclankerSettings(settingsPath).computeBackend, "runpod-serverless");
  });
});

test("extractComputeFlag plumbs --compute for setup, investigate, and audit", () => {
  assert.deepEqual(extractComputeFlag(["--compute", "modal"]), { compute: "modal", rest: [] });
  assert.deepEqual(extractComputeFlag(["--compute=docker", "extra"]), { compute: "docker", rest: ["extra"] });
  assert.deepEqual(extractComputeFlag([]), { compute: undefined, rest: [] });
  assert.throws(() => extractComputeFlag(["--compute", "nope"]), /Unknown compute backend/);
  assert.throws(() => extractComputeFlag(["--compute"]), /Missing value/);
});

test("docker run args keep the phase 1 shape and honor computeDefaults", () => {
  const identity = { uid: 1000, gid: 1000 };
  const args = buildDockerRunArgs({
    image: "ubuntu:24.04",
    hostWorkspace: "/repo",
    workspaceRoot: "/workspace",
    workdir: "/workspace/sub",
    command: "pwd",
    identity,
  });
  assert.deepEqual(args, [
    "run", "--rm", "-i", "--init",
    "--volume", "/repo:/workspace",
    "--workdir", "/workspace/sub",
    "--user", "1000:1000",
    "--env", "GRCLANKER_COMPUTE_BACKEND=docker",
    "--env", "HOME=/tmp",
    "ubuntu:24.04", "bash", "-lc", "pwd",
  ]);

  const locked = buildDockerRunArgs({
    image: "ubuntu:24.04",
    hostWorkspace: "/repo",
    workspaceRoot: "/workspace",
    workdir: "/workspace",
    command: "pwd",
    mountMode: "ro",
    networkPolicy: "deny-all",
    env: { FOO: "bar" },
  });
  assert.ok(locked.includes("/repo:/workspace:ro"));
  assert.ok(locked.includes("--network") && locked.includes("none"));
  assert.ok(locked.includes("FOO=bar"));
  assert.ok(!locked.includes("--user"));

  const toolArgs = buildDockerToolRunArgs("/repo", {
    computeBackend: "docker",
    dockerImage: "python:3.12-slim",
    computeDefaults: { workspaceMountMode: "ro" },
  }, "/repo/pkg", "ls");
  assert.ok(toolArgs.includes("/repo:/workspace:ro"));
  assert.equal(toolArgs[toolArgs.indexOf("--workdir") + 1], "/workspace/pkg");
  assert.throws(() => buildDockerToolRunArgs("/repo", { computeBackend: "docker" }, "/elsewhere", "ls"), /session root/);
});

test("docker adapter runs through the injected runner and reports health", async () => {
  const { runner, calls } = createFakeRunner(async (executable, args) => {
    if (args[0] === "info") return { exitCode: 0 };
    return { exitCode: 3, stdout: "out", stderr: "err" };
  });
  const backend = createDockerBackend({
    image: "ubuntu:24.04",
    workspaceRoot: "/workspace",
    localRoot: "/repo",
    runner,
    identity: null,
  });
  await backend.healthcheck();
  const staged = await backend.stageWorkspace({ localPath: "/repo", sessionId: "s1" });
  assert.equal(staged.remotePath, "/workspace");
  const result = await backend.exec({ sessionId: "s1", command: ["echo", "hi there"], cwd: "/workspace" });
  assert.deepEqual(result, { exitCode: 3, stdout: "out", stderr: "err", artifacts: [] });
  assert.equal(calls[1].executable, "docker");
  assert.equal(calls[1].args.at(-1), "'echo' 'hi there'");
  await assert.rejects(() => backend.snapshot("s1"), /does not support snapshot/);
  await backend.teardown("s1");

  const { runner: failing } = createFakeRunner(async () => ({ exitCode: 1 }));
  await assert.rejects(
    () => createDockerBackend({ image: "x", workspaceRoot: "/w", localRoot: "/repo", runner: failing }).healthcheck(),
    /daemon is not reachable/,
  );
});

test("parallels adapter stages, execs, snapshots, restores, and tears down through prlctl", async () => {
  const { runner, calls } = createFakeRunner(async (executable, args) => {
    assert.equal(executable, "prlctl");
    if (args[0] === "exec" && args.at(-1).includes("test -d")) return { exitCode: 0, stdout: "ok" };
    if (args[0] === "exec") return { exitCode: 0, stdout: "hello\n" };
    if (args[0] === "snapshot") return { exitCode: 0, stdout: "The snapshot with id {a1b2c3d4-0000-1111-2222-333344445555} has been successfully created.\n" };
    return { exitCode: 0 };
  });
  const backend = createParallelsBackend({
    sourceKind: "template",
    sourceName: "grclanker-template",
    clonePrefix: "grclanker-sandbox",
    runner,
    sleep: async () => {},
  });

  await backend.healthcheck();
  const staged = await backend.stageWorkspace({ localPath: "/Users/me/repo", sessionId: "sess" });
  assert.equal(staged.remotePath, "/media/psf/grclanker-workspace-repo");
  const create = calls.find((call) => call.args[0] === "create");
  assert.deepEqual(create.args.slice(2), ["--ostemplate", "grclanker-template"]);
  assert.ok(calls.some((call) => call.args[0] === "set" && call.args.includes("--shf-host-add")));
  assert.ok(calls.some((call) => call.args[0] === "start"));

  const result = await backend.exec({ sessionId: "sess", command: ["echo hello"], cwd: "/media/psf/grclanker-workspace-repo/sub" });
  assert.equal(result.exitCode, 0);
  assert.equal(result.stdout, "hello\n");
  const exec = calls.at(-1);
  assert.deepEqual(exec.args.slice(0, 1), ["exec"]);
  assert.match(exec.args.at(-1), /^cd -- '\/media\/psf\/grclanker-workspace-repo\/sub' && echo hello$/);

  const cloneName = create.args[1];
  const snapshotId = await backend.snapshot("sess");
  assert.equal(snapshotId, "{a1b2c3d4-0000-1111-2222-333344445555}");
  await backend.restore("sess", snapshotId);
  assert.deepEqual(calls.at(-1).args, ["snapshot-switch", cloneName, "--id", "{a1b2c3d4-0000-1111-2222-333344445555}"]);
  await assert.rejects(() => backend.restore("sess", "someone-elses"), /not created by this session/);

  await backend.teardown("sess");
  const tail = calls.slice(-2).map((call) => call.args[0]);
  assert.deepEqual(tail, ["stop", "delete"]);
  await assert.rejects(() => backend.exec({ sessionId: "sess", command: ["true"], cwd: "/x" }), /Call stageWorkspace first/);
  assert.equal(parseParallelsSnapshotId("nothing here"), undefined);
});

test("parallels adapter destroys the clone when staging fails", async () => {
  const { runner, calls } = createFakeRunner(async (_executable, args) => {
    if (args[0] === "start") return { exitCode: 1, stderr: "boot failed" };
    return { exitCode: 0 };
  });
  const backend = createParallelsBackend({
    sourceKind: "base-vm",
    sourceName: "base",
    clonePrefix: "p",
    runner,
    sleep: async () => {},
    mountTimeoutMs: 0,
  });
  await assert.rejects(() => backend.stageWorkspace({ localPath: "/repo", sessionId: "s" }), /Could not start/);
  assert.equal(calls[0].args[0], "clone");
  assert.deepEqual(calls.slice(-2).map((call) => call.args[0]), ["stop", "delete"]);
});

test("modal adapter shells out through documented modal shell flags and redacts tokens", async () => {
  const args = buildModalShellArgs({
    image: "debian:bookworm-slim",
    command: "pwd",
    localPath: "/repo",
    gpu: "a10g",
    environment: "main",
  });
  assert.deepEqual(args.slice(0, -1), [
    "shell", "--no-pty", "--image", "debian:bookworm-slim",
    "--add-local", "/repo", "--gpu", "a10g", "--env", "main", "--cmd",
  ]);
  assert.equal(args.at(-1), buildModalCommandWrapper("pwd"));
  assert.equal(decodeModalCommandWrapper(args.at(-1)), "pwd");

  await withEnv({ MODAL_TOKEN_ID: "ak-testtoken123", MODAL_TOKEN_SECRET: "as-supersecret456" }, async () => {
    const { runner, calls } = createFakeRunner(async (_executable, invocation) => {
      if (invocation[0] === "--version") return { exitCode: 0, stdout: "modal client version: 1.0" };
      return { exitCode: 0, stdout: "leaked as-supersecret456\n" };
    });
    const backend = createModalBackend({ runner, gpu: "any" });
    await backend.healthcheck();
    const staged = await backend.stageWorkspace({ localPath: "/home/me/repo", sessionId: "m1" });
    assert.equal(staged.remotePath, "/mnt/repo");
    const result = await backend.exec({ sessionId: "m1", command: ["pwd"], cwd: "/mnt/repo", env: { A: "b c" } });
    assert.equal(result.stdout, "leaked [REDACTED]\n");
    const call = calls.at(-1);
    assert.equal(call.executable, "modal");
    assert.ok(call.args.includes("--add-local") && call.args.includes("/home/me/repo"));
    assert.match(decodeModalCommandWrapper(call.args.at(-1)), /^export A='b c'; cd -- '\/mnt\/repo' && pwd$/);
    await assert.rejects(() => backend.snapshot("m1"), /does not support/);
    await backend.teardown("m1");
  });

  await withEnv({ MODAL_TOKEN_ID: undefined, MODAL_TOKEN_SECRET: undefined, MODAL_CONFIG_PATH: MISSING_MODAL_CONFIG_PATH }, async () => {
    const backend = createModalBackend({ runner: async () => ({ exitCode: 0, stdout: "", stderr: "" }) });
    await assert.rejects(() => backend.healthcheck(), /Set MODAL_TOKEN_ID/);
  });
});

test("runpod serverless adapter follows the documented run, status, and cancel operations", async () => {
  await withEnv({ RUNPOD_API_KEY: "rpa_secretkey_ABCDEFG", RUNPOD_ENDPOINT_ID: "ep123" }, async () => {
    const requests = [];
    let statusPolls = 0;
    const fetchMock = async (url, init = {}) => {
      requests.push({ url, method: init.method, headers: init.headers, body: init.body });
      const respond = (payload, status = 200) => new Response(JSON.stringify(payload), { status });
      if (url.endsWith("/health")) return respond({ workers: { ready: 1 } });
      if (url.endsWith("/run")) return respond({ id: "job-1", status: "IN_QUEUE" });
      if (url.includes("/status/job-1")) {
        statusPolls += 1;
        return statusPolls < 2
          ? respond({ id: "job-1", status: "IN_PROGRESS" })
          : respond({ id: "job-1", status: "COMPLETED", output: { exitCode: 0, stdout: "done\n", stderr: "", artifacts: ["out/report.json"] } });
      }
      return respond({ error: "unexpected" }, 500);
    };
    const backend = createRunpodServerlessBackend({ fetch: fetchMock, sleep: async () => {}, pollIntervalMs: 0 });
    await backend.healthcheck();
    assert.equal(requests[0].url, "https://api.runpod.ai/v2/ep123/health");
    assert.equal(requests[0].headers.authorization, "Bearer rpa_secretkey_ABCDEFG");

    const chunks = [];
    const result = await backend.exec({
      sessionId: "s",
      command: ["make test"],
      cwd: "/workspace",
      timeoutMs: 30_000,
      onData: (chunk) => chunks.push(chunk.toString()),
    });
    assert.deepEqual(result, { exitCode: 0, stdout: "done\n", stderr: "", artifacts: ["out/report.json"] });
    assert.deepEqual(chunks, ["done\n"]);
    const run = requests.find((request) => request.url.endsWith("/run"));
    assert.equal(run.method, "POST");
    assert.deepEqual(JSON.parse(run.body), {
      input: { command: "make test", cwd: "/workspace", env: {} },
      policy: { executionTimeout: 30_000 },
    });
    assert.equal(requests.filter((request) => request.url.includes("/status/job-1")).length, 2);

    const failingFetch = async (url) => {
      if (url.endsWith("/run")) return new Response(JSON.stringify({ id: "job-2", status: "IN_QUEUE" }), { status: 200 });
      if (url.includes("/status/")) return new Response(JSON.stringify({ id: "job-2", status: "FAILED", error: "boom rpa_secretkey_ABCDEFG" }), { status: 200 });
      return new Response("{}", { status: 200 });
    };
    const failing = createRunpodServerlessBackend({ fetch: failingFetch, sleep: async () => {}, pollIntervalMs: 0 });
    await assert.rejects(
      () => failing.exec({ sessionId: "s", command: ["false"], cwd: "/workspace" }),
      (error) => /status FAILED/.test(error.message) && !error.message.includes("rpa_secretkey_ABCDEFG"),
    );

    const unauthorized = createRunpodServerlessBackend({ fetch: async () => new Response("denied", { status: 401 }) });
    await assert.rejects(() => unauthorized.healthcheck(), /HTTP 401/);
  });
  assert.deepEqual(parseRunpodWorkerOutput(null), { exitCode: 1, stdout: "", stderr: "", artifacts: [] });
});

test("runpod pod adapter reads the documented pod fields and execs over ssh", async () => {
  await withEnv({ RUNPOD_API_KEY: "rpa_podkey_ABCDEFG", RUNPOD_POD_ID: "pod42" }, async () => {
    const requests = [];
    const fetchMock = async (url, init = {}) => {
      requests.push({ url, headers: init.headers });
      return new Response(JSON.stringify({
        id: "pod42",
        desiredStatus: "RUNNING",
        publicIp: "203.0.113.10",
        portMappings: { "22": 22022 },
      }), { status: 200 });
    };
    const { runner, calls } = createFakeRunner(async () => ({ exitCode: 0, stdout: "ok\n" }));
    const backend = createRunpodPodBackend({ fetch: fetchMock, runner });
    await backend.healthcheck();
    assert.equal(requests[0].url, "https://rest.runpod.io/v1/pods/pod42");
    assert.equal(requests[0].headers.authorization, "Bearer rpa_podkey_ABCDEFG");

    const staged = await backend.stageWorkspace({ localPath: "/repo", sessionId: "sess" });
    assert.equal(staged.remotePath, "/workspace/sess");
    assert.deepEqual(calls.map((call) => call.executable), ["git", "ssh", "scp"]);
    assert.deepEqual(calls[0].args, ["-C", "/repo", "ls-files", "--cached", "-z"]);
    assert.ok(calls[2].args.includes("root@203.0.113.10:/workspace/sess"));
    assert.match(calls[2].args.at(-2), /grclanker-runpod-stage-[^/]+\/\.$/, "scp uploads the private staging copy, not the repo root");

    const result = await backend.exec({ sessionId: "sess", command: ["uname -a"], cwd: "/workspace/sess" });
    assert.equal(result.stdout, "ok\n");
    const exec = calls.at(-1);
    assert.deepEqual(exec.args.slice(0, 7), [
      "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new", "-p", "22022", "root@203.0.113.10",
    ]);
    assert.match(exec.args.at(-1), /^cd -- '\/workspace\/sess' && uname -a$/);

    await backend.teardown("sess");
    assert.match(calls.at(-1).args.at(-1), /^rm -rf -- '\/workspace\/sess'$/);
    assert.deepEqual(buildPodSshArgs({ host: "h", port: 1, user: "u" }, "true").slice(-2), ["u@h", "true"]);

    const noSsh = createRunpodPodBackend({
      fetch: async () => new Response(JSON.stringify({ id: "pod42", desiredStatus: "RUNNING" }), { status: 200 }),
      runner,
    });
    await assert.rejects(() => noSsh.healthcheck(), /does not expose public SSH/);
  });
});

test("cloudflare and vercel stubs fail fast with a clear message", async () => {
  for (const kind of ["cloudflare-sandbox", "vercel-sandbox"]) {
    const backend = createExecutionBackend("/repo", { computeBackend: kind });
    await assert.rejects(() => backend.healthcheck(), /not available yet/);
    await assert.rejects(() => backend.exec({ sessionId: "s", command: ["true"], cwd: "/" }), /not available yet/);
    await backend.teardown("s");
  }
});

test("env list reports every backend with kind, bucket, and readiness", () => {
  withEnv({
    MODAL_TOKEN_ID: undefined,
    MODAL_TOKEN_SECRET: undefined,
    MODAL_CONFIG_PATH: MISSING_MODAL_CONFIG_PATH,
    RUNPOD_API_KEY: undefined,
    RUNPOD_ENDPOINT_ID: undefined,
    RUNPOD_POD_ID: undefined,
  }, () => {
    const settings = { computeBackend: "modal", computeProfile: "gpu-burst" };
    const detected = COMPUTE_BACKEND_KINDS.map((kind) => ({
      kind,
      label: kind,
      summary: "",
      available: kind === "host",
      detail: kind === "host" ? "Built-in local execution is always available." : "not detected in test",
    }));
    const entries = buildComputeBackendList(settings, detected);
    assert.equal(entries.length, 9);
    assert.deepEqual(entries.map((entry) => entry.kind), [...COMPUTE_BACKEND_KINDS]);
    const host = entries.find((entry) => entry.kind === "host");
    assert.equal(host.readiness, "ready");
    assert.equal(host.bucket, "host");
    const modal = entries.find((entry) => entry.kind === "modal");
    assert.equal(modal.preferred, true);
    assert.equal(modal.readiness, "not detected");
    assert.equal(modal.bucket, "gpu-burst");
    assert.equal(entries.find((entry) => entry.kind === "vercel-sandbox").readiness, "not available");

    const text = formatComputeBackendList(entries, settings);
    assert.match(text, /Preferred compute backend: modal/);
    assert.match(text, /Compute profile:\s+gpu-burst/);
    assert.match(text, /\* modal\s+gpu-burst\s+not detected/);
    assert.match(text, /runpod-pod\s+persistent-remote/);
  });
});

test("runtime awaits remote teardown on the success path and the throw path", async () => {
  await withEnv({ RUNPOD_API_KEY: "rpa_podkey_ABCDEFG", RUNPOD_POD_ID: "pod42" }, async () => {
    const settings = { computeBackend: "runpod-pod", computeProfile: "persistent-remote" };
    const fetchMock = async () => new Response(RUNPOD_POD_JSON, { status: 200 });

    const success = createFakeRunner(async (_executable, args) => {
      if (args.at(-1).startsWith("rm -rf")) {
        await new Promise((done) => setTimeout(done, 20));
        return { exitCode: 0 };
      }
      return { exitCode: 0, stdout: "ok\n" };
    });
    const output = await withComputeBackendExecution("/repo", settings, async (execution) => {
      assert.equal(execution.kind, "runpod-pod");
      const result = await execution.bashOperations.exec("uname -a", "/repo", { onData: () => {} });
      assert.equal(result.exitCode, 0);
      assert.equal(activeComputeSessionCount(), 1);
      assert.ok(!success.calls.some((call) => call.args.at(-1).startsWith("rm -rf")));
      return "done";
    }, { fetch: fetchMock, runner: success.runner });
    assert.equal(output, "done");
    assert.equal(activeComputeSessionCount(), 0);
    const removal = success.calls.at(-1);
    assert.equal(removal.executable, "ssh");
    assert.match(removal.args.at(-1), /^rm -rf -- '\/workspace\/grclanker-[0-9a-z-]+'$/);

    const failing = createFakeRunner(async () => ({ exitCode: 0, stdout: "" }));
    await assert.rejects(
      () => withComputeBackendExecution("/repo", settings, async (execution) => {
        await execution.bashOperations.exec("true", "/repo", { onData: () => {} });
        throw new Error("tool blew up");
      }, { fetch: fetchMock, runner: failing.runner }),
      /tool blew up/,
    );
    assert.equal(activeComputeSessionCount(), 0);
    assert.match(failing.calls.at(-1).args.at(-1), /^rm -rf -- '\/workspace\/grclanker-[0-9a-z-]+'$/);

    const untouched = createFakeRunner(async () => ({ exitCode: 0 }));
    await withComputeBackendExecution("/repo", settings, async () => undefined, { fetch: fetchMock, runner: untouched.runner });
    assert.equal(untouched.calls.length, 0);
  });
});

test("session_shutdown tears down a staged runpod-pod session regardless of the preferred backend", async () => {
  await withEnv({ RUNPOD_API_KEY: "rpa_podkey_ABCDEFG", RUNPOD_POD_ID: "pod42" }, async () => {
    const fetchMock = async () => new Response(RUNPOD_POD_JSON, { status: 200 });
    const { runner, calls } = createFakeRunner(async () => ({ exitCode: 0, stdout: "ok\n" }));

    // The run was started with a per-run --compute override, so settings still prefer host.
    const execution = resolveComputeBackendExecution(
      "/repo",
      { computeBackend: "runpod-pod", computeProfile: "persistent-remote" },
      { fetch: fetchMock, runner },
    );
    const result = await execution.bashOperations.exec("uname -a", "/repo", { onData: () => {} });
    assert.equal(result.exitCode, 0);
    assert.equal(activeComputeSessionCount(), 1);
    assert.ok(!calls.some((call) => call.args.at(-1).startsWith("rm -rf")));

    let sandboxResets = 0;
    await shutdownComputeSessions({ computeBackend: "host" }, { resetSandboxRuntime: async () => { sandboxResets += 1; } });
    assert.equal(activeComputeSessionCount(), 0);
    assert.equal(sandboxResets, 0, "the sandbox reset stays gated on sandbox-runtime");
    const removal = calls.at(-1);
    assert.equal(removal.executable, "ssh");
    assert.match(removal.args.at(-1), /^rm -rf -- '\/workspace\/grclanker-[0-9a-z-]+'$/);

    // A second shutdown is a no-op: the session is already gone.
    await shutdownComputeSessions({ computeBackend: "host" });
    assert.equal(calls.filter((call) => call.args.at(-1).startsWith("rm -rf")).length, 1);

    // The sandbox reset runs for sandbox-runtime, and registry teardown still runs when it throws.
    const second = resolveComputeBackendExecution(
      "/repo",
      { computeBackend: "runpod-pod", computeProfile: "persistent-remote" },
      { fetch: fetchMock, runner },
    );
    await second.bashOperations.exec("true", "/repo", { onData: () => {} });
    assert.equal(activeComputeSessionCount(), 1);
    await assert.rejects(
      () => shutdownComputeSessions({ computeBackend: "sandbox-runtime" }, {
        resetSandboxRuntime: async () => {
          sandboxResets += 1;
          throw new Error("reset failed");
        },
      }),
      /reset failed/,
    );
    assert.equal(sandboxResets, 1);
    assert.equal(activeComputeSessionCount(), 0);
    assert.equal(calls.filter((call) => call.args.at(-1).startsWith("rm -rf")).length, 2);
  });
});

test("parseParallelsSnapshotId round-trips braced and bare ids verbatim", () => {
  const uuid = "a1b2c3d4-0000-1111-2222-333344445555";
  assert.equal(parseParallelsSnapshotId(`Snapshot {${uuid}} has been created`), `{${uuid}}`);
  assert.equal(parseParallelsSnapshotId(`Snapshot ${uuid} has been created`), uuid);
  assert.equal(parseParallelsSnapshotId(`ID: {${uuid.toUpperCase()}}`), `{${uuid.toUpperCase()}}`);
  assert.equal(parseParallelsSnapshotId("Snapshot created: 0123456789abcdef and nothing else"), undefined);
  assert.equal(parseParallelsSnapshotId(`prefix-${uuid}`), undefined, "a uuid glued to other hex is not an id");
  assert.equal(parseParallelsSnapshotId(""), undefined);
});

test("runpod pod adapter removes the directory it created when scp fails", async () => {
  await withEnv({ RUNPOD_API_KEY: "rpa_podkey_ABCDEFG", RUNPOD_POD_ID: "pod42" }, async () => {
    const { runner, calls } = createFakeRunner(async (executable) => (
      executable === "scp" ? { exitCode: 1, stderr: "lost connection" } : { exitCode: 0 }
    ));
    const backend = createRunpodPodBackend({
      fetch: async () => new Response(RUNPOD_POD_JSON, { status: 200 }),
      runner,
    });
    await assert.rejects(() => backend.stageWorkspace({ localPath: "/repo", sessionId: "sess" }), /Could not copy/);
    assert.deepEqual(calls.map((call) => call.executable), ["git", "ssh", "scp", "ssh"]);
    assert.match(calls[1].args.at(-1), /^mkdir -p -- '\/workspace\/sess'$/);
    assert.match(calls[3].args.at(-1), /^rm -rf -- '\/workspace\/sess'$/);
    await backend.teardown("sess");
    assert.equal(calls.length, 4);
  });
});

test("runpod pod cleanup keeps the session tracked until the removal is confirmed", async () => {
  await withEnv({ RUNPOD_API_KEY: "rpa_podkey_ABCDEFG", RUNPOD_POD_ID: "pod42" }, async () => {
    const fetchMock = async () => new Response(RUNPOD_POD_JSON, { status: 200 });
    const isRemoval = (call) => call.executable === "ssh" && String(call.args.at(-1)).startsWith("rm -rf");
    const removals = (calls) => calls.filter(isRemoval);
    const stuck = { exitCode: 1, stderr: "rm: cannot remove '/workspace/sess': Device or resource busy rpa_podkey_ABCDEFG" };

    // Adapter level: the runner resolves with exit code 1 (it never rejects), so the result has
    // to be inspected. The removal is retried, the session stays staged, and the error names the
    // pod, the path, and the delete command without the API key that the remote echoed.
    let removalExit = 1;
    const adapter = createFakeRunner(async (_executable, args) => (
      String(args.at(-1)).startsWith("rm -rf") ? (removalExit === 0 ? { exitCode: 0 } : stuck) : { exitCode: 0, stdout: "ok\n" }
    ));
    const backend = createRunpodPodBackend({ fetch: fetchMock, runner: adapter.runner });
    await backend.stageWorkspace({ localPath: "/repo", sessionId: "sess" });
    await assert.rejects(
      () => backend.teardown("sess"),
      (error) => {
        assert.ok(error instanceof ExecutionBackendCleanupError, "typed cleanup error");
        assert.match(error.message, /runpod-pod could not remove \/workspace\/sess on RunPod pod pod42/);
        assert.ok(
          error.message.includes(`(delete it with: ssh -p 22022 root@203.0.113.10 ${quoteForBash("rm -rf -- '/workspace/sess'")})`),
          `delete command named: ${error.message}`,
        );
        assert.match(error.message, /rm -rf exited 1 on 2 attempts: rm: cannot remove/);
        assert.ok(!error.message.includes("rpa_podkey_ABCDEFG"), "the remote's stderr is scrubbed");
        assert.match(error.resource, /\/workspace\/sess on RunPod pod pod42/);
        return true;
      },
    );
    assert.equal(removals(adapter.calls).length, RUNPOD_CLEANUP_ATTEMPTS, "the removal is retried before giving up");
    // Still staged: a second teardown retries instead of returning early, and exit code 0 untracks.
    removalExit = 0;
    await backend.teardown("sess");
    assert.equal(removals(adapter.calls).length, RUNPOD_CLEANUP_ATTEMPTS + 1);
    await backend.teardown("sess");
    assert.equal(removals(adapter.calls).length, RUNPOD_CLEANUP_ATTEMPTS + 1, "untracked after the confirmed removal");

    // Runtime level: the registry keeps the session while the removal fails, the failure is the
    // result of withComputeBackendExecution on the success path, and a later sweep retries it.
    const settings = { computeBackend: "runpod-pod", computeProfile: "persistent-remote" };
    let runtimeRemovalExit = 1;
    const runtime = createFakeRunner(async (_executable, args) => (
      String(args.at(-1)).startsWith("rm -rf") ? { exitCode: runtimeRemovalExit, stderr: runtimeRemovalExit ? "busy" : "" } : { exitCode: 0, stdout: "ok\n" }
    ));
    assert.equal(activeComputeSessionCount(), 0);
    await assert.rejects(
      () => withComputeBackendExecution("/repo", settings, async (execution) => {
        await execution.bashOperations.exec("true", "/repo", { onData: () => {} });
        return "done";
      }, { fetch: fetchMock, runner: runtime.runner }),
      (error) => error instanceof ExecutionBackendCleanupError && /on RunPod pod pod42/.test(error.message),
    );
    assert.equal(activeComputeSessionCount(), 1, "the session stays tracked after a failed removal");
    assert.equal(removals(runtime.calls).length, RUNPOD_CLEANUP_ATTEMPTS);

    // The shutdown sweep reports the failure and keeps the handle; once rm exits 0 it is gone.
    await assert.rejects(
      () => shutdownComputeSessions({ computeBackend: "host" }),
      (error) => {
        assert.equal(error.name, "ComputeSessionTeardownError");
        assert.match(error.message, /1 compute session could not be torn down and stays tracked:\n- Compute backend error: runpod-pod could not remove/);
        return true;
      },
    );
    assert.equal(activeComputeSessionCount(), 1);
    assert.equal(removals(runtime.calls).length, RUNPOD_CLEANUP_ATTEMPTS * 2);
    runtimeRemovalExit = 0;
    await shutdownComputeSessions({ computeBackend: "host" });
    assert.equal(activeComputeSessionCount(), 0, "exit code 0 untracks the session");
    assert.equal(removals(runtime.calls).length, RUNPOD_CLEANUP_ATTEMPTS * 2 + 1);

    // Throw path: the run's own error stays primary and keeps its type; the cleanup failure is
    // appended rather than lost, and the session stays tracked.
    class ToolError extends Error {}
    let throwPathRemovalExit = 1;
    const throwPath = createFakeRunner(async (_executable, args) => (
      String(args.at(-1)).startsWith("rm -rf") ? { exitCode: throwPathRemovalExit, stderr: "" } : { exitCode: 0, stdout: "" }
    ));
    await assert.rejects(
      () => withComputeBackendExecution("/repo", settings, async (execution) => {
        await execution.bashOperations.exec("true", "/repo", { onData: () => {} });
        throw new ToolError("tool blew up");
      }, { fetch: fetchMock, runner: throwPath.runner }),
      (error) => {
        assert.ok(error instanceof ToolError);
        assert.match(error.message, /^tool blew up\nCleanup also failed: Compute backend error: runpod-pod could not remove \/workspace\/grclanker-[0-9a-z-]+ on RunPod pod pod42/);
        return true;
      },
    );
    assert.equal(activeComputeSessionCount(), 1);
    throwPathRemovalExit = 0;
    await shutdownComputeSessions({ computeBackend: "host" });
    assert.equal(activeComputeSessionCount(), 0);

    // Staging failure whose own cleanup fails: the partial upload is named, the session stays
    // tracked (adapter and registry), and the sweep retries the removal.
    let stagingRemovalExit = 1;
    const staging = createFakeRunner(async (executable, args) => {
      if (executable === "scp") return { exitCode: 1, stderr: "lost connection" };
      if (String(args.at(-1)).startsWith("rm -rf")) return { exitCode: stagingRemovalExit, stderr: stagingRemovalExit ? "busy" : "" };
      return { exitCode: 0, stdout: "" };
    });
    const execution = resolveComputeBackendExecution("/repo", settings, { fetch: fetchMock, runner: staging.runner });
    await assert.rejects(
      () => execution.bashOperations.exec("true", "/repo", { onData: () => {} }),
      (error) => {
        assert.ok(error instanceof ExecutionBackendCleanupError);
        assert.match(error.message, /The workspace copy failed \(scp exited 1: lost connection\) and the partial upload could not be removed \(rm -rf exited 1 on 2 attempts: busy\)/);
        return true;
      },
    );
    assert.equal(activeComputeSessionCount(), 1, "a partial upload keeps the session tracked");
    assert.deepEqual(staging.calls.map((call) => call.executable), ["git", "ssh", "scp", "ssh", "ssh"]);
    stagingRemovalExit = 0;
    await execution.teardown();
    assert.equal(activeComputeSessionCount(), 0);
    assert.equal(removals(staging.calls).length, RUNPOD_CLEANUP_ATTEMPTS + 1);
    assert.equal(staging.calls.filter((call) => call.executable === "scp").length, 1, "teardown does not re-stage");

    // The synchronous exit hook inspects the exit code too and tells the operator about the remnant.
    const syncCalls = [];
    const syncBackend = createRunpodPodBackend({
      fetch: fetchMock,
      runner: async (_executable, args) => (String(args.at(-1)).startsWith("rm -rf") ? { exitCode: 1, stderr: "" } : { exitCode: 0, stdout: "" }),
      syncRunner: (executable, args) => {
        syncCalls.push({ executable, args });
        return { exitCode: 1, stdout: "", stderr: "busy" };
      },
    });
    await syncBackend.stageWorkspace({ localPath: "/repo", sessionId: "sync" });
    const written = [];
    const originalWrite = process.stderr.write;
    process.stderr.write = (chunk) => {
      written.push(String(chunk));
      return true;
    };
    try {
      syncBackend.teardownSync("sync");
      syncBackend.teardownSync("sync");
    } finally {
      process.stderr.write = originalWrite;
    }
    assert.equal(syncCalls.length, 2, "the session stays staged after a failed synchronous removal");
    assert.match(written.join(""), /runpod-pod could not remove \/workspace\/sync on RunPod pod pod42/);
  });
});

function git(cwd, ...args) {
  const result = spawnSync("git", ["-C", cwd, ...args], { encoding: "utf8" });
  assert.equal(result.status, 0, `git ${args.join(" ")} failed: ${result.stderr}`);
  return result.stdout;
}

function plant(root, relativePath, contents) {
  mkdirSync(join(root, dirname(relativePath)), { recursive: true });
  writeFileSync(join(root, relativePath), contents);
}

function listFilesRecursively(root, prefix = "") {
  const entries = [];
  for (const entry of readdirSync(join(root, prefix), { withFileTypes: true })) {
    const relativePath = prefix ? `${prefix}/${entry.name}` : entry.name;
    if (entry.isDirectory()) entries.push(...listFilesRecursively(root, relativePath));
    else entries.push(relativePath);
  }
  return entries.sort();
}

test("runpod pod staging uploads the git index only and never a planted secret", async () => {
  const repo = mkdtempSync(join(tmpdir(), "grclanker-pod-stage-"));
  const secrets = {
    ".env": "PLANTED_SECRET_ENV=fake-env-secret-1a2b3c\n",
    "credentials.json": "{\"secret\":\"fake-credentials-secret-4d5e6f\"}\n",
    "client_secret.json": "{\"client_secret\":\"fake-client-secret-7g8h9i\"}\n",
    "acme-service-account.json": "{\"private_key\":\"fake-service-account-secret-0j1k2l\"}\n",
    "export/bundle.zip": "fake-export-bundle-secret-3m4n5o\n",
    "oscal-workspace/x.json": "{\"token\":\"fake-oscal-workspace-secret-6p7q8r\"}\n",
  };
  try {
    git(repo, "init", "-q");
    plant(repo, "README.md", "# tracked\n");
    plant(repo, "src/index.ts", "export const tracked = true;\n");
    plant(repo, "scripts/run.sh", "#!/bin/sh\necho tracked\n");
    chmodSync(join(repo, "scripts/run.sh"), 0o755);
    git(repo, "add", "README.md", "src/index.ts", "scripts/run.sh");
    git(repo, "-c", "user.email=test@example.invalid", "-c", "user.name=test", "commit", "-q", "-m", "init");
    for (const [relativePath, contents] of Object.entries(secrets)) plant(repo, relativePath, contents);
    // A sensitive file that was committed by mistake must still stay local.
    plant(repo, "config/credentials.json", "{\"secret\":\"fake-committed-secret-9s0t1u\"}\n");
    git(repo, "add", "-f", "config/credentials.json");
    // A tracked file modified after the commit is uploaded with its working-tree content.
    plant(repo, "README.md", "# tracked and modified\n");
    plant(repo, "untracked-note.md", "not added yet\n");

    const plan = await planPodWorkspaceStaging(repo, createProcessCommandRunner());
    assert.deepEqual(plan.files, ["README.md", "scripts/run.sh", "src/index.ts"]);
    assert.deepEqual(plan.excluded, ["config/credentials.json"]);
    assert.deepEqual(plan.skipped, []);

    const realRunner = createProcessCommandRunner();
    let uploaded;
    const { runner, calls } = createFakeRunner(async (executable, args) => {
      if (executable === "git") return realRunner(executable, args);
      if (executable === "scp") {
        const source = args.at(-2);
        assert.ok(source.endsWith("/."), source);
        const stageRoot = source.slice(0, -2);
        uploaded = {
          files: listFilesRecursively(stageRoot),
          contents: Object.fromEntries(listFilesRecursively(stageRoot).map((file) => [file, readFileSync(join(stageRoot, file), "utf8")])),
          runMode: statSync(join(stageRoot, "scripts/run.sh")).mode & 0o777,
        };
      }
      return { exitCode: 0 };
    });
    await withEnv({ RUNPOD_API_KEY: "rpa_podkey_ABCDEFG", RUNPOD_POD_ID: "pod42" }, async () => {
      const backend = createRunpodPodBackend({ fetch: async () => new Response(RUNPOD_POD_JSON, { status: 200 }), runner });
      const staged = await backend.stageWorkspace({ localPath: repo, sessionId: "sess" });
      assert.match(staged.detail, /^copied 3 tracked files \(1 sensitive path excluded, 0 non-regular or missing entries skipped\) from /);
    });

    assert.deepEqual(uploaded.files, ["README.md", "scripts/run.sh", "src/index.ts"]);
    assert.equal(uploaded.contents["README.md"], "# tracked and modified\n");
    assert.equal(uploaded.runMode, 0o755, "file modes survive the staging copy");
    const remoteArgs = calls.filter((call) => call.executable !== "git").flatMap((call) => call.args);
    assert.deepEqual(calls.map((call) => call.executable), ["git", "ssh", "scp"]);
    for (const relativePath of [...Object.keys(secrets), "config/credentials.json", "untracked-note.md"]) {
      assert.ok(!uploaded.files.includes(relativePath), `${relativePath} reached the staged set`);
      assert.ok(!remoteArgs.some((arg) => arg.includes(relativePath)), `${relativePath} appeared in an ssh or scp argument`);
    }
    const stagedText = Object.values(uploaded.contents).join("\n") + remoteArgs.join("\n");
    const markers = [...Object.values(secrets), "fake-committed-secret-9s0t1u", "not added yet"]
      .map((contents) => /fake-[a-z0-9-]+/.exec(contents)?.[0] ?? contents.trim());
    assert.equal(markers.length, 8);
    for (const marker of markers) {
      assert.ok(!stagedText.includes(marker), `secret ${marker} reached the upload`);
    }
    assert.ok(!remoteArgs.some((arg) => arg.startsWith(`${repo}/`) || arg === `${repo}/.`), "scp never points at the repo root");

    // The staging copy is private and removed after the upload.
    const stageRoot = calls.find((call) => call.executable === "scp").args.at(-2).slice(0, -2);
    assert.ok(!existsSync(stageRoot), "the temp staging copy is removed after scp");

    // A workspace outside any git work tree is refused, never copied blindly.
    const plain = mkdtempSync(join(tmpdir(), "grclanker-pod-plain-"));
    try {
      plant(plain, ".env", "PLANTED=fake-plain-secret\n");
      const plainCalls = createFakeRunner(async (executable, args) => (executable === "git" ? realRunner(executable, args) : { exitCode: 0 }));
      await withEnv({ RUNPOD_API_KEY: "rpa_podkey_ABCDEFG", RUNPOD_POD_ID: "pod42" }, async () => {
        const backend = createRunpodPodBackend({ fetch: async () => new Response(RUNPOD_POD_JSON, { status: 200 }), runner: plainCalls.runner });
        await assert.rejects(
          () => backend.stageWorkspace({ localPath: plain, sessionId: "sess" }),
          /git ls-files exited 128 for .*runpod-pod stages tracked files only/,
        );
      });
      assert.deepEqual(plainCalls.calls.map((call) => call.executable), ["git"], "no ssh or scp call is made for a non-git workspace");
    } finally {
      rmSync(plain, { recursive: true, force: true });
    }

    for (const path of Object.keys(secrets)) assert.equal(isSensitiveStagingPath(path), true, path);
    for (const path of ["nested/.env.local", "a/export/b.txt", "deep/oscal-workspace/y", "keys/server.pem", "id_ed25519", ".env/config"]) {
      assert.equal(isSensitiveStagingPath(path), true, path);
    }
    for (const path of ["README.md", "src/exporter.ts", "environment.md", "id_ed25519.pub", "docs/env.md"]) {
      assert.equal(isSensitiveStagingPath(path), false, path);
    }
    assert.ok(RUNPOD_STAGING_DENYLIST.includes("*service-account*.json"));
  } finally {
    rmSync(repo, { recursive: true, force: true });
  }
});

test("runpod pod staging denies the whole .env family and every gitignore secret name even when force-added", async () => {
  const repo = mkdtempSync(join(tmpdir(), "grclanker-pod-deny-"));
  // Every path below is ignored by this repository's own .gitignore and then force-added, the way
  // a credential file lands in the index by mistake. Each carries a distinct canary.
  const forceAdded = {
    ".envrc": "export PLANTED=fake-envrc-canary-a1\n",
    ".env.local": "PLANTED=fake-env-local-canary-b2\n",
    ".env.production": "PLANTED=fake-env-production-canary-c3\n",
    ".environment": "PLANTED=fake-environment-canary-d4\n",
    "nested/dir/.envrc": "export PLANTED=fake-nested-envrc-canary-e5\n",
    "nested/.envs/token.txt": "fake-env-directory-canary-f6\n",
    "deploy/my.service-account.v2.json": "{\"private_key\":\"fake-service-account-v2-canary-g7\"}\n",
    "deploy/service-account.json": "{\"private_key\":\"fake-service-account-plain-canary-h8\"}\n",
    "ops/.okta.yaml": "okta:\n  token: fake-okta-canary-i9\n",
    "data/export/x.zip": "fake-export-canary-j0\n",
    "audits/oscal-workspace/y.json": "{\"token\":\"fake-oscal-canary-k1\"}\n",
    "config/client_secret.json": "{\"client_secret\":\"fake-client-secret-canary-l2\"}\n",
    "config/app-client_secret.prod.json": "{\"client_secret\":\"fake-client-secret-glob-canary-m3\"}\n",
    "config/app-client-secret.json": "{\"client_secret\":\"fake-client-secret-dash-canary-n4\"}\n",
    "svc/prod.credentials.json": "{\"secret\":\"fake-credentials-suffix-canary-o5\"}\n",
    "svc/robot.sa.json": "{\"private_key\":\"fake-sa-json-canary-p6\"}\n",
    "legacy/Credentials.JSON": "{\"secret\":\"fake-case-canary-q7\"}\n",
    ".dev.vars": "PLANTED=fake-dev-vars-canary-r8\n",
    ".dev.vars.production": "PLANTED=fake-dev-vars-production-canary-s9\n",
    ".secrets/token.txt": "fake-secrets-dir-canary-t0\n",
    "keys/id_rsa": "fake-id-rsa-canary-u1\n",
    "keys/server.key": "fake-server-key-canary-v2\n",
    "keys/apns.p8": "fake-p8-canary-w3\n",
    "keys/putty.ppk": "fake-ppk-canary-x4\n",
    "keys/store.jks": "fake-jks-canary-y5\n",
    "keys/store.keystore": "fake-keystore-canary-z6\n",
    "keys/bundle.p12": "fake-p12-canary-a7\n",
  };
  // Ordinary tracked files, including names that merely contain "env", the negated
  // `.dev.vars.example` template, and a public key half, must still stage.
  const ordinary = {
    "README.md": "# tracked\n",
    "environment.md": "# environment notes\n",
    "config/envelope.ts": "export const envelope = true;\n",
    "guides/env.md": "# env guide\n",
    "src/exporter.ts": "export const exporter = true;\n",
    ".dev.vars.example": "PLANTED=replace-me\n",
    "keys/id_ed25519.pub": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPublicHalfOnly comment\n",
  };
  try {
    git(repo, "init", "-q");
    plant(repo, ".gitignore", readFileSync(REPO_GITIGNORE, "utf8"));
    for (const [relativePath, contents] of Object.entries(ordinary)) plant(repo, relativePath, contents);
    git(repo, "add", ".gitignore", ...Object.keys(ordinary));
    for (const [relativePath, contents] of Object.entries(forceAdded)) plant(repo, relativePath, contents);
    git(repo, "add", "-f", ...Object.keys(forceAdded));
    git(repo, "-c", "user.email=test@example.invalid", "-c", "user.name=test", "commit", "-q", "-m", "force-added secrets");

    // Everything planted is in the index now, so only the deny layer can keep it local.
    const index = git(repo, "ls-files", "--cached").split("\n").filter(Boolean);
    for (const relativePath of Object.keys(forceAdded)) assert.ok(index.includes(relativePath), `${relativePath} should be tracked`);
    const expectedFiles = [".gitignore", ...Object.keys(ordinary)].sort();

    const plan = await planPodWorkspaceStaging(repo, createProcessCommandRunner());
    assert.deepEqual([...plan.files].sort(), expectedFiles);
    assert.deepEqual([...plan.excluded].sort(), Object.keys(forceAdded).sort());
    assert.deepEqual(plan.skipped, []);

    const realRunner = createProcessCommandRunner();
    let uploaded;
    const { runner, calls } = createFakeRunner(async (executable, args) => {
      if (executable === "git") return realRunner(executable, args);
      if (executable === "scp") {
        const stageRoot = args.at(-2).slice(0, -2);
        const files = listFilesRecursively(stageRoot);
        uploaded = { files, contents: Object.fromEntries(files.map((file) => [file, readFileSync(join(stageRoot, file), "utf8")])) };
      }
      return { exitCode: 0 };
    });
    await withEnv({ RUNPOD_API_KEY: "rpa_podkey_ABCDEFG", RUNPOD_POD_ID: "pod42" }, async () => {
      const backend = createRunpodPodBackend({ fetch: async () => new Response(RUNPOD_POD_JSON, { status: 200 }), runner });
      const staged = await backend.stageWorkspace({ localPath: repo, sessionId: "sess" });
      assert.match(staged.detail, new RegExp(`^copied ${expectedFiles.length} tracked files \\(${Object.keys(forceAdded).length} sensitive paths excluded, `));
    });

    assert.deepEqual(uploaded.files, expectedFiles);
    for (const [relativePath, contents] of Object.entries(ordinary)) assert.equal(uploaded.contents[relativePath], contents);
    const remoteArgs = calls.filter((call) => call.executable !== "git").flatMap((call) => call.args);
    assert.deepEqual(calls.map((call) => call.executable), ["git", "ssh", "scp"]);
    const stagedText = Object.values(uploaded.contents).join("\n") + remoteArgs.join("\n");
    for (const [relativePath, contents] of Object.entries(forceAdded)) {
      const canary = /fake-[a-z0-9-]+/.exec(contents)[0];
      assert.ok(!uploaded.files.includes(relativePath), `${relativePath} reached the materialized copy`);
      assert.ok(!remoteArgs.some((arg) => arg.includes(relativePath)), `${relativePath} appeared in an ssh or scp argument`);
      assert.ok(!stagedText.includes(canary), `canary ${canary} from ${relativePath} reached the upload`);
    }

    // The predicate itself, including the flip of `.envrc` from allowed to denied and the names
    // that were re-checked against .gitignore and AGENTS.md.
    for (const path of [
      ".envrc", ".env.local", ".env.production", ".environment", ".ENV", "nested/dir/.envrc", "a/.envs/b.txt",
      "deploy/my.service-account.v2.json", "acme-service-account.json", "service-account.json", "Service-Account.JSON",
      "ops/.okta.yaml", "data/export/x.zip", "deep/oscal-workspace/y", ".secrets/x", ".secrets",
      ".dev.vars", ".dev.vars.local", "worker/.dev.vars",
      "x/prod.credentials.json", "x/robot.sa.json", "x/app-client-secret.json", "x/app-client_secret.v2.json", "legacy/Credentials.JSON",
      "k/apns.p8", "k/putty.ppk", "k/store.jks", "k/store.keystore", "k/bundle.p12", "k/bundle.pfx", "k/server.PEM", "k/id_ecdsa",
    ]) {
      assert.equal(isSensitiveStagingPath(path), true, path);
    }
    for (const path of [
      "README.md", "src/exporter.ts", "environment.md", "id_ed25519.pub", "docs/env.md", "config/envelope.ts",
      ".dev.vars.example", "env/config.ts", "envrc", "export.ts", "my-export/x.txt", "exports/x.txt", "secrets/x.txt", "keys/notes.txt",
    ]) {
      assert.equal(isSensitiveStagingPath(path), false, path);
    }
    for (const entry of [".env*", ".dev.vars*", "!.dev.vars.example", ".secrets/", "*.credentials.json", "*client-secret*.json", "*.sa.json", "*.p8", "*.ppk"]) {
      assert.ok(RUNPOD_STAGING_DENYLIST.includes(entry), entry);
    }
    assert.ok(!RUNPOD_STAGING_DENYLIST.includes(".env.*"), "the narrow .env.* entry is replaced by the .env* family");
  } finally {
    rmSync(repo, { recursive: true, force: true });
  }
});

test("runpod pod adapter rejects empty and traversal session ids at the boundary", async () => {
  for (const bad of ["", " ", "../etc", "a/b", "..", "x..y", "-leading", "sp ace", "$(id)"]) {
    assert.throws(() => assertSafeSessionId(bad), /not a safe path segment/, JSON.stringify(bad));
    assert.throws(() => buildPodSessionPath("/workspace", bad), /not a safe path segment/);
  }
  assert.equal(buildPodSessionPath("/workspace/", "grclanker-1.2_3"), "/workspace/grclanker-1.2_3");
  await withEnv({ RUNPOD_API_KEY: "rpa_podkey_ABCDEFG", RUNPOD_POD_ID: "pod42" }, async () => {
    const { runner, calls } = createFakeRunner(async () => ({ exitCode: 0 }));
    const backend = createRunpodPodBackend({ fetch: async () => new Response(RUNPOD_POD_JSON, { status: 200 }), runner });
    await assert.rejects(() => backend.stageWorkspace({ localPath: "/repo", sessionId: "../../root" }), /not a safe path segment/);
    await assert.rejects(() => backend.teardown("../../root"), /not a safe path segment/);
    assert.equal(calls.length, 0);
  });
});

test("runpod serverless poll loop stops with a typed timeout error and cancels the job", async () => {
  await withEnv({ RUNPOD_API_KEY: "rpa_secretkey_ABCDEFG", RUNPOD_ENDPOINT_ID: "ep123" }, async () => {
    assert.equal(DEFAULT_RUNPOD_JOB_TIMEOUT_MS, 600_000);
    let clock = 0;
    const requests = [];
    const fetchMock = async (url, init = {}) => {
      requests.push({ url, method: init.method });
      if (url.endsWith("/run")) return new Response(JSON.stringify({ id: "job-slow", status: "IN_QUEUE" }), { status: 200 });
      if (url.includes("/status/")) return new Response(JSON.stringify({ id: "job-slow", status: "IN_PROGRESS" }), { status: 200 });
      return new Response("{}", { status: 200 });
    };
    const backend = createRunpodServerlessBackend({
      fetch: fetchMock,
      sleep: async () => {
        clock += 120_000;
      },
      now: () => clock,
      pollIntervalMs: 0,
    });
    await assert.rejects(
      () => backend.exec({ sessionId: "s", command: ["sleep 1d"], cwd: "/workspace" }),
      (error) => error instanceof ExecutionBackendTimeoutError
        && error.name === "ExecutionBackendTimeoutError"
        && error.timeoutMs === DEFAULT_RUNPOD_JOB_TIMEOUT_MS
        && /timed out after 600s/.test(error.message),
    );
    const cancel = requests.at(-1);
    assert.equal(cancel.url, "https://api.runpod.ai/v2/ep123/cancel/job-slow");
    assert.equal(cancel.method, "POST");
    assert.ok(requests.filter((request) => request.url.includes("/status/")).length <= 7);
  });
});

test("modal command wrapper survives the client's shlex bash -c wrapper", () => {
  const command = `printf '%s|%s|%s\\n' "double quoted" 'single quoted' "$HOME_MARKER" && echo 'it'"'"'s $ok'`;
  const wrapper = buildModalCommandWrapper(command);
  assert.match(wrapper, /^f=\$\(mktemp\) && printf %s [A-Za-z0-9+/=]+ \| base64 -d > \$f && bash \$f; s=\$\?; rm -f \$f; exit \$s$/);
  assert.ok(!wrapper.includes('"') && !wrapper.includes("'") && !wrapper.includes("\\"));
  assert.equal(decodeModalCommandWrapper(wrapper), command);

  const python = spawnSync("python3", [
    "-c",
    "import json, shlex, sys; print(json.dumps(shlex.split('/bin/bash -c \"%s\"' % sys.argv[1])))",
    wrapper,
  ], { encoding: "utf8" });
  if (python.status === 0) {
    assert.deepEqual(JSON.parse(python.stdout), ["/bin/bash", "-c", wrapper]);
  }

  const decodeProbe = spawnSync("bash", ["-c", "printf '' | base64 -d >/dev/null 2>&1 && command -v mktemp >/dev/null"]);
  if (decodeProbe.status === 0) {
    const run = spawnSync("/bin/bash", ["-c", wrapper], { encoding: "utf8", env: { ...process.env, HOME_MARKER: "dollar-ok" } });
    assert.equal(run.status, 0, run.stderr);
    assert.equal(run.stdout, "double quoted|single quoted|dollar-ok\nit's $ok\n");
    const failing = spawnSync("/bin/bash", ["-c", buildModalCommandWrapper("exit 7")], { encoding: "utf8" });
    assert.equal(failing.status, 7);
  }
});

test("one-shot backends offer bash only and the smoke test never reports write-then-read as passed", async () => {
  const contractSettings = { computeBackend: "host", parallelsTemplateName: "tpl" };
  const oneShotKinds = COMPUTE_BACKEND_KINDS.filter((kind) =>
    createExecutionBackend("/repo", contractSettings, { runner: async () => ({ exitCode: 0 }) }, kind).capabilities.oneShot,
  );
  assert.deepEqual(oneShotKinds, ["modal", "runpod-serverless"]);

  await withEnv({
    MODAL_TOKEN_ID: "ak-FAKEID0123456789ABCD",
    MODAL_TOKEN_SECRET: "as-FAKESECRET0123456789",
    RUNPOD_API_KEY: "rpa_FAKEKEY0123456789ABCDEF",
    RUNPOD_ENDPOINT_ID: "ep123",
  }, async () => {
    // Both fakes behave like the real providers: every exec starts from the original workspace,
    // so a remote write would "succeed" and the next read would still return the original bytes.
    // Only a single execution can observe its own write.
    const original = "original contents\n";
    const answer = (command) => (command.includes("printf 'alpha") ? "alpha\n" : original);
    const modal = createFakeRunner(async (_executable, args) => {
      if (args[0] === "--version") return { exitCode: 0, stdout: "modal client version: 1.0" };
      return { exitCode: 0, stdout: answer(decodeModalCommandWrapper(args.at(-1))) };
    });
    const serverlessRequests = [];
    const serverlessFetch = async (url, init = {}) => {
      serverlessRequests.push({ url, body: init.body });
      if (url.endsWith("/health")) return new Response(JSON.stringify({ workers: { ready: 1 } }), { status: 200 });
      if (url.endsWith("/run")) {
        // Answer as an already completed job so the test does not wait for the default poll
        // interval; the poll protocol itself is covered by the serverless adapter test.
        const command = JSON.parse(init.body).input.command;
        return new Response(JSON.stringify({
          id: "job-1",
          status: "COMPLETED",
          output: { exitCode: 0, stdout: answer(command), stderr: "", artifacts: [] },
        }), { status: 200 });
      }
      return new Response("{}", { status: 200 });
    };

    const cases = [
      ["modal", { computeBackend: "modal" }, { runner: modal.runner }],
      ["runpod-serverless", { computeBackend: "runpod-serverless" }, { fetch: serverlessFetch }],
    ];
    for (const [kind, settings, deps] of cases) {
      await withComputeBackendExecution("/repo", settings, async (execution) => {
        assert.equal(execution.kind, kind);
        assert.equal(execution.backend.capabilities.oneShot, true);
        assert.equal(typeof execution.bashOperations.exec, "function");
        // The stateful tools are not offered at all, so the extension falls back to its
        // host-local read, write, edit, ls, find, and grep, which keep their state locally.
        for (const surface of ["readOperations", "writeOperations", "editOperations", "lsOperations", "findOperations", "grepOperations"]) {
          assert.equal(execution[surface], undefined, `${kind} must not offer ${surface}`);
        }
        assert.match(execution.summary, /stay on the local workspace because/);

        const lines = [];
        const log = (line) => lines.push(line);
        await runBackendToolSmokeTest({ cwd: "/repo", timeoutSeconds: 5 }, execution, log);
        await runBackendSearchSmokeTest({ cwd: "/repo", timeoutSeconds: 5 }, execution, log);
        assert.deepEqual(lines, [
          `tool_adapter=skipped (${ONE_SHOT_SMOKE_NOTE})`,
          "tool_one_shot_round_trip=ok",
          `tool_find=skipped (${ONE_SHOT_SMOKE_NOTE})`,
          `tool_grep=skipped (${ONE_SHOT_SMOKE_NOTE})`,
        ], kind);
        assert.ok(!lines.some((line) => /^tool_(write|read|edit|ls|find|grep)=ok$/.test(line)), `${kind} reported a stateful probe as passed`);
      }, deps);
    }
    assert.equal(ONE_SHOT_SMOKE_NOTE, "one-shot backend, stateful file operations not offered");
    const roundTrip = serverlessRequests.filter((request) => request.url.endsWith("/run"));
    assert.equal(roundTrip.length, 1);
    assert.match(JSON.parse(roundTrip[0].body).input.command, /printf 'alpha\\n' > "\$probe_file" && cat "\$probe_file"/);

    // The in-execution round trip is a real check: a remote that loses the write fails it, and the
    // failure is reported instead of a pass.
    const lossy = createFakeRunner(async (_executable, args) => {
      if (args[0] === "--version") return { exitCode: 0, stdout: "modal client version: 1.0" };
      return { exitCode: 0, stdout: "" };
    });
    await withComputeBackendExecution("/repo", { computeBackend: "modal" }, async (execution) => {
      const lines = [];
      await assert.rejects(
        () => runBackendToolSmokeTest({ cwd: "/repo", timeoutSeconds: 5 }, execution, (line) => lines.push(line)),
        /One-shot write-then-read verification inside a single execution failed/,
      );
      assert.deepEqual(lines, [`tool_adapter=skipped (${ONE_SHOT_SMOKE_NOTE})`]);
    }, { runner: lossy.runner });

    // Stateful backends keep the full surface, so the change is scoped to one-shot kinds.
    const pod = createFakeRunner(async () => ({ exitCode: 0, stdout: "ok\n" }));
    await withEnv({ RUNPOD_POD_ID: "pod42" }, async () => {
      const execution = resolveComputeBackendExecution("/repo", { computeBackend: "runpod-pod" }, { runner: pod.runner, fetch: async () => new Response(RUNPOD_POD_JSON, { status: 200 }) });
      assert.equal(execution.backend.capabilities.oneShot, false);
      for (const surface of ["readOperations", "writeOperations", "editOperations", "lsOperations", "findOperations", "grepOperations"]) {
        assert.equal(typeof execution[surface], "object", `runpod-pod must keep ${surface}`);
      }
      await execution.teardown();
    });

    // The agent is told the same thing in its system prompt note.
    const note = buildComputeBackendSystemPromptNote("/repo", { computeBackend: "modal" });
    assert.match(note, /modal is a one-shot backend: only bash and user `!` commands are routed through it/);
    assert.match(note, /Read, write, edit, ls, grep, and find operate on the local workspace/);
    assert.ok(!note.includes("Bash, read, write, edit, ls, grep, and find are routed through the compute backend"));
  });
});

test("parallels share args honor the configured workspace mount mode", async () => {
  assert.deepEqual(
    buildParallelsShareArgs("clone-1", "share", "/Users/me/repo", "ro"),
    ["set", "clone-1", "--shf-host-add", "share", "--path", "/Users/me/repo", "--mode", "ro"],
  );
  const { runner, calls } = createFakeRunner(async (_executable, args) => {
    if (args[0] === "exec") return { exitCode: 0, stdout: "ok" };
    return { exitCode: 0 };
  });
  const backend = createExecutionBackend("/Users/me/repo", {
    computeBackend: "parallels-vm",
    parallelsTemplateName: "tpl",
    computeDefaults: { workspaceMountMode: "ro" },
  }, { runner }, "parallels-vm");
  await backend.stageWorkspace({ localPath: "/Users/me/repo", sessionId: "s" });
  const share = calls.find((call) => call.args.includes("--shf-host-add"));
  assert.equal(share.args.at(-2), "--mode");
  assert.equal(share.args.at(-1), "ro");

  const before = calls.length;
  const explicit = createParallelsBackend({ sourceKind: "template", sourceName: "tpl", clonePrefix: "p", mountMode: "ro", runner, sleep: async () => {} });
  await explicit.stageWorkspace({ localPath: "/Users/me/repo", sessionId: "rw", mountMode: "rw" });
  const perRequest = calls.slice(before).find((call) => call.args.includes("--shf-host-add"));
  assert.equal(perRequest.args.at(-1), "rw");
});

test("COMPUTE_BACKEND_KINDS is derived from the metadata record keys", () => {
  assert.deepEqual([...COMPUTE_BACKEND_KINDS], [
    "host",
    "sandbox-runtime",
    "docker",
    "parallels-vm",
    "modal",
    "runpod-pod",
    "runpod-serverless",
    "cloudflare-sandbox",
    "vercel-sandbox",
  ]);
  assert.equal(new Set(COMPUTE_BACKEND_KINDS).size, COMPUTE_BACKEND_KINDS.length);
});

test("local kinds route through the contract adapters with byte-identical docker args", async () => {
  const settings = { computeBackend: "docker", dockerImage: "python:3.12-slim", computeDefaults: { workspaceMountMode: "ro", networkPolicy: "deny-all" } };
  const { runner, calls } = createFakeRunner(async () => ({ exitCode: 0, stdout: "/workspace/pkg\n" }));
  const execution = resolveComputeBackendExecution("/repo", settings, { runner });
  assert.equal(execution.kind, "docker");
  assert.equal(execution.backend.kind, "docker");
  const chunks = [];
  const result = await execution.bashOperations.exec("pwd", "/repo/pkg", { onData: (chunk) => chunks.push(chunk.toString()) });
  assert.equal(result.exitCode, 0);
  assert.deepEqual(chunks, ["/workspace/pkg\n"]);
  assert.deepEqual(calls[0].args, ["info"]);
  assert.deepEqual(calls[1].args, buildDockerToolRunArgs("/repo", settings, "/repo/pkg", "pwd"));
  await execution.teardown();

  const unreachable = resolveComputeBackendExecution("/repo", settings, { runner: async () => ({ exitCode: 1, stdout: "", stderr: "" }) });
  await assert.rejects(() => unreachable.bashOperations.exec("pwd", "/repo", { onData: () => {} }), /Docker daemon is not reachable/);

  const parallels = resolveComputeBackendExecution("/repo", { computeBackend: "parallels-vm", parallelsTemplateName: "tpl" }, { runner });
  assert.equal(parallels.backend.capabilities.snapshot, true);
  assert.equal(parallels.backend.capabilities.restore, true);
  assert.equal(typeof parallels.teardown, "function");
  await parallels.teardown();

  const host = resolveComputeBackendExecution("/repo", { computeBackend: "host" });
  assert.equal(host.backend, undefined);
  await host.teardown();
});

test("redactSecrets hides bearer tokens and configured provider secrets", () => {
  withEnv({ RUNPOD_API_KEY: "rpa_abcdefghijk" }, () => {
    assert.equal(redactSecrets("key rpa_abcdefghijk used"), "key [REDACTED] used");
    assert.equal(redactSecrets("Authorization: Bearer abcdefghijklmnop"), "Authorization: Bearer [REDACTED]");
  });
  withEnv({ RUNPOD_API_KEY: undefined, MODAL_TOKEN_SECRET: undefined }, () => {
    assert.equal(redactSecrets("remote key rpa_ZZZZZZZZZZZZZZZZZZZZZZZZ echoed"), "remote key [REDACTED] echoed");
    assert.equal(redactSecrets("id ak-ABCDEFGHIJKLMNOP secret as-QRSTUVWXYZ123456"), "id [REDACTED] secret [REDACTED]");
    assert.equal(
      redactSecrets("RUNPOD_API_KEY=whatever-shape MODAL_TOKEN_SECRET='quoted value' VERCEL_TOKEN=\"dq\""),
      "RUNPOD_API_KEY=[REDACTED] MODAL_TOKEN_SECRET=[REDACTED] VERCEL_TOKEN=[REDACTED]",
    );
    const pem = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----";
    assert.equal(redactSecrets(`cat ~/.ssh/id_ed25519\n${pem}\ndone`), "cat ~/.ssh/id_ed25519\n[REDACTED PRIVATE KEY]\ndone");
    assert.equal(redactSecrets("plain output stays"), "plain output stays");
  });
});

test("redacting sink catches a secret split across streamed chunks", () => {
  withEnv({ RUNPOD_API_KEY: "fake-distinctive-secret-9f8e7d6c" }, () => {
    const chunks = [];
    const sink = createRedactingSink((chunk) => chunks.push(chunk.toString("utf8")));
    sink.write(Buffer.from("token=fake-distinctive-"));
    assert.deepEqual(chunks, []);
    sink.write(Buffer.from("secret-9f8e7d6c\npartial trailing"));
    assert.deepEqual(chunks, ["token=[REDACTED]\n"]);
    sink.end();
    assert.deepEqual(chunks, ["token=[REDACTED]\n", "partial trailing"]);
    const silent = createRedactingSink(undefined);
    silent.write(Buffer.from("ignored"));
    silent.end();
  });
});

const FAKE_PEM_BODY = ["b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW", "QyNTUxOQAAACBmYWtlIGtleSBib2R5IGZvciB0ZXN0cyBvbmx5AAAAAAAAAAAAAAAAAAA"];
const FAKE_PEM = `-----BEGIN OPENSSH PRIVATE KEY-----\n${FAKE_PEM_BODY.join("\n")}\n-----END OPENSSH PRIVATE KEY-----\n`;
const UNTERMINATED_PEM = "[REDACTED PRIVATE KEY: unterminated block, body withheld]";

// Chunking strategies a producer can exhibit: one write, a line-flushing script or tty, and a
// byte-at-a-time trickle (which also splits multi-byte characters).
const CHUNKERS = {
  "one-shot": (text) => [Buffer.from(text, "utf8")],
  "per-line": (text) => text.split(/(?<=\n)/).map((line) => Buffer.from(line, "utf8")),
  "byte-at-a-time": (text) => [...Buffer.from(text, "utf8")].map((byte) => Buffer.from([byte])),
};

function collectSink(text, chunker, extraSecrets = []) {
  const chunks = [];
  const sink = createRedactingSink((chunk) => chunks.push(chunk.toString("utf8")), extraSecrets);
  for (const chunk of chunker(text)) sink.write(chunk);
  const beforeEnd = chunks.join("");
  sink.end();
  return { chunks, beforeEnd, joined: chunks.join("") };
}

test("redacting sink never flushes through an open PEM block under any chunking", () => {
  const text = `before\n./notes.md:${FAKE_PEM}after\n`;
  for (const [strategy, chunker] of Object.entries(CHUNKERS)) {
    const { joined } = collectSink(text, chunker);
    assert.equal(joined, "before\n./notes.md:[REDACTED PRIVATE KEY]\nafter\n", strategy);
  }

  // Per-line delivery: lines before the marker flow immediately, the block is held until END.
  const chunks = [];
  const sink = createRedactingSink((chunk) => chunks.push(chunk.toString("utf8")));
  sink.write(Buffer.from("before\n"));
  sink.write(Buffer.from("./notes.md:-----BEGIN OPENSSH PRIVATE KEY-----\n"));
  assert.deepEqual(chunks, ["before\n", "./notes.md:"]);
  for (const line of FAKE_PEM_BODY) sink.write(Buffer.from(`${line}\n`));
  assert.deepEqual(chunks, ["before\n", "./notes.md:"], "body lines stay held while the block is open");
  sink.write(Buffer.from("-----END OPENSSH PRIVATE KEY-----"));
  assert.deepEqual(chunks, ["before\n", "./notes.md:"], "END without a newline is still a partial line");
  sink.write(Buffer.from("\nafter\n"));
  assert.deepEqual(chunks, ["before\n", "./notes.md:", "[REDACTED PRIVATE KEY]\nafter\n"]);
  sink.end();
  assert.equal(chunks.join(""), "before\n./notes.md:[REDACTED PRIVATE KEY]\nafter\n");

  // A closed block followed by an open one: the closed block is redacted, the open one held and
  // then withheld at end() together with its body.
  const two = collectSink(`${FAKE_PEM}-----BEGIN RSA PRIVATE KEY-----\n${FAKE_PEM_BODY[0]}\n`, CHUNKERS["per-line"]);
  assert.equal(two.beforeEnd, "[REDACTED PRIVATE KEY]\n");
  assert.equal(two.joined, `[REDACTED PRIVATE KEY]\n${UNTERMINATED_PEM}\n`);

  // END arriving in the same chunk as the last body line but without its newline: the block is
  // held, then flushed as one redacted block once the newline lands.
  const crossing = [];
  const crossingSink = createRedactingSink((chunk) => crossing.push(chunk.toString("utf8")));
  crossingSink.write(Buffer.from(`-----BEGIN OPENSSH PRIVATE KEY-----\n${FAKE_PEM_BODY[0]}\n`));
  crossingSink.write(Buffer.from(`${FAKE_PEM_BODY[1]}\n-----END OPENSSH PRIVATE KEY-----`));
  assert.deepEqual(crossing, []);
  crossingSink.write(Buffer.from("\nnext\n"));
  assert.deepEqual(crossing, ["[REDACTED PRIVATE KEY]\nnext\n"]);
  crossingSink.write(Buffer.from(`${FAKE_PEM}`));
  assert.deepEqual(crossing, ["[REDACTED PRIVATE KEY]\nnext\n", "[REDACTED PRIVATE KEY]\n"], "a later block is still found after the first one closed");
  crossingSink.end();
});

test("unterminated PEM blocks are withheld with their body and ordinary output after them survives", () => {
  const marker = "-----BEGIN OPENSSH PRIVATE KEY-----";
  const cases = [
    [`${marker}\n${FAKE_PEM_BODY[0]}\n${FAKE_PEM_BODY[1]}\ndone\n`, `${UNTERMINATED_PEM}\ndone\n`],
    [`${marker}\r\n${FAKE_PEM_BODY[0]}\r\n${FAKE_PEM_BODY[1]}\r\ndone\r\n`, `${UNTERMINATED_PEM}\r\ndone\r\n`],
    [`${marker}\n${FAKE_PEM_BODY[0]}\nlog one\nlog two\nlog three\nlog four\nlog five\n`, `${UNTERMINATED_PEM}\nlog one\nlog two\nlog three\nlog four\nlog five\n`],
    [`${marker}\n${FAKE_PEM_BODY[0]}\nok\n`, `${UNTERMINATED_PEM}\nok\n`],
    [`${marker}\n${FAKE_PEM_BODY[0]}\nMIIEow`, UNTERMINATED_PEM],
    [`${marker}\n${FAKE_PEM_BODY[0]}`, UNTERMINATED_PEM],
    [`${marker}`, "[REDACTED PRIVATE KEY: unterminated block]"],
    [`${marker}\n`, "[REDACTED PRIVATE KEY: unterminated block]\n"],
    [`${marker}\nnot a body line at all\n`, "[REDACTED PRIVATE KEY: unterminated block]\nnot a body line at all\n"],
    [`${marker}\n${FAKE_PEM_BODY[0]}:trailer\n`, `[REDACTED PRIVATE KEY: unterminated block]\n${FAKE_PEM_BODY[0]}:trailer\n`],
    [`prefix ${marker}\n${FAKE_PEM_BODY[0]}\n`, `prefix ${UNTERMINATED_PEM}\n`],
    ["no marker here\n", "no marker here\n"],
    [`${FAKE_PEM}${marker}\n${FAKE_PEM_BODY[0]}\n`, `[REDACTED PRIVATE KEY]\n${UNTERMINATED_PEM}\n`],
  ];
  for (const [input, expected] of cases) {
    assert.equal(redactUnterminatedPemBlocks(redactSecrets(input)), expected, JSON.stringify(input));
  }
});

test("redacting sink withholds a never-closed PEM body at end() and at the hold cap", () => {
  // A truncated key file (END missing) followed by ordinary output, under every chunking.
  const truncated = `-----BEGIN OPENSSH PRIVATE KEY-----\n${FAKE_PEM_BODY.join("\n")}\ndone\n`;
  for (const [strategy, chunker] of Object.entries(CHUNKERS)) {
    const { beforeEnd, joined } = collectSink(truncated, chunker);
    assert.equal(beforeEnd, "", `${strategy}: nothing is emitted while the block is open`);
    assert.equal(joined, `${UNTERMINATED_PEM}\ndone\n`, strategy);
    assert.ok(!FAKE_PEM_BODY.some((line) => joined.includes(line)), `${strategy}: a body line survived`);
  }

  // The cap: filled with key-shaped base64, none of it may escape, and ordinary output appended
  // afterwards still flows.
  const chunks = [];
  const sink = createRedactingSink((chunk) => chunks.push(chunk.toString("utf8")));
  sink.write(Buffer.from("-----BEGIN RSA PRIVATE KEY-----\n"));
  const bodyLines = [];
  let written = 0;
  while (chunks.length === 0 && written < REDACTING_SINK_MAX_HELD_CHARS * 2) {
    const line = `MIIE${bodyLines.length.toString(36).padStart(6, "0")}${"QUFB".repeat(15)}\n`;
    bodyLines.push(line.trimEnd());
    sink.write(Buffer.from(line));
    written += line.length;
  }
  assert.ok(chunks.length > 0, "the held buffer is flushed once it reaches the cap");
  assert.ok(written <= REDACTING_SINK_MAX_HELD_CHARS + 128);
  assert.deepEqual(chunks, [`${UNTERMINATED_PEM}\n`], "the marker and every body line are withheld at the cap");
  sink.write(Buffer.from("later line\n"));
  assert.equal(chunks.at(-1), "later line\n", "the sink is back to per-line flushing after the forced flush");
  sink.end();
  const flushed = chunks.join("");
  assert.ok(!flushed.includes("BEGIN RSA"));
  assert.ok(!bodyLines.some((line) => flushed.includes(line)), "no key-shaped fill line escaped");

  // A long single line without a newline is bounded by the same cap.
  const single = [];
  const singleSink = createRedactingSink((chunk) => single.push(chunk.toString("utf8")));
  singleSink.write(Buffer.from("y".repeat(REDACTING_SINK_MAX_HELD_CHARS)));
  assert.equal(single.length, 1);
  singleSink.end();
});

test("redactExecutionResult withholds an unterminated PEM body like the sink and the file-tool exception keeps raw bytes", async () => {
  const truncated = `-----BEGIN OPENSSH PRIVATE KEY-----\n${FAKE_PEM_BODY.join("\n")}\ndone\n`;
  const expected = `${UNTERMINATED_PEM}\ndone\n`;
  const leaks = (text) => text.includes("BEGIN OPENSSH PRIVATE KEY") || FAKE_PEM_BODY.some((line) => text.includes(line));

  // The exported function on its own: stdout and stderr are withheld the same way, and the
  // fields that are not output are untouched.
  const direct = redactExecutionResult({ exitCode: 3, stdout: truncated, stderr: truncated, artifacts: ["out.txt"] });
  assert.equal(direct.stdout, expected);
  assert.equal(direct.stderr, expected);
  assert.ok(!leaks(direct.stdout) && !leaks(direct.stderr));
  assert.equal(direct.exitCode, 3);
  assert.deepEqual(direct.artifacts, ["out.txt"]);

  // Through the guard with redaction on: finish() and the stream agree byte for byte under
  // every chunking.
  for (const [strategy, chunker] of Object.entries(CHUNKERS)) {
    const chunks = [];
    const guard = createExecutionOutputGuard({ onData: (chunk) => chunks.push(chunk.toString("utf8")) });
    for (const chunk of chunker(truncated)) guard.onData(chunk);
    guard.end();
    const finished = guard.finish({ exitCode: 0, stdout: truncated, stderr: truncated, artifacts: [] });
    assert.equal(finished.stdout, expected, strategy);
    assert.equal(finished.stderr, expected, strategy);
    assert.equal(chunks.join(""), finished.stdout, strategy);
  }

  // The file-tool exception is unchanged: with redactOutput false neither half touches the bytes.
  const rawChunks = [];
  const off = createExecutionOutputGuard({ onData: (chunk) => rawChunks.push(chunk.toString("utf8")), redactOutput: false });
  off.onData(Buffer.from(truncated, "utf8"));
  off.end();
  const raw = off.finish({ exitCode: 0, stdout: truncated, stderr: truncated, artifacts: [] });
  assert.equal(raw.stdout, truncated);
  assert.equal(raw.stderr, truncated);
  assert.equal(rawChunks.join(""), truncated);

  // On host through the contract adapter with a real shell: the returned result reads the same
  // as the stream, on stdout and on stderr. The real process runner is kept but the shell is
  // not a login shell, because a login profile may write to stderr and this asserts stderr exactly.
  const keyDir = mkdtempSync(join(tmpdir(), "grclanker-result-"));
  const keyPath = join(keyDir, "id_ed25519.partial");
  writeFileSync(keyPath, truncated.slice(0, truncated.length - "done\n".length));
  try {
    const processRunner = createProcessCommandRunner();
    const host = createHostBackend({
      runner: (executable, args, options) => processRunner(executable, args.map((arg) => (arg === "-lc" ? "-c" : arg)), options),
    });
    const stdoutChunks = [];
    const stdoutResult = await host.exec({
      sessionId: "s",
      command: [`cat ${quoteForBash(keyPath)}; printf 'done\\n'`],
      cwd: keyDir,
      onData: (chunk) => stdoutChunks.push(chunk.toString("utf8")),
    });
    assert.equal(stdoutResult.exitCode, 0);
    assert.equal(stdoutResult.stdout, expected);
    assert.equal(stdoutChunks.join(""), expected);
    assert.equal(stdoutResult.stderr, "");

    const stderrChunks = [];
    const stderrResult = await host.exec({
      sessionId: "s",
      command: [`cat ${quoteForBash(keyPath)} >&2; printf 'done\\n' >&2`],
      cwd: keyDir,
      onData: (chunk) => stderrChunks.push(chunk.toString("utf8")),
    });
    assert.equal(stderrResult.exitCode, 0);
    assert.equal(stderrResult.stderr, expected);
    assert.equal(stderrChunks.join(""), expected);
    assert.equal(stderrResult.stdout, "");

    // The runtime file tools read through capture() with the guard off, so a truncated key file
    // still round-trips its raw bytes for the edit tool.
    const { runner } = createFakeRunner(async (_executable, args) => {
      if (args[0] === "info") return { exitCode: 0, stdout: "ok" };
      return { exitCode: 0, stdout: truncated };
    });
    await withComputeBackendExecution("/repo", { computeBackend: "docker" }, async (execution) => {
      const roundTrip = (await execution.editOperations.readFile("/repo/id_ed25519.partial")).toString("utf8");
      assert.equal(roundTrip, truncated);
      const streamed = [];
      await execution.bashOperations.exec("cat id_ed25519.partial", "/repo", { onData: (chunk) => streamed.push(chunk.toString("utf8")) });
      assert.equal(streamed.join(""), expected);
    }, { runner });
  } finally {
    rmSync(keyDir, { recursive: true, force: true });
  }
});

test("redacting sink holds a dangling Bearer for the token on the next line", () => {
  const chunks = [];
  const sink = createRedactingSink((chunk) => chunks.push(chunk.toString("utf8")));
  sink.write(Buffer.from("Authorization: Bearer\n"));
  assert.deepEqual(chunks, ["Authorization: "], "a line ending in Bearer waits for the next line");
  sink.write(Buffer.from("abcdefghijklmnopqrstuvwxyz\n"));
  assert.deepEqual(chunks, ["Authorization: ", "Bearer\n[REDACTED]\n"], "the token on the next line is redacted, the whitespace is kept");
  sink.write(Buffer.from("plain\nBearer   "));
  sink.end();
  assert.equal(chunks.join(""), "Authorization: Bearer\n[REDACTED]\nplain\nBearer   ");

  for (const [strategy, chunker] of Object.entries(CHUNKERS)) {
    const { joined } = collectSink("Authorization: Bearer\nabcdefghijklmnopqrstuvwxyz\ndone\n", chunker);
    assert.equal(joined, "Authorization: Bearer\n[REDACTED]\ndone\n", strategy);
  }
});

test("every backend output path redacts credentials echoed by the remote under every chunking", async () => {
  const envSecret = "fake-distinctive-secret-9f8e7d6c";
  const remoteOnlySecret = "rpa_REMOTEONLYKEY0123456789ABCDEF";
  const leak = `token=${envSecret} remote=${remoteOnlySecret} café\n${FAKE_PEM}tail without newline ${envSecret}`;
  const leaks = (text) => text.includes(envSecret)
    || text.includes(remoteOnlySecret)
    || text.includes("BEGIN OPENSSH PRIVATE KEY")
    || FAKE_PEM_BODY.some((line) => text.includes(line));
  const assertClean = (label, ...texts) => {
    for (const text of texts) {
      assert.ok(!leaks(text), `${label} surfaced a credential: ${text}`);
    }
    assert.ok(texts.some((text) => text.includes("[REDACTED]")), `${label} produced no redaction marker`);
  };
  const expectedStream = `token=[REDACTED] remote=[REDACTED] café\n[REDACTED PRIVATE KEY]\ntail without newline [REDACTED]`;

  await withEnv({
    RUNPOD_API_KEY: envSecret,
    RUNPOD_POD_ID: "pod42",
    RUNPOD_ENDPOINT_ID: "ep123",
    MODAL_TOKEN_ID: "ak-FAKEID0123456789ABCD",
    MODAL_TOKEN_SECRET: "as-FAKESECRET0123456789",
  }, async () => {
    const makeLeakyRunner = (chunker) => async (_executable, args, options = {}) => {
      if (options.onData) {
        for (const chunk of chunker(leak)) options.onData(chunk);
      }
      if (args[0] === "exec" && String(args.at(-1)).includes("test -d")) return { exitCode: 0, stdout: "ok", stderr: "" };
      if (["info", "--version", "list"].includes(args[0])) return { exitCode: 0, stdout: "ok", stderr: "" };
      return { exitCode: 0, stdout: leak, stderr: `stderr ${envSecret}\n` };
    };
    const leakyFetch = async (url) => {
      if (url.includes("/pods/")) return new Response(RUNPOD_POD_JSON, { status: 200 });
      if (url.endsWith("/run")) return new Response(JSON.stringify({ id: "job-1", status: "IN_QUEUE" }), { status: 200 });
      if (url.includes("/status/")) {
        return new Response(JSON.stringify({
          id: "job-1",
          status: "COMPLETED",
          output: { exitCode: 0, stdout: leak, stderr: `stderr ${envSecret}` },
        }), { status: 200 });
      }
      return new Response("{}", { status: 200 });
    };

    const runExec = async (label, backend) => {
      const chunks = [];
      const staged = await backend.stageWorkspace({ localPath: "/repo", sessionId: "leak" });
      const result = await backend.exec({
        sessionId: "leak",
        command: ["env"],
        cwd: staged.remotePath,
        onData: (chunk) => chunks.push(chunk.toString("utf8")),
      });
      const streamed = chunks.join("");
      assertClean(label, streamed, result.stdout, result.stderr);
      assert.ok(streamed.includes("café"), `${label} corrupted a multi-byte character`);
      await backend.teardown("leak");
      return streamed;
    };

    for (const [strategy, chunker] of Object.entries(CHUNKERS)) {
      const runner = makeLeakyRunner(chunker);
      for (const kind of ["docker", "parallels-vm", "modal", "runpod-pod"]) {
        const settings = { computeBackend: kind, parallelsTemplateName: "tpl" };
        const streamed = await runExec(`${kind} (${strategy})`, createExecutionBackend("/repo", settings, { runner, fetch: leakyFetch }, kind));
        assert.equal(streamed, expectedStream, `${kind} (${strategy})`);
      }
      const sandboxStream = await runExec(
        `sandbox-runtime (${strategy})`,
        createSandboxRuntimeBackend({ runner, wrapCommand: async (command) => command }),
      );
      assert.equal(sandboxStream, expectedStream, `sandbox-runtime (${strategy})`);

      const runtimeChunks = [];
      await withComputeBackendExecution("/repo", { computeBackend: "docker" }, async (execution) => {
        await execution.bashOperations.exec("env", "/repo", { onData: (chunk) => runtimeChunks.push(chunk.toString("utf8")) });
        assert.equal(runtimeChunks.join(""), expectedStream, `docker runtime (${strategy})`);
        // File content round-trips through the edit tool, so reads keep the raw bytes rather
        // than writing a redaction marker back into the file.
        const roundTrip = (await execution.editOperations.readFile("/repo/.env")).toString("utf8");
        assert.equal(roundTrip, leak);
      }, { runner });
    }

    // Serverless output arrives whole from /status, so there is a single delivery to check.
    const serverless = await runExec(
      "runpod-serverless",
      createExecutionBackend("/repo", { computeBackend: "runpod-serverless" }, { fetch: leakyFetch }, "runpod-serverless"),
    );
    assert.equal(serverless, `${expectedStream}stderr [REDACTED]`);

    const host = resolveComputeBackendExecution(tmpdir(), { computeBackend: "host" });
    const hostChunks = [];
    const hostResult = await host.bashOperations.exec(
      "printf '%s\\n' \"key=$RUNPOD_API_KEY\"; printf 'no newline %s' \"$RUNPOD_API_KEY\"",
      tmpdir(),
      { onData: (chunk) => hostChunks.push(chunk.toString("utf8")) },
    );
    assert.equal(hostResult.exitCode, 0);
    assertClean("host", hostChunks.join(""));
    assert.equal(hostChunks.join(""), "key=[REDACTED]\nno newline [REDACTED]");

    // A real shell streaming a key file line at a time, the way a tty-attached or line-flushing
    // producer would deliver it.
    const keyDir = mkdtempSync(join(tmpdir(), "grclanker-pem-"));
    const keyPath = join(keyDir, "id_ed25519");
    writeFileSync(keyPath, FAKE_PEM);
    try {
      const pemChunks = [];
      const pemResult = await host.bashOperations.exec(
        `while IFS= read -r l; do printf '%s\\n' "$l"; sleep 0.05; done < ${quoteForBash(keyPath)}; printf 'done\\n'`,
        keyDir,
        { onData: (chunk) => pemChunks.push(chunk.toString("utf8")) },
      );
      assert.equal(pemResult.exitCode, 0);
      const streamed = pemChunks.join("");
      assert.ok(!streamed.includes("BEGIN OPENSSH PRIVATE KEY"), streamed);
      assert.ok(!FAKE_PEM_BODY.some((line) => streamed.includes(line)), streamed);
      assert.equal(streamed, "[REDACTED PRIVATE KEY]\ndone\n");

      // A truncated key file (END missing) read in one go: the block never closes, so the marker
      // and body are withheld at the end of the command and the output after them survives.
      const truncatedPath = join(keyDir, "id_ed25519.partial");
      writeFileSync(truncatedPath, `-----BEGIN OPENSSH PRIVATE KEY-----\n${FAKE_PEM_BODY.join("\n")}\n`);
      const truncatedChunks = [];
      const truncatedResult = await host.bashOperations.exec(
        `cat ${quoteForBash(truncatedPath)}; printf 'done\\n'`,
        keyDir,
        { onData: (chunk) => truncatedChunks.push(chunk.toString("utf8")) },
      );
      assert.equal(truncatedResult.exitCode, 0);
      const truncatedStream = truncatedChunks.join("");
      assert.ok(!truncatedStream.includes("BEGIN OPENSSH PRIVATE KEY"), truncatedStream);
      assert.ok(!FAKE_PEM_BODY.some((line) => truncatedStream.includes(line)), truncatedStream);
      assert.equal(truncatedStream, `${UNTERMINATED_PEM}\ndone\n`);

      // The runtime's own command timeout killing a key mid-stream: END never arrives, the sink is
      // ended on the throw path, and neither the header nor any body line reaches the stream.
      const longBody = Array.from({ length: 8 }, (_, index) => `MIIEowIBAAKCAQEA${index}FAKEKEYBODYLINE${"QUFB".repeat(10)}`);
      const longKeyPath = join(keyDir, "id_rsa");
      writeFileSync(longKeyPath, `-----BEGIN RSA PRIVATE KEY-----\n${longBody.join("\n")}\n-----END RSA PRIVATE KEY-----\n`);
      const killedChunks = [];
      await assert.rejects(
        host.bashOperations.exec(
          `while IFS= read -r l; do printf '%s\\n' "$l"; sleep 0.2; done < ${quoteForBash(longKeyPath)}`,
          keyDir,
          { timeout: 1, onData: (chunk) => killedChunks.push(chunk.toString("utf8")) },
        ),
        /timeout:1/,
      );
      const killedStream = killedChunks.join("");
      assert.ok(!killedStream.includes("BEGIN RSA PRIVATE KEY"), killedStream);
      assert.ok(!longBody.some((line) => killedStream.includes(line)), killedStream);
      assert.ok(!killedStream.includes("MIIEow"), killedStream);
      assert.equal(killedStream, `${UNTERMINATED_PEM}\n`);
    } finally {
      rmSync(keyDir, { recursive: true, force: true });
    }
  });
});

test("redactErrorMessage scrubs embedded URL, bearer, session, API key, and HTML shapes", () => {
  const html = "<html><body><h1>502 Bad Gateway</h1><pre>Authorization: Bearer CANARY-BEARER-u1; Cookie: session=CANARY-SESSION-u1; X-Api-Key: CANARY-APIKEY-u1</pre></body></html>";
  const DOCTYPE_HTML = "<!DOCTYPE html>\n<html lang=\"en\"><body>CANARY-DOC-u1</body></html>";
  const cases = [
    [
      "Re-authorize at https://example.invalid/callback?access_token=CANARY-URLTOKEN-u1&state=x now",
      "Re-authorize at https://example.invalid/callback?access_token=[REDACTED]&state=[REDACTED] now",
    ],
    ["see https://host/p#CANARY-FRAGMENT-u1 and https://host/q?CANARY-BAREQUERY-u1", "see https://host/p#[REDACTED] and https://host/q?[REDACTED]"],
    ["https://user:CANARY-PASSWORD-u1@host/path?x=1", "https://[REDACTED]@host/path?x=[REDACTED]"],
    ["Authorization: Bearer CANARY-BEARER-u1", "Authorization: Bearer [REDACTED]"],
    ["Cookie: session=CANARY-SESSION-u1; other=1</pre>", "Cookie: [REDACTED]</pre>"],
    ["Set-Cookie: sid=CANARY-SESSION-u1; Path=/; HttpOnly", "Set-Cookie: [REDACTED]"],
    ["X-Api-Key: CANARY-APIKEY-u1", "X-Api-Key: [REDACTED]"],
    ["api_key=CANARY-APIKEY-u1 session_id=CANARY-SESSION-u1", "api_key=[REDACTED] session_id=[REDACTED]"],
    [
      "{\"session\":\"CANARY-SESSION-u1\",\"token\":\"CANARY-TOKEN-u1\",\"cookie\":\"CANARY-COOKIE-u1\"}",
      "{\"session\":\"[REDACTED]\",\"token\":\"[REDACTED]\",\"cookie\":\"[REDACTED]\"}",
    ],
    [`upstream said: ${html}`, `upstream said: [HTML document withheld (${html.length} chars)]`],
    [`${DOCTYPE_HTML} trailing`, `[HTML document withheld (${DOCTYPE_HTML.length} chars)] trailing`],
    [`Could not prepare /workspace/s on the pod. -----BEGIN RSA PRIVATE KEY-----\n${FAKE_PEM_BODY[0]}`, `Could not prepare /workspace/s on the pod. ${UNTERMINATED_PEM}`],
    // Ordinary text survives: a documentation URL without a query, a short value, prose.
    ["see https://docs.runpod.io/serverless/endpoints/send-requests; token: 3; session count 4", "see https://docs.runpod.io/serverless/endpoints/send-requests; token: 3; session count 4"],
  ];
  for (const [input, expected] of cases) {
    assert.equal(redactErrorMessage(input), expected);
    assert.ok(!/CANARY-[A-Z]+-u1/.test(redactErrorMessage(input)), input);
  }
  // Command output keeps HTML (it may be the legitimate result of the command) but the same
  // header, cookie, and URL shapes are scrubbed inside it.
  assert.equal(
    redactSecrets(`${html} https://example.invalid/cb?access_token=CANARY-URLTOKEN-u1`),
    "<html><body><h1>502 Bad Gateway</h1><pre>Authorization: Bearer [REDACTED]; Cookie: [REDACTED]</pre></body></html> https://example.invalid/cb?access_token=[REDACTED]",
  );
  // The constructor is the choke point: a subclass message and a message with our own markers
  // both come out scrubbed, and scrubbing is idempotent.
  const thrown = new ExecutionBackendError(`lookup failed: ${html} at https://x/cb?access_token=CANARY-URLTOKEN-u1`);
  assert.equal(thrown.message, `Compute backend error: lookup failed: [HTML document withheld (${html.length} chars)] at https://x/cb?access_token=[REDACTED]`);
  assert.equal(redactErrorMessage(thrown.message), thrown.message);
  const timeout = new ExecutionBackendTimeoutError("runpod-serverless", "job at https://x/status?token=CANARY-URLTOKEN-u1", 5000);
  assert.equal(timeout.message, "Compute backend error: runpod-serverless timed out after 5s: job at https://x/status?token=[REDACTED]");

  // JSON bodies contribute message-bearing fields only; other keys are named, never serialized.
  assert.equal(summarizeJsonBody({ error: "Forbidden. Re-authorize at https://x/cb?access_token=t" }), "error: Forbidden. Re-authorize at https://x/cb?access_token=t");
  assert.equal(summarizeJsonBody({ error: { message: "nested", code: 7 } }), "error: message: nested");
  assert.equal(summarizeJsonBody({ upstream: html, session: "CANARY-SESSION-u1" }), "JSON body with keys upstream, session");
  assert.equal(summarizeJsonBody([1, 2, 3]), "JSON array with 3 entries");
  assert.equal(summarizeJsonBody(undefined), "no detail");
  assert.equal(summarizeJsonBody({}), "empty JSON body");
  assert.equal(summarizeJsonBody(`${"x".repeat(500)}`), `${"x".repeat(400)}... (500 chars)`);
  assert.equal(describeEndpoint("https://api.runpod.ai/v2/ep123/status/job-1?token=CANARY-URLTOKEN-u1#frag"), "api.runpod.ai/v2/ep123/status/job-1");
  assert.equal(describeEndpoint("not a url"), "the provider endpoint");
});

// The rule 9 error-path sweep: every provider surface, failing with every body shape the sweep
// used, observed on every channel the runtime surfaces (thrown message, result.stdout,
// result.stderr, streamed chunks, console). No canary may reach any of them.
test("provider error bodies never reach thrown messages, results, streams, or logs on any surface", async () => {
  const canary = (name) => `CANARY-${name}-sweep`;
  const CANARY_PATTERN = /CANARY-[A-Z]+-sweep/;
  const html = `<html><body><h1>502 Bad Gateway</h1><pre>Authorization: Bearer ${canary("BEARER")}; Cookie: session=${canary("SESSION")}; X-Api-Key: ${canary("APIKEY")}</pre></body></html>`;
  const tokenUrl = `https://example.invalid/callback?access_token=${canary("URLTOKEN")}&state=x`;
  const forbiddenJson = JSON.stringify({ error: `Forbidden. Re-authorize at ${tokenUrl}` });
  const urlLine = `worker rejected: re-authorize at ${tokenUrl}\n`;

  const HTTP_SHAPES = {
    "502-html": () => new Response(html, { status: 502, headers: { "content-type": "text/html; charset=utf-8" } }),
    "403-json-url": () => new Response(forbiddenJson, { status: 403, headers: { "content-type": "application/json" } }),
    "200-html": () => new Response(html, { status: 200, headers: { "content-type": "text/html" } }),
  };
  const STDERR_SHAPES = { "html-stderr": `${html}\n`, "url-stderr": urlLine };

  const consoleLines = [];
  const original = { log: console.log, error: console.error, warn: console.warn };
  for (const method of Object.keys(original)) {
    console[method] = (...args) => consoleLines.push(args.map(String).join(" "));
  }

  const rows = [];
  // Runs one surface and asserts every channel is canary-free; returns the channels for callers
  // that also want to pin the exact message.
  const observe = async (backend, surface, shape, action) => {
    const chunks = [];
    const channels = { thrown: "", stdout: "", stderr: "", streamed: "", logs: "" };
    try {
      const result = await action((chunk) => chunks.push(chunk.toString("utf8")));
      channels.stdout = result?.stdout ?? "";
      channels.stderr = result?.stderr ?? "";
    } catch (error) {
      channels.thrown = `${error.name}: ${error.message}`;
    }
    channels.streamed = chunks.join("");
    channels.logs = consoleLines.splice(0).join("\n");
    const label = `${backend} ${surface} ${shape}`;
    for (const [channel, text] of Object.entries(channels)) {
      const hit = CANARY_PATTERN.exec(text);
      assert.equal(hit, null, `${label}: ${channel} carried ${hit?.[0]}: ${text}`);
    }
    assert.ok(!channels.thrown.startsWith("SyntaxError"), `${label}: raw parse error escaped: ${channels.thrown}`);
    rows.push({ backend, surface, shape, outcome: channels.thrown ? "thrown" : "returned" });
    return channels;
  };

  try {
    await withEnv({
      RUNPOD_API_KEY: "fake-runpod-key-0123456789",
      RUNPOD_POD_ID: "pod42",
      RUNPOD_ENDPOINT_ID: "ep123",
      MODAL_TOKEN_ID: "ak-FAKEID0123456789ABCD",
      MODAL_TOKEN_SECRET: "as-FAKESECRET0123456789",
    }, async () => {
      const serverlessFetch = (failing, shape, jobOverride) => async (url) => {
        if (failing === "/health" && url.endsWith("/health")) return HTTP_SHAPES[shape]();
        if (url.endsWith("/health")) return new Response("{}", { status: 200 });
        if (failing === "/run" && url.endsWith("/run")) return HTTP_SHAPES[shape]();
        if (url.endsWith("/run")) return new Response(JSON.stringify({ id: "job-1", status: "IN_QUEUE" }), { status: 200 });
        if (url.includes("/status/")) {
          if (jobOverride) return new Response(JSON.stringify(jobOverride), { status: 200 });
          return HTTP_SHAPES[shape]();
        }
        if (url.includes("/cancel/")) return failing === "/cancel" ? HTTP_SHAPES["502-html"]() : new Response("{}", { status: 200 });
        throw new Error(`unexpected url ${url}`);
      };
      const serverless = (fetch) => createRunpodServerlessBackend({ fetch, sleep: async () => {}, pollIntervalMs: 0 });
      const execServerless = (fetch) => (onData) => serverless(fetch).exec({ sessionId: "s", command: ["env"], cwd: "/workspace", onData });

      // RunPod serverless HTTP surfaces, three shapes each.
      for (const shape of Object.keys(HTTP_SHAPES)) {
        const health = await observe("runpod-serverless", "GET /health", shape, () => serverless(serverlessFetch("/health", shape)).healthcheck());
        assert.match(health.thrown, /^ExecutionBackendError: Compute backend error: RunPod endpoint health check/);
        await observe("runpod-serverless", "POST /run", shape, execServerless(serverlessFetch("/run", shape)));
        await observe("runpod-serverless", "GET /status (poll)", shape, execServerless(serverlessFetch("/status", shape)));
      }
      const health502 = await observe("runpod-serverless", "GET /health", "502-html (message)", () => serverless(serverlessFetch("/health", "502-html")).healthcheck());
      assert.equal(
        health502.thrown,
        `ExecutionBackendError: Compute backend error: RunPod endpoint health check failed with HTTP 502 from api.runpod.ai/v2/ep123/health: non-JSON text/html body (${Buffer.byteLength(html)} bytes) withheld`,
      );
      const health403 = await observe("runpod-serverless", "GET /health", "403-json-url (message)", () => serverless(serverlessFetch("/health", "403-json-url")).healthcheck());
      assert.equal(
        health403.thrown,
        "ExecutionBackendError: Compute backend error: RunPod endpoint health check failed with HTTP 403 from api.runpod.ai/v2/ep123/health: error: Forbidden. Re-authorize at https://example.invalid/callback?access_token=[REDACTED]&state=[REDACTED]",
      );
      const health200 = await observe("runpod-serverless", "GET /health", "200-html (message)", () => serverless(serverlessFetch("/health", "200-html")).healthcheck());
      assert.equal(
        health200.thrown,
        `ExecutionBackendError: Compute backend error: RunPod endpoint health check returned HTTP 200 from api.runpod.ai/v2/ep123/health with a non-JSON text/html body (${Buffer.byteLength(html)} bytes) withheld; expected JSON.`,
      );

      // Job-level shapes on the status poll: FAILED with a URL string, FAILED with an object
      // holding the HTML (as a message field and as an unknown field), COMPLETED with worker
      // stderr carrying both, and a 403 status followed by a 502 cancel.
      const failedUrl = await observe("runpod-serverless", "GET /status (poll)", "FAILED error string with URL", execServerless(
        serverlessFetch("/status", "200-html", { id: "job-1", status: "FAILED", error: urlLine.trim() }),
      ));
      assert.equal(
        failedUrl.thrown,
        "ExecutionBackendError: Compute backend error: RunPod job job-1 ended with status FAILED. worker rejected: re-authorize at https://example.invalid/callback?access_token=[REDACTED]&state=[REDACTED]",
      );
      const failedHtmlMessage = await observe("runpod-serverless", "GET /status (poll)", "FAILED error object with HTML message", execServerless(
        serverlessFetch("/status", "200-html", { id: "job-1", status: "FAILED", error: { message: html, code: 502 } }),
      ));
      assert.equal(
        failedHtmlMessage.thrown,
        `ExecutionBackendError: Compute backend error: RunPod job job-1 ended with status FAILED. message: [HTML document withheld (${html.length} chars)]`,
      );
      const failedHtmlField = await observe("runpod-serverless", "GET /status (poll)", "FAILED error object with HTML in an unknown field", execServerless(
        serverlessFetch("/status", "200-html", { id: "job-1", status: "FAILED", error: { upstream: html, session: canary("SESSION") } }),
      ));
      assert.equal(failedHtmlField.thrown, "ExecutionBackendError: Compute backend error: RunPod job job-1 ended with status FAILED. JSON body with keys upstream, session");
      const completed = await observe("runpod-serverless", "GET /status (poll)", "COMPLETED worker stderr with HTML and URL", execServerless(
        serverlessFetch("/status", "200-html", { id: "job-1", status: "COMPLETED", output: { exitCode: 1, stdout: `${html}\n`, stderr: urlLine } }),
      ));
      assert.equal(completed.stdout, "<html><body><h1>502 Bad Gateway</h1><pre>Authorization: Bearer [REDACTED]; Cookie: [REDACTED]</pre></body></html>\n");
      assert.equal(completed.stderr, "worker rejected: re-authorize at https://example.invalid/callback?access_token=[REDACTED]&state=[REDACTED]\n");
      assert.equal(completed.streamed, completed.stdout + completed.stderr);
      const cancelAfterStatus = await observe("runpod-serverless", "GET /status 403 then POST /cancel 502", "cancel-on-error", execServerless(
        async (url) => (url.includes("/cancel/") ? HTTP_SHAPES["502-html"]() : serverlessFetch("/status", "403-json-url")(url)),
      ));
      assert.match(cancelAfterStatus.thrown, /RunPod job status failed with HTTP 403/);

      // RunPod pod: GET /pods/{podId} from all three entry points, then ssh and scp stderr.
      const podFetch = (shape) => async () => HTTP_SHAPES[shape]();
      const quietRunner = async () => ({ exitCode: 0, stdout: "", stderr: "" });
      for (const shape of Object.keys(HTTP_SHAPES)) {
        for (const [entry, run] of [
          ["healthcheck", (backend) => () => backend.healthcheck()],
          ["exec", (backend) => (onData) => backend.exec({ sessionId: "s", command: ["env"], cwd: "/workspace/s", onData })],
          ["stageWorkspace", (backend) => () => backend.stageWorkspace({ localPath: "/repo", sessionId: "s" })],
        ]) {
          const backend = createRunpodPodBackend({ fetch: podFetch(shape), runner: quietRunner });
          const channels = await observe("runpod-pod", `GET /pods/pod42 via ${entry}`, shape, run(backend));
          assert.match(channels.thrown, /^ExecutionBackendError: Compute backend error: RunPod pod pod42 lookup/);
        }
      }
      const podJsonFetch = async () => new Response(RUNPOD_POD_JSON, { status: 200 });
      const stderrRunner = (text, { failing }) => async (executable, args, options = {}) => {
        const isMkdir = executable === "ssh" && String(args.at(-1)).startsWith("mkdir");
        const isScp = executable === "scp";
        const isExec = executable === "ssh" && !isMkdir && !String(args.at(-1)).startsWith("rm -rf");
        const fails = (failing === "mkdir" && isMkdir) || (failing === "scp" && isScp) || (failing === "exec" && isExec);
        if (!fails) return { exitCode: 0, stdout: "", stderr: "" };
        options.onData?.(Buffer.from(text, "utf8"));
        return { exitCode: 1, stdout: "", stderr: text };
      };
      for (const [shape, text] of Object.entries(STDERR_SHAPES)) {
        const mkdir = await observe("runpod-pod", "ssh mkdir stderr", shape, () =>
          createRunpodPodBackend({ fetch: podJsonFetch, runner: stderrRunner(text, { failing: "mkdir" }) }).stageWorkspace({ localPath: "/repo", sessionId: "s" }));
        assert.match(mkdir.thrown, /Could not prepare \/workspace\/s on the pod\./);
        const scp = await observe("runpod-pod", "scp stderr", shape, () =>
          createRunpodPodBackend({ fetch: podJsonFetch, runner: stderrRunner(text, { failing: "scp" }) }).stageWorkspace({ localPath: "/repo", sessionId: "s" }));
        assert.match(scp.thrown, /Could not copy the workspace to the pod\./);
        const exec = await observe("runpod-pod", "ssh exec stderr", shape, (onData) =>
          createRunpodPodBackend({ fetch: podJsonFetch, runner: stderrRunner(text, { failing: "exec" }) }).exec({ sessionId: "s", command: ["env"], cwd: "/workspace/s", onData }));
        assert.ok(exec.stderr.includes("[REDACTED]"), exec.stderr);
        assert.equal(exec.streamed, exec.stderr);

        // The file tools' capture() adapter over a pod: a failing remote command's stderr becomes
        // the thrown error the read tool reports.
        const captureChannels = await observe("runpod-pod", "capture() over ssh", shape, (onData) =>
          withComputeBackendExecution("/repo", { computeBackend: "runpod-pod" }, async (execution) => {
            await execution.bashOperations.exec("env", "/repo", { onData });
            return execution.editOperations.readFile("/repo/.env");
          }, { runner: stderrRunner(text, { failing: "exec" }), fetch: podJsonFetch }));
        assert.match(captureChannels.thrown, /^ExecutionBackendError: Compute backend error: /);
      }

      // Spawned CLI backends: the provider CLI's stderr is command output and goes through the
      // guard; the same shapes must come out clean on stderr and on the stream.
      const cliRunner = (text) => async (_executable, args, options = {}) => {
        if (["info", "--version", "list"].includes(args[0])) return { exitCode: 0, stdout: "ok", stderr: "" };
        if (args[0] === "exec" && String(args.at(-1)).includes("test -d")) return { exitCode: 0, stdout: "ok", stderr: "" };
        if (["clone", "create", "set", "start", "stop", "delete", "snapshot", "snapshot-switch"].includes(args[0])) {
          return { exitCode: 0, stdout: "", stderr: "" };
        }
        options.onData?.(Buffer.from(text, "utf8"));
        return { exitCode: 1, stdout: "", stderr: text };
      };
      for (const [shape, text] of Object.entries(STDERR_SHAPES)) {
        for (const kind of ["docker", "parallels-vm", "modal"]) {
          const backend = createExecutionBackend("/repo", { computeBackend: kind, parallelsTemplateName: "tpl" }, { runner: cliRunner(text) }, kind);
          const channels = await observe(kind, "CLI stderr", shape, async (onData) => {
            const staged = await backend.stageWorkspace({ localPath: "/repo", sessionId: "s" });
            try {
              return await backend.exec({ sessionId: "s", command: ["env"], cwd: staged.remotePath, onData });
            } finally {
              await backend.teardown("s");
            }
          });
          assert.ok(channels.stderr.includes("[REDACTED]"), `${kind} ${shape}: ${channels.stderr}`);
          assert.equal(channels.streamed, channels.stderr, `${kind} ${shape}`);
        }
        const sandbox = await observe("sandbox-runtime", "CLI stderr", shape, (onData) =>
          createSandboxRuntimeBackend({ runner: cliRunner(text), wrapCommand: async (command) => command })
            .exec({ sessionId: "s", command: ["env"], cwd: "/repo", onData }));
        assert.equal(sandbox.streamed, sandbox.stderr);

        // Parallels quotes prlctl output into thrown errors on create and snapshot failures.
        const failingPrlctl = (failingVerb) => async (_executable, args, options = {}) => {
          if (args[0] === failingVerb) return { exitCode: 1, stdout: text, stderr: text };
          return cliRunner(text)(_executable, args, options);
        };
        const create = await observe("parallels-vm", "prlctl create stdout/stderr", shape, () =>
          createExecutionBackend("/repo", { computeBackend: "parallels-vm", parallelsTemplateName: "tpl" }, { runner: failingPrlctl("create") }, "parallels-vm")
            .stageWorkspace({ localPath: "/repo", sessionId: "s" }));
        assert.match(create.thrown, /Could not create disposable Parallels sandbox/);
        const snapshotBackend = createExecutionBackend("/repo", { computeBackend: "parallels-vm", parallelsTemplateName: "tpl" }, { runner: failingPrlctl("snapshot") }, "parallels-vm");
        const snapshot = await observe("parallels-vm", "prlctl snapshot stdout/stderr", shape, async () => {
          await snapshotBackend.stageWorkspace({ localPath: "/repo", sessionId: "s" });
          try {
            return await snapshotBackend.snapshot("s");
          } finally {
            await snapshotBackend.teardown("s");
          }
        });
        assert.match(snapshot.thrown, /Could not snapshot Parallels sandbox/);
      }

      // Host: a real shell writing the shapes to stderr, streamed through the guard.
      const host = resolveComputeBackendExecution(tmpdir(), { computeBackend: "host" });
      for (const [shape, text] of Object.entries(STDERR_SHAPES)) {
        const channels = await observe("host", "bash -lc stderr", shape, (onData) =>
          host.bashOperations.exec(`printf '%s' ${quoteForBash(text)} >&2; exit 1`, tmpdir(), { onData }));
        assert.ok(channels.streamed.includes("[REDACTED]"), channels.streamed);
      }
    });
  } finally {
    Object.assign(console, original);
  }

  // 17 serverless rows (3 shapes x 3 surfaces, 3 pinned messages, 4 job shapes, cancel-on-error),
  // 17 pod rows (3 shapes x 3 entry points, 2 stderr shapes x mkdir, scp, exec, capture), 12 CLI
  // rows (2 shapes x docker, parallels-vm, modal, sandbox-runtime, prlctl create, prlctl
  // snapshot), 2 host rows.
  const surfaces = new Set(rows.map((row) => `${row.backend} ${row.surface}`));
  assert.equal(rows.length, 48, `expected the full sweep table, ran ${rows.length} rows`);
  for (const backend of ["runpod-serverless", "runpod-pod", "modal", "docker", "parallels-vm", "sandbox-runtime", "host"]) {
    assert.ok(rows.some((row) => row.backend === backend), `no rows for ${backend}`);
  }
  assert.ok(surfaces.has("runpod-pod capture() over ssh"));
});

test("search caps through the contract adapters are reported instead of silently truncated", async () => {
  const rgMatch = (path, line) => JSON.stringify({ type: "match", data: { path: { text: path }, line_number: line } });
  const { runner } = createFakeRunner(async (_executable, args) => {
    const script = String(args.at(-1));
    if (args[0] === "info") return { exitCode: 0, stdout: "ok" };
    if (script.includes("printf yes")) return { exitCode: 0, stdout: "yes" };
    if (script.includes("printf dir")) return { exitCode: 0, stdout: "dir" };
    if (script.includes("rg --files")) return { exitCode: 0, stdout: "./a.md\n./b.md\n./c.md\n" };
    if (script.includes("rg '--json'")) return { exitCode: 0, stdout: `${rgMatch("./a.md", 1)}\n${rgMatch("./b.md", 2)}\n` };
    return { exitCode: 0, stdout: "" };
  });

  await withComputeBackendExecution("/repo", { computeBackend: "docker" }, async (execution) => {
    const capped = await execution.findOperations.glob("*.md", "/repo", { ignore: [], limit: 2 });
    assert.equal(capped.length, 2, "glob returns exactly the cap so Pi's find tool reports the results limit");
    const uncapped = await execution.findOperations.glob("*.md", "/repo", { ignore: [], limit: 10 });
    assert.equal(uncapped.length, 3);

    const truncated = await execution.grepOperations.searchMatches({ pattern: "x", searchPath: "/repo", limit: 1 });
    assert.equal(truncated.matches.length, 1);
    assert.equal(truncated.matchLimitReached, true);
    const complete = await execution.grepOperations.searchMatches({ pattern: "x", searchPath: "/repo", limit: 2 });
    assert.equal(complete.matches.length, 2);
    assert.equal(complete.matchLimitReached, false);
  }, { runner });
});

test("parallels mount wait reports the deadline exit as a typed timeout and destroys the clone", async () => {
  const { runner, calls } = createFakeRunner(async (_executable, args) => {
    if (args[0] === "exec") return { exitCode: 0, stdout: "missing" };
    return { exitCode: 0 };
  });
  const backend = createParallelsBackend({
    sourceKind: "template",
    sourceName: "tpl",
    clonePrefix: "p",
    workspacePathOverride: "/custom/mount",
    runner,
    sleep: async () => {},
    mountTimeoutMs: 0,
  });
  await assert.rejects(
    () => backend.stageWorkspace({ localPath: "/repo", sessionId: "s" }),
    (error) => error instanceof ExecutionBackendTimeoutError
      && /parallels-vm timed out after 0s/.test(error.message)
      && /before the mount deadline/.test(error.message)
      && /Tried: \/custom\/mount, \/media\/psf\/grclanker-workspace-repo/.test(error.message),
  );
  assert.deepEqual(calls.slice(-2).map((call) => call.args[0]), ["stop", "delete"]);
  await assert.rejects(() => backend.exec({ sessionId: "s", command: ["true"], cwd: "/x" }), /Call stageWorkspace first/);
});

test("modal credentials resolve from the environment or the CLI profile file without exposing a token value", async () => {
  const home = mkdtempSync(join(tmpdir(), "grclanker-modal-home-"));
  const profilePath = join(home, MODAL_CONFIG_FILE_NAME);
  const PROFILE_ID = "ak-FAKEPROFILEID0123456789";
  const PROFILE_SECRET = "as-FAKEPROFILESECRET0123456789";
  // Not shaped like a Modal token on purpose: only the loader's fixed-text contract, never the
  // format scrub, can keep it out of an error.
  const PLANTED = "plantedProfileSecret7Q9Z";
  const tokenValues = [PROFILE_ID, PROFILE_SECRET, PLANTED];
  const assertNoTokenValue = (text) => {
    for (const value of tokenValues) assert.ok(!text.includes(value), `token value leaked into: ${text}`);
  };
  const noEnv = { MODAL_TOKEN_ID: undefined, MODAL_TOKEN_SECRET: undefined, MODAL_PROFILE: undefined, MODAL_CONFIG_PATH: undefined };
  const settings = { computeBackend: "modal" };
  const credentialIssues = (issues) => issues.filter((issue) => !issue.startsWith("Install the modal CLI"));
  const versionRunner = () => createFakeRunner(async (_executable, args) => (
    args[0] === "--version" ? { exitCode: 0, stdout: "modal client version: 1.0\n" } : { exitCode: 0, stdout: "ok\n" }
  ));

  try {
    // Documented location: ~/.modal.toml, overridable through MODAL_CONFIG_PATH.
    assert.equal(resolveModalConfigPath({}, home), profilePath);
    assert.equal(resolveModalConfigPath({ MODAL_CONFIG_PATH: "/etc/modal/profile.toml" }, home), "/etc/modal/profile.toml");

    // 1. The documented shape written by `modal token set`, env unset: not flagged, and the
    //    healthcheck and exec paths proceed to the CLI call.
    writeFileSync(profilePath, `# written by modal token set\n[default]\ntoken_id = "${PROFILE_ID}"\ntoken_secret = "${PROFILE_SECRET}"\n`);
    await withEnv({ ...noEnv, MODAL_CONFIG_PATH: profilePath }, async () => {
      assert.deepEqual(detectModalCredentials(), { kind: "profile", path: profilePath, profile: "default" });
      assert.deepEqual(credentialIssues(getComputeBackendConfigurationIssues(settings, "modal")), []);
      const state = getComputeBackendCredentialState("modal");
      assert.equal(state.ok, true);
      assert.match(state.detail, /^Found Modal CLI profile "default" in .*\.modal\.toml\.$/);
      assertNoTokenValue(state.detail);

      const { runner, calls } = versionRunner();
      const backend = createModalBackend({ runner });
      await backend.healthcheck();
      assert.deepEqual(calls.map((call) => [call.executable, call.args[0]]), [["modal", "--version"]]);
      const result = await backend.exec({ sessionId: "p", command: ["pwd"], cwd: "/mnt/repo" });
      assert.equal(result.exitCode, 0);
      assert.equal(calls.at(-1).args[0], "shell");
      for (const call of calls) assertNoTokenValue(JSON.stringify(call.args));
    });
    // The same file is found through the home directory, not only through the override.
    assert.deepEqual(detectModalCredentials({}, home), { kind: "profile", path: profilePath, profile: "default" });

    // 2. Neither the environment nor the file: still flagged, and the CLI is never called.
    await withEnv({ ...noEnv, MODAL_CONFIG_PATH: MISSING_MODAL_CONFIG_PATH }, async () => {
      assert.equal(detectModalCredentials().kind, "missing");
      const issues = credentialIssues(getComputeBackendConfigurationIssues(settings, "modal"));
      assert.equal(issues.length, 1);
      assert.match(
        issues[0],
        /^Set MODAL_TOKEN_ID and MODAL_TOKEN_SECRET in the environment, or run `modal setup` \/ `modal token set` to write .*\.modal\.toml \(the file does not exist\)\.$/,
      );
      assert.equal(getComputeBackendCredentialState("modal").ok, false);
      const { runner, calls } = versionRunner();
      const backend = createModalBackend({ runner });
      await assert.rejects(() => backend.healthcheck(), /Set MODAL_TOKEN_ID and MODAL_TOKEN_SECRET/);
      await assert.rejects(() => backend.exec({ sessionId: "p", command: ["pwd"], cwd: "/" }), /Set MODAL_TOKEN_ID and MODAL_TOKEN_SECRET/);
      assert.equal(calls.length, 0);
    });

    // The environment alone is still enough, with or without a file.
    await withEnv({ ...noEnv, MODAL_TOKEN_ID: "ak-FAKEENVID0123456789ABC", MODAL_TOKEN_SECRET: "as-FAKEENVSECRET0123456789", MODAL_CONFIG_PATH: MISSING_MODAL_CONFIG_PATH }, () => {
      assert.deepEqual(detectModalCredentials(), { kind: "environment" });
      assert.deepEqual(credentialIssues(getComputeBackendConfigurationIssues(settings, "modal")), []);
      assert.equal(getComputeBackendCredentialState("modal").detail, "Found MODAL_TOKEN_ID, MODAL_TOKEN_SECRET in the environment.");
    });

    // Per-key resolution like the client: an environment override for one key completes a
    // profile that holds only the other.
    writeFileSync(profilePath, `[default]\ntoken_secret = "${PROFILE_SECRET}"\n`);
    await withEnv({ ...noEnv, MODAL_TOKEN_ID: "ak-FAKEENVID0123456789ABC", MODAL_CONFIG_PATH: profilePath }, () => {
      assert.equal(detectModalCredentials().kind, "profile");
    });
    await withEnv({ ...noEnv, MODAL_CONFIG_PATH: profilePath }, () => {
      const source = detectModalCredentials();
      assert.equal(source.kind, "missing");
      assert.equal(source.detail, 'profile "default" has no token_id');
    });

    // 3. Profile selection: MODAL_PROFILE, else the table marked active, else default.
    writeFileSync(profilePath, [
      "[default]",
      'loglevel = "DEBUG"',
      "",
      "[work] # activated with `modal profile activate work`",
      `token_id = '${PROFILE_ID}'`,
      `token_secret = "${PROFILE_SECRET}" # trailing comment`,
      "active = true",
      "logs_timeout = 10",
      "",
    ].join("\n"));
    await withEnv({ ...noEnv, MODAL_CONFIG_PATH: profilePath }, () => {
      assert.deepEqual(detectModalCredentials(), { kind: "profile", path: profilePath, profile: "work" });
    });
    await withEnv({ ...noEnv, MODAL_CONFIG_PATH: profilePath, MODAL_PROFILE: "default" }, () => {
      const source = detectModalCredentials();
      assert.equal(source.kind, "missing");
      assert.equal(source.detail, 'profile "default" has no token_id and token_secret');
      assertNoTokenValue(describeModalCredentialSource(source));
    });
    await withEnv({ ...noEnv, MODAL_CONFIG_PATH: profilePath, MODAL_PROFILE: "staging" }, () => {
      const source = detectModalCredentials();
      assert.equal(source.kind, "missing");
      assert.equal(source.detail, 'the file has no "staging" profile');
    });

    // 4. A malformed profile with a planted credential on the bad line: the error carries the
    //    path, the line number, and the code only, and the healthcheck never reaches the CLI.
    writeFileSync(profilePath, `[default]\ntoken_id = "${PROFILE_ID}"\ntoken_secret = ${PLANTED}\n`);
    await withEnv({ ...noEnv, MODAL_CONFIG_PATH: profilePath }, async () => {
      const source = detectModalCredentials();
      assert.equal(source.kind, "invalid");
      assert.equal(source.message, `Unable to parse Modal config file: invalid TOML in ${profilePath} at line 3 (INVALID_TOML)`);
      const issues = credentialIssues(getComputeBackendConfigurationIssues(settings, "modal"));
      assert.equal(issues.length, 1);
      assert.match(
        issues[0],
        /^Unable to parse Modal config file: invalid TOML in .*\.modal\.toml at line 3 \(INVALID_TOML\)\. Fix the file or set MODAL_TOKEN_ID and MODAL_TOKEN_SECRET in the environment\.$/,
      );
      assertNoTokenValue(issues[0]);
      assertNoTokenValue(getComputeBackendCredentialState("modal").detail);
      const { runner, calls } = versionRunner();
      const backend = createModalBackend({ runner });
      await assert.rejects(() => backend.healthcheck(), (error) => {
        assert.ok(error instanceof ExecutionBackendError);
        assert.match(error.message, /invalid TOML in .* at line 3 \(INVALID_TOML\)/);
        assertNoTokenValue(error.message);
        return true;
      });
      assert.equal(calls.length, 0);
    });

    // Other malformed shapes: a bare line carrying tokens, a duplicate table, a broken header, a duplicate key.
    for (const [text, line, code] of [
      [`[default]\n${PLANTED} ${PROFILE_SECRET}\n`, 2, "INVALID_TOML"],
      [`[default]\ntoken_id = "${PROFILE_ID}"\n[default]\ntoken_secret = "${PROFILE_SECRET}"\n`, 3, "DUPLICATE_KEY"],
      [`[default\ntoken_id = "${PROFILE_ID}"\n`, 1, "INVALID_TOML"],
      [`[default]\ntoken_id = "${PROFILE_ID}"\ntoken_id = "${PLANTED}"\n`, 3, "DUPLICATE_KEY"],
    ]) {
      assert.throws(() => parseModalProfileText(text, profilePath), (error) => {
        assert.equal(error.name, "ConfigFileError");
        assert.equal(error.message, `Unable to parse Modal config file: invalid TOML in ${profilePath} at line ${line} (${code})`);
        assertNoTokenValue(error.message);
        return true;
      });
    }

    // The parser keeps presence only; no token value is held on the parsed result.
    const parsed = parseModalProfileText(`[default]\ntoken_id = "${PROFILE_ID}"\ntoken_secret = "${PROFILE_SECRET}"\n`, profilePath);
    assert.deepEqual([...parsed.profiles.get("default").credentials].sort(), ["token_id", "token_secret"]);
    assertNoTokenValue(JSON.stringify([...parsed.profiles.entries()].map(([name, table]) => [name, [...table.credentials], table.active])));

    // 5. A read failure other than ENOENT follows the loader standard: path and errno code, no filesystem wording.
    const directoryPath = join(home, "profile-dir");
    mkdirSync(directoryPath);
    await withEnv({ ...noEnv, MODAL_CONFIG_PATH: directoryPath }, () => {
      const source = detectModalCredentials();
      assert.equal(source.kind, "invalid");
      assert.equal(source.message, `Unable to read Modal config file ${directoryPath} (EISDIR)`);
      const issues = credentialIssues(getComputeBackendConfigurationIssues(settings, "modal"));
      assert.match(issues[0], /^Unable to read Modal config file .* \(EISDIR\)\. Fix the file or set MODAL_TOKEN_ID/);
    });
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});
