import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  COMPUTE_BACKEND_KINDS,
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
  parseRunpodWorkerOutput,
} from "../dist/pi/backends/runpod.js";
import { activeComputeSessionCount } from "../dist/pi/compute-sessions.js";
import { shutdownComputeSessions } from "../dist/pi/compute-shutdown.js";
import {
  buildComputeBackendList,
  extractComputeFlag,
  formatComputeBackendList,
} from "../dist/pi/env.js";
import { createSandboxRuntimeBackend } from "../dist/pi/backends/local.js";
import {
  assertSafeSessionId,
  createRedactingSink,
  ExecutionBackendTimeoutError,
  redactSecrets,
} from "../dist/pi/execution-backend.js";
import { normalizeGrclankerSettings, readGrclankerSettings } from "../dist/pi/settings.js";

const RUNPOD_POD_JSON = JSON.stringify({
  id: "pod42",
  desiredStatus: "RUNNING",
  publicIp: "203.0.113.10",
  portMappings: { "22": 22022 },
});

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
    for (const flag of ["snapshot", "restore", "gpu", "stageWorkspace", "artifactSync", "interactive"]) {
      assert.equal(typeof backend.capabilities[flag], "boolean", `${kind}.capabilities.${flag}`);
    }
  }
  assert.equal(createExecutionBackend("/tmp/repo", settings, {}, "parallels-vm").capabilities.snapshot, true);
  assert.equal(createExecutionBackend("/tmp/repo", settings, {}, "modal").capabilities.gpu, true);
  assert.equal(createExecutionBackend("/tmp/repo", settings, {}, "docker").capabilities.gpu, false);
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

  await withEnv({ MODAL_TOKEN_ID: undefined, MODAL_TOKEN_SECRET: undefined }, async () => {
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
    assert.equal(calls[0].executable, "ssh");
    assert.equal(calls[1].executable, "scp");
    assert.ok(calls[1].args.includes("root@203.0.113.10:/workspace/sess"));

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
    assert.deepEqual(calls.map((call) => call.executable), ["ssh", "scp", "ssh"]);
    assert.match(calls[0].args.at(-1), /^mkdir -p -- '\/workspace\/sess'$/);
    assert.match(calls[2].args.at(-1), /^rm -rf -- '\/workspace\/sess'$/);
    await backend.teardown("sess");
    assert.equal(calls.length, 3);
  });
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

test("every backend output path redacts credentials echoed by the remote", async () => {
  const envSecret = "fake-distinctive-secret-9f8e7d6c";
  const remoteOnlySecret = "rpa_REMOTEONLYKEY0123456789ABCDEF";
  const leak = `token=${envSecret} remote=${remoteOnlySecret}\n-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\ntail without newline ${envSecret}`;
  const leaks = (text) => text.includes(envSecret) || text.includes(remoteOnlySecret) || text.includes("BEGIN OPENSSH PRIVATE KEY");
  const assertClean = (kind, ...texts) => {
    for (const text of texts) {
      assert.ok(!leaks(text), `${kind} surfaced a credential: ${text}`);
    }
    assert.ok(texts.some((text) => text.includes("[REDACTED]")), `${kind} produced no redaction marker`);
  };

  await withEnv({
    RUNPOD_API_KEY: envSecret,
    RUNPOD_POD_ID: "pod42",
    RUNPOD_ENDPOINT_ID: "ep123",
    MODAL_TOKEN_ID: "ak-FAKEID0123456789ABCD",
    MODAL_TOKEN_SECRET: "as-FAKESECRET0123456789",
  }, async () => {
    const leakyRunner = async (_executable, args, options = {}) => {
      if (options.onData) {
        const split = Math.floor(leak.length / 2);
        options.onData(Buffer.from(leak.slice(0, split), "utf8"));
        options.onData(Buffer.from(leak.slice(split), "utf8"));
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

    const runExec = async (kind, backend) => {
      const chunks = [];
      const staged = await backend.stageWorkspace({ localPath: "/repo", sessionId: "leak" });
      const result = await backend.exec({
        sessionId: "leak",
        command: ["env"],
        cwd: staged.remotePath,
        onData: (chunk) => chunks.push(chunk.toString("utf8")),
      });
      assertClean(kind, chunks.join(""), result.stdout, result.stderr);
      await backend.teardown("leak");
    };

    for (const kind of ["docker", "parallels-vm", "modal", "runpod-pod", "runpod-serverless"]) {
      const settings = { computeBackend: kind, parallelsTemplateName: "tpl" };
      await runExec(kind, createExecutionBackend("/repo", settings, { runner: leakyRunner, fetch: leakyFetch }, kind));
    }
    await runExec("sandbox-runtime", createSandboxRuntimeBackend({ runner: leakyRunner, wrapCommand: async (command) => command }));

    const runtimeChunks = [];
    await withComputeBackendExecution("/repo", { computeBackend: "docker" }, async (execution) => {
      await execution.bashOperations.exec("env", "/repo", { onData: (chunk) => runtimeChunks.push(chunk.toString("utf8")) });
      assertClean("docker runtime", runtimeChunks.join(""));
      // File content round-trips through the edit tool, so reads keep the raw bytes rather
      // than writing a redaction marker back into the file.
      const roundTrip = (await execution.editOperations.readFile("/repo/.env")).toString("utf8");
      assert.equal(roundTrip, leak);
    }, { runner: leakyRunner });

    const hostChunks = [];
    const host = resolveComputeBackendExecution(tmpdir(), { computeBackend: "host" });
    const hostResult = await host.bashOperations.exec(
      "printf '%s\\n' \"key=$RUNPOD_API_KEY\"; printf 'no newline %s' \"$RUNPOD_API_KEY\"",
      tmpdir(),
      { onData: (chunk) => hostChunks.push(chunk.toString("utf8")) },
    );
    assert.equal(hostResult.exitCode, 0);
    assertClean("host", hostChunks.join(""));
    assert.equal(hostChunks.join(""), "key=[REDACTED]\nno newline [REDACTED]");
  });
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
