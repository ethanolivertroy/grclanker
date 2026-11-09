import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const cliRoot = fileURLToPath(new URL("../", import.meta.url));
const hooksUrl = new URL("helpers/pi-binary-cache-mock-hooks.mjs", import.meta.url).href;
const preload = `data:text/javascript,${encodeURIComponent(`import { register } from "node:module"; register(${JSON.stringify(hooksUrl)});`)}`;

test("Pi's managed binary cache uses GRCLANKER_HOME before its first import", () => {
  const base = mkdtempSync(join(tmpdir(), "grclanker-pi-binary-cache-"));
  try {
    const agentDir = join(base, ".grclanker", "agent");
    const fd = join(agentDir, "bin", process.platform === "win32" ? "fd.exe" : "fd");
    const recordPath = join(base, "launch.json");
    mkdirSync(join(agentDir, "bin"), { recursive: true });
    writeFileSync(fd, "managed binary sentinel\n");
    writeFileSync(join(agentDir, "settings.json"), JSON.stringify({
      modelMode: "hosted",
      providerKind: "anthropic",
      defaultProvider: "anthropic",
      defaultModel: "claude-sonnet-4-6",
      computeBackend: "host",
    }));
    for (const entry of ["dist/index.js", "bin/grclanker.js"]) {
      for (const configuredHome of [base, join(base, ".grclanker")]) {
        const result = spawnSync(process.execPath, ["--import", preload, join(cliRoot, entry)], {
          cwd: base,
          encoding: "utf8",
          timeout: 30_000,
          env: {
            ...process.env,
            GRCLANKER_HOME: configuredHome,
            GRCLANKER_CODING_AGENT_DIR: join(base, "stale-agent-dir"),
            GRCLANKER_TEST_PI_LAUNCH_RECORD: recordPath,
          },
        });
        assert.equal(result.status, 0, `${entry}: ${result.stdout}${result.stderr}`);
        assert.deepEqual(JSON.parse(readFileSync(recordPath, "utf8")), { fd, agentDir });
      }
    }
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test("help and version do not resolve the configured runtime home", () => {
  for (const option of ["--help", "--version"]) {
    const result = spawnSync(process.execPath, [join(cliRoot, "dist/index.js"), option], {
      encoding: "utf8",
      timeout: 30_000,
      env: { ...process.env, GRCLANKER_HOME: join(tmpdir(), ".pi", "invalid") },
    });
    assert.equal(result.status, 0, `${option}: ${result.stdout}${result.stderr}`);
  }
});

test("env execution help does not resolve the configured runtime home", () => {
  for (const command of ["exec", "smoke-test"]) {
    for (const flag of ["--help", "-h"]) {
      const result = spawnSync(process.execPath, [join(cliRoot, "dist/index.js"), "env", command, flag], {
        encoding: "utf8",
        timeout: 30_000,
        env: { ...process.env, GRCLANKER_HOME: join(tmpdir(), ".pi", "invalid") },
      });
      assert.equal(result.status, 0, `${result.stdout}${result.stderr}`);
      assert.match(result.stdout, new RegExp(`Usage:\\s+grclanker env ${command}`));
    }
  }
});

test("env exec prepends the isolated managed binary directory without setup", () => {
  const base = mkdtempSync(join(tmpdir(), "grclanker-env-binary-cache-"));
  try {
    const binDir = join(base, ".grclanker", "agent", "bin");
    for (const configuredHome of [base, join(base, ".grclanker")]) {
      for (const inheritedAgentDir of [undefined, join(base, "stale-agent-dir")]) {
        const env = { ...process.env, GRCLANKER_HOME: configuredHome };
        if (inheritedAgentDir === undefined) delete env.GRCLANKER_CODING_AGENT_DIR;
        else env.GRCLANKER_CODING_AGENT_DIR = inheritedAgentDir;
        const result = spawnSync(process.execPath, [
          join(cliRoot, "dist", "index.js"), "env", "exec", "--backend", "host", "--",
          process.execPath, "--input-type=module", "-e",
          'import { delimiter } from "node:path"; console.log(process.env.PATH.split(delimiter)[0]);',
        ], {
          cwd: base,
          encoding: "utf8",
          timeout: 30_000,
          env,
        });
        assert.equal(result.status, 0, `${result.stdout}${result.stderr}`);
        assert.equal(result.stdout.trim().split(/\r?\n/).at(-1), binDir);
        assert.equal(existsSync(join(base, ".grclanker", "agent", "settings.json")), false,
          "env exec must not require or write model setup");
      }
    }
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test("forwarded help arguments and option values keep env exec isolated", () => {
  const base = mkdtempSync(join(tmpdir(), "grclanker-env-forwarded-help-"));
  try {
    mkdirSync(join(base, "--help"));
    const command = [
      process.execPath, "--input-type=module", "-e",
      'import { delimiter } from "node:path"; console.log(process.env.PATH.split(delimiter)[0]); console.log(process.argv[1]);',
      "--", "--help",
    ];
    for (const optionArgs of [[], ["--cwd", "--help"]]) {
      const result = spawnSync(process.execPath, [
        join(cliRoot, "dist/index.js"), "env", "exec", "--backend", "host", ...optionArgs, "--", ...command,
      ], {
        cwd: base,
        encoding: "utf8",
        timeout: 30_000,
        env: {
          ...process.env,
          GRCLANKER_HOME: base,
          GRCLANKER_CODING_AGENT_DIR: join(base, "stale-agent-dir"),
        },
      });
      assert.equal(result.status, 0, `${result.stdout}${result.stderr}`);
      assert.deepEqual(result.stdout.trim().split(/\r?\n/).slice(-2), [join(base, ".grclanker", "agent", "bin"), "--help"]);
    }
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});
