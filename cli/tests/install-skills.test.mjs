import test, { after, before } from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import http from "node:http";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const REPO_ROOT = resolve(import.meta.dirname, "../..");
const SKILL = readFileSync(resolve(REPO_ROOT, "skills", "grclanker", "SKILL.md"), "utf8");
const OLD_SKILL = "---\nname: grclanker\ndescription: The previous install.\n---\n\nOld instructions.\n";

const pwshBin = process.env.PWSH || "pwsh";
const hasPwsh = spawnSync(pwshBin, ["-NoProfile", "-Command", "exit 0"]).status === 0;
const PS_INSTALLER = resolve(REPO_ROOT, "public", "install-skills.ps1");

const INSTALLERS = [
  {
    name: "install-skills",
    command: "bash",
    args: [resolve(REPO_ROOT, "public", "install-skills")],
    skip: false,
  },
  {
    name: "install-skills.ps1",
    command: pwshBin,
    args: ["-NoProfile", "-File", PS_INSTALLER],
    skip: !hasPwsh,
  },
];

let server;
let baseUrl;

before(async () => {
  server = http.createServer((request, response) => {
    if (request.url === "/skill") {
      response.end(SKILL);
    } else if (request.url === "/cut-off") {
      response.writeHead(200, { "content-length": String(Buffer.byteLength(SKILL)) });
      response.write(SKILL.slice(0, 600), () => request.socket.destroy());
    } else if (request.url === "/sign-in") {
      response.writeHead(200, { "content-type": "text/html" });
      response.end("<!doctype html><title>Sign in to the network</title>\n");
    } else {
      response.writeHead(404);
      response.end("404: Not Found");
    }
  });
  await new Promise((resolveListen) => server.listen(0, "127.0.0.1", resolveListen));
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});

after(async () => {
  server.closeAllConnections();
  await new Promise((resolveClose) => server.close(resolveClose));
});

function stageHome(installedSkill = null) {
  const home = mkdtempSync(join(tmpdir(), "grclanker-skills-"));
  const skillDir = join(home, ".codex", "skills", "grclanker");
  if (installedSkill !== null) {
    mkdirSync(skillDir, { recursive: true });
    writeFileSync(join(skillDir, "SKILL.md"), installedSkill);
  }
  return { home, skillDir };
}

// pwsh colors its errors unless NO_COLOR is set, and wraps a long message
// across lines that start with a "|" gutter.
function unwrap(output) {
  return output.replace(/\u001b\[[0-9;]*m/g, "").replace(/\s*\n\s*\|\s*/g, " ");
}

function runInstaller(installer, home, route, env = {}) {
  return new Promise((resolveRun, rejectRun) => {
    const child = spawn(installer.command, installer.args, {
      cwd: home,
      // spawnSync would freeze this process, so the local HTTP server could never answer.
      stdio: ["ignore", "pipe", "pipe"],
      env: {
        ...process.env,
        HOME: home,
        GRCLANKER_SKILL_URL: `${baseUrl}${route}`,
        ...env,
      },
    });
    let output = "";
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
    }, 30000);
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      output += chunk;
    });
    child.stderr.on("data", (chunk) => {
      output += chunk;
    });
    child.on("error", (error) => {
      clearTimeout(timer);
      rejectRun(error);
    });
    child.on("close", (status) => {
      clearTimeout(timer);
      resolveRun({ status, output });
    });
  });
}

for (const installer of INSTALLERS) {
  test(`${installer.name} keeps the installed skill when the download is cut off`, { skip: installer.skip }, async () => {
    const { home, skillDir } = stageHome(OLD_SKILL);
    try {
      const result = await runInstaller(installer, home, "/cut-off");
      assert.notEqual(result.status, 0, result.output);
      assert.equal(readFileSync(join(skillDir, "SKILL.md"), "utf8"), OLD_SKILL);
      assert.deepEqual(readdirSync(skillDir), ["SKILL.md"]);
      assert.match(unwrap(result.output), /Could not download/);
    } finally {
      rmSync(home, { recursive: true, force: true });
    }
  });

  test(`${installer.name} refuses a download that is not the grclanker skill`, { skip: installer.skip }, async () => {
    const { home, skillDir } = stageHome(OLD_SKILL);
    try {
      const result = await runInstaller(installer, home, "/sign-in");
      assert.notEqual(result.status, 0, result.output);
      assert.equal(readFileSync(join(skillDir, "SKILL.md"), "utf8"), OLD_SKILL);
      assert.deepEqual(readdirSync(skillDir), ["SKILL.md"]);
      assert.match(unwrap(result.output), /did not return a grclanker SKILL\.md/);
    } finally {
      rmSync(home, { recursive: true, force: true });
    }
  });

  test(`${installer.name} leaves no skill directory behind when a first install fails`, { skip: installer.skip }, async () => {
    const { home, skillDir } = stageHome();
    try {
      const result = await runInstaller(installer, home, "/missing");
      assert.notEqual(result.status, 0, result.output);
      assert.equal(existsSync(skillDir), false);
      assert.match(unwrap(result.output), /Could not download/);
    } finally {
      rmSync(home, { recursive: true, force: true });
    }
  });

  test(`${installer.name} installs the skill, then upgrades it and removes stale downloads`, { skip: installer.skip }, async () => {
    const { home, skillDir } = stageHome();
    try {
      const first = await runInstaller(installer, home, "/skill");
      assert.equal(first.status, 0, first.output);
      assert.equal(readFileSync(join(skillDir, "SKILL.md"), "utf8"), SKILL);
      assert.deepEqual(readdirSync(skillDir), ["SKILL.md"]);

      writeFileSync(join(skillDir, "SKILL.md"), OLD_SKILL);
      writeFileSync(join(skillDir, ".SKILL.md.0badc0de"), "---\nname: grc");
      writeFileSync(join(skillDir, ".SKILL.md.backup"), OLD_SKILL);
      writeFileSync(join(skillDir, "notes.md"), "Mine.\n");
      const upgrade = await runInstaller(installer, home, "/skill");
      assert.equal(upgrade.status, 0, upgrade.output);
      assert.equal(readFileSync(join(skillDir, "SKILL.md"), "utf8"), SKILL);
      assert.deepEqual(readdirSync(skillDir).sort(), [".SKILL.md.backup", "SKILL.md", "notes.md"]);
    } finally {
      rmSync(home, { recursive: true, force: true });
    }
  });

  test(`${installer.name} refuses to replace a SKILL.md directory`, { skip: installer.skip }, async () => {
    const { home, skillDir } = stageHome();
    try {
      mkdirSync(join(skillDir, "SKILL.md"), { recursive: true });
      writeFileSync(join(skillDir, "SKILL.md", "notes.md"), "Mine.\n");
      const result = await runInstaller(installer, home, "/skill");
      assert.notEqual(result.status, 0, result.output);
      assert.deepEqual(readdirSync(skillDir), ["SKILL.md"]);
      assert.deepEqual(readdirSync(join(skillDir, "SKILL.md")), ["notes.md"]);
      assert.match(unwrap(result.output), /SKILL\.md is a directory, so nothing was changed/);
    } finally {
      rmSync(home, { recursive: true, force: true });
    }
  });
}

// Windows PowerShell 5.1 saves the bytes it got before a download was cut off
// and reports no error. pwsh 7 fails the request instead, so stand in for 5.1.
const WINDOWS_POWERSHELL_CUT_OFF = [
  "function Invoke-WebRequest([string]$Uri, [string]$OutFile, [switch]$PassThru, [switch]$UseBasicParsing) {",
  "  [System.IO.File]::WriteAllText($OutFile, $env:CUT_OFF_BODY)",
  "  if ($PassThru) { [pscustomobject]@{ Headers = @{ 'Content-Length' = $env:CUT_OFF_LENGTH } } }",
  "}",
].join("\n");

test("install-skills.ps1 keeps the installed skill when Windows PowerShell 5.1 accepts a cut-off download", { skip: !hasPwsh }, async () => {
  const { home, skillDir } = stageHome(OLD_SKILL);
  const body = SKILL.slice(0, 600);
  try {
    const installer = {
      command: pwshBin,
      args: ["-NoProfile", "-Command", `${WINDOWS_POWERSHELL_CUT_OFF}\n& '${PS_INSTALLER}'`],
    };
    const result = await runInstaller(installer, home, "/skill", {
      CUT_OFF_BODY: body,
      CUT_OFF_LENGTH: String(Buffer.byteLength(SKILL)),
    });
    assert.notEqual(result.status, 0, result.output);
    assert.equal(readFileSync(join(skillDir, "SKILL.md"), "utf8"), OLD_SKILL);
    assert.deepEqual(readdirSync(skillDir), ["SKILL.md"]);
    assert.match(
      unwrap(result.output),
      new RegExp(`Could not download .* Got ${Buffer.byteLength(body)} of ${Buffer.byteLength(SKILL)} bytes`),
    );
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test("install-skills.ps1 turns off the progress bar that can stall noninteractive hosts", () => {
  assert.match(readFileSync(PS_INSTALLER, "utf8"), /\$ProgressPreference = "SilentlyContinue"/);
});
