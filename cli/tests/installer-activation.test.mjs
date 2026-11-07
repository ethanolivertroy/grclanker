import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const repoRoot = resolve(import.meta.dirname, "../..");
const pwsh = process.env.PWSH || "pwsh";
const hasPwsh = spawnSync(pwsh, ["-NoProfile", "-Command", "exit 0"]).status === 0;
const installers = [
  { name: "shell", command: "/bin/bash", script: "install", target: "linux-x64", extension: "tar.gz" },
  { name: "PowerShell", command: pwsh, script: "install.ps1", target: "win32-x64", extension: "zip", skip: !hasPwsh },
];

function stage(installer, entries = {}) {
  const root = mkdtempSync(join(tmpdir(), "grclanker-activation-"));
  const install = join(root, "install");
  const bin = join(root, "bin");
  mkdirSync(install);
  mkdirSync(bin);
  const oldLauncher = installer.name === "shell" ? "#!/bin/bash\necho old\n" : "@echo old\r\n";
  const launcher = join(bin, installer.name === "shell" ? "grclanker" : "grclanker.cmd");
  writeFileSync(launcher, oldLauncher);
  chmodSync(launcher, 0o755);
  writeFileSync(join(install, "old-evidence.txt"), "previous complete install");
  const release = join(root, "cli/release");
  mkdirSync(release, { recursive: true });
  const archive = join(release, `grclanker-9.9.9-${installer.target}.${installer.extension}`);
  const result = spawnSync("python3", ["-c", `
import io,json,sys,tarfile,zipfile
entries=json.loads(sys.argv[2])
if sys.argv[1].endswith('.zip'):
    with zipfile.ZipFile(sys.argv[1], 'w') as archive:
        for name,body in entries.items(): archive.writestr(name,body)
else:
    with tarfile.open(sys.argv[1], 'w:gz') as archive:
        for name,body in entries.items():
            data=body.encode(); info=tarfile.TarInfo(name); info.size=len(data); info.mode=0o755
            archive.addfile(info,io.BytesIO(data))
`, archive, JSON.stringify(entries)], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  const versions = join(root, installer.name === "PowerShell" ? ".install.v" : ".install.versions");
  return { root, install, bin, launcher, oldLauncher, archive, versions };
}

function invoke(installer, fixture, extra = {}, prelude) {
  const args = prelude ? ["-NoProfile", "-Command", `${prelude}; & '${join(repoRoot, "public", installer.script).replaceAll("'", "''")}' 9.9.9`] : [
    ...(installer.name === "PowerShell" ? ["-NoProfile", "-File"] : []),
    join(repoRoot, "public", installer.script), "9.9.9",
  ];
  return spawnSync(installer.command, args, {
    cwd: fixture.root,
    env: { ...process.env, HOME: join(fixture.root, "home"), GRCLANKER_INSTALL_DIR: fixture.install, GRCLANKER_BIN_DIR: fixture.bin,
      GRCLANKER_INSTALL_TARGET: installer.target, GRCLANKER_ASSET_URL: installer.name === "PowerShell" ? "" : `file://${fixture.archive}`, GRCLANKER_RELEASE_BASE_URL: "", ...extra },
    encoding: "utf8", timeout: 20000,
  });
}

const completeEntries = {
  grclanker: "#!/bin/bash\necho new\n",
  "grclanker.cmd": "@echo new\r\n",
  "node/node.exe": "synthetic Windows runtime for Linux-hosted installer tests",
  "app/bin/grclanker.js": "console.log('new');\n",
};

for (const installer of installers) {
  test(`${installer.name} refuses an incomplete replacement without changing installation or launcher`, { skip: installer.skip }, () => {
    const fixture = stage(installer, { "unrelated.txt": "not a runnable bundle" });
    try {
      const result = invoke(installer, fixture);
      assert.notEqual(result.status, 0);
      assert.match(`${result.stdout}\n${result.stderr}`, /validation failed/i);
      assert.equal(readFileSync(fixture.launcher, "utf8"), fixture.oldLauncher);
      assert.equal(readFileSync(join(fixture.install, "old-evidence.txt"), "utf8"), "previous complete install");
      assert.deepEqual(readdirSync(fixture.versions), []);
    } finally { rmSync(fixture.root, { recursive: true, force: true }); }
  });

  test(`${installer.name} keeps the previous installation when publishing the command fails`, { skip: installer.skip }, () => {
    const fixture = stage(installer, completeEntries);
    try {
      rmSync(fixture.launcher);
      mkdirSync(fixture.launcher);
      writeFileSync(join(fixture.launcher, "must-stay.txt"), "previous launcher path");
      const result = invoke(installer, fixture);
      assert.notEqual(result.status, 0);
      assert.equal(readFileSync(join(fixture.launcher, "must-stay.txt"), "utf8"), "previous launcher path");
      assert.equal(readFileSync(join(fixture.install, "old-evidence.txt"), "utf8"), "previous complete install");
      assert.deepEqual(readdirSync(fixture.versions), []);
    } finally { rmSync(fixture.root, { recursive: true, force: true }); }
  });
}

test("shell rolls the command back if compatibility-path activation fails after the command switch", () => {
  const fixture = stage(installers[0], completeEntries);
  try {
    const stub = join(fixture.root, "stub");
    mkdirSync(stub);
    writeFileSync(join(stub, "mv"), '#!/bin/bash\ncase "$1" in *.alias) exit 73 ;; esac\nexec /bin/mv "$@"\n');
    chmodSync(join(stub, "mv"), 0o755);
    const result = invoke(installers[0], fixture, { PATH: `${stub}:${process.env.PATH}` });
    assert.notEqual(result.status, 0);
    assert.equal(readFileSync(fixture.launcher, "utf8"), fixture.oldLauncher);
    assert.equal(readFileSync(join(fixture.install, "old-evidence.txt"), "utf8"), "previous complete install");
    assert.deepEqual(readdirSync(fixture.versions), []);
  } finally { rmSync(fixture.root, { recursive: true, force: true }); }
});

test("PowerShell rolls the command back if compatibility-path activation fails after the command switch", { skip: !hasPwsh }, () => {
  const fixture = stage(installers[1], completeEntries);
  try {
    const result = invoke(installers[1], fixture, {}, `
      function global:Move-Item {
        [CmdletBinding()] param([string]$LiteralPath, [string]$Destination)
        if ($LiteralPath.EndsWith('.alias')) { throw 'synthetic compatibility activation failure' }
        Microsoft.PowerShell.Management\\Move-Item -LiteralPath $LiteralPath -Destination $Destination
      }
    `);
    assert.notEqual(result.status, 0);
    assert.equal(readFileSync(fixture.launcher, "utf8"), fixture.oldLauncher);
    assert.equal(readFileSync(join(fixture.install, "old-evidence.txt"), "utf8"), "previous complete install");
    assert.deepEqual(readdirSync(fixture.versions), []);
  } finally { rmSync(fixture.root, { recursive: true, force: true }); }
});
