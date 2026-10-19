import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  realpathSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { writeFile } from "node:fs/promises";
import { createRequire, syncBuiltinESMExports } from "node:module";
import { hostname, tmpdir } from "node:os";
import { basename, join } from "node:path";

import { runToolCall } from "../dist/extensions/grc-tools/abort.js";
import {
  numberedNames,
  writeBundleAtomically,
  writeFileAtomically,
} from "../dist/extensions/grc-tools/atomic-output.js";
import { SIMULATED_CRASH, newEntries, withWriteFailure } from "./helpers/atomic-output.mjs";

const MODULE_URL = new URL("../dist/extensions/grc-tools/atomic-output.js", import.meta.url).href;
const HOST_TOKEN = createHash("sha256").update(hostname()).digest("hex").slice(0, 8);
const fsPromises = createRequire(import.meta.url)("node:fs/promises");

function createTempBase(prefix) {
  return mkdtempSync(join(tmpdir(), prefix));
}

function stagingEntries(root) {
  return readdirSync(root).filter((name) => name.startsWith(".grclanker-staging-"));
}

async function writeSampleBundle(staged, { zip = true } = {}) {
  mkdirSync(join(staged.dir, "analysis"), { mode: 0o700 });
  await writeFile(join(staged.dir, "analysis", "findings.json"), "[]\n", { mode: 0o600 });
  await writeFile(join(staged.dir, "README.md"), "# bundle\n", { mode: 0o600 });
  if (zip) await writeFile(staged.zipPath, "zip-bytes", { mode: 0o600 });
}

/** Spawns a node process that runs `source` as a module and resolves once it prints `ready`. */
function spawnModule(source) {
  const child = spawn(process.execPath, ["--input-type=module", "-e", source], { stdio: ["ignore", "pipe", "pipe"] });
  const ready = new Promise((resolvePromise, rejectPromise) => {
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => {
      stdout += chunk;
      if (stdout.includes("ready")) resolvePromise();
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
    });
    child.on("exit", (code) => rejectPromise(new Error(`child exited (${code}) before it was ready: ${stderr}`)));
  });
  const exited = new Promise((resolvePromise) => child.on("exit", resolvePromise));
  return { child, ready, exited };
}

async function deadPid() {
  const { child, ready, exited } = spawnModule("");
  ready.catch(() => {});
  await exited;
  return child.pid;
}

/**
 * Source for a process that writes a zipped `bundle` under `root` and stops at the commit's move (a
 * rename or a link) onto `stopAt`, before the move happens or, with `afterMove`, right after it: it
 * prints `ready` and then hangs, or exits.
 */
function commitThatStops(root, stopAt, how, { afterMove = false } = {}) {
  return `
    import { createRequire, syncBuiltinESMExports } from "node:module";
    import { writeFile } from "node:fs/promises";
    import { join } from "node:path";
    const fsPromises = createRequire(${JSON.stringify(MODULE_URL)})("node:fs/promises");
    for (const name of ["rename", "link"]) {
      const move = fsPromises[name];
      fsPromises[name] = async (from, to) => {
        if (to !== ${JSON.stringify(stopAt)}) return move(from, to);
        ${afterMove ? "await move(from, to);" : ""}
        process.stdout.write("ready");
        ${how === "exit" ? "process.exit(0);" : "return new Promise(() => setInterval(() => {}, 1000));"}
      };
    }
    syncBuiltinESMExports();
    const { writeBundleAtomically } = await import(${JSON.stringify(MODULE_URL)});
    await writeBundleAtomically({ root: ${JSON.stringify(root)}, names: ["bundle"], zip: true }, async (staged) => {
      await writeFile(join(staged.dir, "README.md"), "# bundle\\n");
      await writeFile(staged.zipPath, "zip-bytes");
    });
  `;
}

/** Runs `effect` right after this process renames something onto `target`, while `run` executes. */
async function afterRename(target, effect, run) {
  const original = fsPromises.rename;
  fsPromises.rename = async (from, to) => {
    await original(from, to);
    if (to === target) effect();
  };
  syncBuiltinESMExports();
  try {
    return await run();
  } finally {
    fsPromises.rename = original;
    syncBuiltinESMExports();
  }
}

/**
 * Runs `effect` right before this process moves something onto `target` with one of `methods`, while
 * `run` executes. An `effect` that throws refuses the move with that error.
 */
async function beforeMove(target, effect, run, { methods = ["rename", "link"] } = {}) {
  const originals = Object.fromEntries(methods.map((name) => [name, fsPromises[name]]));
  for (const [name, original] of Object.entries(originals)) {
    fsPromises[name] = async (from, to) => {
      if (to === target) effect();
      return original(from, to);
    };
  }
  syncBuiltinESMExports();
  try {
    return await run();
  } finally {
    Object.assign(fsPromises, originals);
    syncBuiltinESMExports();
  }
}

function errorWithCode(code) {
  return Object.assign(new Error(`simulated ${code}`), { code });
}

test("numberedNames yields the base name and then -2 through -count", () => {
  assert.deepEqual(numberedNames("acme-audit-bundle", 4), [
    "acme-audit-bundle",
    "acme-audit-bundle-2",
    "acme-audit-bundle-3",
    "acme-audit-bundle-4",
  ]);
});

test("writeBundleAtomically commits the directory and archive under the first free name and removes its staging directory", async () => {
  const root = createTempBase("grclanker-atomic-commit-");
  mkdirSync(join(root, "bundle"));
  writeFileSync(join(root, "bundle-2.zip"), "older archive");
  let stagedName;

  const result = await writeBundleAtomically(
    { root, names: numberedNames("bundle", 6), zip: true },
    async (staged) => {
      stagedName = staged.dir.split("/").at(-1);
      assert.equal(staged.zipPath, `${staged.dir}.zip`);
      assert.deepEqual(staged.target, { outputDir: join(root, "bundle-3"), zipPath: join(root, "bundle-3.zip") });
      assert.equal(existsSync(join(root, "bundle-3")), false, "nothing exists at the final path while the writer runs");
      await writeSampleBundle(staged);
    },
  );

  assert.equal(stagedName, "bundle-3", "the staged directory already carries the name it commits under");
  assert.deepEqual(result, { outputDir: join(root, "bundle-3"), zipPath: join(root, "bundle-3.zip") });
  assert.equal(readFileSync(join(result.outputDir, "analysis", "findings.json"), "utf8"), "[]\n");
  assert.equal(readFileSync(result.zipPath, "utf8"), "zip-bytes");
  assert.equal(statSync(result.outputDir).mode & 0o777, 0o700);
  assert.equal(readFileSync(join(root, "bundle-2.zip"), "utf8"), "older archive", "an existing archive is never replaced");
  assert.deepEqual(readdirSync(root).sort(), ["bundle", "bundle-2.zip", "bundle-3", "bundle-3.zip"]);
});

test("writeBundleAtomically leaves no bundle, archive, or staging directory when the writer fails partway", async () => {
  const root = createTempBase("grclanker-atomic-failure-");

  await assert.rejects(
    writeBundleAtomically({ root, names: ["bundle"], zip: true }, async (staged) => {
      await writeSampleBundle(staged, { zip: false });
      throw new Error("collector failed while writing");
    }),
    /collector failed while writing/,
  );
  const calls = await withWriteFailure(async () => {
    await assert.rejects(
      writeBundleAtomically({ root, names: ["bundle"], zip: true }, (staged) => writeSampleBundle(staged)),
      new RegExp(SIMULATED_CRASH),
    );
  }, { failAt: 2 });

  assert.equal(calls, 2);
  assert.deepEqual(readdirSync(root), []);
});

test("writeBundleAtomically discards the staged bundle when the signal aborts during the write", async () => {
  const root = createTempBase("grclanker-atomic-abort-");
  const controller = new AbortController();

  await assert.rejects(
    writeBundleAtomically({ root, names: ["bundle"], zip: true, signal: controller.signal }, async (staged) => {
      await writeSampleBundle(staged);
      controller.abort();
    }),
    { name: "AbortError" },
  );

  assert.deepEqual(readdirSync(root), []);
});

test("writeBundleAtomically stages nothing when the signal is already aborted", async () => {
  const root = createTempBase("grclanker-atomic-preaborted-");
  let wrote = false;

  await assert.rejects(
    writeBundleAtomically({ root, names: ["bundle"], signal: AbortSignal.abort() }, async () => {
      wrote = true;
    }),
    { name: "AbortError" },
  );

  assert.equal(wrote, false);
  assert.deepEqual(readdirSync(root), []);
});

test("an abort that arrives once the bundle starts moving into place lets the commit finish, and the write resolves", async () => {
  const root = createTempBase("grclanker-atomic-late-abort-");
  const controller = new AbortController();

  const result = await beforeMove(join(root, "bundle"), () => controller.abort(), () =>
    writeBundleAtomically({ root, names: ["bundle"], zip: true, signal: controller.signal }, (staged) => writeSampleBundle(staged)));

  assert.equal(controller.signal.aborted, true);
  assert.deepEqual(result, { outputDir: join(root, "bundle"), zipPath: join(root, "bundle.zip") });
  assert.equal(readFileSync(result.zipPath, "utf8"), "zip-bytes");
  assert.deepEqual(readdirSync(root).sort(), ["bundle", "bundle.zip"]);
});

test("a write marks the tool call it runs in as committed once its bundle is in place, and a write that commits nothing does not", async () => {
  const root = createTempBase("grclanker-atomic-call-");
  const call = { committed: false };

  await runToolCall(call, () => writeBundleAtomically({ root, names: ["bundle"] }, async (staged) => {
    await writeSampleBundle(staged, { zip: false });
    assert.equal(call.committed, false, "a bundle still in staging is not committed");
  }));
  assert.equal(call.committed, true);

  const failed = { committed: false };
  await assert.rejects(
    runToolCall(failed, () => writeBundleAtomically({ root, names: ["other"] }, async () => {
      throw new Error("collector failed");
    })),
    /collector failed/,
  );
  assert.equal(failed.committed, false);
});

test("a write that commits nothing removes the directories it created on the way to its root, and keeps the ones that were there", async () => {
  const base = createTempBase("grclanker-atomic-created-");
  const root = join(base, "exports", "acme", "audit");
  const failingWriter = async () => {
    throw new Error("collector failed");
  };
  const controller = new AbortController();

  await assert.rejects(
    writeBundleAtomically({ root, names: ["bundle"], zip: true, signal: controller.signal }, async (staged) => {
      await writeSampleBundle(staged);
      controller.abort();
    }),
    { name: "AbortError" },
  );
  assert.deepEqual(readdirSync(base), [], "an aborted write");
  await assert.rejects(writeBundleAtomically({ root, names: ["bundle"] }, failingWriter), /collector failed/);
  assert.deepEqual(readdirSync(base), [], "a failed write");
  await assert.rejects(
    writeBundleAtomically({ root, names: ["bundle"], checkName: () => { throw new Error("refused"); } }, failingWriter),
    /refused/,
  );
  assert.deepEqual(readdirSync(base), [], "a write whose names are refused");

  mkdirSync(join(base, "exports"));
  await assert.rejects(writeBundleAtomically({ root, names: ["bundle"] }, failingWriter), /collector failed/);
  assert.deepEqual(readdirSync(base), ["exports"], "a directory that was there already stays");
  assert.deepEqual(readdirSync(join(base, "exports")), []);

  const result = await writeBundleAtomically({ root, names: ["bundle"] }, (staged) => writeSampleBundle(staged, { zip: false }));
  assert.equal(result.outputDir, join(root, "bundle"));
  assert.deepEqual(readdirSync(root), ["bundle"], "a write that commits keeps the directories it created");
});

test("createRoot makes the root in place of a plain mkdir and names the path the bundle lands under, and what it made is removed when nothing commits", async () => {
  const base = createTempBase("grclanker-atomic-create-root-");
  mkdirSync(join(base, "actual"));
  const actual = realpathSync(join(base, "actual"));
  symlinkSync(actual, join(base, "alias"));
  const root = join(base, "alias", "exports");
  const roots = [];
  const createRoot = (dir) => {
    roots.push(dir);
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    return realpathSync(dir);
  };

  const result = await writeBundleAtomically({ root, createRoot, names: ["bundle"] }, async (staged) => {
    assert.equal(staged.target.outputDir, join(actual, "exports", "bundle"));
    await writeSampleBundle(staged, { zip: false });
  });
  assert.deepEqual(roots, [root]);
  assert.equal(result.outputDir, join(actual, "exports", "bundle"));
  await assert.rejects(
    writeBundleAtomically({ root, createRoot, names: ["bundle"], exhaustedMessage: (dir) => `No free name under ${dir}` }, async () => {}),
    { message: `No free name under ${join(actual, "exports")}` },
  );

  const refusedRoot = join(base, "refused", "exports");
  await assert.rejects(
    writeBundleAtomically({
      root: refusedRoot,
      createRoot: (dir) => {
        mkdirSync(dir, { recursive: true });
        throw new Error(`Refusing to use ${dir}`);
      },
      names: ["bundle"],
    }, async () => {}),
    /Refusing to use/,
  );
  assert.equal(existsSync(join(base, "refused")), false);
});

test("writeBundleAtomically fails before staging when every name is taken", async () => {
  const root = createTempBase("grclanker-atomic-exhausted-");
  mkdirSync(join(root, "bundle"));
  writeFileSync(join(root, "bundle-2.zip"), "");
  let wrote = false;
  const write = async () => {
    wrote = true;
  };

  await assert.rejects(
    writeBundleAtomically({ root, names: numberedNames("bundle", 2), zip: true }, write),
    { message: `Unable to allocate output directory under ${root}` },
  );
  await assert.rejects(
    writeBundleAtomically({ root, names: ["bundle"], exhaustedMessage: "every bundle name is taken" }, write),
    { message: "every bundle name is taken" },
  );

  assert.equal(wrote, false);
  assert.deepEqual(readdirSync(root).sort(), ["bundle", "bundle-2.zip"]);
});

test("when another writer takes the expected name first, the bundle is written again under the next free name", async () => {
  const root = createTempBase("grclanker-atomic-race-");
  const targets = [];

  const result = await writeBundleAtomically({ root, names: numberedNames("bundle", 3), zip: true }, async (staged) => {
    targets.push(staged.target.outputDir);
    await writeFile(join(staged.dir, "location.txt"), staged.target.outputDir);
    await writeFile(staged.zipPath, basename(staged.dir));
    if (targets.length === 1) {
      mkdirSync(join(root, "bundle"));
      writeFileSync(join(root, "bundle-2.zip"), "claimed");
    }
  });

  assert.deepEqual(targets, [join(root, "bundle"), join(root, "bundle-3")], "the writer runs again with the new target");
  assert.deepEqual(result, { outputDir: join(root, "bundle-3"), zipPath: join(root, "bundle-3.zip") });
  assert.equal(readFileSync(join(result.outputDir, "location.txt"), "utf8"), result.outputDir, "a recorded location names where the bundle landed");
  assert.equal(readFileSync(result.zipPath, "utf8"), "bundle-3", "the archive is rebuilt under the new name too");
  assert.equal(readFileSync(join(root, "bundle-2.zip"), "utf8"), "claimed");
  assert.deepEqual(readdirSync(join(root, "bundle")), [], "the other writer's directory is untouched");
  assert.deepEqual(readdirSync(root).sort(), ["bundle", "bundle-2.zip", "bundle-3", "bundle-3.zip"]);
});

test("when the archive's name is taken after the directory moves, the directory is withdrawn and the bundle is written again", async () => {
  const root = createTempBase("grclanker-atomic-zip-race-");
  const targets = [];

  const result = await afterRename(
    join(root, "bundle"),
    () => writeFileSync(join(root, "bundle.zip"), "claimed"),
    () => writeBundleAtomically({ root, names: numberedNames("bundle", 3), zip: true }, async (staged) => {
      targets.push(staged.target.outputDir);
      await writeFile(join(staged.dir, "location.txt"), staged.target.outputDir);
      await writeFile(staged.zipPath, basename(staged.dir));
    }),
  );

  assert.deepEqual(targets, [join(root, "bundle"), join(root, "bundle-2")], "the writer runs again with the new target");
  assert.deepEqual(result, { outputDir: join(root, "bundle-2"), zipPath: join(root, "bundle-2.zip") });
  assert.equal(readFileSync(join(result.outputDir, "location.txt"), "utf8"), result.outputDir);
  assert.equal(readFileSync(result.zipPath, "utf8"), "bundle-2");
  assert.equal(readFileSync(join(root, "bundle.zip"), "utf8"), "claimed");
  assert.deepEqual(readdirSync(root).sort(), ["bundle-2", "bundle-2.zip", "bundle.zip"], "no directory is left without its archive");
});

test("an archive another writer creates just before this one moves into place is never replaced", async () => {
  const root = createTempBase("grclanker-atomic-zip-clobber-");
  let runs = 0;

  const result = await beforeMove(
    join(root, "bundle.zip"),
    () => writeFileSync(join(root, "bundle.zip"), "claimed"),
    () => writeBundleAtomically({ root, names: numberedNames("bundle", 3), zip: true }, async (staged) => {
      runs += 1;
      await writeSampleBundle(staged);
    }),
  );

  assert.equal(readFileSync(join(root, "bundle.zip"), "utf8"), "claimed", "the other writer's archive keeps its content");
  assert.equal(runs, 2, "the bundle is written again under the next free name");
  assert.deepEqual(result, { outputDir: join(root, "bundle-2"), zipPath: join(root, "bundle-2.zip") });
  assert.equal(readFileSync(result.zipPath, "utf8"), "zip-bytes");
  assert.deepEqual(readdirSync(root).sort(), ["bundle-2", "bundle-2.zip", "bundle.zip"], "no directory is left without its archive");
});

test("a rename refused with EPERM or EACCES is a name collision only when the name exists, as Windows reports one", async () => {
  for (const code of ["EPERM", "EACCES"]) {
    const root = createTempBase("grclanker-atomic-windows-collision-");
    let runs = 0;
    const write = () => writeBundleAtomically({ root, names: numberedNames("bundle", 3), zip: true }, async (staged) => {
      runs += 1;
      await writeSampleBundle(staged);
    });

    const result = await beforeMove(join(root, "bundle"), () => {
      mkdirSync(join(root, "bundle"));
      throw errorWithCode(code);
    }, write, { methods: ["rename"] });

    assert.equal(runs, 2, `${code} onto an existing directory moves on to the next name`);
    assert.equal(result.outputDir, join(root, "bundle-2"));
    assert.deepEqual(readdirSync(root).sort(), ["bundle", "bundle-2", "bundle-2.zip"]);

    runs = 0;
    await assert.rejects(
      beforeMove(join(root, "bundle-3"), () => { throw errorWithCode(code); }, write, { methods: ["rename"] }),
      { code },
    );
    assert.equal(runs, 1, `${code} with nothing at the destination is an error, not a collision`);
    assert.deepEqual(readdirSync(root).sort(), ["bundle", "bundle-2", "bundle-2.zip"], "the failed write leaves nothing behind");
  }
});

test("on a filesystem without hard links, the archive moves into place with a rename", async () => {
  const root = createTempBase("grclanker-atomic-no-hard-links-");

  const result = await beforeMove(
    join(root, "bundle.zip"),
    () => { throw errorWithCode("EPERM"); },
    () => writeBundleAtomically({ root, names: numberedNames("bundle", 3), zip: true }, (staged) => writeSampleBundle(staged)),
    { methods: ["link"] },
  );

  assert.deepEqual(result, { outputDir: join(root, "bundle"), zipPath: join(root, "bundle.zip") });
  assert.equal(readFileSync(result.zipPath, "utf8"), "zip-bytes");
  assert.deepEqual(readdirSync(root).sort(), ["bundle", "bundle.zip"]);
});

test("concurrent writes in one process claim different names up front, and a failed write releases its claim", async () => {
  const root = createTempBase("grclanker-atomic-concurrent-");
  const targets = [];
  let started = 0;
  let releaseWriters;
  const allStarted = new Promise((resolvePromise) => {
    releaseWriters = resolvePromise;
  });
  const writer = (index) => async (staged) => {
    targets[index] = staged.target.outputDir;
    started += 1;
    if (started === 3) releaseWriters();
    await allStarted;
    if (index === 1) throw new Error("this export failed");
    await writeSampleBundle(staged);
  };

  const results = await Promise.allSettled([0, 1, 2].map((index) =>
    writeBundleAtomically({ root, names: numberedNames("bundle", 6), zip: true }, writer(index))));

  assert.deepEqual([...targets].sort(), ["bundle", "bundle-2", "bundle-3"].map((name) => join(root, name)));
  assert.deepEqual(results.map((result) => result.status), ["fulfilled", "rejected", "fulfilled"]);
  assert.equal(results[0].value.outputDir, targets[0], "each write commits under the name it claimed");
  assert.equal(results[2].value.outputDir, targets[2]);
  assert.equal(existsSync(targets[1]), false);
  assert.deepEqual(stagingEntries(root), []);

  const next = await writeBundleAtomically({ root, names: numberedNames("bundle", 6), zip: true }, (staged) => writeSampleBundle(staged));
  assert.equal(next.outputDir, targets[1], "the failed write's name is free again");
});

test("a directory that writes in flight created stays, even empty, while one of them still needs it, and the last of them removes it", async () => {
  const base = createTempBase("grclanker-atomic-shared-created-");
  const shared = join(base, "exports");
  const slowRoot = join(shared, "slow");
  const failingWriter = async () => {
    throw new Error("collector failed");
  };
  let reachedMkdir;
  const atMkdir = new Promise((resolvePromise) => {
    reachedMkdir = resolvePromise;
  });
  let resumeMkdir;
  const resumed = new Promise((resolvePromise) => {
    resumeMkdir = resolvePromise;
  });
  const originalMkdir = fsPromises.mkdir;
  fsPromises.mkdir = async (path, options) => {
    if (path === slowRoot) {
      reachedMkdir();
      await resumed;
    }
    return originalMkdir(path, options);
  };
  syncBuiltinESMExports();
  try {
    const slow = writeBundleAtomically({ root: slowRoot, names: ["bundle"] }, failingWriter);
    await atMkdir;
    await assert.rejects(writeBundleAtomically({ root: join(shared, "fast"), names: ["bundle"] }, failingWriter), /collector failed/);
    assert.deepEqual(readdirSync(shared), [], "the failed write leaves the directory the paused one still needs, though it is empty");
    resumeMkdir();
    await assert.rejects(slow, /collector failed/);
  } finally {
    fsPromises.mkdir = originalMkdir;
    syncBuiltinESMExports();
  }
  assert.deepEqual(readdirSync(base), []);
});

test("writeBundleAtomically commits only the directory when the writer produced no archive", async () => {
  const root = createTempBase("grclanker-atomic-nozip-");

  const zipped = await writeBundleAtomically({ root, names: ["with-zip-option"], zip: true }, (staged) => writeSampleBundle(staged, { zip: false }));
  const plain = await writeBundleAtomically({ root, names: ["plain"] }, (staged) => writeSampleBundle(staged));

  assert.equal(existsSync(zipped.outputDir), true);
  assert.equal(existsSync(zipped.zipPath), false);
  assert.equal(existsSync(plain.outputDir), true);
  assert.equal(existsSync(plain.zipPath), false, "without zip: true an archive the writer left in staging is discarded");
  assert.deepEqual(readdirSync(root).sort(), ["plain", "with-zip-option"]);
});

test("checkName sees each candidate in order up to the free one, and throwing refuses the export before staging", async () => {
  const root = createTempBase("grclanker-atomic-check-");
  mkdirSync(join(root, "bundle"));
  const checked = [];

  const result = await writeBundleAtomically(
    { root, names: numberedNames("bundle", 4), zip: true, checkName: (name) => checked.push(name) },
    (staged) => writeSampleBundle(staged),
  );

  assert.equal(result.outputDir, join(root, "bundle-2"));
  assert.deepEqual(checked, ["bundle", "bundle-2"]);

  let wrote = false;
  await assert.rejects(
    writeBundleAtomically(
      {
        root,
        names: numberedNames("bundle", 4),
        zip: true,
        checkName: (name) => {
          if (name === "bundle-3") throw new Error(`Refusing to use ${name}`);
        },
      },
      async () => {
        wrote = true;
      },
    ),
    /Refusing to use bundle-3/,
  );
  assert.equal(wrote, false);
  assert.deepEqual(readdirSync(root).sort(), ["bundle", "bundle-2", "bundle-2.zip"]);
});

test("writeBundleAtomically refuses names that are not a single path segment", async () => {
  const root = createTempBase("grclanker-atomic-names-");
  for (const name of ["../escape", "nested/bundle", "..", "", ".grclanker-staging-00000000-1-ab"]) {
    await assert.rejects(writeBundleAtomically({ root, names: [name] }, async () => {}), /Refusing to use bundle name/);
  }
  assert.deepEqual(readdirSync(root), []);
});

test("a process killed mid-write leaves nothing at the final path, and the next write removes its staging directory and reuses the name", async () => {
  const root = createTempBase("grclanker-atomic-kill-");
  const { child, ready, exited } = spawnModule(`
    import { writeFile } from "node:fs/promises";
    import { join } from "node:path";
    import { writeBundleAtomically } from ${JSON.stringify(MODULE_URL)};
    await writeBundleAtomically({ root: ${JSON.stringify(root)}, names: ["bundle"], zip: true }, async (staged) => {
      await writeFile(join(staged.dir, "partial.json"), "{");
      process.stdout.write("ready");
      await new Promise(() => setInterval(() => {}, 1000));
    });
  `);
  await ready;
  child.kill("SIGKILL");
  await exited;

  const leftovers = stagingEntries(root);
  assert.equal(leftovers.length, 1, "the killed writer's staging directory is the only entry");
  assert.deepEqual(readdirSync(root), leftovers, "no partial bundle or archive exists at the final path");
  assert.ok(existsSync(join(root, leftovers[0], "bundle", "partial.json")));

  const result = await writeBundleAtomically({ root, names: numberedNames("bundle", 6), zip: true }, (staged) => writeSampleBundle(staged));

  assert.equal(result.outputDir, join(root, "bundle"), "the rerun commits under the name the killed run would have used");
  assert.deepEqual(readdirSync(root).sort(), ["bundle", "bundle.zip"]);
});

const COMMIT_STOPS = [
  { stopAt: "bundle", afterMove: false },
  { stopAt: "bundle.zip", afterMove: false },
  { stopAt: "bundle.zip", afterMove: true },
];

test("a commit whose process was killed partway is finished by the next write under the same root", async () => {
  for (const { stopAt, afterMove } of COMMIT_STOPS) {
    const root = createTempBase("grclanker-atomic-commit-kill-");
    const { child, ready, exited } = spawnModule(commitThatStops(root, join(root, stopAt), "hang", { afterMove }));
    await ready;
    child.kill("SIGKILL");
    await exited;
    const when = `killed ${afterMove ? "after" : "before"} the move onto ${stopAt}`;
    assert.equal(existsSync(join(root, "bundle")), stopAt === "bundle.zip", when);
    assert.equal(existsSync(join(root, "bundle.zip")), afterMove, when);
    assert.equal(stagingEntries(root).length, 1);

    const next = await writeBundleAtomically({ root, names: numberedNames("bundle", 6), zip: true }, (staged) => writeSampleBundle(staged));

    assert.equal(readFileSync(join(root, "bundle", "README.md"), "utf8"), "# bundle\n");
    assert.equal(readFileSync(join(root, "bundle.zip"), "utf8"), "zip-bytes", "the interrupted bundle lands with its archive");
    assert.equal(next.outputDir, join(root, "bundle-2"));
    assert.deepEqual(readdirSync(root).sort(), ["bundle", "bundle-2", "bundle-2.zip", "bundle.zip"]);
  }
});

test("a process that exits partway through a commit finishes it on the way out", async () => {
  for (const { stopAt, afterMove } of COMMIT_STOPS) {
    const root = createTempBase("grclanker-atomic-commit-exit-");
    const { ready, exited } = spawnModule(commitThatStops(root, join(root, stopAt), "exit", { afterMove }));
    ready.catch(() => {});

    assert.equal(await exited, 0);
    const when = `exited ${afterMove ? "after" : "before"} the move onto ${stopAt}`;
    assert.deepEqual(readdirSync(root).sort(), ["bundle", "bundle.zip"], when);
    assert.equal(readFileSync(join(root, "bundle", "README.md"), "utf8"), "# bundle\n");
    assert.equal(readFileSync(join(root, "bundle.zip"), "utf8"), "zip-bytes");
  }
});

test("finishing an interrupted commit withdraws its directory when the archive's name was taken in the meantime", async () => {
  const root = createTempBase("grclanker-atomic-commit-taken-");
  const { child, ready, exited } = spawnModule(commitThatStops(root, join(root, "bundle.zip"), "hang"));
  await ready;
  child.kill("SIGKILL");
  await exited;
  writeFileSync(join(root, "bundle.zip"), "another writer's archive");

  const next = await writeBundleAtomically({ root, names: numberedNames("bundle", 6), zip: true }, (staged) => writeSampleBundle(staged));

  assert.equal(readFileSync(join(root, "bundle.zip"), "utf8"), "another writer's archive");
  assert.equal(next.outputDir, join(root, "bundle-2"));
  assert.deepEqual(readdirSync(root).sort(), ["bundle-2", "bundle-2.zip", "bundle.zip"], "no directory is left without its archive");
});

test("the sweep keeps staging entries that belong to a live process or another host", async () => {
  const root = createTempBase("grclanker-atomic-sweep-");
  const { child, ready, exited } = spawnModule(`process.stdout.write("ready"); setInterval(() => {}, 1000);`);
  await ready;
  const dead = await deadPid();
  const live = `.grclanker-staging-${HOST_TOKEN}-${child.pid}-aaaaaaaaaaaa`;
  const otherHost = `.grclanker-staging-${HOST_TOKEN === "00000000" ? "11111111" : "00000000"}-${dead}-bbbbbbbbbbbb`;
  const abandoned = `.grclanker-staging-${HOST_TOKEN}-${dead}-cccccccccccc`;
  for (const name of [live, otherHost, abandoned]) mkdirSync(join(root, name, "bundle"), { recursive: true });

  try {
    await writeBundleAtomically({ root, names: ["bundle"] }, (staged) => writeSampleBundle(staged, { zip: false }));
  } finally {
    child.kill("SIGKILL");
    await exited;
  }

  assert.deepEqual(stagingEntries(root).sort(), [live, otherHost].sort());
  assert.equal(existsSync(join(root, "bundle", "README.md")), true);
});

test("writeFileAtomically replaces a file in one step and keeps the old content when the write fails", async () => {
  const root = createTempBase("grclanker-atomic-file-");
  const target = join(root, "catalog.json");
  writeFileSync(target, "{\"version\":1}\n");

  await withWriteFailure(async () => {
    await assert.rejects(writeFileAtomically(target, "{\"version\":2}\n", { encoding: "utf8" }), new RegExp(SIMULATED_CRASH));
  }, { failAt: 1 });
  assert.equal(readFileSync(target, "utf8"), "{\"version\":1}\n");
  assert.deepEqual(newEntries(root, new Set(["catalog.json"])), []);

  await writeFileAtomically(target, "{\"version\":2}\n", { encoding: "utf8", mode: 0o600 });
  assert.equal(readFileSync(target, "utf8"), "{\"version\":2}\n");
  assert.equal(statSync(target).mode & 0o777, 0o600);
  assert.deepEqual(readdirSync(root), ["catalog.json"]);
});

test("the staging directory, and the directories made on the way to the root, go away when the process exits while a write is in flight", async () => {
  const base = createTempBase("grclanker-atomic-exit-");
  const root = join(base, "exports", "acme");
  const { ready, exited } = spawnModule(`
    import { writeBundleAtomically } from ${JSON.stringify(MODULE_URL)};
    void writeBundleAtomically({ root: ${JSON.stringify(root)}, names: ["bundle"] }, async () => {
      process.stdout.write("ready");
      setTimeout(() => process.exit(0), 10);
      await new Promise(() => setInterval(() => {}, 1000));
    });
  `);
  await ready;
  await exited;
  assert.deepEqual(readdirSync(base), []);
});
