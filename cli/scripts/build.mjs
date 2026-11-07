#!/usr/bin/env node
import { spawn } from "node:child_process";
import { access, readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { dirname, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { replaceDirectoryAtomically } from "../core/atomic-files.ts";

const cliRoot = resolve(import.meta.dirname, "..");

function run(command, args, cwd) {
  return new Promise((resolveRun, reject) => {
    const child = spawn(command, args, { cwd, stdio: "inherit" });
    child.once("error", reject);
    child.once("exit", (status, signal) => {
      if (status === 0) resolveRun();
      else reject(new Error(`${command} failed (${signal ?? `exit ${status}`})`));
    });
  });
}

/**
 * A failed compiler never removes or partially overwrites the last runnable build.
 * The project override also stages the registry bootstrap that excludes stale
 * generated Cursor entries; the final build validates the regenerated entries.
 */
export async function buildCli({ root = cliRoot, project = "tsconfig.json", runCommand = run } = {}) {
  const require = createRequire(resolve(root, "package.json"));
  const typescriptManifestPath = require.resolve("typescript/package.json");
  const manifest = JSON.parse(await readFile(typescriptManifestPath, "utf8"));
  const compiler = resolve(dirname(typescriptManifestPath), manifest.bin.tsc);
  await runCommand(process.execPath, [resolve(root, "scripts/patch-embedded-pi.mjs")], root);
  await replaceDirectoryAtomically(resolve(root, "dist"), async (staging) => {
    await runCommand(process.execPath, [compiler, "--project", resolve(root, project), "--outDir", staging], root);
    // Do not publish a successful-but-empty compiler invocation.
    for (const entry of ["index.js", "core/registry.js", "extensions/grc-tools.js"]) await access(resolve(staging, entry));
  });
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  try {
    const args = process.argv.slice(2);
    if (args.length !== 0 && (args.length !== 2 || args[0] !== "--project" || !args[1].trim())) {
      throw new Error("Usage: build.mjs [--project <tsconfig>]");
    }
    await buildCli({ project: args[1] });
  } catch (error) {
    console.error(`CLI build failed: ${error instanceof Error ? error.message : String(error)}`);
    process.exitCode = 1;
  }
}
