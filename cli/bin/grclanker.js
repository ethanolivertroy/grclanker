#!/usr/bin/env node
import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const binDir = dirname(fileURLToPath(import.meta.url));
const distEntry = resolve(binDir, "../dist/index.js");
const srcEntry = resolve(binDir, "../index.ts");
const distBranding = resolve(binDir, "../dist/pi/branding.js");
const srcBranding = resolve(binDir, "../pi/branding.ts");
const MIN_NODE = [20, 19, 0];

function parseVersion(version) {
  return version.replace(/^v/, "").split(".").map((part) => Number(part) || 0);
}

function isOlderThan(required) {
  const current = parseVersion(process.versions.node);
  for (let i = 0; i < required.length; i += 1) {
    const left = current[i] ?? 0;
    const right = required[i] ?? 0;
    if (left > right) return false;
    if (left < right) return true;
  }
  return false;
}

async function importEntry(entryPath) {
  await import(pathToFileURL(entryPath).href);
}

async function assertBrandedRuntime(entryPath) {
  if (!existsSync(entryPath)) return;
  const mod = await import(pathToFileURL(entryPath).href);
  if (typeof mod.assertEmbeddedPiBranding !== "function") {
    throw new Error("Embedded branding verifier is unavailable in this grclanker build.");
  }
  await mod.assertEmbeddedPiBranding(resolve(binDir, ".."));
}

async function run() {
  if (isOlderThan(MIN_NODE)) {
    console.error(
      `grclanker requires Node.js 20.19.0 or newer for source/npm installs (found ${process.version}).`,
    );
    console.error("Use the release-bundle installer if you do not want to manage Node yourself.");
    process.exit(1);
  }

  if (existsSync(distEntry)) {
    await assertBrandedRuntime(distBranding);
    await importEntry(distEntry);
    return;
  }

  if (existsSync(srcEntry)) {
    try {
      const { register } = await import("tsx/esm/api");
      register();
      await assertBrandedRuntime(srcBranding);
      await importEntry(srcEntry);
      return;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      console.error(`Unable to start grclanker from source: ${message}`);
      process.exit(1);
    }
  }

  console.error("Unable to locate grclanker runtime. Expected dist/index.js or index.ts next to the package.");
  process.exit(1);
}

run();
