/**
 * The ZIP archive an audit bundle export writes next to its bundle directory.
 */
import { createWriteStream } from "node:fs";
import { chmod } from "node:fs/promises";
import { ZipArchive } from "archiver";
import { ToolCallAbortedError } from "./abort.js";

/** A file to archive and the name it is stored under. */
export interface ZipEntry {
  path: string;
  name: string;
}

/**
 * Writes a new archive at `zipPath`, readable by its owner only, holding every
 * file under the directory `source` by its path relative to that directory, or
 * just the listed entries. An existing file at `zipPath` is never replaced.
 *
 * A failure or an abort of `signal` stops the archive: it opens no further
 * file, and the call rejects, with ToolCallAbortedError for an abort, once the
 * output stream has closed. The partial archive is left for the caller to
 * discard along with the rest of its staging directory.
 */
export async function createZipArchive(
  source: string | readonly ZipEntry[],
  zipPath: string,
  signal?: AbortSignal,
): Promise<void> {
  if (signal?.aborted) throw new ToolCallAbortedError(signal);
  await new Promise<void>((resolve, reject) => {
    const output = createWriteStream(zipPath, { mode: 0o600, flags: "wx" });
    const archive = new ZipArchive({ zlib: { level: 9 } });
    // A derived signal carries the listener, so exports running at once do not pile listeners onto the tool call's signal.
    const watched = signal && AbortSignal.any([signal]);
    let failure: { error: unknown } | undefined;
    const stop = (error: unknown) => {
      if (failure) return;
      failure = { error };
      watched?.removeEventListener("abort", onAbort);
      archive.abort();
      // archiver cannot cancel the entry in progress, so it drains into nothing rather than stalling with its file open.
      archive.unpipe(output);
      archive.resume();
      output.destroy();
    };
    const onAbort = () => stop(new ToolCallAbortedError(signal!));

    output.on("close", () => {
      watched?.removeEventListener("abort", onAbort);
      if (failure) reject(failure.error);
      else resolve();
    });
    output.on("error", stop);
    archive.on("error", stop);
    watched?.addEventListener("abort", onAbort, { once: true });
    archive.pipe(output);
    if (typeof source === "string") archive.directory(source, false);
    else for (const entry of source) archive.file(entry.path, { name: entry.name });
    archive.finalize().catch(stop);
  });
  await chmod(zipPath, 0o600);
}
