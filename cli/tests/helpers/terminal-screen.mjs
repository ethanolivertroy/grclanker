/**
 * Read Pi's alternate-screen TUI as plain text. The TUI writes each changed
 * row as `ESC [ <row> ; 1 H ESC [ 2 K <text>` and clears the screen before a
 * full redraw, so applying those writes in order and dropping every other
 * escape sequence gives the screen a user sees.
 */
import { setTimeout as sleep } from "node:timers/promises";

// CSI sequences, OSC strings, DCS/SOS/PM/APC strings, then any other two-byte escape.
const ESCAPES = /\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][\s\S]*?(?:\x07|\x1b\\)|\x1b[PX^_][\s\S]*?\x1b\\|\x1b[ -/]*[0-~]/g;
const SCREEN_WRITES = /\x1b\[2J|\x1b\[(\d+);1H\x1b\[2K/g;

/** `text` without escape sequences or carriage returns. */
export function stripTerminal(text) {
  return text.replace(ESCAPES, "").replaceAll("\r", "");
}

/** The alternate screen after `output`, one plain line per row. */
export function screenText(output) {
  const rows = [];
  let row;
  let from = 0;
  const flush = (end) => {
    if (row !== undefined) rows[row] = stripTerminal(output.slice(from, end)).trimEnd();
  };
  for (const match of output.matchAll(SCREEN_WRITES)) {
    flush(match.index);
    if (match[1] === undefined) {
      rows.length = 0;
      row = undefined;
    } else {
      row = Number(match[1]) - 1;
    }
    from = match.index + match[0].length;
  }
  flush(output.length);
  return Array.from(rows, (line) => line ?? "").join("\n");
}

/** Poll `read()` until `predicate` accepts it. */
export async function waitForText(read, predicate, description, timeoutMs = 60_000) {
  const started = Date.now();
  for (;;) {
    const text = read();
    if (predicate(text)) return text;
    if (Date.now() - started > timeoutMs) throw new Error(`Timed out waiting for ${description}. Last screen:\n${text}`);
    await sleep(25);
  }
}

/** A terminal for Pi's TUI that keeps what it is sent and types what a test asks it to. */
export class ScreenTerminal {
  output = "";
  #onInput;

  constructor(columns = 120, rows = 60) {
    this.columns = columns;
    this.rows = rows;
  }

  get kittyProtocolActive() {
    return false;
  }

  start(onInput) {
    this.#onInput = onInput;
  }

  stop() {
    this.#onInput = undefined;
  }

  async drainInput() {}

  write(data) {
    this.output += data;
  }

  /** Send keys: each character of `text` as one key, or one escape sequence such as `\x1b[Z`. */
  type(text) {
    if (this.#onInput === undefined) throw new Error("The terminal app is not running");
    if (text.startsWith("\x1b")) this.#onInput(text);
    else for (const key of text) this.#onInput(key);
  }

  screen() {
    return screenText(this.output);
  }

  waitFor(predicate, description) {
    return waitForText(() => this.screen(), predicate, description);
  }

  moveBy() {}
  hideCursor() {}
  showCursor() {}
  clearLine() {}
  clearFromCursor() {}
  clearScreen() {}
  setTitle() {}
  setProgress() {}
  setProgramStatus() {}
}
