import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";

import { joinBashArgs, quoteForBash } from "../dist/pi/shell.js";

test("quoteForBash prevents command substitution and variable expansion", () => {
  const payload = "$(printf hacked)-$HOME-`printf nope`";
  const result = spawnSync("bash", ["-lc", `printf '%s' ${quoteForBash(payload)}`], {
    encoding: "utf8",
  });

  assert.equal(result.status, 0);
  assert.equal(result.stdout, payload);
});

test("joinBashArgs preserves argv boundaries for env exec style commands", () => {
  const command = joinBashArgs(["printf", "%s|%s", "a b", "$HOME"]);
  const result = spawnSync("bash", ["-lc", command], { encoding: "utf8" });

  assert.equal(result.status, 0);
  assert.equal(result.stdout, "a b|$HOME");
});
