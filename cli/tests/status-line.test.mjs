import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { FooterComponent, initTheme } from "@earendil-works/pi-coding-agent";
import { FooterDataProvider } from "../node_modules/@earendil-works/pi-coding-agent/dist/core/footer-data-provider.js";
import grcTools from "../dist/extensions/grc-tools.js";
import { formatGrclankerStatus } from "../dist/extensions/grc-tools/header.js";

const ANSI_RE = /\x1b\[[0-9;]*m/g;

function stripAnsi(text) {
  return text.replace(ANSI_RE, "");
}

function createFooterSession(cwd) {
  const sessionManager = {
    getCwd: () => cwd,
    getSessionName: () => undefined,
    getSessionId: () => "status-line-test",
    getLeafId: () => null,
    getEntryCount: () => 0,
    getEntries: () => [],
    getBranch: () => [],
  };
  return {
    sessionManager,
    state: { model: undefined, thinkingLevel: "off" },
    model: undefined,
    routedModel: undefined,
    getContextUsage: () => undefined,
  };
}

async function renderStatusLineAfterSessionStart(width) {
  const grclankerHome = mkdtempSync(join(tmpdir(), "grclanker-status-line-"));
  const previousHome = process.env.GRCLANKER_HOME;
  process.env.GRCLANKER_HOME = grclankerHome;
  const footerData = new FooterDataProvider(grclankerHome);

  try {
    const handlers = new Map();
    grcTools({
      on(event, handler) {
        handlers.set(event, handler);
        return () => {};
      },
      registerTool() {},
      getActiveTools: () => [],
    });

    const session = createFooterSession(grclankerHome);
    const sessionStart = handlers.get("session_start");
    assert.equal(typeof sessionStart, "function");
    await sessionStart({ type: "session_start" }, {
      hasUI: true,
      cwd: grclankerHome,
      model: undefined,
      sessionManager: session.sessionManager,
      ui: {
        setStatus: (key, text) => footerData.setExtensionStatus(key, text),
        notify() {},
        setHeader() {},
      },
    });

    initTheme("dark");
    const lines = new FooterComponent(session, footerData).render(width);
    return { statuses: new Map(footerData.getExtensionStatuses()), statusLine: stripAnsi(lines.at(-1)) };
  } finally {
    footerData.dispose();
    if (previousHome === undefined) delete process.env.GRCLANKER_HOME;
    else process.env.GRCLANKER_HOME = previousHome;
    rmSync(grclankerHome, { recursive: true, force: true });
  }
}

test("formatGrclankerStatus separates segments with a middle dot and drops empty ones", () => {
  assert.equal(
    formatGrclankerStatus(["compute: bash runs directly on the local host shell", " 241 domain tools ready "]),
    "compute: bash runs directly on the local host shell · 241 domain tools ready",
  );
  assert.equal(formatGrclankerStatus(["", "241 domain tools ready", "  "]), "241 domain tools ready");
  assert.equal(formatGrclankerStatus([]), "");
});

test("Pi footer status line separates the compute and domain tool segments", async () => {
  const { statuses, statusLine } = await renderStatusLineAfterSessionStart(200);

  assert.deepEqual([...statuses.keys()], ["grclanker"]);
  assert.match(statusLine, /^compute: bash runs directly on the local host shell · \d+ domain tools ready$/);
  assert.doesNotMatch(statusLine, /shell \d+ domain tools/);
});
