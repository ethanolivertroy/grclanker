import test from "node:test";
import assert from "node:assert/strict";
import {
  chmodSync,
  existsSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, join, relative } from "node:path";
import { inflateRawSync } from "node:zlib";

import {
  GwsCliCommandError,
  checkGwsCliAccess,
  collectGwsOperatorEvidenceBundle,
  defaultGwsCliRunner,
  investigateGwsAlerts,
  registerGwsOperatorTools,
  resolveGwsCliExecutable,
  reviewGwsTokenActivity,
  traceGwsAdminActivity,
} from "../dist/extensions/grc-tools/gws-ops.js";

function createTempBase(prefix) {
  return mkdtempSync(join(tmpdir(), prefix));
}

function createFakeBinary(base, name = "gws") {
  const pathname = join(base, name);
  writeFileSync(pathname, "#!/bin/sh\n");
  return pathname;
}

/** A real executable stand-in for gws so defaultGwsCliRunner is exercised end to end. */
function createScriptedBinary(base, script) {
  const pathname = join(base, "gws");
  writeFileSync(pathname, `#!/bin/sh\n${script}\n`);
  chmodSync(pathname, 0o755);
  return pathname;
}

/**
 * The published gws prints two lines for --version (crates/google-workspace-cli/src/main.rs, the is_version_flag branch:
 * `gws <CARGO_PKG_VERSION>`, then the fixed disclaimer added in 0.3.5 as CHANGELOG entry 1991d53). Pinned here byte for
 * byte as the v0.22.5 release binary prints it, so every fixture in this file answers --version with the real shape.
 */
const REAL_VERSION_LINES = ["gws 0.22.5", "This is not an officially supported Google product."];
const REAL_VERSION_STDOUT = `${REAL_VERSION_LINES.join("\n")}\n`;
/** The shell branch a scripted gws uses to answer --version with the real two-line output. */
const PRINT_REAL_VERSION = `if [ "$1" = "--version" ]; then printf '%s\\n' "${REAL_VERSION_LINES[0]}" "${REAL_VERSION_LINES[1]}"; exit 0; fi`;

function parseParams(args) {
  const paramsIndex = args.indexOf("--params");
  if (paramsIndex === -1) return {};
  return JSON.parse(args[paramsIndex + 1]);
}

function execution(executable, args, stdout) {
  return {
    executable: executable.executable,
    displayExecutable: executable.displayExecutable,
    args,
    command: [executable.displayExecutable, ...args].join(" "),
    stdout,
    stderr: "",
    exitCode: 0,
  };
}

/** Alert Center alerts carry status and severity under metadata, per the Alert resource reference. */
function alertsPayload(overrides = {}) {
  return {
    alerts: [
      {
        alertId: "a-1",
        type: "Suspicious login",
        source: "Google Operations",
        createTime: "2030-01-01T00:00:00Z",
        metadata: { alertId: "a-1", status: "NOT_STARTED", severity: "HIGH", assignee: "secops@example.com" },
      },
      {
        alertId: "a-2",
        type: "Password spray",
        source: "Google Operations",
        createTime: "2030-01-02T00:00:00Z",
        metadata: { alertId: "a-2", status: "CLOSED", severity: "MEDIUM" },
      },
    ],
    ...overrides,
  };
}

function adminPayload(overrides = {}) {
  return {
    items: [
      {
        id: { time: "2030-01-01T12:00:00Z", uniqueQualifier: "u1", applicationName: "admin", customerId: "C0123abcd" },
        actor: { email: "admin@example.com", profileId: "100", callerType: "USER" },
        ipAddress: "203.0.113.1",
        events: [{ type: "APPLICATION_SETTINGS", name: "CHANGE_APPLICATION_SETTING" }],
      },
    ],
    ...overrides,
  };
}

function tokenPayload(overrides = {}) {
  return {
    items: [
      {
        id: { time: "2030-01-01T12:05:00Z", uniqueQualifier: "u2", applicationName: "token", customerId: "C0123abcd" },
        actor: {
          email: "user@example.com",
          applicationInfo: { applicationName: "Drive Syncer", oAuthClientId: "client-1" },
        },
        events: [{ type: "auth", name: "authorize" }, { type: "auth", name: "request" }],
      },
    ],
    ...overrides,
  };
}

function listFilesRecursively(root) {
  const files = [];
  for (const entry of readdirSync(root, { withFileTypes: true })) {
    const pathname = join(root, entry.name);
    if (entry.isDirectory()) files.push(...listFilesRecursively(pathname));
    else files.push(pathname);
  }
  return files;
}

/** Reads every entry of a zip through its central directory so the extracted text can be grepped. */
function readZipEntries(zipPath) {
  const buffer = readFileSync(zipPath);
  const eocd = buffer.lastIndexOf(Buffer.from([0x50, 0x4b, 0x05, 0x06]));
  assert.ok(eocd >= 0, "zip end-of-central-directory record not found");
  const entryCount = buffer.readUInt16LE(eocd + 10);
  let offset = buffer.readUInt32LE(eocd + 16);
  const entries = new Map();
  for (let index = 0; index < entryCount; index += 1) {
    assert.equal(buffer.readUInt32LE(offset), 0x02014b50, "central directory header signature");
    const method = buffer.readUInt16LE(offset + 10);
    const compressedSize = buffer.readUInt32LE(offset + 20);
    const nameLength = buffer.readUInt16LE(offset + 28);
    const extraLength = buffer.readUInt16LE(offset + 30);
    const commentLength = buffer.readUInt16LE(offset + 32);
    const localOffset = buffer.readUInt32LE(offset + 42);
    const name = buffer.toString("utf8", offset + 46, offset + 46 + nameLength);
    const dataStart = localOffset + 30 + buffer.readUInt16LE(localOffset + 26) + buffer.readUInt16LE(localOffset + 28);
    const data = buffer.subarray(dataStart, dataStart + compressedSize);
    if (!name.endsWith("/")) {
      entries.set(name, method === 8 ? inflateRawSync(data).toString("utf8") : data.toString("utf8"));
    }
    offset += 46 + nameLength + extraLength + commentLength;
  }
  return entries;
}

const PLANTED_SECRET = "FAKESECRET-9f8e7d6c";
const ENV_TOKEN_PLACEHOLDER = "__GOOGLE_WORKSPACE_CLI_TOKEN__";

function planted(carrier) {
  return `${PLANTED_SECRET}-${carrier}`;
}

/** A heredoc lets the shell expand $GOOGLE_WORKSPACE_CLI_TOKEN inside the JSON, so the CLI stand-in echoes its own credential. */
function heredoc(payload) {
  const json = JSON.stringify(payload).split(`"${ENV_TOKEN_PLACEHOLDER}"`).join('"$GOOGLE_WORKSPACE_CLI_TOKEN"');
  return `cat <<EOF\n${json}\nEOF`;
}

/** A gws stand-in whose every response carries planted secrets: camelCase keys, {name, value} pairs, alert data blobs, links, and the env token. */
function createSecretEchoingBinary(base) {
  const alerts = {
    alerts: [
      {
        alertId: "a-1",
        type: "Device compromised",
        source: "Mobile device management",
        createTime: "2030-01-01T00:00:00Z",
        etag: planted("alert-etag"),
        securityInvestigationToolLink: `https://admin.google.com/ac/sc/investigation?token=${planted("alert-link-query")}`,
        metadata: { alertId: "a-1", status: "NOT_STARTED", severity: "HIGH", assignee: "secops@example.com" },
        data: {
          "@type": "type.googleapis.com/google.apps.alertcenter.type.DeviceCompromised",
          rawConfig: `snmp community=${planted("alert-data-community")}`,
          note: planted("alert-data-benign-key"),
          client_secret: planted("alert-data-client-secret"),
          echoedToken: ENV_TOKEN_PLACEHOLDER,
        },
      },
    ],
  };
  const admin = {
    items: [
      {
        id: { time: "2030-01-01T12:00:00Z", uniqueQualifier: "u1", applicationName: "admin", customerId: "C0123abcd" },
        actor: { email: "admin@example.com", profileId: "100", callerType: "USER", key: planted("admin-actor-key") },
        ipAddress: "203.0.113.1",
        events: [{
          type: "APPLICATION_SETTINGS",
          name: "CHANGE_APPLICATION_SETTING",
          parameters: [
            { name: "oauth_token", value: planted("admin-oauth-token-param") },
            { name: "NEW_VALUE", value: planted("admin-benign-param") },
            { name: "SETTING_NAME", value: ENV_TOKEN_PLACEHOLDER },
          ],
        }],
        privateKey: planted("admin-private-key"),
      },
    ],
  };
  const token = {
    items: [
      {
        id: { time: "2030-01-01T12:05:00Z", uniqueQualifier: "u2", applicationName: "token", customerId: "C0123abcd" },
        actor: { email: ENV_TOKEN_PLACEHOLDER, applicationInfo: { applicationName: "Drive Syncer", oAuthClientId: "client-1" } },
        events: [{ type: "auth", name: "authorize", parameters: [{ name: "accessToken", multiValue: [planted("token-access-token-multivalue")] }] }],
        refreshToken: planted("token-refresh-token"),
      },
    ],
    nextPageToken: "more-tokens",
  };
  return createScriptedBinary(base, [
    PRINT_REAL_VERSION,
    'case "$*" in',
    "  alertcenter:v1beta1*)",
    heredoc(alerts),
    "    ;;",
    "  *'\"applicationName\":\"admin\"'*)",
    heredoc(admin),
    "    ;;",
    "  *'\"applicationName\":\"token\"'*)",
    heredoc(token),
    "    ;;",
    '  *) echo "unexpected command: $*" 1>&2; exit 3 ;;',
    "esac",
  ].join("\n"));
}

function createRunner(options = {}) {
  const seen = options.seen ?? [];
  return async (request) => {
    const { executable, args } = request;
    seen.push(request);
    const command = [executable.displayExecutable, ...args].join(" ");
    if (args[0] === "--version") {
      return execution(executable, args, REAL_VERSION_STDOUT);
    }

    if (args[0] === "alertcenter:v1beta1") {
      return execution(executable, args, JSON.stringify(options.alerts ?? alertsPayload()));
    }

    if (args[0] === "admin-reports") {
      const applicationName = parseParams(args).applicationName;
      if (applicationName === "admin") {
        return execution(executable, args, typeof options.admin === "string" ? options.admin : JSON.stringify(options.admin ?? adminPayload()));
      }
      if (applicationName === "token") {
        return execution(executable, args, JSON.stringify(options.token ?? tokenPayload()));
      }
    }

    throw new Error(`Unexpected mocked gws command: ${command}`);
  };
}

test("resolveGwsCliExecutable prefers explicit binary path", () => {
  const base = createTempBase("grclanker-gws-ops-bin-");
  const fake = createFakeBinary(base);

  const resolved = resolveGwsCliExecutable({ gwsBin: fake });
  assert.equal(resolved.executable, fake);
  assert.equal(resolved.installed, true);
  assert.equal(resolved.source, "argument");
});

test("resolveGwsCliExecutable falls back to GRCLANKER_GWS_BIN before PATH", () => {
  const base = createTempBase("grclanker-gws-ops-envbin-");
  const fake = createFakeBinary(base);
  const argBinary = createFakeBinary(base, "gws-arg");

  const fromEnv = resolveGwsCliExecutable({}, { GRCLANKER_GWS_BIN: fake, PATH: "/nonexistent" });
  assert.equal(fromEnv.executable, fake);
  assert.equal(fromEnv.source, "environment");
  assert.equal(fromEnv.installed, true);

  const argWins = resolveGwsCliExecutable({ gwsBin: argBinary }, { GRCLANKER_GWS_BIN: fake });
  assert.equal(argWins.executable, argBinary);
  assert.equal(argWins.source, "argument");

  const missing = resolveGwsCliExecutable({}, { GRCLANKER_GWS_BIN: join(base, "does-not-exist") });
  assert.equal(missing.installed, false);
  assert.equal(missing.source, "environment");
});

test("credential precedence: config_dir maps to GOOGLE_WORKSPACE_CLI_CONFIG_DIR and GOOGLE_WORKSPACE_CLI_* values are inherited untouched", async () => {
  const base = createTempBase("grclanker-gws-ops-env-");
  const fake = createFakeBinary(base);
  const seen = [];
  const inherited = {
    PATH: "/usr/bin",
    GOOGLE_WORKSPACE_CLI_TOKEN: "ya29.inherited-token",
    GOOGLE_WORKSPACE_CLI_CREDENTIALS_FILE: "/secrets/service-account.json",
    GOOGLE_WORKSPACE_CLI_CONFIG_DIR: "/home/operator/.config/gws",
    UNRELATED: "keep",
  };

  await traceGwsAdminActivity({ gwsBin: fake, configDir: join(base, "override-config") }, createRunner({ seen }), inherited);
  assert.equal(seen.length, 1);
  assert.equal(seen[0].executable.executable, fake);
  assert.equal(seen[0].env.GOOGLE_WORKSPACE_CLI_CONFIG_DIR, join(base, "override-config"));
  assert.equal(seen[0].env.GOOGLE_WORKSPACE_CLI_TOKEN, "ya29.inherited-token");
  assert.equal(seen[0].env.GOOGLE_WORKSPACE_CLI_CREDENTIALS_FILE, "/secrets/service-account.json");
  assert.equal(seen[0].env.UNRELATED, "keep");
  assert.equal(inherited.GOOGLE_WORKSPACE_CLI_CONFIG_DIR, "/home/operator/.config/gws");

  seen.length = 0;
  await reviewGwsTokenActivity({ gwsBin: fake }, createRunner({ seen }), inherited);
  assert.equal(seen[0].env.GOOGLE_WORKSPACE_CLI_CONFIG_DIR, "/home/operator/.config/gws");
  assert.equal(seen[0].env.GOOGLE_WORKSPACE_CLI_TOKEN, "ya29.inherited-token");

  seen.length = 0;
  await checkGwsCliAccess({ gwsBin: fake, configDir: "  " }, createRunner({ seen }), inherited);
  assert.equal(seen[0].args[0], "--version");
  assert.equal(seen[0].expectJson, false);
  assert.equal(seen[0].env.GOOGLE_WORKSPACE_CLI_CONFIG_DIR, "/home/operator/.config/gws");
});

test("curated commands match the published gws CLI shape: <service> <resource> <method> --params <json>", async () => {
  const base = createTempBase("grclanker-gws-ops-shape-");
  const fake = createFakeBinary(base);
  const before = Date.now();

  const alerts = await investigateGwsAlerts({ gwsBin: fake, max_results: 25, filter: "createTime >= \"2030-01-01T00:00:00Z\"" }, createRunner());
  assert.deepEqual(alerts.command.args.slice(0, 4), ["alertcenter:v1beta1", "alerts", "list", "--params"]);
  assert.deepEqual(JSON.parse(alerts.command.args[4]), { pageSize: 25, filter: "createTime >= \"2030-01-01T00:00:00Z\"" });

  const admin = await traceGwsAdminActivity({ gwsBin: fake, lookback_days: 10, max_results: 500 }, createRunner());
  assert.deepEqual(admin.command.args.slice(0, 4), ["admin-reports", "activities", "list", "--params"]);
  const adminParams = JSON.parse(admin.command.args[4]);
  assert.equal(adminParams.userKey, "all");
  assert.equal(adminParams.applicationName, "admin");
  assert.equal(adminParams.maxResults, 250);
  assert.ok(Math.abs(before - 10 * 24 * 60 * 60 * 1000 - Date.parse(adminParams.startTime)) < 5000);

  const token = await reviewGwsTokenActivity({ gwsBin: fake }, createRunner());
  const tokenParams = JSON.parse(token.command.args[4]);
  assert.equal(tokenParams.applicationName, "token");
  assert.equal(tokenParams.maxResults, 50);
  assert.match(token.command.command, /^\S+ admin-reports activities list --params '\{"userKey":"all","applicationName":"token"/);
});

test("max_results above the bridge limit is clamped to 250 and the clamp is stated in the notes", async () => {
  const base = createTempBase("grclanker-gws-ops-clamp-");
  const fake = createFakeBinary(base);

  const admin = await traceGwsAdminActivity({ gwsBin: fake, max_results: 1000 }, createRunner());
  assert.equal(JSON.parse(admin.command.args[4]).maxResults, 250);
  assert.ok(admin.notes.some((note) => /^Max results: 250 \(requested 1000, clamped to the bridge limit of 250/.test(note)), admin.notes.join("\n"));

  const alerts = await investigateGwsAlerts({ gwsBin: fake, max_results: 300 }, createRunner());
  assert.equal(JSON.parse(alerts.command.args[4]).pageSize, 250);
  assert.ok(alerts.notes.some((note) => /^Page size: 250 \(requested 300, clamped to the bridge limit of 250/.test(note)), alerts.notes.join("\n"));

  const withinLimit = await reviewGwsTokenActivity({ gwsBin: fake, max_results: 40 }, createRunner());
  assert.ok(withinLimit.notes.includes("Max results: 40"));
});

test("checkGwsCliAccess previews the probe command in dry-run mode", async () => {
  const base = createTempBase("grclanker-gws-ops-check-");
  const fake = createFakeBinary(base);

  const result = await checkGwsCliAccess({ gwsBin: fake, dry_run: true }, createRunner());
  assert.equal(result.status, "preview");
  assert.equal(result.version, "gws 0.22.5");
  assert.match(result.command.command, /admin-reports activities list/);
});

test("checkGwsCliAccess maps auth failures cleanly", async () => {
  const base = createTempBase("grclanker-gws-ops-auth-");
  const fake = createFakeBinary(base);
  const runner = async ({ executable, args }) => {
    const command = [executable.displayExecutable, ...args].join(" ");
    if (args[0] === "--version") {
      return execution(executable, args, REAL_VERSION_STDOUT);
    }
    throw new GwsCliCommandError("auth", "Credentials missing", command, 2);
  };

  await assert.rejects(
    () => checkGwsCliAccess({ gwsBin: fake }, runner),
    (error) => error instanceof GwsCliCommandError && error.kind === "auth",
  );
});

test("verdict rule 1: a failing CLI invocation is an explicit error mapped from the documented exit codes", async () => {
  const base = createTempBase("grclanker-gws-ops-exit-");
  const fake = createScriptedBinary(base, `${PRINT_REAL_VERSION}\necho "Error: credentials missing, expired, or invalid" 1>&2\nexit 2`);

  await assert.rejects(
    () => traceGwsAdminActivity({ gwsBin: fake }, defaultGwsCliRunner),
    (error) => error instanceof GwsCliCommandError
      && error.kind === "auth"
      && error.exitCode === 2
      && /credentials missing/.test(error.message)
      && /admin-reports activities list/.test(error.command),
  );

  const apiFailure = createScriptedBinary(createTempBase("grclanker-gws-ops-exit1-"), 'echo "{\\"error\\":{\\"code\\":403}}"\nexit 1');
  await assert.rejects(
    () => reviewGwsTokenActivity({ gwsBin: apiFailure }, defaultGwsCliRunner),
    (error) => error instanceof GwsCliCommandError && error.kind === "api" && error.exitCode === 1,
  );

  const discoveryFailure = createScriptedBinary(createTempBase("grclanker-gws-ops-exit4-"), "exit 4");
  await assert.rejects(
    () => reviewGwsTokenActivity({ gwsBin: discoveryFailure }, defaultGwsCliRunner),
    (error) => error instanceof GwsCliCommandError && error.kind === "discovery" && /non-zero exit code without additional output/.test(error.message),
  );

  await assert.rejects(
    () => traceGwsAdminActivity({ gwsBin: join(base, "missing-gws") }, defaultGwsCliRunner),
    (error) => error instanceof GwsCliCommandError && error.kind === "missing" && /not installed or not on PATH/.test(error.message),
  );
});

test("verdict rule 1: a successful but non-JSON CLI response is an explicit error, while --version may be plain text", async () => {
  const base = createTempBase("grclanker-gws-ops-nonjson-");
  const fake = createScriptedBinary(base, `${PRINT_REAL_VERSION}\necho "Fetching discovery document..."\necho "done"`);

  await assert.rejects(
    () => traceGwsAdminActivity({ gwsBin: fake }, defaultGwsCliRunner),
    (error) => error instanceof GwsCliCommandError
      && error.kind === "internal"
      && /could not parse the output as structured JSON/.test(error.message),
  );

  const preview = await checkGwsCliAccess({ gwsBin: fake, dry_run: true }, defaultGwsCliRunner);
  assert.equal(preview.version, "gws 0.22.5");

  await assert.rejects(
    () => checkGwsCliAccess({ gwsBin: fake }, defaultGwsCliRunner),
    (error) => error instanceof GwsCliCommandError && /could not parse the output as structured JSON/.test(error.message),
  );

  const runnerFake = createFakeBinary(createTempBase("grclanker-gws-ops-nonjson-runner-"));
  await assert.rejects(
    () => traceGwsAdminActivity({ gwsBin: runnerFake }, createRunner({ admin: "not json at all" })),
    (error) => error instanceof GwsCliCommandError && /could not parse the output as structured JSON/.test(error.message),
  );
});

test("defaultGwsCliRunner parses a real JSON response and forwards the environment", async () => {
  const base = createTempBase("grclanker-gws-ops-realjson-");
  const fake = createScriptedBinary(
    base,
    `${PRINT_REAL_VERSION}\n` + 'echo "{\\"items\\":[{\\"id\\":{\\"time\\":\\"2030-01-01T12:00:00Z\\",\\"uniqueQualifier\\":\\"u1\\"},\\"actor\\":{\\"email\\":\\"$GOOGLE_WORKSPACE_CLI_CONFIG_DIR\\"},\\"events\\":[{\\"name\\":\\"CHANGE_APPLICATION_SETTING\\"}]}]}"',
  );

  const result = await traceGwsAdminActivity({ gwsBin: fake, configDir: "/tmp/cfg-from-arg" }, defaultGwsCliRunner, { PATH: process.env.PATH });
  assert.equal(result.count, 1);
  assert.equal(result.complete, true);
  assert.equal(result.records[0].actor, "/tmp/cfg-from-arg");
});

test("investigateGwsAlerts parses alert records from documented Alert Center fields", async () => {
  const base = createTempBase("grclanker-gws-ops-alerts-");
  const fake = createFakeBinary(base);

  const result = await investigateGwsAlerts({ gwsBin: fake, max_results: 25 }, createRunner());
  assert.equal(result.count, 2);
  assert.equal(result.complete, true);
  assert.equal(result.nextPageToken, undefined);
  assert.equal(result.records[0].id, "a-1");
  assert.equal(result.records[0].status, "NOT_STARTED");
  assert.equal(result.records[0].severity, "HIGH");
  assert.equal(result.records[0].actor, "secops@example.com");
  assert.equal(result.records[1].status, "CLOSED");
  assert.match(result.command.command, /alertcenter:v1beta1 alerts list/);
  assert.ok(result.notes.some((note) => /^Complete: the CLI response carried no nextPageToken/.test(note)));
});

test("investigateGwsAlerts explains the missing alertcenter alias when gws exits with a validation error", async () => {
  const base = createTempBase("grclanker-gws-ops-alias-");
  const fake = createScriptedBinary(base, "echo \"Unknown service 'alertcenter'. Known services: drive, gmail, admin-reports\" 1>&2\nexit 3");

  await assert.rejects(
    () => investigateGwsAlerts({ gwsBin: fake }, defaultGwsCliRunner),
    (error) => error instanceof GwsCliCommandError
      && error.kind === "validation"
      && error.exitCode === 3
      && /registers no alertcenter alias/.test(error.message)
      && /gws_assess_monitoring/.test(error.message)
      && /Unknown service 'alertcenter'/.test(error.message),
  );

  const preview = await investigateGwsAlerts({ gwsBin: fake, dry_run: true }, defaultGwsCliRunner);
  assert.equal(preview.mode, "dry_run");
  assert.equal(preview.complete, null);
  assert.ok(preview.notes.some((note) => /registers no alertcenter service alias/.test(note)));
});

test("null standard: a dry-run preview renders null for every record-derived field beside a not-collected status, never 0 or []", async () => {
  const base = createTempBase("grclanker-gws-ops-preview-null-");
  const fake = createFakeBinary(base);
  const seen = [];
  const runner = createRunner({ seen });
  const previewStatus = "not collected: dry run previewed the command and did not execute it, so no records were requested";

  const previews = [
    await investigateGwsAlerts({ gwsBin: fake, dry_run: true }, runner),
    await traceGwsAdminActivity({ gwsBin: fake, dry_run: true }, runner),
    await reviewGwsTokenActivity({ gwsBin: fake, dry_run: true }, runner),
  ];
  assert.equal(seen.length, 0, "a preview never invokes the CLI");
  for (const preview of previews) {
    assert.equal(preview.mode, "dry_run", preview.title);
    assert.equal(preview.status, previewStatus, preview.title);
    assert.equal(preview.count, null, preview.title);
    assert.equal(preview.complete, null, preview.title);
    assert.equal(preview.nextPageToken, null, preview.title);
    assert.equal(preview.records, null, preview.title);
    assert.equal(preview.raw, null, preview.title);
    assert.match(preview.text, /^Status: not collected: dry run previewed the command/m, preview.title);
    assert.doesNotMatch(preview.text, /^Records: /m, preview.title);
  }

  // The registered tool JSON is the agent-visible surface; it carries the same nulls and status, and no [] placeholder.
  const tools = registeredTools();
  for (const name of ["gws_ops_investigate_alerts", "gws_ops_trace_admin_activity", "gws_ops_review_tokens"]) {
    const result = await tools.run(name, { gws_bin: fake, dry_run: true });
    assert.equal(result.isError, undefined, name);
    assert.equal(result.details.mode, "dry_run", name);
    assert.equal(result.details.status, previewStatus, name);
    assert.equal(result.details.count, null, name);
    assert.equal(result.details.complete, null, name);
    assert.equal(result.details.records, null, name);
    assert.equal(result.details.next_page_token, null, name);
  }

  // An executed call keeps its real counts and states completeness from the page cursor.
  const executed = await traceGwsAdminActivity({ gwsBin: fake }, createRunner());
  assert.equal(executed.mode, "execute");
  assert.equal(executed.count, 1);
  assert.equal(executed.status, "complete: the CLI response carried no nextPageToken, so the 1 record(s) are the whole population for this query");
  const truncated = await traceGwsAdminActivity({ gwsBin: fake }, createRunner({ admin: adminPayload({ nextPageToken: "CAoQ1" }) }));
  assert.match(truncated.status, /^partial: at least 1; the CLI response carried a nextPageToken after 1 record\(s\)/);
});

test("traceGwsAdminActivity normalizes activity records", async () => {
  const base = createTempBase("grclanker-gws-ops-admin-");
  const fake = createFakeBinary(base);

  const result = await traceGwsAdminActivity({ gwsBin: fake, lookback_days: 10 }, createRunner());
  assert.equal(result.count, 1);
  assert.equal(result.complete, true);
  assert.equal(result.records[0].actor, "admin@example.com");
  assert.equal(result.records[0].detail, "203.0.113.1");
  assert.equal(result.records[0].eventNames[0], "CHANGE_APPLICATION_SETTING");
});

test("verdict rule 7: a response carrying nextPageToken is recorded as a partial view", async () => {
  const base = createTempBase("grclanker-gws-ops-truncated-");
  const fake = createFakeBinary(base);

  const admin = await traceGwsAdminActivity({ gwsBin: fake }, createRunner({ admin: adminPayload({ nextPageToken: "CAoQ1" }) }));
  assert.equal(admin.count, 1);
  assert.equal(admin.complete, false);
  assert.equal(admin.nextPageToken, "CAoQ1");
  assert.ok(admin.notes.some((note) => /^Partial view: the CLI response carried a nextPageToken after 1 record\(s\)/.test(note)));

  const alerts = await investigateGwsAlerts({ gwsBin: fake }, createRunner({ alerts: alertsPayload({ nextPageToken: "next-alerts" }) }));
  assert.equal(alerts.complete, false);
  assert.equal(alerts.nextPageToken, "next-alerts");

  const token = await reviewGwsTokenActivity({ gwsBin: fake }, createRunner({ token: tokenPayload({ nextPageToken: "tok" }) }));
  assert.equal(token.complete, false);
  assert.equal(token.nextPageToken, "tok");
});

test("verdict rule 7: --page-all NDJSON pages aggregate and completeness follows the last page", async () => {
  const base = createTempBase("grclanker-gws-ops-ndjson-");
  const fake = createFakeBinary(base);
  const page = (qualifier, nextPageToken) => JSON.stringify({
    items: [{ id: { time: "2030-01-01T12:00:00Z", uniqueQualifier: qualifier }, actor: { email: "admin@example.com" }, events: [{ name: "ADD_USER" }] }],
    ...(nextPageToken ? { nextPageToken } : {}),
  });

  const complete = await traceGwsAdminActivity({ gwsBin: fake }, createRunner({ admin: `${page("p1", "t1")}\n${page("p2", "t2")}\n${page("p3")}` }));
  assert.equal(complete.count, 3);
  assert.equal(complete.complete, true);
  assert.deepEqual(complete.records.map((record) => record.id), ["p1", "p2", "p3"]);

  const truncated = await traceGwsAdminActivity({ gwsBin: fake }, createRunner({ admin: `${page("p1", "t1")}\n${page("p2", "t2")}` }));
  assert.equal(truncated.count, 2);
  assert.equal(truncated.complete, false);
  assert.equal(truncated.nextPageToken, "t2");
});

test("reviewGwsTokenActivity highlights token telemetry without inventory cloning", async () => {
  const base = createTempBase("grclanker-gws-ops-token-");
  const fake = createFakeBinary(base);

  const result = await reviewGwsTokenActivity({ gwsBin: fake }, createRunner());
  assert.equal(result.count, 1);
  assert.equal(result.records[0].application, "Drive Syncer");
  assert.match(result.notes.join(" "), /not a full tenant-wide token inventory/i);
});

test("collectGwsOperatorEvidenceBundle writes raw evidence, summaries, completeness flags, and a zip", async () => {
  const base = createTempBase("grclanker-gws-ops-bundle-");
  const fake = createFakeBinary(base);
  const outputRoot = join(base, "export");

  const result = await collectGwsOperatorEvidenceBundle(
    {
      gwsBin: fake,
      output_dir: outputRoot,
      max_results: 10,
      lookback_days: 7,
    },
    createRunner({ token: tokenPayload({ nextPageToken: "more-tokens" }) }),
  );

  assert.ok("outputDir" in result);
  assert.equal(basename(result.outputDir), "gws-operator-evidence");
  assert.equal(result.zipPath, `${result.outputDir}.zip`);
  assert.equal(result.commandCount, 3);
  assert.equal(result.recordCount, 4);
  assert.deepEqual(result.categories, { alerts: 2, admin_activity: 1, token_activity: 1 });
  assert.equal(existsSync(join(result.outputDir, "README.md")), true);
  assert.equal(existsSync(join(result.outputDir, "summary.md")), true);
  assert.equal(existsSync(join(result.outputDir, "analysis", "alerts.json")), true);
  assert.equal(existsSync(join(result.outputDir, "raw", "token_activity.json")), true);
  assert.equal(existsSync(result.zipPath), true);
  assert.match(readFileSync(join(result.outputDir, "commands.json"), "utf8"), /admin-reports/);

  const tokenAnalysis = JSON.parse(readFileSync(join(result.outputDir, "analysis", "token_activity.json"), "utf8"));
  assert.equal(tokenAnalysis.complete, false);
  assert.equal(tokenAnalysis.nextPageToken, "more-tokens");
  assert.match(tokenAnalysis.status, /^partial: at least 1; the CLI response carried a nextPageToken/);
  const adminAnalysis = JSON.parse(readFileSync(join(result.outputDir, "analysis", "admin_activity.json"), "utf8"));
  assert.equal(adminAnalysis.complete, true);
  assert.equal(adminAnalysis.nextPageToken, null);
  assert.match(adminAnalysis.status, /^complete: the CLI response carried no nextPageToken/);
  assert.equal(adminAnalysis.records.length, 1);
  const summary = readFileSync(join(result.outputDir, "summary.md"), "utf8");
  assert.match(summary, /Complete page: no \(nextPageToken present\)/);
  assert.match(summary, /Complete page: yes/);
  assert.match(summary, /^- Status: complete: the CLI response carried no nextPageToken/m);
  assert.match(summary, /^- Status: partial: at least 1; /m);
});

test("rule 9 (end to end): the evidence bundle and tool results never carry a planted secret or the echoed CLI token", async () => {
  const base = createTempBase("grclanker-gws-ops-secrets-");
  const fake = createSecretEchoingBinary(base);
  const outputRoot = join(base, "export");
  const env = { PATH: process.env.PATH, GOOGLE_WORKSPACE_CLI_TOKEN: planted("env-token-value") };
  const leakPattern = new RegExp(`${PLANTED_SECRET}-[a-z0-9-]+`);

  const trace = await traceGwsAdminActivity({ gwsBin: fake }, defaultGwsCliRunner, env);
  assert.equal(trace.count, 1);
  assert.equal(JSON.stringify(trace).match(leakPattern), null, "traceGwsAdminActivity result leaked a planted value");
  assert.deepEqual(trace.raw.items[0].events, [{ type: "APPLICATION_SETTINGS", name: "CHANGE_APPLICATION_SETTING" }]);
  assert.equal("privateKey" in trace.raw.items[0], false);
  assert.equal("key" in trace.raw.items[0].actor, false);

  const tokens = await reviewGwsTokenActivity({ gwsBin: fake }, defaultGwsCliRunner, env);
  assert.equal(tokens.records[0].actor, "[REDACTED]");
  assert.equal(tokens.raw.items[0].actor.email, "[REDACTED]");
  assert.equal(tokens.raw.nextPageToken, "more-tokens");
  assert.equal(tokens.complete, false);

  const alerts = await investigateGwsAlerts({ gwsBin: fake }, defaultGwsCliRunner, env);
  assert.equal(alerts.records[0].status, "NOT_STARTED");
  assert.equal("data" in alerts.raw.alerts[0], false);
  assert.equal("securityInvestigationToolLink" in alerts.raw.alerts[0], false);
  assert.equal(JSON.stringify(alerts).match(leakPattern), null, "investigateGwsAlerts result leaked a planted value");

  const result = await collectGwsOperatorEvidenceBundle({ gwsBin: fake, output_dir: outputRoot }, defaultGwsCliRunner, env);
  assert.equal(result.recordCount, 3);
  const files = listFilesRecursively(result.outputDir);
  assert.equal(files.length, 9, "README, summary, commands, three analysis files, three raw captures");
  for (const file of files) {
    const leak = readFileSync(file, "utf8").match(leakPattern);
    assert.equal(leak, null, `${relative(result.outputDir, file)} leaked ${leak?.[0]}`);
  }
  const entries = readZipEntries(result.zipPath);
  assert.equal(entries.size, files.length);
  for (const [name, content] of entries) {
    const leak = content.match(leakPattern);
    assert.equal(leak, null, `zip entry ${name} leaked ${leak?.[0]}`);
  }

  const rawAdmin = JSON.parse(readFileSync(join(result.outputDir, "raw", "admin_activity.json"), "utf8"));
  assert.equal(rawAdmin.raw.items[0].actor.email, "admin@example.com");
  assert.equal(rawAdmin.raw.items[0].ipAddress, "203.0.113.1");
  const rawAlerts = JSON.parse(readFileSync(join(result.outputDir, "raw", "alerts.json"), "utf8"));
  assert.deepEqual(rawAlerts.raw.alerts[0].metadata, { alertId: "a-1", status: "NOT_STARTED", severity: "HIGH", assignee: "secops@example.com" });
  assert.match(readFileSync(join(result.outputDir, "README.md"), "utf8"), /projected to the documented Reports API and Alert Center fields/);
});

/** Registers the bridge tools against a stand-in host and returns them keyed by name, applying prepareArguments the way the host does. */
function registeredTools() {
  const tools = new Map();
  registerGwsOperatorTools({ registerTool: (definition) => tools.set(definition.name, definition) });
  return {
    run: async (name, rawArgs) => {
      const definition = tools.get(name);
      assert.ok(definition, `tool ${name} is registered`);
      return definition.execute("call-1", definition.prepareArguments(rawArgs));
    },
  };
}

test("rule 9: CLI stderr is scrubbed where the error is built, so no thrown message, tool result, or probe carries a planted credential", async () => {
  const base = createTempBase("grclanker-gws-ops-stderr-");
  const envToken = "PLANTEDr4-env-token-value-0123";
  const bearer = "ya29.PLANTEDr4bearer0123456789";
  const pair = "access_token=PLANTEDr4pair0123456789";
  const leak = /PLANTED/;
  const env = { PATH: process.env.PATH, GOOGLE_WORKSPACE_CLI_TOKEN: envToken };
  // The CLI stand-in echoes its own credential from the environment plus the two documented token shapes into stderr and exits 2 (auth).
  const stderrLine = `Error: token $GOOGLE_WORKSPACE_CLI_TOKEN rejected; retry with Bearer ${bearer} or ${pair}`;
  const denied = createScriptedBinary(base, `${PRINT_REAL_VERSION}\necho "${stderrLine}" 1>&2\nexit 2`);

  // The thrown error is the surface the live smoke script logs.
  await assert.rejects(
    () => traceGwsAdminActivity({ gwsBin: denied }, defaultGwsCliRunner, env),
    (error) => {
      assert.ok(error instanceof GwsCliCommandError);
      assert.equal(error.kind, "auth");
      assert.doesNotMatch(error.message, leak, `thrown message leaked: ${error.message}`);
      assert.equal(error.message, "Error: token [REDACTED] rejected; retry with Bearer [REDACTED] or access_token=[REDACTED]");
      return true;
    },
  );

  // The registered tools read the real environment, so the planted token is placed there for the duration of the calls.
  const previous = process.env.GOOGLE_WORKSPACE_CLI_TOKEN;
  process.env.GOOGLE_WORKSPACE_CLI_TOKEN = envToken;
  try {
    const tools = registeredTools();
    for (const name of ["gws_ops_investigate_alerts", "gws_ops_trace_admin_activity", "gws_ops_review_tokens", "gws_ops_collect_evidence_bundle", "gws_ops_check_cli"]) {
      const result = await tools.run(name, { gws_bin: denied, output_dir: join(base, "export") });
      assert.equal(result.isError, true, name);
      assert.equal(result.details.kind, "auth", name);
      assert.doesNotMatch(JSON.stringify(result), leak, `${name} tool result leaked: ${JSON.stringify(result)}`);
      assert.match(result.content[0].text, /Bearer \[REDACTED\] or access_token=\[REDACTED\]/, name);
    }

    // The validation branch re-wraps the message for the missing alertcenter alias; the rewrapped text stays scrubbed.
    const rejected = createScriptedBinary(createTempBase("grclanker-gws-ops-stderr-exit3-"), `echo "Unknown service 'alertcenter' (${pair})" 1>&2\nexit 3`);
    const alias = await tools.run("gws_ops_investigate_alerts", { gws_bin: rejected });
    assert.equal(alias.details.kind, "validation");
    assert.doesNotMatch(JSON.stringify(alias), leak);
    assert.match(alias.content[0].text, /registers no alertcenter alias/);

    // A parse failure never repeats the CLI's stdout, even its first characters.
    const garbage = createScriptedBinary(createTempBase("grclanker-gws-ops-stderr-parse-"), `echo "$GOOGLE_WORKSPACE_CLI_TOKEN ${bearer} is not json"`);
    const parse = await tools.run("gws_ops_trace_admin_activity", { gws_bin: garbage });
    assert.equal(parse.details.kind, "internal");
    assert.doesNotMatch(JSON.stringify(parse), leak, `parse failure leaked: ${parse.content[0].text}`);
    assert.match(parse.content[0].text, /could not parse the output as structured JSON \(SyntaxError while reading \d+ character\(s\) of stdout; the output is not repeated here\)/);
  } finally {
    if (previous === undefined) delete process.env.GOOGLE_WORKSPACE_CLI_TOKEN;
    else process.env.GOOGLE_WORKSPACE_CLI_TOKEN = previous;
  }

  // A successful probe keeps its stderr (warnings) but scrubbed, since checkGwsCliAccess returns the execution to callers.
  const noisy = createScriptedBinary(
    createTempBase("grclanker-gws-ops-stderr-warn-"),
    `${PRINT_REAL_VERSION}\necho "Warning: refreshed with $GOOGLE_WORKSPACE_CLI_TOKEN and Bearer ${bearer}" 1>&2\necho '{"items":[]}'`,
  );
  const check = await checkGwsCliAccess({ gwsBin: noisy }, defaultGwsCliRunner, env);
  assert.equal(check.status, "ready");
  assert.equal(check.probe.stderr, "Warning: refreshed with [REDACTED] and Bearer [REDACTED]");
  assert.doesNotMatch(JSON.stringify(check), leak);
});

test("rule 9: the --version first line is matched against the real two-line output and only the numeric core reaches gws_ops_check_cli", async () => {
  const envToken = "PLANTEDr6-version-env-token-0123456789";
  const fragment = envToken.slice(0, 20);
  const leak = /PLANTED/;
  const env = { PATH: process.env.PATH, GOOGLE_WORKSPACE_CLI_TOKEN: envToken };
  const probeOk = `echo '{"items":[]}'`;
  const scripted = (label, versionScript) => createScriptedBinary(
    createTempBase(`grclanker-gws-ops-version-${label}-`),
    `if [ "$1" = "--version" ]; then ${versionScript}; exit 0; fi\n${probeOk}`,
  );
  const version = async (label, versionScript, runEnv = env) => {
    const result = await checkGwsCliAccess({ gwsBin: scripted(label, versionScript) }, defaultGwsCliRunner, runEnv);
    assert.doesNotMatch(JSON.stringify(result), leak, `${label}: ${JSON.stringify(result)}`);
    assert.equal(JSON.stringify(result).includes(fragment), false, `${label}: the token fragment reached the result`);
    return result.version;
  };
  const withheld = "gws 0.22.5 (the rest of the --version output did not match the documented `gws <version>` first line and is not repeated here)";
  const printLines = (...lines) => `printf '%s\\n' ${lines.map((line) => `"${line}"`).join(" ")}`;

  // The real binary's output, byte for byte: the documented branch fires and the disclaimer line is never repeated.
  const real = await checkGwsCliAccess({ gwsBin: scripted("real", printLines(...REAL_VERSION_LINES)) }, defaultGwsCliRunner, env);
  assert.equal(real.version, "gws 0.22.5");
  assert.equal(JSON.stringify(real).includes("officially"), false, "the disclaimer line is not rendered");
  assert.equal(await version("crlf", `printf 'gws 0.22.5\\r\\nThis is not an officially supported Google product.\\r\\n'`), "gws 0.22.5");
  assert.equal(await version("single", `echo "gws 0.22.5"`), "gws 0.22.5", "the single line releases before 0.3.5 printed still matches");
  assert.equal(await version("vprefix", `echo "gws v1.2.3"`), "gws 1.2.3");

  // A Cargo pre-release or build suffix is accepted so the line is recognized, but only major.minor.patch is rendered.
  assert.equal(await version("pre", `echo "gws v1.2.3-beta.1"`), "gws 1.2.3");
  assert.equal(await version("build", `echo "gws 0.22.5+build.PLANTEDr6meta"`), "gws 0.22.5");
  // The parent's criterion: a 20-character fragment of the token in the pre-release position is neither a known value
  // nor a credential shape, so no scrub catches it; the projection renders the numeric core and nothing else.
  assert.equal(fragment.length, 20);
  assert.equal(await version("fragment", `echo "gws 0.22.5-${fragment}"`), "gws 0.22.5");
  assert.equal(await version("fragment-ya29", `echo "gws 0.22.5-PLANTEDr6ya29body012"`), "gws 0.22.5", "20 characters of a ya29 body without its prefix");
  assert.equal(await version("suffix64", `echo "gws 0.22.5-${"a".repeat(64)}"`), "gws 0.22.5");
  assert.equal(await version("suffix65", `echo "gws 0.22.5-${"a".repeat(65)}"`), withheld, "a suffix beyond the grammar falls to the core note");
  // The whole token in the pre-release position is a known value: scrubbed to [REDACTED], which the grammar rejects.
  assert.equal(await version("whole", `echo "gws 0.22.5-$GOOGLE_WORKSPACE_CLI_TOKEN"`), withheld);
  const shortToken = { PATH: process.env.PATH, GOOGLE_WORKSPACE_CLI_TOKEN: "PLANTEDr6tok" };
  assert.equal(await version("short", `echo "gws 0.22.5-$GOOGLE_WORKSPACE_CLI_TOKEN"`, shortToken), withheld);

  // The round 5 echo fixture: the binary echoes its own credential and a bearer after the version. Still clean.
  const echoing = scripted("echo", `echo "gws 0.22.5 PLANTEDr6versionword token=$GOOGLE_WORKSPACE_CLI_TOKEN Bearer ya29.PLANTEDr6versionbearer0123"`);
  const result = await checkGwsCliAccess({ gwsBin: echoing }, defaultGwsCliRunner, env);
  assert.equal(result.version, withheld);
  assert.doesNotMatch(JSON.stringify(result), leak);
  // A token on the second line of otherwise real output, the lines reordered, or another binary name: never rendered.
  assert.equal(await version("second-line", printLines("gws 0.22.5", "$GOOGLE_WORKSPACE_CLI_TOKEN")), "gws 0.22.5");
  assert.equal(await version("reordered", printLines(REAL_VERSION_LINES[1], REAL_VERSION_LINES[0])), withheld);
  assert.equal(await version("name", `echo "google-workspace-cli 0.22.5"`), withheld);
  assert.equal(await version("huge", `echo "gws 1234567.0.0"`), "unrecognized (--version printed 15 character(s) without a version number; the output is not repeated here)");

  // Only the credential: no version number is found, so the line is dropped behind a descriptor that counts the printed characters.
  assert.equal(await version("token", `echo "$GOOGLE_WORKSPACE_CLI_TOKEN"`), `unrecognized (--version printed ${envToken.length} character(s) without a version number; the output is not repeated here)`);
  assert.equal(await version("silent", "true"), "unknown (--version printed nothing)");

  // The registered tool reads the real environment; its text and JSON carry the projected version only.
  const previous = process.env.GOOGLE_WORKSPACE_CLI_TOKEN;
  process.env.GOOGLE_WORKSPACE_CLI_TOKEN = envToken;
  try {
    const realTool = await registeredTools().run("gws_ops_check_cli", { gws_bin: scripted("real-tool", printLines(...REAL_VERSION_LINES)) });
    assert.equal(realTool.isError, undefined);
    assert.equal(realTool.details.version, "gws 0.22.5");
    assert.match(realTool.content[0].text, /^Version: gws 0\.22\.5$/m);
    assert.equal(JSON.stringify(realTool).includes("officially"), false);

    const fragmentTool = await registeredTools().run("gws_ops_check_cli", { gws_bin: scripted("fragment-tool", `echo "gws 0.22.5-${fragment}"`) });
    assert.equal(fragmentTool.details.version, "gws 0.22.5");
    assert.match(fragmentTool.content[0].text, /^Version: gws 0\.22\.5$/m);
    assert.equal(JSON.stringify(fragmentTool).includes(fragment), false, "the fragment reached the tool text or JSON");

    const tool = await registeredTools().run("gws_ops_check_cli", { gws_bin: echoing });
    assert.equal(tool.isError, undefined);
    assert.equal(tool.details.version, withheld);
    assert.match(tool.content[0].text, /^Version: gws 0\.22\.5 \(the rest of the --version output/m);
    assert.doesNotMatch(JSON.stringify(tool), leak, JSON.stringify(tool));
    assert.equal(JSON.stringify(tool).includes(envToken), false);
  } finally {
    if (previous === undefined) delete process.env.GOOGLE_WORKSPACE_CLI_TOKEN;
    else process.env.GOOGLE_WORKSPACE_CLI_TOKEN = previous;
  }
});

test("rule 9: GwsCliCommandError scrubs its message in the constructor, independently of the runner", async () => {
  const envToken = "PLANTEDr5-ctor-env-token-0123";
  const leak = /PLANTED/;
  const raw = `token ${envToken} rejected; retry with Bearer ya29.PLANTEDr5ctorbearer0123 or access_token=PLANTEDr5ctorpair0123 via https://accounts.example/x?code=PLANTEDr5ctorcode`;

  // Constructed directly, bypassing the runner: the known value, both token shapes, and the URL query are gone from .message.
  const direct = new GwsCliCommandError("api", raw, "gws admin-reports activities list", 1, [envToken]);
  assert.equal(direct.message, "token [REDACTED] rejected; retry with Bearer [REDACTED] or access_token=[REDACTED] via https://accounts.example/x");
  assert.equal(direct.kind, "api");
  assert.equal(direct.exitCode, 1);
  // Without known values the shape scrub still applies; the env value then relies on the caller passing it.
  const shapesOnly = new GwsCliCommandError("api", raw, "gws x", 1);
  assert.equal(shapesOnly.message, `token ${envToken} rejected; retry with Bearer [REDACTED] or access_token=[REDACTED] via https://accounts.example/x`);

  // The stdout-only error path: nothing on stderr, so the runner's stderr scrub never runs and the constructor is the only layer before the exit.
  const env = { PATH: process.env.PATH, GOOGLE_WORKSPACE_CLI_TOKEN: envToken };
  const stdoutOnly = createScriptedBinary(
    createTempBase("grclanker-gws-ops-ctor-stdout-"),
    `${PRINT_REAL_VERSION}\necho "${raw}"\nexit 1`,
  );
  await assert.rejects(
    () => traceGwsAdminActivity({ gwsBin: stdoutOnly }, defaultGwsCliRunner, env),
    (error) => {
      assert.ok(error instanceof GwsCliCommandError);
      assert.equal(error.kind, "api");
      assert.doesNotMatch(error.message, leak, `thrown message leaked: ${error.message}`);
      assert.match(error.message, /^token \[REDACTED\] rejected; retry with Bearer \[REDACTED\] or access_token=\[REDACTED\] via https:\/\/accounts\.example\/x$/);
      return true;
    },
  );
});

test("verdict rule 8: re-running the evidence bundle allocates -2 and never overwrites the earlier bundle or zip", async () => {
  const base = createTempBase("grclanker-gws-ops-rerun-");
  const fake = createFakeBinary(base);
  const outputRoot = join(base, "export");

  const first = await collectGwsOperatorEvidenceBundle({ gwsBin: fake, output_dir: outputRoot }, createRunner());
  const firstZip = readFileSync(first.zipPath);
  const second = await collectGwsOperatorEvidenceBundle({ gwsBin: fake, output_dir: outputRoot }, createRunner());
  const third = await collectGwsOperatorEvidenceBundle({ gwsBin: fake, output_dir: outputRoot }, createRunner());

  assert.equal(basename(second.outputDir), "gws-operator-evidence-2");
  assert.equal(basename(third.outputDir), "gws-operator-evidence-3");
  assert.equal(second.zipPath, `${second.outputDir}.zip`);
  assert.ok(existsSync(first.zipPath));
  assert.ok(existsSync(second.zipPath));
  assert.ok(existsSync(third.zipPath));
  assert.deepEqual(readFileSync(first.zipPath), firstZip);
  assert.deepEqual(
    readdirSync(outputRoot).sort(),
    [
      "gws-operator-evidence",
      "gws-operator-evidence-2",
      "gws-operator-evidence-2.zip",
      "gws-operator-evidence-3",
      "gws-operator-evidence-3.zip",
      "gws-operator-evidence.zip",
    ],
  );
});

test("collectGwsOperatorEvidenceBundle previews commands in dry-run mode", async () => {
  const base = createTempBase("grclanker-gws-ops-preview-");
  const fake = createFakeBinary(base);

  const result = await collectGwsOperatorEvidenceBundle(
    {
      gwsBin: fake,
      dry_run: true,
      lookback_days: 7,
    },
    createRunner(),
  );

  assert.equal(result.mode, "dry_run");
  assert.equal(result.commands.length, 3);
});

test("collectGwsOperatorEvidenceBundle rejects symlinked output roots", async () => {
  const base = createTempBase("grclanker-gws-ops-symlink-");
  const fake = createFakeBinary(base);
  const safeRoot = join(base, "safe");
  const realOutside = join(base, "outside");
  writeFileSync(join(base, "placeholder.txt"), "ok");
  const symlinkRoot = join(base, "link-root");

  try {
    writeFileSync(join(base, "seed.txt"), "seed");
    symlinkSync(base, symlinkRoot, "dir");
  } catch {
    return;
  }

  await assert.rejects(
    () => collectGwsOperatorEvidenceBundle(
      {
        gwsBin: fake,
        output_dir: symlinkRoot,
      },
      createRunner(),
    ),
    /symlink/i,
  );

  assert.equal(existsSync(realOutside), false);
  assert.equal(existsSync(safeRoot), false);
});
