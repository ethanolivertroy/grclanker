import {
  GwsCliCommandError,
  checkGwsCliAccess,
  collectGwsOperatorEvidenceBundle,
  investigateGwsAlerts,
  resolveGwsCliExecutable,
  reviewGwsTokenActivity,
  traceGwsAdminActivity,
} from "../dist/extensions/grc-tools/gws-ops.js";

function log(message) {
  process.stdout.write(`${message}\n`);
}

function logActivity(label, result) {
  log(`${label}: ${result.count} records, complete page: ${result.complete ? "yes" : `no (nextPageToken ${result.nextPageToken})`}`);
}

try {
  const executable = resolveGwsCliExecutable();
  if (!executable.installed) {
    log(
      "Skipping Google Workspace CLI operator smoke test: `gws` is not installed. Install googleworkspace/cli and authenticate it first.",
    );
    process.exit(0);
  }

  const access = await checkGwsCliAccess();
  log(`gws executable: ${access.executable}`);
  log(`gws version: ${access.version}`);
  log(`Bridge status: ${access.status}`);

  logActivity("gws_ops_trace_admin_activity", await traceGwsAdminActivity({ lookback_days: 7, max_results: 5 }));
  logActivity("gws_ops_review_tokens", await reviewGwsTokenActivity({ lookback_days: 7, max_results: 5 }));

  try {
    logActivity("gws_ops_investigate_alerts", await investigateGwsAlerts({ max_results: 5 }));
  } catch (error) {
    if (error instanceof GwsCliCommandError && error.kind === "validation") {
      log(`gws_ops_investigate_alerts: skipped, ${error.message}`);
    } else {
      throw error;
    }
  }

  const preview = await collectGwsOperatorEvidenceBundle({ dry_run: true, lookback_days: 7, max_results: 5 });
  log(`gws_ops_collect_evidence_bundle (dry run): ${preview.commands.length} commands previewed`);
  log("Google Workspace CLI operator smoke test passed.");
} catch (error) {
  if (error instanceof GwsCliCommandError && (error.kind === "missing" || error.kind === "auth")) {
    log(`Skipping Google Workspace CLI operator smoke test: ${error.message}`);
    process.exit(0);
  }

  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`${message}\n`);
  process.exit(1);
}
