## Purpose

Inspect Google Workspace identity, delegated administration, third-party OAuth exposure, audit activity, alerts, and two-step-verification policy using read-only tenant APIs.

## Design guidance

This is the tenant security inspector, not the `gws` operator bridge. Keep directory, reporting, Alert Center, per-user token, and Cloud Identity policy evidence distinct. A failed child token read or unavailable policy token must demote every dependent finding.
