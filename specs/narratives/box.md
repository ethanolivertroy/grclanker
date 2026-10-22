## Purpose

Audit Box enterprise identity, sharing, governance, retention, legal-hold, Shield, and event-monitoring posture with read-only Content API evidence.

## Design guidance

Treat settings marked unused by Box as unenforced, not compliant. Keep marker, offset, and event-stream completion semantics separate. Preserve Admin Console review where individual delegated permissions or policy details are not exposed by the API. Report the access check failed only when Box refuses the credentials themselves on every probe (a 401, or a token exchange 400 with invalid_client, invalid_grant, or unauthorized_client), and name the credential settings rather than app scopes.
