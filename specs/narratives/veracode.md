## Purpose

Assess Veracode application scan coverage, policy compliance, finding hygiene, SCA, DAST, and identity posture through HMAC-signed REST APIs.

## Design guidance

Sign the exact same-origin request after final query construction. Exhaust HAL totals before deriving portfolio metrics, and retain every failed or skipped per-application, workspace, credential, sandbox, project, and dynamic-analysis read as unavailable evidence.
