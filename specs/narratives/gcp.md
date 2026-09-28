## Purpose

Give security and compliance teams a read-only, repeatable view of Google Cloud identity, logging, organization guardrails, data protection, and network posture without treating an unreadable API or sampled project set as compliance.

## Design guidance

Use a dedicated least-privilege audit principal and an explicit organization or project scope. Preserve quota, API-enablement, IAM-denial, project-cap, and pagination limits as evidence. Verdicts use complete collector counts; rendered arrays are only presentation samples.
