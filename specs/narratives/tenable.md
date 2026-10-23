## Purpose

Tenable Security Inspector gives auditors a read-only view of a Tenable Vulnerability Management tenant and, when configured, a Tenable Security Center console: whether scanning is scheduled, credentialed, and current, whether scanners, agents, and assets cover the estate, who can administer the platform, and whether open findings are prioritized and remediated within their SLA.

## Rationale

Tenable shows each key only what its role may see. An Administrator key gets full user records, while lower roles get the reduced user shape and only the scans, assets, and findings shared with them. A portable implementation must keep that difference visible instead of reading a narrower view as a compliant tenant, so a key that is not confirmed as Administrator never produces a pass on a check that depends on the user list.

Asset and vulnerability data arrive through asynchronous exports whose chunks can fail, be listed beyond the download cap, or carry records with none of the documented members. Each of those conditions marks the export partial and caps the checks built on it, so an export that was only partly read cannot pass.

## Runtime behavior

- The tool only reads, except for the POST requests that start the asset and vulnerability exports.
- Each export is polled every 2 seconds for up to 300 seconds, and only the first max_chunks available chunks are downloaded.
- A throttled or failed request is retried before it counts as failed: HTTP 429 and 5xx answers get up to 4 more attempts, each waiting as long as Retry-After asks up to 30 seconds, and so does a GET that times out or fails before its whole answer arrives. The timeout bounds the wait for the headers and each gap between pieces of the body rather than the whole body, so a large export chunk that keeps arriving is not cut off by it while a body that stalls is retried. Each attempt is capped at 10 minutes, and a body still arriving at the cap is not retried, since another attempt would arrive just as slowly. The POST that starts an export is not sent again after a timeout or a network failure, because Tenable may already have started that export. A request that still fails names its method and path, the status, the timeout, cap, or network error, and the number of attempts, and a chunk that still fails leaves the export truncated.
- Each platform's checks are assessed only when that platform's URL and key pair are configured. Checks for a platform that is not configured are reported as manual and do not change the other platform's results.
- The export job lists cover only the previous 3 days, so the export automation check is a point-in-time signal, and report schedules are not exposed by the API.
- Scanner records are kept without their linking key.

## Non-goals

- Changing Tenable settings, launching scans, or issuing any administrative write request
- Reading report schedules, scan-embedded credentials, or other settings the API does not expose
- Treating a non-Administrator view as complete tenant coverage
- Reproducing a particular programming language, package layout, or command-line framework

## Portable implementation guidance

Keep the API clients, export polling, evidence projection, verdict evaluation, and bundle writer as separable concerns. Count from the full collected arrays at the decision point rather than from evidence previews. Keep each dataset's read state (read, refused, failed, not configured, or partial) next to its records so every finding can say which sources it depended on and why a pass was capped.
