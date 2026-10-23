## Purpose

Qualys Security Inspector gives auditors a read-only view of a Qualys subscription: whether vulnerability scans are scheduled, authenticated, current, and reach every network segment, whether asset groups, scanner appliances, Cloud Agents, cloud connectors, and tags keep the asset inventory complete, whether open detections are remediated within their SLA and patchable ones are tracked, and who can administer the subscription, how reports are distributed, whether web applications are scanned, and whether activity is logged.

## Rationale

Qualys shows each user only what its role and scope tags allow. A Manager or Super User sees the whole subscription, while other roles see only the assets and objects in their scope. A portable implementation must keep that difference visible instead of reading a scoped view as a compliant subscription, so when the configured user is verified to hold another role or to carry scope tags, every check that would otherwise pass is capped at warn.

Most lists arrive through WARNING/URL continuations or QPS searches that stop at a record or page cap, and some answers are a single document whose continuation is never followed. Each of those conditions marks the list partial and caps the checks built on it, so a list that was only partly read cannot pass. Several controls, such as asset group completeness, report distribution, and option profile review, need facts the API does not expose, so they never pass on API evidence alone.

## Runtime behavior

- The tool only reads. QPS searches are POST requests that change nothing, and the OAuth mode's token request to the platform gateway is the only other POST.
- Lists stop at 5000 records and 25 pages unless the list states another cap; hosts and detections stop at host_limit and detection_limit.
- A refused or failed read never counts as an empty list: the checks that need it are manual and name the read, and when Qualys answers that a module is unavailable the finding says the module may be unlicensed or the role not permitted.
- A throttled or failed read is retried before it counts as failed: HTTP 409, 429, and 5xx answers, timeouts, and network errors get up to QUALYS_MAX_RETRIES more attempts, each waiting as long as X-RateLimit-ToWait-Sec or Retry-After asks, up to 30 seconds. A read that still fails names its endpoint, the status or the timeout, and the number of attempts.
- The knowledge base is looked up only for the QIDs of open detections, 200 QIDs per request and at most 2000 QIDs.
- The WAS scan history search runs only for web applications the lookback scan search did not resolve, and is recorded as not collected when no web application needed it or when an earlier WAS read failed.
- Agent activation keys are read only to tell whether one is present and are never exported.

## Non-goals

- Changing Qualys settings, launching scans, or issuing any administrative write request
- Reconciling asset groups against an authoritative inventory such as a CMDB or IPAM
- Confirming report recipients, log retention, or review cadence, which the API does not expose
- Evaluating CloudView resources or Policy Compliance posture detail
- Treating a scoped view as complete subscription coverage
- Reproducing a particular programming language, package layout, or command-line framework

## Portable implementation guidance

Keep the API client, continuation handling, evidence projection, verdict evaluation, and bundle writer as separable concerns. Count from the full collected arrays at the decision point rather than from evidence previews. Keep each dataset's read state (read, refused, not collected because an earlier read failed, or partial) next to its records so every finding can say which sources it depended on and why a pass was capped.
