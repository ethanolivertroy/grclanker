## Purpose

CrowdStrike Security Inspector gives auditors a read-only view of a CrowdStrike Falcon tenant. It covers five areas:

- Prevention: whether assigned prevention policies enable machine learning, exploit mitigation, script control, sensor tamper protection, and on-write detection.
- Response: whether response policies allow Real Time Response with bounded sessions, and whether alerts are triaged and hosts contained in time.
- Device control and firewall: whether device control and host firewall policies enforce.
- Sensor coverage: whether sensors update automatically and cover every host, host group, and discovered asset with an acceptable Zero Trust score.
- Access governance: who administers the tenant, which API clients can write to sensitive collections, which exclusions weaken detection, and whether Identity Protection has an active enforcing rule.

## Rationale

Falcon answers each API client only for the collections its scopes grant, and modules such as Identity Protection, Discover, and Zero Trust Assessment exist only on licensed tenants. A portable implementation must keep a refusal distinct from an empty answer. A 401, 403, or 404 from a module reports that module as unlicensed or not permitted, never as compliant.

Most lists come from offset walks and ID lookups that stop at a cap, and a few come from a single ID read whose total can exceed what it returned. Each of those conditions marks the list partial and caps the checks built on it at warn. A fail that rests on something being absent from a partial list becomes manual instead. The public API documents no last-used date for API clients, so when a client does return one, its staleness reaches evidence only, never the verdict.

## Runtime behavior

- The tool only reads. Besides the OAuth2 token request, its only POST requests are the user lookup and the alert search, which change nothing.
- Policy lists stop at 5000 policies; hosts stop at host_limit (5000), alerts at alert_limit (2000), users and API clients at user_limit (500), each exclusion type at exclusion_limit (500), and each user's role grants at 500.
- A refused or failed read never counts as an empty list. The checks that need it are manual and name the read, and a read that depends on a failed one is recorded as not collected.
- A throttled or failed request, the token request included, is retried before it counts as failed: 429 and 5xx answers, timeouts, and network errors get up to 4 more attempts, each waiting as long as the rate-limit headers ask within 250 milliseconds to 15 seconds. A request that still fails names its endpoint, the status or the timeout, and the number of attempts.
- When the token request refuses the API client credentials (a 401, or a 403 whose error reads Failed to issue access token - Not Authorized) or every probe returns 401, the access check reports failed instead of listing missing scopes. Its next step names the client ID, secret, and cloud settings after a refused token request, and the cloud setting alone when Falcon issued a token that every probe refused, since only the client's own cloud accepts its tokens.
- Exclusion regexes, paths, names, descriptions, and comments pass through the data redaction pass and the exclusion text pass before they reach evidence, summaries, decision facts, or the bundle.
- The 90-day periods for stale admin logins and unused API clients are fixed and cannot be configured.

## Non-goals

- Changing Falcon settings, containing hosts, opening Real Time Response sessions, or issuing any administrative write request
- Judging detection content, threat hunting results, or incident handling quality
- Reconciling the host inventory against an authoritative source such as a CMDB
- Treating a refused or unlicensed module as a compliant one
- Reproducing a particular programming language, package layout, or command-line framework

## Portable implementation guidance

Keep the API client, pagination, evidence projection, verdict evaluation, and bundle writer as separable concerns. Count from the full collected arrays at the decision point rather than from evidence previews. Keep each dataset's read state (read, refused, not collected because an earlier read failed, or partial) next to its records so every finding can say which sources it depended on and why a pass was capped.
