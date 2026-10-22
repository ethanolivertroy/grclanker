---
title: LaunchDarkly
description: Read-only LaunchDarkly security inspector covering identity, access control, environment governance, flag hygiene, and monitoring across 25 controls.
---

The LaunchDarkly integration audits a LaunchDarkly account through the REST API v2. It maps what it finds to the 25 controls in the [LaunchDarkly Security Inspector spec](/specs/launchdarkly-sec-inspector/).

Every tool is read-only. The inspector never creates, updates, or deletes anything in the account. Access tokens are redacted from errors, output, and exported bundles.

## What it inspects

- **Identity:** member MFA coverage, Owner and Admin concentration, orphaned members, team custom role usage, member email domains, and the evidence available for SSO/SAML enforcement.
- **Access control:** custom role policies (wildcard actions, sensitive administrative grants, deny-by-default design) and access tokens (expiry, staleness, service token scope, personal token scope).
- **Environment governance:** production environment restrictions, required approvals, secure mode, default TTL, confirm changes, required comments, server-side SDK key age, and test or temporary projects.
- **Flag hygiene:** individual context targeting in production, stale flags, and circular prerequisite chains.
- **Monitoring and integrations:** audit log retention and critical action coverage, Relay Proxy automatic configuration scope and secure mode, integration audit log subscription scope, and webhook HTTPS plus signing.

## Setup and authentication

LaunchDarkly authenticates REST calls with a personal or service access token. The token is sent verbatim in the `Authorization` header, with no `Bearer` prefix. The `LD-API-Version` header pins the response shape.

The inspector defaults to API version `20240415`. It switches to `beta` only for the SDK keys endpoint, which is still a beta resource.

Configuration precedence is explicit tool arguments, then environment variables, then the TOML config file:

| Setting | Tool argument | Environment variable | Config file key |
| --- | --- | --- | --- |
| Access token (required) | `token` | `LAUNCHDARKLY_API_TOKEN` (fallback `LD_ACCESS_TOKEN`) | `token`, `api_token`, or `access_token` |
| Base URL | `base_url` | `LAUNCHDARKLY_BASE_URL` (fallback `LD_BASE_URI`) | `base_url` or `base_uri` |
| API version | `api_version` | `LAUNCHDARKLY_API_VERSION` | `api_version` |
| Timeout (seconds, default 30) | `timeout_seconds` | `LAUNCHDARKLY_TIMEOUT` | `timeout_seconds` or `timeout` |
| Approved member domains | `allowed_domains` | `LAUNCHDARKLY_ALLOWED_DOMAINS` | `allowed_domains` or `domains` |
| Project scope | `project_keys` | `LAUNCHDARKLY_PROJECTS` | `projects` or `project_keys` |
| Config file path | `config_path` | `LAUNCHDARKLY_CONFIG` | n/a (defaults to `~/.config/launchdarkly-sec-inspector/config.toml`) |

Base URL defaults to `https://app.launchdarkly.com`. Use `https://app.launchdarkly.us` for the federal instance and `https://app.eu.launchdarkly.com` for the EU instance.

An argument that is not passed never erases an environment value. For example, a tool called with only `timeout_seconds` still sends `LAUNCHDARKLY_API_TOKEN` to the instance the file `LAUNCHDARKLY_CONFIG` names.

A config file named by `config_path` or `LAUNCHDARKLY_CONFIG` must exist. A missing default file is simply absent.

When the config file cannot be read or parsed, the tool fails and nothing is written. The failure message is fixed text that carries only:

- The path.
- The filesystem's error code (`ENOENT`, `EACCES`, `EISDIR`).
- The line the in-house TOML parser rejected (`Unable to parse LaunchDarkly config file: invalid TOML in <path> at line 2`).

It never carries the offending line itself.

A minimal config file:

```toml
token = "api-xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
base_url = "https://app.launchdarkly.com"
allowed_domains = ["example.com"]
projects = ["web", "mobile"]
```

### Token role requirements

- **Reader base role:** Enough for members, teams, custom roles, projects, environments, flags, flag statuses, webhooks, Relay Proxy configurations, and integration subscriptions.
- **Admin or Owner base role:** Required for `GET /api/v2/tokens?showAll=true` to return every member's personal tokens (controls 8 through 11). Recommended for full audit log depth.
- **Custom role alternative:** An audit custom role needs `basePermissions: reader` plus `viewProject` on each audited project, because the role actions reference defines `viewProject` and `viewTeam` but no dedicated member, role, or audit log view actions. The spec's `viewMembers`, `viewRoles`, and `viewAuditLog` actions do not exist.

The SDK keys endpoint (`/api/v2/projects/{projectKey}/environments/{environmentKey}/sdk-keys`) is beta and may not be available on every plan. When it is unreadable, control 19 is reported as `manual` with the evidence a human needs to collect.

## Run it

After setup, start `grclanker` and ask in plain words. The agent calls the matching tools, for example:

```text
Check whether my LaunchDarkly credentials can read everything grclanker needs.
Run the LaunchDarkly assessments and list the failing findings first.
Export a LaunchDarkly audit bundle.
```

For a posture readout or a framework mapping, use the [assess](/docs/workflows/assess/) or [audit](/docs/workflows/audit/) workflow, for example `grclanker assess "our LaunchDarkly account"`. Both start with `launchdarkly_check_access`, then run the assessments or `launchdarkly_export_audit_bundle`.

## Tools

| Tool | Purpose |
| --- | --- |
| `launchdarkly_check_access` | Probe caller identity plus 11 read surfaces (members, teams, custom roles, projects, environments, flags, access tokens, audit log, webhooks, Relay Proxy configs, integration subscriptions). Reports `healthy` only when every core surface is readable; webhooks, Relay Proxy configs, and integration subscriptions are optional. Reports `failed` when every probe returns 401 because LaunchDarkly rejected the access token; the next step names `LAUNCHDARKLY_API_TOKEN` (or `LD_ACCESS_TOKEN`), and `LAUNCHDARKLY_BASE_URL` (or `LD_BASE_URI`) for a federal or EU token. |
| `launchdarkly_assess_identity` | Controls 1, 2, 3, 6, 7, 24. Arguments: `member_limit`, `team_limit`, `max_owners`, `max_admins`, `allowed_domains`. |
| `launchdarkly_assess_access_control` | Controls 4, 5, 8, 9, 10, 11. Arguments: `role_limit`, `token_limit`, `stale_token_days`. |
| `launchdarkly_assess_environment_governance` | Controls 16, 17, 19, 22, 23. Arguments: `project_limit`, `environment_limit`, `project_keys`, `production_pattern`, `test_project_pattern`, `sdk_key_max_age_days`. |
| `launchdarkly_assess_flag_hygiene` | Controls 14, 15, 25. Arguments: `project_limit`, `flag_limit`, `project_keys`, `production_pattern`, `stale_flag_days`. |
| `launchdarkly_assess_monitoring_integrations` | Controls 12, 13, 18, 20, 21. Arguments: `retention_days`, `integration_keys`, `relay_config_max_age_days`, `production_pattern`. |
| `launchdarkly_export_audit_bundle` | Runs the access check and all five assessments, then writes a bundle plus zip under `output_dir` (default `./export/launchdarkly`). |

Every tool accepts the shared auth arguments `token`, `base_url`, `api_version`, `config_path`, and `timeout_seconds`.

The list arguments `allowed_domains`, `project_keys`, and `integration_keys` are comma-separated strings, for example `"web,mobile"`.

`allowed_domains` and `project_keys` can also come from their environment variables (same comma-separated form) or the config file (TOML arrays). `integration_keys` is a tool argument only.

Production environments are those flagged `critical` in LaunchDarkly, or whose key or name matches `production_pattern` (default `prod`, case-insensitive).

Control 16 evaluates custom role policies with a resource specifier parser. The parser follows the documented `proj/<key>:env/<key>;tag1,tag2,{selector:value}` syntax:

- Project and environment keys support `*` globs.
- Tags must all be present on the environment.
- The `{critical:true}` property-based selector matches environments marked critical.

The bare form `proj/*:env/*;critical:true:flag/*` is accepted as an alias for the documented `proj/*:env/*;{critical:true}:flag/*`.

### Export bundle layout

```text
<host>-<accountId>-audit-bundle/
  metadata.json
  QUICK_REFERENCE.md
  _errors.log                      (only when some reads failed)
  core_data/access_check.json      the access check result
  core_data/collection_status.json one row per collection with its read status, truncation, and counts, plus totals
  core_data/                       API snapshots with credential values replaced by [REDACTED] and flags projected; collections carry truncated, seen, total, items, and readable/error when a read failed
  analysis/findings.json           all findings with evidence and mappings
  analysis/<category>.json         one summary per assessment
  analysis/summary.md
  compliance/executive_summary.md
  compliance/unified_compliance_matrix.md
  compliance/fedramp/fedramp_compliance_report.md
  compliance/cmmc/cmmc_compliance_report.md
  compliance/soc2/soc2_compliance_report.md
  compliance/cis/cis_controls_report.md
  compliance/pci_dss/pci_dss_compliance_report.md
  compliance/disa_stig/stig_compliance_checklist.md
  compliance/irap/irap_compliance_report.md
  compliance/ismap/ismap_compliance_report.md
<host>-<accountId>-audit-bundle.zip
```

#### Reruns and output paths

Repeated exports never overwrite earlier results.

- When `<host>-<accountId>-audit-bundle` (or its zip) already exists, the next run allocates `-2` through `-6`. It fails once all six names are taken.
- The zip always takes the name of the directory it was built from (`<host>-<accountId>-audit-bundle-2.zip`).

Output paths are resolved through `resolveSecureOutputPath`, which rejects directory traversal and symlinked parents. Files are written with owner-only permissions.

## Finding shape and status semantics

Every finding is `{ id, control, title, severity, status, summary, evidence, mappings, frameworks }`. Finding ids are `LD-01` through `LD-25` and match the spec control numbers.

- `pass`: The API evidence satisfies the control.
- `warn`: Any of these:
  - The control is partially satisfied.
  - The data was too thin to conclude (for example, no production environments detected or an endpoint was unreadable).
  - A low severity hygiene issue was found.
- `fail`: The API evidence shows the control is not met.
- `manual`: The API cannot verify the control. The summary and `evidence.manual_evidence` state exactly what a human must collect.

## Control coverage

Verdicts on unread, partial, or truncated data follow the rules in [How the tools handle evidence](#how-the-tools-handle-evidence).

| # | Spec control | Tool | Finding | Status semantics |
| --- | --- | --- | --- | --- |
| 1 | SSO/SAML enforcement enabled for the account | `launchdarkly_assess_identity` | LD-01 | Always `manual`: the API does not expose the account SSO setting. Evidence includes SCIM-provisioned member counts, members with passwords, and SAML/SCIM/MFA audit entries. |
| 2 | MFA required for all members | `launchdarkly_assess_identity` | LD-02 | `pass` when every active member reports `mfa: enabled`; `fail` otherwise; `warn` when no members were readable. |
| 3 | No members with Owner role beyond minimum required | `launchdarkly_assess_identity` | LD-03 | `fail` when Owners exceed `max_owners`; `warn` when Admins exceed `max_admins`. |
| 4 | Custom roles follow least-privilege (no wildcard actions) | `launchdarkly_assess_access_control` | LD-04 | `fail` when any allow statement uses wildcard actions or open-ended `notActions`; `warn` when no custom roles exist. |
| 5 | Custom role policies deny sensitive actions by default | `launchdarkly_assess_access_control` | LD-05 | `fail` when a role allows account, member, role, token, relay, webhook, or team administration actions without an explicit deny; `warn` when roles use reader base permissions. |
| 6 | All members assigned to teams | `launchdarkly_assess_identity` | LD-06 | `fail` when active members have no team; `warn` when no teams exist. |
| 7 | Team permissions use custom roles, not built-in admin | `launchdarkly_assess_identity` | LD-07 | `fail` when sampled teams have no custom roles; `warn` when no teams exist; `pass` only when every sampled team has a custom role and the members listing is complete, so the count of members still holding built-in Admin or Owner base roles is known. A truncated members listing demotes the clean verdict to `warn` with the built-in role holders stated as unknown and `built_in_admin_or_owner_members` rendered `null`; `manual` when teams or members cannot be read. |
| 8 | API access tokens have expiration dates set | `launchdarkly_assess_access_control` | LD-08 | `fail` when any visible token lacks `expiry`; `warn` when tokens were not readable or the inventory is partial (see below). |
| 9 | No API tokens unused beyond 90 days | `launchdarkly_assess_access_control` | LD-09 | `fail` when `lastUsed` (or creation) is older than `stale_token_days`; `warn` on a partial inventory. |
| 10 | Service tokens scoped to minimum required roles | `launchdarkly_assess_access_control` | LD-10 | `fail` for Owner/Admin base role or wildcard inline policies; `warn` for the Writer base role, for a partial or unknown inventory (including an empty listing), or when the only Admin service token is the one running the assessment (disclosed in the summary). |
| 11 | Personal tokens limited to individual member scope | `launchdarkly_assess_access_control` | LD-11 | `fail` when personal tokens are not tied to a current member in a complete member listing; `warn` when a token's base role outranks its member's role, when the member listing is truncated so unmatched tokens cannot be confirmed as orphaned, or when the inventory is partial or unknown (including an empty listing). |
| 12 | Audit log retention (>= 90 days queryable) | `launchdarkly_assess_monitoring_integrations` | LD-12 | `pass` when entries older than `retention_days` are returned and the recent audit log query was read; `warn` when the retention probe returned none but recent entries exist, or when the probe returned entries while the recent audit log query was unreadable; `fail` when a readable audit log returned no entries at all (the retention probe and the recent query both empty); `manual` when the retention probe is unreadable (including when no audit log query is readable) or when the probe returned nothing and the recent query was unreadable. The summary names each unreadable query with its request and error. |
| 13 | Audit log events present for critical actions | `launchdarkly_assess_monitoring_integrations` | LD-13 | `pass` when member or role entries carry critical actions and both queries were read; `warn` when no critical actions were returned, or when critical actions were seen but one of the two queries was unreadable; `manual` when both the member and the role query are unreadable (including when no audit log query is readable). The summary names each unreadable query with its request and error. |
| 14 | Flag targeting rules do not expose individual user keys in production | `launchdarkly_assess_flag_hygiene` | LD-14 | `fail` when production flags carry `targets` or `contextTargets` values; `warn` when no production flags were readable. |
| 15 | Stale flags identified (> 30 days) | `launchdarkly_assess_flag_hygiene` | LD-15 | `warn` when flags are inactive or unrequested beyond `stale_flag_days`. |
| 16 | Environment-level access controls restrict production modifications | `launchdarkly_assess_environment_governance` | LD-16 | `pass` only when every production environment is restricted by a custom role statement (a `deny` or `notResources` entry whose resource specifier matches it, or a role whose environment-scoped allows never cover it); `warn` when the environment relies on the `critical` designation alone, which only enables safeguards; `fail` when a non-critical production environment has no role restriction. |
| 17 | Approval workflows enabled for production changes | `launchdarkly_assess_environment_governance` | LD-17 | `fail` when `approvalSettings.required` is false; `warn` when the gate is weakened by `bypassApprovalsForPendingChanges`, `canReviewOwnRequest`, `canApplyDeclinedChanges` (one approval is enough even when other reviewers declined), or a non-empty `requiredApprovalTags` list (untagged flags skip approval). The normalized `approval_settings` block, including `minNumApprovals`, is included in `production_environment_settings` evidence. |
| 18 | Relay proxy configurations use secure mode | `launchdarkly_assess_monitoring_integrations` | LD-18 | `fail` for wildcard project or environment scope or referenced production environments without secure mode; `warn` when unmodified beyond `relay_config_max_age_days`; `manual` when no automatic configurations exist. |
| 19 | SDK keys rotated within policy period (< 365 days) | `launchdarkly_assess_environment_governance` | LD-19 | `fail` when server-side keys exceed `sdk_key_max_age_days`; `manual` when the beta SDK keys endpoint is unreadable. |
| 20 | Integrations use least-privilege scopes | `launchdarkly_assess_monitoring_integrations` | LD-20 | `fail` when enabled subscriptions allow all actions across all projects; `manual` when no subscriptions were found for the probed integration keys. |
| 21 | Webhook endpoints use HTTPS and signing is enabled | `launchdarkly_assess_monitoring_integrations` | LD-21 | `fail` when an enabled webhook uses plain HTTP or has no secret; `warn` when only disabled webhooks are insecure or the endpoint was unreadable. |
| 22 | No test/temporary projects in production account | `launchdarkly_assess_environment_governance` | LD-22 | `warn` when project keys, names, or tags match `test_project_pattern`. |
| 23 | Environment critical settings (secure mode, default TTL) configured | `launchdarkly_assess_environment_governance` | LD-23 | `fail` when production lacks secure mode; `warn` for zero TTL or missing confirm changes / required comments. |
| 24 | Member email domains match organization domain policy | `launchdarkly_assess_identity` | LD-24 | `fail` when active members use unapproved domains; `manual` when no `allowed_domains` policy is supplied (the observed domain distribution is included). |
| 25 | Flag prerequisites do not create circular dependencies | `launchdarkly_assess_flag_hygiene` | LD-25 | `fail` when the prerequisite graph contains a cycle. |

## Framework mappings

Each finding carries the eight framework references from the spec compliance table as `mappings` and as a `frameworks` object keyed by `fedramp`, `cmmc`, `soc2`, `cis`, `pci_dss`, `stig`, `irap`, and `ismap`.

For example, control 1 carries `FedRAMP IA-2(1)`, `CMMC L2 3.5.3`, `SOC 2 CC6.1`, `CIS 16.2`, `PCI-DSS 8.4.1`, `STIG SRG-APP-000148`, `IRAP ISM-1546`, and `ISMAP CPS-7.1`.

The export bundle renders one report per framework plus a unified matrix.

## Live smoke test

```bash
LAUNCHDARKLY_API_TOKEN=api-... npm --prefix cli run test:launchdarkly:live
```

The script prints a skip message and exits 0 when no token or config file is present.

Otherwise it runs `launchdarkly_check_access` and the access control assessment, and prints surface status and finding summaries. It never writes to the account.

## Limitations and manual controls

- Control 1 is always `manual`. LaunchDarkly does not expose the account SSO or Require SSO setting through the REST API. Confirm it in Organization settings > Security and capture a screenshot or IdP configuration.
- Control 2 evaluates per-member `mfa` status. The account level "Require MFA" toggle is not exposed by the API, so the finding asks you to confirm it in Organization settings, even when every member has MFA enabled.
- Control 19 depends on the beta SDK keys endpoint. When it is unavailable, record the creation date of each active server-side SDK key from Organization settings > SDK keys.
- Control 20 probes a default list of integration keys, because the API has no endpoint that enumerates every integration subscription.
  - Default keys: `datadog`, `dynatrace`, `elastic`, `honeycomb`, `logdna`, `msteams`, `new-relic-apm`, `signalfx`, `splunk`.
  - Pass `integration_keys` for other integrations.
- Control 18 covers Relay Proxy automatic configurations only. Relay Proxy deployments that use static SDK keys must be reviewed manually.
- The API caps audit log queries at 20 entries per request. Retention is demonstrated by probing for any entry older than `retention_days`, rather than by enumerating the entire log.
- Listing every member's personal tokens requires an Admin or Owner token.
  - `GET /api/v2/tokens?showAll=true` returns other members' personal tokens only when the caller has the Admin role.
  - So the inspector resolves the caller through `/api/v2/caller-identity` and looks up the caller's own token and member base roles in the listing. It treats personal tokens from other members as proof of a complete inventory.
  - An Admin personal token whose member record cannot be resolved (members unreadable or truncated) resolves to unknown rather than full. An empty listing resolves to unknown. A truncated token listing resolves to partial.
  - When the inventory is partial or its completeness is unknown, controls 8 through 11 never `pass`, even when zero tokens are visible:
    - A clean result becomes `warn` with the caveat in the finding summary.
    - Failures stay `fail`.
    - Every finding carries a `token_inventory` evidence block.
- Listing limits are verdict boundaries, not silent caps.
  - Defaults are 1000 members, 100 teams, 200 roles, 500 tokens, 50 projects, 50 environments per project, and 500 flags per environment.
  - When an account exceeds a limit, the affected findings `warn` with the seen versus total counts and name the argument to raise. They never `pass` on a slice of the data.
- Audit log sampling is intentional (20 entries per query) and is not treated as truncation. Controls 12 and 13 are presence probes rather than inventory claims.

## How the tools handle evidence

This section is reference for reviewing findings and bundles: how unread, partial, or truncated data limits a verdict, how the tools page through the API and report incomplete listings, and how credentials are kept out of findings, bundles, and error text. You don't need it to set up or run the integration.

### Redaction and projection

Credentials never reach the bundle. Every `core_data/` snapshot (including `access_check.json`) passes through a redaction step:

- The string value under any credential-shaped key is replaced with `[REDACTED]`, and the key is kept.
  - Credential-shaped keys: `token`, `secret`, `password`, `passphrase`, `apiKey`, `mobileKey`, `fullKey`, `authorization`, and their snake_case and plural forms.
  - The rule also covers `{name, value}` header pairs inside integration configs.
- Webhook and integration destination URLs are reduced to scheme plus host, so path or query tokens are dropped.

Flags are projected to their governance fields:

- `key`, `name`, `kind`, `temporary`, `archived`, `deprecated`, `creation_date`, `tags`, `maintainer_id`, and a variation count.
- Per environment: `on`, `archived`, `last_modified`, the rule count, prerequisite keys, and target counts per context kind.

Variation values and targeting clause values are never written.

Non-JSON error bodies are described by content type and length in error text, never echoed.

The assessment tools return findings, summaries, and errors without the raw snapshots.

### Unreadable inventories

An unreadable endpoint never produces a `pass`. It produces `warn` or `manual`, and it is recorded in the assessment `errors` list and the bundle `_errors.log`.

The rule holds for every inventory a finding reads, not only its primary one. A finding that combines several collections never `pass`es while any of them is unreadable (403, 401, 5xx, or a transport error). That holds even when the readable collections alone would satisfy the control.

The summary then carries `Unreadable inventory: <collection> (<endpoint>: <error>), so <what was not checked>. Collect manually: <evidence>`. The evidence lists the same under `unreadable_inventories` and `manual_evidence`.

The verdict is `manual` when the missing inventory is essential:

- LD-06 without members or teams
- LD-07 without teams or members
- LD-11 without members
- LD-12 without the retention probe
- LD-14/15/25 without environments or flags
- LD-15 without flag statuses
- LD-16 without custom roles or environments
- LD-17/19/23 without environments
- LD-19 without any readable SDK keys endpoint
- LD-18 without Relay Proxy configurations

The verdict is `warn` when the readable inventories still support a judgement:

- LD-07 with some team role listings unreadable
- LD-08 through LD-11 with the caller identity unreadable
- LD-08/09/10 with members unreadable
- LD-12 with the recent audit log unreadable
- LD-13 with the member or role audit query unreadable
- LD-18 with projects or environments unreadable
- LD-20 with one integration's subscriptions unreadable

Failing verdicts on the readable half stay `fail`.

A success status is not a success by itself. A 2xx response is recorded as a failed read of that request when its body is:

- Empty.
- Not JSON (a portal or proxy page).
- JSON of another shape (a list without an `items` array, a resource without any of its documented keys, a bare array).

The failed read carries `http_status: 200` and a fixed status-and-length note. The body is never echoed. So the request's dependents go `manual` or `warn` instead of passing or failing on data that was never observed.

### Data-side scrub

Every record a listing or single-resource read returns passes through one data-side scrub at the client. The scrub runs before any finding, snapshot, or bundle file sees the record.

- The whole subtree under a credential-shaped key (`token`, `tokens`, `secret`, `credentials`, `password`, `apiKey`, ...) becomes `[REDACTED]`, whether it is a string, a list, or a nested object.
- Header pairs (`{name, value}`) lose their value.
- `url` and `endpoint` fields keep scheme and host only.
- Every other string loses query tokens, bearer and assignment carriers, LaunchDarkly key shapes, high-entropy tokens, and the configured token. Free text is included (audit `comment`, `title`, `description`, role descriptions).

The export runs the same pass again over the snapshots it writes, as defense in depth.

### Error text

Recorded error text follows one rule at one place. A single function produces every one of these:

- Collection error
- Access surface `error`
- Assessment `errors` entry
- `_errors.log` line
- Tool failure message

The function passes the thrown message through the module scrubber. A `SyntaxError` raised by the transport is recorded as its class name plus a fixed note, because the parser's message quotes the body.

The scrubber removes the configured access token at full length in plain, base64, base64url, URL-encoded, form-encoded, and JSON-escaped form.

It also removes the value of every credential carrier, whatever the value's shape:

- **Credential pairs:** A `key=value`, `key: value`, or `"key": "value"` pair loses its value when its key carries a credential word (`api_token`, `LAUNCHDARKLY_API_TOKEN`, `LD_ACCESS_TOKEN`, and the bearer ids `secret_id`, `session_id`, and `token_id`).
  - The same holds when the key follows a JSON escape (`\"token\": \"v\"`) or a command-line flag (`--token v`, `--token=v`, `-Dtoken=v`).
- **Authorization schemes:** An authorization scheme word in any casing (`Bearer`, `bearer`, `Basic`, `Token`) loses the value after it.
  - A bare token and a whole auth-param list (`Snowflake Token="v"`, `Digest username="v", nonce="v", response="v"`) are removed alike.
  - The word itself stays only under `Authorization`, `Proxy-Authorization`, and `WWW-Authenticate`. Under those headers, a challenge's `realm="api"` stays as well.
  - An API-key or token header (`X-Api-Key: splunk rejected`) and a credential-named assignment (`token=Bearer v`) lose their whole value.
- **Cookies:** A cookie header loses its value whole, its `;` separating pairs and attributes.
- **URLs:** The query of any URL becomes one marker.
  - A credential-named parameter of a relative path or bare query string loses its value whole, a `;` inside the value included. For example, `?token=v;rest` renders `?token=[REDACTED]`, as URLSearchParams reads it.
  - A webhook or callback URL keeps its origin alone.

A `webhook`-prefixed key is a URL carrier only when its last segment is `url` or `uri`, or when the key is the bare `webhook`. `webhook_secret`, `webhook_token`, and `webhookSecret` are credential keys and lose their value whatever its shape.

A configured secret that is itself a carrier word (`password`, `Authorization`, `Bearer`) is removed after the carriers rather than before them. So the pair or header it names still loses its value.

A name after a path slash (`GET /api/v2/tokens: 403`) is a path segment, not a key. A key whose last segment names a setting (`base_url`, `token_url`, `stale_token_days`, `caller_token_role`, `session_duration`) keeps a word value and loses only a token-shaped or registered one.

So every fixed message and every finding summary, manual-evidence instruction, and bundle document survives the pass unchanged. The test suite sweeps thousands of strings recorded by healthy and partially denied runs for alterations.

### Truncated listings

A truncated listing never produces a `pass` either.

Every paginated collection (members, teams, team roles, custom roles, access tokens, projects, environments, SDK keys, flags) is fetched up to its `*_limit` argument. The client reports whether more items remained: `_links.next` still present, or `totalCount` above the collected count.

Every exit that can leave items behind is flagged:

- An empty page that still carries `_links.next`.
- A `_links.next` that repeats an already fetched URL.
- A single-request listing (webhooks, Relay Proxy configurations, integration subscriptions, flag statuses) whose payload still advertises a next page or a `totalCount` above the returned items.

#### Next links to other origins

A server-supplied `_links.next.href` is followed only when it resolves to the same origin as the configured base URL (scheme, host, and port).

An absolute, protocol-relative, or scheme-changed link to any other origin is refused before a request is built. That holds in any spelling the URL parser reads as an authority, including `///`, `/\`, `\\`, and upper-case or backslashed schemes.

The refusal uses fixed text. It names the configured origin and the scheme, host, and port the link resolved to (or its bare scheme, such as `javascript:`), and nothing else from the link. As a result:

- The access token never travels to a host the server chose.
- The pages already read are kept.
- The listing is reported truncated, with the refusal as its `truncation_reason` in the `core_data` record and its `collection_status.json` row.

The cap argument is not offered as the remedy, because raising it cannot help.

#### Truncation in findings

When a finding depends on a truncated collection:

- A clean verdict becomes `warn`.
- The summary ends with `Truncated listing: <collection> (<seen> of <total> collected)` plus the argument to raise.
- The evidence carries `truncated_collections` with the seen versus total counts.

Failing verdicts stay `fail`.

A population count or inventory list that would read as "none exist" renders `null` rather than `0` or `[]` when the listing it is derived from stopped before any record was read. This covers:

- Member, invite, team, custom role, token, project, and environment counts in the findings and in each assessment `summary`.
- `team_roles`, `domain_distribution`, `production_environments`, and `production_environment_settings` among the lists.

A positive count from a truncated listing renders as the lower bound observed, and `truncated_collections` sits beside it.

Item-level detail from a truncated token listing is withheld. LD-08 renders `tokens_without_expiry` as `null` beside `tokens_without_expiry_count`, and the names return from a complete listing. So a truncated page never names its part of the inventory as the whole.

The `core_data/` snapshots record the same `truncated`, `seen`, and `total` fields per collection. The executive summary lists every truncated listing.

## Official documentation consulted

- [LaunchDarkly REST API overview: authentication, versioning, rate limiting, pagination](https://launchdarkly.com/docs/api)
- [LaunchDarkly OpenAPI specification](https://app.launchdarkly.com/api/v2/openapi.json)
- [Get caller identity](https://launchdarkly.com/docs/api/other/get-caller-identity)
- [Account members](https://launchdarkly.com/docs/api/account-members)
- [Teams](https://launchdarkly.com/docs/api/teams)
- [Custom roles](https://launchdarkly.com/docs/api/custom-roles)
- [Access tokens](https://launchdarkly.com/docs/api/access-tokens)
- [Projects](https://launchdarkly.com/docs/api/projects)
- [Environments (including the beta SDK keys endpoint)](https://launchdarkly.com/docs/api/environments)
- [Feature flags](https://launchdarkly.com/docs/api/feature-flags)
- [Feature flag statuses](https://launchdarkly.com/docs/api/feature-flags/get-feature-flag-status-across-environments)
- [Audit log](https://launchdarkly.com/docs/api/audit-log)
- [Webhooks](https://launchdarkly.com/docs/api/webhooks)
- [Relay Proxy configurations](https://launchdarkly.com/docs/api/relay-proxy-configurations)
- [Integration audit log subscriptions](https://launchdarkly.com/docs/api/integration-audit-log-subscriptions)
- [API migration guide (flag `env` filter behavior)](https://launchdarkly.com/docs/guides/api/api-migration-guide)
- [Role resources syntax](https://launchdarkly.com/docs/home/account/roles/role-resources)
- [Role concepts, including the `{critical:true}` property-based selector](https://launchdarkly.com/docs/home/account/roles/role-concepts#property-based-selectors)
- [Critical environments (safeguards versus custom role access)](https://launchdarkly.com/docs/home/account/environment#critical-environments)
- [Role actions reference](https://launchdarkly.com/docs/home/account/roles/role-actions)
- [Multi-factor authentication](https://launchdarkly.com/docs/home/account/mfa)
- [Enable SAML SSO](https://launchdarkly.com/docs/home/account/saml/enable)
- [Owner role](https://launchdarkly.com/docs/home/account/roles/owners)
- [Environment settings (secure mode, critical environments, approvals)](https://launchdarkly.com/docs/home/account/environment/settings)
- [Environment keys (SDK key rotation)](https://launchdarkly.com/docs/home/account/environment/keys)
- [Relay Proxy automatic configuration](https://launchdarkly.com/docs/sdk/relay-proxy/automatic-configuration)
