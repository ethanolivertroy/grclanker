---
title: LaunchDarkly
description: Read-only LaunchDarkly account security inspector covering identity, access control, environment governance, flag hygiene, and monitoring integrations across 25 spec controls.
---

The LaunchDarkly integration audits a LaunchDarkly account through the REST API v2 and maps what it finds to the 25 controls in `specs/launchdarkly-sec-inspector.spec.md`. Every tool is read-only: the inspector never creates, updates, or deletes anything in the account, and access tokens are redacted from errors, output, and exported bundles.

## What it inspects

- Identity: member MFA coverage, Owner and Admin concentration, orphaned members, team custom role usage, member email domains, and the evidence available for SSO/SAML enforcement.
- Access control: custom role policies (wildcard actions, sensitive administrative grants, deny-by-default design) and access tokens (expiry, staleness, service token scope, personal token scope).
- Environment governance: production environment restrictions, required approvals, secure mode, default TTL, confirm changes, required comments, server-side SDK key age, and test or temporary projects.
- Flag hygiene: individual context targeting in production, stale flags, and circular prerequisite chains.
- Monitoring and integrations: audit log retention and critical action coverage, Relay Proxy automatic configuration scope and secure mode, integration audit log subscription scope, and webhook HTTPS plus signing.

## Setup and authentication

LaunchDarkly authenticates REST calls with a personal or service access token sent verbatim in the `Authorization` header (no `Bearer` prefix), and pins the response shape with the `LD-API-Version` header. The inspector defaults to API version `20240415` and switches to `beta` only for the SDK keys endpoint, which is still a beta resource.

Configuration precedence is explicit tool arguments, then environment variables, then the TOML config file:

| Setting | Tool argument | Environment variable | Config file key |
| --- | --- | --- | --- |
| Access token (required) | `token` | `LAUNCHDARKLY_API_TOKEN` (fallback `LD_ACCESS_TOKEN`) | `token`, `api_token`, or `access_token` |
| Base URL | `base_url` | `LAUNCHDARKLY_BASE_URL` (fallback `LD_BASE_URI`) | `base_url` |
| API version | `api_version` | `LAUNCHDARKLY_API_VERSION` | `api_version` |
| Timeout (seconds) | `timeout_seconds` | `LAUNCHDARKLY_TIMEOUT` | `timeout_seconds` |
| Approved member domains | `allowed_domains` | `LAUNCHDARKLY_ALLOWED_DOMAINS` | `allowed_domains` |
| Project scope | `project_keys` | `LAUNCHDARKLY_PROJECTS` | `projects` |
| Config file path | `config_path` | `LAUNCHDARKLY_CONFIG` | n/a (defaults to `~/.config/launchdarkly-sec-inspector/config.toml`) |

Base URL defaults to `https://app.launchdarkly.com`. Use `https://app.launchdarkly.us` for the federal instance and `https://app.eu.launchdarkly.com` for the EU instance.

A minimal config file:

```toml
token = "api-xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
base_url = "https://app.launchdarkly.com"
allowed_domains = ["example.com"]
projects = ["web", "mobile"]
```

### Token role requirements

- Reader base role: enough for members, teams, custom roles, projects, environments, flags, flag statuses, webhooks, Relay Proxy configurations, and integration subscriptions.
- Admin or Owner base role: required for `GET /api/v2/tokens?showAll=true` to return every member's personal tokens (controls 8 through 11), and recommended for full audit log depth.
- Custom role alternative: the role actions reference defines `viewProject` and `viewTeam` but no dedicated member, role, or audit log view actions, so an audit custom role needs `basePermissions: reader` plus `viewProject` on each audited project. The spec's `viewMembers`, `viewRoles`, and `viewAuditLog` actions do not exist.

The SDK keys endpoint (`/api/v2/projects/{projectKey}/environments/{environmentKey}/sdk-keys`) is beta and may not be available on every plan; when it is unreadable, control 19 is reported as `manual` with the evidence a human needs to collect.

## Tools

| Tool | Purpose |
| --- | --- |
| `launchdarkly_check_access` | Probe caller identity plus 11 read surfaces (members, teams, custom roles, projects, environments, flags, access tokens, audit log, webhooks, Relay Proxy configs, integration subscriptions). Reports `healthy` only when every core surface is readable; webhooks, Relay Proxy configs, and integration subscriptions are optional. |
| `launchdarkly_assess_identity` | Controls 1, 2, 3, 6, 7, 24. Arguments: `member_limit`, `team_limit`, `max_owners`, `max_admins`, `allowed_domains`. |
| `launchdarkly_assess_access_control` | Controls 4, 5, 8, 9, 10, 11. Arguments: `role_limit`, `token_limit`, `stale_token_days`. |
| `launchdarkly_assess_environment_governance` | Controls 16, 17, 19, 22, 23. Arguments: `project_limit`, `environment_limit`, `project_keys`, `production_pattern`, `test_project_pattern`, `sdk_key_max_age_days`. |
| `launchdarkly_assess_flag_hygiene` | Controls 14, 15, 25. Arguments: `project_limit`, `flag_limit`, `project_keys`, `production_pattern`, `stale_flag_days`. |
| `launchdarkly_assess_monitoring_integrations` | Controls 12, 13, 18, 20, 21. Arguments: `retention_days`, `integration_keys`, `relay_config_max_age_days`, `production_pattern`. |
| `launchdarkly_export_audit_bundle` | Runs the access check and all five assessments, then writes a bundle plus zip under `output_dir` (default `./export/launchdarkly`). |

Every tool accepts the shared auth arguments `token`, `base_url`, `api_version`, `config_path`, and `timeout_seconds`.

Production environments are those flagged `critical` in LaunchDarkly or whose key or name matches `production_pattern` (default `prod`, case-insensitive).

Control 16 evaluates custom role policies with a resource specifier parser that follows the documented `proj/<key>:env/<key>;tag1,tag2,{selector:value}` syntax: project and environment keys support `*` globs, tags must all be present on the environment, and the `{critical:true}` property-based selector matches environments marked critical. The bare form `proj/*:env/*;critical:true:flag/*` is accepted as an alias for the documented `proj/*:env/*;{critical:true}:flag/*`.

### Export bundle layout

```text
<host>-<accountId>-audit-bundle/
  metadata.json
  QUICK_REFERENCE.md
  _errors.log                      (only when some reads failed)
  core_data/                       raw API snapshots, secrets masked
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

Output paths are resolved through `resolveSecureOutputPath`, which rejects directory traversal and symlinked parents, and files are written with owner-only permissions. SDK keys, mobile keys, Relay Proxy keys, webhook secrets, and integration credentials are masked before they reach `core_data/`.

## Finding shape and status semantics

Every finding is `{ id, control, title, severity, status, summary, evidence, mappings, frameworks }`. Finding ids are `LD-01` through `LD-25` and match the spec control numbers.

- `pass`: the API evidence satisfies the control.
- `warn`: the control is partially satisfied, the data was too thin to conclude (for example no production environments detected or an endpoint was unreadable), or a low severity hygiene issue was found.
- `fail`: the API evidence shows the control is not met.
- `manual`: the API cannot verify the control; the summary and `evidence.manual_evidence` state exactly what a human must collect.

An unreadable endpoint never produces a `pass`; it produces `warn` or `manual` and is recorded in the assessment `errors` list and the bundle `_errors.log`.

## Control coverage

| # | Spec control | Tool | Finding | Status semantics |
| --- | --- | --- | --- | --- |
| 1 | SSO/SAML enforcement enabled for the account | `launchdarkly_assess_identity` | LD-01 | Always `manual`: the API does not expose the account SSO setting. Evidence includes SCIM-provisioned member counts, members with passwords, and SAML/SCIM/MFA audit entries. |
| 2 | MFA required for all members | `launchdarkly_assess_identity` | LD-02 | `pass` when every active member reports `mfa: enabled`; `fail` otherwise; `warn` when no members were readable. |
| 3 | No members with Owner role beyond minimum required | `launchdarkly_assess_identity` | LD-03 | `fail` when Owners exceed `max_owners`; `warn` when Admins exceed `max_admins`. |
| 4 | Custom roles follow least-privilege (no wildcard actions) | `launchdarkly_assess_access_control` | LD-04 | `fail` when any allow statement uses wildcard actions or open-ended `notActions`; `warn` when no custom roles exist. |
| 5 | Custom role policies deny sensitive actions by default | `launchdarkly_assess_access_control` | LD-05 | `fail` when a role allows account, member, role, token, relay, webhook, or team administration actions without an explicit deny; `warn` when roles use reader base permissions. |
| 6 | All members assigned to teams | `launchdarkly_assess_identity` | LD-06 | `fail` when active members have no team; `warn` when no teams exist. |
| 7 | Team permissions use custom roles, not built-in admin | `launchdarkly_assess_identity` | LD-07 | `fail` when sampled teams have no custom roles; `warn` when no teams exist. |
| 8 | API access tokens have expiration dates set | `launchdarkly_assess_access_control` | LD-08 | `fail` when any token lacks `expiry`; `warn` when tokens were not readable. |
| 9 | No API tokens unused beyond 90 days | `launchdarkly_assess_access_control` | LD-09 | `fail` when `lastUsed` (or creation) is older than `stale_token_days`. |
| 10 | Service tokens scoped to minimum required roles | `launchdarkly_assess_access_control` | LD-10 | `fail` for Owner/Admin base role or wildcard inline policies; `warn` for the Writer base role. |
| 11 | Personal tokens limited to individual member scope | `launchdarkly_assess_access_control` | LD-11 | `fail` when personal tokens are not tied to a current member; `warn` when they carry Owner/Admin scope. |
| 12 | Audit log retention (>= 90 days queryable) | `launchdarkly_assess_monitoring_integrations` | LD-12 | `pass` when entries older than `retention_days` are returned; `warn` when none are; `fail` when the audit log is unreadable or empty. |
| 13 | Audit log events present for critical actions | `launchdarkly_assess_monitoring_integrations` | LD-13 | `pass` when member or role entries carry critical actions; `warn` when none were returned; `fail` when unreadable. |
| 14 | Flag targeting rules do not expose individual user keys in production | `launchdarkly_assess_flag_hygiene` | LD-14 | `fail` when production flags carry `targets` or `contextTargets` values; `warn` when no production flags were readable. |
| 15 | Stale flags identified (> 30 days) | `launchdarkly_assess_flag_hygiene` | LD-15 | `warn` when flags are inactive or unrequested beyond `stale_flag_days`. |
| 16 | Environment-level access controls restrict production modifications | `launchdarkly_assess_environment_governance` | LD-16 | `pass` only when every production environment is restricted by a custom role statement (a `deny` or `notResources` entry whose resource specifier matches it, or a role whose environment-scoped allows never cover it); `warn` when the environment relies on the `critical` designation alone, which only enables safeguards; `fail` when a non-critical production environment has no role restriction. |
| 17 | Approval workflows enabled for production changes | `launchdarkly_assess_environment_governance` | LD-17 | `fail` when `approvalSettings.required` is false; `warn` when bypass or self review is allowed. |
| 18 | Relay proxy configurations use secure mode | `launchdarkly_assess_monitoring_integrations` | LD-18 | `fail` for wildcard project or environment scope or referenced production environments without secure mode; `warn` when unmodified beyond `relay_config_max_age_days`; `manual` when no automatic configurations exist. |
| 19 | SDK keys rotated within policy period (< 365 days) | `launchdarkly_assess_environment_governance` | LD-19 | `fail` when server-side keys exceed `sdk_key_max_age_days`; `manual` when the beta SDK keys endpoint is unreadable. |
| 20 | Integrations use least-privilege scopes | `launchdarkly_assess_monitoring_integrations` | LD-20 | `fail` when enabled subscriptions allow all actions across all projects; `manual` when no subscriptions were found for the probed integration keys. |
| 21 | Webhook endpoints use HTTPS and signing is enabled | `launchdarkly_assess_monitoring_integrations` | LD-21 | `fail` when an enabled webhook uses plain HTTP or has no secret; `warn` when only disabled webhooks are insecure or the endpoint was unreadable. |
| 22 | No test/temporary projects in production account | `launchdarkly_assess_environment_governance` | LD-22 | `warn` when project keys, names, or tags match `test_project_pattern`. |
| 23 | Environment critical settings (secure mode, default TTL) configured | `launchdarkly_assess_environment_governance` | LD-23 | `fail` when production lacks secure mode; `warn` for zero TTL or missing confirm changes / required comments. |
| 24 | Member email domains match organization domain policy | `launchdarkly_assess_identity` | LD-24 | `fail` when active members use unapproved domains; `manual` when no `allowed_domains` policy is supplied (the observed domain distribution is included). |
| 25 | Flag prerequisites do not create circular dependencies | `launchdarkly_assess_flag_hygiene` | LD-25 | `fail` when the prerequisite graph contains a cycle. |

## Framework mappings

Each finding carries the eight framework references from the spec compliance table as `mappings` (for example `FedRAMP IA-2(1)`, `CMMC L2 3.5.3`, `SOC 2 CC6.1`, `CIS 16.2`, `PCI-DSS 8.4.1`, `STIG SRG-APP-000148`, `IRAP ISM-1546`, `ISMAP CPS-7.1` for control 1) and as a `frameworks` object keyed by `fedramp`, `cmmc`, `soc2`, `cis`, `pci_dss`, `stig`, `irap`, and `ismap`. The export bundle renders one report per framework plus a unified matrix.

## Live smoke test

```bash
LAUNCHDARKLY_API_TOKEN=api-... npm --prefix cli run test:launchdarkly:live
```

The script prints a skip message and exits 0 when no token or config file is present. Otherwise it runs `launchdarkly_check_access` and the access control assessment, printing surface status and finding summaries. It never writes to the account.

## Limitations and manual controls

- Control 1 is always `manual`. LaunchDarkly does not expose the account SSO or Require SSO setting through the REST API; confirm it in Organization settings > Security and capture a screenshot or IdP configuration.
- Control 2 evaluates per-member `mfa` status. The account level "Require MFA" toggle is not exposed by the API, so the finding asks you to confirm it in Organization settings even when every member has MFA enabled.
- Control 19 depends on the beta SDK keys endpoint. When it is unavailable, record the creation date of each active server-side SDK key from Organization settings > SDK keys.
- Control 20 probes a default list of integration keys (`datadog`, `dynatrace`, `elastic`, `honeycomb`, `logdna`, `msteams`, `new-relic-apm`, `signalfx`, `splunk`) because the API has no endpoint that enumerates every integration subscription. Pass `integration_keys` for other integrations.
- Control 18 covers Relay Proxy automatic configurations only; Relay Proxy deployments that use static SDK keys must be reviewed manually.
- Audit log queries are capped at 20 entries per request by the API; retention is demonstrated by probing for any entry older than `retention_days` rather than by enumerating the entire log.
- Listing every member's personal tokens requires an Admin or Owner token. With a Reader token, controls 8 through 11 evaluate only the tokens visible to the caller.

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
