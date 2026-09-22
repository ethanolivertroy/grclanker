---
title: MuleSoft Anypoint Platform
description: Read-only security inspector for MuleSoft Anypoint Platform organizations covering identity and access, API Manager policies, runtime infrastructure, and audit logging across 25 spec controls.
---

The MuleSoft integration inspects an Anypoint Platform organization through the public Anypoint Platform APIs and reports framework-mapped findings for the 25 controls in `specs/mulesoft-sec-inspector.spec.md`. It never mutates the organization: every request is a `GET`, except the token exchange and the audit log query, which the Audit Log Query API exposes as a `POST`.

## What it inspects

- **Access Management**: external identity providers, MFA exemptions, Organization Administrator membership, role groups and environment scoping, environments, connected apps, business groups
- **API Manager and Exchange**: API instance policies (client ID enforcement, JWT, OAuth, basic auth, rate limiting, spike control), active contracts, Exchange asset publication status
- **Runtime infrastructure**: CloudHub applications (runtime version, workers, persistent queues, properties), Anypoint VPC firewall rules, dedicated load balancer TLS settings and certificates, hybrid servers, Anypoint MQ queues and clients, Secrets Manager secret groups
- **Audit and monitoring**: Audit Log Query API availability, CloudHub and Runtime Manager alerts for production applications

## Setup and authentication

Set the organization ID and one credential source. Explicit tool arguments win over environment variables, which win over the TOML config file.

| Setting | Argument | Environment variable | `config.toml` key |
| --- | --- | --- | --- |
| Organization (business group) ID | `organization_id` | `ANYPOINT_ORG_ID` (or `ANYPOINT_ORGANIZATION_ID`) | `org_id` |
| Connected app client credentials | `client_id`, `client_secret` | `ANYPOINT_CLIENT_ID`, `ANYPOINT_CLIENT_SECRET` | `client_id`, `client_secret` |
| Username and password | `username`, `password` | `ANYPOINT_USERNAME`, `ANYPOINT_PASSWORD` | `username`, `password` |
| Pre-issued bearer token | `token` | `ANYPOINT_TOKEN` (or `ANYPOINT_ACCESS_TOKEN`) | `token` |
| Control plane | `control_plane` (`us`, `eu`, `gov`) | `ANYPOINT_CONTROL_PLANE` | `control_plane` |
| Custom base URL | `base_url` | `ANYPOINT_BASE_URL` | `base_url` |
| Environment filter | `environments` (comma-separated names or IDs) | `ANYPOINT_ENVIRONMENTS` | `environments` (array) |
| Request timeout (seconds) | `timeout_seconds` | `ANYPOINT_TIMEOUT` | `timeout` |
| Config file path | `config_file` | `MULESOFT_SEC_INSPECTOR_CONFIG` | default `~/.config/mulesoft-sec-inspector/config.toml` |

Auth mode is chosen in this order: pre-issued token, connected app client credentials, then username and password.

- Connected apps exchange credentials with `POST /accounts/api/v2/oauth2/token` using `grant_type=client_credentials`.
- Username and password log in with `POST /accounts/login`.
- Tokens are held in memory only and refreshed before `expires_in` elapses. Secrets, bearer tokens, and every secret-bearing response field (`client_secret`, `clientSecret`, `password`, tokens, authorization values, API and access keys, VPN `presharedKey` values, hybrid server `registrationKey` values, signing and text keys, SNMP `community` strings, hashes, and `name`/`value` property pairs whose name matches) are redacted from errors, tool output, and bundle snapshots; URL-valued fields (alert and webhook `url`/`uri` values) are reduced to scheme and host.

### Control planes

| `control_plane` | Base URL |
| --- | --- |
| `us` (default) | `https://anypoint.mulesoft.com` |
| `eu` | `https://eu1.anypoint.mulesoft.com` |
| `gov` | `https://gov.anypoint.mulesoft.com` |

Pass `base_url` for any other hostname; the control plane is then reported as `custom`.

### Example `config.toml`

```toml
org_id = "3a2b1c0d-1111-2222-3333-444455556666"
client_id = "0fa2aa2f0aeb4978b96796a0843f898c"
client_secret = "replace-me"
control_plane = "us"
environments = ["Production", "Sandbox"]
timeout = 30
```

### Connected app permissions

Create a connected app that acts on its own behalf (client credentials) and grant it read-only permissions in the organization and each environment you want inspected. `mulesoft_check_access` probes every surface and names the permission for any `401` or `403`.

| Surface | Read permission |
| --- | --- |
| Organization, members, role groups, environments, connected apps, identity providers, hierarchy | Access Management: Organization Administrator is required for identity provider settings and MFA exemptions; the remaining reads work with any principal that can view the organization |
| API Manager APIs and policies | API Manager: View APIs Configuration, View Policies, View Contracts |
| Exchange assets | Exchange: Exchange Viewer |
| CloudHub applications and alerts, hybrid servers | Runtime Manager: Read Applications, Read Alerts, Read Servers |
| Anypoint VPCs and dedicated load balancers | Runtime Manager: CloudHub Network Viewer |
| Audit log platforms, queries, and retention settings | Access Management: Audit Log Viewer. The retention settings read (`GET /audit/v2/organizations/{orgId}/retentionSettings`) is evidence only for control 17; a `403` on it is recorded in the finding and `_errors.log` without changing the verdict |
| Anypoint MQ regions, queues, clients | MQ: View destinations, View clients |
| Secrets Manager secret groups | Secrets Manager: Manage secret groups (includes read) or Read secrets metadata |

Because Anypoint scopes are environment-specific for most products, grant them for each environment the assessment should sample.

## Tools

| Tool | Purpose |
| --- | --- |
| `mulesoft_check_access` | Probes 20 read surfaces (Access Management, API Manager, Exchange, CloudHub, Runtime Manager, audit log, MQ, Secrets Manager), reports `healthy` or `limited`, and lists missing permissions. |
| `mulesoft_assess_identity_access` | Controls 1-6, 18, 19, 25: identity providers, MFA exemptions, admin count, role group least privilege and environment scoping, environment isolation, connected app scopes and staleness, business groups. |
| `mulesoft_assess_api_gateway` | Controls 7-9, 20: authentication and rate limiting policies on API instances (production first), client credential rotation evidence, Exchange asset governance. |
| `mulesoft_assess_runtime_infrastructure` | Controls 10-16, 21-23: runtime versions, worker sizing, persistent queue encryption, VPC firewall rules and open ingress, DLB TLS versions and certificate expiry, MQ, Secrets Manager, hybrid servers. |
| `mulesoft_assess_audit_monitoring` | Controls 17, 24: audit log entries in the lookback window and alert coverage for production applications. |
| `mulesoft_export_audit_bundle` | Runs the access check and all four assessments and writes a bundle plus `.zip` under `output_dir` (default `./export/mulesoft`): `core_data/` holds projected and redacted snapshots (a denied, errored, or never-requested dataset is written as a `{ collected: false, dataset, status, endpoint, error }` marker, and a dataset assembled from several reads of which some failed as `{ collected: "partial", failed_reads, items }`), `analysis/` holds the findings and per-category summaries with an `inventories` map naming each source as complete, partial, unread, or not requested, and `compliance/` holds the executive summary, unified matrix, and eight framework reports. |

All tools accept the authentication arguments above. Assessment tools also accept thresholds such as `max_admins`, `max_roles_per_group`, `max_connected_app_scopes`, `stale_connected_app_days`, `environment_limit`, `api_limit`, `application_limit`, `runtime_support_warning_days`, `certificate_warning_days`, and `audit_lookback_hours`. Environments are sampled production first, so a low `environment_limit` still covers production.

Each finding has the shape `{ id, control, title, severity, status, summary, evidence, mappings }` where `severity` is `critical`, `high`, `medium`, `low`, or `info` and `status` is `pass`, `warn`, `fail`, or `manual`. A `manual` finding states exactly what evidence a human must collect from Anypoint Platform. When a read failed or the credential saw only part of the inventory, `evidence.unreadable_sources` and `evidence.partial_view` list the causes.

### Verdict safety

Every finding follows the same rules so that missing or partial evidence never produces a `pass`:

- An unreadable, forbidden (401/403), or errored primary source yields `manual` with a summary that starts `Could not evaluate:`, names the source and HTTP cause, and states the evidence to collect. A failed secondary source turns a would-be pass into `manual` with `Could not confirm:`.
- An empty inventory never passes by default. Each control states whether emptiness is `fail` (no identity provider, zero audit events in 7 days, a production environment with no alerts) or `manual` (zero role groups, environments, connected apps, API instances, applications, VPCs, or Exchange assets).
- Controls that do not apply (no dedicated load balancer, no Anypoint MQ region, no hybrid server, no persistent queues, `createSubOrgs` entitlement false) and endpoints that return 404 on the control plane render as `manual` with a not-applicable or unavailable summary.
- Items without a date (connected apps without `last_used`, applications without `endOfSupportDate` or a runtime version, certificates without `validTo`) are reported in their own bucket and yield at most `warn`.
- A partial view (environment filter or `environment_limit` that excludes environments, `api_limit` or `application_limit` caps, truncated pages, per-item reads that were truncated or failed, a credential scoped to a business group) is recorded with seen and total counts, and a would-be pass becomes `warn` with a `Partial view:` prefix and the sentence "The unseen items were not evaluated, so the control cannot pass on this sample."
- Verdicts read the documented flags they depend on (`isFederated`, `allow_new_non_sso_users`, `mfaVerificationExcluded`, policy `disabled`, `tlsv1`, `httpMode` and `defaultCipherSuite`, `persistentQueuesEncrypted`, property `secure`, alert `enabled`, `entitlements.createSubOrgs`, hierarchy `isRoot`); an absent flag never supports `pass`.
- Pagination runs to the requested limit and every list reports whether it was truncated; a first page is never treated as the whole population.
- A read that depends on a list which was not read (role group roles and members, connected app scopes, API instances and policies, applications, servers, MQ regions, queues, and clients, secret groups, VPC and load balancer details, the load balancer certificate probes, alerts) is never requested; it is recorded as `not requested` naming the parent read, and the finding reports the parent failure once instead of an empty child read. When some parents were read and others were not, the children of the unread parents are reported as a partial failure.
- Evidence and summaries derived from an unread or unrequested source render `null` rather than `0` or `[]`: `evidence.partial_view` is `null` (not `[]`) when a source was never read, and every category summary carries an `inventories` map naming each source as `complete (N items)`, `partial (N of M)`, `unread (<error>)`, or `not requested (<reason>)`.
- Re-running the export allocates a new directory and derives the `.zip` name from it, so no prior bundle or archive is overwritten.

### Bundle layout

```text
<org>-audit-bundle/
  metadata.json
  QUICK_REFERENCE.md
  _errors.log                         (only when some reads failed)
  core_data/                          projected and redacted API snapshots; not-collected markers for denied or unrequested datasets
  analysis/findings.json              all 25 findings
  analysis/summary.json               status counts per category
  analysis/<category>.json            summary (with an inventories map), findings, and errors per assessment
  compliance/executive_summary.md
  compliance/unified_compliance_matrix.md
  compliance/<framework>/<framework>_compliance_report.md   (fedramp, cmmc, soc2, cis, pci_dss, disa_stig, irap, ismap)
<org>-audit-bundle.zip
```

Output paths are resolved inside `output_dir`; traversal outside the root and symlinked parent directories are rejected, and files are written with `0600` permissions.

## Control coverage

The `Inputs` column names the sources each finding reads, using the keys of the category summary's `inventories` map. A primary input that is unread makes the finding `manual` with `Could not evaluate:`; a secondary input that is unread turns a would-be pass or warn into `manual` with `Could not confirm:` (a fail keeps its verdict and adds a note); an input that is truncated, capped, filtered, or only partly read adds a `Partial view:` note and turns a would-be pass into `warn`. Per-item reads (`role_group_roles`, `connected_app_scopes`, `api_policies`, `vpc_details`, `load_balancer_details`, and the per-environment inventories) are `not requested` when their parent list was not read, and the finding reports the parent.

| # | Spec control | Tool | Finding | Inputs | Status semantics |
| --- | --- | --- | --- | --- | --- |
| 1 | SSO/SAML or OIDC external identity provider configured | identity_access | `MULESOFT-IAM-01` | `identity_providers`, `organization`; secondary `identity_provider_settings` | fail: zero identity providers, or every provider disabled; warn: `isFederated` absent or false, `allow_new_non_sso_users` not exposed, or new non-SSO users allowed; pass: an active provider, `isFederated=true`, and non-SSO user creation disabled. Partial view: identity provider list truncated, or business group scope |
| 2 | MFA enforced for all organization members | identity_access | `MULESOFT-IAM-02` | `mfa_exempt_users` (plus the `members` count) | fail: users listed with `mfaVerificationExcluded=true`; warn: the exemption query returned users without the flag; manual: zero exemptions (the organization-wide MFA setting is not exposed, so capture it or the IdP MFA policy). `members_sampled` is context and renders `null` when the member list is unread. Partial view: exempt-user or member list truncated |
| 3 | Organization Administrator membership minimized | identity_access | `MULESOFT-IAM-03` | `role_groups`, `role_group_roles`, `role_group_users` | fail: distinct members of admin role groups above `max_admins` (default 5); manual: zero role groups or no admin role group visible; pass: within the threshold. Partial view: role group list truncated, role assignments truncated for named groups, or admin membership truncated at the seen count (the admin count is then a lower bound and a pass becomes warn); `members_sampled` renders `null` when the member list is unread |
| 4 | Role groups follow least privilege | identity_access | `MULESOFT-IAM-04` | `role_groups`, `role_group_roles` | fail: custom role group grants Organization Administrator or Owner; warn: more than `max_roles_per_group` roles; manual: zero role groups; pass otherwise. Partial view: role group list or per-group role assignments truncated |
| 5 | Role groups scoped to specific environments | identity_access | `MULESOFT-IAM-05` | `role_groups`, `role_group_roles` | fail: more than 5 org-wide environment roles; warn: 1-5; manual: zero role groups or zero environment-level assignments; pass: every environment-level role carries `context_params.envId`. Partial view: as control 4 |
| 6 | Production and sandbox environments isolated | identity_access | `MULESOFT-IAM-06` | `environments` | fail: environment names contradict their type; warn: environments without `isProduction` or `type`, or no production or no sandbox environment; manual: zero environments; pass otherwise. Partial view: environment list truncated |
| 7 | Authentication policies on production APIs | api_gateway | `MULESOFT-API-07` | `environments`, `api_manager_apis`, `api_policies` | fail: a production API instance has no enabled authentication policy; warn: a matching policy whose `disabled` flag was not returned, or only non-production instances lack one; manual: zero API instances or no production instance sampled; pass: `disabled=false` confirmed on every instance. Partial view: environments excluded by the filter or `environment_limit`, `api_limit` reached, an API list truncated, or a per-API policy read truncated; an API list that was read in some environments but not others is a partial failure that renders manual |
| 8 | Rate limiting policies applied | api_gateway | `MULESOFT-API-08` | `environments`, `api_manager_apis`, `api_policies` | fail: production instance without an enabled rate limiting or spike control policy; warn: unknown `disabled` state or non-production only; manual: zero instances or no production instance sampled; pass: `disabled=false` confirmed on every instance. Partial view: as control 7 |
| 9 | Client credentials rotated within policy period | api_gateway | `MULESOFT-API-09` | `environments`, `api_manager_apis` (contract counts) | manual: the API does not expose secret rotation timestamps; when the environment or API inventory could not be read the summary names the HTTP cause and `active_contracts` and `apis_sampled` render `null` |
| 10 | Supported Mule runtime versions | runtime_infrastructure | `MULESOFT-RT-10` | `environments`, `cloudhub_applications` | fail: Mule 3 or `endOfSupportDate` in the past; warn: end of support within `runtime_support_warning_days`, or the version or end of support date not exposed; manual: zero CloudHub applications; pass otherwise. Partial view: environments excluded, or `application_limit` left applications uninspected |
| 11 | Worker sizing reviewed | runtime_infrastructure | `MULESOFT-RT-11` | `environments`, `cloudhub_applications` | warn: multiple or large workers in non-production, four or more workers with CPU under 10 percent (applications are listed with `retrieveStatistics=true` so `workers.recentStatistics.cpu` is populated), worker data missing, or four or more workers without CPU statistics; manual: zero applications; pass otherwise. Partial view: as control 10 |
| 12 | Persistent queues encrypted | runtime_infrastructure | `MULESOFT-RT-12` | `environments`, `cloudhub_applications` | fail: `persistentQueues` enabled without `persistentQueuesEncrypted=true`; manual: zero applications or no application enables persistent queues (not applicable); pass: encryption confirmed on every queue-enabled application. Partial view: as control 10 |
| 13 | VPC firewall rules restrictive | runtime_infrastructure | `MULESOFT-RT-13` | `vpcs`, `vpc_details` | fail: rule allows all protocols; warn: wide port ranges or CIDR broader than /16; manual: zero VPCs, a VPC without a `firewallRules` list, or a per-VPC detail read that failed; pass otherwise. Partial view: VPC list truncated |
| 14 | No 0.0.0.0/0 VPC ingress | runtime_infrastructure | `MULESOFT-RT-14` | `vpcs`, `vpc_details` | fail: open ingress on any port other than 8081 and 8082, including the DLB back-end ports 8091 and 8092 that CloudHub scopes to the VPC CIDR by default; warn: open ingress only on 8081 or 8082, the ports the shared load balancer exposes; manual: zero VPCs, a VPC without a `firewallRules` list, or a per-VPC detail read that failed; pass otherwise. Partial view: as control 13 |
| 15 | DLB enforces TLS 1.2+ and strong cipher suites | runtime_infrastructure | `MULESOFT-RT-15` | `load_balancers`, `load_balancer_details` | fail: `tlsv1=true`, or `defaultCipherSuite` offers RC4, DES/3DES, NULL, EXPORT, MD5, anonymous, or other weak ciphers; warn: `httpMode` is `on`, the `tlsv1` or `httpMode` flags were not returned, `defaultCipherSuite` was not returned, or the suite includes non-forward-secret (static RSA) ciphers or broad OpenSSL groups such as `HIGH` (the documented OldDefault set); manual: no dedicated load balancer (not applicable) or the per-DLB detail read failed; pass: `tlsv1=false`, no plain HTTP, and a suite limited to ECDHE/DHE ciphers. `defaultCipherSuite` is read from the list (`shortFormat=false`) or, when absent, from `GET /cloudhub/api/organizations/{orgId}/vpcs/{vpcId}/loadbalancers/{dlbId}`. Partial view: load balancer list truncated |
| 16 | DLB certificates valid beyond 30 days | runtime_infrastructure | `MULESOFT-RT-16` | `load_balancers`; partial-view input `load_balancer_details` (it supplies extra `sslEndpoints` and is neither a primary nor a secondary input of this control) | fail: live TLS probe shows expiry within 30 days; warn: within `certificate_warning_days` (default 60), a certificate that could not be dated, or a dated certificate whose chain did not validate against the auditor's trust store (`authorized=false`, or validation not reported); manual: no dedicated load balancer, or none of the probed certificates could be dated over TLS; pass: every certificate dated, chain validated, and beyond the warning window. One probe runs per `sslEndpoints` entry using its `publicKeyCN` (or a concrete SAN) as the SNI name (the load balancer's own domain when the record lists no endpoints), so counts are per certificate, not per load balancer. Partial view: load balancer list truncated, or the per-DLB detail read failed ("so SSL endpoints carried only by the detail record were not probed"); the failed detail read alone never renders this control manual (unlike control 15, where that read is a primary input), it only caps a pass at warn while the domain probe from the list record still runs |
| 17 | Audit logging active and queryable | audit_monitoring | `MULESOFT-AUD-17` | `audit_query`, `audit_query_fallback`; evidence only: `audit_platforms`, `audit_retention_settings` | pass: entries within `audit_lookback_hours` (default 24); warn: entries only within 7 days; fail: zero entries in 7 days; manual: the audit query was forbidden or failed. The organization's audit log retention period (`retention_period_days`, plus any scheduled change) is read from `GET /audit/v2/organizations/{orgId}/retentionSettings` and recorded in the summary and evidence; it does not change the verdict, and an unreadable retention read is named in the summary instead. Partial view: business group scope |
| 18 | Connected apps use minimum scopes | identity_access | `MULESOFT-IAM-18` | `connected_applications`, `connected_app_scopes` | fail: client credentials app holds `full`, admin, owner, or manage scopes; warn: user-delegated app requests `full` or more than `max_connected_app_scopes`; manual: zero connected apps, or a per-app scope read that failed; pass: scopes read for every app with no administrative scopes. The inventory is requested with `hide_managed=false`, so MuleSoft-managed connected apps are included and the server `total` covers them. Partial view: connected app list truncated, or scope lists truncated for named apps |
| 19 | Stale connected apps reviewed | identity_access | `MULESOFT-IAM-19` | `connected_applications` | warn: unused for `stale_connected_app_days` (default 90), disabled, or without a `last_used` timestamp; manual: zero connected apps; pass: every app used within the window. In practice this control warns on Anypoint Platform: the published `listOrganizationConnectedApplications` schema carries no `last_used`, `lastUsed`, `last_used_at`, or `usage` field even with `includeUsage=true` (the portal exposes last-used only in the per-user `/connectedApplications/authorizations` view), so the summary states that the missing timestamps are expected and asks for the usage review to be recorded manually. Partial view: connected app list truncated |
| 20 | Exchange assets follow governance review | api_gateway | `MULESOFT-API-20` | `exchange_assets` | warn: assets published to the public portal; manual otherwise, including zero assets (export the API Governance conformance report and publishing settings). Partial view: asset search truncated |
| 21 | Anypoint MQ access restricted by environment | runtime_infrastructure | `MULESOFT-RT-21` | `environments`, `mq_regions`, `mq_queues`; secondary `mq_clients` | warn: unencrypted queues; manual: zero MQ regions (not applicable), the client list unread (`Could not confirm`, with `mq_clients[].clients` `null` and the summary stating an unread number of client apps), or inventory returned (confirm client apps are not shared across environments); never pass. Partial view: environments excluded |
| 22 | Secrets Manager used for sensitive configuration | runtime_infrastructure | `MULESOFT-RT-22` | `environments`, `cloudhub_applications`, `secret_groups` | fail: sensitive-looking CloudHub properties not marked secure; warn: production environment without secret groups, or applications without a `properties` object; manual: zero applications or no production environment sampled; pass otherwise. Partial view: as control 10 |
| 23 | Hybrid runtime servers registered and reporting | runtime_infrastructure | `MULESOFT-RT-23` | `environments`, `hybrid_servers` | fail: all servers disconnected; warn: some not `RUNNING`; manual: zero servers registered (not applicable); pass otherwise. Partial view: environments excluded |
| 24 | Alerts configured for production applications | audit_monitoring | `MULESOFT-AUD-24` | `environments`, `alerts`, `cloudhub_applications` | fail: production environment with no enabled CloudHub or Runtime Manager alert; warn: alerts without an `enabled` flag or applications not covered; manual: no production environment sampled or zero production applications; pass: `enabled=true` alerts cover every sampled production application. Partial view: environments excluded |
| 25 | Business groups separate tenants | identity_access | `MULESOFT-IAM-25` | `organization_hierarchy`; secondary `organization` | pass: business groups exist and `entitlements.createSubOrgs` is true; warn: the entitlement flag was not exposed; manual: the organization is itself a business group (`isRoot=false`; this control's own verdict, checked before the pass and warn conditions, so the general business-group rule below never applies to it), zero business groups, the entitlement is false (not applicable), or the hierarchy is unread |

Every assessment reads `GET /accounts/api/organizations/{orgId}/hierarchy` and adds a partial-view note (a would-be pass becomes `warn`) when the configured organization is a business group (`isRoot=false`), because root organization administrators, role groups, environments, connected apps, VPCs, dedicated load balancers, Exchange assets, and audit entries of the root and sibling groups are outside the view. Control 25 is the one exception: the tenant structure it judges is the root organization's, which a business group cannot see at all, so it renders `manual` in that case and there is no would-be pass for the note to demote. Root scope is only established by `isRoot=true` on a readable hierarchy: a forbidden hierarchy read or a response without the flag also records the scope as unknown instead of assuming the root organization.

## Framework mappings

Every finding carries the eight mappings from the spec's compliance table as `mappings` strings such as `FedRAMP IA-2(1)`, `CMMC L2 3.5.3`, `SOC 2 CC6.1`, `CIS 16.2`, `PCI-DSS 8.4.1`, `DISA STIG SRG-APP-000148`, `IRAP ISM-1546`, and `ISMAP CPS-7.1`. The bundle writes one report per framework under `compliance/` and a unified matrix with every mapping side by side.

## Live smoke test

```bash
ANYPOINT_ORG_ID=... ANYPOINT_CLIENT_ID=... ANYPOINT_CLIENT_SECRET=... npm --prefix cli run test:mulesoft:live
```

The script exits 0 with a skip message when no credentials are present. With credentials it runs `mulesoft_check_access` and the identity and access assessment against the real organization.

## Limitations and manual controls

- Organization-wide MFA enforcement is not exposed by the Access Management API; control 2 only fails when MFA-exempt users exist and is otherwise manual.
- Client secret rotation dates (control 9) and Exchange governance approvals (control 20) are not exposed by any public API; both are manual with the exact evidence to collect.
- Connected app last-used timestamps (control 19) are not part of the organization-level connected apps response, so control 19 warns in practice and never passes without a timestamp; the tool still reads `last_used` variants when a tenant returns them.
- Anypoint Monitoring advanced alerts have no published public API, so control 24 uses CloudHub alerts (`/cloudhub/api/v2/alerts`) and Runtime Manager alerts (`/hybrid/api/v1/alerts`) and asks for Anypoint Monitoring exports as manual evidence.
- The dedicated load balancer API does not return certificate validity, so control 16 performs a live TLS handshake with `node:tls` against each DLB domain, once per SSL endpoint with the endpoint's `publicKeyCN` as the SNI name. The handshake deliberately runs with `rejectUnauthorized: false` so that a certificate with a self-signed, private-CA, or incomplete chain can still be read and dated; certificate verification is therefore off for the connection itself, and instead `socket.authorized` and `socket.authorizationError` are recorded per certificate as `authorized` and `authorization_error`. A chain that does not validate against the auditor host's trust store caps the verdict at warn. Hosts that cannot be probed from the auditor are reported as undated and yield warn, or manual when no certificate could be probed at all.
- CloudHub 2.0 private spaces and Runtime Fabric are not inventoried; controls 13 and 14 become manual when no Anypoint VPC is visible.
- Secure CloudHub properties are never returned in plaintext by the API; control 22 checks that sensitive-looking property keys are marked secure and that production environments have Secrets Manager secret groups.
- Every snapshot is redacted before it is written to the bundle: values under keys that name a secret (`secret`, `password`, `token`, `privateKey`, `authorization`, `apiKey`, `accessKey`, `credential`, `textKey`, `signingKey`, `community`, `hash`, VPN `presharedKey`, hybrid server `registrationKey`, and their case and separator variants) and the `value` of any `name`/`value` pair whose name matches are replaced with `[REDACTED]`; values under `url`/`uri` keys (alert and webhook targets, callback URLs) are reduced to scheme and host; and any other URL string keeps its scheme, host, and path with its userinfo and query string removed whole. Every string a snapshot, an evidence list, or a summary keeps from a Anypoint response passes the data-side pass at the collector (`collect`, the TLS probe result, and `redactSnapshot`): the client's remembered credentials in every form and every carrier (`Authorization`, `Cookie`, `Set-Cookie`, and API key headers, quoted or bare; URL userinfo and query strings, which go whole; credential-named assignments and fields; auth schemes; JWTs; PEM blocks) are removed from a description, a note, a name, or a comment; no bare-token rule runs on data, so identifiers such as `prod-us-east-2026`, a UUID, or a quoted `Content-Type` header stay. A value nested deeper than 32 levels is replaced by `[REDACTED]` at that depth rather than passed through, in the collector pass and in `redactSnapshot` alike (the payload is server-controlled). CloudHub application properties, API policy configuration, and audit log entries are projected to the fields the verdicts read.
- Error strings never quote a response body. A body without Anypoint's documented `message`, `error_description`, `error`, or `errors[0].message` field (a proxy or WAF page, whatever its content type claims, or JSON without those fields) is described as "non-JSON body (text/html, 5120 bytes)" or "JSON body without a recognized error field (...)", on every surface including the token exchange, `/accounts/login`, and the audit log query. Every error string is passed through one redaction pass when `MulesoftApiError` is constructed and again when the error is recorded, so `access_check.json`, `unreadable_sources`, `analysis/*.json` `errors` arrays, `_errors.log`, and tool results carry status, path, and shape only. The pass removes the configured client secret, password, and every token obtained whatever their shape and in their base64, base64url, URL-encoded, and JSON-escaped forms; any value inside a carrier whatever its shape (`Authorization`, `Cookie`, `Set-Cookie`, and API key headers, cookie and session assignments, URL userinfo and query pairs, the `Bearer`, `Basic`, `Digest`, `Token`, and `ApiKey` schemes, credential-named fields and assignments, SOAP credential elements, command-line flags); and bare values only when they have a real token shape (JWTs, PEM blocks, hex digests, vendor-prefixed keys, and runs of 16 or more characters with base64 symbols, scattered digits, or token casing, including a run standing after `=` under a non-credential pair name such as `theme=`). A carrier or token shape standing right after a literal JSON escape (`\n`, `\u000a`, `\/`, and the rest, as a doubly-encoded body carries them) is treated exactly as one after a real newline, tab, or space. A bare name-shaped value standing alone in prose, such as an environment name or `prod-us-east-2026`, is indistinguishable from a resource name and stays.
- Config file errors are fixed text. A file that cannot be read fails with "Unable to read MuleSoft config file <path> (<CODE>)" (the Node error code only, `ENOENT` included when `config_file`, `MULESOFT_SEC_INSPECTOR_CONFIG`, or `ANYPOINT_CONFIG_FILE` names the path; the default location is skipped when absent). The reader accepts only blank lines, `#` comments, `[table]` headers, and single-line `key = value` pairs whose value is a string closed on the same line, a single-line array, a boolean, a number, or a bare word; any other line (a value standing alone, an array of tables, a continued array or string) or a quote that does not close on its line fails with "Unable to parse MuleSoft config file: invalid TOML in <path> at line N (INVALID_TOML)". A malformed line that earlier releases skipped silently now stops the tool, and the line itself is never included, so a credential standing on it, after an unterminated quote, or inside a multi-line string is never echoed.

## Official documentation

Endpoint paths, pagination, and response fields were verified against the Anypoint Platform API specifications published on Anypoint Exchange (portal `anypoint-platform`, group `f1e97bc6-315a-4490-82a7-23abe036327a.anypoint-platform`):

- [Access Management API](https://anypoint.mulesoft.com/exchange/portals/anypoint-platform/f1e97bc6-315a-4490-82a7-23abe036327a.anypoint-platform/access-management-api/) (`/accounts/api`, `/accounts/api/v2/oauth2/token`, `/accounts/login`, `mfaVerificationExcluded`, `includeUsage`, connected app `/scopes`)
- [API Manager API](https://anypoint.mulesoft.com/exchange/portals/anypoint-platform/f1e97bc6-315a-4490-82a7-23abe036327a.anypoint-platform/api-manager-api/) (`/apimanager/api/v1/organizations/{orgId}/environments/{envId}/apis` and `/apis/{apiId}/policies`)
- [Exchange API v2](https://anypoint.mulesoft.com/exchange/portals/anypoint-platform/f1e97bc6-315a-4490-82a7-23abe036327a.anypoint-platform/exchange-experience-api/) (`/exchange/api/v2/assets/search` with `limit` and `offset`)
- [CloudHub API](https://anypoint.mulesoft.com/exchange/portals/anypoint-platform/f1e97bc6-315a-4490-82a7-23abe036327a.anypoint-platform/cloudhub-api/) (`/cloudhub/api/v2/applications`, `/cloudhub/api/v2/alerts`, `/cloudhub/api/organizations/{orgId}/vpcs`, `/cloudhub/api/organizations/{orgId}/loadbalancers`, `X-ANYPNT-ENV-ID`)
- [ARM REST Services](https://anypoint.mulesoft.com/exchange/portals/anypoint-platform/f1e97bc6-315a-4490-82a7-23abe036327a.anypoint-platform/arm-rest-services/) (`/hybrid/api/v1/servers`, `/hybrid/api/v1/alerts` with `X-ANYPNT-ENV-ID` and `X-ANYPNT-ORG-ID`)
- [Audit Log Query API](https://anypoint.mulesoft.com/exchange/portals/anypoint-platform/f1e97bc6-315a-4490-82a7-23abe036327a.anypoint-platform/audit-log-query-api/) (`POST /audit/v2/organizations/{orgId}/query`, `GET /audit/v2/organizations/{orgId}/platforms`, `GET /audit/v2/organizations/{orgId}/retentionSettings`) and [Configure Audit Log Retention](https://docs.mulesoft.com/access-management/audit-log-retention)
- [Anypoint MQ Admin API](https://anypoint.mulesoft.com/exchange/portals/anypoint-platform/f1e97bc6-315a-4490-82a7-23abe036327a.anypoint-platform/anypoint-mq-admin/) (`/mq/admin/api/v1/organizations/{orgId}/environments/{envId}/regions`, `/regions/{regionId}/destinations/queues`, `/clients`)
- [Secrets Manager API](https://anypoint.mulesoft.com/exchange/portals/anypoint-platform/f1e97bc6-315a-4490-82a7-23abe036327a.anypoint-platform/secrets-manager/) (`/secrets-manager/api/v1/organizations/{orgId}/environments/{envId}/secretGroups`)

Product documentation used for control semantics and permissions:

- [Connected Apps for Developers](https://docs.mulesoft.com/access-management/connected-apps-developers) and [Configuring Identity Management](https://docs.mulesoft.com/access-management/external-identity)
- [Multi-Factor Authentication](https://docs.mulesoft.com/access-management/multi-factor-authentication)
- [Roles](https://docs.mulesoft.com/access-management/roles), [Environments](https://docs.mulesoft.com/access-management/environments), and [Business Groups](https://docs.mulesoft.com/access-management/business-groups)
- [Audit Logging](https://docs.mulesoft.com/access-management/audit-logging)
- [Control Plane Hostnames](https://docs.mulesoft.com/control-planes/control-plane-hostnames-allowlists) and [MuleSoft Government Cloud](https://docs.mulesoft.com/gov-cloud/)
- [Included Policies Directory](https://docs.mulesoft.com/gateway/latest/policies-included-directory), [Client ID Enforcement](https://docs.mulesoft.com/gateway/latest/policies-included-client-id-enforcement), [Rate Limiting](https://docs.mulesoft.com/gateway/latest/policies-included-rate-limiting), and [Client Applications, Contracts, and Credentials](https://docs.mulesoft.com/api-manager/latest/api-contracts-landing-page)
- [Exchange API](https://docs.mulesoft.com/exchange/exchange-api) and [Asset Lifecycle States](https://docs.mulesoft.com/exchange/lifecycle)
- [CloudHub Runtime Continuous Updates](https://docs.mulesoft.com/cloudhub/cloudhub-app-runtime-version-updates), [Manage Queues](https://docs.mulesoft.com/cloudhub/managing-queues), [Safely Hide Application Properties](https://docs.mulesoft.com/cloudhub/secure-application-properties), and [Custom Application Alerts](https://docs.mulesoft.com/cloudhub/custom-application-alerts)
- [VPC Firewall Rules](https://docs.mulesoft.com/cloudhub/vpc-firewall-rules-concept), [Dedicated Load Balancers](https://docs.mulesoft.com/cloudhub/cloudhub-dedicated-load-balancer), [SSL Endpoints and Certificates](https://docs.mulesoft.com/cloudhub/lb-ssl-endpoints), and [Certificate Validation and Cipher Suites](https://docs.mulesoft.com/cloudhub/lb-cert-validation) (`defaultCipherSuite`, `/loadbalancers/ciphersuites`)
- [Servers, Server Groups, and Clusters](https://docs.mulesoft.com/runtime-manager/managing-servers) and [Runtime Manager Alerts](https://docs.mulesoft.com/runtime-manager/alerts-on-runtime-manager)
- [Anypoint Monitoring Alerts](https://docs.mulesoft.com/monitoring/alerts-hf)
- [Anypoint MQ Access Management](https://docs.mulesoft.com/mq/mq-access-management)
- [Secret Groups](https://docs.mulesoft.com/anypoint-security/asm-secret-group-concept)
