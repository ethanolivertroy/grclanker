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
- Tokens are held in memory only and refreshed before `expires_in` elapses. Secrets, bearer tokens, and secret-bearing response fields (`client_secret`, `clientSecret`, `password`, tokens) are redacted from errors, tool output, and bundle snapshots.

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
| Audit log platforms and queries | Access Management: Audit Log Viewer |
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
| `mulesoft_export_audit_bundle` | Runs the access check and all four assessments and writes a bundle plus `.zip` under `output_dir` (default `./export/mulesoft`). |

All tools accept the authentication arguments above. Assessment tools also accept thresholds such as `max_admins`, `max_roles_per_group`, `max_connected_app_scopes`, `stale_connected_app_days`, `environment_limit`, `api_limit`, `application_limit`, `runtime_support_warning_days`, `certificate_warning_days`, and `audit_lookback_hours`. Environments are sampled production first, so a low `environment_limit` still covers production.

Each finding has the shape `{ id, control, title, severity, status, summary, evidence, mappings }` where `severity` is `critical`, `high`, `medium`, `low`, or `info` and `status` is `pass`, `warn`, `fail`, or `manual`. A `manual` finding states exactly what evidence a human must collect from Anypoint Platform. When a read failed or the credential saw only part of the inventory, `evidence.unreadable_sources` and `evidence.partial_view` list the causes.

### Verdict safety

Every finding follows the same rules so that missing or partial evidence never produces a `pass`:

- An unreadable, forbidden (401/403), or errored primary source yields `manual` with a summary that starts `Could not evaluate:`, names the source and HTTP cause, and states the evidence to collect. A failed secondary source turns a would-be pass into `manual` with `Could not confirm:`.
- An empty inventory never passes by default. Each control states whether emptiness is `fail` (no identity provider, zero audit events in 7 days, a production environment with no alerts) or `manual` (zero role groups, environments, connected apps, API instances, applications, VPCs, or Exchange assets).
- Controls that do not apply (no dedicated load balancer, no Anypoint MQ region, no hybrid server, no persistent queues, `createSubOrgs` entitlement false) and endpoints that return 404 on the control plane render as `manual` with a not-applicable or unavailable summary.
- Items without a date (connected apps without `last_used`, applications without `endOfSupportDate` or a runtime version, certificates without `validTo`) are reported in their own bucket and yield at most `warn`.
- A partial view (environment filter or `environment_limit` that excludes environments, `api_limit` or `application_limit` caps, truncated pages, a credential scoped to a business group) is recorded with seen and total counts, and a would-be pass becomes `warn` with a `Partial view:` prefix.
- Verdicts read the documented flags they depend on (`isFederated`, `allow_new_non_sso_users`, `mfaVerificationExcluded`, policy `disabled`, `tlsv1`, `httpMode` and `defaultCipherSuite`, `persistentQueuesEncrypted`, property `secure`, alert `enabled`, `entitlements.createSubOrgs`, hierarchy `isRoot`); an absent flag never supports `pass`.
- Pagination runs to the requested limit and every list reports whether it was truncated; a first page is never treated as the whole population.
- Re-running the export allocates a new directory and derives the `.zip` name from it, so no prior bundle or archive is overwritten.

### Bundle layout

```text
<org>-audit-bundle/
  metadata.json
  QUICK_REFERENCE.md
  _errors.log                         (only when some reads failed)
  core_data/                          raw API snapshots, secrets redacted
  analysis/findings.json              all 25 findings
  analysis/summary.json               status counts per category
  analysis/<category>.json            summary, findings, and errors per assessment
  compliance/executive_summary.md
  compliance/unified_compliance_matrix.md
  compliance/<framework>/<framework>_compliance_report.md   (fedramp, cmmc, soc2, cis, pci_dss, disa_stig, irap, ismap)
<org>-audit-bundle.zip
```

Output paths are resolved inside `output_dir`; traversal outside the root and symlinked parent directories are rejected, and files are written with `0600` permissions.

## Control coverage

| # | Spec control | Tool | Finding | Status semantics |
| --- | --- | --- | --- | --- |
| 1 | SSO/SAML or OIDC external identity provider configured | identity_access | `MULESOFT-IAM-01` | fail: zero identity providers, or every provider disabled; warn: `isFederated` absent or false, `allow_new_non_sso_users` not exposed, or new non-SSO users allowed; pass: an active provider, `isFederated=true`, and non-SSO user creation disabled |
| 2 | MFA enforced for all organization members | identity_access | `MULESOFT-IAM-02` | fail: users listed with `mfaVerificationExcluded=true`; warn: the exemption query returned users without the flag; manual: zero exemptions (the organization-wide MFA setting is not exposed, so capture it or the IdP MFA policy) |
| 3 | Organization Administrator membership minimized | identity_access | `MULESOFT-IAM-03` | fail: distinct members of admin role groups above `max_admins` (default 5); manual: zero role groups or no admin role group visible; pass: within the threshold |
| 4 | Role groups follow least privilege | identity_access | `MULESOFT-IAM-04` | fail: custom role group grants Organization Administrator or Owner; warn: more than `max_roles_per_group` roles; manual: zero role groups; pass otherwise |
| 5 | Role groups scoped to specific environments | identity_access | `MULESOFT-IAM-05` | fail: more than 5 org-wide environment roles; warn: 1-5; manual: zero role groups or zero environment-level assignments; pass: every environment-level role carries `context_params.envId` |
| 6 | Production and sandbox environments isolated | identity_access | `MULESOFT-IAM-06` | fail: environment names contradict their type; warn: environments without `isProduction` or `type`, or no production or no sandbox environment; manual: zero environments; pass otherwise |
| 7 | Authentication policies on production APIs | api_gateway | `MULESOFT-API-07` | fail: a production API instance has no enabled authentication policy; warn: a matching policy whose `disabled` flag was not returned, or only non-production instances lack one; manual: zero API instances or no production instance sampled; pass: `disabled=false` confirmed on every instance |
| 8 | Rate limiting policies applied | api_gateway | `MULESOFT-API-08` | fail: production instance without an enabled rate limiting or spike control policy; warn: unknown `disabled` state or non-production only; manual: zero instances or no production instance sampled; pass: `disabled=false` confirmed on every instance |
| 9 | Client credentials rotated within policy period | api_gateway | `MULESOFT-API-09` | manual: the API does not expose secret rotation timestamps; the summary names the HTTP cause when the contract inventory could not be read |
| 10 | Supported Mule runtime versions | runtime_infrastructure | `MULESOFT-RT-10` | fail: Mule 3 or `endOfSupportDate` in the past; warn: end of support within `runtime_support_warning_days`, or the version or end of support date not exposed; manual: zero CloudHub applications; pass otherwise |
| 11 | Worker sizing reviewed | runtime_infrastructure | `MULESOFT-RT-11` | warn: multiple or large workers in non-production, four or more workers with CPU under 10 percent (applications are listed with `retrieveStatistics=true` so `workers.recentStatistics.cpu` is populated), worker data missing, or four or more workers without CPU statistics; manual: zero applications; pass otherwise |
| 12 | Persistent queues encrypted | runtime_infrastructure | `MULESOFT-RT-12` | fail: `persistentQueues` enabled without `persistentQueuesEncrypted=true`; manual: zero applications or no application enables persistent queues (not applicable); pass: encryption confirmed on every queue-enabled application |
| 13 | VPC firewall rules restrictive | runtime_infrastructure | `MULESOFT-RT-13` | fail: rule allows all protocols; warn: wide port ranges or CIDR broader than /16; manual: zero VPCs or a VPC without a `firewallRules` list; pass otherwise |
| 14 | No 0.0.0.0/0 VPC ingress | runtime_infrastructure | `MULESOFT-RT-14` | fail: open ingress on any port other than 8081 and 8082, including the DLB back-end ports 8091 and 8092 that CloudHub scopes to the VPC CIDR by default; warn: open ingress only on 8081 or 8082, the ports the shared load balancer exposes; manual: zero VPCs or a VPC without a `firewallRules` list; pass otherwise |
| 15 | DLB enforces TLS 1.2+ and strong cipher suites | runtime_infrastructure | `MULESOFT-RT-15` | fail: `tlsv1=true`, or `defaultCipherSuite` offers RC4, DES/3DES, NULL, EXPORT, MD5, anonymous, or other weak ciphers; warn: `httpMode` is `on`, the `tlsv1` or `httpMode` flags were not returned, `defaultCipherSuite` was not returned, or the suite includes non-forward-secret (static RSA) ciphers or broad OpenSSL groups such as `HIGH` (the documented OldDefault set); manual: no dedicated load balancer (not applicable) or the per-DLB detail read failed; pass: `tlsv1=false`, no plain HTTP, and a suite limited to ECDHE/DHE ciphers. `defaultCipherSuite` is read from the list (`shortFormat=false`) or, when absent, from `GET /cloudhub/api/organizations/{orgId}/vpcs/{vpcId}/loadbalancers/{dlbId}` |
| 16 | DLB certificates valid beyond 30 days | runtime_infrastructure | `MULESOFT-RT-16` | fail: live TLS probe shows expiry within 30 days; warn: within `certificate_warning_days` (default 60), a certificate that could not be dated, or a dated certificate whose chain did not validate against the auditor's trust store (`authorized=false`, or validation not reported); manual: no dedicated load balancer or no certificate could be probed; pass: every certificate dated, chain validated, and beyond the warning window. One probe runs per `sslEndpoints` entry using its `publicKeyCN` (or a concrete SAN) as the SNI name, so counts are per certificate, not per load balancer |
| 17 | Audit logging active and queryable | audit_monitoring | `MULESOFT-AUD-17` | pass: entries within `audit_lookback_hours` (default 24); warn: entries only within 7 days; fail: zero entries in 7 days; manual: the audit query was forbidden or failed |
| 18 | Connected apps use minimum scopes | identity_access | `MULESOFT-IAM-18` | fail: client credentials app holds `full`, admin, owner, or manage scopes; warn: user-delegated app requests `full` or more than `max_connected_app_scopes`; manual: zero connected apps; pass: scopes read for every app with no administrative scopes. The inventory is requested with `hide_managed=false`, so MuleSoft-managed connected apps are included and the server `total` covers them |
| 19 | Stale connected apps reviewed | identity_access | `MULESOFT-IAM-19` | warn: unused for `stale_connected_app_days` (default 90), disabled, or without a `last_used` timestamp; manual: zero connected apps; pass: every app used within the window |
| 20 | Exchange assets follow governance review | api_gateway | `MULESOFT-API-20` | warn: assets published to the public portal; manual otherwise, including zero assets (export the API Governance conformance report and publishing settings) |
| 21 | Anypoint MQ access restricted by environment | runtime_infrastructure | `MULESOFT-RT-21` | warn: unencrypted queues; manual: zero MQ regions (not applicable) or inventory returned (confirm client apps are not shared across environments); never pass |
| 22 | Secrets Manager used for sensitive configuration | runtime_infrastructure | `MULESOFT-RT-22` | fail: sensitive-looking CloudHub properties not marked secure; warn: production environment without secret groups, or applications without a `properties` object; manual: zero applications or no production environment sampled; pass otherwise |
| 23 | Hybrid runtime servers registered and reporting | runtime_infrastructure | `MULESOFT-RT-23` | fail: all servers disconnected; warn: some not `RUNNING`; manual: zero servers registered (not applicable); pass otherwise |
| 24 | Alerts configured for production applications | audit_monitoring | `MULESOFT-AUD-24` | fail: production environment with no enabled CloudHub or Runtime Manager alert; warn: alerts without an `enabled` flag or applications not covered; manual: no production environment sampled or zero production applications; pass: `enabled=true` alerts cover every sampled production application |
| 25 | Business groups separate tenants | identity_access | `MULESOFT-IAM-25` | pass: business groups exist and `entitlements.createSubOrgs` is true; warn: the entitlement flag was not exposed; manual: the organization is itself a business group (`isRoot=false`), zero business groups, or the entitlement is false (not applicable) |

Every assessment reads `GET /accounts/api/organizations/{orgId}/hierarchy` and adds a partial-view note (a would-be pass becomes `warn`) when the configured organization is a business group (`isRoot=false`), because root organization administrators, role groups, environments, connected apps, VPCs, dedicated load balancers, Exchange assets, and audit entries of the root and sibling groups are outside the view. Root scope is only established by `isRoot=true` on a readable hierarchy: a forbidden hierarchy read or a response without the flag also records the scope as unknown instead of assuming the root organization.

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
- Anypoint Monitoring advanced alerts have no published public API, so control 24 uses CloudHub alerts (`/cloudhub/api/v2/alerts`) and Runtime Manager alerts (`/hybrid/api/v1/alerts`) and asks for Anypoint Monitoring exports as manual evidence.
- The dedicated load balancer API does not return certificate validity, so control 16 performs a live TLS handshake with `node:tls` against each DLB domain, once per SSL endpoint with the endpoint's `publicKeyCN` as the SNI name. The handshake deliberately runs with `rejectUnauthorized: false` so that a certificate with a self-signed, private-CA, or incomplete chain can still be read and dated; certificate verification is therefore off for the connection itself, and instead `socket.authorized` and `socket.authorizationError` are recorded per certificate as `authorized` and `authorization_error`. A chain that does not validate against the auditor host's trust store caps the verdict at warn. Hosts that cannot be probed from the auditor are reported as undated and yield warn, or manual when no certificate could be probed at all.
- CloudHub 2.0 private spaces and Runtime Fabric are not inventoried; controls 13 and 14 become manual when no Anypoint VPC is visible.
- Secure CloudHub properties are never returned in plaintext by the API; control 22 checks that sensitive-looking property keys are marked secure and that production environments have Secrets Manager secret groups.
- Anypoint MQ client secrets and connected app secrets are redacted before they are written to the bundle.

## Official documentation

Endpoint paths, pagination, and response fields were verified against the Anypoint Platform API specifications published on Anypoint Exchange (portal `anypoint-platform`, group `f1e97bc6-315a-4490-82a7-23abe036327a.anypoint-platform`):

- [Access Management API](https://anypoint.mulesoft.com/exchange/portals/anypoint-platform/f1e97bc6-315a-4490-82a7-23abe036327a.anypoint-platform/access-management-api/) (`/accounts/api`, `/accounts/api/v2/oauth2/token`, `/accounts/login`, `mfaVerificationExcluded`, `includeUsage`, connected app `/scopes`)
- [API Manager API](https://anypoint.mulesoft.com/exchange/portals/anypoint-platform/f1e97bc6-315a-4490-82a7-23abe036327a.anypoint-platform/api-manager-api/) (`/apimanager/api/v1/organizations/{orgId}/environments/{envId}/apis` and `/apis/{apiId}/policies`)
- [Exchange API v2](https://anypoint.mulesoft.com/exchange/portals/anypoint-platform/f1e97bc6-315a-4490-82a7-23abe036327a.anypoint-platform/exchange-experience-api/) (`/exchange/api/v2/assets/search` with `limit` and `offset`)
- [CloudHub API](https://anypoint.mulesoft.com/exchange/portals/anypoint-platform/f1e97bc6-315a-4490-82a7-23abe036327a.anypoint-platform/cloudhub-api/) (`/cloudhub/api/v2/applications`, `/cloudhub/api/v2/alerts`, `/cloudhub/api/organizations/{orgId}/vpcs`, `/cloudhub/api/organizations/{orgId}/loadbalancers`, `X-ANYPNT-ENV-ID`)
- [ARM REST Services](https://anypoint.mulesoft.com/exchange/portals/anypoint-platform/f1e97bc6-315a-4490-82a7-23abe036327a.anypoint-platform/arm-rest-services/) (`/hybrid/api/v1/servers`, `/hybrid/api/v1/alerts` with `X-ANYPNT-ENV-ID` and `X-ANYPNT-ORG-ID`)
- [Audit Log Query API](https://anypoint.mulesoft.com/exchange/portals/anypoint-platform/f1e97bc6-315a-4490-82a7-23abe036327a.anypoint-platform/audit-log-query-api/) (`POST /audit/v2/organizations/{orgId}/query`, `GET /audit/v2/organizations/{orgId}/platforms`)
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
