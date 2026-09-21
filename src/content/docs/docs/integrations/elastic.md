---
title: Elastic
description: Read-only Elasticsearch and Kibana security posture assessment mapped to FedRAMP, CMMC, SOC 2, CIS, PCI-DSS, STIG, IRAP, and ISMAP.
---

The Elastic integration inspects Elasticsearch and Kibana security configuration through their public REST APIs. It never writes to the cluster or to Kibana: every tool uses read-only endpoints (the only POST requests are the documented query and privilege-check endpoints). Findings implement the 23 numbered controls in `specs/elastic-sec-inspector.spec.md` and carry that spec's compliance mappings.

## What it inspects

- Authentication realms (native, file, LDAP, Active Directory, PKI, SAML, Kerberos, OIDC, JWT) and anonymous access
- SAML and OIDC attribute mapping plus the role mappings that assign roles to SSO users
- API key inventory, expiration, age, and privilege scope (including owner `limited_by` privileges)
- Roles, users, and role mappings for superuser overuse and overly permissive privileges, plus field-level and document-level security coverage
- Transport and HTTP layer TLS, minimum protocol versions, and certificate expiration
- Audit logging, its event include list, and its output destination
- ILM retention, snapshot repositories and SLM policies, cluster security settings, Watcher actions, Kibana connectors, and ingest pipelines
- License tier coverage of the security features in use
- Kibana spaces, Kibana roles, and Fleet agent policies, outputs, Fleet Server hosts, and enrollment keys
- Elastic Cloud deployment inventory when a Cloud API key is supplied (optional)

## Setup and authentication

Configuration resolves with the precedence explicit tool arguments, then environment variables, then the config file. A higher-precedence source that supplies credentials replaces credentials of a different type from a lower-precedence source, so passing `username` and `password` to a tool wins over `ELASTIC_API_KEY` in the environment.

| Environment variable | Purpose |
|----------------------|---------|
| `ELASTIC_URL` (or `ELASTICSEARCH_URL`) | Elasticsearch base URL, for example `https://es.example.com:9200` or `https://<deployment>.es.<region>.cloud.es.io:9243` |
| `ELASTIC_API_KEY` | API key as `base64(id:api_key)`; an `id:api_key` pair is encoded automatically (sent as `Authorization: ApiKey ...`) |
| `ELASTIC_USERNAME`, `ELASTIC_PASSWORD` | Basic authentication (sent as `Authorization: Basic ...`) |
| `ELASTIC_BEARER_TOKEN` | OAuth2, SAML, or OIDC access token (sent as `Authorization: Bearer ...`) |
| `KIBANA_URL` | Kibana base URL. Kibana controls become `manual` findings when omitted |
| `KIBANA_SPACE_ID` | Kibana space for space-aware paths (`/s/{space}/api/...`); omit for the default space |
| `ELASTIC_CLOUD_API_KEY` | Elastic Cloud API key for deployment inventory (optional) |
| `ELASTIC_CLOUD_API_URL` | Elastic Cloud API base URL, default `https://api.elastic-cloud.com` |
| `ELASTIC_TIMEOUT` | HTTP timeout in seconds, default 30 |
| `ELASTIC_SEC_INSPECTOR_CONFIG` | Path to a YAML config file, default `~/.elastic-sec-inspector/config.yaml` |

The same Elasticsearch credential is sent to Kibana, which accepts Elasticsearch API keys and basic credentials. Every Kibana request carries the `kbn-xsrf: true` header. Kibana enforces that header on non-GET requests for basic authentication, and the integration only issues GET requests to Kibana, so the header is included for consistency across authentication schemes.

Config file example (`~/.elastic-sec-inspector/config.yaml`):

```yaml
url: https://es.example.com:9200
api_key: base64-encoded-id:key
kibana:
  url: https://kibana.example.com:5601
  space_id: default
cloud:
  api_key: optional-cloud-api-key
timeout: 30
```

Flat keys such as `kibana_url`, `space_id`, `username`, `password`, `bearer_token`, and `cloud_api_key` are also accepted.

### Required privileges

Create a dedicated read-only auditing role. `elastic_check_access` probes these privileges with `POST /_security/user/_has_privileges` and lists any that are missing.

| Cluster privilege | Surfaces it unlocks |
|-------------------|---------------------|
| `monitor` | `/_cluster/settings`, `/_nodes/settings`, `/_ssl/certificates`, `/_license`, `/_xpack`, `/_xpack/usage` |
| `read_security` (or `manage_security`) | `/_security/user`, `/_security/role`, `/_security/role_mapping`, `/_security/_query/api_key` |
| `manage_api_key` | `with_limited_by=true` on the query API keys endpoint, which exposes owner privileges for keys that inherit them |
| `read_pipeline` (or `manage_pipeline`) | `/_ingest/pipeline` |
| `monitor_snapshot` | `/_snapshot/_all` |
| `read_ilm` (or `manage_ilm`) | `/_ilm/status`, `/_ilm/policy` |
| `read_slm` (or `manage_slm`) | `/_slm/status`, `/_slm/policy` |
| `monitor_watcher` | `/_watcher/_query/watches` |

For Kibana, grant read access to the Spaces, Fleet, Security (detection rules), Stack Management (alerting rules, connectors, roles), and Stack Monitoring features across the spaces you intend to audit. Elastic Cloud deployment inventory needs an organization-level Cloud API key with viewer access.

## Tools

| Tool | Purpose |
|------|---------|
| `elastic_check_access` | Probe every read surface (29 endpoints across Elasticsearch, Kibana, and Elastic Cloud), report readable, not readable, and not configured surfaces, and list missing cluster and index privileges |
| `elastic_assess_identity` | Controls 1, 9, 10, 13, 14: realms, API key hygiene and scope, SSO mapping, anonymous access |
| `elastic_assess_access_control` | Controls 6, 7, 8: roles and users, field-level security, document-level security |
| `elastic_assess_transport_security` | Controls 2, 3, 4, 5: transport TLS, HTTP TLS, minimum TLS version, certificate expiration |
| `elastic_assess_cluster_hardening` | Controls 11, 12, 17, 18, 19, 20, 22, 23: audit logging and output, ILM, snapshots, cluster security settings, Watcher and alerting, ingest pipelines, license |
| `elastic_assess_kibana` | Controls 15, 16, 21: Kibana spaces, Kibana roles, Fleet |
| `elastic_export_audit_bundle` | Run every assessment and write `core_data/`, `analysis/`, `compliance/`, `QUICK_REFERENCE.md`, `_errors.log` on partial failure, and a `.zip` |

All tools accept the connection arguments (`elasticsearch_url`, `kibana_url`, `space_id`, `api_key`, `username`, `password`, `bearer_token`, `cloud_api_key`, `cloud_api_url`, `config_file`, `timeout_seconds`). Assessment tools add thresholds: `api_key_limit`, `max_api_key_age_days` (90), `max_superusers` (2), `sensitive_index_patterns`, `tenant_index_patterns`, `cert_expiry_warning_days` (30), `watch_limit`, `kibana_limit`, and `max_enrollment_keys_per_policy` (3). The export tool adds `output_dir` (default `./export/elastic`).

Example prompts:

```text
Check whether my Elastic auditing key can read everything grclanker needs.
Assess Elastic access control with sensitive_index_patterns customers-* and tenant_index_patterns tenant-*.
Export an Elastic audit bundle to ./export/elastic.
```

## Control coverage

Status semantics: `pass` means API evidence shows the control is satisfied, `warn` means it is partially satisfied or not fully confirmable from the visible data, `fail` means API evidence shows a violation, and `manual` means the API cannot verify it and the summary states exactly what evidence a human must collect.

Every verdict follows the same evidence rules, so a `pass` is never produced from missing or partial data:

- A forbidden (401/403), timed out, or errored source endpoint yields `manual`; the summary names the endpoint and error and lists what to collect. Observed violations still `fail` (for example too many superusers) even when a secondary source is unreadable.
- An empty inventory never passes by default. Each control states how emptiness is judged: zero users, roles, spaces, certificates, or ingest pipelines is `manual` because Elasticsearch and Kibana always return built-in entries; zero ILM policies, repositories, or SLM policies is `fail`; zero role mappings for an SSO realm is `fail`; zero Fleet policies is `manual` (not applicable); zero API keys passes only because controls 9 and 10 concern existing keys, and only with full inventory visibility.
- Controls that are scoped out (Kibana not configured), disabled by configuration (no SSO realm), or unavailable on the license tier (FLS, DLS, Watcher on Basic) render as `manual` with a "Not applicable" or "Scoped out" summary. Features in use without a covering license `fail`.
- Items without a date (API keys with no `creation`, certificates with no `expiry`, SLM policies with no `last_success`, a license with no expiry or status) are bucketed separately, reported in the evidence, and cap the verdict at `warn`.
- Partial inventories cap the verdict at `warn` or `manual` and report seen and total counts: an API key query limited to the caller's own keys (no `read_security`, `manage_api_key`, or `manage_security`), a truncated page set, node settings from only some nodes, `GET /_ssl/certificates` on a multi-node cluster (it reports only the responding node), and Kibana inventories read from a single space when other spaces exist.
- Every enabling flag is read before a `pass`: `xpack.security.enabled`, `xpack.security.transport.ssl.enabled` and `verification_mode`, `xpack.security.http.ssl.enabled`, `xpack.security.audit.enabled`, realm `enabled` flags, anonymous role settings, and license type and status. An absent or false flag never supports `pass`, and settings resolve as transient over persistent over node-level over cluster defaults.
- Pagination runs to the configured limit; when the total exceeds what was read, the dataset is marked truncated and the verdict is downgraded.

| # | Control | Tool | Finding | Status semantics |
|---|---------|------|---------|------------------|
| 1 | Authentication realm configuration | `elastic_assess_identity` | `ELASTIC-01` | pass when an LDAP, Active Directory, PKI, SAML, Kerberos, OIDC, or JWT realm is enabled (disabled realms do not count); fail when only native or file realms are visible; warn when `xpack.security.enabled` is not visible or node settings cover only some nodes; manual when realm settings are unreadable |
| 2 | TLS enforcement on the transport layer | `elastic_assess_transport_security` | `ELASTIC-02` | fail when `xpack.security.transport.ssl.enabled` is false on any node or security is disabled; warn when `verification_mode` is `none`, the setting is unset (documented default false) and only usage statistics report TLS, `xpack.security.enabled` is not visible, or only some nodes responded |
| 3 | TLS enforcement on the HTTP layer | `elastic_assess_transport_security` | `ELASTIC-03` | fail when `xpack.security.http.ssl.enabled` is false or the configured URL is plain http; warn when TLS terminates upstream of an https endpoint, the security flag is not visible, or only some nodes responded |
| 4 | Minimum TLS protocol version | `elastic_assess_transport_security` | `ELASTIC-04` | fail when `supported_protocols` includes anything below TLSv1.2; warn when unset on a 7.x node, the security flag is not visible, or only some nodes responded |
| 5 | Certificate expiration | `elastic_assess_transport_security` | `ELASTIC-05` | fail when any certificate has expired; warn when one expires within `cert_expiry_warning_days`, a certificate reports no expiry date (not counted as valid), or the cluster has more nodes than the single node `GET /_ssl/certificates` reports on; manual when the certificate list is empty |
| 6 | Role-based access control | `elastic_assess_access_control` | `ELASTIC-06` | fail when superuser holders exceed `max_superusers` or users hold custom roles granting cluster `all` or index `all` on `*` (still fails when roles are unreadable); warn when such roles or mappings exist unused; manual when the user or role inventory is empty or unreadable |
| 7 | Field-level security | `elastic_assess_access_control` | `ELASTIC-07` | with `sensitive_index_patterns`, fail when a pattern has no FLS role; without patterns, warn when no role uses FLS; on a license below Platinum, fail when patterns are supplied (they cannot be protected) and otherwise manual (not applicable); manual when roles or the license are unreadable; warn when patterns are covered but the tier cannot be confirmed |
| 8 | Document-level security | `elastic_assess_access_control` | `ELASTIC-08` | same semantics as control 7 using `tenant_index_patterns` and DLS queries |
| 9 | API key management | `elastic_assess_identity` | `ELASTIC-09` | fail when non-Fleet active keys lack expiration or exceed `max_api_key_age_days`; warn when only Fleet-managed keys do, invalidated or expired keys linger, active keys report no creation date, the credential sees only its own keys, or the list is truncated (seen and total reported); zero keys passes only with full inventory visibility because the control concerns existing keys |
| 10 | API key privilege scope | `elastic_assess_identity` | `ELASTIC-10` | fail when active keys grant cluster `all` (or inherit superuser via `limited_by`); warn when `limited_by` is not visible or the inventory is partial or truncated |
| 11 | Audit logging enabled | `elastic_assess_cluster_hardening` | `ELASTIC-11` | fail when `xpack.security.audit.enabled` is not explicitly true on any inspected node (documented default false) or the license does not include audit logging; warn when disabled on some nodes, the effective include list omits `authentication_failed`, `access_denied`, or `security_config_change`, the security flag is not visible, or only some nodes responded |
| 12 | Audit log output | `elastic_assess_cluster_hardening` | `ELASTIC-12` | fail when auditing is disabled; otherwise always `manual`, because Elasticsearch only writes audit events to the local `logfile` output and forwarding cannot be observed through the API |
| 13 | SAML/OIDC SSO configuration | `elastic_assess_identity` | `ELASTIC-13` | pass when each enabled SAML or OIDC realm defines a principal attribute or claim and has enabled role mappings or authorization realms on an active Platinum or higher license; fail when a realm has zero enabled role mappings and no authorization realms, or the license does not cover SSO; warn when a realm is incomplete or the license or security flag cannot be confirmed; manual (not applicable) when no enabled SAML or OIDC realm is configured |
| 14 | Anonymous access disabled | `elastic_assess_identity` | `ELASTIC-14` | pass when no anonymous roles are configured (absence is the compliant state); fail when anonymous roles include superuser or broad privileges; warn when other roles are set, the security flag is not visible, or only some nodes responded; transient settings override persistent ones |
| 15 | Kibana space isolation | `elastic_assess_kibana` | `ELASTIC-15` | pass when multiple spaces exist and custom roles are space-scoped with no custom role granting `all` across `*`; warn when only the default space exists; manual when the space list is empty (the default space always exists) or spaces or roles are unreadable |
| 16 | Kibana role privileges | `elastic_assess_kibana` | `ELASTIC-16` | fail when a custom Kibana role grants base `all` across every space; warn when only reserved roles exist (no privilege separation was implemented); manual when roles are empty or unreadable |
| 17 | Index lifecycle policies | `elastic_assess_cluster_hardening` | `ELASTIC-17` | fail when no ILM policy exists or ILM is not `RUNNING`; warn when an in-use policy has no delete phase; manual when `GET /_ilm/status` or the policy list is unreadable |
| 18 | Snapshot encryption | `elastic_assess_cluster_hardening` | `ELASTIC-18` | fail when no repository or no SLM policy exists or SLM is not `RUNNING`; pass for GCS and Azure (platform encrypted) and S3 with `server_side_encryption`; warn when an SLM policy reports no `last_success` (not counted as a working backup); `manual` for `fs`, `hdfs`, `url`, and S3 without the setting, or when `GET /_slm/status` is unreadable |
| 19 | Cluster security settings | `elastic_assess_cluster_hardening` | `ELASTIC-19` | fail when `xpack.security.enabled` is false; warn when password hashing is not a bcrypt or pbkdf2 variant, the security flag is not visible in node settings, cluster settings, usage statistics, or xpack info, or only some nodes responded |
| 20 | Watcher and alerting security | `elastic_assess_cluster_hardening` | `ELASTIC-20` | fail when watch webhooks or Kibana connectors target plain http; warn when watch actions embed basic-auth credentials, connectors are missing secrets, a list is truncated, or connectors were read from one space while other spaces exist; manual when watches or connectors are unreadable, Kibana is scoped out, or Watcher is unlicensed and Kibana is not configured; a confirmed unlicensed Watcher is reported as not applicable and only connectors are assessed |
| 21 | Fleet agent policy security | `elastic_assess_kibana` | `ELASTIC-21` | fail when Fleet outputs or Fleet Server hosts use plain http; warn when policies lack tamper protection (`is_protected` not true), outputs pin no CA trust, active enrollment keys exceed `max_enrollment_keys_per_policy`, or the policy list is truncated; manual (not applicable) when zero policies exist in the inspected space, or when any Fleet endpoint is unreadable |
| 22 | Ingest pipeline security | `elastic_assess_cluster_hardening` | `ELASTIC-22` | fail when a custom pipeline `set` processor assigns a literal sensitive-looking value; warn when custom pipelines use `script` processors; manual when the pipeline list is empty (Elasticsearch ships managed pipelines) or unreadable |
| 23 | License level verification | `elastic_assess_cluster_hardening` | `ELASTIC-23` | fail when the license tier does not cover configured features (SAML, OIDC, Kerberos, JWT, FLS, DLS need Platinum; LDAP, AD, PKI, audit logging, Watcher need Gold), the license is not active, or no license type is returned; warn for trial, expiry within 30 days, a missing expiry date, a missing status field, or when only some nodes responded |

Because Elasticsearch never returns secure settings and the API cannot observe log shipping, control 12 is a permanent `manual` finding whenever auditing is enabled. Controls 15, 16, and 21 are `manual` when `KIBANA_URL` is not set, and control 20 cannot pass on watches alone in that case.

## Framework mappings

Every finding carries the eight mappings from the spec's compliance table for its control, for example `ELASTIC-01` maps to FedRAMP IA-2, CMMC AC.L2-3.1.1, SOC 2 CC6.1, CIS 1.1, PCI-DSS 8.3.1, STIG SRG-APP-000148, IRAP ISM-1557, and ISMAP CPS-04. The audit bundle renders them in `compliance/unified_compliance_matrix.md` and in one report per framework under `compliance/frameworks/` (`fedramp.md`, `cmmc.md`, `soc2.md`, `cis.md`, `pci-dss.md`, `stig.md`, `irap.md`, `ismap.md`).

## Audit bundle layout

```text
<host>-audit-bundle/
  QUICK_REFERENCE.md
  metadata.json
  core_data/<dataset>.json          raw API snapshots, secrets redacted
  analysis/access.json              readable surfaces and missing privileges
  analysis/findings.json            all 23 findings
  analysis/<area>.json              per-area assessment output
  compliance/executive_summary.md
  compliance/unified_compliance_matrix.md
  compliance/frameworks/<framework>.md
  _errors.log                       only when some reads failed
<host>-audit-bundle.zip
```

Output paths are resolved inside `output_dir` with traversal and symlinked-parent protection, and files are written with owner-only permissions. Re-running the export never overwrites a prior bundle: the directory name is allocated first (`<host>-audit-bundle`, then `-2` through `-9`, skipping any name whose directory or `.zip` already exists) and the archive name is derived from it, so directory and archive stay paired. Paginated datasets under `core_data/` carry a `page` block with `seen`, `total`, `pages`, and `truncated`. Fleet enrollment `api_key` values are removed and setting names that carry secrets (`password`, `bind_password`, `client_secret`, `api_key`, `token`, `private_key`, SSL `key` paths) are redacted before anything is written.

## Live smoke test

```bash
ELASTIC_URL=https://es.example.com:9200 ELASTIC_API_KEY=... KIBANA_URL=https://kibana.example.com:5601 \
  npm --prefix cli run test:elastic:live
```

The script prints a skip message and exits 0 when no credentials or config file are present. Otherwise it runs `elastic_check_access`, stops if core surfaces are unreadable, and then runs the transport security assessment. Mocked API coverage lives in `cli/tests/elastic.test.mjs` and runs with `npm --prefix cli run test:cli`.

## Limitations and manual controls

- Control 12 (audit log output) is always `manual` when auditing is enabled: collect evidence that `<cluster>_audit.json` is shipped to a tamper-resistant store.
- Control 18 is `manual` for repository types whose encryption is not visible through the API: collect bucket or filesystem encryption evidence.
- Secure settings (bind passwords, client secrets, keystore entries) are never returned by Elasticsearch, so SSO checks rely on non-secret realm settings and role mappings.
- Controls 7 and 8 report `warn` rather than `pass` when no index patterns are supplied, because the API cannot know which indices hold sensitive or tenant data.
- Cluster-level defaults come from `GET /_cluster/settings?include_defaults=true` and per-node values from `GET /_nodes/settings`; settings that differ between nodes are reported per node, and when some nodes fail to respond every settings-based verdict is capped at `warn` with the responding and total node counts.
- Without `read_security`, `manage_api_key`, or `manage_security`, `POST /_security/_query/api_key` returns only the caller's own keys; controls 9 and 10 then report a partial view and cannot pass.
- `GET /_ssl/certificates` describes only the node that served the request; on multi-node clusters control 5 is capped at `warn` until certificates from every node are collected.
- Kibana connectors, alerting rules, detection rules, and Fleet policies are read from the configured `space_id` (the default space unless set); when other spaces exist, control 20 is capped at `warn` and names the spaces still to inspect, and an empty Fleet inventory is reported for the inspected space only.
- List collection stops at `api_key_limit`, `watch_limit`, and `kibana_limit`; a truncated dataset is recorded in `core_data/` and downgrades the dependent verdicts rather than being treated as the full population.
- Elastic Cloud is used only for deployment inventory (`GET /api/v1/deployments`); the per-deployment detail and activity endpoints listed in the spec are not collected, and deployment configuration is assessed through the cluster and Kibana APIs instead.
- The integration does not evaluate CIS Elasticsearch Benchmark line items beyond the spec's 23 controls.

## Official documentation

Endpoint paths, headers, pagination parameters, and response fields were verified against these Elastic documentation pages:

- Elasticsearch authenticate: [Authenticate API](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-security-authenticate)
- Privilege probe: [Has privileges API](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-security-has-privileges)
- Users, roles, role mappings: [Get users](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-security-get-user), [Get roles](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-security-get-role), [Get role mappings](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-security-get-role-mapping)
- API keys (`search_after` pagination, `with_limited_by`): [Query API keys](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-security-query-api-keys)
- License and features: [Get license](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-license-get), [X-Pack info](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-xpack-info), [X-Pack usage](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-xpack-usage)
- Settings: [Cluster get settings](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-cluster-get-settings), [Nodes info](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-nodes-info), [Security settings reference](https://www.elastic.co/docs/reference/elasticsearch/configuration-reference/security-settings), [Auditing settings reference](https://www.elastic.co/docs/reference/elasticsearch/configuration-reference/auding-settings), [Audit events](https://www.elastic.co/docs/reference/elasticsearch/elasticsearch-audit-events)
- TLS: [SSL certificates API](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-ssl-certificates), [Secure cluster communications](https://www.elastic.co/docs/deploy-manage/security/secure-cluster-communications)
- Data lifecycle: [Get ILM status](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-ilm-get-status), [Get ILM policy](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-ilm-get-lifecycle), [Get SLM status](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-slm-get-status), [Get SLM policy](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-slm-get-lifecycle), [Get snapshot repository](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-snapshot-get-repository)
- Watcher and ingest: [Query watches](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-watcher-query-watches), [Get pipelines](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-ingest-get-pipeline)
- Kibana conventions (`kbn-xsrf`, API key and basic authentication): [Kibana APIs](https://www.elastic.co/docs/api/doc/kibana/), [Kibana general settings](https://www.elastic.co/docs/reference/kibana/configuration-reference/general-settings)
- Kibana endpoints: [Get spaces](https://www.elastic.co/docs/api/doc/kibana/operation/operation-get-spaces-space), [Get roles](https://www.elastic.co/docs/api/doc/kibana/operation/operation-get-security-role), [Get agent policies](https://www.elastic.co/docs/api/doc/kibana/operation/operation-get-fleet-agent-policies), [Get outputs](https://www.elastic.co/docs/api/doc/kibana/operation/operation-get-fleet-outputs), [Get enrollment API keys](https://www.elastic.co/docs/api/doc/kibana/operation/operation-get-fleet-enrollment-api-keys), [Get Fleet Server hosts](https://www.elastic.co/docs/api/doc/kibana/operation/operation-get-fleet-fleet-server-hosts), [Find detection rules](https://www.elastic.co/docs/api/doc/kibana/operation/operation-findrules), [Find alerting rules](https://www.elastic.co/docs/api/doc/kibana/operation/operation-get-alerting-rules-find), [Get connectors](https://www.elastic.co/docs/api/doc/kibana/operation/operation-get-actions-connectors), [Kibana status](https://www.elastic.co/docs/api/doc/kibana/operation/operation-get-status)
- Elastic Cloud: [List deployments](https://www.elastic.co/docs/api/doc/cloud/operation/operation-list-deployments)
- Credentials and privileges: [Elasticsearch API keys](https://www.elastic.co/docs/deploy-manage/api-keys/elasticsearch-api-keys), [Elasticsearch privileges](https://www.elastic.co/docs/deploy-manage/users-roles/cluster-or-deployment-auth/elasticsearch-privileges), [Subscriptions](https://www.elastic.co/subscriptions)
