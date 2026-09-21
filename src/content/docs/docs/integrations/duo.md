---
title: Duo Security Inspector
description: Read-only Cisco Duo MFA posture assessment through the Duo Admin API with multi-framework audit bundles.
---

The Duo tools inspect a Cisco Duo tenant through the Duo Admin API using one read-only audit principal. They cover global MFA enforcement, user enrollment and inactivity, bypass codes, administrator hygiene, policy depth (trusted endpoints, device health, remembered devices, factor restrictions), integration coverage, and authentication telemetry, then export an evidence bundle mapped to FedRAMP, CMMC, SOC 2, CIS, PCI-DSS, DISA STIG, IRAP, and ISMAP.

Every endpoint and field the tools read is documented in the [Duo Admin API reference](https://duo.com/docs/adminapi). Where the reference is silent (for example offline access limits) the control is rendered as Manual with the reason instead of guessing.

## Setup and authentication

Create an Admin API application in the Duo Admin Panel (Applications, Protect an Application, Admin API) and export its keys:

```bash
export DUO_IKEY=DIXXXXXXXXXXXXXXXXXX
export DUO_SKEY=your-secret-key
export DUO_API_HOST=api-XXXXXXXX.duosecurity.com
export DUO_LOOKBACK_DAYS=30   # optional, 1 to 180
```

Each tool also accepts `api_host`, `ikey`, `skey`, and `lookback_days` arguments that override the environment. Requests are signed with HMAC-SHA512. The endpoints the reference marks as v5-only (`/admin/v2/policies` and `/admin/v2/policies/global` in the Policies section, `/admin/v3/integrations` in the Integrations section) use the seven-line v5 canonical string: date, method, host, path, sorted query string, SHA-512 of the request body (the empty string for GET), and SHA-512 of the additional `X-Duo-*` headers (none are sent). Every other `/admin/v1` and `/admin/v2` endpoint keeps the legacy v2 canonical string.

Grant the Admin API application these read-only permissions:

| Permission | Used for |
|---|---|
| Grant read information | `/admin/v1/info/summary`, `/admin/v1/info/authentication_attempts` |
| Grant resource - Read | users, bypass codes, WebAuthn credentials, policies, integrations |
| Grant administrators - Read | administrators, allowed admin authentication methods |
| Grant settings | `/admin/v1/settings` (lockout, help desk bypass, notifications) |
| Grant read log | authentication, activity, telephony, offline enrollment, and Trust Monitor logs |

Do not grant any write permission. The tools never call a mutating endpoint.

## Tools

| Tool | What it does |
|---|---|
| `duo_check_access` | Probes settings, users, policies, admins, authentication logs, and integrations and reports which surfaces the audit principal can read. |
| `duo_assess_authentication` | Global MFA enforcement mode, phishing-resistant factors, deprecated factors, new user policy, remembered devices, trusted endpoints, bypass codes, enrollment completeness, inactive users, WebAuthn adoption, offline access evidence. |
| `duo_assess_admin_access` | Owner concentration, administrator MFA methods, help desk bypass governance, stale and never-logged-in administrators, user lockout policy. Administrator activity logs are collected as evidence (`core_data/activity_logs.json`) rather than graded. |
| `duo_assess_integrations` | Explicit policy attachment, Universal Prompt adoption, self-service portal governance, Admin API least privilege, critical application coverage, device health depth. |
| `duo_assess_monitoring` | Authentication log factor hygiene, Trust Monitor coverage, telephony credits and reliance, authentication attempt outcomes and impossible travel, notification settings. |
| `duo_export_audit_bundle` | Runs all four assessments and writes the shared bundle layout plus a zip archive (defaults to `./export/duo`). |

## Endpoints

| Endpoint | Reference section | Notes |
|---|---|---|
| `GET /admin/v1/settings` | Settings, Retrieve Settings | `helpdesk_bypass`, `helpdesk_bypass_expiration`, `lockout_threshold`, `lockout_expire_duration`, `unenrolled_user_lockout_threshold`, notification flags; `global_ssp_policy_enforced` is reported as legacy evidence only |
| `GET /admin/v1/info/summary` | Account Info, Retrieve Summary | `edition`, `telephony_credits_remaining` |
| `GET /admin/v1/info/authentication_attempts` | Account Info, Authentication Attempts Report | `mintime` and `maxtime` in Unix seconds; `authentication_attempts.{ERROR,FAILURE,FRAUD,SUCCESS}` |
| `GET /admin/v2/policies/global` and `GET /admin/v2/policies` | Policies | `sections.authentication_policy.user_auth_behavior`, `authentication_methods`, `new_user`, `remembered_devices`, `trusted_endpoints`, `health_checks`, `duo_desktop`, `operating_systems`, `full_disk_encryption`, `screen_lock` |
| `GET /admin/v1/users` | Users, Retrieve Users | `status`, `is_enrolled`, `last_login`, `phones`, `tokens`, `u2f_tokens`, `webauthncredentials`; `limit` max 300, paged with `metadata.next_offset` |
| `GET /admin/v1/bypass_codes` | Bypass Codes, Retrieve Bypass Codes | `bypass_code_id`, `created` (older than 24 hours is flagged), `expiration` (`null` never expires), `reuse_count` (`null` unlimited uses), `user` |
| `GET /admin/v1/webauthncredentials` | WebAuthn Credentials, Retrieve WebAuthn Credentials | `uv_capable`, `user`; `limit` max 500 |
| `GET /admin/v1/admins` | Administrators, Retrieve Administrators | `role`, `status`, `last_login` |
| `GET /admin/v1/admins/allowed_auth_methods` | Administrators, Retrieve Allowed Authentication Methods | `verified_push_enabled`, `webauthn_enabled`, `sms_enabled`, `voice_enabled` |
| `GET /admin/v3/integrations` | Integrations, Retrieve Integrations | `type`, `policy_key`, `user_access`, `sensitivity_level`, `compliance_requirements`, `prompt_v4_enabled`, `frameless_auth_prompt_enabled`, `self_service_allowed`, `adminapi_*`; `limit` max 500; v5 signing |
| `GET /admin/v2/logs/authentication` | Logs, Authentication Logs | `mintime` and `maxtime` in milliseconds, `next_offset` cursor; `result`, `factor`, `timestamp`, `user.key`, `access_device.location.country` |
| `GET /admin/v2/logs/activity`, `GET /admin/v2/logs/telephony` | Logs | activity log evidence; telephony usage (`type` sms or phone) |
| `GET /admin/v1/logs/offline_enrollment` | Logs, Offline Enrollment Logs | `mintime` in Unix seconds; returns the 1000 earliest events per call, so full pages are followed by advancing `mintime` to the newest `timestamp` plus one (capped at 5000 events, reported incomplete beyond that); `action`, `description.factor` |
| `GET /admin/v1/trust_monitor/events` | Trust Monitor, Retrieve Events | `mintime` and `maxtime` in milliseconds, `limit` max 200; `metadata.next_offset` is an opaque cursor sent back as `offset`; `priority_event`, `state` |

## Control coverage

Status semantics: `Pass` means the documented setting or population meets the control; `Partial` means the control is met only in part, an inventory was incomplete (seen and total counts are reported), or undated records prevent a clean verdict; `Fail` means the documented setting contradicts the control; `Manual` means the API could not answer (403, missing permission, missing edition, or an undocumented field) and the finding names the endpoint, permission, and evidence to collect. A forbidden or errored call never produces `Pass`.

| # | Spec control | Finding | Automation |
|---|---|---|---|
| 1 | Global MFA policy | DUO-AUTH-007 (enforcement mode), DUO-AUTH-001 (phishing-resistant factors) | Automated |
| 2 | User enrollment completeness | DUO-AUTH-008 | Automated (`status`, `is_enrolled`) |
| 3 | Bypass code audit | DUO-AUTH-006 | Automated |
| 4 | Inactive user detection | DUO-AUTH-009 | Automated (`last_login` over 90 days; null bucketed, capped at Partial) |
| 5 | Admin role review | DUO-ADMIN-001 | Automated |
| 6 | Trusted endpoint policy | DUO-AUTH-005 | Automated |
| 7 | Device health requirements | DUO-INTEGRATIONS-006 | Automated on Advantage and Premier; Manual naming the edition otherwise |
| 8 | Remembered devices policy | DUO-AUTH-004 | Automated |
| 9 | Authentication method restrictions | DUO-AUTH-002 | Automated |
| 10 | New user policy | DUO-AUTH-003 | Automated |
| 11 | User lockout policy | DUO-ADMIN-005 | Automated (`lockout_threshold` 10 or fewer) |
| 12 | Integration policy assignments | DUO-INTEGRATIONS-001 | Automated |
| 13 | Unprotected application detection | DUO-INTEGRATIONS-005 | Automated when applications carry `sensitivity_level` or `compliance_requirements`; Manual otherwise |
| 14 | Trust Monitor configuration | DUO-MON-002 | Automated where the edition exposes Trust Monitor events |
| 15 | Authentication log anomalies | DUO-MON-005 (attempt outcomes, impossible travel), DUO-MON-001 (factor hygiene) | Automated; travel analysis needs `access_device.location` (Advantage and Premier) |
| 16 | Telephony credit monitoring | DUO-MON-003 | Automated; Manual when `telephony_credits_remaining` is absent (unknown credits never pass) |
| 17 | U2F/WebAuthn credential inventory | DUO-AUTH-010 | Automated |
| 18 | Offline access configuration | DUO-AUTH-011 | Manual: Policy Section Data documents no offline access section; offline enrollment events are collected as evidence |
| 19 | Self-service portal policy | DUO-INTEGRATIONS-003 | Automated per integration (`self_service_allowed` from `/admin/v3/integrations`); the legacy `global_ssp_policy_enforced` setting is evidence only |
| 20 | API permission audit | DUO-INTEGRATIONS-004 | Automated (`adminapi_*` flags) |

Supporting findings without a spec control number: DUO-ADMIN-002 (administrator MFA strength), DUO-ADMIN-003 (help desk bypass governance), DUO-ADMIN-004 (stale administrators), DUO-INTEGRATIONS-002 (Universal Prompt adoption), DUO-MON-004 (notifications).

## Framework mappings

Every finding carries FedRAMP, CMMC, SOC 2, CIS, PCI-DSS, DISA STIG, IRAP, and ISMAP identifiers from the mapping table in `specs/duo-sec-inspector.spec.md`. The bundle writes one report per framework under `compliance/` and a unified matrix in `compliance/unified_compliance_matrix.md`.

## Audit bundle layout

```text
<api-host>_<timestamp>/
  QUICK_REFERENCE.md
  config.json
  core_data/          raw Admin API payloads plus collection_status.json
  analysis/           one JSON per assessment plus findings.json
  compliance/         executive_summary.md, unified_compliance_matrix.md, <framework>/<report>.md
  _errors.log         only when a read failed but the bundle still completed
<api-host>_<timestamp>.zip
```

Re-running the export allocates a new directory and zip; it never overwrites a previous bundle.

## Live smoke test

```bash
DUO_API_HOST=... DUO_IKEY=... DUO_SKEY=... npm --prefix cli run test:duo:live
```

The smoke test exits 0 without credentials. With credentials it runs the access check and all four assessments, prints every finding, and fails if any finding passed while carrying a collection error.

## Limitations and manual controls

- Offline access limits (days and authentication count) are not exposed by the Admin API; verify them in the Global Policy Offline Access section.
- Device health, operating system, disk encryption, screen lock, User Location, and access device location data require Duo Advantage or Premier. On other editions the affected findings are Manual and name the edition reported by `/admin/v1/info/summary`.
- Critical application detection relies on `sensitivity_level` and `compliance_requirements`, which administrators set in the Admin Panel. Untagged tenants receive a Manual finding.
- Log-based checks sample up to 400 events per log within the lookback window; when the sample is incomplete the affected findings are capped at Partial and report seen, total, and cap counts.
- The reference notes that Trust Monitor is available to Duo Premier and Advantage accounts created before September 29, 2025 and that the events endpoint reaches end of support on January 31, 2027. Tenants without it receive a Manual DUO-MON-002 naming the endpoint and permission.
- The Auth API and Accounts API are out of scope; only Admin API read endpoints are used.

## References

- [Duo Admin API](https://duo.com/docs/adminapi)
- [Duo Policy and Control](https://duo.com/docs/policy)
- [Duo Trusted Endpoints](https://duo.com/docs/trusted-endpoints)
- [Duo Trust Monitor](https://duo.com/docs/trust-monitor)
