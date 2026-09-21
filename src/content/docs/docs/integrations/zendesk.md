---
title: Zendesk
description: Read-only Zendesk Support security inspection covering authentication, access control, audit logging, data protection, apps, brands, and external integrations, with an exportable audit bundle.
---

The Zendesk integration inspects a Zendesk Support account through the public Support API and renders the 25 controls from `specs/zendesk-sec-inspector.spec.md` as normalized findings. Every tool is read-only: nothing is created, updated, or deleted in the account.

## What it inspects

- Authentication: agent two-factor coverage from the documented per-user flag, plus manual evidence prompts for SSO, password level, IP restrictions, session expiration, and end-user sign-in, none of which the published API exposes.
- Access control: custom roles that grant admin-equivalent permissions, admin count and dormant admins, group segmentation, API token exposure, and OAuth client scope, redirect URI, and token hygiene.
- Data protection: audit log availability and retention (Enterprise), HIPAA and deletion policy prompts, authenticated attachment downloads, attachment limits, and suspended ticket backlog age.
- Integrations: marketplace and private app inventories, sandbox provisioning, cross-brand help center consistency, sharing agreements, https-only targets and webhooks, and triggers or automations that deliver ticket data to external destinations.

## Setup and authentication

Zendesk retired email and password access to the API, so the tools support two credential types:

| Mode | How it is sent | When to use |
|------|----------------|-------------|
| API token | `Authorization: Basic base64({email}/token:{api_token})` | Quickest to set up. Zendesk is retiring API tokens (unused tokens are deactivated from July 28, 2026 and all API tokens stop working on April 30, 2027), so plan the OAuth migration. |
| OAuth access token | `Authorization: Bearer {token}` | Preferred. Create an OAuth client in Admin Center, grant the `read` scope, and mint an access token. |

Create an API token in Admin Center under Apps and integrations > APIs > Zendesk API (API token access must be enabled). Use an **admin** identity: several inventories (OAuth clients and tokens, audit logs, owned apps, brands, suspended tickets) are admin-only, and the assessors cap every verdict at `warn` when the credential is not an admin because a lower role sees only a partial view of the account. The audit log and custom roles additionally require an Enterprise plan.

Configuration precedence is explicit tool arguments, then environment variables, then a JSON config file:

| Environment variable | Purpose |
|----------------------|---------|
| `ZENDESK_SUBDOMAIN` | The `{subdomain}` in `https://{subdomain}.zendesk.com` (a full URL is accepted). |
| `ZENDESK_EMAIL` | Email that owns the API token (API token mode only). |
| `ZENDESK_API_TOKEN` | API token (API token mode). |
| `ZENDESK_OAUTH_TOKEN` or `ZENDESK_ACCESS_TOKEN` | OAuth access token (bearer mode). When both an OAuth token and an API token are present, OAuth wins unless `email` and `api_token` are passed explicitly. |
| `ZENDESK_BASE_URL` | Optional API base override. Defaults to `https://{subdomain}.zendesk.com/api/v2`. |
| `ZENDESK_TIMEOUT` | Optional HTTP timeout in seconds. Defaults to 30. |
| `ZENDESK_CONFIG_FILE` | Optional path to a JSON config file. Defaults to `~/.zendesk/config.json`. |

The config file accepts `subdomain`, `email`, `api_token`, `oauth_token`, `base_url`, and `timeout_seconds`:

```json
{
  "subdomain": "acme",
  "oauth_token": "your-oauth-access-token"
}
```

Tokens never appear in tool output, bundle files, or error messages; the client redacts them before surfacing any failure.

## Tools

| Tool | Purpose |
|------|---------|
| `zendesk_check_access` | Probes 18 read surfaces (current user, account settings, team members, custom roles, groups, group memberships, audit logs, OAuth clients and tokens, app installations, owned apps, brands, webhooks, targets, triggers, automations, sharing agreements, suspended tickets) and reports which admin-only or Enterprise-only surfaces the credential cannot read. |
| `zendesk_assess_authentication` | Controls 1-5 and 21. |
| `zendesk_assess_access_control` | Controls 6-8, 13, and 14. |
| `zendesk_assess_data_protection` | Controls 9-12 and 18-20. |
| `zendesk_assess_integrations` | Controls 15-17 and 22-25. |
| `zendesk_export_audit_bundle` | Runs the access check and all four assessments, then writes `core_data/` (raw API snapshots), `analysis/` (`findings.json` and one JSON per category), `compliance/` (`executive_summary.md`, `unified_compliance_matrix.md`, and one report per framework), `QUICK_REFERENCE.md`, `_errors.log` when collection was partial, and a paired `.zip`. Reruns allocate a new directory (`-2`, `-3`, ...) and the zip name follows the directory, so a prior bundle is never overwritten. |

Assessment tools accept `admin_threshold` (default 5), `stale_days` (default 90), `retention_days` (default 365), `suspended_ticket_age_days` (default 30), and `max_items` (default 2000, the point at which an inventory is recorded as truncated). The export tool adds `output_dir` (default `./export/zendesk`); output paths are resolved inside that root with traversal and symlinked-parent protection.

Every finding has the shape `{id, control, title, severity, status, summary, evidence, mappings}`. Severity is one of `critical | high | medium | low | info`, and status is one of:

- `pass`: verified from documented API fields, read to completion, by an admin credential.
- `warn`: verified but needs review, or the evidence was partial (truncated inventory, undated items, non-admin credential).
- `fail`: a verified gap.
- `manual`: the API does not expose the setting, the endpoint was forbidden or unavailable on the plan, or the inventory was suspiciously empty. The summary names the cause and the exact Admin Center evidence a reviewer must collect. Manual never counts as passing.

## Control coverage

| # | Control | Tool | Finding | Status semantics |
|---|---------|------|---------|------------------|
| 1 | SSO enforcement enabled | `zendesk_assess_authentication` | `ZD-01` | Always `manual`: the Account Settings reference exposes no SSO field. Capture Admin Center > Account > Security > Team member authentication. |
| 2 | Two-factor authentication required for agents | `zendesk_assess_authentication` | `ZD-02` | `pass` when every active agent and admin reports `two_factor_auth_enabled=true` and the list was read to completion; `warn` when the flag is missing or the list is truncated; `fail` when any member reports `false`; `manual` when the list is forbidden or empty. |
| 3 | Password policy meets complexity requirements | `zendesk_assess_authentication` | `ZD-03` | Always `manual`: no password level field is published. |
| 4 | IP restrictions configured for agent access | `zendesk_assess_authentication` | `ZD-04` | Always `manual`: no IP restriction field is published. |
| 5 | Session timeout configured and reasonable | `zendesk_assess_authentication` | `ZD-05` | Always `manual`: no session expiration field is published. |
| 6 | Agent roles follow least privilege | `zendesk_assess_access_control` | `ZD-06` | `fail` when a custom role with members grants admin-equivalent permissions (`manage_roles=all-except-self`, `manage_team_members=all-with-self-restriction`, `manage_api_credentials=true`, or `ticket_access=all` with business rule and trigger management); `warn` on truncation or when every agent is unrestricted; `manual` when users or custom roles (Enterprise) are unreadable or the team is empty. |
| 7 | No excessive admin accounts | `zendesk_assess_access_control` | `ZD-07` | `fail` above `admin_threshold`; `warn` on dormant or undated `last_login_at` or truncation; `manual` when zero admins are visible (partial view). |
| 8 | Group-based access controls configured | `zendesk_assess_access_control` | `ZD-08` | `pass` with two or more groups and memberships read to completion; `warn` with one group or no memberships or truncation; `manual` when unreadable or empty. |
| 9 | Audit logging enabled and accessible | `zendesk_assess_data_protection` | `ZD-09` | `pass` when `/audit_logs` is readable with entries; `manual` when forbidden, 404 (plan), or empty. |
| 10 | Audit log retention meets compliance requirements | `zendesk_assess_data_protection` | `ZD-10` | `pass` when the oldest entry is at least `retention_days` old; `warn` when younger; `manual` when the oldest entry is undated or unreadable. |
| 11 | HIPAA compliance mode enabled (if applicable) | `zendesk_assess_data_protection` | `ZD-11` | Always `manual`: HIPAA and Advanced Data Privacy settings are not published. |
| 12 | Data deletion/redaction policies configured | `zendesk_assess_data_protection` | `ZD-12` | Always `manual`, enriched with `settings.tickets.agent_ticket_deletion` and the count of custom roles allowed to redact or manage deletion schedules. |
| 13 | API tokens are minimal and reviewed | `zendesk_assess_access_control` | `ZD-13` | `pass` only when `settings.api.api_token_access=false`; otherwise `manual` (the token inventory is not in the published reference). |
| 14 | OAuth application permissions are scoped | `zendesk_assess_access_control` | `ZD-14` | `fail` when a client has no `scope` or an `http://` redirect URI; `warn` for public clients, write or impersonate tokens, non-expiring or stale or undated tokens, or truncation; `pass` when all clients and tokens were read to completion, including a readable zero-client inventory with the count stated. |
| 15 | Marketplace apps reviewed for permissions | `zendesk_assess_integrations` | `ZD-15` | `pass` when the readable inventory is empty (nothing to review); `manual` with the inventory when apps are installed. |
| 16 | Private/custom apps have appropriate scope | `zendesk_assess_integrations` | `ZD-16` | `pass` when the readable inventory is empty; `warn` when apps are deprecated or obsolete; otherwise `manual` with the inventory. |
| 17 | Sandbox environment used for testing | `zendesk_assess_integrations` | `ZD-17` | `pass` when `settings.active_features.sandbox=true`; `warn` when `false`; `manual` when absent or unreadable. |
| 18 | CDN security (attachment hosting) configured | `zendesk_assess_data_protection` | `ZD-18` | `pass` when `settings.tickets.private_attachments=true`; `fail` when `false`; `manual` when absent. |
| 19 | File attachment restrictions configured | `zendesk_assess_data_protection` | `ZD-19` | Always `manual`, enriched with `settings.limits.attachment_size` and `settings.tickets.email_attachments`. |
| 20 | Suspended ticket handling automated | `zendesk_assess_data_protection` | `ZD-20` | `pass` when the readable queue is empty or every ticket is younger than `suspended_ticket_age_days`; `warn` on aged, undated, or truncated tickets; `manual` when forbidden. |
| 21 | End-user authentication required (no anonymous tickets) | `zendesk_assess_authentication` | `ZD-21` | Always `manual`, enriched with `settings.api.api_password_access_end_users`. |
| 22 | Brand security settings consistent across brands | `zendesk_assess_integrations` | `ZD-22` | `pass` when an admin read every active brand and they share one `help_center_state`; `warn` for mixed states, non-admin view, or truncation; `manual` when zero brands are visible or unreadable. |
| 23 | External sharing agreements reviewed | `zendesk_assess_integrations` | `ZD-23` | `pass` when the readable inventory is empty; `warn` when agreements are failed or misconfigured; `manual` when accepted or pending agreements exist. |
| 24 | External notification targets use HTTPS | `zendesk_assess_integrations` | `ZD-24` | `fail` when any active target or webhook is non-https; `warn` when a webhook has no authentication, one endpoint is unreadable, or the inventory is truncated; `pass` when every destination is https and authenticated (or both readable inventories are empty). |
| 25 | Triggers/automations do not send data to external URLs | `zendesk_assess_integrations` | `ZD-25` | `fail` when an active rule notifies an `http://` destination; `warn` when rules notify external webhooks, targets, or sharing agreements, or the inventory is truncated; `manual` when zero rules are visible; `pass` when the complete rule set has no external actions. |

## Framework mappings

Every finding carries the row from the spec's compliance table for its control, prefixed by framework (`FedRAMP`, `CMMC`, `SOC 2`, `CIS`, `PCI-DSS`, `DISA STIG`, `IRAP`, `ISMAP`). The export bundle renders one report per framework under `compliance/`, filtering each finding's mappings to that framework. For example, control 2 maps to `FedRAMP IA-2(1)`, `CMMC IA.L2-3.5.3`, `SOC 2 CC6.1`, `CIS 4.5`, `PCI-DSS 8.3.2`, `DISA STIG SRG-APP-000149`, `IRAP ISM-1401`, and `ISMAP 8.2.2`.

## Live smoke

```bash
ZENDESK_SUBDOMAIN=acme ZENDESK_EMAIL=admin@example.com ZENDESK_API_TOKEN=... \
  npm --prefix cli run test:zendesk:live
```

The script prints a skip message and exits 0 when no credentials are present. With credentials it runs `zendesk_check_access` and `zendesk_assess_access_control` and prints the per-surface access status and each finding.

## Limitations and manual controls

- Controls 1, 3, 4, 5, 11, 12, 19, and 21 are always `manual` because the published Account Settings reference does not expose SSO, password level, IP restrictions, session expiration, HIPAA mode, deletion schedules, allowed attachment types, or end-user sign-in requirements. Each finding names the Admin Center page to capture.
- Controls 13, 15, 16, and 23 are `manual` whenever the inventory is non-empty: reviewing token ownership, app permissions, or sharing partners is a human activity. The finding carries the inventory as evidence.
- The API token inventory endpoint is not part of the published API reference and is not called.
- Audit logs and custom roles require an Enterprise plan; the tools report 403 or 404 as `manual` with a plan or permission cause, never as a pass.
- Help Center article visibility, Talk, Chat, and Sell settings are not inspected.
- Non-admin credentials cap every verdict at `warn`.

## Official documentation consulted

- [Security and authentication](https://developer.zendesk.com/api-reference/introduction/security-and-auth/)
- [Pagination](https://developer.zendesk.com/api-reference/introduction/pagination/)
- [Rate limits](https://developer.zendesk.com/api-reference/introduction/rate-limits/)
- [Account Settings](https://developer.zendesk.com/api-reference/ticketing/account-configuration/account_settings/)
- [Users](https://developer.zendesk.com/api-reference/ticketing/users/users/)
- [Custom Agent Roles](https://developer.zendesk.com/api-reference/ticketing/account-configuration/custom_roles/)
- [Groups](https://developer.zendesk.com/api-reference/ticketing/groups/groups/)
- [Group Memberships](https://developer.zendesk.com/api-reference/ticketing/groups/group_memberships/)
- [Audit Logs](https://developer.zendesk.com/api-reference/ticketing/account-configuration/audit_logs/)
- [OAuth Clients](https://developer.zendesk.com/api-reference/ticketing/oauth/oauth_clients/)
- [OAuth Tokens](https://developer.zendesk.com/api-reference/ticketing/oauth/oauth_tokens/)
- [Apps](https://developer.zendesk.com/api-reference/ticketing/apps/apps/)
- [Brands](https://developer.zendesk.com/api-reference/ticketing/account-configuration/brands/)
- [Webhooks](https://developer.zendesk.com/api-reference/webhooks/webhooks-api/webhooks/)
- [Targets](https://developer.zendesk.com/api-reference/ticketing/targets/targets/)
- [Triggers](https://developer.zendesk.com/api-reference/ticketing/business-rules/triggers/)
- [Automations](https://developer.zendesk.com/api-reference/ticketing/business-rules/automations/)
- [Sharing Agreements](https://developer.zendesk.com/api-reference/ticketing/account-configuration/sharing_agreements/)
- [Suspended Tickets](https://developer.zendesk.com/api-reference/ticketing/tickets/suspended_tickets/)
