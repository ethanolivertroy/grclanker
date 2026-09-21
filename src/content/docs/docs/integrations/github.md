---
title: GitHub
description: Read-only GitHub organization security inspector covering identity, repository protection, Actions, code security, integrations, and audit bundle export.
---

The GitHub inspector reviews one GitHub organization (github.com, GitHub Enterprise Cloud, or GitHub Enterprise Server) through the REST and GraphQL APIs. Every tool is read-only; nothing is written back to the tenant.

## What it inspects

- Identity and access: 2FA requirement and members without 2FA, SAML SSO and identity linkage, Enterprise Managed Users, IP allow list, base permission, public repository creation, private fork policy, outside collaborators, privileged access, audit log visibility.
- Repository protection: effective branch rules for every active default branch (rulesets plus legacy branch protection), approving review detail, status checks, signed commits, force push and deletion, web commit signoff.
- Actions: allowed actions policy, workflow token defaults, workflow pull request approval, Actions enablement scope, self-hosted runner and runner group exposure.
- Code security: code security configurations, secret scanning and push protection defaults, Dependabot defaults, code scanning default setup.
- Integrations: webhook transport security across org and repository hooks, deploy key scope and age, GitHub App installation permissions.

## Setup and authentication

Set the organization and one credential family. Explicit tool arguments win over environment variables.

| Variable | Purpose |
|----------|---------|
| `GITHUB_ORG` or `GH_ORG` | Organization login (a `https://github.com/<org>` URL is accepted) |
| `GITHUB_TOKEN` or `GH_TOKEN` | Personal access token for PAT auth |
| `GITHUB_APP_ID`, `GITHUB_APP_INSTALLATION_ID`, `GITHUB_APP_PRIVATE_KEY` or `GITHUB_APP_PRIVATE_KEY_PATH` | GitHub App installation-token auth (RS256 JWT minted locally) |
| `GITHUB_API_URL` (alias `GITHUB_API_BASE_URL`) | REST base URL, default `https://api.github.com`; use `https://<host>/api/v3` for GHES |
| `GITHUB_GRAPHQL_URL` | GraphQL endpoint; derived from the REST URL when unset (`/graphql` on github.com, `/api/graphql` on GHES) |
| `GITHUB_ENTERPRISE` | Enterprise slug for the EMU and enterprise identity queries |
| `GITHUB_LOOKBACK_DAYS` | Audit log window, default 30 |

Required read access for a complete run: organization owner (or an App with organization administration, members, webhooks, and Actions read plus repository administration read) so that `members?filter=2fa_disabled`, outside collaborators, org webhooks, App installations, runner groups, deploy keys, and repository hooks are readable. For SAML-protected organizations a PAT must be authorized for SSO. Surfaces the principal cannot read produce Manual findings that name the missing permission; they never pass.

## Tools

| Tool | What it does |
|------|--------------|
| `github_check_access` | Probes the org profile, members, repositories, audit log, organization roles, rulesets, Actions permissions, and code security configurations and reports `healthy` or `limited` |
| `github_assess_org_access` | Identity and access findings GITHUB-ORG-001 to GITHUB-ORG-011 |
| `github_assess_repo_protection` | Repository protection findings GITHUB-REPO-001 to GITHUB-REPO-007 |
| `github_assess_actions_security` | Actions findings GITHUB-ACT-001 to GITHUB-ACT-005 |
| `github_assess_code_security` | Code security findings GITHUB-CODE-001 to GITHUB-CODE-006 |
| `github_assess_integrations` | Webhook, deploy key, App installation, OAuth, and package findings GITHUB-INTEG-001 to GITHUB-INTEG-005 |
| `github_export_audit_bundle` | Runs every collector once and writes an evidence bundle under `output_dir` |

All tools accept `organization`, `auth_mode` (`pat` or `app`), `api_token`, `app_id`, `app_private_key`, `app_private_key_path`, `installation_id`, `enterprise`, and `lookback_days`; the export tool adds `output_dir`.

## Control coverage

| Spec control | Tool | Finding | Status semantics |
|--------------|------|---------|------------------|
| 1 SAML SSO Enforcement | org_access | GITHUB-ORG-006 | Pass with a SAML provider and every member linked; Partial when identities are truncated; Fail without a provider |
| 2 Two-Factor Authentication | org_access | GITHUB-ORG-001 | Pass on the org flag with an empty `2fa_disabled` list; Fail when members lack 2FA; Partial when the owner-only filter is forbidden |
| 3 Enterprise Managed Users | org_access | GITHUB-ORG-007 | Pass on an enterprise OIDC provider; Partial for SAML-only enterprise IdP; Manual without `GITHUB_ENTERPRISE` |
| 4 IP Allow List | org_access | GITHUB-ORG-008 | Pass when ENABLED with active entries and enforced for installed apps |
| 5 Member Base Permissions | org_access | GITHUB-ORG-002 | Pass on `read` or `none` |
| 6 Repository Visibility Defaults | org_access | GITHUB-ORG-009 | Pass when members cannot create public repositories |
| 7 Fork Policy | org_access | GITHUB-ORG-010 | Pass when private forking is disabled |
| 8 Outside Collaborator Policy | org_access | GITHUB-ORG-003 | Pass on zero outside collaborators (stated), Partial up to five, Fail above |
| 9 OAuth App Restrictions | integrations | GITHUB-INTEG-004 | Manual: the policy has no REST or GraphQL field |
| 10 Branch Protection Rules | repo_protection | GITHUB-REPO-002, GITHUB-REPO-004 | Pass when every active default branch requires pull requests and blocks force pushes and deletions |
| 11 Required Pull Request Reviews | repo_protection | GITHUB-REPO-006 | Pass when every active repository requires an approving review |
| 12 Required Status Checks | repo_protection | GITHUB-REPO-007 | Pass when every active repository requires a status check |
| 13 Signed Commit Requirement | repo_protection | GITHUB-REPO-003 | Pass when every active repository enforces signatures |
| 14 Repository Rulesets | repo_protection | GITHUB-REPO-001 | Pass when active org rulesets reach every repository |
| 15 Code Scanning Enabled | code_security | GITHUB-CODE-005 | Pass when a default configuration enables default setup |
| 16 Secret Scanning Enabled | code_security | GITHUB-CODE-002, GITHUB-CODE-003 | Pass on the org defaults or the default configuration |
| 17 Dependabot Enabled | code_security | GITHUB-CODE-004 | Pass when alerts and security updates are both on |
| 18 Security Policy | code_security | GITHUB-CODE-006 | Manual (deferred GraphQL sweep) |
| 19 Audit Log Streaming | org_access | GITHUB-ORG-011 | Manual (enterprise-level endpoint); GITHUB-ORG-005 covers visibility only |
| 20 Webhook Security | integrations | GITHUB-INTEG-001 | Fail on plain HTTP, `insecure_ssl = 1`, or a missing secret |
| 21 Actions Permissions | actions_security | GITHUB-ACT-001, 002, 003, 005 | Pass on selected or local-only actions, read-only tokens, no workflow approval |
| 22 Runner Group Restrictions | actions_security | GITHUB-ACT-004 | Pass when no group is org-wide or open to public repositories; Info with no org-level runners |
| 23 Deploy Key Management | integrations | GITHUB-INTEG-002 | Fail on write-capable or year-old keys; Partial on undated keys |
| 24 GitHub App Permissions Audit | integrations | GITHUB-INTEG-003 | Fail on admin or write-to-all permissions |
| 25 Package Registry Access | integrations | GITHUB-INTEG-005 | Manual (deferred packages sweep) |

Extra findings: GITHUB-ORG-004 (privileged access ratio) and GITHUB-REPO-005 (web commit signoff).

## Verdict rules

- A forbidden, missing, or errored endpoint renders Manual with the HTTP status and the evidence a reviewer must collect.
- Partial inventories (truncated GraphQL connections, per-repository 403s, an audit log sample capped at 200 events) render Partial, or Pass only for the visibility-only audit log control with the cap stated.
- Empty inventories pass only where the summary says emptiness is compliant (outside collaborators, App installations, webhooks and deploy keys with a non-empty repository inventory). Empty repository inventories render Info or Partial because the sweep covered nothing.
- Deploy keys without `created_at` never count as fresh.
- REST pagination follows `Link` headers to completion; GraphQL connections page on `endCursor` and record truncation.
- A rerun of the export allocates a new directory and a zip with the same stem, so prior bundles are never overwritten.

## Framework mappings

Each finding carries the FedRAMP (800-53 r5), CMMC 2.0, SOC 2, CIS GitHub Benchmark, PCI DSS 4.0, DISA STIG, IRAP (ISM), and ISMAP references from the spec mapping table for its control, and the export writes one report per framework under `compliance/frameworks/`.

## Audit bundle layout

```
<org>-audit-bundle[-N]/
  QUICK_REFERENCE.md
  config.json
  core_data/{org_access,repo_protection,actions_security,code_security,integrations}.json
  analysis/findings.json and one file per category
  compliance/executive_summary.md
  compliance/unified_compliance_matrix.md
  compliance/frameworks/<framework>.md
  _errors.log (only when a collector failed)
<org>-audit-bundle[-N].zip
```

## Live smoke

```bash
GITHUB_ORG=my-org GITHUB_TOKEN=ghp_... npm --prefix cli run test:github:live
```

The script exits 0 with a skip message when no credentials are present. With credentials it runs the access check and all five assessments and prints the per-status counts and every Fail summary.

## Limitations and manual controls

- OAuth application access restriction (control 9) is Manual because neither the REST `organization-full` schema nor the GraphQL `Organization` type exposes the policy.
- Audit log streaming (19), security policy presence (18), and package registry visibility (25) are Manual in this release; the findings cite the exact endpoint or GraphQL field a reviewer or a follow-on collector should use.
- Open alert counts for code scanning, secret scanning, and Dependabot are not collected yet; controls 15 to 17 check defaults and configurations only.
- The org runners endpoint does not enumerate repository-level self-hosted runners.
- The interactive OAuth App flow from the spec is not implemented; use a PAT or a GitHub App.

## Official documentation

- [Get an organization](https://docs.github.com/en/rest/orgs/orgs#get-an-organization)
- [List organization members](https://docs.github.com/en/rest/orgs/members#list-organization-members) (`filter=2fa_disabled`)
- [List outside collaborators](https://docs.github.com/en/rest/orgs/outside-collaborators#list-outside-collaborators-for-an-organization)
- [Organization roles](https://docs.github.com/en/rest/orgs/organization-roles)
- [List SAML SSO authorizations](https://docs.github.com/en/enterprise-cloud@latest/rest/orgs/orgs#list-saml-sso-authorizations-for-an-organization)
- [Get the audit log for an organization](https://docs.github.com/en/enterprise-cloud@latest/rest/orgs/orgs#get-the-audit-log-for-an-organization)
- [List organization webhooks](https://docs.github.com/en/rest/orgs/webhooks#list-organization-webhooks) and [List repository webhooks](https://docs.github.com/en/rest/repos/webhooks#list-repository-webhooks)
- [List app installations for an organization](https://docs.github.com/en/rest/orgs/orgs#list-app-installations-for-an-organization)
- [List organization repositories](https://docs.github.com/en/rest/repos/repos#list-organization-repositories)
- [Organization rulesets](https://docs.github.com/en/rest/orgs/rules), [Repository rulesets](https://docs.github.com/en/rest/repos/rules), and [Get rules for a branch](https://docs.github.com/en/rest/repos/rules#get-rules-for-a-branch)
- [Get branch protection](https://docs.github.com/en/rest/branches/branch-protection#get-branch-protection)
- [List deploy keys](https://docs.github.com/en/rest/deploy-keys/deploy-keys#list-deploy-keys)
- [Actions permissions for an organization](https://docs.github.com/en/rest/actions/permissions)
- [Self-hosted runner groups](https://docs.github.com/en/rest/actions/self-hosted-runner-groups) and [Self-hosted runners](https://docs.github.com/en/rest/actions/self-hosted-runners)
- [Code security configurations](https://docs.github.com/en/rest/code-security/configurations)
- GraphQL [Organization](https://docs.github.com/en/graphql/reference/objects#organization), [OrganizationIdentityProvider](https://docs.github.com/en/graphql/reference/objects#organizationidentityprovider), [IpAllowListEntry](https://docs.github.com/en/graphql/reference/objects#ipallowlistentry), [EnterpriseOwnerInfo](https://docs.github.com/en/graphql/reference/objects#enterpriseownerinfo)
- [Generating a JWT for a GitHub App](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-json-web-token-jwt-for-a-github-app)
- Deferred collectors: [Audit log stream configurations](https://docs.github.com/en/enterprise-cloud@latest/rest/enterprise-admin/audit-log#list-audit-log-stream-configurations-for-an-enterprise), [List packages for an organization](https://docs.github.com/en/rest/packages/packages#list-packages-for-an-organization), GraphQL [Repository.isSecurityPolicyEnabled](https://docs.github.com/en/graphql/reference/objects#repository)
