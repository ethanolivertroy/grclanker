---
slug: "github-sec-inspector"
name: "GitHub Security Inspector"
vendor: "GitHub"
category: "devops-developer-platforms"
language: "typescript"
status: "implemented"
version: "1.0"
last_updated: "2026-03-29"
source_repo: "https://github.com/hackIDLE/github-sec-inspector"
---

# github-sec-inspector — Architecture Specification

## 1. Overview

**GitHub Enterprise Cloud** is the most widely adopted platform for source code hosting, collaboration, and DevOps automation. Organizations use it to manage repositories, CI/CD pipelines (GitHub Actions), package registries, code review workflows, and developer access across thousands of contributors.

Misconfigurations at the organization or enterprise level — unenforced SSO, missing two-factor authentication requirements, overly permissive member base permissions, unprotected default branches, disabled security scanning, unrestricted Actions workflows, or unmonitored OAuth/GitHub App integrations — can expose source code, enable supply chain attacks, leak secrets, and undermine the software development lifecycle. Because GitHub is the central nervous system of modern software delivery, its security posture directly determines an organization's exposure to code tampering, credential theft, and insider threats.

**github-sec-inspector** is an automated compliance inspection tool that connects to a GitHub organization (or enterprise) via the GitHub APIs, collects security-relevant configuration data across organization settings, repositories, rulesets, Actions posture, code security features, and access controls, evaluates the configuration against hardened baselines derived from multiple compliance frameworks, and produces actionable reports with framework-specific control mappings.

The current implementation ships natively inside `grclanker` as a TypeScript tool family: `github_check_access`, `github_assess_org_access`, `github_assess_repo_protection`, `github_assess_actions_security`, `github_assess_code_security`, and `github_export_audit_bundle`.

## 2. APIs & SDKs

### 2.1 GitHub REST API v3

Base URL: `https://api.github.com`

#### Organization Settings & Members

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/orgs/{org}` | GET | Organization profile, settings, default permissions, 2FA requirement |
| `/orgs/{org}/settings/billing/actions` | GET | Actions usage and billing |
| `/orgs/{org}/members` | GET | List organization members (with filter, role params) |
| `/orgs/{org}/members/{username}` | GET | Check membership status |
| `/orgs/{org}/memberships/{username}` | GET | Get membership details (role: member/admin) |
| `/orgs/{org}/outside_collaborators` | GET | List outside collaborators across all repos |
| `/orgs/{org}/teams` | GET | List all teams |
| `/orgs/{org}/teams/{team_slug}/members` | GET | List team members |
| `/orgs/{org}/teams/{team_slug}/repos` | GET | List repos accessible to a team |
| `/orgs/{org}/failed_invitations` | GET | List failed membership invitations |
| `/orgs/{org}/invitations` | GET | List pending invitations |
| `/orgs/{org}/blocks` | GET | List blocked users |

#### Security & Access Management

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/orgs/{org}/security-managers` | GET | List security manager teams (deprecated Jan 2026; use Organization Roles) |
| `/orgs/{org}/organization-roles` | GET | List organization roles and assignments |
| `/orgs/{org}/credential-authorizations` | GET | List SAML SSO credential authorizations for members |
| `/orgs/{org}/installations` | GET | List GitHub App installations on the org |
| `/orgs/{org}/hooks` | GET | List organization webhooks |
| `/orgs/{org}/hooks/{hook_id}` | GET | Get webhook details (config, events, SSL verification) |

#### Audit Log

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/orgs/{org}/audit-log` | GET | Query organization audit log events (with `phrase`, `include`, `after` params) |
| `/enterprises/{enterprise}/audit-log` | GET | Enterprise-level audit log (Enterprise Cloud only) |

#### Code Security (GHAS)

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/orgs/{org}/code-scanning/alerts` | GET | List code scanning alerts across all repos |
| `/orgs/{org}/secret-scanning/alerts` | GET | List secret scanning alerts across all repos |
| `/orgs/{org}/dependabot/alerts` | GET | List Dependabot alerts across all repos |
| `/orgs/{org}/code-security/configurations` | GET | List code security configurations |
| `/repos/{owner}/{repo}/code-scanning/alerts` | GET | Repository-level code scanning alerts |
| `/repos/{owner}/{repo}/secret-scanning/alerts` | GET | Repository-level secret scanning alerts |
| `/repos/{owner}/{repo}/dependabot/alerts` | GET | Repository-level Dependabot alerts |
| `/repos/{owner}/{repo}/vulnerability-alerts` | GET | Check if Dependabot alerts are enabled |

#### Repository Settings & Branch Protection

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/orgs/{org}/repos` | GET | List all organization repositories |
| `/repos/{owner}/{repo}` | GET | Repository details (visibility, default branch, settings) |
| `/repos/{owner}/{repo}/branches/{branch}/protection` | GET | Branch protection rules |
| `/repos/{owner}/{repo}/branches/{branch}/protection/required_pull_request_reviews` | GET | Required review settings |
| `/repos/{owner}/{repo}/branches/{branch}/protection/required_signatures` | GET | Signed commit requirement |
| `/repos/{owner}/{repo}/branches/{branch}/protection/required_status_checks` | GET | Required status checks |
| `/repos/{owner}/{repo}/branches/{branch}/protection/enforce_admins` | GET | Admin enforcement of protections |
| `/repos/{owner}/{repo}/rulesets` | GET | Repository rulesets (newer API replacing branch protection) |
| `/orgs/{org}/rulesets` | GET | Organization-level rulesets |

#### Deploy Keys, Secrets, and Actions

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/repos/{owner}/{repo}/keys` | GET | List deploy keys |
| `/repos/{owner}/{repo}/actions/permissions` | GET | Actions permissions for a repo |
| `/orgs/{org}/actions/permissions` | GET | Actions permissions for the org |
| `/orgs/{org}/actions/permissions/workflow` | GET | Default workflow permissions |
| `/orgs/{org}/actions/permissions/selected-actions` | GET | Allowed actions configuration |
| `/orgs/{org}/actions/runner-groups` | GET | Self-hosted runner groups |
| `/orgs/{org}/actions/runners` | GET | List self-hosted runners |
| `/orgs/{org}/actions/secrets` | GET | List organization-level Actions secrets |
| `/orgs/{org}/dependabot/secrets` | GET | List organization-level Dependabot secrets |
| `/orgs/{org}/packages` | GET | List packages in the organization registry |

#### OAuth and GitHub Apps

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/orgs/{org}/installations` | GET | GitHub App installations |
| `/app/installations/{installation_id}` | GET | Installation details and permissions |
| `/orgs/{org}/credential-authorizations` | GET | OAuth credential authorizations (SAML SSO orgs) |

### 2.2 GitHub GraphQL API v4

Base URL: `https://api.github.com/graphql`

#### Organization-Level Queries

```graphql
# SAML Identity Provider configuration
query {
  organization(login: "org-name") {
    samlIdentityProvider {
      ssoUrl
      issuer
      digestMethod
      signatureMethod
      externalIdentities(first: 100) {
        edges {
          node {
            samlIdentity { nameId }
            scimIdentity { username }
            user { login, email }
          }
        }
      }
    }
  }
}

# IP Allow List entries
query {
  organization(login: "org-name") {
    ipAllowListEnabledSetting
    ipAllowListForInstalledAppsEnabledSetting
    ipAllowListEntries(first: 100) {
      nodes {
        allowListValue
        isActive
        name
        createdAt
      }
    }
  }
}

# Enterprise Managed Users (EMU) detection
query {
  organization(login: "org-name") {
    membersWithRole(first: 1) {
      nodes {
        login
        enterpriseUserAccount {
          login
          enterprise { slug }
        }
      }
    }
  }
}

# Repository security features
query {
  organization(login: "org-name") {
    repositories(first: 100) {
      nodes {
        name
        isPrivate
        defaultBranchRef {
          name
          branchProtectionRule {
            requiresApprovingReviews
            requiredApprovingReviewCount
            requiresCodeOwnerReviews
            requiresCommitSignatures
            requiresStatusChecks
            requiresLinearHistory
            dismissesStaleReviews
            restrictsReviewDismissals
            isAdminEnforced
            allowsForcePushes
            allowsDeletions
          }
        }
        hasVulnerabilityAlertsEnabled
        securityPolicyUrl
        deleteBranchOnMerge
        mergeCommitAllowed
        squashMergeAllowed
        rebaseMergeAllowed
      }
    }
  }
}
```

#### Enterprise-Level Queries (Enterprise Cloud)

```graphql
# Enterprise audit log
query {
  enterprise(slug: "enterprise-slug") {
    ownerInfo {
      admins(first: 10) { nodes { login } }
      affiliatedUsersWithTwoFactorDisabled(first: 100) {
        nodes { login, email }
      }
      samlIdentityProvider {
        ssoUrl
        issuer
        externalIdentities(first: 100) {
          nodes {
            samlIdentity { nameId }
            user { login }
          }
        }
      }
    }
  }
}
```

### 2.3 SDKs and CLIs

| Tool | Language | Package | Notes |
|------|----------|---------|-------|
| **go-github** | Go | `github.com/google/go-github/v68` | Google-maintained Go client for GitHub REST API v3 |
| **shurcooL/githubv4** | Go | `github.com/shurcooL/githubv4` | Go client for GitHub GraphQL API v4 |
| **gh CLI** | Go | `gh` (Homebrew, apt, etc.) | Official GitHub CLI; extensible with extensions |
| **PyGithub** | Python | `pip install PyGithub` | Full-featured Python wrapper for REST API |
| **ghapi** | Python | `pip install ghapi` | Lightweight Python wrapper auto-generated from OpenAPI spec |
| **octokit/rest.js** | JS/TS | `npm install @octokit/rest` | Official JavaScript REST client |
| **octokit/graphql.js** | JS/TS | `npm install @octokit/graphql` | Official JavaScript GraphQL client |
| **octokit.rb** | Ruby | `gem install octokit` | Official Ruby client |
| **Terraform GitHub Provider** | HCL | `integrations/github` | Infrastructure-as-code for GitHub settings |

### 2.4 API Rate Limits

| API | Limit | Notes |
|-----|-------|-------|
| REST API (authenticated) | 5,000 requests/hour | Per PAT or OAuth token |
| REST API (GitHub App) | 5,000 requests/hour per installation | Higher for large orgs |
| GraphQL API | 5,000 points/hour | Cost varies by query complexity |
| Audit Log REST | 1,750 queries/hour per user | Lower rate for audit log queries |
| Search API | 30 requests/minute | Separate rate limit bucket |

## 3. Authentication

### 3.1 Personal Access Token (Fine-Grained)

```bash
export GITHUB_TOKEN="github_pat_..."
export GITHUB_ORG="your-organization"
```

Fine-grained PATs (recommended) can be scoped to specific repositories and permissions. Required permissions for full audit:
- **Organization**: `read:org`, `read:audit_log`, `admin:org` (for some settings)
- **Repository**: `read:repo`, `read:security_events`
- **Members**: `read:org`

### 3.2 Personal Access Token (Classic)

```bash
export GITHUB_TOKEN="ghp_..."
export GITHUB_ORG="your-organization"
```

Classic PATs require the following scopes:
- `repo` — full repository access (needed for branch protection, security alerts)
- `admin:org` — organization settings, members, teams, webhooks
- `read:audit_log` — audit log access
- `security_events` — code scanning and secret scanning alerts
- `read:packages` — package registry access

### 3.3 GitHub App Authentication

```bash
export GITHUB_APP_ID="12345"
export GITHUB_APP_PRIVATE_KEY_PATH="/path/to/private-key.pem"
export GITHUB_APP_INSTALLATION_ID="67890"
export GITHUB_ORG="your-organization"
```

GitHub Apps provide the highest rate limits and finest-grained permissions. The app must be installed on the organization with the following permissions:
- **Organization**: Administration (read), Members (read), Plan (read)
- **Repository**: Administration (read), Code scanning alerts (read), Dependabot alerts (read), Secret scanning alerts (read), Metadata (read)

### 3.4 OAuth App (Interactive)

For interactive use or CI/CD systems using OAuth flow. Not recommended for automated inspection; prefer PAT or GitHub App.

### 3.5 SAML SSO Authorization

In organizations with SAML SSO enabled, tokens must be explicitly authorized for the organization. Classic PATs must be SSO-authorized via GitHub Settings > Developer settings > Personal access tokens > Authorize.

### 3.6 Environment Variables (github-sec-inspector)

| Variable | Required | Description |
|----------|----------|-------------|
| `GITHUB_TOKEN` | Yes* | Personal access token (classic or fine-grained) |
| `GITHUB_ORG` | Yes | Target organization slug |
| `GITHUB_ENTERPRISE` | Optional | Enterprise slug (for enterprise-level checks) |
| `GITHUB_APP_ID` | Alt* | GitHub App ID |
| `GITHUB_APP_PRIVATE_KEY_PATH` | Alt* | Path to GitHub App private key PEM file |
| `GITHUB_APP_INSTALLATION_ID` | Alt* | GitHub App installation ID |
| `GITHUB_API_URL` | Optional | API base URL (default: `https://api.github.com`; set for GHES) |
| `GITHUB_GRAPHQL_URL` | Optional | GraphQL URL (default: `https://api.github.com/graphql`) |

*Either `GITHUB_TOKEN` or all three `GITHUB_APP_*` variables are required.

## 4. Security Controls

### Identity & Authentication

| # | Control | Severity | What Is Checked |
|---|---------|----------|-----------------|
| 1 | **SAML SSO Enforcement** | Critical | Verify SAML SSO is configured and enforced for the organization via GraphQL `samlIdentityProvider`; check that all members have active SAML identity bindings |
| 2 | **Two-Factor Authentication Requirement** | Critical | Verify `two_factor_requirement_enabled` is `true` on the organization; enumerate members without 2FA via `/orgs/{org}/members?filter=2fa_disabled` |
| 3 | **Enterprise Managed Users (EMU)** | High | Detect whether the organization uses EMU (managed by enterprise IdP); check enterprise user account bindings via GraphQL |
| 4 | **IP Allow List** | High | Via GraphQL, verify `ipAllowListEnabledSetting` is `ENABLED`; enumerate allow list entries; check `ipAllowListForInstalledAppsEnabledSetting` |

### Organization Permissions & Policies

| # | Control | Severity | What Is Checked |
|---|---------|----------|-----------------|
| 5 | **Member Base Permissions** | High | Check `default_repository_permission` on the org object; flag if set to `write` or `admin` (should be `read` or `none`) |
| 6 | **Repository Visibility Defaults** | Medium | Check `members_can_create_public_repositories`; verify `members_can_create_private_repositories` and `members_can_create_internal_repositories` policies |
| 7 | **Fork Policy** | Medium | Check `members_can_fork_private_repositories`; flag if private repo forking is unrestricted |
| 8 | **Outside Collaborator Policy** | High | Enumerate outside collaborators via `/orgs/{org}/outside_collaborators`; flag excessive external access; check if admin approval is required |
| 9 | **OAuth App Restrictions** | High | Verify OAuth application access policy is set to restricted; check `/orgs/{org}/credential-authorizations` for unauthorized OAuth apps |

### Repository & Code Protection

| # | Control | Severity | What Is Checked |
|---|---------|----------|-----------------|
| 10 | **Branch Protection Rules** | Critical | For every repo's default branch, verify protection is enabled; check `requiresApprovingReviews`, `isAdminEnforced`, `allowsForcePushes=false`, `allowsDeletions=false` |
| 11 | **Required Pull Request Reviews** | High | Verify `requiredApprovingReviewCount >= 1`; check `requiresCodeOwnerReviews`, `dismissesStaleReviews`, `restrictsReviewDismissals` |
| 12 | **Required Status Checks** | High | Verify `requiresStatusChecks=true` with specific required contexts; flag repos with no CI checks |
| 13 | **Signed Commit Requirement** | Medium | Check `requiresCommitSignatures` on branch protection; flag repos where unsigned commits are allowed on protected branches |
| 14 | **Repository Rulesets** | Medium | Enumerate org-level and repo-level rulesets; verify they enforce branch protection, tag protection, and push restrictions |

### Code Security Features (GHAS)

| # | Control | Severity | What Is Checked |
|---|---------|----------|-----------------|
| 15 | **Code Scanning Enabled** | High | Verify code scanning (CodeQL or third-party) is configured on all repositories; count open critical/high alerts via `/orgs/{org}/code-scanning/alerts` |
| 16 | **Secret Scanning Enabled** | Critical | Verify secret scanning is enabled on all repositories; check push protection is enabled; count open alerts via `/orgs/{org}/secret-scanning/alerts` |
| 17 | **Dependabot Enabled** | High | Verify Dependabot alerts and security updates are enabled; count open critical/high alerts via `/orgs/{org}/dependabot/alerts` |
| 18 | **Security Policy** | Low | Check each repo has a `SECURITY.md` or `securityPolicyUrl` configured |

### Audit & Monitoring

| # | Control | Severity | What Is Checked |
|---|---------|----------|-----------------|
| 19 | **Audit Log Streaming** | High | Verify audit log streaming is configured to an external SIEM; check via enterprise settings or audit log API |
| 20 | **Webhook Security** | High | Audit all organization webhooks; flag webhooks without `secret` configured, webhooks with `insecure_ssl=1`, webhooks sending to non-HTTPS URLs |

### Actions & CI/CD Security

| # | Control | Severity | What Is Checked |
|---|---------|----------|-----------------|
| 21 | **Actions Permissions** | High | Check org-level Actions permissions; flag if `allowed_actions` is `all` (should be `selected` or `local_only`); verify `default_workflow_permissions` is `read` not `write` |
| 22 | **Runner Group Restrictions** | Medium | Audit self-hosted runner groups; flag runners accessible to all repos; verify runner group repository access restrictions |
| 23 | **Deploy Key Management** | Medium | Enumerate deploy keys across all repos; flag keys with write access; flag keys older than 365 days without rotation |
| 24 | **GitHub App Permissions Audit** | High | Enumerate all GitHub App installations; flag apps with excessive permissions (admin access, write to all repos); check for inactive/unused apps |
| 25 | **Package Registry Access** | Medium | Audit package visibility settings; flag packages with public visibility in private organizations; check package access inheritance |

## 5. Compliance Framework Mappings

| # | Control | FedRAMP (800-53 r5) | CMMC 2.0 | SOC 2 (TSC) | CIS GitHub Benchmark | PCI-DSS 4.0 | DISA STIG | IRAP (ISM) | ISMAP |
|---|---------|---------------------|----------|-------------|---------------------|-------------|-----------|------------|-------|
| 1 | SAML SSO Enforcement | IA-2, IA-8 | AC.L2-3.1.1 | CC6.1 | 1.1.1 | 8.3.1 | SRG-APP-000148 | ISM-1557 | 5.1.1 |
| 2 | Two-Factor Authentication | IA-2(1), IA-2(2) | IA.L2-3.5.3 | CC6.1 | 1.1.2 | 8.4.2 | SRG-APP-000149 | ISM-1401 | 5.1.2 |
| 3 | Enterprise Managed Users | IA-2, IA-5 | IA.L2-3.5.1 | CC6.1 | 1.1.3 | 8.2.1 | SRG-APP-000163 | ISM-1558 | 5.1.3 |
| 4 | IP Allow List | SC-7, AC-17 | SC.L2-3.13.1 | CC6.1, CC6.6 | 1.2.1 | 1.3.1 | SRG-APP-000142 | ISM-1416 | 5.1.4 |
| 5 | Member Base Permissions | AC-3, AC-6 | AC.L2-3.1.5 | CC6.3 | 1.3.1 | 7.2.1 | SRG-APP-000033 | ISM-1508 | 5.2.1 |
| 6 | Repository Visibility Defaults | AC-3, AC-22 | AC.L2-3.1.22 | CC6.1 | 1.3.2 | 7.2.2 | SRG-APP-000211 | ISM-0264 | 5.2.2 |
| 7 | Fork Policy | AC-3, AC-4 | AC.L2-3.1.3 | CC6.1 | 1.3.3 | 7.2.3 | SRG-APP-000033 | ISM-0405 | 5.2.3 |
| 8 | Outside Collaborator Policy | AC-2, AC-6(5) | AC.L2-3.1.6 | CC6.2, CC6.3 | 1.3.4 | 7.2.4 | SRG-APP-000340 | ISM-1509 | 5.2.4 |
| 9 | OAuth App Restrictions | AC-3, AC-6 | AC.L2-3.1.5 | CC6.6, CC6.8 | 1.4.1 | 6.3.2 | SRG-APP-000386 | ISM-1490 | 5.2.5 |
| 10 | Branch Protection Rules | CM-3, SI-7 | CM.L2-3.4.5 | CC8.1 | 2.1.1 | 6.5.1 | SRG-APP-000133 | ISM-1072 | 5.3.1 |
| 11 | Required Pull Request Reviews | CM-3, CM-5 | CM.L2-3.4.5 | CC8.1 | 2.1.2 | 6.5.2 | SRG-APP-000381 | ISM-1525 | 5.3.2 |
| 12 | Required Status Checks | SI-7, SA-11 | SA.L2-3.13.10 | CC8.1 | 2.1.3 | 6.5.3 | SRG-APP-000456 | ISM-1525 | 5.3.3 |
| 13 | Signed Commit Requirement | SI-7(6) | SI.L2-3.14.1 | CC8.1 | 2.1.4 | 6.5.4 | SRG-APP-000411 | ISM-1072 | 5.3.4 |
| 14 | Repository Rulesets | CM-3, CM-5 | CM.L2-3.4.5 | CC8.1 | 2.1.5 | 6.5.5 | SRG-APP-000133 | ISM-1072 | 5.3.5 |
| 15 | Code Scanning Enabled | RA-5, SA-11 | RA.L2-3.11.2 | CC7.1 | 3.1.1 | 6.5.6 | SRG-APP-000456 | ISM-1163 | 5.4.1 |
| 16 | Secret Scanning Enabled | IA-5(7), SC-12 | SC.L2-3.13.10 | CC6.1, CC7.1 | 3.1.2 | 6.5.7 | SRG-APP-000175 | ISM-1590 | 5.4.2 |
| 17 | Dependabot Enabled | RA-5, SI-2 | RA.L2-3.11.2 | CC7.1 | 3.1.3 | 6.3.3 | SRG-APP-000456 | ISM-1163 | 5.4.3 |
| 18 | Security Policy | PL-2, IR-8 | IR.L2-3.6.1 | CC2.2 | 3.1.4 | 12.10.1 | SRG-APP-000516 | ISM-0043 | 5.4.4 |
| 19 | Audit Log Streaming | AU-2, AU-6, SI-4 | AU.L2-3.3.1 | CC7.2, CC7.3 | 4.1.1 | 10.2.1 | SRG-APP-000095 | ISM-0580 | 5.5.1 |
| 20 | Webhook Security | SC-8, SI-4 | SC.L2-3.13.8 | CC6.7 | 4.1.2 | 4.2.1 | SRG-APP-000439 | ISM-1139 | 5.5.2 |
| 21 | Actions Permissions | CM-7, AC-3 | CM.L2-3.4.7 | CC6.8, CC8.1 | 5.1.1 | 6.3.2 | SRG-APP-000386 | ISM-1490 | 5.6.1 |
| 22 | Runner Group Restrictions | AC-3, CM-7 | AC.L2-3.1.3 | CC6.3 | 5.1.2 | 7.2.5 | SRG-APP-000033 | ISM-0405 | 5.6.2 |
| 23 | Deploy Key Management | IA-5, SC-12 | IA.L2-3.5.10 | CC6.1, CC6.6 | 5.2.1 | 8.6.3 | SRG-APP-000175 | ISM-1590 | 5.6.3 |
| 24 | GitHub App Permissions Audit | AC-6(10), CM-11 | AC.L2-3.1.7 | CC6.3, CC6.8 | 5.2.2 | 6.3.2 | SRG-APP-000342 | ISM-1490 | 5.6.4 |
| 25 | Package Registry Access | AC-3, AC-22 | AC.L2-3.1.22 | CC6.1 | 5.3.1 | 7.2.6 | SRG-APP-000211 | ISM-0264 | 5.6.5 |

## 6. Existing Tools

| Tool | Type | Relevance |
|------|------|-----------|
| **github/safe-settings** | GitHub App | Declarative repo/org settings management via YAML; enforces branch protection, collaborators, labels, and org settings; apply-and-drift-detect model |
| **ossf/allstar** | GitHub App | OpenSSF project for continuous security policy enforcement; checks branch protection, binary artifacts, CI tests, pinned dependencies, SECURITY.md, admin access |
| **ossf/scorecard** | CLI / GitHub Action | OpenSSF Scorecard assesses 18+ security heuristics (branch protection, code review, dependency pinning, fuzzing, SAST, signed releases, etc.); assigns 0-10 score per check |
| **github/codeql-action** | GitHub Action | CodeQL static analysis for code scanning; detects vulnerabilities in supported languages |
| **trufflesecurity/trufflehog** | CLI | Secret scanning across git history, live endpoints, and filesystems |
| **aquasecurity/trivy** | CLI | Vulnerability scanner for code repos, container images, IaC; includes GitHub integration |
| **bridgecrewio/checkov** | CLI | IaC and supply chain scanner; includes GitHub Actions workflow checks |
| **Legit Security** | SaaS | Commercial SDLC security platform with GitHub security posture management |
| **Apiiro** | SaaS | Risk-based application security platform with GitHub integration |
| **GitGuardian** | SaaS/CLI | Secret detection and remediation for GitHub repos |
| **Terraform GitHub Provider** | IaC | `integrations/github` Terraform provider for declarative management of GitHub settings as code |

## 7. Architecture

The project is written in Go and mirrors the modular architecture of [okta-inspector-py](https://github.com/hackIDLE/okta-inspector-py).

```
github-sec-inspector/
├── cmd/
│   └── github-sec-inspector/
│       └── main.go                  # Entrypoint, CLI parsing, orchestration
├── internal/
│   ├── client/
│   │   ├── client.go                # Unified client (REST + GraphQL)
│   │   ├── rest.go                  # REST API v3 client (wraps go-github)
│   │   ├── graphql.go               # GraphQL API v4 client (wraps shurcooL/githubv4)
│   │   ├── auth.go                  # PAT, GitHub App, and OAuth authentication
│   │   └── ratelimit.go             # Rate limiting, retry, and pagination helpers
│   ├── collector/
│   │   ├── collector.go             # Top-level data collector orchestrator
│   │   ├── org.go                   # Collect org settings, member policies, teams
│   │   ├── members.go               # Collect members, 2FA status, SAML identities
│   │   ├── repos.go                 # Collect repositories and visibility settings
│   │   ├── branches.go              # Collect branch protection rules and rulesets
│   │   ├── security.go              # Collect GHAS: code scanning, secret scanning, Dependabot
│   │   ├── actions.go               # Collect Actions permissions, runners, workflows
│   │   ├── apps.go                  # Collect GitHub App installations, OAuth apps
│   │   ├── webhooks.go              # Collect organization webhooks
│   │   ├── keys.go                  # Collect deploy keys across repos
│   │   ├── packages.go              # Collect package registry configurations
│   │   ├── audit.go                 # Collect audit log events and streaming config
│   │   └── enterprise.go            # Collect enterprise-level settings (if applicable)
│   ├── models/
│   │   ├── githubdata.go            # GitHubData: container for all collected API data
│   │   ├── finding.go               # ComplianceFinding: individual check result
│   │   └── result.go                # AuditResult: aggregated audit output
│   ├── analyzers/
│   │   ├── base.go                  # Analyzer interface and registry
│   │   ├── common.go                # Shared analysis helpers
│   │   ├── fedramp.go               # FedRAMP (NIST 800-53 r5) analyzer
│   │   ├── cmmc.go                  # CMMC 2.0 analyzer
│   │   ├── soc2.go                  # SOC 2 (TSC) analyzer
│   │   ├── cis.go                   # CIS GitHub Benchmark analyzer
│   │   ├── pci_dss.go               # PCI-DSS 4.0 analyzer
│   │   ├── stig.go                  # DISA STIG analyzer
│   │   ├── irap.go                  # IRAP (ISM) analyzer
│   │   └── ismap.go                 # ISMAP analyzer
│   ├── reporters/
│   │   ├── base.go                  # Reporter interface and registry
│   │   ├── executive.go             # Executive summary (pass/fail counts, risk score)
│   │   ├── matrix.go                # Cross-framework compliance matrix
│   │   ├── fedramp.go               # FedRAMP-formatted report
│   │   ├── cmmc.go                  # CMMC-formatted report
│   │   ├── soc2.go                  # SOC 2 formatted report
│   │   ├── cis.go                   # CIS benchmark report
│   │   ├── pci_dss.go               # PCI-DSS 4.0 report
│   │   ├── stig.go                  # DISA STIG checklist (CKL/XCCDF)
│   │   ├── irap.go                  # IRAP assessment report
│   │   ├── ismap.go                 # ISMAP assessment report
│   │   └── validation.go            # Finding validation and deduplication
│   ├── engine/
│   │   └── engine.go                # AuditEngine: collect → analyze → report → archive
│   └── tui/
│       ├── app.go                   # Bubble Tea TUI application
│       ├── components/
│       │   ├── spinner.go           # Progress spinner
│       │   ├── table.go             # Results table
│       │   └── summary.go           # Summary dashboard
│       └── views/
│           ├── audit.go             # Audit progress view
│           └── results.go           # Results browser view
├── testdata/
│   ├── fixtures/                    # Mock API response JSON files
│   └── golden/                      # Golden file test outputs
├── go.mod
├── go.sum
├── Makefile
├── Dockerfile
├── .goreleaser.yml
├── .github/
│   └── workflows/
│       ├── ci.yml                   # Lint, test, build
│       └── release.yml              # GoReleaser publish
├── COPYING                          # GPL v3
├── README.md
└── spec.md                          # This file
```

### Data Flow

```
┌──────────────────┐     ┌──────────────┐     ┌────────────┐     ┌────────────┐
│      Client      │────>│  Collector   │────>│  Analyzers │────>│  Reporters │
│ (REST + GraphQL) │     │ (GitHubData) │     │ (Findings) │     │ (Reports)  │
└──────────────────┘     └──────────────┘     └────────────┘     └────────────┘
       │                                             │
       │               ┌────────────┐                │
       └──────────────>│   Engine   │<───────────────┘
                       │ (Orchestr.)│
                       └────────────┘
```

## 8. CLI Interface

```bash
# Basic audit with personal access token
github-sec-inspector audit \
  --org your-organization \
  --token $GITHUB_TOKEN

# Audit with GitHub App authentication
github-sec-inspector audit \
  --org your-organization \
  --app-id 12345 \
  --app-private-key /path/to/private-key.pem \
  --app-installation-id 67890

# Include enterprise-level checks
github-sec-inspector audit \
  --org your-organization \
  --enterprise your-enterprise \
  --token $GITHUB_TOKEN

# Run only specific frameworks
github-sec-inspector audit \
  --org your-organization \
  --token $GITHUB_TOKEN \
  --frameworks fedramp,stig,pci-dss

# Audit specific repositories only
github-sec-inspector audit \
  --org your-organization \
  --token $GITHUB_TOKEN \
  --repos repo1,repo2,repo3

# Output to custom directory
github-sec-inspector audit \
  --org your-organization \
  --token $GITHUB_TOKEN \
  --output-dir ./github-audit-results

# JSON-only output (no TUI)
github-sec-inspector audit \
  --org your-organization \
  --token $GITHUB_TOKEN \
  --format json \
  --quiet

# List available frameworks
github-sec-inspector frameworks

# Validate connectivity and permissions
github-sec-inspector validate \
  --org your-organization \
  --token $GITHUB_TOKEN

# Scan a single repository
github-sec-inspector repo \
  --owner your-organization \
  --repo your-repo \
  --token $GITHUB_TOKEN

# Environment variable usage
export GITHUB_TOKEN="ghp_..."
export GITHUB_ORG="your-organization"
export GITHUB_ENTERPRISE="your-enterprise"
github-sec-inspector audit
```

## 9. Build Sequence

### Phase 1 — Foundation (Weeks 1-2)
- [ ] Initialize Go module, project scaffolding, CI/CD pipeline
- [ ] Implement `internal/client/` — REST and GraphQL clients with PAT and GitHub App auth
- [ ] Implement `internal/models/` — `GitHubData`, `ComplianceFinding`, `AuditResult`
- [ ] Implement `internal/collector/org.go`, `members.go` — org settings, member enumeration, 2FA status
- [ ] Write unit tests with mock API responses in `testdata/fixtures/`

### Phase 2 — Core Analyzers (Weeks 3-4)
- [ ] Implement `internal/analyzers/base.go` — analyzer interface and registry
- [ ] Implement controls 1-9 (identity, authentication, org permissions)
- [ ] Implement `internal/collector/repos.go`, `branches.go` — repo enumeration and branch protection
- [ ] Implement controls 10-14 (repository and code protection)
- [ ] Build first analyzer: `fedramp.go`
- [ ] Build `stig.go` and `cmmc.go` analyzers

### Phase 3 — GHAS & Actions (Weeks 5-6)
- [ ] Implement `internal/collector/security.go` — code scanning, secret scanning, Dependabot
- [ ] Implement `internal/collector/actions.go`, `apps.go`, `webhooks.go`, `keys.go`
- [ ] Implement controls 15-25 (GHAS, audit, Actions, apps, packages)
- [ ] Build remaining analyzers: `soc2.go`, `cis.go`, `pci_dss.go`, `irap.go`, `ismap.go`

### Phase 4 — Reporting & CLI (Weeks 7-8)
- [ ] Implement `internal/reporters/` — all report formatters
- [ ] Implement `internal/engine/engine.go` — orchestration pipeline
- [ ] Implement `cmd/github-sec-inspector/main.go` — CLI with cobra or stdlib flags
- [ ] STIG CKL/XCCDF export support
- [ ] JSON, CSV, and Markdown output formats

### Phase 5 — TUI & Polish (Weeks 9-10)
- [ ] Implement `internal/tui/` — Bubble Tea interactive interface
- [ ] Implement GraphQL-based collectors for SAML, IP allow list, enterprise data
- [ ] Dockerfile and GoReleaser configuration
- [ ] Integration tests against a GitHub organization
- [ ] Documentation, README, and usage examples
- [ ] Golden file tests for report output stability

## 10. Status

**Not yet implemented. Spec only.**
