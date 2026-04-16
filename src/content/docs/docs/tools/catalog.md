---
title: Tool Catalog
description: Bundled grclanker GRC and compute tools grouped by domain.
---

`grclanker tools` lists the same bundled extension registration surface the agent uses at runtime. Use `grclanker tools <name>` for detailed parameter help, or `grclanker tools --json` for automation.

Current bundled surface:

- 72 domain tools
- 7 compute backend tools

## Compute Backend

| Tool | Purpose |
|---|---|
| `bash` | bash (compute backend) |
| `edit` | edit (compute backend) |
| `find` | find (compute backend) |
| `grep` | grep (compute backend) |
| `ls` | ls (compute backend) |
| `read` | read (compute backend) |
| `write` | write (compute backend) |

## Ansible AAP

| Tool | Purpose |
|---|---|
| `ansible_assess_host_coverage` | Assess Ansible AAP host coverage |
| `ansible_assess_job_health` | Assess Ansible AAP job health |
| `ansible_assess_platform_security` | Assess Ansible AAP platform security |
| `ansible_check_access` | Check Ansible AAP audit access |
| `ansible_export_audit_bundle` | Export Ansible AAP audit bundle |

## CMVP

| Tool | Purpose |
|---|---|
| `cmvp_get_module` | Get FIPS Module by Certificate Number |
| `cmvp_search_historical` | Search Historical/Expired FIPS Modules |
| `cmvp_search_in_process` | Search FIPS Modules In Process |
| `cmvp_search_modules` | Search FIPS Validated Modules |

## Duo

| Tool | Purpose |
|---|---|
| `duo_assess_admin_access` | Assess Duo admin access |
| `duo_assess_authentication` | Assess Duo authentication posture |
| `duo_assess_integrations` | Assess Duo integrations |
| `duo_assess_monitoring` | Assess Duo monitoring |
| `duo_check_access` | Check Duo audit access |
| `duo_export_audit_bundle` | Export Duo audit bundle |

## FedRAMP

| Tool | Purpose |
|---|---|
| `fedramp_assess_readiness` | Assess FedRAMP readiness |
| `fedramp_check_sources` | Check official FedRAMP sources |
| `fedramp_generate_ads_bundle` | Generate ADS starter bundle |
| `fedramp_generate_ads_site` | Generate ADS public trust-center site |
| `fedramp_get_ksi` | Get official FedRAMP KSI |
| `fedramp_get_process` | Get official FedRAMP process |
| `fedramp_get_requirement` | Get official FedRAMP requirement |
| `fedramp_plan_ads_package` | Plan ADS trust-center package |
| `fedramp_plan_process_artifacts` | Plan FedRAMP process artifacts |
| `fedramp_search_frmr` | Search official FedRAMP FRMR data |

## GitHub

| Tool | Purpose |
|---|---|
| `github_assess_actions_security` | Assess GitHub Actions security |
| `github_assess_code_security` | Assess GitHub code security |
| `github_assess_org_access` | Assess GitHub org access |
| `github_assess_repo_protection` | Assess GitHub repo protection |
| `github_check_access` | Check GitHub audit access |
| `github_export_audit_bundle` | Export GitHub audit bundle |

## Google Workspace

| Tool | Purpose |
|---|---|
| `gws_assess_admin_access` | Assess Google Workspace admin access |
| `gws_assess_identity` | Assess Google Workspace identity posture |
| `gws_assess_integrations` | Assess Google Workspace integrations |
| `gws_assess_monitoring` | Assess Google Workspace monitoring |
| `gws_check_access` | Check Google Workspace audit access |
| `gws_export_audit_bundle` | Export Google Workspace audit bundle |

## Google Workspace Operator

| Tool | Purpose |
|---|---|
| `gws_ops_check_cli` | Check Google Workspace CLI operator bridge |
| `gws_ops_collect_evidence_bundle` | Collect Google Workspace operator evidence bundle |
| `gws_ops_investigate_alerts` | Investigate Google Workspace alerts with gws |
| `gws_ops_review_tokens` | Review Google Workspace token activity with gws |
| `gws_ops_trace_admin_activity` | Trace Google Workspace admin activity with gws |

## KEV / EPSS

| Tool | Purpose |
|---|---|
| `kevs_check_ransomware` | Check Ransomware-Linked Vulnerabilities |
| `kevs_get_epss` | Get EPSS Exploit Probability |
| `kevs_recent` | List Recently Added KEV Entries |
| `kevs_search` | Search Known Exploited Vulnerabilities |

## Okta

| Tool | Purpose |
|---|---|
| `okta_assess_admin_access` | Assess Okta admin access |
| `okta_assess_authentication` | Assess Okta authentication posture |
| `okta_assess_integrations` | Assess Okta integrations |
| `okta_assess_monitoring` | Assess Okta monitoring |
| `okta_check_access` | Check Okta audit access |
| `okta_export_audit_bundle` | Export Okta audit bundle |

## OSCAL

| Tool | Purpose |
|---|---|
| `oscal_assemble_ssp` | Assemble SSP from markdown |
| `oscal_check_trestle` | Check OSCAL trestle setup |
| `oscal_create_model` | Create OSCAL model |
| `oscal_generate_ssp_markdown` | Generate SSP markdown |
| `oscal_import_model` | Import OSCAL model |
| `oscal_init_workspace` | Initialize OSCAL workspace |
| `oscal_validate_model` | Validate OSCAL model |

## SCF

| Tool | Purpose |
|---|---|
| `scf_get_control` | Get SCF control bundle |
| `scf_get_crosswalk` | Get SCF framework crosswalk |
| `scf_get_evidence_request` | Get SCF evidence request |
| `scf_search_controls` | Search SCF controls |

## Slack

| Tool | Purpose |
|---|---|
| `slack_assess_admin_access` | Assess Slack admin access |
| `slack_assess_identity` | Assess Slack identity posture |
| `slack_assess_integrations` | Assess Slack integrations |
| `slack_assess_monitoring` | Assess Slack monitoring |
| `slack_check_access` | Check Slack audit access |
| `slack_export_audit_bundle` | Export Slack audit bundle |

## Vanta

| Tool | Purpose |
|---|---|
| `vanta_check_access` | Check Vanta auditor access |
| `vanta_export_audit` | Export Vanta audit evidence |
| `vanta_list_audits` | List Vanta audits |
