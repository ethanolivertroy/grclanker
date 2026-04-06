---
slug: "crowdstrike-sec-inspector"
name: "CrowdStrike Security Inspector"
vendor: "CrowdStrike"
category: "security-network-infrastructure"
language: "go"
status: "spec-only"
version: "1.0"
last_updated: "2026-03-29"
source_repo: "https://github.com/hackIDLE/crowdstrike-sec-inspector"
---

# crowdstrike-sec-inspector

Multi-framework security compliance audit tool for CrowdStrike Falcon.

## 1. Overview

CrowdStrike Falcon is a cloud-native endpoint detection and response (EDR) platform that provides next-generation antivirus (NGAV), threat intelligence, device control, firewall management, and identity protection. It is the dominant commercial endpoint security platform across federal, enterprise, and regulated environments.

Security compliance auditing of CrowdStrike Falcon matters because:

- **Prevention policy misconfiguration** is the single most common cause of endpoint protection gaps — ML detection levels, exploit mitigation, and script-based execution controls must be validated against organizational baselines.
- **Policy precedence is order-based**, meaning a permissive policy higher in the list silently overrides a restrictive one lower down. Without automated auditing, these ordering errors go undetected.
- **Sensor deployment coverage gaps** (hosts not enrolled, sensors out of date, hosts not assigned to policy groups) create blind spots that attackers exploit.
- **Response policy drift** (RTR disabled, custom scripts allowed, session timeouts extended) weakens incident response capability over time.
- **Device control exceptions** (USB, Thunderbolt, SD card) accumulate and are rarely reviewed.
- **FedRAMP, CMMC, PCI-DSS, and DISA STIG** all require evidence of endpoint protection configuration, and manual evidence collection is slow and error-prone.

This tool automates the extraction, analysis, and reporting of CrowdStrike Falcon security configuration against multiple compliance frameworks.

## 2. APIs & SDKs

### Falcon API Service Collections

CrowdStrike Falcon exposes a RESTful API organized into service collections. The following are the primary collections relevant to security compliance auditing:

| Service Collection | Key Operations | Compliance Relevance |
|---|---|---|
| **Prevention Policies** | `queryCombinedPreventionPolicies`, `getPreventionPolicies` | ML detection levels, exploit mitigation, script control, sensor tamper protection |
| **Response Policies** | `queryCombinedRTResponsePolicies`, `getRTResponsePolicies` | RTR enable/disable, custom scripts, session timeout (15-120 min), concurrent sessions (1-10) |
| **Device Control Policies** | `queryCombinedDeviceControlPolicies`, `getDeviceControlPolicies` | USB, SD card, Bluetooth, Thunderbolt blocking/allowing |
| **Firewall Management** | `query_rules`, `get_rules`, `query_rule_groups`, `query_policy_rules` | Host-based firewall rules, rule groups, policy-to-rule assignments |
| **Sensor Update Policies** | `queryCombinedSensorUpdatePolicies`, `getSensorUpdatePolicies` | Sensor version pinning per platform (Windows/macOS/Linux), auto-update settings, up to 100 custom policies |
| **Host Groups** | `queryCombinedHostGroups`, `getHostGroups` | Static, Dynamic, StaticByID groups — determines policy assignment coverage |
| **Hosts** | `QueryDevicesByFilter`, `GetDeviceDetails` | Asset inventory, sensor version, OS, last seen, containment status |
| **User Management** | `RetrieveUserUUIDsByCID`, `RetrieveUser`, `GetUserRoleIds`, `GetAvailableRoleIds` | RBAC audit, admin enumeration, permission grants |
| **Falcon Discover** | `query_hosts`, `get_hosts` | Managed vs. unmanaged asset visibility, entity_type filtering |
| **Detections** | `QueryDetects`, `GetDetectSummaries`, `UpdateDetectsByIdsV2` | Detection volume, response SLA, status distribution |
| **IOA Exclusions** | `queryIOAExclusionsV1`, `getIOAExclusionsV1` | Indicator of Attack exclusion policies (cl_regex, ifn_regex patterns) |
| **ML Exclusions** | `queryMLExclusionsV1`, `getMLExclusionsV1` | Machine learning detection exceptions |
| **Sensor Visibility Exclusions** | `querySensorVisibilityExclusionsV1`, `getSensorVisibilityExclusionsV1` | Host visibility exclusion policies |
| **Installation Tokens** | `tokens_query`, `tokens_read` | Bulk sensor installation token management |
| **Falcon FileVantage** | `queryPolicies`, `getPolicies` | File integrity monitoring (FIM) policy configuration |
| **Identity Protection** | `api_preempt_proxy_post_graphql` | Identity threat detection, lateral movement prevention |
| **Zero Trust Assessment** | `getAssessmentV1` | Per-host ZTA scores |

### SDKs

| SDK | Language | Package | Notes |
|---|---|---|---|
| **FalconPy** | Python | `crowdstrike-falconpy` (PyPI) | Official SDK, full API coverage, excellent docs at [falconpy.io](https://falconpy.io) |
| **PSFalcon** | PowerShell | PSGallery | Official PowerShell module |
| **crimson-falcon** | Ruby | RubyGems | Community-maintained |
| **Falcon Toolkit** | Python | CLI wrapper | Higher-level CLI tooling over FalconPy |
| **gofalcon** | Go | GitHub | Official Go SDK |
| **rusty-falcon** | Rust | crates.io | Community-maintained |

### API Conventions

- All endpoints use OAuth 2.0 bearer tokens (see Authentication below).
- Pagination: Most query endpoints return resource IDs; use `ids` parameter on detail endpoints to fetch full objects in batches of up to 500.
- Rate limiting: 100 requests/minute for most endpoints; 6000 requests/minute for streaming.
- All responses are JSON with `meta`, `resources`, and `errors` top-level keys.
- Filter syntax (FQL): `platform_name:'Windows'+enabled:'true'` — used across all query endpoints.

## 3. Authentication

### Credential Model

CrowdStrike Falcon uses **API Client ID + Secret** pairs created in:

**Falcon Console > Support and Resources > API Clients and Keys**

Each API client is scoped to specific API permissions (read/write per service collection). The inspector tool requires **read-only** access to all service collections listed in Section 2.

### OAuth 2.0 Flow

```
POST /oauth2/token
Content-Type: application/x-www-form-urlencoded

client_id=<CS_CLIENT_ID>&client_secret=<CS_CLIENT_SECRET>
```

Returns a bearer token valid for 30 minutes. FalconPy handles token refresh automatically.

### Environment Variables

| Variable | Description | Example |
|---|---|---|
| `CS_CLIENT_ID` | API Client ID | `abcdef1234567890abcdef1234567890` |
| `CS_CLIENT_SECRET` | API Client Secret | `AbCdEf1234567890AbCdEf1234567890AbCdEf12` |
| `CS_BASE_URL` | Region-specific base URL | `https://api.crowdstrike.com` |
| `CS_MEMBER_CID` | (Optional) Child CID for MSSP/Flight Control | `ABCDEF1234567890ABCDEF1234567890-12` |

### Regional Endpoints

| Region | Base URL | Notes |
|---|---|---|
| **US-1** | `https://api.crowdstrike.com` | Default commercial cloud |
| **US-2** | `https://api.us-2.crowdstrike.com` | Secondary US commercial cloud |
| **EU-1** | `https://api.eu-1.crowdstrike.com` | European commercial cloud |
| **US-GOV-1** | `https://api.laggar.gcw.crowdstrike.com` | GovCloud (FedRAMP High) |

### FalconPy Authentication Example

```python
from falconpy import APIHarness

falcon = APIHarness(
    client_id=os.environ["CS_CLIENT_ID"],
    client_secret=os.environ["CS_CLIENT_SECRET"],
    base_url=os.environ.get("CS_BASE_URL", "https://api.crowdstrike.com"),
    member_cid=os.environ.get("CS_MEMBER_CID"),
)
```

### MSSP / Flight Control

For managed security service providers, the `member_cid` parameter allows querying child tenants from a parent API client. The inspector supports iterating over all child CIDs for multi-tenant audits.

## 4. Security Controls

The following controls are audited. Each control maps to one or more compliance framework requirements (see Section 5).

| # | Control | API Source | What Is Checked |
|---|---|---|---|
| **CS-01** | Prevention Policy — ML Detection Levels | Prevention Policies | `MLSliderDetectionLevels` and `MLSliderPreventionLevels` are set to `AGGRESSIVE` or `EXTRA_AGGRESSIVE` for all platforms |
| **CS-02** | Prevention Policy — Exploit Mitigation | Prevention Policies | `ExploitMitigation` settings enabled (DEP, ASLR, heap spray, stack pivot, ROP, etc.) |
| **CS-03** | Prevention Policy — Script-Based Execution Control | Prevention Policies | `ScriptBasedExecutionMonitoring`, `InterpreterOnly`, `EngineFull` settings enabled |
| **CS-04** | Prevention Policy — Sensor Tamper Protection | Prevention Policies | `SensorTamperProtection` is enabled |
| **CS-05** | Prevention Policy — On-Write Detection | Prevention Policies | `OnWriteDetection` enabled for all applicable content types |
| **CS-06** | Response Policy — RTR Enabled | Response Policies | Real-Time Response is enabled; `CustomScriptsAllowed` is restricted |
| **CS-07** | Response Policy — Session Limits | Response Policies | Session timeout <= 30 minutes; concurrent sessions <= 3 |
| **CS-08** | Device Control — USB Blocking | Device Control Policies | USB mass storage devices blocked by default; exceptions reviewed |
| **CS-09** | Device Control — Peripheral Restrictions | Device Control Policies | Bluetooth, Thunderbolt, SD card policies configured |
| **CS-10** | Firewall — Host Firewall Enabled | Firewall Management | Firewall rules are defined and assigned to policy groups |
| **CS-11** | Firewall — Default Deny | Firewall Management | Default rule action is DENY; explicit allow rules are documented |
| **CS-12** | Sensor Update — Auto-Update Enabled | Sensor Update Policies | Sensor auto-update is enabled; pinned versions are current (within N-2) |
| **CS-13** | Sensor Coverage — Deployment Completeness | Hosts, Host Groups | Percentage of known assets with active sensors; last-seen within 7 days |
| **CS-14** | Sensor Coverage — Host Group Assignment | Host Groups | Percentage of hosts assigned to at least one group (and therefore receiving policy) |
| **CS-15** | Unmanaged Asset Detection | Falcon Discover | Unmanaged assets identified via network discovery; count and trend |
| **CS-16** | RBAC — Admin Count | User Management | Number of admin-role users; flag if > 5 or if shared accounts detected |
| **CS-17** | RBAC — Least Privilege | User Management | Users have only the roles necessary; flag overprivileged accounts |
| **CS-18** | RBAC — API Client Permissions | User Management | API clients have minimal required scopes; flag write permissions on sensitive collections |
| **CS-19** | Exclusion Review — IOA Exclusions | IOA Exclusions | All IOA exclusions listed; flag broad regex patterns (e.g., `.*`) |
| **CS-20** | Exclusion Review — ML Exclusions | ML Exclusions | All ML exclusions listed; flag path-based exclusions in sensitive directories |
| **CS-21** | Exclusion Review — Sensor Visibility | Sensor Visibility Exclusions | All visibility exclusions listed; flag exclusions that hide entire directories |
| **CS-22** | Detection Response SLA | Detections | Percentage of critical/high detections resolved within 24/72 hours |
| **CS-23** | Containment Policy | Hosts | Hosts under network containment are documented; containment is lifted within SLA |
| **CS-24** | Identity Protection | Identity Protection | Identity protection is enabled; lateral movement prevention is active |
| **CS-25** | Zero Trust Assessment | Zero Trust Assessment | Per-host ZTA scores; flag hosts below organizational threshold |

## 5. Compliance Framework Mappings

Each control maps to requirements across eight compliance frameworks:

| Control | FedRAMP | CMMC 2.0 | SOC 2 | CIS | PCI-DSS 4.0 | DISA STIG | IRAP | ISMAP |
|---|---|---|---|---|---|---|---|---|
| **CS-01** ML Detection Levels | SI-3, SI-3(1) | SI.L2-3.14.2 | CC6.8 | CIS 10.1 | 5.2 | V-256374 | ISM-1417 | 8.1.1 |
| **CS-02** Exploit Mitigation | SI-16 | SI.L2-3.14.7 | CC6.8 | CIS 10.5 | 5.2 | V-256375 | ISM-1490 | 8.1.1 |
| **CS-03** Script Execution Control | CM-7(2) | CM.L2-3.4.7 | CC6.8 | CIS 2.7 | 5.2 | V-256376 | ISM-1490 | 8.1.2 |
| **CS-04** Sensor Tamper Protection | SC-7(12), SI-7 | SI.L2-3.14.6 | CC6.1 | CIS 10.4 | 5.2.3 | V-256377 | ISM-1418 | 8.1.1 |
| **CS-05** On-Write Detection | SI-3 | SI.L2-3.14.2 | CC6.8 | CIS 10.1 | 5.2 | V-256374 | ISM-1417 | 8.1.1 |
| **CS-06** RTR Enabled | IR-4, IR-5 | IR.L2-3.6.1 | CC7.3 | CIS 10.7 | 12.10 | V-256378 | ISM-0576 | 7.1.1 |
| **CS-07** Session Limits | AC-12, SC-10 | AC.L2-3.1.11 | CC6.1 | CIS 5.6 | 8.2.8 | V-256379 | ISM-1164 | 5.1.2 |
| **CS-08** USB Blocking | MP-7 | MP.L2-3.8.7 | CC6.4 | CIS 10.3 | 9.5 | V-256380 | ISM-0340 | 11.1.1 |
| **CS-09** Peripheral Restrictions | MP-7 | MP.L2-3.8.7 | CC6.4 | CIS 10.3 | 9.5 | V-256380 | ISM-0340 | 11.1.1 |
| **CS-10** Host Firewall Enabled | SC-7 | SC.L2-3.13.1 | CC6.6 | CIS 4.8 | 1.3 | V-256381 | ISM-1416 | 10.1.1 |
| **CS-11** Default Deny | SC-7(5) | SC.L2-3.13.6 | CC6.6 | CIS 4.8 | 1.2.1 | V-256382 | ISM-1416 | 10.1.1 |
| **CS-12** Sensor Auto-Update | SI-2 | SI.L2-3.14.1 | CC6.8 | CIS 10.2 | 6.3 | V-256383 | ISM-1143 | 8.2.1 |
| **CS-13** Deployment Completeness | CM-8 | CM.L2-3.4.1 | CC6.1 | CIS 1.1 | 2.4 | V-256384 | ISM-1301 | 6.1.1 |
| **CS-14** Host Group Assignment | CM-8, CM-6 | CM.L2-3.4.2 | CC6.1 | CIS 1.1 | 2.4 | V-256384 | ISM-1301 | 6.1.1 |
| **CS-15** Unmanaged Assets | CM-8(3) | CM.L2-3.4.1 | CC6.1 | CIS 1.1 | 2.4 | V-256385 | ISM-1301 | 6.1.1 |
| **CS-16** Admin Count | AC-6(5) | AC.L2-3.1.7 | CC6.3 | CIS 5.1 | 7.2 | V-256386 | ISM-1380 | 5.2.1 |
| **CS-17** Least Privilege | AC-6 | AC.L2-3.1.5 | CC6.3 | CIS 5.4 | 7.2.2 | V-256387 | ISM-1380 | 5.2.1 |
| **CS-18** API Client Permissions | AC-6(10) | AC.L2-3.1.7 | CC6.3 | CIS 5.4 | 7.2.2 | V-256388 | ISM-1380 | 5.2.1 |
| **CS-19** IOA Exclusions | SI-3(10), CM-7 | SI.L2-3.14.2 | CC6.8 | CIS 10.6 | 5.2.3 | V-256389 | ISM-1417 | 8.1.3 |
| **CS-20** ML Exclusions | SI-3(10) | SI.L2-3.14.2 | CC6.8 | CIS 10.6 | 5.2.3 | V-256389 | ISM-1417 | 8.1.3 |
| **CS-21** Sensor Visibility Exclusions | SI-4(2) | SI.L2-3.14.6 | CC7.2 | CIS 10.6 | 5.2.3 | V-256390 | ISM-1418 | 8.1.3 |
| **CS-22** Detection Response SLA | IR-4(1), IR-6 | IR.L2-3.6.2 | CC7.3 | CIS 17.4 | 12.10.1 | V-256391 | ISM-0123 | 7.1.2 |
| **CS-23** Containment Policy | IR-4, SC-7(20) | IR.L2-3.6.1 | CC7.4 | CIS 17.8 | 12.10 | V-256392 | ISM-0576 | 7.1.1 |
| **CS-24** Identity Protection | IA-2, IA-5 | IA.L2-3.5.1 | CC6.1 | CIS 6.1 | 8.3 | V-256393 | ISM-1557 | 5.3.1 |
| **CS-25** Zero Trust Assessment | RA-5, CA-7 | CA.L2-3.12.3 | CC7.1 | CIS 1.3 | 11.3 | V-256394 | ISM-1526 | 6.2.1 |

## 6. Existing Tools

### CrowdStrike Native

| Tool | Description | Limitations |
|---|---|---|
| **Falcon Compliance** | Built-in compliance dashboard in Falcon Console | Limited to CIS benchmarks for OS-level settings; does not audit Falcon's own configuration |
| **Falcon Spotlight** | Vulnerability management module | Focuses on CVE/patch compliance, not Falcon policy configuration |
| **Falcon Exposure Management** | Attack surface management | Asset discovery, not policy auditing |
| **CrowdStrike Reporting** | Executive and operational dashboards | Pre-built reports; not customizable for multi-framework mapping |
| **Falcon LogScale (Humio)** | Log aggregation and SIEM | Raw event data; requires custom queries for compliance evidence |

### Third-Party

| Tool | Description | Limitations |
|---|---|---|
| **Drata / Vanta / Secureframe** | Automated compliance platforms | Generic CrowdStrike integration checks "is it installed?"; do not audit policy settings |
| **SCUBA (CISA)** | SaaS security configuration scanner | Supports M365, Google Workspace — does not cover CrowdStrike |
| **ScubaGoggles** | Google Workspace security audit | Not applicable to CrowdStrike |

### Gap This Tool Fills

No existing tool audits CrowdStrike Falcon's **own security configuration** (prevention policies, response policies, device control, firewall rules, RBAC, exclusions) against **multiple compliance frameworks simultaneously**. This is the gap `crowdstrike-sec-inspector` fills.

## 7. Architecture

The project follows the same package layout as [okta-inspector](https://github.com/ethanolivertroy/okta-inspector), adapted for CrowdStrike Falcon.

```
crowdstrike-sec-inspector/
├── spec.md                          # This file
├── pyproject.toml                   # Project metadata, dependencies (falconpy, rich, click)
├── README.md                        # User-facing documentation
├── COPYING                          # License
├── src/
│   └── crowdstrike_inspector/
│       ├── __init__.py              # Package version
│       ├── __main__.py              # python -m crowdstrike_inspector
│       ├── cli.py                   # Click CLI entrypoint
│       ├── client.py                # FalconPy API wrapper (auth, pagination, error handling)
│       ├── collector.py             # Data collection orchestrator (calls client, caches results)
│       ├── engine.py                # Audit engine (runs analyzers, collects findings)
│       ├── models.py                # Pydantic models (Finding, Severity, ControlResult, AuditReport)
│       ├── output.py                # Output formatting (JSON, rich table, CSV)
│       ├── analyzers/
│       │   ├── __init__.py
│       │   ├── base.py              # BaseAnalyzer ABC
│       │   ├── common.py            # Shared utility functions
│       │   ├── fedramp.py           # FedRAMP-specific analysis
│       │   ├── cmmc.py              # CMMC 2.0 analysis
│       │   ├── soc2.py              # SOC 2 analysis
│       │   ├── pci_dss.py           # PCI-DSS 4.0 analysis
│       │   ├── stig.py              # DISA STIG analysis
│       │   ├── cis.py               # CIS Benchmark analysis
│       │   ├── irap.py              # IRAP (Australia) analysis
│       │   └── ismap.py             # ISMAP (Japan) analysis
│       └── reporters/
│           ├── __init__.py
│           ├── base.py              # BaseReporter ABC
│           ├── executive.py         # Executive summary (pass/fail counts, risk score)
│           ├── matrix.py            # Cross-framework control matrix
│           ├── validation.py        # Evidence validation for auditors
│           ├── fedramp.py           # FedRAMP SSP evidence format
│           ├── cmmc.py              # CMMC assessment evidence
│           ├── soc2.py              # SOC 2 evidence format
│           ├── pci_dss.py           # PCI-DSS ROC evidence
│           ├── stig.py              # DISA STIG checklist (CKL/XCCDF)
│           ├── cis.py               # CIS benchmark report
│           ├── irap.py              # IRAP evidence format
│           └── ismap.py             # ISMAP evidence format
├── tests/
│   ├── conftest.py                  # Shared fixtures, mock API responses
│   ├── test_client.py
│   ├── test_collector.py
│   ├── test_engine.py
│   ├── test_analyzers/
│   │   └── ...
│   └── test_reporters/
│       └── ...
└── testdata/
    ├── prevention_policies.json     # Sample API responses for testing
    ├── response_policies.json
    ├── device_control_policies.json
    ├── firewall_rules.json
    ├── sensor_update_policies.json
    ├── host_groups.json
    ├── hosts.json
    ├── users.json
    ├── detections.json
    └── exclusions.json
```

### Key Design Decisions

1. **FalconPy as the sole API dependency** — no raw HTTP calls. FalconPy handles auth, token refresh, pagination, and regional routing.
2. **Collector caches all API responses** before analysis begins, enabling offline re-analysis and reproducible audits.
3. **Analyzers are stateless functions** — they receive collected data and return `Finding` objects. Each analyzer maps to one compliance framework.
4. **Reporters transform findings into framework-specific output formats** (JSON, Markdown, CKL, CSV).
5. **Pydantic models** for all data structures ensure type safety and serialization.

## 8. CLI Interface

```bash
# Full audit against all frameworks
crowdstrike-inspector audit --all

# Audit specific frameworks
crowdstrike-inspector audit --frameworks fedramp,cmmc,pci-dss

# Audit specific control categories
crowdstrike-inspector audit --controls prevention,device-control,rbac

# Output formats
crowdstrike-inspector audit --all --format json --output report.json
crowdstrike-inspector audit --all --format csv --output findings.csv
crowdstrike-inspector audit --all --format markdown --output report.md

# STIG checklist output
crowdstrike-inspector audit --frameworks stig --format ckl --output falcon.ckl

# Executive summary only
crowdstrike-inspector audit --all --report executive

# Cross-framework matrix
crowdstrike-inspector audit --all --report matrix

# Multi-tenant (MSSP)
crowdstrike-inspector audit --all --member-cid ABCDEF1234567890ABCDEF1234567890-12
crowdstrike-inspector audit --all --all-tenants

# Specify region
crowdstrike-inspector audit --all --region us-gov-1

# Dry run (validate credentials, list available data)
crowdstrike-inspector check-auth
crowdstrike-inspector list-policies
crowdstrike-inspector list-hosts --count

# Environment variables for auth
export CS_CLIENT_ID="your-client-id"
export CS_CLIENT_SECRET="your-client-secret"
export CS_BASE_URL="https://api.crowdstrike.com"

# Or pass inline
crowdstrike-inspector audit --all \
  --client-id "$CS_CLIENT_ID" \
  --client-secret "$CS_CLIENT_SECRET" \
  --base-url "https://api.laggar.gcw.crowdstrike.com"
```

## 9. Build Sequence

### Phase 1: Foundation

- [ ] Project scaffolding (pyproject.toml, src layout, CLI skeleton)
- [ ] FalconPy client wrapper with auth, pagination, and error handling
- [ ] Pydantic models for findings, controls, and reports
- [ ] Data collector for Prevention Policies and Response Policies
- [ ] Test fixtures with sample API responses

### Phase 2: Core Prevention & Response Controls (CS-01 through CS-07)

- [ ] Prevention policy analyzer (ML levels, exploit mitigation, script control, tamper protection, on-write detection)
- [ ] Response policy analyzer (RTR settings, session limits)
- [ ] FedRAMP mapping for prevention and response controls
- [ ] JSON and Markdown output reporters
- [ ] Unit tests with mocked API responses

### Phase 3: Device Control & Firewall (CS-08 through CS-11)

- [ ] Device control policy collector and analyzer
- [ ] Firewall management collector and analyzer
- [ ] CMMC and PCI-DSS framework mappings
- [ ] CSV output reporter

### Phase 4: Sensor & Asset Management (CS-12 through CS-15)

- [ ] Sensor update policy collector and analyzer
- [ ] Host inventory collector (sensor version, last seen, containment status)
- [ ] Host group coverage analysis
- [ ] Falcon Discover integration for unmanaged assets
- [ ] SOC 2 framework mapping

### Phase 5: RBAC & Exclusions (CS-16 through CS-21)

- [ ] User management collector and analyzer
- [ ] API client permissions audit
- [ ] IOA, ML, and sensor visibility exclusion collectors and analyzers
- [ ] DISA STIG framework mapping and CKL reporter
- [ ] CIS benchmark mapping

### Phase 6: Detection & Response (CS-22 through CS-25)

- [ ] Detection API integration and response SLA analysis
- [ ] Containment policy audit
- [ ] Identity protection status check
- [ ] Zero Trust Assessment integration
- [ ] IRAP and ISMAP framework mappings

### Phase 7: Advanced Features

- [ ] Executive summary reporter with risk scoring
- [ ] Cross-framework control matrix reporter
- [ ] MSSP multi-tenant audit support (iterate child CIDs)
- [ ] Evidence validation reporter for auditors
- [ ] Offline mode (audit from cached/exported data)
- [ ] Delta reporting (compare current vs. previous audit)

### Phase 8: Polish

- [ ] Comprehensive test coverage (>80%)
- [ ] CI/CD pipeline (GitHub Actions)
- [ ] Documentation (README, usage guide, contributing guide)
- [ ] PyPI packaging and distribution
- [ ] Integration tests against CrowdStrike Falcon sandbox (if available)

## 10. Status

**Not yet implemented. Spec only.**

This document defines the architecture, security controls, compliance mappings, and build plan for `crowdstrike-sec-inspector`. No code has been written yet.
