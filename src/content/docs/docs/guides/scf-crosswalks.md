---
title: SCF Crosswalks
description: Search Secure Controls Framework controls, map requirements between frameworks such as NIST SP 800-53 and SOC 2, and get the evidence each control expects.
---

The SCF tools read the [Secure Controls Framework](https://securecontrolsframework.com/) (SCF), a set of more than 1,400 controls with crosswalks to more than 200 laws, regulations, and frameworks. Use them to translate between frameworks: find the SCF control behind a requirement, see what it maps to elsewhere, and get the assessment objectives and evidence an assessor expects. They need no credentials and only read.

## Run it

Start `grclanker` and ask in plain words. The agent calls the matching tools:

```text
Which SCF control covers account management, and what does it map to in NIST SP 800-53 R5?
Which SCF controls does FedRAMP Moderate SI-07(01) map to?
Summarize the SCF crosswalk for ISO 27001.
What assessment objectives and evidence does SCF list for IAC-15?
Get SCF evidence request E-IAM-07.
```

The [audit](/docs/workflows/audit/) workflow uses these tools for control language and crosswalks, and the [assess](/docs/workflows/assess/) workflow uses them for control language.

## Tools

| Tool | Behavior |
| --- | --- |
| `scf_search_controls` | Finds SCF controls by ID, title, family, description, evidence request, or mapped framework control. |
| `scf_get_control` | Returns one control with its assessment objectives and evidence requests, and optionally its mapping in one framework. |
| `scf_get_crosswalk` | Maps controls between SCF and one framework in either direction, or summarizes the whole crosswalk. |
| `scf_get_evidence_request` | Returns one evidence request with its artifact description and the SCF controls it supports. |

## Where the data comes from

The tools read a static JSON API at [hackidle.github.io/scf-api](https://hackidle.github.io/scf-api/), which is rebuilt from official SCF releases. Every search reports the current control total.

Each response is cached in memory for 24 hours, so repeat lookups in one session do not refetch. Nothing is written to disk, and the cache starts empty each time `grclanker` starts. There is no offline copy, so the tools need to reach `hackidle.github.io`.

Results follow the SCF release the API serves, so mappings and counts can differ from the examples on this page.

## Search controls

```text
scf_search_controls {"query":"account management"}
```

It answers with a count, `Found 4 SCF control(s) matching "account management" (of 1468 total).`, and a table of the matches:

| control_id | family | title | evidence_refs |
| --- | --- | --- | --- |
| IAC-15 | IAC | Account Management | E-IAM-07, E-IAM-08 |
| IAC-15.1 | IAC | Automated System Account Management (Directory ... | None |
| IAC-16 | IAC | Privileged Account Management (PAM) | E-IAM-03 |
| IAC-18 | IAC | User Responsibilities for Account Management | None |

Search treats the query as one phrase and ignores case. It looks in each control's ID, title, family, description, SCF question, NIST CSF function, evidence request IDs, and crosswalks, including framework IDs and mapped framework control IDs. Results come back in SCF order, not ranked by relevance.

`limit` defaults to 10 and accepts 1 to 50. The count stops at `limit`, so when the two are equal, raise `limit` to see the rest. Titles longer than 50 characters are shortened, and only the first two evidence requests are listed.

Because mapped control IDs are searchable, a search can find the SCF controls behind a framework requirement without naming the framework:

```text
scf_search_controls {"query":"AC-02(01)"}
```

That finds IAC-15.1. The match is a substring, so `AC-02` also matches `AC-02(01)` and the other AC-02 enhancements, in every framework that uses those IDs. For an exact lookup in one framework, use `scf_get_crosswalk`.

## Get a control

```text
scf_get_control {"control_id":"IAC-15","framework":"NIST SP 800-53 R5"}
```

The response starts with the control's title, family, conformity cadence, relative weight, PPTDF category (people, process, technology, data, or facility), and NIST CSF function. Then it lists:

- the evidence request IDs, the SCF profiles that include the control, and counts of linked risks and threats, with long lists cut short by a count such as `(+2 more)`
- the control description
- with `framework`, the mapped controls in that framework, here `AC-02`, or a note that there are none
- the number of assessment objectives, with the first five
- each evidence request, with its artifact name and description

`control_id` ignores case. `framework` takes a framework ID or name, resolved the same way as in `scf_get_crosswalk`. A control ID that does not exist fails with `404 Not Found`.

## Map between frameworks

`scf_get_crosswalk` resolves one framework, then answers one of three questions:

| Arguments | Returns |
| --- | --- |
| `framework` and `control_id` | The framework controls that one SCF control maps to |
| `framework` and `framework_control_id` | The SCF controls that one framework control maps to |
| `framework` alone | Mapped-control counts and sample rows in both directions |

```text
scf_get_crosswalk {"framework":"NIST SP 800-53 R5","control_id":"IAC-15"}
scf_get_crosswalk {"framework":"fedramp moderate","framework_control_id":"SI-07(01)"}
scf_get_crosswalk {"framework":"ISO 27001","limit":5}
```

The second call returns:

```text
FedRAMP R5 - Moderate Baseline [usa-federal-gsa-fedramp-5-mod]
Framework control: SI-07(01)
Mapped SCF controls: END-06.1
```

A single-control lookup lists every mapping. If you pass both `control_id` and `framework_control_id`, `control_id` wins. The overview shows the first 10 rows in each direction unless you set `limit`, up to 50.

### Name the framework

`framework` accepts a framework ID or a display name, ignoring case. The tool tries these in order and stops at the first that finds exactly one framework:

1. An exact framework ID, such as `general-nist-800-53-r5-2`
2. An exact display name, such as `NIST SP 800-53 R5`
3. A framework whose ID or name contains the query, such as `ISO 27001`
4. A framework whose ID and name together contain every word of the query, such as `fedramp moderate`

If several frameworks still match, the tool lists up to five of them with their IDs. `FedRAMP` alone matches all four FedRAMP baselines, for example. Pass the ID from that list to be exact.

Common frameworks and the shape of their control IDs:

| Framework | `framework` ID | Control ID example |
| --- | --- | --- |
| NIST SP 800-53 R5 | `general-nist-800-53-r5-2` | `AC-02`, `SI-07(01)` |
| FedRAMP R5 Moderate Baseline | `usa-federal-gsa-fedramp-5-mod` | `AC-02(01)` |
| NIST SP 800-171 R3 | `general-nist-800-171-r3` | `03.01.01.a` |
| CMMC 2.0 Level 2 | `usa-federal-dow-cmmc-2-level-2` | `ACL2.-3.1.1` |
| Trust Services Criteria (2017), used for SOC 2 | `general-aicpa-tsc-2017` | `CC6.1` |
| ISO 27001 (2022) | `general-iso-27001-2022` | `5.1(a)` |
| PCI DSS v4.0.1 | `general-pci-dss-4-0-1` | `1.1.1` |
| NIST Cybersecurity Framework 2.0 | `general-nist-csf-2-0` | `DE.AE-02` |
| HIPAA Security Rule (2013) | `usa-federal-law-hipaa-security-rule-2013` | `164.306(a)(1)` |

The NIST SP 800-53 R5 baselines and the other FedRAMP baselines have IDs of their own, such as `general-nist-800-53-r5-2-mod` and `usa-federal-gsa-fedramp-5-high`.

### Match the control ID format

A framework control ID must match the crosswalk exactly, including case and zero padding. SCF control IDs, by contrast, ignore case. The NIST SP 800-53 and FedRAMP crosswalks pad control numbers to two digits and put enhancements in parentheses:

| You have | Use |
| --- | --- |
| `AC-2`, or `ac-2` in OSCAL | `AC-02` |
| `SI-7(1)`, or `si-7.1` in OSCAL and FedRAMP KSIs | `SI-07(01)` |
| `AC-2(11)`, or `ac-2.11` in OSCAL | `AC-02(11)` |

`SI-7(1)` returns "No mappings found." even though `SI-07(01)` maps to END-06.1. When a lookup comes back empty, run the overview for that framework to see the format it uses.

## Get an evidence request

```text
scf_get_evidence_request {"erl_id":"E-IAM-07"}
```

```text
E-IAM-07 - Account Management Compliance Reviews
  Area:          Identity & Access Management
  SCF controls:  IAC-15, IAC-15.7
  CMMC mapping:  None
  Description:   Documented evidence of account management compliance reviews.
```

`erl_id` ignores case. `scf_get_control` already lists the evidence requests for a control, so use this tool when you start from an evidence request ID, such as one on an assessor's request list.

## From a FedRAMP KSI to evidence

The FedRAMP, SCF, and OSCAL tools chain together. This path starts from a KSI and ends with the objectives and evidence for one of its controls:

1. `fedramp_get_ksi {"query":"KSI-CNA-EIS"}` lists the Rev5 controls the indicator maps to, including `si-7.1`.
2. `scf_get_crosswalk {"framework":"fedramp moderate","framework_control_id":"SI-07(01)"}` maps that control to END-06.1, Integrity Checks.
3. `scf_get_control {"control_id":"END-06.1"}` lists four assessment objectives. END-06.1 has no evidence requests of its own, so check its parent: `scf_get_control {"control_id":"END-06"}` lists E-END-01, Endpoint Security Tools.
4. Write the SI-7(1) implementation in `si/si-7.1.md` of your [OSCAL workspace](/docs/guides/oscal-workspaces/).

## Troubleshooting

- **A crosswalk lookup returns "No mappings found."** The framework control ID does not match the crosswalk's format. See [Match the control ID format](#match-the-control-id-format).
- **"matched multiple SCF frameworks."** Pass one of the listed IDs as `framework`.
- **"No SCF framework matched."** The name is not in SCF's framework list. SOC 2, for example, appears as Trust Services Criteria (TSC) (2017), so use `TSC` or `general-aicpa-tsc-2017`.
- **"Fetch failed: ... (404 Not Found)."** The control or evidence request ID does not exist. Search for the control, or check the ID's shape, such as `IAC-15.1` or `E-IAM-07`.
- **Any other fetch failure.** The API was unreachable. The tools keep no offline copy, so retry once the network is back.

## Related

- [FedRAMP Readiness](/docs/guides/fedramp-readiness/) looks up KSIs and the Rev5 controls they map to.
- [OSCAL Workspaces](/docs/guides/oscal-workspaces/) turns control implementations into an OSCAL system security plan.
- The [scf-api repository](https://github.com/hackIDLE/scf-api) describes the data files the tools read.
