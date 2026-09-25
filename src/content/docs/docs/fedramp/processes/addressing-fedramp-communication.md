---
title: Addressing FedRAMP Communication — FedRAMP Process
description: Official Consolidated Rules summary for the AFC FedRAMP process, including applicability and requirements.
---

> Generated from the official [FedRAMP/rules](https://github.com/FedRAMP/rules) GitHub repo.
> Source path: [`fedramp-consolidated-rules.json`](https://github.com/FedRAMP/rules/blob/main/fedramp-consolidated-rules.json) on `main` at blob `7d628b63fdd9`.
> Consolidated Rules version: `2026.07.02.02` · upstream `last_updated`: `2026-07-02`.
> Supporting narrative documentation is available from the official `FedRAMP/2026-markdown` repository.

# Addressing FedRAMP Communication

Short name: `AFC` · Process ID: `AFC` · Web slug: `addressing-fedramp-communication`

Applies to: `both`
Status: `stable`


Official page: [https://www.fedramp.gov/2026/reference/addressing-fedramp-communication/](https://www.fedramp.gov/2026/reference/addressing-fedramp-communication/)

## Effective Status

- 20x: required · Consolidated Rules for 2026 · obtain 2026-01-05 · grace through 2026-07-01
- Rev5: required · Consolidated Rules for 2026 · obtain 2026-01-05 · grace through 2026-07-01
- Shared requirements: 16

## Purpose

The Addressing FedRAMP Communication rules (formerly FedRAMP Security Inbox) ensure FedRAMP can reliably contact the security and compliance staff responsible for every FedRAMP-authorized cloud service offering. These rules also set expectations for urgent communications, response time testing, and routing important messages separately from general support or customer service channels.

## Rule Subsets

- `CSO` — General Provider Responsibilities: These rules apply to providers with any type of FedRAMP Certification. · types: 20x, Rev5 · classes: B, C, D
- `FRP` — FedRAMP Responsibilities: These rules apply to FedRAMP when communicating with cloud service providers. · types: 20x, Rev5 · classes: B, C, D

## Requirements and Recommendations

## BOTH

### `AFC-CSO-ACK` SHOULD — Acknowledge Receipt

Providers SHOULD promptly and automatically acknowledge the receipt of messages received from FedRAMP in their FedRAMP Security Inbox.

Terms: `FedRAMP Security Inbox`, `Promptly`, `Provider`

Affects: Providers

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `AFC-CSO-CRA` MUST — Complete Required Actions

Providers MUST complete the required actions in Emergency or Emergency Test designated messages sent by FedRAMP within the timeframe included in the message.

Terms: `Certification Class`, `Provider`

Affects: Providers

Note: Timeframes may vary by FedRAMP Certification class.

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `AFC-CSO-EMR` MUST — Emergency Message Routing

Providers MUST route Emergency designated messages sent by FedRAMP to a senior security official for their awareness.

Terms: `Provider`

Affects: Providers

Note: Senior security officials are determined by the provider.

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `AFC-CSO-IMA` SHOULD — Important Message Actions

Providers SHOULD complete the required actions in Important designated messages sent by FedRAMP within the timeframe specified in the message.

Terms: `Certification Class`, `Provider`

Affects: Providers

Note: Timeframes may vary by FedRAMP Certification class.

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `AFC-CSO-INB` MUST — Maintain a FedRAMP Security Inbox

Providers MUST establish and maintain an email address to receive messages from FedRAMP; this inbox is a FedRAMP Security Inbox (FSI).

Terms: `FedRAMP Security Inbox`, `Provider`

Affects: Providers

Note: Unless otherwise notified, FedRAMP will use the listed Security Email on the Marketplace for these notifications.
If a provider establishes a new inbox in reaction to this guidance that is different from the Security Email then they must follow the AFC-CSO-NOC (Notification of Changes) rules to notify FedRAMP.

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `AFC-CSO-NOC` MUST — Notification of Changes

Providers MUST immediately notify FedRAMP of any changes to the email address for their FedRAMP Security Inbox.

Terms: `FedRAMP Security Inbox`, `Provider`

Affects: Providers

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `AFC-CSO-RCV` MUST — Receive Email Without Disruption

Providers MUST receive and react to email messages from FedRAMP without disruption and without requiring additional actions from FedRAMP.

Terms: `Provider`

Affects: Providers

Note: This requirement is intended to prevent cloud service providers from requiring FedRAMP to complete a CAPTCHA, log into a customer portal, or otherwise take service-specific actions that might prevent the security team from receiving the message.

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `AFC-CSO-TFG` MUST — Trust @fedramp.gov and @gsa.gov

Providers MUST treat any email originating from an @fedramp.gov or @gsa.gov email address as if it was sent from FedRAMP by default; if such a message is confirmed to originate from someone other than FedRAMP then the FedRAMP Security Inbox rules no longer apply.

Terms: `FedRAMP Security Inbox`, `Provider`

Affects: Providers

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `AFC-FRP-CDS` MUST — Criticality Designators

FedRAMP MUST convey the criticality of the message in the subject line, IF the message requires an elevated reaction, using one of the following designators:

Checklist items:
- **Emergency:** There is a potential incident or crisis such that FedRAMP requires an extremely urgent reaction; emergency messages will contain aggressive timeframes for reaction and failure to meet these timeframes will result in corrective action.
- **Emergency Test:** FedRAMP requires an extremely urgent reaction to confirm the functionality and effectiveness of the FedRAMP Security Inbox; emergency test messages will contain aggressive timeframes for reaction and failure to meet these timeframes will result in corrective action.
- **Important:** There is an important issue that FedRAMP requires the cloud service provider to address; important messages will contain reasonable timeframes for reaction and failure to meet these timeframes may result in corrective action.

Terms: `FedRAMP Security Inbox`, `Incident`, `Provider`

Affects: FedRAMP

Note: Messages sent by FedRAMP without one of these designators are considered general communications and do not require an elevated reaction; these may be resolved in the normal course of business by the cloud service provider.

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `AFC-FRP-COR` MUST — Explain Corrective Actions

FedRAMP MUST clearly specify the corrective actions that will result from failure to complete the required actions in the body of messages that require an elevated reaction; such actions may vary from negative ratings in the FedRAMP Marketplace to suspension of FedRAMP Certification depending on the severity of the event.

Affects: FedRAMP

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `AFC-FRP-ERT` MUST — Elevated Reaction Timeframes

FedRAMP MUST clearly specify the expected timeframe for completing required actions in the body of messages that require an elevated reaction; timeframes for actions will vary depending on the situation but the default timeframes to provide an estimated resolution time for Emergency and Emergency Test designated messages will be as follows:

Checklist items:
- **Class D:** within 12 hours
- **Class C:** by 3:00 p.m. Eastern Time on the 2nd business day
- **Class B:** by 3:00 p.m. Eastern Time on the 3rd business day
- **Class A:** by 3:00 p.m. Eastern Time on the 5th business day

Terms: `Debilitating Customer Effect`, `FedRAMP Certified`, `Provider`

Affects: FedRAMP

Note: FedRAMP Class D Certified cloud service providers are expected to address Emergency messages (including tests) from FedRAMP with a reaction time appropriate to operating a service where failure to react rapidly might have a severe or debilitating customer effect on the U.S. Government; some Emergency messages may require faster reaction and all such messages should be addressed as quickly as possible.

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `AFC-FRP-PNT` MUST — Public Notice of Emergency Tests

FedRAMP MUST post a public notice at least 10 business days in advance of sending an Emergency Test message; such notices MUST include explanation of the likely expected actions and timeframes for the Emergency Test message.

Terms: `Likely`

Affects: FedRAMP

Structured timeframe: `10` bizdays

Note: Public notice may include blog posts, social media posts, announcements during Community Updates, or e-blasts.
As this process matures, additional confirmed options may become available.

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `AFC-FRP-RPM` MAY — Reaction Metrics

FedRAMP MAY track and publicly share the time required by cloud service providers to take the actions specified in messages that require an elevated reaction.

Terms: `Provider`

Affects: FedRAMP

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `AFC-FRP-RQA` MUST — Required Actions

FedRAMP MUST clearly specify the required actions in the body of messages that require an elevated reaction.

Affects: FedRAMP

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `AFC-FRP-UFS` MUST — Use FedRAMP_Security Email in Emergencies

FedRAMP MUST send Emergency and Emergency Test designated messages from fedramp_security@gsa.gov OR fedramp_security@fedramp.gov.

Affects: FedRAMP

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `AFC-FRP-VRE` MUST — Verified Emails

FedRAMP MUST send messages to cloud service providers using an official @fedramp.gov or @gsa.gov email address with properly configured Sender Policy Framework (SPF), DomainKeys Identified Mail (DKIM), and Domain-based Message Authentication Reporting and Conformance (DMARC) email authentication.

Terms: `Provider`

Affects: FedRAMP

Note: Anyone at GSA can send email from @fedramp.gov or @gsa.gov - FedRAMP team members will typically have "FedRAMP" or "F20B" in their name but this is not universal or enforceable. The nature of government enterprise IT services makes it difficult for FedRAMP to isolate FedRAMP-specific team members with enforceable identifiers.

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.
