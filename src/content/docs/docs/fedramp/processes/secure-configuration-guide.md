---
title: Secure Configuration Guide — FedRAMP Process
description: Official Consolidated Rules summary for the SCG FedRAMP process, including applicability and requirements.
---

> Generated from the official [FedRAMP/rules](https://github.com/FedRAMP/rules) GitHub repo.
> Source path: [`fedramp-consolidated-rules.json`](https://github.com/FedRAMP/rules/blob/main/fedramp-consolidated-rules.json) on `main` at blob `7d628b63fdd9`.
> Consolidated Rules version: `2026.07.02.02` · upstream `last_updated`: `2026-07-02`.
> Supporting narrative documentation is available from the official `FedRAMP/2026-markdown` repository.

# Secure Configuration Guide

Short name: `SCG` · Process ID: `SCG` · Web slug: `secure-configuration-guide`

Applies to: `both`
Status: `stable`


Official page: [https://www.fedramp.gov/2026/reference/secure-configuration-guide/](https://www.fedramp.gov/2026/reference/secure-configuration-guide/)

## Effective Status

- 20x: required · Consolidated Rules for 2026 · obtain 2026-03-01 · grace through 2026-07-01
- Rev5: required · Consolidated Rules for 2026 · obtain 2026-03-01 · grace through 2026-07-01
- Shared requirements: 9

## Purpose

The Secure Configuration Guide rules help agencies and other customers understand how to configure a cloud service offering securely. These rules require providers to clearly explain the security impact of common settings so customers can make informed configuration choices.

## Rule Subsets

- `CSO` — General Provider Responsibilities: These rules apply to providers with FedRAMP Certifications of any type. · types: 20x, Rev5 · classes: B, C, D
- `ENH` — Enhanced Capabilities: These recommendations apply to providers with FedRAMP Certifications of any type. · types: 20x, Rev5 · classes: B, C, D

## Requirements and Recommendations

## BOTH

### `SCG-CSO-AUP` MUST — Use Instructions

Providers MUST include instructions in the FedRAMP Certification Package that explain how to obtain and use the Secure Configuration Guide.

Terms: `Certification Package`, `Provider`

Affects: Providers

Note: These instructions may appear in a variety of ways; it is up to the provider to do so in the most appropriate and effective ways for their specific customer needs.

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `SCG-CSO-PUB` SHOULD — Public Secure Configuration Guidance

Providers SHOULD make the Secure Configuration Guide available publicly.

Terms: `Provider`

Affects: Providers

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `SCG-CSO-RSC` MUST — Recommended Secure Configuration

Providers MUST create, maintain, and make available recommendations for securely configuring their cloud services (the Secure Configuration Guide) that includes at least the following information:

Checklist items:
- Required: Instructions on how to securely access, configure, operate, and decommission top-level administrative accounts that control enterprise access to the entire cloud service offering.
- Required: Explanations of security-related settings that can be operated only by top-level administrative accounts and their security implications.
- Recommended: Explanations of security-related settings that can be operated only by privileged accounts and their security implications.

Terms: `Cloud Service Offering`, `Privileged Account`, `Provider`, `Top-Level Administrative Account`

Affects: Providers

Note: These rules refer to this guidance as a Secure Configuration Guide but cloud service providers may make this guidance available in various appropriate forms that provide the best customer experience.
This guidance should explain how top-level administrative accounts and privileged accounts are named and referred to in the cloud service offering.

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `SCG-CSO-SDF` SHOULD — Secure Defaults

Providers SHOULD set all settings to their recommended secure defaults for top-level administrative accounts and privileged accounts when initially provisioned.

Terms: `Privileged Account`, `Provider`, `Top-Level Administrative Account`

Affects: Providers

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `SCG-ENH-API` SHOULD — API Capability

Providers SHOULD offer the capability to view and adjust security settings via an API or similar capability.

Terms: `Provider`

Affects: Providers

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `SCG-ENH-CMP` SHOULD — Comparison Capability

Providers SHOULD offer the capability to compare all current settings for top-level administrative accounts and privileged accounts to the recommended secure defaults.

Terms: `Privileged Account`, `Provider`, `Top-Level Administrative Account`

Affects: Providers

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `SCG-ENH-EXP` SHOULD — Export Capability

Providers SHOULD offer the capability to export all security settings in a machine-readable format.

Terms: `Machine-Readable`, `Provider`

Affects: Providers

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `SCG-ENH-MRG` SHOULD — Machine-Readable Guidance

Providers SHOULD also provide the Secure Configuration Guide in a machine-readable format that can be used by customers or third-party tools to compare against current settings.

Terms: `Machine-Readable`, `Provider`

Affects: Providers

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `SCG-ENH-VRH` SHOULD — Versioning and Release History

Providers SHOULD provide versioning and a release history for recommended secure default settings for top-level administrative accounts and privileged accounts as they are adjusted over time.

Terms: `Privileged Account`, `Provider`, `Top-Level Administrative Account`

Affects: Providers

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.
