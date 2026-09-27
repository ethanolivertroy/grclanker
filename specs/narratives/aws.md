## Purpose

AWS Security Inspector gives auditors a read-only, multi-framework view of one AWS account across identity, logging, threat detection, organization guardrails, data protection, and network security. It gathers evidence directly from the services that own each setting and produces findings that remain traceable to the operation, region, and resource population assessed.

## Rationale

AWS security posture is distributed across global and regional services. A complete assessment must distinguish account-wide IAM and Organizations evidence from per-region EC2, RDS, KMS, Config, GuardDuty, and Security Hub evidence. It must also distinguish a genuinely empty account from a denied operation, an incomplete response, or a collection stopped by a configured cap.

The contract reads direct resource settings where an aggregate service cannot prove the control. Examples include account and bucket public-access blocks, default encryption, TLS-only bucket policies, VPC flow-log coverage, network access rules, and key rotation. This keeps each verdict tied to evidence that another implementation can collect independently.

## Non-goals

- Changing AWS resources, policies, standards, detectors, recorders, or contacts
- Assuming roles into additional accounts or aggregating an organization-wide report
- Treating Security Hub or Config scores as substitutes for direct resource checks
- Claiming complete regional coverage when region discovery fails or a region cap is reached
- Reproducing a particular programming language, software development kit, package layout, or command-line framework

## Portable implementation guidance

Keep service calls behind a read-only client boundary and attach the service action and region to every failed collection. Discover enabled regions unless the caller explicitly supplies a region list. Collect regional evidence independently so one denied region does not erase readable evidence from another. Validate successful responses against the documented output shape before treating an absent list as empty. Preserve the global handling required for root-account activity.
