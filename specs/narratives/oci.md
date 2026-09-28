## Purpose

Give security and compliance teams a read-only, repeatable view of OCI identity, Cloud Guard, Audit, networking, Vault, Object Storage, and Compute posture without treating a failed OCI CLI command as an empty inventory.

## Design guidance

Use a dedicated OCI audit profile with explicit tenancy, compartment, and region scope. Preserve command failures and every configured collection cap as evidence. Keep identity-domain settings manual when the classic IAM API does not expose them.
