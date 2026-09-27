## Purpose

Assess ServiceNow instance identity, access controls, hardening, auditability, integrations, plugins, and operations governance through read-only Table and Aggregate APIs.

## Design guidance

Cross-check row visibility with authoritative counts because ACL filtering can silently hide records. Preserve unreadable properties, tables, and licensed features as unknown evidence, and never convert a skipped dependent request into an empty list.
