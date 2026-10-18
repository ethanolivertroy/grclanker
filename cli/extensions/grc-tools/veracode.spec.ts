// The members the documented user and API credential records carry; a 200 body with none of them is not the resource
// and is never read as evidence.
export const USER_MEMBERS: readonly string[] = ["user_id", "user_name", "email_address", "roles"];
export const API_CREDENTIAL_MEMBERS: readonly string[] = ["api_id", "created_ts", "expiration_ts", "revocation_ts"];
// Scan statuses, uppercased, that count as a published scan, and those that count as a failed one.
export const COMPLETED_SCAN_STATUSES: readonly string[] = [
  "PUBLISHED",
  "PUBLISHED_TO_VENDOR",
  "PUBLISHED_TO_ENTERPRISE",
  "PUBLISHED_TO_ENTERPRISEINT",
];
export const FAILED_SCAN_STATUSES: readonly string[] = [
  "ANALYSIS_ERRORS",
  "SCAN_CANCELED",
  "PRE_SCAN_FAILED",
  "PRE_SCAN_CANCELED",
  "NTO_PRE_SCAN_CANCELED",
  "INCOMPLETE",
  "MODULE_SELECTION_REQUIRED",
];
// Days each policy scan frequency allows between scans; ONCE asks for one scan ever, and any other frequency is ignored.
export const FREQUENCY_DAYS: Readonly<Record<string, number>> = {
  WEEKLY: 7,
  MONTHLY: 31,
  QUARTERLY: 92,
  SEMI_ANNUALLY: 183,
  ANNUALLY: 366,
  EVERY_18_MONTHS: 548,
  EVERY_2_YEARS: 731,
  EVERY_3_YEARS: 1096,
};
// Finding annotation actions, uppercased, that record a mitigation.
export const MITIGATION_ACTIONS: readonly string[] = [
  "FP",
  "APPDESIGN",
  "OSENV",
  "NETENV",
  "ACCEPTRISK",
  "BYENV",
  "BYDESIGN",
  "LIBRARY",
  "DEFER",
  "CUSTOMCLEANSERPROPOSED",
];
// Days an open, unresolved flaw may stay open, by numeric severity; flaws of any other severity are not aged.
export const FLAW_AGE_THRESHOLDS: Readonly<Record<number, number>> = { 5: 30, 4: 60, 3: 90, 2: 180 };
// Each control's framework references, in the order FedRAMP, CMMC, SOC 2, CIS Controls v8, PCI-DSS, STIG, IRAP, ISMAP.
export const VERACODE_FRAMEWORK_MAPPINGS: Readonly<Record<number, readonly [string, string, string, string, string, string, string, string]>> = {
  1: ["SA-11", "L2 3.14.1", "CC7.1", "16.12", "6.5", "SRG-APP-000456", "ISM-1143", "VM-01"],
  2: ["SA-11(1)", "L2 3.14.3", "CC7.1", "16.2", "6.3", "SRG-APP-000456", "ISM-1143", "VM-02"],
  3: ["SI-2", "L2 3.14.1", "CC7.1", "7.4", "6.3.3", "SRG-APP-000456", "ISM-1143", "VM-03"],
  4: ["SA-11", "L2 3.14.1", "CC7.1", "16.12", "6.5.6", "SRG-APP-000456", "ISM-1143", "VM-01"],
  5: ["SA-11(2)", "L2 3.14.2", "CC7.1", "16.4", "6.3.2", "SRG-APP-000454", "ISM-1490", "VM-04"],
  6: ["SA-4(2)", "L2 3.4.2", "CC3.2", "2.2", "6.3.2", "SRG-APP-000516", "ISM-1490", "RM-01"],
  7: ["AC-6", "L2 3.1.5", "CC6.3", "6.8", "7.2.2", "SRG-APP-000340", "ISM-0432", "AC-01"],
  8: ["AC-6(5)", "L2 3.1.5", "CC6.3", "5.4", "7.2.1", "SRG-APP-000340", "ISM-0432", "AC-02"],
  9: ["IA-5(1)", "L2 3.5.8", "CC6.1", "5.2", "8.6.3", "SRG-APP-000174", "ISM-1590", "AM-01"],
  10: ["SA-11", "L2 3.14.1", "CC8.1", "16.7", "6.5", "SRG-APP-000456", "ISM-1143", "SD-01"],
  11: ["SA-11", "L2 3.14.1", "CC7.1", "16.12", "6.5", "SRG-APP-000456", "ISM-1143", "VM-01"],
  12: ["SI-2", "L2 3.14.1", "CC7.4", "7.2", "6.3.3", "SRG-APP-000456", "ISM-1143", "VM-05"],
  13: ["SA-11(8)", "L2 3.14.6", "CC7.1", "16.6", "6.6", "SRG-APP-000456", "ISM-1143", "VM-06"],
  14: ["SA-11", "L2 3.14.1", "CC8.1", "16.12", "6.5.6", "SRG-APP-000456", "ISM-1143", "SD-02"],
  15: ["SA-11(1)", "L2 3.14.3", "CC7.1", "16.2", "6.3", "SRG-APP-000516", "ISM-1143", "VM-02"],
  16: ["SA-11", "L2 3.14.1", "CC7.1", "16.12", "6.5", "SRG-APP-000456", "ISM-1143", "VM-07"],
  17: ["SA-11", "L2 3.14.1", "CC7.1", "16.12", "6.5", "SRG-APP-000456", "ISM-1143", "VM-03"],
  18: ["SA-11(2)", "L2 3.14.2", "CC7.1", "16.4", "6.3.2", "SRG-APP-000454", "ISM-1490", "VM-04"],
  19: ["SA-11", "L2 3.14.1", "CC7.1", "16.12", "6.5", "SRG-APP-000456", "ISM-1143", "VM-01"],
  20: ["SA-11(1)", "L2 3.14.3", "CC7.1", "16.2", "6.3", "SRG-APP-000456", "ISM-1143", "VM-02"],
};
