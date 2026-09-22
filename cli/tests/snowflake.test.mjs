import test from "node:test";
import assert from "node:assert/strict";
import { createVerify, generateKeyPairSync } from "node:crypto";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";

import {
  SHOW_ROW_CAP,
  SNOWFLAKE_CONTROLS,
  SNOWFLAKE_FRAMEWORKS,
  SNOWFLAKE_STATEMENTS,
  SnowflakeSqlClient,
  SnowflakeStatementError,
  assertReadOnlyStatement,
  assessSnowflakeAccessControl,
  assessSnowflakeDataProtection,
  assessSnowflakeMonitoringAndLifecycle,
  assessSnowflakeNetworkAndAuthentication,
  buildSnowflakeKeyPairJwt,
  checkSnowflakeAccess,
  classifyUserType,
  collectStatement,
  computePublicKeyFingerprint,
  exportSnowflakeAuditBundle,
  normalizeJwtAccountIdentifier,
  parseSimpleToml,
  redactSecrets,
  registerSnowflakeTools,
  resolveSecureOutputPath,
  resolveSnowflakeConfiguration,
} from "../dist/extensions/grc-tools/snowflake.js";
import { getRegisteredToolSummaries } from "../dist/pi/tool-catalog.js";
import { assertSecretsAbsent, readBundleFiles, readZipEntries } from "./helpers/bundle-contents.mjs";

const { privateKey: testPrivateKey, publicKey: testPublicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const TEST_PRIVATE_KEY_PEM = testPrivateKey.export({ type: "pkcs8", format: "pem" });
const TEST_PUBLIC_KEY_PEM = testPublicKey.export({ type: "spki", format: "pem" });

const ALL_CONTROL_IDS = Object.values(SNOWFLAKE_CONTROLS).map((definition) => definition.id);
const DAY_MS = 86_400_000;

function createTempBase(prefix) {
  return mkdtempSync(join(tmpdir(), prefix));
}

function isoDaysAgo(days) {
  return new Date(Date.now() - days * DAY_MS).toISOString();
}

function sampleConfig(overrides = {}) {
  return {
    account: "myorg-myaccount",
    user: "auditor",
    baseUrl: "https://myorg-myaccount.snowflakecomputing.com",
    tokenType: "KEYPAIR_JWT",
    privateKeyPem: TEST_PRIVATE_KEY_PEM,
    role: "AUDIT_ROLE",
    warehouse: "AUDIT_WH",
    timeoutMs: 5000,
    statementTimeoutSeconds: 30,
    pollIntervalMs: 0,
    maxRetries: 3,
    retryBaseMs: 0,
    maxPartitions: 50,
    rowLimit: 1000,
    sourceChain: ["tests"],
    ...overrides,
  };
}

function jsonResponse(value, options = {}) {
  return new Response(JSON.stringify(value), {
    status: options.status ?? 200,
    statusText: options.statusText ?? "",
    headers: {
      "content-type": "application/json",
      ...(options.headers ?? {}),
    },
  });
}

function headerValue(headers, name) {
  if (!headers) return undefined;
  if (headers instanceof Headers) return headers.get(name) ?? undefined;
  if (typeof headers.get === "function") return headers.get(name) ?? undefined;
  return headers[name] ?? headers[name.toLowerCase()];
}

function resultSet(statement, columns, values, extra = {}) {
  const rows = values.map((entry) => {
    const row = {};
    columns.forEach((column, index) => {
      const value = entry[index];
      row[column] = value === null || value === undefined ? null : String(value);
    });
    return row;
  });
  return {
    statement,
    columns,
    rows,
    numRows: rows.length,
    partitionCount: 1,
    fetchedPartitions: 1,
    truncated: false,
    ...extra,
  };
}

const USER_COLUMNS = [
  "NAME",
  "LOGIN_NAME",
  "TYPE",
  "DISABLED",
  "HAS_PASSWORD",
  "HAS_MFA",
  "EXT_AUTHN_DUO",
  "HAS_RSA_PUBLIC_KEY",
  "HAS_PAT",
  "HAS_WORKLOAD_IDENTITY",
  "LAST_SUCCESS_LOGIN",
  "PASSWORD_LAST_SET_TIME",
  "CREATED_ON",
  "DEFAULT_ROLE",
  "OWNER",
];

function userRow(overrides = {}) {
  const row = {
    NAME: "ALICE",
    LOGIN_NAME: "ALICE",
    TYPE: "PERSON",
    DISABLED: "false",
    HAS_PASSWORD: "true",
    HAS_MFA: "true",
    EXT_AUTHN_DUO: "false",
    HAS_RSA_PUBLIC_KEY: "false",
    HAS_PAT: "false",
    HAS_WORKLOAD_IDENTITY: "false",
    LAST_SUCCESS_LOGIN: isoDaysAgo(3),
    PASSWORD_LAST_SET_TIME: isoDaysAgo(20),
    CREATED_ON: isoDaysAgo(400),
    DEFAULT_ROLE: "ANALYST",
    OWNER: "USERADMIN",
    ...overrides,
  };
  return USER_COLUMNS.map((column) => row[column]);
}

const HEALTHY_USERS = [
  userRow(),
  userRow({ NAME: "BOB", LOGIN_NAME: "BOB", EXT_AUTHN_DUO: "true", HAS_MFA: "false", LAST_SUCCESS_LOGIN: isoDaysAgo(10) }),
  userRow({ NAME: "CAROL_DISABLED", LOGIN_NAME: "CAROL", DISABLED: "true", HAS_MFA: "false", LAST_SUCCESS_LOGIN: null }),
  userRow({ NAME: "SVC_ETL", LOGIN_NAME: "SVC_ETL", TYPE: "SERVICE", HAS_PASSWORD: "false", HAS_MFA: "false", HAS_RSA_PUBLIC_KEY: "true", LAST_SUCCESS_LOGIN: isoDaysAgo(1) }),
];

const POLICY_REFERENCE_COLUMNS = [
  "POLICY_DB",
  "POLICY_SCHEMA",
  "POLICY_NAME",
  "POLICY_KIND",
  "REF_DATABASE_NAME",
  "REF_SCHEMA_NAME",
  "REF_ENTITY_NAME",
  "REF_ENTITY_DOMAIN",
  "REF_COLUMN_NAME",
  "TAG_NAME",
  "POLICY_STATUS",
];

function policyReference(kind, name, domain, entity, column = null, status = "ACTIVE") {
  return ["GOV", "POLICIES", name, kind, domain === "ACCOUNT" || domain === "USER" ? null : "SALES", domain === "ACCOUNT" || domain === "USER" ? null : "PUBLIC", entity, domain, column, null, status];
}

const POLICY_REFERENCE_FUNCTION_COLUMNS = POLICY_REFERENCE_COLUMNS.slice(0, 8);

function policyFunctionReference(kind, name, domain, entity) {
  return policyReference(kind, name, domain, entity).slice(0, 8);
}

function policyReferencesFunctionCall(database, schema, name) {
  return `${database}.INFORMATION_SCHEMA.POLICY_REFERENCES(POLICY_NAME => '${database}.${schema}.${name}')`;
}

const UNSUPPORTED_ACCOUNT_USAGE_POLICY_KINDS = ["'PASSWORD_POLICY'", "'SESSION_POLICY'", "'AUTHENTICATION_POLICY'"];

function rejectUndocumentedAccountUsageKinds(statement) {
  if (!statement.includes("ACCOUNT_USAGE.POLICY_REFERENCES")) return;
  for (const kind of UNSUPPORTED_ACCOUNT_USAGE_POLICY_KINDS) {
    if (statement.includes(kind)) {
      throw new Error(`ACCOUNT_USAGE.POLICY_REFERENCES does not support ${kind}; use the INFORMATION_SCHEMA.POLICY_REFERENCES table function (statement: ${statement})`);
    }
  }
}

const PARAMETER_COLUMNS = ["key", "value", "default", "level", "description", "type"];
const INTEGRATION_COLUMNS = ["name", "type", "category", "enabled", "comment", "created_on"];
const WAREHOUSE_COLUMNS = ["name", "state", "type", "size", "auto_suspend", "auto_resume", "owner"];
const DATABASE_COLUMNS = ["created_on", "name", "kind", "origin", "owner", "retention_time"];
const SHARE_COLUMNS = ["created_on", "kind", "owner_account", "name", "database_name", "to", "owner", "comment", "listing_global_name", "secure_objects_only"];
const NETWORK_POLICY_COLUMNS = ["NAME", "OWNER", "ALLOWED_IP_LIST", "BLOCKED_IP_LIST", "CREATED", "LAST_ALTERED"];
const PASSWORD_POLICY_COLUMNS = [
  "NAME",
  "DATABASE",
  "SCHEMA",
  "OWNER",
  "PASSWORD_MIN_LENGTH",
  "PASSWORD_MAX_LENGTH",
  "PASSWORD_MIN_UPPER_CASE_CHARS",
  "PASSWORD_MIN_LOWER_CASE_CHARS",
  "PASSWORD_MIN_NUMERIC_CHARS",
  "PASSWORD_MIN_SPECIAL_CHARS",
  "PASSWORD_MIN_AGE_DAYS",
  "PASSWORD_MAX_AGE_DAYS",
  "PASSWORD_MAX_RETRIES",
  "PASSWORD_LOCKOUT_TIME_MINS",
  "PASSWORD_HISTORY",
];
const SESSION_POLICY_COLUMNS = ["NAME", "DATABASE", "SCHEMA", "OWNER", "SESSION_IDLE_TIMEOUT_MINS", "SESSION_UI_IDLE_TIMEOUT_MINS", "SESSION_MAX_LIFESPAN_MINS", "SESSION_UI_MAX_LIFESPAN_MINS"];
const GRANT_COLUMNS = ["PRIVILEGE", "GRANTED_ON", "NAME", "TABLE_CATALOG", "TABLE_SCHEMA", "GRANTED_TO", "GRANTEE_NAME", "GRANT_OPTION", "GRANTED_BY"];
const GLOBAL_GRANT_COLUMNS = ["PRIVILEGE", "GRANTED_ON", "NAME", "GRANTED_TO", "GRANTEE_NAME", "GRANT_OPTION"];
const DIRECT_GRANT_COLUMNS = ["PRIVILEGE", "GRANTED_ON", "NAME", "TABLE_CATALOG", "TABLE_SCHEMA", "GRANTEE_NAME"];
const PUBLIC_GRANT_COLUMNS = ["PRIVILEGE", "GRANTED_ON", "NAME", "TABLE_CATALOG", "TABLE_SCHEMA", "GRANTED_BY"];

function sessionContextRows(role) {
  return [["MYORG-MYACCOUNT", "AUDITOR", role, "AUDIT_WH", "AWS_US_WEST_2", "9.20.1"]];
}

const SESSION_COLUMNS = ["ACCOUNT_NAME", "USER_NAME", "ROLE_NAME", "WAREHOUSE_NAME", "REGION_NAME", "VERSION"];

function normalizeStatement(statement) {
  return statement.replace(/\s+/g, " ").trim();
}

function healthyFixture(statement, options = {}) {
  const role = options.role ?? "ACCOUNTADMIN";
  const s = normalizeStatement(statement);
  const rs = (columns, values) => resultSet(statement, columns, values);
  rejectUndocumentedAccountUsageKinds(s);

  if (s.startsWith("SELECT CURRENT_ACCOUNT()")) return rs(SESSION_COLUMNS, sessionContextRows(role));
  if (s === "SHOW NETWORK POLICIES") return rs(["created_on", "name", "comment", "entries_in_allowed_ip_list", "entries_in_blocked_ip_list"], [["2025-01-01 00:00:00", "CORP_POLICY", "corporate egress", "2", "0"]]);
  if (s === "SHOW PARAMETERS LIKE 'NETWORK_POLICY' IN ACCOUNT") return rs(PARAMETER_COLUMNS, [["NETWORK_POLICY", "CORP_POLICY", "", "ACCOUNT", "Network policy for the account", "STRING"]]);
  if (s === "SHOW PARAMETERS LIKE 'DATA_RETENTION_TIME_IN_DAYS' IN ACCOUNT") return rs(PARAMETER_COLUMNS, [["DATA_RETENTION_TIME_IN_DAYS", "1", "1", "ACCOUNT", "Time travel retention", "NUMBER"]]);
  if (s.startsWith("SHOW PARAMETERS LIKE 'REQUIRE_STORAGE_INTEGRATION_FOR_STAGE_%'")) {
    return rs(PARAMETER_COLUMNS, [
      ["REQUIRE_STORAGE_INTEGRATION_FOR_STAGE_CREATION", "true", "false", "ACCOUNT", "", "BOOLEAN"],
      ["REQUIRE_STORAGE_INTEGRATION_FOR_STAGE_OPERATION", "true", "false", "ACCOUNT", "", "BOOLEAN"],
    ]);
  }
  if (s.startsWith("SHOW PARAMETERS LIKE 'PREVENT_UNLOAD_TO_%'")) {
    return rs(PARAMETER_COLUMNS, [
      ["PREVENT_UNLOAD_TO_INLINE_URL", "true", "false", "ACCOUNT", "", "BOOLEAN"],
      ["PREVENT_UNLOAD_TO_INTERNAL_STAGES", "true", "false", "ACCOUNT", "", "BOOLEAN"],
    ]);
  }
  if (s === "SHOW INTEGRATIONS") {
    return rs(INTEGRATION_COLUMNS, [
      ["OKTA_SAML", "SAML2", "SECURITY", "true", "", "2025-01-01"],
      ["OKTA_SCIM", "SCIM", "SECURITY", "true", "", "2025-01-01"],
      ["S3_INT", "EXTERNAL_STAGE", "STORAGE", "true", "", "2025-01-01"],
    ]);
  }
  if (s === "SHOW WAREHOUSES") return rs(WAREHOUSE_COLUMNS, [["AUDIT_WH", "SUSPENDED", "STANDARD", "X-Small", "60", "true", "SYSADMIN"], ["ETL_WH", "STARTED", "STANDARD", "Small", "300", "true", "SYSADMIN"]]);
  if (s === "SHOW DATABASES") return rs(DATABASE_COLUMNS, [["2025-01-01", "SALES", "STANDARD", "", "SYSADMIN", "7"], ["2025-01-01", "SNOWFLAKE", "APPLICATION", "SNOWFLAKE.ACCOUNT_USAGE", "", "1"]]);
  if (s === "SHOW SHARES") return rs(SHARE_COLUMNS, [["2025-01-01", "INBOUND", "PROVIDER.ACCT", "PROVIDER_SHARE", "PROVIDER_DB", "", "", "", null, "true"]]);
  if (s === "SHOW REPLICATION GROUPS") return rs(["snowflake_region", "created_on", "account_name", "name", "type", "is_primary"], []);

  if (s.includes("ACCOUNT_USAGE.POLICY_REFERENCES") && s.includes("COUNT(*)")) return rs(["REFERENCE_COUNT"], [["7"]]);
  if (s.includes("ACCOUNT_USAGE.POLICY_REFERENCES") && s.includes("'NETWORK_POLICY'")) return rs(POLICY_REFERENCE_COLUMNS, [policyReference("NETWORK_POLICY", "SVC_POLICY", "USER", "SVC_ETL")]);
  if (s.includes(policyReferencesFunctionCall("GOV", "POLICIES", "STRONG_PW"))) return rs(POLICY_REFERENCE_FUNCTION_COLUMNS, [policyFunctionReference("PASSWORD_POLICY", "STRONG_PW", "ACCOUNT", "MYORG-MYACCOUNT"), policyFunctionReference("PASSWORD_POLICY", "STRONG_PW", "USER", "BOB")]);
  if (s.includes(policyReferencesFunctionCall("GOV", "POLICIES", "SESSION_STRICT"))) return rs(POLICY_REFERENCE_FUNCTION_COLUMNS, [policyFunctionReference("SESSION_POLICY", "SESSION_STRICT", "ACCOUNT", "MYORG-MYACCOUNT")]);
  if (s.includes("ACCOUNT_USAGE.POLICY_REFERENCES") && s.includes("'MASKING_POLICY'")) {
    return rs(POLICY_REFERENCE_COLUMNS, [
      policyReference("MASKING_POLICY", "MASK_SSN", "TABLE", "CUSTOMERS", "SSN"),
      policyReference("MASKING_POLICY", "MASK_EMAIL", "TABLE", "CUSTOMERS", "EMAIL"),
      policyReference("MASKING_POLICY", "MASK_EMAIL", "TABLE", "LEADS", "EMAIL"),
    ]);
  }
  if (s.includes("ACCOUNT_USAGE.POLICY_REFERENCES") && s.includes("'ROW_ACCESS_POLICY'")) return rs(POLICY_REFERENCE_COLUMNS, [policyReference("ROW_ACCESS_POLICY", "REGION_RAP", "TABLE", "ORDERS")]);

  if (s.includes("ACCOUNT_USAGE.NETWORK_POLICIES") && s.includes("COUNT(*)")) return rs(["POLICY_COUNT"], [["1"]]);
  if (s.includes("ACCOUNT_USAGE.NETWORK_POLICIES")) return rs(NETWORK_POLICY_COLUMNS, [["CORP_POLICY", "SECURITYADMIN", "['10.0.0.0/8','192.168.1.0/24']", "[]", "2025-01-01", "2025-06-01"]]);
  if (s.includes("ACCOUNT_USAGE.USERS") && s.includes("COUNT(*)")) return rs(["USER_COUNT"], [["4"]]);
  if (s.includes("ACCOUNT_USAGE.USERS")) return rs(USER_COLUMNS, HEALTHY_USERS);
  if (s.includes("ACCOUNT_USAGE.PASSWORD_POLICIES") && s.includes("COUNT(*)")) return rs(["POLICY_COUNT"], [["1"]]);
  if (s.includes("ACCOUNT_USAGE.PASSWORD_POLICIES")) return rs(PASSWORD_POLICY_COLUMNS, [["STRONG_PW", "GOV", "POLICIES", "SECURITYADMIN", "14", "256", "1", "1", "1", "1", "0", "90", "5", "30", "12"]]);
  if (s.includes("ACCOUNT_USAGE.SESSION_POLICIES") && s.includes("COUNT(*)")) return rs(["POLICY_COUNT"], [["1"]]);
  if (s.includes("ACCOUNT_USAGE.SESSION_POLICIES")) return rs(SESSION_POLICY_COLUMNS, [["SESSION_STRICT", "GOV", "POLICIES", "SECURITYADMIN", "30", "30", "240", "240"]]);

  if (s.includes("ACCOUNT_USAGE.GRANTS_TO_ROLES") && s.includes("COUNT(*)")) return rs(["GRANT_COUNT"], [["12"]]);
  if (s.includes("ACCOUNT_USAGE.GRANTS_TO_ROLES") && s.includes("GRANTED_ON = 'ROLE'")) {
    return rs(GRANT_COLUMNS, [
      ["USAGE", "ROLE", "ANALYST", null, null, "ROLE", "SYSADMIN", "false", "SECURITYADMIN"],
      ["USAGE", "ROLE", "SYSADMIN", null, null, "ROLE", "ACCOUNTADMIN", "false", "SECURITYADMIN"],
      ["USAGE", "ROLE", "SECURITYADMIN", null, null, "ROLE", "ACCOUNTADMIN", "false", "SECURITYADMIN"],
      ["USAGE", "ROLE", "USERADMIN", null, null, "ROLE", "SECURITYADMIN", "false", "SECURITYADMIN"],
    ]);
  }
  if (s.includes("ACCOUNT_USAGE.GRANTS_TO_ROLES") && s.includes("GRANTED_ON = 'ACCOUNT'")) return rs(GLOBAL_GRANT_COLUMNS, [["MANAGE GRANTS", "ACCOUNT", "MYORG-MYACCOUNT", "ROLE", "SECURITYADMIN", "true"]]);
  if (s.includes("ACCOUNT_USAGE.GRANTS_TO_ROLES") && s.includes("GRANTED_TO = 'USER'")) return rs(DIRECT_GRANT_COLUMNS, []);
  if (s.includes("ACCOUNT_USAGE.GRANTS_TO_ROLES") && s.includes("GRANTEE_NAME = 'PUBLIC'")) return rs(PUBLIC_GRANT_COLUMNS, []);
  if (s.includes("ACCOUNT_USAGE.GRANTS_TO_USERS") && s.includes("COUNT(*)")) return rs(["GRANT_COUNT"], [["3"]]);
  if (s.includes("ACCOUNT_USAGE.GRANTS_TO_USERS")) return rs(["ROLE", "GRANTEE_NAME", "GRANTED_BY", "CREATED_ON"], [["ACCOUNTADMIN", "ALICE", "ACCOUNTADMIN", "2025-01-01"], ["ACCOUNTADMIN", "BOB", "ACCOUNTADMIN", "2025-01-01"], ["SECURITYADMIN", "ALICE", "ACCOUNTADMIN", "2025-01-01"]]);
  if (s.includes("ACCOUNT_USAGE.QUERY_HISTORY") && s.includes("GROUP BY ROLE_NAME")) return rs(["ROLE_NAME", "QUERY_COUNT", "USER_COUNT"], [["ANALYST", "500", "5"], ["SYSADMIN", "20", "1"]]);
  if (s.includes("ACCOUNT_USAGE.QUERY_HISTORY")) return rs(["QUERY_COUNT"], [["520"]]);
  if (s.includes("ACCOUNT_USAGE.LOGIN_HISTORY") && s.includes("GROUP BY IS_SUCCESS")) return rs(["IS_SUCCESS", "EVENT_COUNT"], [["YES", "900"], ["NO", "3"]]);
  if (s.includes("ACCOUNT_USAGE.LOGIN_HISTORY") && s.includes("IS_SUCCESS = 'NO'")) return rs(["USER_NAME", "CLIENT_IP", "REPORTED_CLIENT_TYPE", "FAILURE_COUNT", "LAST_ERROR"], [["BOB", "10.1.2.3", "SNOWFLAKE_UI", "3", "INCORRECT_USERNAME_PASSWORD"]]);
  if (s.includes("ACCOUNT_USAGE.LOGIN_HISTORY")) return rs(["EVENT_COUNT"], [["903"]]);
  if (s.includes("ACCOUNT_USAGE.ACCESS_HISTORY")) return rs(["EVENT_COUNT"], [["4200"]]);
  if (s.includes("ACCOUNT_USAGE.MASKING_POLICIES")) return rs(["POLICY_COUNT"], [["2"]]);
  if (s.includes("ACCOUNT_USAGE.ROW_ACCESS_POLICIES")) return rs(["POLICY_COUNT"], [["1"]]);
  if (s.includes("ACCOUNT_USAGE.TAG_REFERENCES") && s.includes("GROUP BY TAG_DATABASE")) return rs(["TAG_DATABASE", "TAG_SCHEMA", "TAG_NAME", "REFERENCE_COUNT"], [["GOV", "TAGS", "PII", "4"], ["GOV", "TAGS", "CONFIDENTIAL", "1"]]);
  if (s.includes("ACCOUNT_USAGE.TAG_REFERENCES")) return rs(["REFERENCE_COUNT"], [["5"]]);

  throw new Error(`No healthy fixture for statement: ${s}`);
}

function failingFixture(statement) {
  const s = normalizeStatement(statement);
  const rs = (columns, values) => resultSet(statement, columns, values);
  rejectUndocumentedAccountUsageKinds(s);

  if (s.startsWith("SELECT CURRENT_ACCOUNT()")) return rs(SESSION_COLUMNS, sessionContextRows("ACCOUNTADMIN"));
  if (s === "SHOW NETWORK POLICIES") return rs(["created_on", "name", "comment", "entries_in_allowed_ip_list", "entries_in_blocked_ip_list"], [["2025-01-01", "OPEN_POLICY", "", "1", "0"]]);
  if (s === "SHOW PARAMETERS LIKE 'NETWORK_POLICY' IN ACCOUNT") return rs(PARAMETER_COLUMNS, [["NETWORK_POLICY", "", "", "", "Network policy for the account", "STRING"]]);
  if (s === "SHOW PARAMETERS LIKE 'DATA_RETENTION_TIME_IN_DAYS' IN ACCOUNT") return rs(PARAMETER_COLUMNS, [["DATA_RETENTION_TIME_IN_DAYS", "0", "1", "ACCOUNT", "", "NUMBER"]]);
  if (s.startsWith("SHOW PARAMETERS LIKE 'REQUIRE_STORAGE_INTEGRATION_FOR_STAGE_%'")) {
    return rs(PARAMETER_COLUMNS, [
      ["REQUIRE_STORAGE_INTEGRATION_FOR_STAGE_CREATION", "false", "false", "", "", "BOOLEAN"],
      ["REQUIRE_STORAGE_INTEGRATION_FOR_STAGE_OPERATION", "false", "false", "", "", "BOOLEAN"],
    ]);
  }
  if (s.startsWith("SHOW PARAMETERS LIKE 'PREVENT_UNLOAD_TO_%'")) {
    return rs(PARAMETER_COLUMNS, [
      ["PREVENT_UNLOAD_TO_INLINE_URL", "false", "false", "", "", "BOOLEAN"],
      ["PREVENT_UNLOAD_TO_INTERNAL_STAGES", "false", "false", "", "", "BOOLEAN"],
    ]);
  }
  if (s === "SHOW INTEGRATIONS") {
    return rs(INTEGRATION_COLUMNS, [
      ["OLD_SAML", "SAML2", "SECURITY", "false", "", "2024-01-01"],
      ["LAMBDA_API", "AWS_API_GATEWAY", "API", "true", "", "2025-01-01"],
      ["OPENAI_ACCESS", "EXTERNAL_ACCESS", "EXTERNAL_ACCESS", "true", "", "2025-01-01"],
    ]);
  }
  if (s === "SHOW WAREHOUSES") return rs(WAREHOUSE_COLUMNS, [["ALWAYS_ON_WH", "STARTED", "STANDARD", "Large", "0", "true", "SYSADMIN"], ["SLOW_WH", "STARTED", "STANDARD", "Small", "3600", "true", "SYSADMIN"]]);
  if (s === "SHOW DATABASES") return rs(DATABASE_COLUMNS, [["2025-01-01", "SALES", "STANDARD", "", "SYSADMIN", "0"], ["2025-01-01", "HR", "STANDARD", "", "SYSADMIN", "7"]]);
  if (s === "SHOW SHARES") return rs(SHARE_COLUMNS, [["2025-01-01", "OUTBOUND", "MYORG.MYACCOUNT", "PARTNER_SHARE", "SALES", "PARTNER.ACCT1, PARTNER.ACCT2", "ACCOUNTADMIN", "", "MYORG.LISTING1", "false"]]);
  if (s === "SHOW REPLICATION GROUPS") return rs(["snowflake_region", "created_on", "account_name", "name", "type", "is_primary"], []);

  if (s.includes("ACCOUNT_USAGE.POLICY_REFERENCES") && s.includes("'NETWORK_POLICY'")) return rs(POLICY_REFERENCE_COLUMNS, []);
  if (s.includes(policyReferencesFunctionCall("GOV", "POLICIES", "WEAK_PW"))) return rs(POLICY_REFERENCE_FUNCTION_COLUMNS, [policyFunctionReference("PASSWORD_POLICY", "WEAK_PW", "USER", "NO_MFA_USER")]);
  if (s.includes(policyReferencesFunctionCall("GOV", "POLICIES", "LOOSE_SESSION"))) return rs(POLICY_REFERENCE_FUNCTION_COLUMNS, []);
  if (s.includes("ACCOUNT_USAGE.POLICY_REFERENCES") && s.includes("'MASKING_POLICY'")) return rs(POLICY_REFERENCE_COLUMNS, []);
  if (s.includes("ACCOUNT_USAGE.POLICY_REFERENCES") && s.includes("'ROW_ACCESS_POLICY'")) return rs(POLICY_REFERENCE_COLUMNS, []);
  if (s.includes("ACCOUNT_USAGE.NETWORK_POLICIES")) return rs(NETWORK_POLICY_COLUMNS, [["OPEN_POLICY", "SECURITYADMIN", "['0.0.0.0/0']", "[]", "2025-01-01", "2025-01-01"]]);
  if (s.includes("ACCOUNT_USAGE.USERS")) {
    return rs(USER_COLUMNS, [
      userRow({ NAME: "NO_MFA_USER", LOGIN_NAME: "NO_MFA_USER", HAS_MFA: "false", EXT_AUTHN_DUO: "false", LAST_SUCCESS_LOGIN: isoDaysAgo(200) }),
      userRow({ NAME: "GHOST", LOGIN_NAME: "GHOST", HAS_MFA: "true", LAST_SUCCESS_LOGIN: null }),
      userRow({ NAME: "SVC_LEGACY", LOGIN_NAME: "SVC_LEGACY", TYPE: "LEGACY_SERVICE", HAS_PASSWORD: "true", HAS_MFA: "false", HAS_RSA_PUBLIC_KEY: "false", LAST_SUCCESS_LOGIN: isoDaysAgo(2) }),
    ]);
  }
  if (s.includes("ACCOUNT_USAGE.PASSWORD_POLICIES")) return rs(PASSWORD_POLICY_COLUMNS, [["WEAK_PW", "GOV", "POLICIES", "SECURITYADMIN", "8", "256", "0", "0", "0", "0", "0", "0", "100", "0", "0"]]);
  if (s.includes("ACCOUNT_USAGE.SESSION_POLICIES")) return rs(SESSION_POLICY_COLUMNS, [["LOOSE_SESSION", "GOV", "POLICIES", "SECURITYADMIN", "240", "240", "1440", "1440"]]);
  if (s.includes("ACCOUNT_USAGE.GRANTS_TO_ROLES") && s.includes("GRANTED_ON = 'ROLE'")) {
    return rs(GRANT_COLUMNS, [
      ["USAGE", "ROLE", "ACCOUNTADMIN", null, null, "ROLE", "DATA_ENGINEER", "false", "ACCOUNTADMIN"],
      ["USAGE", "ROLE", "SYSADMIN", null, null, "ROLE", "ACCOUNTADMIN", "false", "SECURITYADMIN"],
      ["USAGE", "ROLE", "ORPHAN_ROLE", null, null, "ROLE", "DATA_ENGINEER", "false", "SECURITYADMIN"],
    ]);
  }
  if (s.includes("ACCOUNT_USAGE.GRANTS_TO_ROLES") && s.includes("GRANTED_ON = 'ACCOUNT'")) return rs(GLOBAL_GRANT_COLUMNS, [["MANAGE GRANTS", "ACCOUNT", "MYORG-MYACCOUNT", "ROLE", "DATA_ENGINEER", "false"]]);
  if (s.includes("ACCOUNT_USAGE.GRANTS_TO_ROLES") && s.includes("GRANTED_TO = 'USER'")) return rs(DIRECT_GRANT_COLUMNS, [["SELECT", "TABLE", "CUSTOMERS", "SALES", "PUBLIC", "ALICE"]]);
  if (s.includes("ACCOUNT_USAGE.GRANTS_TO_ROLES") && s.includes("GRANTEE_NAME = 'PUBLIC'")) return rs(PUBLIC_GRANT_COLUMNS, [["SELECT", "TABLE", "CUSTOMERS", "SALES", "PUBLIC", "SYSADMIN"]]);
  if (s.includes("ACCOUNT_USAGE.GRANTS_TO_USERS")) return rs(["ROLE", "GRANTEE_NAME", "GRANTED_BY", "CREATED_ON"], [["ACCOUNTADMIN", "A", "X", "2025"], ["ACCOUNTADMIN", "B", "X", "2025"], ["ACCOUNTADMIN", "C", "X", "2025"], ["ACCOUNTADMIN", "D", "X", "2025"]]);
  if (s.includes("ACCOUNT_USAGE.QUERY_HISTORY")) return rs(["ROLE_NAME", "QUERY_COUNT", "USER_COUNT"], [["ACCOUNTADMIN", "800", "3"], ["ANALYST", "200", "4"]]);
  if (s.includes("ACCOUNT_USAGE.LOGIN_HISTORY") && s.includes("GROUP BY IS_SUCCESS")) return rs(["IS_SUCCESS", "EVENT_COUNT"], [["YES", "100"], ["NO", "60"]]);
  if (s.includes("ACCOUNT_USAGE.LOGIN_HISTORY")) return rs(["USER_NAME", "CLIENT_IP", "REPORTED_CLIENT_TYPE", "FAILURE_COUNT", "LAST_ERROR"], [["ADMIN", "203.0.113.9", "JDBC_DRIVER", "55", "INCORRECT_USERNAME_PASSWORD"]]);
  if (s.includes("ACCOUNT_USAGE.ACCESS_HISTORY")) return rs(["EVENT_COUNT"], [["0"]]);
  if (s.includes("ACCOUNT_USAGE.MASKING_POLICIES")) return rs(["POLICY_COUNT"], [["0"]]);
  if (s.includes("ACCOUNT_USAGE.ROW_ACCESS_POLICIES")) return rs(["POLICY_COUNT"], [["2"]]);
  if (s.includes("ACCOUNT_USAGE.TAG_REFERENCES")) return rs(["TAG_DATABASE", "TAG_SCHEMA", "TAG_NAME", "REFERENCE_COUNT"], []);

  throw new Error(`No failing fixture for statement: ${s}`);
}

function emptyFixture(statement) {
  const healthy = healthyFixture(statement);
  return { ...healthy, rows: [], numRows: 0 };
}

function createMockClient(resolver, configOverrides = {}) {
  const executed = [];
  return {
    executed,
    getResolvedConfig: () => sampleConfig(configOverrides),
    async execute(statement) {
      assertReadOnlyStatement(statement);
      executed.push(statement);
      const result = await resolver(statement);
      return result;
    },
  };
}

function findingById(result, id) {
  const found = result.findings.find((item) => item.id === id);
  assert.ok(found, `expected finding ${id}`);
  return found;
}

function statusMap(result) {
  return Object.fromEntries(result.findings.map((item) => [item.id, item.status]));
}

async function runAllAssessments(client) {
  return [
    await assessSnowflakeNetworkAndAuthentication(client),
    await assessSnowflakeAccessControl(client),
    await assessSnowflakeMonitoringAndLifecycle(client),
    await assessSnowflakeDataProtection(client),
  ];
}

function allFindings(results) {
  return results.flatMap((result) => result.findings);
}

test("resolveSnowflakeConfiguration prefers explicit args over environment values and config files", () => {
  const home = createTempBase("grclanker-snowflake-home-");
  mkdirSync(join(home, ".snowflake"), { recursive: true });
  writeFileSync(join(home, ".snowflake", "connections.toml"), [
    "[default]",
    "account = \"toml-acct\"",
    "user = \"toml_user\"",
    "role = \"TOML_ROLE\"",
    "warehouse = \"TOML_WH\"",
    "authenticator = \"SNOWFLAKE_JWT\"",
    "",
  ].join("\n"));

  const resolved = resolveSnowflakeConfiguration(
    {
      account: "arg-acct",
      user: "arg_user",
      private_key: TEST_PRIVATE_KEY_PEM,
      role: "ARG_ROLE",
      timeout_seconds: 9,
      statement_timeout_seconds: 45,
      row_limit: 500,
    },
    {
      SNOWFLAKE_ACCOUNT: "env-acct",
      SNOWFLAKE_USER: "env_user",
      SNOWFLAKE_ROLE: "ENV_ROLE",
      SNOWFLAKE_WAREHOUSE: "ENV_WH",
      SNOWFLAKE_TOKEN: "env-token-value",
    },
    { homeDirectory: home },
  );

  assert.equal(resolved.account, "arg-acct");
  assert.equal(resolved.user, "arg_user");
  assert.equal(resolved.role, "ARG_ROLE");
  assert.equal(resolved.warehouse, "ENV_WH");
  assert.equal(resolved.tokenType, "KEYPAIR_JWT");
  assert.equal(resolved.privateKeyPem, TEST_PRIVATE_KEY_PEM.trim());
  assert.equal(resolved.baseUrl, "https://arg-acct.snowflakecomputing.com");
  assert.equal(resolved.timeoutMs, 9000);
  assert.equal(resolved.statementTimeoutSeconds, 45);
  assert.equal(resolved.rowLimit, 500);
  assert.equal(resolved.connectionName, "default");
  assert.ok(resolved.sourceChain.includes("arguments-account"));
  assert.ok(resolved.sourceChain.includes("environment-warehouse"));
  assert.ok(resolved.sourceChain.some((entry) => entry.startsWith("config-file:")));
});

test("resolveSnowflakeConfiguration falls back to environment values and then to connections.toml", () => {
  const home = createTempBase("grclanker-snowflake-home-");
  mkdirSync(join(home, ".snowflake"), { recursive: true });
  writeFileSync(join(home, ".snowflake", "rsa_key.p8"), TEST_PRIVATE_KEY_PEM);
  writeFileSync(join(home, ".snowflake", "connections.toml"), [
    "# audit connection",
    "[audit]",
    "account = \"myorg-myaccount\"",
    "user = \"toml_user\"  # trailing comment",
    "private_key_file = \"~/.snowflake/rsa_key.p8\"",
    "role = \"TOML_ROLE\"",
    "warehouse = \"TOML_WH\"",
    "",
  ].join("\n"));

  const fromEnv = resolveSnowflakeConfiguration(
    {},
    {
      SNOWFLAKE_ACCOUNT: "env_acct.us-east-1",
      SNOWFLAKE_USER: "env_user",
      SNOWFLAKE_PRIVATE_KEY: TEST_PRIVATE_KEY_PEM.replace(/\n/g, "\\n"),
      SNOWFLAKE_ROLE: "ENV_ROLE",
      SNOWFLAKE_CONNECTION_NAME: "audit",
    },
    { homeDirectory: home },
  );
  assert.equal(fromEnv.account, "env_acct.us-east-1");
  assert.equal(fromEnv.user, "env_user");
  assert.equal(fromEnv.role, "ENV_ROLE");
  assert.equal(fromEnv.warehouse, "TOML_WH");
  assert.equal(fromEnv.privateKeyPem, TEST_PRIVATE_KEY_PEM);
  assert.equal(fromEnv.baseUrl, "https://env-acct.us-east-1.snowflakecomputing.com");
  assert.ok(fromEnv.sourceChain.includes("environment-account"));
  assert.ok(fromEnv.sourceChain.includes("config-file-warehouse"));

  const fromToml = resolveSnowflakeConfiguration({ connection: "audit" }, {}, { homeDirectory: home });
  assert.equal(fromToml.account, "myorg-myaccount");
  assert.equal(fromToml.user, "toml_user");
  assert.equal(fromToml.role, "TOML_ROLE");
  assert.equal(fromToml.warehouse, "TOML_WH");
  assert.equal(fromToml.tokenType, "KEYPAIR_JWT");
  assert.equal(fromToml.privateKeyPem, TEST_PRIVATE_KEY_PEM);
  assert.equal(fromToml.connectionName, "audit");
  assert.ok(fromToml.sourceChain.includes("config-file-account"));
  assert.ok(fromToml.sourceChain.includes("config-file-private-key-path"));
});

test("resolveSnowflakeConfiguration reads config.toml default_connection_name and honors SNOWFLAKE_HOME", () => {
  const home = createTempBase("grclanker-snowflake-home-");
  const snowflakeHome = join(home, "custom-snowflake-home");
  mkdirSync(snowflakeHome, { recursive: true });
  writeFileSync(join(snowflakeHome, "config.toml"), [
    "default_connection_name = \"prod\"",
    "",
    "[connections.prod]",
    "account = \"prodorg-prodacct\"",
    "user = \"prod_user\"",
    "token = \"config-oauth-token\"",
    "authenticator = \"oauth\"",
    "",
    "[connections.other]",
    "account = \"other\"",
    "user = \"other\"",
    "",
  ].join("\n"));

  const resolved = resolveSnowflakeConfiguration({}, { SNOWFLAKE_HOME: snowflakeHome }, { homeDirectory: home });
  assert.equal(resolved.account, "prodorg-prodacct");
  assert.equal(resolved.user, "prod_user");
  assert.equal(resolved.tokenType, "OAUTH");
  assert.equal(resolved.token, "config-oauth-token");
  assert.equal(resolved.connectionName, "prod");
  assert.ok(resolved.sourceChain.some((entry) => entry.startsWith(`config-file:${join(snowflakeHome, "config.toml")}`)));
});

test("resolveSnowflakeConfiguration supports OAuth and programmatic access tokens and rejects password-only setups", () => {
  const oauth = resolveSnowflakeConfiguration({}, {
    SNOWFLAKE_ACCOUNT: "myorg-myaccount",
    SNOWFLAKE_USER: "svc",
    SNOWFLAKE_TOKEN: "oauth-access-token",
    SNOWFLAKE_BASE_URL: "https://myorg-myaccount.privatelink.snowflakecomputing.com/",
  }, { homeDirectory: createTempBase("grclanker-snowflake-empty-home-") });
  assert.equal(oauth.tokenType, "OAUTH");
  assert.equal(oauth.token, "oauth-access-token");
  assert.equal(oauth.baseUrl, "https://myorg-myaccount.privatelink.snowflakecomputing.com");

  const pat = resolveSnowflakeConfiguration({ token: "pat-token", token_type: "PROGRAMMATIC_ACCESS_TOKEN" }, {
    SNOWFLAKE_ACCOUNT: "myorg-myaccount",
    SNOWFLAKE_USER: "svc",
  }, { homeDirectory: createTempBase("grclanker-snowflake-empty-home-") });
  assert.equal(pat.tokenType, "PROGRAMMATIC_ACCESS_TOKEN");

  assert.throws(
    () => resolveSnowflakeConfiguration({}, { SNOWFLAKE_ACCOUNT: "acct", SNOWFLAKE_USER: "user", SNOWFLAKE_PASSWORD: "hunter2" }, { homeDirectory: createTempBase("grclanker-snowflake-empty-home-") }),
    /Username\/password authentication is not supported/,
  );
  assert.throws(
    () => resolveSnowflakeConfiguration({}, { SNOWFLAKE_USER: "user" }, { homeDirectory: createTempBase("grclanker-snowflake-empty-home-") }),
    /SNOWFLAKE_ACCOUNT/,
  );
  assert.throws(
    () => resolveSnowflakeConfiguration({ private_key_path: "/nonexistent/rsa_key.p8" }, { SNOWFLAKE_ACCOUNT: "acct", SNOWFLAKE_USER: "user" }, { homeDirectory: createTempBase("grclanker-snowflake-empty-home-") }),
    /private key file was not found/,
  );
});

test("parseSimpleToml handles sections, quoted keys, comments, numbers, and booleans", () => {
  const parsed = parseSimpleToml([
    "# top-level comment",
    "default_connection_name = \"audit\"",
    "",
    "[connections.audit]",
    "account = 'org-acct'",
    "user = \"someone\" # inline comment",
    "port = 443",
    "insecure = false",
    "[connections.\"quoted name\"]",
    "account = \"\"\"triple\"\"\"",
  ].join("\n"));

  assert.equal(parsed[""].default_connection_name, "audit");
  assert.equal(parsed["connections.audit"].account, "org-acct");
  assert.equal(parsed["connections.audit"].user, "someone");
  assert.equal(parsed["connections.audit"].port, 443);
  assert.equal(parsed["connections.audit"].insecure, false);
  assert.equal(parsed["connections.quoted name"].account, "triple");
});

/** Canaries planted on malformed config lines: random alphanumerics, so no 6-character window of one occurs in a legitimate fixture value or in another canary. */
const CONFIG_CANARIES = {
  bareLine: "Bp6TzX3kW9nQ2sRc",
  unterminated: "Lf9BwD4sN7hVe3Ky",
  multiline: "Tn3XcM6zP8gQb5Rw",
  missingValue: "Rk8VqL2tY7jCn4Fs",
  readable: "Zx4HnV7qK2mYt9Pw",
  privateKey: "Qv7ZkT3mR9pXw2Lc",
};
const LIBRARY_ERROR_WORDING = [
  "Nested mappings", "is not valid JSON", "Unresolved alias", "illegal operation", "permission denied", "no such file",
  "not a directory", "Unexpected token", "DECODER routines", "unsupported", "BEGIN PRIVATE KEY",
];

/** Every substring of a planted credential at lengths 6 through 24 (sliding windows), so a partial echo such as a truncated token or a quoted line fragment cannot pass a leak assertion. */
function windowsOf(value, { min = 6, max = 24 } = {}) {
  const windows = new Set();
  for (let size = Math.min(min, value.length); size <= Math.min(max, value.length); size += 1) {
    for (let index = 0; index + size <= value.length; index += 1) windows.add(value.slice(index, index + size));
  }
  return [...windows];
}

/** The window set of every planted secret, for bundle, zip, and payload scans through assertSecretsAbsent. */
function leakWindows(secrets) {
  return [...new Set(secrets.flatMap((secret) => windowsOf(secret)))];
}

function assertNoWindowOf(text, secret, label) {
  for (const window of windowsOf(secret)) assert.ok(!text.includes(window), `${label} carries a window (${window}) of the planted credential: ${text.slice(0, 300)}`);
}

/**
 * Window scan over many outputs: the joined text is checked first (one pass per window), and only a
 * hit falls back to the per-output scan so the failure names the file that carries the window.
 */
function assertNoLeakWindows(outputs, secrets, label) {
  const joined = [...outputs.values()].join("\n");
  const windows = leakWindows(secrets);
  if (windows.some((window) => joined.includes(window))) assertSecretsAbsent(assert, outputs, windows, label);
}

/**
 * Fixture self-check: the legitimate values of a fixture (everything it serves
 * with the planted canaries themselves removed, longest first) contain no
 * 6-character window of any canary, so a window hit in an output can only be a leak.
 */
function assertFixtureFreeOfCanaryWindows(legitimateText, canaries, label) {
  let legitimate = legitimateText;
  for (const canary of [...canaries].sort((a, b) => b.length - a.length)) legitimate = legitimate.split(canary).join("");
  for (const canary of canaries) {
    for (const window of windowsOf(canary, { min: 6, max: 6 })) {
      assert.ok(!legitimate.includes(window), `${label}: legitimate fixture text contains the window ${window} of canary ${canary}`);
    }
  }
}

function assertConfigErrorText(text, { path, code, line, canaries }, label) {
  for (const canary of canaries) assertNoWindowOf(text, canary, `${label} (${canary})`);
  for (const wording of LIBRARY_ERROR_WORDING) assert.ok(!text.includes(wording), `${label} repeats library wording "${wording}": ${text}`);
  if (path) assert.ok(text.includes(path), `${label} names the path ${path}: ${text}`);
  assert.ok(text.includes(`(${code})`), `${label} carries the code ${code}: ${text}`);
  if (line) assert.ok(text.includes(` at line ${line}`), `${label} carries the position line ${line}: ${text}`);
  else assert.doesNotMatch(text, / at line \d+/, `${label} invents no line: ${text}`);
}

function thrownBy(fn) {
  try {
    fn();
  } catch (error) {
    return error;
  }
  assert.fail("expected the call to throw");
}

async function withSnowflakeHome(snowflakeHome, run) {
  const saved = process.env.SNOWFLAKE_HOME;
  process.env.SNOWFLAKE_HOME = snowflakeHome;
  try {
    return await run();
  } finally {
    if (saved === undefined) delete process.env.SNOWFLAKE_HOME;
    else process.env.SNOWFLAKE_HOME = saved;
  }
}

test("rule 9: Snowflake TOML and private key file errors carry only the path, line, and code, never a config line, key material, or filesystem wording", async () => {
  const base = createTempBase("grclanker-snowflake-config-errors-");
  const registered = [];
  registerSnowflakeTools({ registerTool: (tool) => registered.push(tool) });
  const checkAccess = registered.find((tool) => tool.name === "snowflake_check_access");
  const exportBundle = registered.find((tool) => tool.name === "snowflake_export_audit_bundle");
  const allCanaries = Object.values(CONFIG_CANARIES);
  const env = { SNOWFLAKE_ACCOUNT: "myorg-myaccount", SNOWFLAKE_USER: "svc", SNOWFLAKE_TOKEN: "env-token" };
  let homes = 0;
  const snowflakeHome = () => {
    homes += 1;
    const dir = join(base, `home-${homes}`);
    mkdirSync(dir, { recursive: true });
    return dir;
  };

  const parseCases = [
    { name: "bare credential line", text: `[default]\naccount = "myorg-myaccount"\nuser = "svc"\n${CONFIG_CANARIES.bareLine}\n`, line: 4 },
    { name: "unterminated quote", text: `[default]\naccount = "myorg-myaccount"\ntoken = "${CONFIG_CANARIES.unterminated}\nuser = "svc"\n`, line: 3 },
    { name: "multi-line string", text: `[default]\nprivate_key_raw = """-----BEGIN PRIVATE KEY-----\n${CONFIG_CANARIES.multiline}\n-----END PRIVATE KEY-----"""\n`, line: 2 },
    { name: "missing value", text: `[default]\ntoken =\n# ${CONFIG_CANARIES.missingValue}\n`, line: 2 },
  ];
  // Self-check: nothing the malformed files, the environment, or the temp paths legitimately carry shares a 6-character window with a planted canary.
  assertFixtureFreeOfCanaryWindows(`${parseCases.map((testCase) => testCase.text).join("\n")} ${JSON.stringify(env)} ${base}`, allCanaries, "config file canaries");
  for (const testCase of parseCases) {
    for (const fileName of ["connections.toml", "config.toml"]) {
      const home = snowflakeHome();
      const tomlPath = join(home, fileName);
      writeFileSync(tomlPath, testCase.text);
      const direct = thrownBy(() => parseSimpleToml(testCase.text));
      assert.equal(direct.name, "SnowflakeTomlSyntaxError", `${testCase.name}: the parser reports a structured syntax error`);
      assert.equal(direct.line, testCase.line, `${testCase.name}: the parser records the line`);
      assert.equal(direct.message, `Invalid TOML at line ${testCase.line}`, `${testCase.name}: the parser message is the line number only`);

      const expected = { path: tomlPath, code: "INVALID_TOML", line: testCase.line, canaries: allCanaries };
      const thrown = thrownBy(() => resolveSnowflakeConfiguration({}, { ...env, SNOWFLAKE_HOME: home }, { homeDirectory: base }));
      assert.equal(thrown.message, `Unable to parse Snowflake config file: invalid TOML in ${tomlPath} at line ${testCase.line} (INVALID_TOML)`, `${testCase.name} in ${fileName}`);
      assertConfigErrorText(thrown.message, expected, `${testCase.name} resolver error (${fileName})`);
      const result = await withSnowflakeHome(home, () => checkAccess.execute("call", checkAccess.prepareArguments({ account: "myorg-myaccount", user: "svc", token: "arg-token" })));
      assertConfigErrorText(JSON.stringify(result), expected, `${testCase.name} check_access payload (${fileName})`);
    }
  }

  const exportHome = snowflakeHome();
  writeFileSync(join(exportHome, "connections.toml"), parseCases[0].text);
  const outputRoot = join(base, "export");
  const exported = await withSnowflakeHome(exportHome, () => exportBundle.execute("call", exportBundle.prepareArguments({ output_dir: outputRoot })));
  assertConfigErrorText(JSON.stringify(exported), { path: join(exportHome, "connections.toml"), code: "INVALID_TOML", line: 4, canaries: allCanaries }, "export payload");
  assert.equal(existsSync(outputRoot), false, "a config error writes no bundle");

  const readCases = [
    { name: "EISDIR", file: "connections.toml", setup: (path) => mkdirSync(path), control: /illegal operation/ },
    { name: "EISDIR", file: "config.toml", setup: (path) => mkdirSync(path), control: /illegal operation/ },
  ];
  if (process.getuid?.() !== 0) {
    readCases.push({ name: "EACCES", file: "connections.toml", setup: (path) => { writeFileSync(path, `[default]\ntoken = "${CONFIG_CANARIES.readable}"\n`); chmodSync(path, 0o000); }, control: /permission denied/ });
  }
  for (const testCase of readCases) {
    const home = snowflakeHome();
    const tomlPath = join(home, testCase.file);
    testCase.setup(tomlPath);
    assert.match(thrownBy(() => readFileSync(tomlPath, "utf8")).message, testCase.control, `${testCase.name}: positive control uses the filesystem message`);
    const expected = { path: tomlPath, code: testCase.name, canaries: allCanaries };
    const thrown = thrownBy(() => resolveSnowflakeConfiguration({}, { ...env, SNOWFLAKE_HOME: home }, { homeDirectory: base }));
    assert.equal(thrown.message, `Unable to read Snowflake config file ${tomlPath} (${testCase.name})`);
    const result = await withSnowflakeHome(home, () => checkAccess.execute("call", checkAccess.prepareArguments({ account: "myorg-myaccount", user: "svc", token: "arg-token" })));
    assertConfigErrorText(JSON.stringify(result), expected, `${testCase.name} check_access payload (${testCase.file})`);
  }

  const emptyHome = snowflakeHome();
  const absent = resolveSnowflakeConfiguration({}, { ...env, SNOWFLAKE_HOME: emptyHome }, { homeDirectory: base });
  assert.equal(absent.token, "env-token", "missing TOML files are absent, not read failures");
  const notDirectory = join(base, "plain-file");
  writeFileSync(notDirectory, "x");
  const enotdir = thrownBy(() => resolveSnowflakeConfiguration({}, { ...env, SNOWFLAKE_HOME: notDirectory }, { homeDirectory: base }));
  assert.equal(enotdir.message, `Unable to read Snowflake config file ${join(notDirectory, "config.toml")} (ENOTDIR)`);

  const keyDirectory = join(base, "key-directory.p8");
  mkdirSync(keyDirectory);
  const keyIsDir = thrownBy(() => resolveSnowflakeConfiguration({ private_key_path: keyDirectory }, { SNOWFLAKE_ACCOUNT: "myorg-myaccount", SNOWFLAKE_USER: "svc", SNOWFLAKE_HOME: emptyHome }, { homeDirectory: base }));
  assert.equal(keyIsDir.message, `Unable to read Snowflake private key file ${keyDirectory} (EISDIR)`);
  const keyMissing = thrownBy(() => resolveSnowflakeConfiguration({ private_key_path: join(base, "missing.p8") }, { SNOWFLAKE_ACCOUNT: "myorg-myaccount", SNOWFLAKE_USER: "svc", SNOWFLAKE_HOME: emptyHome }, { homeDirectory: base }));
  assert.equal(keyMissing.message, `Snowflake private key file was not found: ${join(base, "missing.p8")} (ENOENT)`);
  if (process.getuid?.() !== 0) {
    const lockedKey = join(base, "locked.p8");
    writeFileSync(lockedKey, `-----BEGIN PRIVATE KEY-----\n${CONFIG_CANARIES.privateKey}\n-----END PRIVATE KEY-----\n`);
    chmodSync(lockedKey, 0o000);
    const keyLocked = thrownBy(() => resolveSnowflakeConfiguration({ private_key_path: lockedKey }, { SNOWFLAKE_ACCOUNT: "myorg-myaccount", SNOWFLAKE_USER: "svc", SNOWFLAKE_HOME: emptyHome }, { homeDirectory: base }));
    assert.equal(keyLocked.message, `Unable to read Snowflake private key file ${lockedKey} (EACCES)`);
  }

  const garbageKey = `-----BEGIN PRIVATE KEY-----\n${CONFIG_CANARIES.privateKey}\n-----END PRIVATE KEY-----\n`;
  const unloadable = thrownBy(() => buildSnowflakeKeyPairJwt({ account: "myorg-myaccount", user: "svc", privateKeyPem: garbageKey }));
  assert.match(unloadable.message, /^Unable to load the Snowflake private key \((ERR_[A-Z0-9_]+|INVALID_PRIVATE_KEY)\)\. Provide a PKCS#8 PEM key/);
  assertConfigErrorText(unloadable.message, { code: unloadable.message.match(/\(([A-Z0-9_]+)\)/)[1], canaries: allCanaries }, "unloadable key error");
  const keyResult = JSON.stringify(await withSnowflakeHome(emptyHome, () => checkAccess.execute("call", checkAccess.prepareArguments({ account: "myorg-myaccount", user: "svc", private_key: garbageKey }))));
  assertConfigErrorText(keyResult, { code: unloadable.message.match(/\(([A-Z0-9_]+)\)/)[1], canaries: allCanaries }, "unloadable key check_access payload");
});

test("buildSnowflakeKeyPairJwt produces an RS256 token with the documented issuer and subject", () => {
  const now = new Date("2026-09-21T12:00:00Z");
  const built = buildSnowflakeKeyPairJwt({ account: "myorg-myaccount", user: "auditor", privateKeyPem: TEST_PRIVATE_KEY_PEM }, now);
  const [headerPart, payloadPart, signaturePart] = built.token.split(".");
  const header = JSON.parse(Buffer.from(headerPart, "base64url").toString("utf8"));
  const payload = JSON.parse(Buffer.from(payloadPart, "base64url").toString("utf8"));

  assert.equal(header.alg, "RS256");
  assert.equal(header.typ, "JWT");
  const fingerprint = computePublicKeyFingerprint(testPrivateKey);
  assert.match(fingerprint, /^SHA256:[A-Za-z0-9+/]+=*$/);
  assert.equal(payload.iss, `MYORG-MYACCOUNT.AUDITOR.${fingerprint}`);
  assert.equal(payload.sub, "MYORG-MYACCOUNT.AUDITOR");
  assert.equal(built.issuer, payload.iss);
  assert.equal(built.subject, payload.sub);
  assert.equal(payload.iat, Math.floor(now.getTime() / 1000));
  assert.ok(payload.exp > payload.iat);
  assert.ok(payload.exp - payload.iat <= 3600);

  const verifier = createVerify("RSA-SHA256");
  verifier.update(`${headerPart}.${payloadPart}`);
  assert.equal(verifier.verify(TEST_PUBLIC_KEY_PEM, Buffer.from(signaturePart, "base64url")), true);
});

test("buildSnowflakeKeyPairJwt strips regions from legacy locators and loads encrypted keys with a passphrase", () => {
  assert.equal(normalizeJwtAccountIdentifier("xy12345.us-east-1.aws"), "XY12345");
  assert.equal(normalizeJwtAccountIdentifier("myorg-myaccount"), "MYORG-MYACCOUNT");
  assert.equal(normalizeJwtAccountIdentifier("xy12345-abc123.global"), "XY12345");

  const legacy = buildSnowflakeKeyPairJwt({ account: "xy12345.us-east-1", user: "svc_user", privateKeyPem: TEST_PRIVATE_KEY_PEM });
  assert.equal(legacy.subject, "XY12345.SVC_USER");

  const encryptedPem = testPrivateKey.export({ type: "pkcs8", format: "pem", cipher: "aes-256-cbc", passphrase: "topsecret" });
  const encrypted = buildSnowflakeKeyPairJwt({ account: "myorg-myaccount", user: "auditor", privateKeyPem: encryptedPem, privateKeyPassphrase: "topsecret" });
  assert.equal(encrypted.subject, "MYORG-MYACCOUNT.AUDITOR");
  assert.throws(
    () => buildSnowflakeKeyPairJwt({ account: "myorg-myaccount", user: "auditor", privateKeyPem: encryptedPem }),
    /Unable to load the Snowflake private key/,
  );
  assert.throws(() => buildSnowflakeKeyPairJwt({ account: "myorg-myaccount", user: "auditor" }), /requires a private key/);
});

test("redactSecrets removes private keys, JWTs, bearer tokens, and configured secrets", () => {
  const jwt = buildSnowflakeKeyPairJwt({ account: "a", user: "b", privateKeyPem: TEST_PRIVATE_KEY_PEM }).token;
  const message = `failed with ${TEST_PRIVATE_KEY_PEM} token ${jwt} header Bearer abcdefghijkl passphrase topsecret`;
  const redacted = redactSecrets(message, ["topsecret"]);
  assert.ok(!redacted.includes("BEGIN PRIVATE KEY"));
  assertNoWindowOf(redacted, TEST_PRIVATE_KEY_PEM.split("\n")[1], "the PEM body");
  assertNoWindowOf(redacted, jwt, "the JWT");
  assertNoWindowOf(redacted, "abcdefghijkl", "a plain-word value after the Bearer scheme (removed whatever its shape)");
  assertNoWindowOf(redacted, "topsecret", "the configured passphrase");
  assert.match(redacted, /^failed with \[REDACTED\]\s*token \[REDACTED\] header Bearer \[REDACTED\] passphrase \[REDACTED\]$/);
});

test("rule 9: scrub boundary: a name-shaped value stays bare in prose and is removed inside every carrier, as a configured secret in every encoding, and whenever it has a real token shape", () => {
  const bare = "statement failed for warehouse prod-us-east-2026 owned by role sess-canary-COOKIE-31415926535897";
  assert.equal(redactSecrets(bare), bare, "a name-shaped value bare in prose is indistinguishable from a resource name");
  assert.equal(redactSecrets(bare, ["prod-us-east-2026"]), "statement failed for warehouse [REDACTED] owned by role sess-canary-COOKIE-31415926535897");
  const carriers = [
    ["Cookie: sid=prod-us-east-2026; Path=/", "Cookie: [REDACTED]"],
    ["Set-Cookie: session=prod-us-east-2026; HttpOnly", "Set-Cookie: [REDACTED]"],
    ["X-Api-Key: prod-us-east-2026 rejected", "X-Api-Key: [REDACTED] rejected"],
    ["Authorization: Basic prod-us-east-2026 rejected", "Authorization: Basic [REDACTED] rejected"],
    ["token=prod-us-east-2026 rejected", "token=[REDACTED] rejected"],
    ['{"client_secret": "prod-us-east-2026"} rejected', '{"client_secret": "[REDACTED]"} rejected'],
    ["(session_id: prod-us-east-2026) rejected", "(session_id: [REDACTED]) rejected"],
    ["https://svc:prod-us-east-2026@host/p?k=prod-us-east-2026 rejected", "https://host/p?[REDACTED] rejected"],
    ["Bearer prod-us-east-2026 rejected", "Bearer [REDACTED] rejected"],
    ["SSWS prod-us-east-2026 rejected", "SSWS [REDACTED] rejected"],
    ["Basic authentication is required", "Basic authentication is required"],
    ["InvalidAuthenticationToken: Access token has expired", "InvalidAuthenticationToken: Access token has expired"],
  ];
  const name = "prod-us-east-2026";
  for (const [input, expected] of carriers) {
    const scrubbed = redactSecrets(input);
    assert.equal(scrubbed, expected, input);
    if (input.includes(name) && !expected.includes(name)) assertNoWindowOf(scrubbed, name, `carrier ${input}`);
  }
  assertNoWindowOf(redactSecrets(bare, [name]), name, "configured secret in prose");

  // Quoted header values (the Codex P1 carrier class): the value goes whatever its quote style (plain, single, JSON-escaped), separator, or frame; the quote and any scheme word stay; quoted non-credential headers come back unchanged.
  const quotedExpectations = [
    [`Cookie: sid="${name}"; Path=/`, "Cookie: [REDACTED]"],
    [`Cookie: sid=\\"${name}\\"`, "Cookie: [REDACTED]"],
    [`Set-Cookie: session='${name}'; HttpOnly`, "Set-Cookie: [REDACTED]"],
    [`Authorization: Bearer "${name}" rejected`, 'Authorization: Bearer "[REDACTED]" rejected'],
    [`Authorization: Bearer '${name}' rejected`, "Authorization: Bearer '[REDACTED]' rejected"],
    [`Authorization: "Bearer ${name}" rejected`, 'Authorization: "Bearer [REDACTED]" rejected'],
    [`\\"Authorization\\": \\"Bearer ${name}\\"`, '\\"Authorization\\": \\"Bearer [REDACTED]\\"'],
    [`X-Api-Key: \\"Ab3dEf9hIj2k\\", next`, 'X-Api-Key: \\"[REDACTED]\\", next'],
    [`X-Auth-Token: "Ab3dEf9hIj2k"`, 'X-Auth-Token: "[REDACTED]"'],
    [`Bearer "${name}" rejected`, 'Bearer "[REDACTED]" rejected'],
  ];
  for (const [input, expected] of quotedExpectations) assert.equal(redactSecrets(input), expected, input);
  // Compound header lines (reviewer B's shape): a quoted value ends at its closing quote, an unquoted cookie or header value ends at ";" or "," before the next "Name:" token or at the end of the line, and the following header keeps its name and gets its own carrier treatment.
  const requestId = "3f2b6a1e-9c4d-4e8f-b1a2-6d7c8e9f0a1b";
  const compoundExpectations = [
    [`Cookie: sid="${name}"; X-Api-Key: "${name}"; Content-Type: "application/json"`, 'Cookie: [REDACTED]; X-Api-Key: "[REDACTED]"; Content-Type: "application/json"'],
    [`Cookie: sid=${name}; X-Api-Key: ${name}; Content-Type: application/json`, "Cookie: [REDACTED]; X-Api-Key: [REDACTED]; Content-Type: application/json"],
    [`Cookie: "sid=${name}; Path=/"; X-Api-Key: "${name}"; Content-Type: "application/json"`, 'Cookie: "[REDACTED]"; X-Api-Key: "[REDACTED]"; Content-Type: "application/json"'],
    [`Set-Cookie: session=${name}; Path=/; HttpOnly, X-Api-Key: ${name}, Content-Type: text/html`, "Set-Cookie: [REDACTED], X-Api-Key: [REDACTED], Content-Type: text/html"],
    [`X-Api-Key: "${name}"; X-Auth-Token: "${name}"`, 'X-Api-Key: "[REDACTED]"; X-Auth-Token: "[REDACTED]"'],
    [`X-Api-Key: ${name}; X-Auth-Token: ${name}; Content-Type: application/json`, "X-Api-Key: [REDACTED]; X-Auth-Token: [REDACTED]; Content-Type: application/json"],
    [`Authorization: Bearer "${name}", X-Api-Key: "${name}", Content-Type: "application/json"`, 'Authorization: Bearer "[REDACTED]", X-Api-Key: "[REDACTED]", Content-Type: "application/json"'],
    [`Cookie: sid=${name}; {"error": "invalid_token", "client_secret": "${name}", "request_id": "${requestId}"}`, `Cookie: [REDACTED]; {"error": "invalid_token", "client_secret": "[REDACTED]", "request_id": "${requestId}"}`],
    [`Cookie: sid="${name}" {"error": "invalid_token", "request_id": "${requestId}"}`, `Cookie: [REDACTED] {"error": "invalid_token", "request_id": "${requestId}"}`],
    [`Cookie: sid=\\"${name}\\"; X-Api-Key: \\"${name}\\"; Content-Type: \\"application/json\\"`, 'Cookie: [REDACTED]; X-Api-Key: \\"[REDACTED]\\"; Content-Type: \\"application/json\\"'],
    [`{\\"Cookie\\": \\"sid=${name}; Path=/\\", \\"X-Api-Key\\": \\"${name}\\", \\"Content-Type\\": \\"application/json\\"}`, '{\\"Cookie\\": \\"[REDACTED]\\", \\"X-Api-Key\\": \\"[REDACTED]\\", \\"Content-Type\\": \\"application/json\\"}'],
  ];
  const gatewayBody = (line) => `Snowflake statement failed (502 Bad Gateway) for /api/v2/statements: <html><body><h1>502 Bad Gateway</h1><p>upstream headers: ${line}</p></body></html>`;
  for (const [input, expected] of compoundExpectations) {
    for (const [label, rendered, expectedRendered] of [["bare", input, expected], ["502 body", gatewayBody(input), gatewayBody(expected)]]) {
      const scrubbed = redactSecrets(rendered);
      assert.equal(scrubbed, expectedRendered, `${label}: ${rendered}`);
      assertNoWindowOf(scrubbed, name, `compound ${label} ${rendered}`);
      for (const following of ["X-Api-Key", "X-Auth-Token", "Content-Type"]) {
        if (rendered.includes(`${following}`)) assert.ok(scrubbed.includes(following), `${following} keeps its name in ${scrubbed}`);
      }
      if (rendered.includes("application/json")) assert.ok(scrubbed.includes("application/json"), `Content-Type keeps its value in ${scrubbed}`);
      if (rendered.includes(requestId)) assert.ok(scrubbed.includes(requestId), `the request id stays in ${scrubbed}`);
      assert.equal(redactSecrets(scrubbed), scrubbed, `second pass over ${rendered}`);
    }
  }
  const quotedCarriers = [
    (value, separator) => `Cookie${separator}sid=${value}; Path=/`,
    (value, separator) => `Cookie${separator}sid = ${value}`,
    (value, separator) => `Set-Cookie${separator}session=${value}; HttpOnly`,
    (value, separator) => `X-Api-Key${separator}${value}`,
    (value, separator) => `X-Auth-Token${separator}${value}`,
    (value, separator) => `Authorization${separator}${value}`,
    (value, separator) => `Authorization${separator}Bearer ${value}`,
    (value, separator) => `Authorization${separator}Basic ${value}`,
    (value, separator) => `Authorization${separator}Snowflake Token=${value}`,
    (value, separator) => `Proxy-Authorization${separator}Bearer ${value}`,
    (value, separator, raw, quote) => `Authorization${separator}${quote}Bearer ${raw}${quote}`,
  ];
  const quotedFrames = [
    (line) => line,
    (line) => `Snowflake statement failed (401 Unauthorized) for /api/v2/statements: the request carried ${line} and was rejected`,
    (line) => `{"code":"390144","message":"Invalid header: ${line}","sqlState":"08001"}`,
  ];
  for (const raw of [name, "Ab3dEf9hIj2k"]) {
    for (const carrier of quotedCarriers) {
      for (const separator of [": ", ":", " : ", " :"]) {
        for (const frame of quotedFrames) {
          for (const quote of ['"', "'", '\\"']) {
            const input = frame(carrier(`${quote}${raw}${quote}`, separator, raw, quote));
            assertNoWindowOf(redactSecrets(input), raw, `quoted carrier ${input}`);
          }
          const control = frame(carrier(raw, separator, raw, ""));
          assertNoWindowOf(redactSecrets(control), raw, `unquoted carrier ${control}`);
        }
      }
    }
  }
  for (const header of SNOWFLAKE_QUOTED_HEADERS_KEPT) {
    assert.equal(redactSecrets(header), header, `must keep quoted header: ${header}`);
    const sentence = `Snowflake statement failed (400 Bad Request) for /api/v2/statements: the response carried ${header}`;
    assert.equal(redactSecrets(sentence), sentence, `must keep quoted header in a sentence: ${sentence}`);
  }
  const secret = 'top secret/value+1"x';
  const forms = {
    raw: secret,
    json: JSON.stringify(secret).slice(1, -1),
    url: encodeURIComponent(secret),
    base64: Buffer.from(secret).toString("base64"),
    base64url: Buffer.from(secret).toString("base64url"),
  };
  const encodedText = Object.entries(forms).map(([name, form]) => `${name}=${form}`).join(" ");
  assert.equal(redactSecrets(encodedText, [secret]), "raw=[REDACTED] json=[REDACTED] url=[REDACTED] base64=[REDACTED] base64url=[REDACTED]");
  assert.equal(
    redactSecrets("bare shapes eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhIn0.c2lnbmF0dXJl 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08 QmFzZTY0K1N5bWJvbHM= aB3xZ9qL2mN8pR4tV7wY1 ABCD-EFGH-1234-5678 xKqZvBnMwLpRtYsHdG stay-01 name_with_words-2026 ERR_MODULE_NOT_FOUND"),
    "bare shapes [REDACTED] [REDACTED] [REDACTED] [REDACTED] [REDACTED] [REDACTED] stay-01 name_with_words-2026 ERR_MODULE_NOT_FOUND",
    "a JWT, a hex digest, a padded base64 run, scattered digits, a second numeric segment, and token casing are removed bare; short runs, names, and uppercase codes stay",
  );
  assert.equal(
    redactSecrets("failed for /api/v1/users/aB3xZ9qL2mN8pR4tV7wY1/factors from /tmp/run-9b6rz9m4l55zg7/config.toml and https://hooks.example.com/services/T0/aB3xZ9qL2mN8pR4tV7wY1"),
    "failed for /api/v1/users/aB3xZ9qL2mN8pR4tV7wY1/factors from /tmp/run-9b6rz9m4l55zg7/config.toml and https://hooks.example.com/services/T0/[REDACTED]",
    "a token-shaped segment of a bare request target or file path is an identifier the run named; inside a URL it is a webhook token",
  );
  assert.equal(
    redactSecrets("casing sessionIdleTimeoutMins minsToBypassMfa lastSuccessLogin QaZwSxEdCrFvTgByHn aBcDeFgHiJkLmNoPqRs ABcdEFghIJklMNopQR"),
    "casing sessionIdleTimeoutMins minsToBypassMfa lastSuccessLogin [REDACTED] [REDACTED] [REDACTED]",
    "camelCase identifiers whose words average three or more letters stay; alternating capitalized fragments and doubled-case runs are tokens",
  );
  assert.equal(
    redactSecrets("private_key_passphrase=4f9c2b7e1d3a4c5b8e6f7a9b0c1d2e3f and oauth_token=hunter2x9 rejected"),
    "private_key_passphrase=[REDACTED] and oauth_token=[REDACTED] rejected",
    "a credential-named key keeps its name once its value is replaced; the trailing = is not read as base64 padding",
  );
  assert.equal(
    redactSecrets("Snowflake OAuth token request failed for /oauth/token-request: invalid_client"),
    "Snowflake OAuth token request failed for /oauth/token-request: invalid_client",
    "the last segment of a bare request path used as a label is not a pair key, so the vendor detail after it stays",
  );

  // Must-keep table (addendum 7): every identifying string a summary may carry survives alone and inside a realistic sentence.
  for (const [kind, values] of Object.entries(SNOWFLAKE_MUST_KEEP)) {
    for (const value of values) {
      assert.equal(redactSecrets(value), value, `must keep bare: ${value}`);
      assert.equal(redactSecrets(value, [SAMPLE_CONFIGURED_TOKEN, TEST_PRIVATE_KEY_PEM]), value, `must keep bare with the configured credentials registered: ${value}`);
      for (const sentence of snowflakeSummarySentences(kind, value)) assert.equal(redactSecrets(sentence), sentence, `must keep in a sentence: ${sentence}`);
    }
  }
});

/** A configured bearer token registered with the scrubber in the must-keep and fixed-text checks: random alphanumerics that occur in no fixed text. */
const SAMPLE_CONFIGURED_TOKEN = "AJ64FNHxZz2NkPrJmyLz";
/** Passphrases for the encrypted-key failure cases: planted credentials, so random alphanumerics with no 6-character window in the remediation text ("its passphrase") or another fixture value. */
const LIVE_RESOLVER_PASSPHRASES = { right: "U5CqFH4YNnkzDWu7frMR", wrong: "aqqMKuvZ2ny3fJuXLhbJ" };

/** Every statement key the Snowflake collectors record: core_data file names, statement outcomes, access check surfaces, and _errors.log line labels. */
const SNOWFLAKE_STATEMENT_KEYS = [
  "session_context", "show_network_policies", "account_network_policy_parameter", "network_policies", "network_policy_references", "users", "password_policies",
  "session_policies", "show_integrations", "role_hierarchy_grants", "global_privilege_grants", "admin_role_grants_to_users", "role_usage_by_queries",
  "direct_user_grants", "public_grants", "login_outcomes", "failed_logins", "access_history_probe", "data_retention_parameter", "show_warehouses",
  "masking_policy_count", "masking_policy_references", "row_access_policy_count", "row_access_policy_references", "tag_references", "stage_parameters",
  "unload_parameters", "show_databases", "show_shares", "show_replication_groups",
];

/** Every statement text the Snowflake client sends, with the limits and lookbacks the collectors use. */
const SNOWFLAKE_REQUESTED_STATEMENTS = [
  ...Object.values(SNOWFLAKE_STATEMENTS).filter((value) => typeof value === "string"),
  SNOWFLAKE_STATEMENTS.networkPolicies(1000),
  SNOWFLAKE_STATEMENTS.policyReferences("MASKING_POLICY", 1000),
  SNOWFLAKE_STATEMENTS.policyReferencesByName({ database: "GOV", schema: "POLICIES", name: "STRONG_PW" }),
  SNOWFLAKE_STATEMENTS.users(1000),
  SNOWFLAKE_STATEMENTS.passwordPolicies(1000),
  SNOWFLAKE_STATEMENTS.sessionPolicies(1000),
  SNOWFLAKE_STATEMENTS.roleGrants(1000),
  SNOWFLAKE_STATEMENTS.globalPrivilegeGrants(1000),
  SNOWFLAKE_STATEMENTS.adminRoleGrantsToUsers(1000),
  SNOWFLAKE_STATEMENTS.roleUsageByQueries(90),
  SNOWFLAKE_STATEMENTS.directUserGrants(1000),
  SNOWFLAKE_STATEMENTS.publicGrants(1000),
  SNOWFLAKE_STATEMENTS.loginOutcomes(30),
  SNOWFLAKE_STATEMENTS.failedLogins(30),
];

/** Quoted non-credential headers (the Codex P1 must-keep rows): a quote alone never makes a header value a credential. */
const SNOWFLAKE_QUOTED_HEADERS_KEPT = [
  'Content-Type: "application/json"',
  'Content-Type:"application/json; charset=utf-8"',
  "Accept: 'application/json'",
  'Content-Length: "42"',
  'X-Request-Id: "3f2b6a1e-9c4d-4e8f-b1a2-6d7c8e9f0a1b"',
  'X-Rate-Limit-Remaining: "599"',
  'User-Agent: "grclanker-cli/0.4.1"',
  'Cache-Control: "no-store"',
  'Location: "/api/v2/statements"',
  '{"Content-Type": "application/json", "Accept": "application/json"}',
  '{\\"Content-Type\\": \\"application/json\\", \\"Accept\\": \\"application/json\\"}',
];

const SNOWFLAKE_MUST_KEEP = {
  statement: SNOWFLAKE_REQUESTED_STATEMENTS,
  key: SNOWFLAKE_STATEMENT_KEYS,
  path: ["POST /api/v2/statements?async=true&requestId=6f1c2b3a-4d5e-4f60-8a9b-0c1d2e3f4a5b", "GET /api/v2/statements/01bd8f2e-0000-1234-0000-000000000001", "/api/v2/statements"],
  host: [
    "https://myorg-myaccount.snowflakecomputing.com", "https://myorg-myaccount.privatelink.snowflakecomputing.com", "https://env-acct.us-east-1.snowflakecomputing.com",
    "myorg-myaccount.snowflakecomputing.com",
  ],
  name: [
    "myorg-myaccount", "MYORG-MYACCOUNT", "xy12345.us-east-1", "env_acct.us-east-1", "auditor", "svc_etl", "SVC_ETL", "ALICE", "NO_MFA_USER", "ACCOUNTADMIN", "SECURITYADMIN", "AUDIT_ROLE",
    "DATA_ENGINEER", "AUDIT_WH", "ALWAYS_ON_WH", "X-Small", "CORP_POLICY", "STRONG_PW", "SESSION_STRICT", "MASK_SSN", "REGION_RAP", "OKTA_SAML", "S3_INT", "PROVIDER_SHARE",
    "PROVIDER.ACCT", "SNOWFLAKE.ACCOUNT_USAGE", "GOV.POLICIES.STRONG_PW", "NETWORK_POLICY", "DATA_RETENTION_TIME_IN_DAYS", "REQUIRE_STORAGE_INTEGRATION_FOR_STAGE_CREATION",
    "PREVENT_UNLOAD_TO_INLINE_URL", "INCORRECT_USERNAME_PASSWORD", "LEGACY_SERVICE", "SERVICE_AGENT", "SNOWFLAKE_UI", "JDBC_DRIVER", "KEYPAIR_JWT", "PROGRAMMATIC_ACCESS_TOKEN", "OAUTH",
    "IMPORTED PRIVILEGES", "MANAGE GRANTS", "ACCOUNT_USAGE", "INFORMATION_SCHEMA.POLICY_REFERENCES",
  ],
  status: ["200 OK", "202 Accepted", "401 Unauthorized", "403 Forbidden", "404 Not Found", "422 Unprocessable Entity", "429 Too Many Requests", "500 Internal Server Error", "502 Bad Gateway", "503 Service Unavailable"],
  id: ALL_CONTROL_IDS,
  source: [
    "arguments-account", "arguments-private-key", "arguments-private-key-path", "arguments-token", "environment-account", "environment-user", "environment-token", "environment-private-key-path",
    "environment-private-key-passphrase", "environment-role", "config-file-account", "config-file-private-key-path", "config-file-warehouse", "config-file:/home/auditor/.snowflake/connections.toml#audit",
    "config-file:/home/auditor/.snowflake/config.toml#default",
  ],
  code: ["INVALID_TOML", "EACCES", "ENOTDIR", "EISDIR", "ENOENT", "UNREADABLE", "ERR_OSSL_UNSUPPORTED", "ERR_OSSL_BAD_DECRYPT", "INVALID_PRIVATE_KEY", "MISSING_PRIVATE_KEY", "003001", "42501", "390144", "08004", "333334", "090001"],
  text: [
    "/home/auditor/.snowflake/connections.toml", "/home/auditor/.snowflake/config.toml", "/home/auditor/.snowflake/rsa_key.p8", "PKCS#8 PEM key", "10000-row limit",
    "total unknown", "SNOWFLAKE_ACCOUNT", "SNOWFLAKE_PRIVATE_KEY_PATH", "SNOWFLAKE_TOKEN", "snowflake_check_access", "snowflake_export_audit_bundle",
  ],
};

/** Realistic Snowflake summary and error sentences with an identifying value in the slot such a value occupies. */
function snowflakeSummarySentences(kind, value) {
  switch (kind) {
    case "statement":
      return [`Refusing to execute a non read-only Snowflake statement: ${value.slice(0, 80)}`, `[denied] show_shares: Snowflake SQL API request failed (422 Unprocessable Entity): SQL access control error\n  ${value}`];
    case "key":
      return [
        `Unknown: ${value} was denied (insufficient privileges): Snowflake SQL API request failed (422 Unprocessable Entity): SQL access control error: Insufficient privileges to operate on account 'MYORG' [code 003001, sqlState 42501]. Collect manually: SHOW SHARES output`,
        `Unreadable inventory: ${value} timed out: Snowflake statement did not complete before the 30s statement timeout., so per-user policy assignments were not checked. The verdict cannot be pass while an inventory it reads is unreadable; collect manually: SHOW PARAMETERS output`,
        `Partial inventory: ${value} hit the 10000-row limit (10000 rows seen); the verdict cannot be pass on a partial result.`,
        `Partial inventory: ${value} returned 1/3 partitions (1000/2600 rows seen).`,
        `[not_requested] ${value}: Not requested: the Snowflake private key could not be loaded (ERR_OSSL_UNSUPPORTED); no statement was sent.`,
      ];
    case "path":
      return [`Snowflake SQL API request timed out after 5000ms (${value})`, `Snowflake SQL API request failed (${value}): fetch failed`];
    case "host":
      return [`Using Snowflake account myorg-myaccount via ${value} (KEYPAIR_JWT).`, `Snowflake SQL API request failed (POST /api/v2/statements?async=true&requestId=6f1c2b3a-4d5e-4f60-8a9b-0c1d2e3f4a5b): getaddrinfo ENOTFOUND ${value}`];
    case "name":
      return [
        `Authenticated as ${value} with role ${value} and warehouse ${value}.`,
        `Authentication not confirmed: the session context statement was denied, so the configured user ${value} and role ${value} are reported as configured, not as observed.`,
        `The active role ${value} lacks MANAGE GRANTS, so SHOW commands may list only objects granted to that role.`,
        `Using Snowflake account ${value} via https://myorg-myaccount.snowflakecomputing.com (${value}).`,
        `Snowflake SQL API request failed (422 Unprocessable Entity): SQL access control error: Insufficient privileges to operate on account '${value}' [code 003001, sqlState 42501]`,
        `3 of 4 users lack MFA: ${value}, ${value}. Unreadable inventory: ${value} (denied).`,
      ];
    case "status":
      return [`Snowflake SQL API request failed (${value}): non-JSON body (text/html, 5120 bytes)`, `Snowflake SQL API request returned an unreadable response (${value}): non-JSON body (text/html, 5120 bytes)`];
    case "id":
      return [`${value} is manual because the users statement was denied.`, `| ${value} | HIGH | MANUAL | Network policy | Unknown: users was denied (insufficient privileges). |`];
    case "source":
      return [`Credential sources: ${value}, environment-role.`, `- Credential source: ${value}`];
    case "code":
      return [
        `Unable to read Snowflake config file /home/auditor/.snowflake/connections.toml (${value})`,
        `Unable to load the Snowflake private key (${value}). Provide a PKCS#8 PEM key and, for an encrypted key, its passphrase.`,
        `Snowflake SQL API request failed (422 Unprocessable Entity): SQL compilation error [code ${value}, sqlState ${value}]`,
      ];
    default:
      return [`${value} was reported by snowflake_check_access.`];
  }
}

/** Every fixed text the Snowflake integration emits, with sample paths and names, passes its scrubber unchanged (GWS note 1). */
const SNOWFLAKE_FIXED_TEXTS = [
  "SNOWFLAKE_ACCOUNT, an account argument, or a connections.toml account entry is required.",
  "SNOWFLAKE_USER, a user argument, or a connections.toml user entry is required.",
  "Provide key-pair credentials (SNOWFLAKE_PRIVATE_KEY_PATH or SNOWFLAKE_PRIVATE_KEY) or a bearer token (SNOWFLAKE_TOKEN). Username/password authentication is not supported by the Snowflake SQL REST API.",
  "Unable to read Snowflake config file /home/auditor/.snowflake/connections.toml (EACCES)",
  "Unable to read Snowflake config file /home/auditor/.snowflake/config.toml (ENOTDIR)",
  "Unable to parse Snowflake config file: invalid TOML in /home/auditor/.snowflake/connections.toml at line 4 (INVALID_TOML)",
  "Snowflake private key file was not found: /home/auditor/.snowflake/rsa_key.p8 (ENOENT)",
  "Unable to read Snowflake private key file /home/auditor/.snowflake/rsa_key.p8 (EISDIR)",
  "Unable to load the Snowflake private key (ERR_OSSL_UNSUPPORTED). Provide a PKCS#8 PEM key and, for an encrypted key, its passphrase.",
  "Unable to load the Snowflake private key (INVALID_PRIVATE_KEY). Provide a PKCS#8 PEM key and, for an encrypted key, its passphrase.",
  "Unable to load the Snowflake private key (MISSING_PRIVATE_KEY). Snowflake key-pair authentication requires a private key.",
  "Not requested: the Snowflake private key could not be loaded (ERR_OSSL_UNSUPPORTED); no statement was sent. Provide a PKCS#8 PEM key and, for an encrypted key, its passphrase.",
  "Not authenticated: the Snowflake private key could not be loaded (ERR_OSSL_UNSUPPORTED); no request was sent.",
  "Snowflake SQL API request timed out after 5000ms (POST /api/v2/statements?async=true&requestId=6f1c2b3a-4d5e-4f60-8a9b-0c1d2e3f4a5b)",
  "Snowflake SQL API request failed (POST /api/v2/statements?async=true&requestId=6f1c2b3a-4d5e-4f60-8a9b-0c1d2e3f4a5b): fetch failed",
  "Snowflake SQL API request failed (GET /api/v2/statements/01bd8f2e-0000-1234-0000-000000000001): The operation was aborted due to timeout",
  "Snowflake statement 01bd8f2e-0000-1234-0000-000000000001 did not complete before the 30s statement timeout.",
  "Snowflake SQL API request failed (422 Unprocessable Entity): SQL access control error:\nInsufficient privileges to operate on account 'MYORG' [code 003001, sqlState 42501]",
  "Snowflake SQL API request failed (403 Forbidden): Denied while fetching https://api.example.com/v1/x?[REDACTED] for this key; Authorization: Bearer [REDACTED]; api_key=[REDACTED]; session_id=[REDACTED] [code 390144, sqlState 08004]",
  "Snowflake SQL API request failed (502 Bad Gateway): non-JSON body (text/html, 5120 bytes)",
  "Snowflake SQL API request returned an unreadable response (200 OK): non-JSON body (text/html, 5120 bytes)",
  "Snowflake SQL API request failed (429 Too Many Requests): Rate limit exceeded [code 000630]",
  "Refusing to execute a non read-only Snowflake statement: DROP TABLE SALES.PUBLIC.CUSTOMERS",
  "Using Snowflake account myorg-myaccount via https://myorg-myaccount.snowflakecomputing.com (KEYPAIR_JWT).",
  "Authenticated as auditor with role ACCOUNTADMIN and warehouse AUDIT_WH.",
  "Authenticated as auditor with role (default role).",
  "Authentication not confirmed: the session context statement was denied, so the configured user auditor and role AUDIT_ROLE are reported as configured, not as observed.",
  "27/31 Snowflake audit surfaces are readable; 15 ACCOUNT_USAGE views responded.",
  "The active role AUDIT_ROLE lacks MANAGE GRANTS, so SHOW commands may list only objects granted to that role.",
  "The active role (unknown) lacks MANAGE GRANTS, so the share inventory may list only objects granted to that role.",
  "Credential sources: arguments-account, arguments-user, arguments-private-key, environment-role, config-file:/home/auditor/.snowflake/connections.toml#default, config-file-warehouse.",
  "Run snowflake_assess_network_and_authentication, snowflake_assess_access_control, snowflake_assess_monitoring_and_lifecycle, snowflake_assess_data_protection, or snowflake_export_audit_bundle.",
  "Grant the audit role IMPORTED PRIVILEGES on the SNOWFLAKE database plus MANAGE GRANTS (or use SECURITYADMIN/ACCOUNTADMIN) and a small warehouse, then re-run snowflake_check_access.",
  "Unknown: show_shares was denied (insufficient privileges): Snowflake SQL API request failed (422 Unprocessable Entity): SQL access control error: Insufficient privileges to operate on account 'MYORG' [code 003001, sqlState 42501]. Collect manually: SHOW SHARES output from ACCOUNTADMIN",
  "Unknown: users timed out: Snowflake statement did not complete before the 30s statement timeout. Collect manually: SNOWFLAKE.ACCOUNT_USAGE.USERS export",
  "Unknown: session_context: Not requested: the Snowflake private key could not be loaded (INVALID_PRIVATE_KEY); no statement was sent. Collect manually: SHOW NETWORK POLICIES output",
  "Unreadable inventory: network_policy_references was denied (insufficient privileges): Snowflake SQL API request failed (403 Forbidden), so per-user network policy assignments were not checked. The verdict cannot be pass while an inventory it reads is unreadable; collect manually: POLICY_REFERENCES output",
  "Unreadable inventory: password_policies (denied), session_policies (timeout).",
  "Partial inventory: show_network_policies hit the 10000-row limit (10000 rows seen); the verdict cannot be pass on a partial result.",
  "Partial inventory: users returned 1/3 partitions (1000/2600 rows seen).",
  "the active role could not be verified and the share inventory may be scoped to a role with narrower visibility",
  "[denied] show_shares: Snowflake SQL API request failed (422 Unprocessable Entity): SQL access control error: Insufficient privileges to operate on account 'MYORG' [code 003001, sqlState 42501]\n  SHOW SHARES",
  "[not_requested] session_context: Not requested: the Snowflake private key could not be loaded (ERR_OSSL_UNSUPPORTED); no statement was sent. Provide a PKCS#8 PEM key and, for an encrypted key, its passphrase.",
  "Authenticated as: auditor (role ACCOUNTADMIN, KEYPAIR_JWT)",
  "Access check: limited (partial visibility: role lacks MANAGE GRANTS)",
  "- `_errors.log`: statements that were denied, failed, timed out, or were never sent during collection",
  "- `_errors.log`: not written because every statement completed",
  "Snowflake access check failed: SNOWFLAKE_ACCOUNT, an account argument, or a connections.toml account entry is required.",
  "Snowflake audit bundle export failed: Unable to parse Snowflake config file: invalid TOML in /home/auditor/.snowflake/config.toml at line 2 (INVALID_TOML)",
  "Refusing to write outside /home/auditor/export: /home/auditor/export/../etc",
  "Refusing to use symlinked parent directory: /home/auditor/export/link",
];

/**
 * The resolver messages as rendered live for the no credentials, partial credentials, bad auth mode,
 * and key or config file failure cases, each against a real temp path and the code the run observed;
 * credential-bearing files carry a config canary so the messages prove they hold path and code only.
 */
function liveResolverMessages() {
  const base = createTempBase("grclanker-snowflake-live-resolver-");
  const emptyHome = join(base, "home");
  mkdirSync(emptyHome);
  const keyDirectory = join(base, "key-directory.p8");
  mkdirSync(keyDirectory);
  const malformedHome = join(base, "malformed");
  mkdirSync(malformedHome);
  writeFileSync(join(malformedHome, "connections.toml"), `[default]\naccount = "myorg-myaccount"\ntoken = "${CONFIG_CANARIES.unterminated}\n`);
  const directoryHome = join(base, "directory");
  mkdirSync(join(directoryHome, "connections.toml"), { recursive: true });
  const garbageKey = `-----BEGIN PRIVATE KEY-----\n${CONFIG_CANARIES.privateKey}\n-----END PRIVATE KEY-----\n`;
  const encryptedPem = testPrivateKey.export({ type: "pkcs8", format: "pem", cipher: "aes-256-cbc", passphrase: LIVE_RESOLVER_PASSPHRASES.right });
  const account = { SNOWFLAKE_ACCOUNT: "myorg-myaccount" };
  const identity = { ...account, SNOWFLAKE_USER: "svc" };
  const resolve = (input, env, home = emptyHome) => thrownBy(() => resolveSnowflakeConfiguration(input, { ...env, SNOWFLAKE_HOME: home }, { homeDirectory: base })).message;
  const build = (config) => thrownBy(() => buildSnowflakeKeyPairJwt({ account: "myorg-myaccount", user: "svc", ...config })).message;
  return {
    paths: { keyDirectory, missingKey: join(base, "missing.p8"), malformedToml: join(malformedHome, "connections.toml"), directoryToml: join(directoryHome, "connections.toml") },
    messages: {
      "no credentials": resolve({}, {}),
      "partial credentials: account without user": resolve({}, account),
      "partial credentials: identity without a key or token": resolve({}, identity),
      "bad auth mode: username and password": resolve({}, { ...identity, SNOWFLAKE_PASSWORD: "hunter2" }),
      "bad auth mode: an unsupported authenticator without a credential": resolve({ token_type: "externalbrowser" }, identity),
      "key file failure: missing file": resolve({ private_key_path: join(base, "missing.p8") }, identity),
      "key file failure: directory at the path": resolve({ private_key_path: keyDirectory }, identity),
      "key file failure: unloadable key material": build({ privateKeyPem: garbageKey }),
      "key file failure: encrypted key with the wrong passphrase": build({ privateKeyPem: encryptedPem, privateKeyPassphrase: LIVE_RESOLVER_PASSPHRASES.wrong }),
      "key file failure: no key": build({}),
      "config file failure: malformed TOML": resolve({}, identity, malformedHome),
      "config file failure: directory at the TOML path": resolve({}, identity, directoryHome),
    },
  };
}

test("rule 9: every fixed text the Snowflake integration emits, including the live resolver messages, passes its scrubber unchanged", () => {
  const live = liveResolverMessages();
  const unsupportedAuth = "Provide key-pair credentials (SNOWFLAKE_PRIVATE_KEY_PATH or SNOWFLAKE_PRIVATE_KEY) or a bearer token (SNOWFLAKE_TOKEN). Username/password authentication is not supported by the Snowflake SQL REST API.";
  const keyLoad = /^Unable to load the Snowflake private key \((ERR_[A-Z0-9_]+|INVALID_PRIVATE_KEY)\)\. Provide a PKCS#8 PEM key and, for an encrypted key, its passphrase\.$/;
  const expected = {
    "no credentials": "SNOWFLAKE_ACCOUNT, an account argument, or a connections.toml account entry is required.",
    "partial credentials: account without user": "SNOWFLAKE_USER, a user argument, or a connections.toml user entry is required.",
    "partial credentials: identity without a key or token": unsupportedAuth,
    "bad auth mode: username and password": unsupportedAuth,
    "bad auth mode: an unsupported authenticator without a credential": unsupportedAuth,
    "key file failure: missing file": `Snowflake private key file was not found: ${live.paths.missingKey} (ENOENT)`,
    "key file failure: directory at the path": `Unable to read Snowflake private key file ${live.paths.keyDirectory} (EISDIR)`,
    "key file failure: unloadable key material": keyLoad,
    "key file failure: encrypted key with the wrong passphrase": keyLoad,
    "key file failure: no key": "Unable to load the Snowflake private key (MISSING_PRIVATE_KEY). Snowflake key-pair authentication requires a private key.",
    "config file failure: malformed TOML": `Unable to parse Snowflake config file: invalid TOML in ${live.paths.malformedToml} at line 3 (INVALID_TOML)`,
    "config file failure: directory at the TOML path": `Unable to read Snowflake config file ${live.paths.directoryToml} (EISDIR)`,
  };
  assert.deepEqual(Object.keys(live.messages), Object.keys(expected));
  for (const [label, message] of Object.entries(live.messages)) {
    if (expected[label] instanceof RegExp) assert.match(message, expected[label], label);
    else assert.equal(message, expected[label], label);
    for (const canary of Object.values(CONFIG_CANARIES)) assertNoWindowOf(message, canary, `live resolver message (${label})`);
    for (const wording of LIBRARY_ERROR_WORDING) assert.ok(!message.includes(wording), `${label} repeats library wording "${wording}": ${message}`);
    assert.equal(redactSecrets(message), message, `live resolver message survives the scrubber (${label})`);
    assert.equal(redactSecrets(message, [SAMPLE_CONFIGURED_TOKEN, TEST_PRIVATE_KEY_PEM, LIVE_RESOLVER_PASSPHRASES.wrong]), message, `live resolver message survives with the configured credentials registered (${label})`);
    for (const passphrase of Object.values(LIVE_RESOLVER_PASSPHRASES)) assertNoWindowOf(message, passphrase, `live resolver message (${label})`);
  }

  for (const text of SNOWFLAKE_FIXED_TEXTS) assert.equal(redactSecrets(text), text, text);
  for (const text of SNOWFLAKE_FIXED_TEXTS) assert.equal(redactSecrets(text, [SAMPLE_CONFIGURED_TOKEN, TEST_PRIVATE_KEY_PEM]), text, `${text} (with the configured credentials registered)`);
});

/** An environment bearer token: random alphanumerics that occur in no fixture value. */
const ENVIRONMENT_TOKEN = "wpcrJHTaWGpcmWkZjzVV";

test("resolveSnowflakeConfiguration keeps environment credentials when an unrelated argument is passed (GWS note 2)", () => {
  const home = createTempBase("grclanker-snowflake-env-args-");
  const env = { SNOWFLAKE_ACCOUNT: "myorg-myaccount", SNOWFLAKE_USER: "svc", SNOWFLAKE_TOKEN: ENVIRONMENT_TOKEN, SNOWFLAKE_ROLE: "AUDIT_ROLE", SNOWFLAKE_HOME: home };

  const resolved = resolveSnowflakeConfiguration({ timeout_seconds: 9 }, env, { homeDirectory: home });
  assert.equal(resolved.token, ENVIRONMENT_TOKEN, "the environment token survives an argument overlay that names no credential");
  assert.equal(resolved.tokenType, "OAUTH");
  assert.equal(resolved.account, "myorg-myaccount");
  assert.equal(resolved.user, "svc");
  assert.equal(resolved.role, "AUDIT_ROLE");
  assert.equal(resolved.timeoutMs, 9000);
  assert.equal(resolved.connectionName, undefined, "no connections.toml is read from an empty SNOWFLAKE_HOME");
  assert.deepEqual(resolved.sourceChain, ["environment-account", "environment-user", "environment-token", "environment-role"]);

  const withUndefinedArguments = resolveSnowflakeConfiguration({ account: undefined, user: undefined, token: undefined, private_key: undefined, token_type: undefined }, env, { homeDirectory: home });
  assert.equal(withUndefinedArguments.token, ENVIRONMENT_TOKEN, "an argument overlay whose credential keys are undefined does not shadow the environment");
  assert.equal(withUndefinedArguments.tokenType, "OAUTH");
  assert.deepEqual(withUndefinedArguments.sourceChain, ["environment-account", "environment-user", "environment-token", "environment-role"]);

  const keyFile = join(home, "rsa_key.p8");
  writeFileSync(keyFile, TEST_PRIVATE_KEY_PEM);
  const keyPair = resolveSnowflakeConfiguration({ row_limit: 500 }, { SNOWFLAKE_ACCOUNT: "myorg-myaccount", SNOWFLAKE_USER: "svc", SNOWFLAKE_PRIVATE_KEY_PATH: keyFile, SNOWFLAKE_HOME: home }, { homeDirectory: home });
  assert.equal(keyPair.tokenType, "KEYPAIR_JWT", "the key file named through the environment still supplies the credential");
  assert.equal(keyPair.privateKeyPem, TEST_PRIVATE_KEY_PEM);
  assert.equal(keyPair.token, undefined);
  assert.equal(keyPair.rowLimit, 500);
  assert.deepEqual(keyPair.sourceChain, ["environment-account", "environment-user", "environment-private-key-path"]);
});

test("SnowflakeSqlClient submits async statements, polls, and fetches every partition", async () => {
  const calls = [];
  const fetchImpl = async (url, init) => {
    calls.push({ url: String(url), init });
    const pathname = new URL(String(url)).pathname + new URL(String(url)).search;
    if (init.method === "POST") {
      return jsonResponse({ code: "333334", message: "Asynchronous execution in progress.", statementHandle: "handle-1", statementStatusUrl: "/api/v2/statements/handle-1" }, { status: 202 });
    }
    if (pathname === "/api/v2/statements/handle-1" && calls.length === 2) {
      return jsonResponse({ code: "333334", message: "Asynchronous execution in progress.", statementHandle: "handle-1" }, { status: 202 });
    }
    if (pathname === "/api/v2/statements/handle-1") {
      return jsonResponse({
        code: "090001",
        statementHandle: "handle-1",
        resultSetMetaData: {
          numRows: 3,
          format: "jsonv2",
          rowType: [{ name: "NAME", type: "text" }, { name: "VALUE", type: "fixed" }],
          partitionInfo: [{ rowCount: 2, uncompressedSize: 10 }, { rowCount: 1, uncompressedSize: 5 }],
        },
        data: [["a", "1"], ["b", null]],
      });
    }
    if (pathname === "/api/v2/statements/handle-1?partition=1") {
      return jsonResponse({ data: [["c", 3]] });
    }
    throw new Error(`unexpected request ${pathname}`);
  };

  const client = new SnowflakeSqlClient(sampleConfig(), { fetchImpl });
  const result = await client.execute("SELECT NAME, VALUE FROM T");

  assert.equal(result.rows.length, 3);
  assert.deepEqual(result.rows[1], { NAME: "b", VALUE: null });
  assert.deepEqual(result.rows[2], { NAME: "c", VALUE: "3" });
  assert.equal(result.numRows, 3);
  assert.equal(result.partitionCount, 2);
  assert.equal(result.fetchedPartitions, 2);
  assert.equal(result.truncated, false);
  assert.equal(result.statementHandle, "handle-1");

  const submit = calls[0];
  assert.match(submit.url, /^https:\/\/myorg-myaccount\.snowflakecomputing\.com\/api\/v2\/statements\?async=true&requestId=[0-9a-f-]{36}$/);
  assert.equal(headerValue(submit.init.headers, "x-snowflake-authorization-token-type"), "KEYPAIR_JWT");
  assert.match(headerValue(submit.init.headers, "authorization"), /^Bearer eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
  assert.equal(headerValue(submit.init.headers, "content-type"), "application/json");
  const body = JSON.parse(submit.init.body);
  assert.equal(body.statement, "SELECT NAME, VALUE FROM T");
  assert.equal(body.timeout, 30);
  assert.equal(body.role, "AUDIT_ROLE");
  assert.equal(body.warehouse, "AUDIT_WH");
  assert.equal("resultSetMetaData" in body, false, "resultSetMetaData is a response object and must not be sent in the request");
  const documentedRequestFields = new Set(["statement", "timeout", "database", "schema", "warehouse", "role", "bindings", "parameters"]);
  for (const field of Object.keys(body)) {
    assert.ok(documentedRequestFields.has(field), `request body field ${field} is not in the documented SQL API request schema`);
  }
  assert.equal(calls.length, 4);
  assert.equal(calls[1].init.method, "GET");
  assert.equal(calls[3].url, "https://myorg-myaccount.snowflakecomputing.com/api/v2/statements/handle-1?partition=1");
});

test("foreign-origin next link: a statementStatusUrl that leaves the configured account origin is never polled, the outcome records the fixed reason, and no part of the URL reaches any text", async () => {
  const foreignParts = { host: "collector.evil-example.net", path: "/harvest/snowflake-jwt", query: "sink=bearer&handle=handle-9" };
  const foreignTarget = `${foreignParts.host}${foreignParts.path}?${foreignParts.query}`;
  const statusText = "Snowflake SQL API returned a statement status URL that is not on the configured account origin; the statement was not polled and its result was not read.";
  const refusedText = "Snowflake SQL API request refused: the request URL is not on the configured account origin, so no request was sent.";

  for (const statusUrl of [`@${foreignTarget}`, `:443@${foreignTarget}`, `https://${foreignTarget}`]) {
    const calls = [];
    const fetchImpl = async (url, init) => {
      calls.push({ url: new URL(String(url)), authorization: headerValue(init.headers, "authorization") });
      if (init.method === "POST") {
        return jsonResponse({ code: "333334", message: "Asynchronous execution in progress.", statementHandle: "handle-9", statementStatusUrl: statusUrl }, { status: 202 });
      }
      throw new Error(`a poll left for ${String(url)}`);
    };
    const client = new SnowflakeSqlClient(sampleConfig(), { fetchImpl });
    await assert.rejects(() => client.execute("SHOW USERS"), (error) => {
      assert.equal(error.name, "SnowflakeStatementError");
      assert.equal(error.message, statusText, `status URL ${statusUrl}`);
      assert.equal(error.kind, "error");
      return true;
    });
    assert.equal(calls.length, 1, `status URL ${statusUrl}: only the submit left`);
    assert.equal(calls[0].url.origin, "https://myorg-myaccount.snowflakecomputing.com");

    const outcome = await collectStatement(client, "users", "SHOW USERS");
    assert.equal(outcome.status, "error");
    assert.equal(outcome.error, statusText);
    assert.equal(outcome.numRows, null);
    assert.equal(outcome.partitionCount, null);
    assert.equal(outcome.truncated, null);
    assert.equal(calls.length, 2, "the collector's submit is the only further request");
    assert.ok(calls.every((call) => call.url.origin === "https://myorg-myaccount.snowflakecomputing.com"), "no request left the configured origin");
    for (const part of Object.values(foreignParts)) assert.ok(!JSON.stringify(outcome).includes(part), `the outcome carries no ${part}`);
  }

  const sameOriginCalls = [];
  const sameOrigin = new SnowflakeSqlClient(sampleConfig(), {
    fetchImpl: async (url, init) => {
      sameOriginCalls.push(new URL(String(url)));
      if (init.method === "POST") {
        return jsonResponse({ code: "333334", message: "Asynchronous execution in progress.", statementHandle: "handle-9", statementStatusUrl: "/api/v2/statements/handle-9" }, { status: 202 });
      }
      return jsonResponse({ code: "090001", statementHandle: "handle-9", resultSetMetaData: { numRows: 1, format: "jsonv2", rowType: [{ name: "NAME", type: "text" }], partitionInfo: [{ rowCount: 1 }] }, data: [["a"]] });
    },
  });
  const followed = await sameOrigin.execute("SHOW USERS");
  assert.equal(followed.rows.length, 1, "a status URL on the configured origin is still polled");
  assert.equal(sameOriginCalls.length, 2);

  // Defense in depth on the request layer itself (a private method, reached here as plain JavaScript): any path that would move the host is refused before a credential is built, with fixed text.
  const guarded = new SnowflakeSqlClient(sampleConfig(), { fetchImpl: async (url) => { throw new Error(`a request left for ${String(url)}`); } });
  for (const pathname of [`@${foreignTarget}`, `:8443@${foreignTarget}`, `https://${foreignTarget}`]) {
    await assert.rejects(() => guarded.request("GET", pathname), (error) => {
      assert.equal(error.name, "SnowflakeStatementError");
      assert.equal(error.message, refusedText, `pathname ${pathname}`);
      assert.equal(error.kind, "error");
      for (const part of Object.values(foreignParts)) assert.ok(!error.message.includes(part), `the refusal carries no ${part}`);
      return true;
    });
  }
});

test("SnowflakeSqlClient records truncation instead of treating the first partition as the whole result", async () => {
  const fetchImpl = async () => jsonResponse({
    statementHandle: "handle-2",
    resultSetMetaData: {
      numRows: 30,
      rowType: [{ name: "NAME" }],
      partitionInfo: [{ rowCount: 10 }, { rowCount: 10 }, { rowCount: 10 }],
    },
    data: Array.from({ length: 10 }, (_, index) => [`row-${index}`]),
  });

  const client = new SnowflakeSqlClient(sampleConfig({ maxPartitions: 1 }), { fetchImpl });
  const result = await client.execute("SELECT NAME FROM T");
  assert.equal(result.partitionCount, 3);
  assert.equal(result.fetchedPartitions, 1);
  assert.equal(result.rows.length, 10);
  assert.equal(result.truncated, true);

  const outcome = await collectStatement(client, "probe", "SELECT NAME FROM T");
  assert.equal(outcome.status, "ok");
  assert.equal(outcome.truncated, true);
});

test("SnowflakeSqlClient retries 429 and 5xx responses with backoff and surfaces exhausted retries", async () => {
  let attempts = 0;
  const fetchImpl = async () => {
    attempts += 1;
    if (attempts === 1) return jsonResponse({ message: "upstream unavailable" }, { status: 503, statusText: "Service Unavailable" });
    if (attempts === 2) return jsonResponse({ message: "slow down" }, { status: 429, statusText: "Too Many Requests", headers: { "retry-after": "0" } });
    return jsonResponse({ statementHandle: "handle-3", resultSetMetaData: { numRows: 1, rowType: [{ name: "ONE" }], partitionInfo: [{ rowCount: 1 }] }, data: [["1"]] });
  };
  const client = new SnowflakeSqlClient(sampleConfig(), { fetchImpl });
  const result = await client.execute("SELECT 1 AS ONE");
  assert.equal(attempts, 3);
  assert.deepEqual(result.rows, [{ ONE: "1" }]);

  const exhausted = new SnowflakeSqlClient(sampleConfig({ maxRetries: 1 }), {
    fetchImpl: async () => jsonResponse({ message: "still down" }, { status: 502, statusText: "Bad Gateway" }),
  });
  await assert.rejects(exhausted.execute("SELECT 1"), (error) => {
    assert.ok(error instanceof SnowflakeStatementError);
    assert.equal(error.statusCode, 502);
    assert.equal(error.kind, "error");
    return true;
  });
});

test("SnowflakeSqlClient classifies insufficient privileges, timeouts, and redacts tokens in errors", async () => {
  const denied = new SnowflakeSqlClient(sampleConfig(), {
    fetchImpl: async () => jsonResponse({ code: "003001", message: "SQL access control error:\nInsufficient privileges to operate on account 'MYORG'", sqlState: "42501" }, { status: 422, statusText: "Unprocessable Entity" }),
  });
  await assert.rejects(denied.execute("SHOW SHARES"), (error) => {
    assert.ok(error instanceof SnowflakeStatementError);
    assert.equal(error.kind, "denied");
    assert.equal(error.sqlCode, "003001");
    assert.equal(error.sqlState, "42501");
    assert.match(error.message, /Insufficient privileges/);
    return true;
  });

  const secretToken = "ayfzGHG9fDtZaSmG3cMg";
  const leaky = new SnowflakeSqlClient(sampleConfig({ tokenType: "OAUTH", token: secretToken, privateKeyPem: undefined, maxRetries: 0 }), {
    fetchImpl: async (_url, init) => {
      assert.equal(headerValue(init.headers, "x-snowflake-authorization-token-type"), "OAUTH");
      assert.equal(headerValue(init.headers, "authorization"), `Bearer ${secretToken}`);
      throw new Error(`socket hang up while sending Bearer ${secretToken}`);
    },
  });
  await assert.rejects(leaky.execute("SELECT 1"), (error) => {
    assertNoWindowOf(error.message, secretToken, "error message with the configured token echoed by the transport");
    assert.match(error.message, /\[REDACTED/);
    return true;
  });

  const slow = new SnowflakeSqlClient(sampleConfig({ timeoutMs: 1000, maxRetries: 0 }), {
    fetchImpl: (_url, init) => new Promise((_resolve, reject) => {
      init.signal.addEventListener("abort", () => reject(new Error("aborted")));
    }),
  });
  await assert.rejects(slow.execute("SELECT 1"), (error) => {
    assert.equal(error.kind, "timeout");
    assert.match(error.message, /timed out/);
    return true;
  });
});

test("SnowflakeSqlClient refuses statements that are not read-only", async () => {
  const client = new SnowflakeSqlClient(sampleConfig(), { fetchImpl: async () => { throw new Error("should not be called"); } });
  await assert.rejects(client.execute("CREATE TABLE t (id INT)"), /non read-only/);
  await assert.rejects(client.execute("ALTER ACCOUNT SET NETWORK_POLICY = x"), /non read-only/);
  await assert.rejects(client.execute("USE ROLE ACCOUNTADMIN"), /non read-only/);
  assert.throws(() => assertReadOnlyStatement("GRANT ROLE x TO USER y"), /non read-only/);
  assert.throws(() => assertReadOnlyStatement("DROP USER x"), /non read-only/);
  assert.doesNotThrow(() => assertReadOnlyStatement("SHOW NETWORK POLICIES"));
  assert.doesNotThrow(() => assertReadOnlyStatement("  select 1"));
  assert.doesNotThrow(() => assertReadOnlyStatement("WITH x AS (SELECT 1) SELECT * FROM x"));
  assert.doesNotThrow(() => assertReadOnlyStatement("DESCRIBE NETWORK POLICY p"));
});

test("assertReadOnlyStatement rejects chained or embedded write statements while accepting every built-in statement", () => {
  assert.throws(() => assertReadOnlyStatement("SELECT 1; DROP TABLE t"), /non read-only/);
  assert.throws(() => assertReadOnlyStatement("SELECT 1;DROP TABLE t"), /non read-only/);
  assert.throws(() => assertReadOnlyStatement("SELECT 1; GRANT ROLE ACCOUNTADMIN TO USER mallory"), /non read-only/);
  assert.throws(() => assertReadOnlyStatement("SELECT 1;"), /non read-only/);
  assert.throws(() => assertReadOnlyStatement("SELECT * FROM TABLE(RESULT_SCAN(LAST_QUERY_ID())) UNION ALL SELECT 1 FROM t WHERE 1 = 1 AND CALL proc()"), /non read-only/);
  assert.throws(() => assertReadOnlyStatement("SHOW USERS; ALTER USER x SET DISABLED = TRUE"), /non read-only/);
  assert.throws(() => assertReadOnlyStatement("WITH x AS (SELECT 1) INSERT INTO t SELECT * FROM x"), /non read-only/);
  assert.throws(() => assertReadOnlyStatement("SELECT 1; USE ROLE ACCOUNTADMIN"), /non read-only/);
  assert.throws(() => assertReadOnlyStatement("SELECT ';' ; DROP TABLE t"), /non read-only/);

  assert.doesNotThrow(() => assertReadOnlyStatement("SELECT * FROM t WHERE note = 'drop; grant'"));
  assert.doesNotThrow(() => assertReadOnlyStatement("SELECT * FROM t WHERE note = 'it''s; fine'"));
  assert.doesNotThrow(() => assertReadOnlyStatement("SELECT CREATED_ON, DELETED_ON, GRANT_OPTION, ALLOWED_IP_LIST, PASSWORD_LAST_SET_TIME FROM t"));

  const sampleArgs = { limit: 500, lookbackDays: 30, policy: { database: "GOV", schema: "POLICIES", name: "STRONG_PW" } };
  const builtIn = Object.entries(SNOWFLAKE_STATEMENTS).map(([name, value]) => {
    if (typeof value === "string") return [name, value];
    if (name === "policyReferences") return [name, value("MASKING_POLICY", sampleArgs.limit)];
    if (name === "policyReferencesByName") return [name, value(sampleArgs.policy)];
    if (name === "roleUsageByQueries" || name === "failedLogins" || name === "loginOutcomes") return [name, value(sampleArgs.lookbackDays)];
    return [name, value(sampleArgs.limit)];
  });
  assert.ok(builtIn.length >= 25);
  for (const [name, statement] of builtIn) {
    assert.doesNotThrow(() => assertReadOnlyStatement(statement), `built-in statement ${name} must pass the read-only guard`);
    assert.equal(typeof statement, "string");
  }
  assert.match(SNOWFLAKE_STATEMENTS.roleUsageByQueries(30), /'INSERT', 'UPDATE', 'DELETE', 'MERGE', 'COPY'/);
});

test("checkSnowflakeAccess reports a healthy account with full visibility", async () => {
  const client = createMockClient((statement) => healthyFixture(statement), { role: "ACCOUNTADMIN" });
  const result = await checkSnowflakeAccess(client);

  assert.equal(result.status, "healthy");
  assert.equal(result.account, "MYORG-MYACCOUNT");
  assert.equal(result.user, "AUDITOR");
  assert.equal(result.role, "ACCOUNTADMIN");
  assert.equal(result.fullVisibility, true);
  assert.ok(result.surfaces.length >= 20);
  assert.ok(result.surfaces.every((surface) => surface.status === "readable"));
  assert.ok(result.surfaces.some((surface) => surface.name === "account_usage_policy_references"));
  assert.ok(result.surfaces.some((surface) => surface.name === "show_shares"));
  assert.match(result.recommendedNextStep, /snowflake_assess_network_and_authentication/);
  assert.ok(result.notes.some((note) => note.includes("KEYPAIR_JWT")));
  assert.ok(client.executed.every((statement) => /^(SHOW|SELECT)\b/i.test(statement.trim())));
});

test("checkSnowflakeAccess reports limited access when ACCOUNT_USAGE views are denied", async () => {
  const client = createMockClient((statement) => {
    if (statement.includes("ACCOUNT_USAGE")) {
      throw new SnowflakeStatementError("SQL compilation error: Database 'SNOWFLAKE' does not exist or not authorized.", { statusCode: 422 });
    }
    if (statement === "SHOW SHARES") {
      throw new Error("request timed out after 5000ms");
    }
    return healthyFixture(statement, { role: "AUDIT_ROLE" });
  }, { role: "AUDIT_ROLE" });
  const result = await checkSnowflakeAccess(client);

  assert.equal(result.status, "limited");
  assert.equal(result.fullVisibility, false);
  const denied = result.surfaces.filter((surface) => surface.status === "denied");
  assert.ok(denied.length >= 10);
  assert.ok(denied.every((surface) => surface.name.startsWith("account_usage_")));
  assert.ok(result.surfaces.some((surface) => surface.name === "show_shares" && surface.status === "timeout"));
  assert.ok(result.notes.some((note) => note.includes("lacks MANAGE GRANTS")));
  assert.match(result.recommendedNextStep, /IMPORTED PRIVILEGES/);
});

test("assessSnowflakeNetworkAndAuthentication passes on a hardened fixture with every control evaluated", async () => {
  const result = await assessSnowflakeNetworkAndAuthentication(createMockClient((statement) => healthyFixture(statement)));
  assert.equal(result.area, "network-and-authentication");
  assert.deepEqual(statusMap(result), {
    "SNOWFLAKE-01": "pass",
    "SNOWFLAKE-02": "pass",
    "SNOWFLAKE-03": "pass",
    "SNOWFLAKE-04": "pass",
    "SNOWFLAKE-05": "pass",
    "SNOWFLAKE-06": "pass",
    "SNOWFLAKE-25": "pass",
  });
  assert.equal(result.summary.pass, 7);
  assert.equal(result.summary.full_visibility, true);
  const control1 = findingById(result, "SNOWFLAKE-01");
  assert.equal(control1.evidence.account_policy, "CORP_POLICY");
  assert.equal(control1.evidence.account_policy_level, "ACCOUNT");
  assert.equal(control1.evidence.user_level_attachments, 1);
  const control3 = findingById(result, "SNOWFLAKE-03");
  assert.equal(control3.evidence.password_human_users, 2);
  assert.equal(control3.severity, "critical");
  for (const item of result.findings) {
    assert.equal(item.mappings.length, SNOWFLAKE_FRAMEWORKS.length);
    for (const framework of SNOWFLAKE_FRAMEWORKS) {
      assert.ok(item.mappings.some((entry) => entry.startsWith(`${framework} `)), `${item.id} lacks ${framework} mapping`);
    }
  }
});

test("assessSnowflakeNetworkAndAuthentication fails on permissive network, missing MFA, weak policies, and disabled SSO", async () => {
  const result = await assessSnowflakeNetworkAndAuthentication(createMockClient((statement) => failingFixture(statement)));
  assert.deepEqual(statusMap(result), {
    "SNOWFLAKE-01": "fail",
    "SNOWFLAKE-02": "fail",
    "SNOWFLAKE-03": "fail",
    "SNOWFLAKE-04": "fail",
    "SNOWFLAKE-05": "fail",
    "SNOWFLAKE-06": "fail",
    "SNOWFLAKE-25": "fail",
  });
  assert.match(findingById(result, "SNOWFLAKE-01").summary, /none is activated at ACCOUNT level/);
  assert.match(findingById(result, "SNOWFLAKE-02").summary, /0\.0\.0\.0\/0/);
  assert.match(findingById(result, "SNOWFLAKE-03").summary, /NO_MFA_USER/);
  assert.match(findingById(result, "SNOWFLAKE-04").summary, /none attached at ACCOUNT level/);
  assert.match(findingById(result, "SNOWFLAKE-05").summary, /lack an RSA public key/);
  assert.match(findingById(result, "SNOWFLAKE-06").summary, /none reports enabled = true/);
  assert.match(findingById(result, "SNOWFLAKE-25").summary, /none attached at ACCOUNT level/);
});

test("assessSnowflakeNetworkAndAuthentication never passes when enabling flags are absent or false", async () => {
  const withoutMfaColumns = await assessSnowflakeNetworkAndAuthentication(createMockClient((statement) => {
    const base = healthyFixture(statement);
    if (normalizeStatement(statement).includes("ACCOUNT_USAGE.USERS") && !statement.includes("COUNT(*)")) {
      const columns = USER_COLUMNS.filter((column) => column !== "HAS_MFA" && column !== "EXT_AUTHN_DUO");
      return resultSet(statement, columns, HEALTHY_USERS.map((row) => USER_COLUMNS.map((column, index) => [column, row[index]]).filter(([column]) => columns.includes(column)).map(([, value]) => value)));
    }
    return base;
  }));
  const mfa = findingById(withoutMfaColumns, "SNOWFLAKE-03");
  assert.equal(mfa.status, "fail");
  assert.equal(mfa.evidence.users_with_unknown_mfa_flags, 2);

  const policyWithoutActivation = await assessSnowflakeNetworkAndAuthentication(createMockClient((statement) => {
    if (statement === "SHOW PARAMETERS LIKE 'NETWORK_POLICY' IN ACCOUNT") {
      return resultSet(statement, PARAMETER_COLUMNS, [["NETWORK_POLICY", "CORP_POLICY", "", "", "", "STRING"]]);
    }
    if (normalizeStatement(statement).includes("'NETWORK_POLICY'") && statement.includes("POLICY_REFERENCES")) {
      return resultSet(statement, POLICY_REFERENCE_COLUMNS, []);
    }
    return healthyFixture(statement);
  }));
  const network = findingById(policyWithoutActivation, "SNOWFLAKE-01");
  assert.equal(network.status, "fail");
  assert.match(network.summary, /none is activated at ACCOUNT level/);

  const passwordPolicyUnattached = await assessSnowflakeNetworkAndAuthentication(createMockClient((statement) => {
    if (statement.includes(policyReferencesFunctionCall("GOV", "POLICIES", "STRONG_PW"))) {
      return resultSet(statement, POLICY_REFERENCE_FUNCTION_COLUMNS, [policyFunctionReference("PASSWORD_POLICY", "STRONG_PW", "USER", "ALICE")]);
    }
    return healthyFixture(statement);
  }));
  assert.equal(findingById(passwordPolicyUnattached, "SNOWFLAKE-04").status, "fail");
});

test("controls 4 and 25 read policy assignments through the INFORMATION_SCHEMA.POLICY_REFERENCES table function, never the ACCOUNT_USAGE view", async () => {
  const client = createMockClient((statement) => healthyFixture(statement));
  const result = await assessSnowflakeNetworkAndAuthentication(client);

  const passwordLookup = client.executed.filter((statement) => statement.includes("INFORMATION_SCHEMA.POLICY_REFERENCES") && statement.includes("STRONG_PW"));
  assert.equal(passwordLookup.length, 1);
  assert.equal(passwordLookup[0], "SELECT POLICY_DB, POLICY_SCHEMA, POLICY_NAME, POLICY_KIND, REF_DATABASE_NAME, REF_SCHEMA_NAME, REF_ENTITY_NAME, REF_ENTITY_DOMAIN FROM TABLE(GOV.INFORMATION_SCHEMA.POLICY_REFERENCES(POLICY_NAME => 'GOV.POLICIES.STRONG_PW'))");
  const sessionLookup = client.executed.filter((statement) => statement.includes("INFORMATION_SCHEMA.POLICY_REFERENCES") && statement.includes("SESSION_STRICT"));
  assert.equal(sessionLookup.length, 1);
  assert.ok(client.executed.every((statement) => !(statement.includes("ACCOUNT_USAGE.POLICY_REFERENCES") && /'(PASSWORD|SESSION)_POLICY'/.test(statement))));

  const control4 = findingById(result, "SNOWFLAKE-04");
  assert.equal(control4.status, "pass");
  assert.equal(control4.evidence.reference_lookups, 1);
  assert.equal(control4.evidence.account_level_attachments, 1);
  assert.deepEqual(control4.evidence.account_level_policies, ["STRONG_PW"]);
  assert.match(control4.summary, /POLICY_REFERENCES lookups/);
  const control25 = findingById(result, "SNOWFLAKE-25");
  assert.equal(control25.status, "pass");
  assert.deepEqual(control25.evidence.account_level_policies, ["SESSION_STRICT"]);
  assert.ok(result.statements.some((outcome) => outcome.key === "password_policy_references_1"));
  assert.ok(result.statements.some((outcome) => outcome.key === "session_policy_references_1"));

  const lookupDenied = await assessSnowflakeNetworkAndAuthentication(createMockClient((statement) => {
    if (statement.includes("INFORMATION_SCHEMA.POLICY_REFERENCES")) {
      throw new SnowflakeStatementError("SQL access control error: Insufficient privileges to operate on password policy 'STRONG_PW'", { statusCode: 422 });
    }
    return healthyFixture(statement);
  }));
  assert.equal(findingById(lookupDenied, "SNOWFLAKE-04").status, "manual");
  assert.match(findingById(lookupDenied, "SNOWFLAKE-04").summary, /denied/i);
  assert.equal(findingById(lookupDenied, "SNOWFLAKE-25").status, "manual");

  const limitedRoleNoAccountRow = await assessSnowflakeNetworkAndAuthentication(createMockClient((statement) => {
    if (statement.includes("INFORMATION_SCHEMA.POLICY_REFERENCES")) {
      return resultSet(statement, POLICY_REFERENCE_FUNCTION_COLUMNS, []);
    }
    return healthyFixture(statement, { role: "AUDIT_ROLE" });
  }, { role: "AUDIT_ROLE" }));
  assert.equal(findingById(limitedRoleNoAccountRow, "SNOWFLAKE-04").status, "manual");
  assert.match(findingById(limitedRoleNoAccountRow, "SNOWFLAKE-04").summary, /APPLY PASSWORD POLICY/);
  assert.equal(findingById(limitedRoleNoAccountRow, "SNOWFLAKE-25").status, "manual");

  const quotedPolicyNames = createMockClient((statement) => {
    if (statement.includes("INFORMATION_SCHEMA.POLICY_REFERENCES")) {
      return resultSet(statement, POLICY_REFERENCE_FUNCTION_COLUMNS, [policyFunctionReference("PASSWORD_POLICY", "Mixed Case", "ACCOUNT", "MYORG-MYACCOUNT")]);
    }
    if (normalizeStatement(statement).includes("ACCOUNT_USAGE.PASSWORD_POLICIES") && !statement.includes("COUNT(*)")) {
      return resultSet(statement, PASSWORD_POLICY_COLUMNS, [["Mixed Case", "gov-db", "POLICIES", "SECURITYADMIN", "14", "256", "1", "1", "1", "1", "0", "90", "5", "30", "12"]]);
    }
    return healthyFixture(statement);
  });
  await assessSnowflakeNetworkAndAuthentication(quotedPolicyNames);
  const quotedLookup = quotedPolicyNames.executed.find((statement) => statement.includes("Mixed Case"));
  assert.equal(quotedLookup, "SELECT POLICY_DB, POLICY_SCHEMA, POLICY_NAME, POLICY_KIND, REF_DATABASE_NAME, REF_SCHEMA_NAME, REF_ENTITY_NAME, REF_ENTITY_DOMAIN FROM TABLE(\"gov-db\".INFORMATION_SCHEMA.POLICY_REFERENCES(POLICY_NAME => '\"gov-db\".POLICIES.\"Mixed Case\"'))");
});

test("control 4 records unchecked policies when the lookup cap is exceeded and never passes on them", async () => {
  const manyPolicies = Array.from({ length: 22 }, (_, index) => [`PW_${index + 1}`, "GOV", "POLICIES", "SECURITYADMIN", "14", "256", "1", "1", "1", "1", "0", "90", "5", "30", "12"]);
  const client = createMockClient((statement) => {
    if (normalizeStatement(statement).includes("ACCOUNT_USAGE.PASSWORD_POLICIES") && !statement.includes("COUNT(*)")) {
      return resultSet(statement, PASSWORD_POLICY_COLUMNS, manyPolicies);
    }
    if (statement.includes("INFORMATION_SCHEMA.POLICY_REFERENCES") && statement.includes("PW_")) {
      const attached = statement.includes("'GOV.POLICIES.PW_1'");
      return resultSet(statement, POLICY_REFERENCE_FUNCTION_COLUMNS, attached ? [policyFunctionReference("PASSWORD_POLICY", "PW_1", "ACCOUNT", "MYORG-MYACCOUNT")] : []);
    }
    return healthyFixture(statement);
  });
  const result = await assessSnowflakeNetworkAndAuthentication(client);
  const control4 = findingById(result, "SNOWFLAKE-04");
  assert.equal(control4.status, "warn");
  assert.equal(control4.evidence.reference_lookups, 20);
  assert.equal(control4.evidence.unchecked_policies.length, 2);
  assert.match(control4.summary, /2 of 22 policies were not checked/);
  assert.equal(client.executed.filter((statement) => statement.includes("INFORMATION_SCHEMA.POLICY_REFERENCES") && statement.includes("PW_")).length, 20);
});

test("assessSnowflakeAccessControl passes on a least-privilege fixture and explains compliant empties", async () => {
  const result = await assessSnowflakeAccessControl(createMockClient((statement) => healthyFixture(statement)));
  assert.equal(result.area, "access-control");
  assert.deepEqual(statusMap(result), {
    "SNOWFLAKE-07": "pass",
    "SNOWFLAKE-08": "pass",
    "SNOWFLAKE-09": "pass",
    "SNOWFLAKE-10": "pass",
    "SNOWFLAKE-16": "pass",
  });
  assert.deepEqual(findingById(result, "SNOWFLAKE-08").evidence.accountadmin_users, ["ALICE", "BOB"]);
  assert.match(findingById(result, "SNOWFLAKE-10").summary, /empty result is the compliant state/);
  assert.match(findingById(result, "SNOWFLAKE-16").summary, /empty result is the compliant state/);
  assert.equal(findingById(result, "SNOWFLAKE-09").evidence.accountadmin_queries, 0);
});

test("assessSnowflakeAccessControl fails on admin inheritance, too many ACCOUNTADMINs, routine admin usage, and PUBLIC grants", async () => {
  const result = await assessSnowflakeAccessControl(createMockClient((statement) => failingFixture(statement)), { maxAccountAdmins: 3 });
  assert.deepEqual(statusMap(result), {
    "SNOWFLAKE-07": "fail",
    "SNOWFLAKE-08": "fail",
    "SNOWFLAKE-09": "fail",
    "SNOWFLAKE-10": "fail",
    "SNOWFLAKE-16": "fail",
  });
  assert.match(findingById(result, "SNOWFLAKE-07").summary, /ACCOUNTADMIN -> DATA_ENGINEER/);
  assert.match(findingById(result, "SNOWFLAKE-08").summary, /4 users hold ACCOUNTADMIN/);
  assert.match(findingById(result, "SNOWFLAKE-09").summary, /800\/1000 routine queries/);
  assert.match(findingById(result, "SNOWFLAKE-10").summary, /granted directly to users/);
  assert.match(findingById(result, "SNOWFLAKE-16").summary, /PUBLIC grants target data objects/);
});

test("assessSnowflakeMonitoringAndLifecycle passes on a monitored fixture and reports NULL login timestamps separately", async () => {
  const result = await assessSnowflakeMonitoringAndLifecycle(createMockClient((statement) => healthyFixture(statement)));
  assert.equal(result.area, "monitoring-and-lifecycle");
  assert.deepEqual(statusMap(result), {
    "SNOWFLAKE-11": "pass",
    "SNOWFLAKE-12": "pass",
    "SNOWFLAKE-13": "pass",
    "SNOWFLAKE-24": "pass",
  });
  assert.equal(findingById(result, "SNOWFLAKE-11").evidence.failed_logins, 3);
  assert.equal(findingById(result, "SNOWFLAKE-12").evidence.users_without_login_timestamp_count, 0);

  const withNullLogin = await assessSnowflakeMonitoringAndLifecycle(createMockClient((statement) => {
    if (normalizeStatement(statement).includes("ACCOUNT_USAGE.USERS") && !statement.includes("COUNT(*)")) {
      return resultSet(statement, USER_COLUMNS, [userRow(), userRow({ NAME: "NEVER_LOGGED_IN", LOGIN_NAME: "NEVER", LAST_SUCCESS_LOGIN: null })]);
    }
    return healthyFixture(statement);
  }));
  const stale = findingById(withNullLogin, "SNOWFLAKE-12");
  assert.equal(stale.status, "warn");
  assert.deepEqual(stale.evidence.users_without_login_timestamp, ["NEVER_LOGGED_IN"]);
  assert.match(stale.summary, /NULL LAST_SUCCESS_LOGIN/);
});

test("assessSnowflakeMonitoringAndLifecycle fails on brute force, stale users, zero retention, and always-on warehouses", async () => {
  const result = await assessSnowflakeMonitoringAndLifecycle(createMockClient((statement) => failingFixture(statement)));
  assert.deepEqual(statusMap(result), {
    "SNOWFLAKE-11": "fail",
    "SNOWFLAKE-12": "fail",
    "SNOWFLAKE-13": "fail",
    "SNOWFLAKE-24": "fail",
  });
  assert.match(findingById(result, "SNOWFLAKE-11").summary, /exceeded 10 failed logins/);
  const stale = findingById(result, "SNOWFLAKE-12");
  assert.deepEqual(stale.evidence.stale_users, ["NO_MFA_USER"]);
  assert.deepEqual(stale.evidence.users_without_login_timestamp, ["GHOST"]);
  assert.match(stale.summary, /were not counted as active/);
  assert.match(findingById(result, "SNOWFLAKE-13").summary, /below the 1-day threshold/);
  assert.match(findingById(result, "SNOWFLAKE-24").summary, /ALWAYS_ON_WH/);
});

test("assessSnowflakeDataProtection passes on a governed fixture while Tri-Secret Secure and CMK stay manual", async () => {
  const result = await assessSnowflakeDataProtection(createMockClient((statement) => healthyFixture(statement)));
  assert.equal(result.area, "data-protection");
  assert.deepEqual(statusMap(result), {
    "SNOWFLAKE-14": "pass",
    "SNOWFLAKE-15": "pass",
    "SNOWFLAKE-17": "pass",
    "SNOWFLAKE-18": "pass",
    "SNOWFLAKE-19": "pass",
    "SNOWFLAKE-20": "manual",
    "SNOWFLAKE-21": "manual",
    "SNOWFLAKE-22": "pass",
    "SNOWFLAKE-23": "pass",
  });
  assert.match(findingById(result, "SNOWFLAKE-20").summary, /Not verifiable through SQL/);
  assert.match(findingById(result, "SNOWFLAKE-20").summary, /Business Critical/);
  assert.match(findingById(result, "SNOWFLAKE-21").summary, /platform-info and CMK system functions only return VPC or VNet identifiers and setup templates, so none was run/);
  assert.doesNotMatch(findingById(result, "SNOWFLAKE-21").summary, /SYSTEM\$/, "the summary names no system function the run did not execute");
  assert.equal(findingById(result, "SNOWFLAKE-14").evidence.masking_references, 3);
  assert.equal(findingById(result, "SNOWFLAKE-14").evidence.tag_classification_summary.length, 2);
  assert.match(findingById(result, "SNOWFLAKE-22").summary, /empty outbound inventory is compliant/);
});

test("assessSnowflakeDataProtection fails on missing masking, open stages, zero Time Travel, and flags shares and integrations", async () => {
  const result = await assessSnowflakeDataProtection(createMockClient((statement) => failingFixture(statement)));
  assert.deepEqual(statusMap(result), {
    "SNOWFLAKE-14": "fail",
    "SNOWFLAKE-15": "fail",
    "SNOWFLAKE-17": "fail",
    "SNOWFLAKE-18": "fail",
    "SNOWFLAKE-19": "fail",
    "SNOWFLAKE-20": "manual",
    "SNOWFLAKE-21": "manual",
    "SNOWFLAKE-22": "warn",
    "SNOWFLAKE-23": "warn",
  });
  assert.match(findingById(result, "SNOWFLAKE-15").summary, /none is assigned to a table or view/);
  assert.match(findingById(result, "SNOWFLAKE-19").summary, /SALES/);
  const shares = findingById(result, "SNOWFLAKE-22");
  assert.equal(shares.evidence.listing_backed_shares, 1);
  assert.match(shares.summary, /1 OUTBOUND shares/);
  assert.match(findingById(result, "SNOWFLAKE-23").summary, /LAMBDA_API/);
});

test("control 22 passes on an empty outbound inventory only under ACCOUNTADMIN and renders manual for every other role", async () => {
  const emptyShares = (role) => createMockClient((statement) => {
    if (normalizeStatement(statement) === "SHOW SHARES") return resultSet(statement, SHARE_COLUMNS, []);
    return healthyFixture(statement, { role });
  }, { role });

  const securityAdminEmpty = await assessSnowflakeDataProtection(emptyShares("SECURITYADMIN"));
  const securityAdminFinding = findingById(securityAdminEmpty, "SNOWFLAKE-22");
  assert.equal(securityAdminFinding.status, "manual");
  assert.match(securityAdminFinding.summary, /SECURITYADMIN/);
  assert.match(securityAdminFinding.summary, /IMPORT SHARE/);
  assert.match(securityAdminFinding.summary, /indistinguishable from a denied read/);
  assert.equal(securityAdminFinding.evidence.shares_seen, 0);

  const securityAdminInboundOnly = await assessSnowflakeDataProtection(createMockClient((statement) => healthyFixture(statement, { role: "SECURITYADMIN" }), { role: "SECURITYADMIN" }));
  assert.equal(findingById(securityAdminInboundOnly, "SNOWFLAKE-22").status, "manual");
  assert.equal(findingById(securityAdminInboundOnly, "SNOWFLAKE-22").evidence.shares_seen, 1);

  const customRoleEmpty = await assessSnowflakeDataProtection(emptyShares("SHARE_ADMIN"));
  assert.equal(findingById(customRoleEmpty, "SNOWFLAKE-22").status, "manual");

  const accountAdminEmpty = await assessSnowflakeDataProtection(emptyShares("ACCOUNTADMIN"));
  assert.equal(findingById(accountAdminEmpty, "SNOWFLAKE-22").status, "pass");
  assert.match(findingById(accountAdminEmpty, "SNOWFLAKE-22").summary, /readable under ACCOUNTADMIN/);

  const securityAdminOutbound = await assessSnowflakeDataProtection(createMockClient((statement) => {
    if (normalizeStatement(statement) === "SHOW SHARES") return failingFixture(statement);
    return healthyFixture(statement, { role: "SECURITYADMIN" });
  }, { role: "SECURITYADMIN" }));
  const outboundFinding = findingById(securityAdminOutbound, "SNOWFLAKE-22");
  assert.equal(outboundFinding.status, "warn");
  assert.match(outboundFinding.summary, /inventory is partial; re-run as ACCOUNTADMIN/);
});

test("SERVICE_AGENT users are classified as service-class and every documented TYPE is assessed or surfaced", async () => {
  assert.equal(classifyUserType("PERSON"), "person");
  assert.equal(classifyUserType(null), "person");
  assert.equal(classifyUserType("NULL"), "person");
  assert.equal(classifyUserType("SERVICE"), "service");
  assert.equal(classifyUserType("SERVICE_AGENT"), "service");
  assert.equal(classifyUserType("LEGACY_SERVICE"), "service");
  assert.equal(classifyUserType("service_agent"), "service");
  assert.equal(classifyUserType("SNOWFLAKE_SERVICE"), "snowflake_managed");
  assert.equal(classifyUserType("FUTURE_TYPE"), "unrecognized");

  const agentWithoutKey = userRow({ NAME: "AGENT_NO_KEY", LOGIN_NAME: "AGENT_NO_KEY", TYPE: "SERVICE_AGENT", HAS_PASSWORD: "false", HAS_MFA: "false", HAS_RSA_PUBLIC_KEY: "false", HAS_WORKLOAD_IDENTITY: "false", HAS_PAT: "true", LAST_SUCCESS_LOGIN: isoDaysAgo(1) });
  const agentWithKey = userRow({ NAME: "AGENT_KEYED", LOGIN_NAME: "AGENT_KEYED", TYPE: "SERVICE_AGENT", HAS_PASSWORD: "false", HAS_MFA: "false", HAS_RSA_PUBLIC_KEY: "true", LAST_SUCCESS_LOGIN: isoDaysAgo(1) });
  const managed = userRow({ NAME: "SPCS_SVC", LOGIN_NAME: "SPCS_SVC", TYPE: "SNOWFLAKE_SERVICE", HAS_PASSWORD: "false", HAS_MFA: "false", HAS_RSA_PUBLIC_KEY: "false", LAST_SUCCESS_LOGIN: isoDaysAgo(1) });
  const usersFixture = (rows) => (statement) => {
    if (normalizeStatement(statement).includes("ACCOUNT_USAGE.USERS") && !statement.includes("COUNT(*)")) return resultSet(statement, USER_COLUMNS, rows);
    return healthyFixture(statement);
  };

  const failing = await assessSnowflakeNetworkAndAuthentication(createMockClient(usersFixture([...HEALTHY_USERS, agentWithoutKey, managed])));
  const control5 = findingById(failing, "SNOWFLAKE-05");
  assert.equal(control5.status, "fail");
  assert.deepEqual(control5.evidence.service_users_without_key_pair, ["AGENT_NO_KEY"]);
  assert.deepEqual(control5.evidence.service_users_by_type, { SERVICE: 1, SERVICE_AGENT: 1 });
  assert.deepEqual(control5.evidence.snowflake_managed_service_users, ["SPCS_SVC"]);
  assert.equal(control5.evidence.user_classes.service, 2);
  assert.equal(control5.evidence.user_classes.snowflake_managed, 1);
  const control3 = findingById(failing, "SNOWFLAKE-03");
  assert.equal(control3.status, "pass");
  assert.equal(control3.evidence.enabled_human_users, 2, "SERVICE_AGENT users are not counted as person users for MFA");

  const passing = await assessSnowflakeNetworkAndAuthentication(createMockClient(usersFixture([...HEALTHY_USERS, agentWithKey, managed])));
  const keyed = findingById(passing, "SNOWFLAKE-05");
  assert.equal(keyed.status, "pass");
  assert.match(keyed.summary, /SERVICE, SERVICE_AGENT, LEGACY_SERVICE/);
  assert.match(keyed.summary, /1 SNOWFLAKE_SERVICE users are Snowflake managed/);

  const unrecognized = userRow({ NAME: "MYSTERY", LOGIN_NAME: "MYSTERY", TYPE: "FUTURE_TYPE", HAS_PASSWORD: "false", HAS_MFA: "false", HAS_RSA_PUBLIC_KEY: "false", LAST_SUCCESS_LOGIN: isoDaysAgo(1) });
  const surfaced = await assessSnowflakeNetworkAndAuthentication(createMockClient(usersFixture([...HEALTHY_USERS, unrecognized])));
  for (const id of ["SNOWFLAKE-03", "SNOWFLAKE-05"]) {
    const item = findingById(surfaced, id);
    assert.equal(item.status, "warn", `${id} must not pass while a user has an unrecognized TYPE`);
    assert.match(item.summary, /unrecognized TYPE \(FUTURE_TYPE\)/);
    assert.deepEqual(item.evidence.user_classes.unrecognized_types, ["FUTURE_TYPE"]);
  }
  const lifecycle = await assessSnowflakeMonitoringAndLifecycle(createMockClient(usersFixture([...HEALTHY_USERS, unrecognized])));
  assert.equal(findingById(lifecycle, "SNOWFLAKE-12").status, "warn");
  assert.match(findingById(lifecycle, "SNOWFLAKE-12").summary, /unrecognized TYPE/);

  const staleAgent = userRow({ NAME: "OLD_AGENT", LOGIN_NAME: "OLD_AGENT", TYPE: "SERVICE_AGENT", HAS_PASSWORD: "false", HAS_MFA: "false", HAS_RSA_PUBLIC_KEY: "true", LAST_SUCCESS_LOGIN: isoDaysAgo(400) });
  const staleLifecycle = await assessSnowflakeMonitoringAndLifecycle(createMockClient(usersFixture([...HEALTHY_USERS, staleAgent])));
  const staleFinding = findingById(staleLifecycle, "SNOWFLAKE-12");
  assert.equal(staleFinding.status, "warn");
  assert.deepEqual(staleFinding.evidence.stale_service_class_users, ["OLD_AGENT"]);
});

test("control 9 records the QUERY_HISTORY row limit so a truncated role list cannot pass", async () => {
  const roleUsage = SNOWFLAKE_STATEMENTS.roleUsageByQueries(30);
  assert.match(roleUsage, /LIMIT 500$/);
  const client = createMockClient((statement) => {
    const normalized = normalizeStatement(statement);
    if (normalized.includes("ACCOUNT_USAGE.QUERY_HISTORY") && normalized.includes("GROUP BY ROLE_NAME")) {
      const rows = Array.from({ length: 500 }, (_, index) => [`ROLE_${index}`, String(1000 - index), "1"]);
      return resultSet(statement, ["ROLE_NAME", "QUERY_COUNT", "USER_COUNT"], rows);
    }
    return healthyFixture(statement);
  });
  const result = await assessSnowflakeAccessControl(client);
  const control9 = findingById(result, "SNOWFLAKE-09");
  assert.equal(control9.status, "warn");
  assert.match(control9.summary, /hit the 500-row limit \(500 rows seen\)/);
  assert.match(control9.summary, /cannot be pass on a partial result/);
  const outcome = result.statements.find((statement) => statement.key === "role_usage_by_queries");
  assert.equal(outcome.rowLimit, 500);
  assert.equal(outcome.truncated, true);

  const monitoring = await assessSnowflakeMonitoringAndLifecycle(createMockClient((statement) => {
    const normalized = normalizeStatement(statement);
    if (normalized.includes("ACCOUNT_USAGE.LOGIN_HISTORY") && normalized.includes("IS_SUCCESS = 'NO'")) {
      const rows = Array.from({ length: 500 }, (_, index) => [`USER_${index}`, `10.0.0.${index % 250}`, "JDBC_DRIVER", "2", "INCORRECT_USERNAME_PASSWORD"]);
      return resultSet(statement, ["USER_NAME", "CLIENT_IP", "REPORTED_CLIENT_TYPE", "FAILURE_COUNT", "LAST_ERROR"], rows);
    }
    return healthyFixture(statement);
  }));
  const control11 = findingById(monitoring, "SNOWFLAKE-11");
  assert.notEqual(control11.status, "pass");
  assert.match(control11.summary, /hit the 500-row limit/);
});

test("all four assessments together cover every one of the 25 spec controls exactly once", async () => {
  const results = await runAllAssessments(createMockClient((statement) => healthyFixture(statement)));
  const ids = allFindings(results).map((item) => item.id).sort();
  assert.deepEqual(ids, [...ALL_CONTROL_IDS].sort());
  assert.equal(ids.length, 25);
  assert.equal(new Set(ids).size, 25);
  assert.equal(ids.length, Object.keys(SNOWFLAKE_CONTROLS).length);
});

test("false-pass self-check (a): denied, failed, or timed-out statements never pass and name the cause", async () => {
  let counter = 0;
  const results = await runAllAssessments(createMockClient((statement) => {
    counter += 1;
    const remainder = counter % 3;
    if (remainder === 0) throw new SnowflakeStatementError("SQL access control error: Insufficient privileges to operate on account", { statusCode: 422 });
    if (remainder === 1) throw new SnowflakeStatementError(`Snowflake statement did not complete before the 30s statement timeout: ${statement.slice(0, 20)}`, { kind: "timeout" });
    throw new Error("SQL compilation error: Object 'SNOWFLAKE.ACCOUNT_USAGE.USERS' does not exist");
  }));
  const findings = allFindings(results);
  assert.equal(findings.length, 25);
  assert.equal(findings.filter((item) => item.status === "pass").length, 0);
  assert.ok(findings.every((item) => item.status === "manual"), JSON.stringify(statusMapFromFindings(findings)));
  for (const item of findings.filter((item) => item.control !== 20 && item.control !== 21)) {
    assert.match(item.summary, /^Unknown: /);
    assert.match(item.summary, /was denied \(insufficient privileges\)|timed out|failed:/);
    assert.match(item.summary, /Collect manually: /);
    assert.ok(item.evidence.statements.every((statement) => statement.status !== "ok"));
  }
  for (const result of results) {
    assert.ok(result.statements.every((statement) => statement.status !== "ok"));
    assert.equal(result.summary.pass, 0);
  }
});

function statusMapFromFindings(findings) {
  return Object.fromEntries(findings.map((item) => [item.id, item.status]));
}

test("false-pass self-check (b): empty result sets only pass where emptiness is compliant, and each such summary says so", async () => {
  const limitedResults = await runAllAssessments(createMockClient((statement) => emptyFixture(statement), { role: undefined }));
  const limitedFindings = allFindings(limitedResults);
  assert.equal(limitedFindings.length, 25);
  const limitedPasses = limitedFindings.filter((item) => item.status === "pass").map((item) => item.id).sort();
  assert.deepEqual(limitedPasses, ["SNOWFLAKE-10", "SNOWFLAKE-16"]);
  for (const item of limitedFindings.filter((candidate) => candidate.status === "pass")) {
    assert.match(item.summary, /empty result is the compliant state/);
  }
  const limitedStatuses = statusMapFromFindings(limitedFindings);
  assert.equal(limitedStatuses["SNOWFLAKE-01"], "fail");
  assert.equal(limitedStatuses["SNOWFLAKE-02"], "fail");
  assert.equal(limitedStatuses["SNOWFLAKE-03"], "manual");
  assert.equal(limitedStatuses["SNOWFLAKE-04"], "fail");
  assert.equal(limitedStatuses["SNOWFLAKE-05"], "manual");
  assert.equal(limitedStatuses["SNOWFLAKE-06"], "manual");
  assert.equal(limitedStatuses["SNOWFLAKE-07"], "manual");
  assert.equal(limitedStatuses["SNOWFLAKE-08"], "manual");
  assert.equal(limitedStatuses["SNOWFLAKE-09"], "manual");
  assert.equal(limitedStatuses["SNOWFLAKE-11"], "manual");
  assert.equal(limitedStatuses["SNOWFLAKE-12"], "manual");
  assert.equal(limitedStatuses["SNOWFLAKE-13"], "manual");
  assert.equal(limitedStatuses["SNOWFLAKE-14"], "fail");
  assert.equal(limitedStatuses["SNOWFLAKE-15"], "fail");
  assert.equal(limitedStatuses["SNOWFLAKE-17"], "manual");
  assert.equal(limitedStatuses["SNOWFLAKE-18"], "manual");
  assert.equal(limitedStatuses["SNOWFLAKE-19"], "manual");
  assert.equal(limitedStatuses["SNOWFLAKE-22"], "manual");
  assert.equal(limitedStatuses["SNOWFLAKE-23"], "manual");
  assert.equal(limitedStatuses["SNOWFLAKE-24"], "manual");
  assert.equal(limitedStatuses["SNOWFLAKE-25"], "fail");
  for (const item of limitedFindings.filter((candidate) => candidate.status === "fail")) {
    assert.match(item.summary, /zero|empty/i);
  }

  const adminResults = await runAllAssessments(createMockClient((statement) => {
    if (normalizeStatement(statement).startsWith("SELECT CURRENT_ACCOUNT()")) return healthyFixture(statement, { role: "ACCOUNTADMIN" });
    return emptyFixture(statement);
  }));
  const adminPasses = allFindings(adminResults).filter((item) => item.status === "pass").map((item) => item.id).sort();
  assert.deepEqual(adminPasses, ["SNOWFLAKE-10", "SNOWFLAKE-16", "SNOWFLAKE-22", "SNOWFLAKE-23"]);
  for (const item of allFindings(adminResults).filter((candidate) => candidate.status === "pass")) {
    assert.match(item.summary, /compliant/);
    assert.match(item.summary, /readable|full visibility|empty/);
  }
});

test("false-pass self-check (c): partial results with unfetched partitions never pass", async () => {
  const results = await runAllAssessments(createMockClient((statement) => {
    const healthy = healthyFixture(statement);
    if (normalizeStatement(statement).startsWith("SELECT CURRENT_ACCOUNT()")) return healthy;
    return { ...healthy, numRows: healthy.rows.length + 40, partitionCount: 3, fetchedPartitions: 1, truncated: true };
  }));
  const findings = allFindings(results);
  assert.equal(findings.length, 25);
  assert.equal(findings.filter((item) => item.status === "pass").length, 0, JSON.stringify(statusMapFromFindings(findings)));
  const downgraded = findings.filter((item) => item.control !== 20 && item.control !== 21);
  assert.ok(downgraded.every((item) => item.status === "warn"));
  for (const item of downgraded) {
    assert.match(item.summary, /Partial inventory: .*returned 1\/3 partitions/);
    assert.match(item.summary, /cannot be pass on a partial result/);
    assert.ok(item.evidence.partial_inventory);
  }
});

test("false-pass self-check (c): a row-limited inventory downgrades pass to warn with seen counts", async () => {
  const client = createMockClient((statement) => healthyFixture(statement), { rowLimit: 100 });
  const rowLimit = client.getResolvedConfig().rowLimit;
  const limitedClient = createMockClient((statement) => {
    const healthy = healthyFixture(statement);
    if (normalizeStatement(statement).includes("ACCOUNT_USAGE.USERS") && !statement.includes("COUNT(*)")) {
      const rows = Array.from({ length: rowLimit }, (_, index) => userRow({ NAME: `USER_${index}`, LOGIN_NAME: `USER_${index}` }));
      return resultSet(statement, USER_COLUMNS, rows);
    }
    return healthy;
  }, { rowLimit });
  const result = await assessSnowflakeNetworkAndAuthentication(limitedClient);
  const mfa = findingById(result, "SNOWFLAKE-03");
  assert.equal(mfa.status, "warn");
  assert.match(mfa.summary, new RegExp(`hit the ${rowLimit}-row limit \\(${rowLimit} rows seen\\)`));
  assert.ok(limitedClient.executed.some((statement) => statement.includes(`LIMIT ${rowLimit}`)));
});

test("false-pass self-check (c): a role without ACCOUNTADMIN visibility cannot pass SHOW-scoped controls", async () => {
  const results = await runAllAssessments(createMockClient((statement) => {
    const normalized = normalizeStatement(statement);
    if (normalized.startsWith("SELECT CURRENT_ACCOUNT()")) return healthyFixture(statement, { role: "AUDIT_ROLE" });
    if (normalized.startsWith("SHOW ") && !normalized.startsWith("SHOW PARAMETERS")) {
      return { ...healthyFixture(statement), rows: [], numRows: 0 };
    }
    return healthyFixture(statement);
  }, { role: "AUDIT_ROLE" }));
  const statuses = statusMapFromFindings(allFindings(results));
  assert.equal(statuses["SNOWFLAKE-01"], "warn");
  assert.equal(statuses["SNOWFLAKE-06"], "manual");
  assert.equal(statuses["SNOWFLAKE-19"], "manual");
  assert.equal(statuses["SNOWFLAKE-22"], "manual");
  assert.equal(statuses["SNOWFLAKE-23"], "manual");
  assert.equal(statuses["SNOWFLAKE-24"], "manual");
  for (const id of ["SNOWFLAKE-06", "SNOWFLAKE-19", "SNOWFLAKE-22", "SNOWFLAKE-23", "SNOWFLAKE-24"]) {
    const item = allFindings(results).find((candidate) => candidate.id === id);
    assert.match(item.summary, /AUDIT_ROLE/);
  }

  const populated = await assessSnowflakeDataProtection(createMockClient((statement) => healthyFixture(statement, { role: "AUDIT_ROLE" }), { role: "AUDIT_ROLE" }));
  assert.equal(findingById(populated, "SNOWFLAKE-19").status, "warn");
  assert.equal(findingById(populated, "SNOWFLAKE-22").status, "manual");
  assert.match(findingById(populated, "SNOWFLAKE-22").summary, /Re-run SHOW SHARES as ACCOUNTADMIN/);
  assert.equal(findingById(populated, "SNOWFLAKE-23").status, "warn");
  const monitoring = await assessSnowflakeMonitoringAndLifecycle(createMockClient((statement) => healthyFixture(statement, { role: "AUDIT_ROLE" }), { role: "AUDIT_ROLE" }));
  assert.equal(findingById(monitoring, "SNOWFLAKE-24").status, "warn");
  assert.match(findingById(monitoring, "SNOWFLAKE-24").summary, /lacks MANAGE GRANTS/);
});

const SHOW_CAP_INVENTORIES = [
  { key: "show_network_policies", statement: "SHOW NETWORK POLICIES", controls: ["SNOWFLAKE-01"], columns: ["created_on", "name", "comment", "entries_in_allowed_ip_list", "entries_in_blocked_ip_list"], row: (index) => ["2025-01-01", index === 0 ? "CORP_POLICY" : `POLICY_${index}`, "", "2", "0"] },
  { key: "show_integrations", statement: "SHOW INTEGRATIONS", controls: ["SNOWFLAKE-06", "SNOWFLAKE-23"], columns: INTEGRATION_COLUMNS, row: (index) => (index === 0 ? ["OKTA_SAML", "SAML2", "SECURITY", "true", "", "2025-01-01"] : [`STAGE_INT_${index}`, "EXTERNAL_STAGE", "STORAGE", "true", "", "2025-01-01"]) },
  { key: "show_warehouses", statement: "SHOW WAREHOUSES", controls: ["SNOWFLAKE-24"], columns: WAREHOUSE_COLUMNS, row: (index) => [`WH_${index}`, "SUSPENDED", "STANDARD", "X-Small", "60", "true", "SYSADMIN"] },
  { key: "show_databases", statement: "SHOW DATABASES", controls: ["SNOWFLAKE-19"], columns: DATABASE_COLUMNS, row: (index) => ["2025-01-01", `DB_${index}`, "STANDARD", "", "SYSADMIN", "7"] },
  { key: "show_shares", statement: "SHOW SHARES", controls: ["SNOWFLAKE-22"], columns: SHARE_COLUMNS, row: (index) => ["2025-01-01", "INBOUND", "PROVIDER.ACCT", `PROVIDER_SHARE_${index}`, `PROVIDER_DB_${index}`, "", "", "", null, "true"] },
  { key: "show_replication_groups", statement: "SHOW REPLICATION GROUPS", controls: ["SNOWFLAKE-22"], columns: ["snowflake_region", "created_on", "account_name", "name", "type", "is_primary"], row: (index) => ["AWS_US_WEST_2", "2025-01-01", "MYORG.MYACCOUNT", `RG_${index}`, "REPLICATION", "true"] },
];

test("rule 10: a SHOW inventory that fills Snowflake's 10,000-row cap is recorded as truncated and its controls never pass", async () => {
  assert.equal(SHOW_ROW_CAP, 10_000);
  for (const inventory of SHOW_CAP_INVENTORIES) {
    const capped = Array.from({ length: SHOW_ROW_CAP }, (_, index) => inventory.row(index));
    const client = createMockClient((statement) => {
      if (normalizeStatement(statement) === inventory.statement) return resultSet(statement, inventory.columns, capped);
      return healthyFixture(statement);
    }, { role: "ACCOUNTADMIN" });
    const findings = allFindings(await runAllAssessments(client));
    for (const id of inventory.controls) {
      const item = findings.find((candidate) => candidate.id === id);
      assert.notEqual(item.status, "pass", `${id} passed on a capped ${inventory.key}`);
      assert.match(item.summary, new RegExp(`Partial inventory: .*${inventory.key} hit the ${SHOW_ROW_CAP}-row limit \\(${SHOW_ROW_CAP} rows seen\\)`), `${id}: ${item.summary}`);
      assert.match(item.summary, /cannot be pass on a partial result/);
      assert.match(item.evidence.partial_inventory, new RegExp(inventory.key));
      assert.ok(item.evidence.statements.some((statement) => statement.key === inventory.key && statement.truncated === true));
    }
    const below = Array.from({ length: SHOW_ROW_CAP - 1 }, (_, index) => inventory.row(index));
    const belowFindings = allFindings(await runAllAssessments(createMockClient((statement) => {
      if (normalizeStatement(statement) === inventory.statement) return resultSet(statement, inventory.columns, below);
      return healthyFixture(statement);
    }, { role: "ACCOUNTADMIN" })));
    for (const id of inventory.controls) {
      const item = belowFindings.find((candidate) => candidate.id === id);
      assert.equal(item.status, "pass", `${id} did not pass one row below the cap: ${item.summary}`);
    }
  }
});

const DENIED_403 = () => new SnowflakeStatementError("Snowflake SQL API request failed (POST /api/v2/statements): HTTP 403 Forbidden", { statusCode: 403 });
const isSession = (s) => s.startsWith("SELECT CURRENT_ACCOUNT()");

/**
 * Every finding whose verdict reads two or more collected statements, with
 * the statement key of each secondary inventory and a matcher for its SQL.
 */
const MULTI_INVENTORY_FINDINGS = [
  { id: "SNOWFLAKE-01", assess: assessSnowflakeNetworkAndAuthentication, secondaries: [
    { key: "account_network_policy_parameter", matches: (s) => s === "SHOW PARAMETERS LIKE 'NETWORK_POLICY' IN ACCOUNT" },
    { key: "network_policy_references", matches: (s) => s.includes("ACCOUNT_USAGE.POLICY_REFERENCES") && s.includes("'NETWORK_POLICY'") },
  ] },
  { id: "SNOWFLAKE-04", assess: assessSnowflakeNetworkAndAuthentication, secondaries: [
    { key: "password_policy_references_1", matches: (s) => s.includes(policyReferencesFunctionCall("GOV", "POLICIES", "STRONG_PW")) },
  ] },
  { id: "SNOWFLAKE-25", assess: assessSnowflakeNetworkAndAuthentication, secondaries: [
    { key: "session_policy_references_1", matches: (s) => s.includes(policyReferencesFunctionCall("GOV", "POLICIES", "SESSION_STRICT")) },
  ] },
  { id: "SNOWFLAKE-07", assess: assessSnowflakeAccessControl, secondaries: [
    { key: "global_privilege_grants", matches: (s) => s.includes("ACCOUNT_USAGE.GRANTS_TO_ROLES") && s.includes("GRANTED_ON = 'ACCOUNT'") },
  ] },
  { id: "SNOWFLAKE-11", assess: assessSnowflakeMonitoringAndLifecycle, secondaries: [
    { key: "failed_logins", matches: (s) => s.includes("ACCOUNT_USAGE.LOGIN_HISTORY") && s.includes("IS_SUCCESS = 'NO'") },
  ] },
  { id: "SNOWFLAKE-13", assess: assessSnowflakeMonitoringAndLifecycle, secondaries: [
    { key: "access_history_probe", matches: (s) => s.includes("ACCOUNT_USAGE.ACCESS_HISTORY"), expect: "warn" },
  ] },
  { id: "SNOWFLAKE-24", assess: assessSnowflakeMonitoringAndLifecycle, secondaries: [
    { key: "session_context", matches: isSession, expect: "warn" },
  ] },
  { id: "SNOWFLAKE-14", assess: assessSnowflakeDataProtection, secondaries: [
    { key: "masking_policy_references", matches: (s) => s.includes("ACCOUNT_USAGE.POLICY_REFERENCES") && s.includes("'MASKING_POLICY'") },
    { key: "tag_references", matches: (s) => s.includes("ACCOUNT_USAGE.TAG_REFERENCES"), expect: "warn" },
  ] },
  { id: "SNOWFLAKE-15", assess: assessSnowflakeDataProtection, secondaries: [
    { key: "row_access_policy_references", matches: (s) => s.includes("ACCOUNT_USAGE.POLICY_REFERENCES") && s.includes("'ROW_ACCESS_POLICY'") },
  ] },
  { id: "SNOWFLAKE-19", assess: assessSnowflakeDataProtection, secondaries: [
    { key: "session_context", matches: isSession, expect: "warn" },
  ] },
  { id: "SNOWFLAKE-22", assess: assessSnowflakeDataProtection, secondaries: [
    { key: "show_replication_groups", matches: (s) => s === "SHOW REPLICATION GROUPS", expect: "warn" },
    { key: "session_context", matches: isSession, expect: "manual" },
  ] },
  { id: "SNOWFLAKE-23", assess: assessSnowflakeDataProtection, secondaries: [
    { key: "session_context", matches: isSession, expect: "warn" },
  ] },
];

test("rule 1 corollary: every multi-inventory finding drops below pass and names the inventory when one secondary statement returns 403", async () => {
  for (const scenario of MULTI_INVENTORY_FINDINGS) {
    const baseline = findingById(await scenario.assess(createMockClient((statement) => healthyFixture(statement), { role: "ACCOUNTADMIN" })), scenario.id);
    assert.equal(baseline.status, "pass", `${scenario.id} must pass on the healthy fixture for the demotion to be meaningful`);
    for (const secondary of scenario.secondaries) {
      const client = createMockClient((statement) => {
        if (secondary.matches(normalizeStatement(statement))) throw DENIED_403();
        return healthyFixture(statement);
      }, { role: "ACCOUNTADMIN" });
      const item = findingById(await scenario.assess(client), scenario.id);
      assert.notEqual(item.status, "pass", `${scenario.id} passed with ${secondary.key} unreadable`);
      if (secondary.expect) assert.equal(item.status, secondary.expect, `${scenario.id} with ${secondary.key} unreadable: ${item.summary}`);
      assert.ok(item.summary.includes(secondary.key), `${scenario.id} summary does not name ${secondary.key}: ${item.summary}`);
      assert.match(item.summary, /denied/i);
      assert.match(item.summary, /[Cc]ollect manually: /);
      const recorded = item.evidence.statements.find((statement) => statement.key === secondary.key);
      assert.equal(recorded?.status, "denied", `${scenario.id} evidence does not record ${secondary.key} as denied`);
      assert.ok(client.executed.some((statement) => secondary.matches(normalizeStatement(statement))), `${secondary.key} was never queried`);
    }
  }

  const tagsDenied = await assessSnowflakeDataProtection(createMockClient((statement) => {
    if (normalizeStatement(statement).includes("ACCOUNT_USAGE.TAG_REFERENCES")) throw DENIED_403();
    return healthyFixture(statement);
  }, { role: "ACCOUNTADMIN" }));
  const masking = findingById(tagsDenied, "SNOWFLAKE-14");
  assert.equal(masking.status, "warn");
  assert.match(masking.summary, /^2 masking policies are assigned through 3 active column or tag references\. Unreadable inventory: tag_references was denied/);
  assert.match(masking.summary, /classification tag coverage \(TAG_REFERENCES\) was not checked/);
  assert.deepEqual(masking.evidence.unreadable_inventories, ["tag_references"]);
  assert.equal(masking.evidence.tag_references_readable, false);

  const replicationDenied = await assessSnowflakeDataProtection(createMockClient((statement) => {
    if (normalizeStatement(statement) === "SHOW REPLICATION GROUPS") throw DENIED_403();
    return healthyFixture(statement);
  }, { role: "ACCOUNTADMIN" }));
  const shares = findingById(replicationDenied, "SNOWFLAKE-22");
  assert.equal(shares.status, "warn");
  assert.match(shares.summary, /SHOW REPLICATION GROUPS\) were not checked/);
  assert.deepEqual(shares.evidence.unreadable_inventories, ["show_replication_groups"]);

  const sessionDenied = await assessSnowflakeDataProtection(createMockClient((statement) => {
    if (isSession(normalizeStatement(statement))) throw DENIED_403();
    return healthyFixture(statement);
  }, { role: "ACCOUNTADMIN" }));
  assert.equal(findingById(sessionDenied, "SNOWFLAKE-22").status, "manual");
  assert.match(findingById(sessionDenied, "SNOWFLAKE-22").summary, /could not be verified as ACCOUNTADMIN/);
  assert.equal(findingById(sessionDenied, "SNOWFLAKE-19").status, "warn");
  assert.match(findingById(sessionDenied, "SNOWFLAKE-19").summary, /SHOW DATABASES may be scoped to a role with narrower visibility/);
  assert.equal(findingById(sessionDenied, "SNOWFLAKE-23").status, "warn");

  const unreadableAndFailing = await assessSnowflakeDataProtection(createMockClient((statement) => {
    if (normalizeStatement(statement).includes("ACCOUNT_USAGE.TAG_REFERENCES")) throw DENIED_403();
    if (normalizeStatement(statement).includes("ACCOUNT_USAGE.MASKING_POLICIES")) return resultSet(statement, ["POLICY_COUNT"], [["0"]]);
    return healthyFixture(statement);
  }, { role: "ACCOUNTADMIN" }));
  const failing = findingById(unreadableAndFailing, "SNOWFLAKE-14");
  assert.equal(failing.status, "fail");
  assert.match(failing.summary, /Unreadable inventory: tag_references \(denied\)\.$/);
});

test("edition-gated and out-of-scope controls render as manual with explicit evidence instructions", async () => {
  const result = await assessSnowflakeDataProtection(createMockClient((statement) => healthyFixture(statement)));
  for (const id of ["SNOWFLAKE-20", "SNOWFLAKE-21"]) {
    const item = findingById(result, id);
    assert.equal(item.status, "manual");
    assert.equal(item.evidence.sql_verifiable, false);
    assert.equal(item.evidence.edition_requirement, "Business Critical or higher");
    assert.match(item.summary, /Collect|Snowflake Support/);
  }
  const accessHistoryDenied = await assessSnowflakeMonitoringAndLifecycle(createMockClient((statement) => {
    if (statement.includes("ACCOUNT_USAGE.ACCESS_HISTORY")) {
      throw new SnowflakeStatementError("SQL compilation error: Object 'SNOWFLAKE.ACCOUNT_USAGE.ACCESS_HISTORY' does not exist or not authorized.", { statusCode: 422 });
    }
    return healthyFixture(statement);
  }));
  const retention = findingById(accessHistoryDenied, "SNOWFLAKE-13");
  assert.equal(retention.status, "warn");
  assert.match(retention.summary, /^Account DATA_RETENTION_TIME_IN_DAYS is 1\. Unreadable inventory: access_history_probe was denied/);
  assert.match(retention.summary, /ACCESS_HISTORY was not readable/);
  assert.match(retention.summary, /Enterprise Edition/);
  assert.match(retention.summary, /collect manually: SHOW PARAMETERS LIKE 'DATA_RETENTION_TIME_IN_DAYS'/);
  assert.deepEqual(retention.evidence.unreadable_inventories, ["access_history_probe"]);
  assert.equal(retention.evidence.access_history_readable, false);
});

test("exportSnowflakeAuditBundle writes core data, analysis, compliance reports, quick reference, and a paired zip", async () => {
  const base = createTempBase("grclanker-snowflake-export-");
  // The configured bearer token: random alphanumerics, so no 6-character window of it occurs in a legitimate fixture value (checked below once the served statements are known).
  const secretToken = "qtz36MNVgApweGXmsgkGzM";
  const config = sampleConfig({ tokenType: "OAUTH", token: secretToken, privateKeyPem: undefined, role: "ACCOUNTADMIN" });
  const client = createMockClient((statement) => healthyFixture(statement), { tokenType: "OAUTH", token: secretToken, privateKeyPem: undefined, role: "ACCOUNTADMIN" });

  const result = await exportSnowflakeAuditBundle(client, config, base);
  assertFixtureFreeOfCanaryWindows(
    `${client.executed.map((statement) => JSON.stringify(healthyFixture(statement))).join(" ")} ${JSON.stringify({ ...config, token: undefined })} ${base}`,
    [secretToken],
    "export fixture",
  );
  assert.ok(existsSync(result.outputDir));
  assert.ok(existsSync(result.zipPath));
  assert.equal(result.zipPath, join(base, `${basename(result.outputDir)}.zip`));
  assert.match(basename(result.outputDir), /^myorg-myaccount-audit-bundle$/);
  assert.equal(result.findingCount, 25);
  assert.equal(result.errorCount, 0);
  assert.ok(result.fileCount >= 40, `expected many files, saw ${result.fileCount}`);
  assert.ok(statSync(result.zipPath).size > 0);

  const expectedFiles = [
    "metadata.json",
    "QUICK_REFERENCE.md",
    join("core_data", "access_check.json"),
    join("core_data", "session_context.json"),
    join("core_data", "show_network_policies.json"),
    join("core_data", "users.json"),
    join("core_data", "show_shares.json"),
    join("analysis", "findings.json"),
    join("analysis", "network-and-authentication.json"),
    join("analysis", "network-and-authentication.md"),
    join("analysis", "access-control.json"),
    join("analysis", "monitoring-and-lifecycle.json"),
    join("analysis", "data-protection.json"),
    join("compliance", "executive_summary.md"),
    join("compliance", "unified_compliance_matrix.md"),
    join("compliance", "fedramp.md"),
    join("compliance", "cmmc.md"),
    join("compliance", "soc-2.md"),
    join("compliance", "cis.md"),
    join("compliance", "pci-dss.md"),
    join("compliance", "stig.md"),
    join("compliance", "irap.md"),
    join("compliance", "ismap.md"),
  ];
  for (const file of expectedFiles) {
    assert.ok(existsSync(join(result.outputDir, file)), `missing ${file}`);
  }
  assert.ok(!existsSync(join(result.outputDir, "_errors.log")));

  const metadata = JSON.parse(readFileSync(join(result.outputDir, "metadata.json"), "utf8"));
  assert.equal(metadata.account, "MYORG-MYACCOUNT");
  assert.equal(metadata.token_type, "OAUTH");
  assert.equal(metadata.failed_statement_count, 0);
  const findings = JSON.parse(readFileSync(join(result.outputDir, "analysis", "findings.json"), "utf8"));
  assert.equal(findings.length, 25);
  assert.deepEqual(findings.map((item) => item.id).sort(), [...ALL_CONTROL_IDS].sort());
  const rawUsers = JSON.parse(readFileSync(join(result.outputDir, "core_data", "users.json"), "utf8"));
  assert.equal(rawUsers.status, "ok");
  assert.equal(rawUsers.rows.length, 4);
  assert.ok(Array.isArray(rawUsers.columns));
  const matrix = readFileSync(join(result.outputDir, "compliance", "unified_compliance_matrix.md"), "utf8");
  assert.match(matrix, /SNOWFLAKE-01/);
  assert.match(matrix, /SC-7/);
  const fedramp = readFileSync(join(result.outputDir, "compliance", "fedramp.md"), "utf8");
  assert.match(fedramp, /# FedRAMP Mapping Report/);
  assert.match(fedramp, /IA-2\(1\)/);
  const summary = readFileSync(join(result.outputDir, "compliance", "executive_summary.md"), "utf8");
  assert.match(summary, /Manual controls: 2/);
  assert.match(summary, /SNOWFLAKE-20/);
  const quick = readFileSync(join(result.outputDir, "QUICK_REFERENCE.md"), "utf8");
  assert.match(quick, /not written because every statement completed/);

  const bundleFiles = readBundleFiles(result.outputDir);
  assert.equal(bundleFiles.size, result.fileCount);
  const zipEntries = readZipEntries(result.zipPath);
  assert.equal(zipEntries.size, bundleFiles.size);
  for (const [relativePath, content] of bundleFiles) {
    assert.equal(zipEntries.get(relativePath.split("\\").join("/")), content, `${relativePath} differs between the directory and the zip`);
  }
  assertSecretsAbsent(assert, bundleFiles, [...leakWindows([secretToken]), "BEGIN PRIVATE KEY"], "bundle directory");
  assertSecretsAbsent(assert, zipEntries, [...leakWindows([secretToken]), "BEGIN PRIVATE KEY"], "bundle zip");
});

test("exportSnowflakeAuditBundle records partial collection failures in _errors.log and never overwrites a prior bundle", async () => {
  const base = createTempBase("grclanker-snowflake-export-");
  const config = sampleConfig({ role: "ACCOUNTADMIN" });
  // Credentials echoed by the server inside an error: random alphanumerics with no 6-character window in a legitimate fixture value.
  const echoedBearer = "DhgYFGELAjr2EcbUuKPw";
  const echoedJwtPayload = "KhzF7wJzSEE4dJCZfUrv";
  const echoedJwtSignature = "wdmjdzXAQuJXUpUhBHLb";
  const echoedJwt = `eyJhbGciOiJSUzI1NiJ9.${echoedJwtPayload}.${echoedJwtSignature}`;
  const echoedKeyLine = TEST_PRIVATE_KEY_PEM.split("\n")[1];
  const resolver = (statement) => {
    if (statement === "SHOW SHARES") {
      throw new SnowflakeStatementError(`SQL access control error: Insufficient privileges to operate on account (request Authorization: Bearer ${echoedBearer}; session ${echoedJwt}; key ${TEST_PRIVATE_KEY_PEM})`, { statusCode: 422 });
    }
    return healthyFixture(statement);
  };

  const firstClient = createMockClient(resolver, { role: "ACCOUNTADMIN" });
  const first = await exportSnowflakeAuditBundle(firstClient, config, base);
  assert.ok(first.errorCount >= 1);
  assertFixtureFreeOfCanaryWindows(
    `${firstClient.executed.filter((statement) => statement !== "SHOW SHARES").map((statement) => JSON.stringify(healthyFixture(statement))).join(" ")} ${JSON.stringify({ ...config, privateKeyPem: undefined })} ${base}`,
    [echoedBearer, echoedJwtPayload, echoedJwtSignature],
    "partial export fixture",
  );
  const errorLog = readFileSync(join(first.outputDir, "_errors.log"), "utf8");
  assert.match(errorLog, /\[denied\] show_shares: /);
  assert.match(errorLog, /SHOW SHARES/);
  assert.match(errorLog, /Authorization: Bearer \[REDACTED\]; session \[REDACTED\]; key \[REDACTED\]/);
  const findings = JSON.parse(readFileSync(join(first.outputDir, "analysis", "findings.json"), "utf8"));
  const shares = findings.find((item) => item.id === "SNOWFLAKE-22");
  assert.equal(shares.status, "manual");
  assert.match(shares.summary, /was denied/);
  const metadata = JSON.parse(readFileSync(join(first.outputDir, "metadata.json"), "utf8"));
  assert.ok(metadata.failed_statement_count >= 1);
  assert.match(readFileSync(join(first.outputDir, "QUICK_REFERENCE.md"), "utf8"), /_errors\.log`: statements that were denied/);
  const echoedSecrets = [...leakWindows([echoedBearer, echoedJwtPayload, echoedJwtSignature, echoedKeyLine]), "BEGIN PRIVATE KEY"];
  assertSecretsAbsent(assert, readBundleFiles(first.outputDir), echoedSecrets, "partial bundle directory");
  assertSecretsAbsent(assert, readZipEntries(first.zipPath), echoedSecrets, "partial bundle zip");

  const firstMetadata = readFileSync(join(first.outputDir, "metadata.json"), "utf8");
  const second = await exportSnowflakeAuditBundle(createMockClient(resolver, { role: "ACCOUNTADMIN" }), config, base);
  assert.notEqual(second.outputDir, first.outputDir);
  assert.notEqual(second.zipPath, first.zipPath);
  assert.equal(basename(second.outputDir), `${basename(first.outputDir)}-2`);
  assert.equal(second.zipPath, join(base, `${basename(second.outputDir)}.zip`));
  assert.ok(existsSync(first.outputDir));
  assert.ok(existsSync(first.zipPath));
  assert.ok(existsSync(second.outputDir));
  assert.ok(existsSync(second.zipPath));
  assert.equal(readFileSync(join(first.outputDir, "metadata.json"), "utf8"), firstMetadata);
});

/** Canaries planted in the error bodies a failing statement returns: random alphanumerics with no 6-character window in the vendor message, the HTML wrapper, or a legitimate fixture value. */
const STATEMENT_CANARIES = { bearer: "Y4W6x9CRzU39NUKa3B", session: "2bBAwKGbUByG8qYPCq", apiKey: "RHW9enMyb9c69WJ9nP", urlToken: "XyJZddzExJmchaeS8g" };
const STATEMENT_HTML_BODY = `<html><body><h1>502 Bad Gateway</h1><p>Authorization: Bearer ${STATEMENT_CANARIES.bearer}</p><p>Set-Cookie: JSESSIONID=${STATEMENT_CANARIES.session}; Path=/</p><p>api_key=${STATEMENT_CANARIES.apiKey}</p><p>Retry at https://api.example.com/v1/x?token=${STATEMENT_CANARIES.urlToken} later.</p></body></html>`;
const STATEMENT_JSON_BODY = {
  code: "390144",
  message: `Denied while fetching https://api.example.com/v1/x?token=${STATEMENT_CANARIES.urlToken} for this key; Authorization: Bearer ${STATEMENT_CANARIES.bearer}; api_key=${STATEMENT_CANARIES.apiKey}; session_id=${STATEMENT_CANARIES.session}`,
  sqlState: "08004",
};

/** Serves healthyFixture result sets through the SQL API wire shape so the real client, error constructor, and record point are exercised. */
function sqlApiFetch(failing = { statement: undefined, variant: "html" }, executed = []) {
  return async (_url, init) => {
    const statement = JSON.parse(init.body).statement;
    executed.push(statement);
    if (failing.statement !== undefined && normalizeStatement(statement) === normalizeStatement(failing.statement)) {
      return failing.variant === "html"
        ? new Response(STATEMENT_HTML_BODY, { status: 502, statusText: "Bad Gateway", headers: { "content-type": "text/html; charset=utf-8" } })
        : jsonResponse(STATEMENT_JSON_BODY, { status: 403, statusText: "Forbidden" });
    }
    const result = healthyFixture(statement);
    return jsonResponse({
      statementHandle: `handle-${executed.length}`,
      resultSetMetaData: { numRows: result.rows.length, rowType: result.columns.map((name) => ({ name, type: "text" })), partitionInfo: [{ rowCount: result.rows.length }] },
      data: result.rows.map((row) => result.columns.map((column) => row[column])),
    });
  };
}

test("rule 9: every Snowflake statement that fails with a 502 HTML page or a JSON error embedding a token URL records only a scrubbed error, on every output", async () => {
  const base = createTempBase("grclanker-snowflake-statement-canaries-");
  const config = sampleConfig({ maxRetries: 0 });

  const executed = [];
  const discovery = new SnowflakeSqlClient(config, { fetchImpl: sqlApiFetch(undefined, executed) });
  const healthyAccess = await checkSnowflakeAccess(discovery);
  assert.equal(healthyAccess.status, "healthy");
  await runAllAssessments(discovery);
  const statements = [...new Map(executed.map((statement) => [normalizeStatement(statement), statement])).values()];
  assert.ok(statements.length >= 30, `every access check probe and assessment statement is discovered (${statements.length})`);
  // Self-check: the healthy result sets, the error bodies around the canaries, the config, and the output path share no 6-character window with a planted canary.
  assertFixtureFreeOfCanaryWindows(
    `${statements.map((statement) => JSON.stringify(healthyFixture(statement))).join(" ")} ${STATEMENT_HTML_BODY} ${JSON.stringify(STATEMENT_JSON_BODY)} ${JSON.stringify({ ...config, privateKeyPem: undefined })} ${base}`,
    Object.values(STATEMENT_CANARIES),
    "statement canaries",
  );

  for (const [index, statement] of statements.entries()) {
    for (const variant of ["html", "json"]) {
      const label = `${normalizeStatement(statement).slice(0, 60)} (${variant})`;
      const fetchImpl = sqlApiFetch({ statement, variant });
      const access = await checkSnowflakeAccess(new SnowflakeSqlClient(config, { fetchImpl }));
      const results = await runAllAssessments(new SnowflakeSqlClient(config, { fetchImpl }));
      const iterationBase = join(base, `${index}-${variant}`);
      mkdirSync(iterationBase);
      const exported = await exportSnowflakeAuditBundle(new SnowflakeSqlClient(config, { fetchImpl }), config, iterationBase);
      const files = readBundleFiles(exported.outputDir);

      const outputs = new Map([
        [`${label} check_access`, JSON.stringify(access)],
        ...results.map((result) => [`${label} assess ${result.area}`, JSON.stringify(result)]),
        ...[...files].map(([name, content]) => [`${label} bundle ${name}`, content]),
        ...[...readZipEntries(exported.zipPath)].map(([name, content]) => [`${label} zip ${name}`, content]),
      ]);
      assertNoLeakWindows(outputs, Object.values(STATEMENT_CANARIES), label);

      const failedOutcomes = results.flatMap((result) => result.statements.filter((outcome) => outcome.status !== "ok"));
      const errorStrings = [
        ...access.surfaces.filter((surface) => surface.status !== "readable").map((surface) => surface.error),
        ...failedOutcomes.map((outcome) => outcome.error),
      ];
      assert.ok(errorStrings.length >= 1, `${label}: the failing statement is recorded as an error`);
      for (const text of errorStrings) {
        if (variant === "html") {
          assert.match(text, /failed \(502 Bad Gateway\): non-JSON body \(text\/html, \d+ bytes\)$/, `${label}: the error carries the status-and-length note, got ${text}`);
        } else {
          assert.match(text, /https:\/\/api\.example\.com\/v1\/x\?\[REDACTED\] for this key/, `${label}: the URL keeps scheme, host, and path and its query collapses to a marker, got ${text}`);
          assert.match(text, /Authorization: Bearer \[REDACTED\]/, `${label}: the authorization scheme stays and its value is redacted, got ${text}`);
        }
      }
      for (const outcome of failedOutcomes) {
        assert.equal(outcome.numRows, null, `${label}: an unread statement has no row count`);
        assert.equal(outcome.truncated, null, `${label}: an unread statement has no truncation flag`);
      }
    }
  }
});

/** A mock client that also records the outcome of every statement it served. */
function recordingClient(resolver, configOverrides = {}) {
  const log = [];
  const client = createMockClient(async (statement) => {
    const normalized = normalizeStatement(statement);
    try {
      const result = await resolver(statement);
      log.push({ statement: normalized, status: "ok", rows: result.rows.length });
      return result;
    } catch (error) {
      log.push({ statement: normalized, status: error instanceof SnowflakeStatementError ? error.kind : "error", error: error.message });
      throw error;
    }
  }, configOverrides);
  return { client, log };
}

/** The leading run of SQL keyword tokens after each SHOW in prose, so "SHOW WAREHOUSES returned zero" yields "SHOW WAREHOUSES". */
function mentionedShowStatements(text) {
  const mentions = [];
  for (const match of text.matchAll(/\bSHOW\b[^\n]*/g)) {
    const kept = [];
    for (const token of match[0].split(/\s+/)) {
      const clean = token.replace(/[.,;:)\]"\\]+$/, "");
      if (!/^[A-Z_%$*'()]+$/.test(clean)) break;
      kept.push(clean);
      if (clean !== token) break;
    }
    if (kept.length > 1) mentions.push(kept.join(" "));
  }
  return mentions;
}

function* statementBearingObjects(value) {
  if (Array.isArray(value)) {
    for (const item of value) yield* statementBearingObjects(item);
  } else if (value && typeof value === "object") {
    if (typeof value.statement === "string" && typeof value.status === "string") yield value;
    for (const item of Object.values(value)) yield* statementBearingObjects(item);
  }
}

/**
 * Every statement named with an outcome anywhere in the outputs (core_data
 * files, access surfaces, statement snapshots, not-collected markers) must be
 * one the client executed with that outcome, and every SHOW command named in
 * prose must be one the run executed.
 */
function assertOutputsNameOnlyExecutedStatements(outputs, log, label) {
  const executed = new Map();
  for (const entry of log) executed.set(entry.statement, entry.status);
  for (const [name, text] of outputs) {
    let parsed;
    try {
      parsed = JSON.parse(text);
    } catch {
      parsed = undefined;
    }
    if (parsed !== undefined) {
      for (const object of statementBearingObjects(parsed)) {
        const status = executed.get(normalizeStatement(object.statement));
        assert.ok(status !== undefined, `${label} ${name}: names a statement the run never executed: ${object.statement}`);
        const claimsOk = object.status === "ok" || object.status === "readable";
        assert.equal(claimsOk, status === "ok", `${label} ${name}: claims ${object.status} for a statement the run observed as ${status}: ${object.statement}`);
        if (!claimsOk) assert.equal(object.status, status, `${label} ${name}: claims ${object.status} but the run observed ${status}`);
      }
    }
    for (const mention of mentionedShowStatements(text)) {
      assert.ok([...executed.keys()].some((statement) => statement.startsWith(mention)), `${label} ${name}: names ${mention} but the run executed no such statement`);
    }
  }
}

function snowflakeOutputs(access, results, exported) {
  return new Map([
    ["check_access", JSON.stringify(access)],
    ...results.map((result) => [`assess ${result.area}`, JSON.stringify(result)]),
    ...[...readBundleFiles(exported.outputDir)].map(([name, content]) => [`bundle ${name}`, content]),
  ]);
}

const SNOWFLAKE_DENIABLE_STATEMENTS = [
  ["show_network_policies", "show_network_policies", (s) => s === "SHOW NETWORK POLICIES"],
  ["show_warehouses", "show_warehouses", (s) => s === "SHOW WAREHOUSES"],
  ["show_databases", "show_databases", (s) => s === "SHOW DATABASES"],
  ["show_shares", "show_shares", (s) => s === "SHOW SHARES"],
  ["show_replication_groups", "show_replication_groups", (s) => s === "SHOW REPLICATION GROUPS"],
  ["tag_references", "account_usage_tag_references", (s) => s.includes("ACCOUNT_USAGE.TAG_REFERENCES")],
  ["users", "account_usage_users", (s) => s.includes("ACCOUNT_USAGE.USERS")],
];

test("collection status: a denied statement is written to core_data and the assess payload with a not-collected marker in place of its rows and null counts, a readable empty result stays [], and every statement named in any output was executed", async () => {
  const base = createTempBase("grclanker-snowflake-denied-markers-");
  const config = sampleConfig({ role: "ACCOUNTADMIN" });

  for (const [key, surfaceName, matches] of SNOWFLAKE_DENIABLE_STATEMENTS) {
    const { client, log } = recordingClient((statement) => {
      if (matches(normalizeStatement(statement))) throw DENIED_403();
      return healthyFixture(statement);
    }, { role: "ACCOUNTADMIN" });
    const access = await checkSnowflakeAccess(client);
    const results = await runAllAssessments(client);
    const exported = await exportSnowflakeAuditBundle(client, config, join(base, key));

    const file = JSON.parse(readFileSync(join(exported.outputDir, "core_data", `${key}.json`), "utf8"));
    assert.equal(file.status, "denied", `${key}: recorded as denied`);
    assert.equal(file.columns, null, `${key}: columns are null, not [], when the statement did not complete`);
    assert.ok(!Array.isArray(file.rows), `${key}: rows are never an array for a statement that did not complete`);
    assert.deepEqual(file.rows, { collected: false, status: "denied", statement: file.statement, error: file.error });
    assert.match(file.rows.error, /HTTP 403 Forbidden/);
    for (const counter of ["numRows", "partitionCount", "fetchedPartitions", "truncated"]) {
      assert.equal(file[counter], null, `${key}: ${counter} is null when the statement did not complete`);
    }

    const echoed = results.flatMap((result) => result.statements).find((statement) => statement.key === key);
    assert.deepEqual(echoed.rows, file.rows, `${key}: the assess payload carries the same marker`);
    assert.equal(echoed.columns, null);

    const surface = access.surfaces.find((item) => item.name === surfaceName);
    assert.equal(surface.status, "denied");
    assert.equal(surface.rowCount, null, `${key}: access check rowCount is null when the probe did not complete`);

    assertOutputsNameOnlyExecutedStatements(snowflakeOutputs(access, results, exported), log, `${key} denied`);
  }

  const { client, log } = recordingClient((statement) => (normalizeStatement(statement) === "SHOW SHARES" ? emptyFixture(statement) : healthyFixture(statement)), { role: "ACCOUNTADMIN" });
  const access = await checkSnowflakeAccess(client);
  const results = await runAllAssessments(client);
  const exported = await exportSnowflakeAuditBundle(client, config, join(base, "empty"));
  const shares = JSON.parse(readFileSync(join(exported.outputDir, "core_data", "show_shares.json"), "utf8"));
  assert.equal(shares.status, "ok");
  assert.deepEqual(shares.rows, [], "a readable empty result set stays []");
  assert.ok(Array.isArray(shares.columns));
  assert.equal(shares.numRows, 0);
  assert.equal(shares.truncated, false);
  assert.equal(access.surfaces.find((item) => item.name === "show_shares").rowCount, 0);
  for (const surface of access.surfaces) assert.equal(typeof surface.rowCount, "number", `${surface.name}: readable surfaces carry a numeric rowCount`);
  assertOutputsNameOnlyExecutedStatements(snowflakeOutputs(access, results, exported), log, "healthy with an empty SHOW SHARES");
});

/** Every output of a run that sent no request, keyed by surface, with the tool payload text added by the caller. */
function assertNoRequestClaims(outputs, label) {
  for (const [name, text] of outputs) {
    assert.ok(!text.includes("/api/v2/statements"), `${label}: ${name} names the statements endpoint although no request was made`);
    assert.ok(!text.includes("Authenticated as"), `${label}: ${name} claims authentication although no request was made`);
    assert.ok(!/SQL API request (failed|timed out)/.test(text), `${label}: ${name} reports a request failure although no request was made`);
    assert.ok(!text.includes("lacks MANAGE GRANTS"), `${label}: ${name} judges the configured role's visibility although no statement ran under it`);
  }
}

test("addendum 5.2: a private key that does not load sends no request, so no output names POST /api/v2/statements or a statement text, and the run reports itself as not authenticated with the key failure code", async () => {
  const base = createTempBase("grclanker-snowflake-not-requested-");
  // Passphrases and key bodies are planted credentials: random alphanumerics, so no 6-character window of one occurs in the remediation text or another fixture value.
  const { right: rightPassphrase, wrong: wrongPassphrase } = LIVE_RESOLVER_PASSPHRASES;
  const encryptedPem = testPrivateKey.export({ type: "pkcs8", format: "pem", cipher: "aes-256-cbc", passphrase: rightPassphrase });
  const variants = [
    { name: "malformed PEM body", overrides: { privateKeyPem: "-----BEGIN PRIVATE KEY-----\nbm90LWEta2V5LWp1c3QtYnl0ZXM=\n-----END PRIVATE KEY-----\n" }, keyMaterial: ["bm90LWEta2V5LWp1c3QtYnl0ZXM="] },
    { name: "encrypted key with the wrong passphrase", overrides: { privateKeyPem: encryptedPem, privateKeyPassphrase: wrongPassphrase }, keyMaterial: [encryptedPem.split("\n")[1], wrongPassphrase, rightPassphrase] },
  ];
  assertFixtureFreeOfCanaryWindows(`${JSON.stringify(sampleConfig({ privateKeyPem: undefined }))} ${base}`, [wrongPassphrase, rightPassphrase], "key failure canaries");
  const registered = [];
  registerSnowflakeTools({ registerTool: (tool) => registered.push(tool) });
  const checkAccessTool = registered.find((tool) => tool.name === "snowflake_check_access");

  for (const variant of variants) {
    const label = variant.name;
    const config = sampleConfig(variant.overrides);
    let fetchCalls = 0;
    const client = new SnowflakeSqlClient(config, {
      fetchImpl: async () => {
        fetchCalls += 1;
        throw new Error("the fixture must never be reached");
      },
    });

    const access = await checkSnowflakeAccess(client);
    assert.equal(fetchCalls, 0, `${label}: the access check sent no request`);
    assert.equal(access.status, "limited");
    assert.equal(access.authentication, "not_authenticated", label);
    assert.equal(access.user, null, `${label}: no user is claimed`);
    assert.equal(access.role, undefined, `${label}: the configured role is not reported as active`);
    assert.equal(access.fullVisibility, false);
    assert.match(access.authenticationNote, /^Not authenticated: the Snowflake private key could not be loaded \((ERR_[A-Z0-9_]+|INVALID_PRIVATE_KEY)\); no request was sent\.$/, label);
    assert.ok(access.notes.includes(access.authenticationNote), `${label}: the notes carry the authentication statement`);
    assert.ok(access.notes.every((note) => !note.startsWith("Authenticated as")), label);
    assert.ok(access.surfaces.length > 10, label);
    const code = access.authenticationNote.match(/\((ERR_[A-Z0-9_]+|INVALID_PRIVATE_KEY)\)/)[1];
    for (const surface of access.surfaces) {
      assert.equal(surface.status, "not_requested", `${label}: ${surface.name}`);
      assert.equal(surface.statement, null, `${label}: ${surface.name} names no statement`);
      assert.equal(surface.rowCount, null, label);
      assert.equal(surface.error, `Not requested: the Snowflake private key could not be loaded (${code}); no statement was sent. Provide a PKCS#8 PEM key and, for an encrypted key, its passphrase.`, label);
    }

    const assessment = await assessSnowflakeNetworkAndAuthentication(client);
    assert.equal(fetchCalls, 0, `${label}: the assessment sent no request`);
    assert.equal(assessment.summary.role, null, `${label}: the configured role is not reported as active`);
    assert.equal(assessment.summary.users_seen, null);
    for (const finding of assessment.findings) {
      assert.equal(finding.status, "manual", `${label}: ${finding.id}`);
      assert.match(finding.summary, /^Unknown: .*Not requested: the Snowflake private key could not be loaded \(/, `${label}: ${finding.id}`);
    }
    for (const statement of assessment.statements) {
      assert.equal(statement.status, "not_requested", `${label}: ${statement.key}`);
      assert.equal(statement.statement, null, `${label}: ${statement.key} names no statement text`);
      assert.equal(statement.code, code, `${label}: ${statement.key} carries the key failure code`);
      assert.deepEqual(statement.rows, { collected: false, status: "not_requested", statement: null, error: statement.error }, `${label}: ${statement.key}`);
      assert.equal(statement.columns, null);
    }

    const exported = await exportSnowflakeAuditBundle(client, config, join(base, label.replace(/\W+/g, "-")));
    assert.equal(fetchCalls, 0, `${label}: the export sent no request`);
    const files = readBundleFiles(exported.outputDir);
    const outputs = new Map([
      ["check_access", JSON.stringify(access)],
      ["assess network-and-authentication", JSON.stringify(assessment)],
      ...[...files].map(([name, content]) => [`bundle ${name}`, content]),
      ...[...readZipEntries(exported.zipPath)].map(([name, content]) => [`zip ${name}`, content]),
    ]);
    assertNoRequestClaims(outputs, label);
    assertNoLeakWindows(outputs, variant.keyMaterial, `${label}: key material`);
    assertSecretsAbsent(assert, outputs, ["BEGIN PRIVATE KEY", "BEGIN ENCRYPTED PRIVATE KEY"], `${label}: PEM markers`);

    const metadata = JSON.parse(files.get("metadata.json"));
    assert.equal(metadata.user, null, label);
    assert.equal(metadata.role, null, label);
    assert.equal(metadata.authentication, "not_authenticated", label);
    assert.equal(metadata.requested_statement_count, 0, `${label}: metadata counts the requests actually made`);
    assert.equal(metadata.not_requested_statement_count, metadata.statement_count, label);
    assert.equal(metadata.failed_statement_count, metadata.statement_count, label);
    const errorLines = files.get("_errors.log").trimEnd().split("\n");
    assert.equal(errorLines.length, metadata.statement_count, `${label}: one line per statement and no statement text lines`);
    for (const line of errorLines) assert.match(line, /^\[not_requested\] [a-z_0-9]+: Not requested: the Snowflake private key could not be loaded \(/, label);
    const accessFile = JSON.parse(files.get("core_data/access_check.json"));
    assert.equal(accessFile.authentication, "not_authenticated", label);
    assert.ok(accessFile.notes.includes(access.authenticationNote), label);
    const summary = files.get("compliance/executive_summary.md");
    assert.ok(summary.includes(`Authentication: ${access.authenticationNote}`), `${label}: the executive summary states the failure instead of an identity`);
    assert.ok(!summary.includes("partial visibility"), label);
    for (const [name, content] of files) {
      if (!name.startsWith("core_data/") || name === "core_data/access_check.json") continue;
      const snapshot = JSON.parse(content);
      assert.equal(snapshot.statement, null, `${label}: ${name} names no statement`);
      assert.equal(snapshot.rows.statement, null, `${label}: ${name} marker names no statement`);
    }

    // The tool boundary: the payload of snowflake_check_access built from the same key through the resolver.
    const realFetch = globalThis.fetch;
    globalThis.fetch = async () => {
      fetchCalls += 1;
      throw new Error("the network must never be reached");
    };
    try {
      const payload = await withSnowflakeHome(base, () => checkAccessTool.execute("call", checkAccessTool.prepareArguments({
        account: "myorg-myaccount",
        user: "auditor",
        role: "AUDIT_ROLE",
        private_key: config.privateKeyPem,
        ...(config.privateKeyPassphrase ? { private_key_passphrase: config.privateKeyPassphrase } : {}),
      })));
      assert.equal(fetchCalls, 0, `${label}: the tool sent no request`);
      assertNoRequestClaims(new Map([["snowflake_check_access payload", JSON.stringify(payload)]]), label);
      for (const material of variant.keyMaterial) assertNoWindowOf(JSON.stringify(payload), material, `${label}: snowflake_check_access payload`);
      assert.ok(JSON.stringify(payload).includes(`Not authenticated: the Snowflake private key could not be loaded (${code}); no request was sent.`), `${label}: the tool payload states the failure`);
    } finally {
      globalThis.fetch = realFetch;
    }
  }
});

test("resolveSecureOutputPath rejects traversal and symlink parents", () => {
  const base = createTempBase("grclanker-snowflake-path-");
  const outside = createTempBase("grclanker-snowflake-outside-");
  const linked = join(base, "linked");
  symlinkSync(outside, linked, "dir");

  assert.throws(() => resolveSecureOutputPath(base, "../escape"), /Refusing to write outside/);
  assert.throws(() => resolveSecureOutputPath(base, join("..", basename(outside), "file.txt")), /Refusing to write outside/);
  assert.throws(() => resolveSecureOutputPath(base, "linked/file.txt"), /symlinked parent directory/);

  const safe = resolveSecureOutputPath(base, join("analysis", "safe.txt"));
  assert.match(safe, /analysis\/safe\.txt$/);
});

test("Snowflake tools are registered in the tool catalog under the Snowflake group", () => {
  const tools = getRegisteredToolSummaries();
  const expected = [
    "snowflake_check_access",
    "snowflake_assess_network_and_authentication",
    "snowflake_assess_access_control",
    "snowflake_assess_monitoring_and_lifecycle",
    "snowflake_assess_data_protection",
    "snowflake_export_audit_bundle",
  ];
  for (const name of expected) {
    const tool = tools.find((candidate) => candidate.name === name);
    assert.ok(tool, `missing tool ${name}`);
    assert.equal(tool.group, "Snowflake");
    assert.ok(tool.description.length > 40, `${name} needs a descriptive description`);
  }
  assert.equal(tools.filter((tool) => tool.name.startsWith("snowflake_")).length, expected.length);
});
