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

/** Canaries planted on malformed config lines; every 8-character window of each is distinct so a partial quote is caught too. */
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

function fragmentsOf(value, size = 8) {
  const fragments = [];
  for (let index = 0; index + size <= value.length; index += 1) fragments.push(value.slice(index, index + size));
  return fragments;
}

function assertConfigErrorText(text, { path, code, line, canaries }, label) {
  for (const canary of canaries) {
    for (const fragment of fragmentsOf(canary)) assert.ok(!text.includes(fragment), `${label} carries a fragment (${fragment}) of ${canary}: ${text}`);
  }
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
  assert.ok(!redacted.includes(jwt));
  assert.ok(!redacted.includes("abcdefghijkl"));
  assert.ok(!redacted.includes("topsecret"));
  assert.ok(redacted.includes("[REDACTED PRIVATE KEY]"));
  assert.ok(redacted.includes("[REDACTED TOKEN]"));
  assert.ok(redacted.includes("[REDACTED]"));
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

  const secretToken = "super-secret-oauth-token-value";
  const leaky = new SnowflakeSqlClient(sampleConfig({ tokenType: "OAUTH", token: secretToken, privateKeyPem: undefined, maxRetries: 0 }), {
    fetchImpl: async (_url, init) => {
      assert.equal(headerValue(init.headers, "x-snowflake-authorization-token-type"), "OAUTH");
      assert.equal(headerValue(init.headers, "authorization"), `Bearer ${secretToken}`);
      throw new Error(`socket hang up while sending Bearer ${secretToken}`);
    },
  });
  await assert.rejects(leaky.execute("SELECT 1"), (error) => {
    assert.ok(!error.message.includes(secretToken));
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
  const secretToken = "bundle-secret-token-value-123456";
  const config = sampleConfig({ tokenType: "OAUTH", token: secretToken, privateKeyPem: undefined, role: "ACCOUNTADMIN" });
  const client = createMockClient((statement) => healthyFixture(statement), { tokenType: "OAUTH", token: secretToken, privateKeyPem: undefined, role: "ACCOUNTADMIN" });

  const result = await exportSnowflakeAuditBundle(client, config, base);
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
  assertSecretsAbsent(assert, bundleFiles, [secretToken, "BEGIN PRIVATE KEY"], "bundle directory");
  assertSecretsAbsent(assert, zipEntries, [secretToken, "BEGIN PRIVATE KEY"], "bundle zip");
});

test("exportSnowflakeAuditBundle records partial collection failures in _errors.log and never overwrites a prior bundle", async () => {
  const base = createTempBase("grclanker-snowflake-export-");
  const config = sampleConfig({ role: "ACCOUNTADMIN" });
  const echoedBearer = "echoed-bearer-token-value-7890abcdef";
  const echoedJwt = "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJlY2hvZWQtand0In0.c2lnbmF0dXJlLWVjaG9lZC1qd3Q";
  const resolver = (statement) => {
    if (statement === "SHOW SHARES") {
      throw new SnowflakeStatementError(`SQL access control error: Insufficient privileges to operate on account (request Authorization: Bearer ${echoedBearer}; session ${echoedJwt}; key ${TEST_PRIVATE_KEY_PEM})`, { statusCode: 422 });
    }
    return healthyFixture(statement);
  };

  const first = await exportSnowflakeAuditBundle(createMockClient(resolver, { role: "ACCOUNTADMIN" }), config, base);
  assert.ok(first.errorCount >= 1);
  const errorLog = readFileSync(join(first.outputDir, "_errors.log"), "utf8");
  assert.match(errorLog, /\[denied\] show_shares: /);
  assert.match(errorLog, /SHOW SHARES/);
  assert.match(errorLog, /Authorization: \[REDACTED\] \[REDACTED TOKEN\]; session \[REDACTED TOKEN\]; key \[REDACTED PRIVATE KEY\]/);
  const findings = JSON.parse(readFileSync(join(first.outputDir, "analysis", "findings.json"), "utf8"));
  const shares = findings.find((item) => item.id === "SNOWFLAKE-22");
  assert.equal(shares.status, "manual");
  assert.match(shares.summary, /was denied/);
  const metadata = JSON.parse(readFileSync(join(first.outputDir, "metadata.json"), "utf8"));
  assert.ok(metadata.failed_statement_count >= 1);
  assert.match(readFileSync(join(first.outputDir, "QUICK_REFERENCE.md"), "utf8"), /_errors\.log`: statements that were denied/);
  const echoedSecrets = [echoedBearer, echoedJwt, "BEGIN PRIVATE KEY"];
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

const STATEMENT_CANARIES = ["CANARY_BEARER_S1", "CANARY_SESSION_S1", "CANARY_APIKEY_S1", "CANARY_URL_TOKEN_S1"];
const STATEMENT_HTML_BODY = "<html><body><h1>502 Bad Gateway</h1><p>Authorization: Bearer CANARY_BEARER_S1</p><p>Set-Cookie: JSESSIONID=CANARY_SESSION_S1; Path=/</p><p>api_key=CANARY_APIKEY_S1</p><p>Retry at https://api.example.com/v1/x?token=CANARY_URL_TOKEN_S1 later.</p></body></html>";
const STATEMENT_JSON_BODY = {
  code: "390144",
  message: "Denied while fetching https://api.example.com/v1/x?token=CANARY_URL_TOKEN_S1 for this key; Authorization: Bearer CANARY_BEARER_S1; api_key=CANARY_APIKEY_S1; session_id=CANARY_SESSION_S1",
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
      assertSecretsAbsent(assert, outputs, STATEMENT_CANARIES, label);

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
          assert.match(text, /https:\/\/api\.example\.com\/v1\/x(?![?#])/, `${label}: the URL keeps scheme, host, and path, got ${text}`);
          assert.match(text, /Authorization: \[REDACTED\]/, `${label}: the authorization value is redacted, got ${text}`);
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
