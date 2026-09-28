export interface ResolverAuthenticationContract {
  modes: readonly string[];
  precedence: readonly string[];
  environment: readonly string[];
  configLocations: readonly string[];
  variants: readonly string[];
  configFields: readonly string[];
  refreshRequest?: string;
}

export function readResolverEnvironment(
  contract: ResolverAuthenticationContract,
  environment: NodeJS.ProcessEnv,
): NodeJS.ProcessEnv {
  return Object.fromEntries(contract.environment.map((name) => [name, environment[name]]));
}

export const OKTA_AUTH_RESOLVER = {
  modes: ["SSWS API token", "OAuth service application private-key JWT", "Prebuilt OAuth client assertion"],
  precedence: ["Explicit tool arguments", "OKTA_CLIENT_* environment variables", "Project .okta.yaml", "Home ~/.okta/okta.yaml"],
  environment: [
    "OKTA_CLIENT_ORGURL",
    "OKTA_CLIENT_AUTHORIZATIONMODE",
    "OKTA_CLIENT_TOKEN",
    "OKTA_CLIENT_CLIENTID",
    "OKTA_CLIENT_PRIVATEKEY",
    "OKTA_CLIENT_PRIVATEKEYID",
    "OKTA_CLIENT_CLIENTASSERTION",
    "OKTA_CLIENT_SCOPES",
  ],
  configLocations: [".okta.yaml", "~/.okta/okta.yaml"],
  variants: ["Commercial, preview, and custom Okta organization origins"],
  configFields: ["orgUrl", "authorizationMode", "token", "clientId", "privateKey", "privateKeyId", "clientAssertion", "scopes"],
  refreshRequest: "POST /oauth2/v1/token with the client_credentials grant and a private_key_jwt assertion.",
} as const satisfies ResolverAuthenticationContract;

export const DUO_AUTH_RESOLVER = {
  modes: ["Duo Admin API HMAC integration key and secret key"],
  precedence: ["Explicit tool arguments", "DUO_* environment variables"],
  environment: ["DUO_API_HOST", "DUO_IKEY", "DUO_SKEY", "DUO_LOOKBACK_DAYS"],
  configLocations: [],
  variants: ["Commercial and FedRAMP Duo API hostnames selected by api_host"],
  configFields: [],
} as const satisfies ResolverAuthenticationContract;

export const GWS_AUTH_RESOLVER = {
  modes: ["Service-account JWT assertion with domain-wide delegation", "Explicit OAuth access token"],
  precedence: ["Explicit tool arguments", "GWS_* and GOOGLE_APPLICATION_CREDENTIALS environment variables"],
  environment: [
    "GWS_AUTH_MODE",
    "GWS_CREDENTIALS_FILE",
    "GWS_SERVICE_ACCOUNT_FILE",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "GWS_CREDENTIALS_JSON",
    "GWS_SERVICE_ACCOUNT_JSON",
    "GWS_ACCESS_TOKEN",
    "GWS_ADMIN_EMAIL",
    "GWS_DOMAIN",
    "GWS_CUSTOMER_ID",
    "GWS_LOOKBACK_DAYS",
  ],
  configLocations: ["Service-account credential JSON supplied explicitly by credentials_file"],
  variants: ["my_customer alias or explicit customer ID", "Delegated administrator subject for service-account authentication"],
  configFields: ["client_email", "private_key", "token_uri"],
  refreshRequest: "POST https://oauth2.googleapis.com/token with a signed JWT bearer grant and delegated administrator subject.",
} as const satisfies ResolverAuthenticationContract;

export const BOX_AUTH_RESOLVER = {
  modes: ["JWT server authentication", "Client Credentials Grant", "OAuth refresh token", "Explicit access token"],
  precedence: ["Explicit tool arguments", "BOX_* environment variables", "Explicit or default inspector YAML config"],
  environment: [
    "BOX_AUTH_METHOD",
    "BOX_JWT_CONFIG_PATH",
    "BOX_JWT_PASSPHRASE",
    "BOX_JWT_ALGORITHM",
    "BOX_CLIENT_ID",
    "BOX_CLIENT_SECRET",
    "BOX_ENTERPRISE_ID",
    "BOX_SUBJECT_TYPE",
    "BOX_SUBJECT_ID",
    "BOX_ACCESS_TOKEN",
    "BOX_TOKEN",
    "BOX_DEVELOPER_TOKEN",
    "BOX_REFRESH_TOKEN",
    "BOX_API_BASE_URL",
    "BOX_BASE_URL",
    "BOX_TOKEN_URL",
    "BOX_TIMEOUT",
    "BOX_MAX_RETRIES",
    "BOX_CONFIG_PATH",
  ],
  configLocations: ["Explicit path from config_path or BOX_CONFIG_PATH", "~/.box-sec-inspector/config.yaml"],
  variants: ["Enterprise or user subject", "JWT RS256, RS384, or RS512 assertion"],
  configFields: [
    "auth_method", "authMethod", "auth_mode", "jwt_config_path", "jwt_config", "jwtConfigPath",
    "jwt_passphrase", "passphrase", "jwt_algorithm", "jwtAlgorithm", "client_id", "clientId", "clientID",
    "client_secret", "clientSecret", "enterprise_id", "enterpriseId", "enterpriseID", "subject_type",
    "subjectType", "subject_id", "subjectId", "user_id", "access_token", "accessToken", "token",
    "developer_token", "refresh_token", "refreshToken", "base_url", "baseUrl", "api_base_url", "token_url",
    "tokenUrl", "timeout_seconds", "timeout", "max_retries", "maxRetries",
  ],
  refreshRequest: "POST https://api.box.com/oauth2/token using the selected JWT, client_credentials, or refresh_token grant.",
} as const satisfies ResolverAuthenticationContract;

export const SLACK_AUTH_RESOLVER = {
  modes: ["User OAuth token", "Bot OAuth token", "SCIM bearer token"],
  precedence: ["Explicit tool arguments", "SLACK_* environment variables", "Slack JSON config file"],
  environment: [
    "SLACK_CONFIG_FILE",
    "SLACK_USER_TOKEN",
    "SLACK_TOKEN",
    "SLACK_BOT_TOKEN",
    "SLACK_SCIM_TOKEN",
    "SLACK_ORG_ID",
    "SLACK_ENTERPRISE_ID",
    "SLACK_WEB_API_BASE_URL",
    "SLACK_SCIM_BASE_URL",
    "SLACK_AUDIT_BASE_URL",
    "SLACK_TIMEOUT",
  ],
  configLocations: ["~/.config/grclanker/slack.json", "Explicit path from SLACK_CONFIG_FILE"],
  variants: ["Enterprise Grid org token plus optional bot and SCIM credentials"],
  configFields: ["user_token", "token", "bot_token", "scim_token", "org_id"],
} as const satisfies ResolverAuthenticationContract;

export const ZOOM_AUTH_RESOLVER = {
  modes: ["Server-to-Server OAuth client credentials", "Explicit OAuth access token"],
  precedence: ["Explicit tool arguments", "ZOOM_* environment variables", "Discovered Zoom JSON config file"],
  environment: [
    "ZOOM_CONFIG_FILE",
    "ZOOM_ACCOUNT_ID",
    "ZOOM_TOKEN",
    "ZOOM_ACCESS_TOKEN",
    "ZOOM_CLIENT_ID",
    "ZOOM_CLIENT_SECRET",
    "ZOOM_BASE_URL",
    "ZOOM_API_BASE_URL",
    "ZOOM_OAUTH_BASE_URL",
    "ZOOM_TIMEOUT",
  ],
  configLocations: [
    "./.zoom.json",
    "./.grclanker-zoom.json",
    "~/.zoom.json",
    "~/.grclanker-zoom.json",
    "~/.config/grclanker/zoom.json",
    "Explicit path from config_file or ZOOM_CONFIG_FILE",
  ],
  variants: ["Master or sub-account ID supplied explicitly"],
  configFields: ["account_id", "accountId", "token", "access_token", "client_id", "clientId", "client_secret", "clientSecret", "base_url", "baseUrl", "oauth_base_url", "oauthBaseUrl"],
  refreshRequest: "POST /oauth/token?grant_type=account_credentials&account_id={accountId} with client Basic authentication.",
} as const satisfies ResolverAuthenticationContract;

export const ZENDESK_AUTH_RESOLVER = {
  modes: ["API token with email Basic authentication", "OAuth bearer token"],
  precedence: ["Explicit tool arguments", "ZENDESK_* environment variables", "Zendesk JSON config file"],
  environment: [
    "ZENDESK_CONFIG_FILE",
    "ZENDESK_SUBDOMAIN",
    "ZENDESK_EMAIL",
    "ZENDESK_API_TOKEN",
    "ZENDESK_OAUTH_TOKEN",
    "ZENDESK_ACCESS_TOKEN",
    "ZENDESK_BASE_URL",
    "ZENDESK_TIMEOUT",
  ],
  configLocations: ["~/.zendesk/config.json", "Explicit path from config_file or ZENDESK_CONFIG_FILE"],
  variants: ["Zendesk subdomain or explicit same-origin API base URL"],
  configFields: ["subdomain", "email", "api_token", "apiToken", "oauth_token", "oauthToken", "base_url", "baseUrl", "timeout_seconds"],
} as const satisfies ResolverAuthenticationContract;

export const SALESFORCE_AUTH_RESOLVER = {
  modes: ["JWT bearer", "Username/password plus security token", "OAuth refresh token", "Explicit access token"],
  precedence: ["Explicit tool arguments", "SF_* environment variables", "Explicit credentials JSON file"],
  environment: [
    "SF_CREDENTIALS_FILE",
    "SF_INSTANCE_URL",
    "SF_LOGIN_URL",
    "SF_USERNAME",
    "SF_PASSWORD",
    "SF_SECURITY_TOKEN",
    "SF_CONSUMER_KEY",
    "SF_CLIENT_ID",
    "SF_CONSUMER_SECRET",
    "SF_CLIENT_SECRET",
    "SF_PRIVATE_KEY_FILE",
    "SF_PRIVATE_KEY",
    "SF_REFRESH_TOKEN",
    "SF_ACCESS_TOKEN",
    "SF_API_VERSION",
    "SF_GRANT_TYPE",
    "SF_SANDBOX",
    "SF_TIMEOUT",
    "SF_MAX_RETRIES",
  ],
  configLocations: ["Explicit credentials JSON file from credentials_file or SF_CREDENTIALS_FILE"],
  variants: ["Production login", "Sandbox login", "Custom My Domain login"],
  configFields: [
    "instance_url", "instanceUrl", "login_url", "loginUrl", "username", "password", "security_token",
    "securityToken", "consumer_key", "client_id", "consumerKey", "clientId", "consumer_secret", "client_secret",
    "consumerSecret", "clientSecret", "private_key_file", "privateKeyFile", "private_key", "privateKey",
    "refresh_token", "refreshToken", "access_token", "accessToken", "api_version", "apiVersion", "grant_type",
    "grantType", "sandbox",
  ],
  refreshRequest: "POST /services/oauth2/token with the selected JWT bearer, refresh_token, or password grant.",
} as const satisfies ResolverAuthenticationContract;

export const SERVICENOW_AUTH_RESOLVER = {
  modes: ["Basic username and password", "OAuth client credentials or refresh token", "Explicit OAuth access token"],
  precedence: ["Explicit tool arguments", "SERVICENOW_* environment variables", "Explicit or default ServiceNow YAML config"],
  environment: [
    "SERVICENOW_CONFIG_FILE",
    "SERVICENOW_URL",
    "SERVICENOW_INSTANCE_URL",
    "SERVICENOW_INSTANCE",
    "SERVICENOW_AUTH_METHOD",
    "SERVICENOW_USERNAME",
    "SERVICENOW_PASSWORD",
    "SERVICENOW_CLIENT_ID",
    "SERVICENOW_CLIENT_SECRET",
    "SERVICENOW_ACCESS_TOKEN",
    "SERVICENOW_TOKEN",
    "SERVICENOW_REFRESH_TOKEN",
    "SERVICENOW_TIMEOUT",
    "SERVICENOW_MAX_RETRIES",
    "SERVICENOW_PAGE_SIZE",
  ],
  configLocations: ["./.servicenow.yaml", "~/.servicenow-sec-inspector/config.yaml", "Explicit path from config_file or SERVICENOW_CONFIG_FILE"],
  variants: ["Instance name or explicit HTTPS instance URL", "Mutual TLS is rejected as unsupported"],
  configFields: [
    "instance_url", "url", "instanceUrl", "base_url", "instance", "instance_name", "instanceName",
    "auth_method", "authMethod", "auth_mode", "username", "user", "password", "client_id", "clientId",
    "client_secret", "clientSecret", "access_token", "accessToken", "token", "refresh_token", "refreshToken",
    "timeout_seconds", "timeout", "max_retries", "maxRetries", "page_size", "pageSize",
  ],
  refreshRequest: "POST /oauth_token.do with client_credentials or refresh_token form fields.",
} as const satisfies ResolverAuthenticationContract;

export const AZURE_AUTH_RESOLVER = {
  modes: ["Explicit Microsoft Graph and Azure Resource Manager bearer tokens", "Azure CLI token discovery", "OAuth client credentials"],
  precedence: ["Explicit tool arguments", "AZURE_* environment variables", "Azure CLI", "OAuth client credentials when a token is absent"],
  environment: [
    "AZURE_AUTHORITY_HOST",
    "AZURE_GRAPH_HOST",
    "AZURE_MANAGEMENT_HOST",
    "AZURE_CLIENT_ID",
    "AZURE_CLIENT_SECRET",
    "AZURE_CLIENT_CERTIFICATE_PATH",
    "AZURE_TENANT_ID",
    "AZURE_SUBSCRIPTION_ID",
    "AZURE_GRAPH_TOKEN",
    "AZURE_MANAGEMENT_TOKEN",
    "AZURE_ACCESS_TOKEN",
  ],
  configLocations: ["Azure CLI account context"],
  variants: ["Azure public cloud", "Azure US Government", "Azure China"],
  configFields: [],
  refreshRequest: "POST /{tenant}/oauth2/v2.0/token using client_credentials independently for Microsoft Graph and Azure Resource Manager scopes.",
} as const satisfies ResolverAuthenticationContract;

export const GCP_AUTH_RESOLVER = {
  modes: ["Explicit OAuth access token", "Service-account application default credentials", "Authorized-user application default credentials", "gcloud access token"],
  precedence: ["Explicit tool arguments", "GCP and GOOGLE_* environment variables", "Application Default Credentials file", "gcloud auth print-access-token"],
  environment: [
    "APPDATA",
    "CLOUDSDK_CONFIG",
    "GCP_ORGANIZATION_ID",
    "GCP_ORG_ID",
    "GCP_ACCESS_TOKEN",
    "GOOGLE_OAUTH_ACCESS_TOKEN",
    "GOOGLE_ACCESS_TOKEN",
    "GCP_CREDENTIALS_FILE",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "GCP_PROJECT_ID",
    "GOOGLE_CLOUD_PROJECT",
    "GCLOUD_PROJECT",
  ],
  configLocations: ["Explicit credentials_file", "GCP_CREDENTIALS_FILE", "GOOGLE_APPLICATION_CREDENTIALS", "Application Default Credentials well-known path"],
  variants: ["Organization scope", "Project scope", "Service-account JWT bearer exchange", "Authorized-user refresh-token exchange"],
  configFields: ["type", "client_email", "private_key", "token_uri", "project_id", "client_id", "client_secret", "refresh_token"],
  refreshRequest: "POST the credential token_uri with a JWT bearer assertion or refresh_token grant.",
} as const satisfies ResolverAuthenticationContract;

export const OCI_AUTH_RESOLVER = {
  modes: ["OCI CLI configuration profile"],
  precedence: ["Explicit tool arguments", "OCI_* environment variables", "Selected OCI CLI profile", "Runtime defaults"],
  environment: ["HOME", "USERPROFILE", "OCI_CONFIG_FILE", "OCI_CLI_PROFILE", "OCI_REGION", "OCI_TENANCY_OCID", "OCI_COMPARTMENT_OCID"],
  configLocations: ["~/.oci/config", "Explicit path from config_file or OCI_CONFIG_FILE"],
  variants: ["Named OCI CLI profile", "Explicit tenancy or compartment scope", "OCI region"],
  configFields: ["tenancy", "region", "user", "fingerprint", "key_file", "pass_phrase", "security_token_file"],
} as const satisfies ResolverAuthenticationContract;

export const CLOUDFLARE_AUTH_RESOLVER = {
  modes: ["Cloudflare API token", "Global API key with account email"],
  precedence: ["Explicit tool arguments", "CLOUDFLARE_* environment variables"],
  environment: [
    "CLOUDFLARE_API_TOKEN",
    "CLOUDFLARE_API_KEY",
    "CLOUDFLARE_EMAIL",
    "CLOUDFLARE_ACCOUNT_ID",
    "CLOUDFLARE_API_BASE_URL",
    "CLOUDFLARE_TIMEOUT",
  ],
  configLocations: [],
  variants: ["Explicit account ID", "Single visible account discovery", "Custom same-origin API base URL"],
  configFields: [],
} as const satisfies ResolverAuthenticationContract;

export const PALOALTO_AUTH_RESOLVER = {
  modes: ["Prisma Cloud access key and secret key", "Prisma Cloud Compute token exchange", "PAN-OS API key", "PAN-OS username and password key generation"],
  precedence: ["Explicit tool arguments", "Palo Alto environment variables", "Palo Alto JSON config file"],
  environment: [
    "PALOALTO_CONFIG_FILE",
    "PRISMA_ACCESS_KEY_ID",
    "PRISMA_SECRET_KEY",
    "PRISMA_API_URL",
    "PRISMA_COMPUTE_URL",
    "PANOS_HOST",
    "PANOS_API_KEY",
    "PANOS_USERNAME",
    "PANOS_PASSWORD",
    "PANOS_VERIFY_TLS",
    "PALOALTO_TIMEOUT",
  ],
  configLocations: ["~/.config/grclanker/paloalto.json", "Explicit path from config_file or PALOALTO_CONFIG_FILE"],
  variants: ["Prisma Cloud CSPM", "Prisma Cloud Compute", "One or more PAN-OS devices", "Per-client PAN-OS TLS verification override"],
  configFields: [
    "PRISMA_ACCESS_KEY_ID", "prisma_access_key_id", "PRISMA_SECRET_KEY", "prisma_secret_key",
    "PRISMA_API_URL", "prisma_api_url", "PRISMA_COMPUTE_URL", "prisma_compute_url",
    "PANOS_HOST", "panos_hosts", "PANOS_API_KEY", "panos_api_key", "PANOS_USERNAME",
    "panos_username", "PANOS_PASSWORD", "panos_password", "PANOS_VERIFY_TLS",
  ],
  refreshRequest: "POST /login for Prisma Cloud or Prisma Compute; POST /api/?type=keygen for PAN-OS username/password authentication.",
} as const satisfies ResolverAuthenticationContract;

export const ZSCALER_AUTH_RESOLVER = {
  modes: ["ZIA legacy API-key obfuscation and session cookie", "ZPA OAuth client credentials"],
  precedence: ["Explicit tool arguments", "Zscaler environment variables", "Zscaler YAML config file"],
  environment: [
    "ZSCALER_CONFIG_FILE",
    "ZIA_CLOUD",
    "ZIA_BASE_URL",
    "ZIA_API_KEY",
    "ZIA_USERNAME",
    "ZIA_PASSWORD",
    "ZPA_CLOUD",
    "ZPA_BASE_URL",
    "ZPA_CLIENT_ID",
    "ZPA_CLIENT_SECRET",
    "ZPA_CUSTOMER_ID",
    "ZSCALER_CLIENT_ID",
    "ZSCALER_CLIENT_SECRET",
    "ZDX_CLIENT_ID",
    "ZDX_CLIENT_SECRET",
    "ZSCALER_TIMEOUT",
    "ZSCALER_MAX_RETRIES",
  ],
  configLocations: ["~/.zscaler/zscaler.yaml", "Explicit path from config_file or ZSCALER_CONFIG_FILE"],
  variants: ["ZIA commercial, beta, government, and tenant clouds", "ZPA production, beta, government, and government-US clouds"],
  configFields: ["zia.client", "zpa.client", "zscaler.client"],
  refreshRequest: "POST /authenticatedSession for ZIA; POST /signin for ZPA OAuth client credentials.",
} as const satisfies ResolverAuthenticationContract;

export const CROWDSTRIKE_AUTH_RESOLVER = {
  modes: ["Falcon OAuth 2.0 client credentials"],
  precedence: ["Explicit tool arguments", "CS_* then FALCON_* environment aliases", "Explicit or default CrowdStrike JSON config"],
  environment: [
    "CS_CONFIG_FILE", "CS_CLIENT_ID", "FALCON_CLIENT_ID", "CS_CLIENT_SECRET", "FALCON_CLIENT_SECRET",
    "CS_CLOUD", "FALCON_CLOUD", "CS_BASE_URL", "FALCON_BASE_URL", "CS_MEMBER_CID",
    "FALCON_MEMBER_CID", "CS_TIMEOUT",
  ],
  configLocations: ["~/.crowdstrike/config.json", "Explicit path from config_file or CS_CONFIG_FILE"],
  variants: ["us-1", "us-2", "eu-1", "us-gov-1", "us-gov-2", "Optional Flight Control member CID"],
  configFields: ["client_id", "clientId", "client_secret", "clientSecret", "cloud", "region", "base_url", "baseUrl", "member_cid", "memberCid", "timeout_seconds"],
  refreshRequest: "POST /oauth2/token with application/x-www-form-urlencoded client_id and client_secret; cache until 60 seconds before expiry and refresh once after HTTP 401.",
} as const satisfies ResolverAuthenticationContract;

export const TENABLE_AUTH_RESOLVER = {
  modes: ["Tenable Vulnerability Management X-ApiKeys access/secret pair", "Tenable Security Center x-apikey access/secret pair"],
  precedence: ["Explicit tool arguments", "TENABLE_* environment variables", "Explicit or default Tenable YAML/JSON config"],
  environment: [
    "TENABLE_CONFIG_FILE", "TENABLE_URL", "TENABLE_BASE_URL", "TENABLE_ACCESS_KEY", "TENABLE_SECRET_KEY",
    "TENABLE_SC_URL", "TENABLE_SC_ACCESS_KEY", "TENABLE_SC_SECRET_KEY", "TENABLE_TIMEOUT",
  ],
  configLocations: ["~/.tenable/config.yaml", "Explicit path from config_file or TENABLE_CONFIG_FILE"],
  variants: ["cloud.tenable.com", "fedcloud.tenable.com", "Tenable Security Center URL", "Simultaneous VM and Security Center tenants"],
  configFields: ["url", "base_url", "access_key", "accessKey", "secret_key", "secretKey", "sc_url", "sc_access_key", "sc_secret_key", "timeout_seconds"],
} as const satisfies ResolverAuthenticationContract;

export const QUALYS_AUTH_RESOLVER = {
  modes: ["HTTP Basic username/password", "Pre-issued bearer token", "Qualys gateway OAuth token exchange"],
  precedence: ["Explicit tool arguments", "QUALYS_* environment variables", "Explicit or default Qualys key/value or INI config"],
  environment: [
    "QUALYS_CONFIG_FILE", "QUALYS_USERNAME", "QUALYS_USER", "QUALYS_PASSWORD", "QUALYS_TOKEN",
    "QUALYS_ACCESS_TOKEN", "QUALYS_USE_OAUTH", "QUALYS_PLATFORM", "QUALYS_API_SERVER", "QUALYS_BASE_URL",
    "QUALYS_API_URL", "QUALYS_GATEWAY_URL", "QUALYS_TIMEOUT", "QUALYS_MAX_RETRIES", "QUALYS_LOOKBACK_DAYS",
  ],
  configLocations: ["~/.qcrc", "Explicit path from config_file or QUALYS_CONFIG_FILE"],
  variants: ["US1", "US2", "US3", "US4", "GOV1", "EU1", "EU2", "EU3", "IN1", "CA1", "AE1", "UK1", "AU1", "KSA1", "Explicit API and gateway URLs"],
  configFields: ["username", "user", "password", "token", "use_oauth", "platform", "hostname", "base_url", "gateway_url", "timeout"],
  refreshRequest: "POST /auth on the selected platform gateway with username, password, and token=true.",
} as const satisfies ResolverAuthenticationContract;

export const VERACODE_AUTH_RESOLVER = {
  modes: ["VERACODE-HMAC-SHA-256 API ID and secret signing"],
  precedence: ["Explicit tool arguments", "VERACODE_* environment variables", "Selected profile in the Veracode credentials INI file"],
  environment: [
    "VERACODE_API_PROFILE", "VERACODE_API_CREDENTIALS_FILE", "VERACODE_API_KEY_ID",
    "VERACODE_API_KEY_SECRET", "VERACODE_REGION", "VERACODE_API_BASE_URL", "VERACODE_TIMEOUT",
  ],
  configLocations: ["~/.veracode/credentials", "Explicit path from credentials_file or VERACODE_API_CREDENTIALS_FILE"],
  variants: ["us: api.veracode.com", "eu: api.veracode.eu", "us-fed: api.veracode.us", "Explicit same-origin API base URL"],
  configFields: ["veracode_api_key_id", "veracode_api_key_secret"],
} as const satisfies ResolverAuthenticationContract;

export const KNOWBE4_AUTH_RESOLVER = {
  modes: ["KnowBe4 Reporting API bearer token", "Optional independent PhishER Product API bearer token"],
  precedence: ["Explicit tool arguments", "KNOWBE4_* environment variables", "Explicit or default KnowBe4 YAML config"],
  environment: [
    "KNOWBE4_CONFIG_FILE", "KNOWBE4_API_TOKEN", "KNOWBE4_REGION", "KNOWBE4_BASE_URL",
    "KNOWBE4_PHISHER_API_TOKEN", "KNOWBE4_PHISHER_GRAPHQL_URL", "KNOWBE4_TIMEOUT", "KNOWBE4_REDACT_PII",
  ],
  configLocations: ["~/.knowbe4-inspector/config.yaml", "Explicit path from config_file or KNOWBE4_CONFIG_FILE"],
  variants: ["us", "eu", "ca", "uk", "de", "Optional region-specific PhishER GraphQL endpoint"],
  configFields: ["api_token", "region", "base_url", "phisher_api_token", "phisher_graphql_url", "timeout", "redact_pii"],
} as const satisfies ResolverAuthenticationContract;

export const DATADOG_AUTH_RESOLVER = {
  modes: ["Datadog API key plus application key"],
  precedence: ["Explicit tool arguments", "DD_* then DATADOG_* environment aliases", "dogshelI-compatible INI configuration"],
  environment: [
    "DD_API_KEY", "DATADOG_API_KEY", "DD_APP_KEY", "DD_APPLICATION_KEY", "DATADOG_APP_KEY",
    "DD_SITE", "DATADOG_SITE", "DD_HOST", "DATADOG_HOST", "DD_CONFIG_FILE", "DATADOG_CONFIG_FILE",
    "DD_TIMEOUT", "DD_MAX_RETRIES",
  ],
  configLocations: ["~/.dogrc", "Explicit path from config_file, DD_CONFIG_FILE, or DATADOG_CONFIG_FILE"],
  variants: ["US1", "US3", "US5", "EU1", "AP1", "AP2", "US government", "Explicit same-origin API base URL"],
  configFields: ["apikey", "appkey", "api_host"],
} as const satisfies ResolverAuthenticationContract;

export const ELASTIC_AUTH_RESOLVER = {
  modes: ["Elasticsearch API key", "HTTP Basic username/password", "Bearer token", "Elastic Cloud API key for deployment metadata"],
  precedence: ["Explicit tool arguments", "ELASTIC_* and KIBANA_* environment variables", "Explicit or default Elastic YAML configuration"],
  environment: [
    "ELASTIC_SEC_INSPECTOR_CONFIG", "ELASTICSEARCH_URL", "ELASTIC_URL", "KIBANA_URL", "KIBANA_SPACE_ID",
    "ELASTIC_API_KEY", "ELASTIC_USERNAME", "ELASTIC_PASSWORD", "ELASTIC_BEARER_TOKEN",
    "ELASTIC_CLOUD_API_KEY", "ELASTIC_CLOUD_API_URL", "ELASTIC_TIMEOUT",
  ],
  configLocations: ["~/.elastic-sec-inspector/config.yaml", "Explicit path from config_file or ELASTIC_SEC_INSPECTOR_CONFIG"],
  variants: ["Self-managed Elasticsearch and Kibana", "Elastic Cloud deployment metadata", "Optional Kibana space"],
  configFields: ["elasticsearch_url", "kibana_url", "kibana_space_id", "api_key", "username", "password", "bearer_token", "cloud_api_key", "cloud_api_url", "timeout_seconds", "max_retries"],
} as const satisfies ResolverAuthenticationContract;

export const NEWRELIC_AUTH_RESOLVER = {
  modes: ["New Relic user API key"],
  precedence: ["Explicit tool arguments", "NEW_RELIC_* environment variables", "Explicit or default New Relic YAML configuration"],
  environment: [
    "NEW_RELIC_SEC_INSPECTOR_CONFIG", "NEW_RELIC_API_KEY", "NEW_RELIC_ACCOUNT_ID",
    "NEW_RELIC_REGION", "NEW_RELIC_TIMEOUT", "NEW_RELIC_AUDIT_WINDOW_DAYS",
  ],
  configLocations: ["~/.newrelic-sec-inspector/config.yaml", "Explicit path from config_file or NEW_RELIC_SEC_INSPECTOR_CONFIG"],
  variants: ["US NerdGraph and REST origins", "EU NerdGraph and REST origins", "One or more account IDs"],
  configFields: ["api_key", "account_ids", "region", "timeout_seconds", "audit_window_days"],
} as const satisfies ResolverAuthenticationContract;

export const SPLUNK_AUTH_RESOLVER = {
  modes: ["Splunk bearer token", "Splunk username/password Basic authentication", "Independent Splunk Cloud ACS token"],
  precedence: ["Explicit tool arguments", "SPLUNK_* environment variables", "Explicit or default Splunk YAML configuration"],
  environment: [
    "SPLUNK_CONFIG_FILE", "SPLUNK_URL", "SPLUNK_TOKEN", "SPLUNK_USERNAME", "SPLUNK_PASSWORD",
    "SPLUNK_STACK", "SPLUNK_ACS_TOKEN", "SPLUNK_ACS_BASE_URL", "SPLUNK_VERIFY_SSL", "SPLUNK_TIMEOUT",
  ],
  configLocations: ["~/.splunk-sec-inspector/config.yaml", "Explicit path from config_file or SPLUNK_CONFIG_FILE"],
  variants: ["Splunk Enterprise management API", "Splunk Cloud management API", "Splunk Cloud ACS"],
  configFields: ["url", "token", "username", "password", "stack", "acs_token", "acs_base_url", "verify_ssl", "timeout_seconds"],
} as const satisfies ResolverAuthenticationContract;

export const SUMOLOGIC_AUTH_RESOLVER = {
  modes: ["Sumo Logic access ID and access key using HTTP Basic authentication"],
  precedence: ["Explicit tool arguments", "SUMOLOGIC_* environment variables", "Explicit or default Sumo Logic YAML configuration"],
  environment: [
    "SUMOLOGIC_CONFIG_FILE", "SUMOLOGIC_ACCESS_ID", "SUMOLOGIC_ACCESS_KEY",
    "SUMOLOGIC_DEPLOYMENT", "SUMOLOGIC_ENDPOINT", "SUMOLOGIC_TIMEOUT",
  ],
  configLocations: ["~/.sumologic-sec-inspector/config.yaml", "Explicit path from config_file or SUMOLOGIC_CONFIG_FILE"],
  variants: ["au", "ca", "ch", "de", "esc", "eu", "fed", "in", "jp", "kr", "us1", "us2", "Explicit regional endpoint"],
  configFields: ["access_id", "access_key", "deployment", "endpoint", "timeout_seconds"],
} as const satisfies ResolverAuthenticationContract;

export const LAUNCHDARKLY_AUTH_RESOLVER = {
  modes: ["LaunchDarkly REST API access token"],
  precedence: ["Explicit tool arguments", "LAUNCHDARKLY_* then LD_* environment aliases", "Explicit or default LaunchDarkly YAML configuration"],
  environment: [
    "LAUNCHDARKLY_CONFIG", "LAUNCHDARKLY_API_TOKEN", "LD_ACCESS_TOKEN", "LAUNCHDARKLY_BASE_URL",
    "LD_BASE_URI", "LAUNCHDARKLY_API_VERSION", "LAUNCHDARKLY_TIMEOUT", "LAUNCHDARKLY_PROJECTS",
    "LAUNCHDARKLY_ALLOWED_DOMAINS",
  ],
  configLocations: ["~/.launchdarkly-sec-inspector/config.yaml", "Explicit path from config_file or LAUNCHDARKLY_CONFIG"],
  variants: ["LaunchDarkly SaaS", "Federal instance", "Explicit same-origin REST API base URL"],
  configFields: ["api_token", "base_url", "api_version", "timeout_seconds", "project_keys", "allowed_domains"],
} as const satisfies ResolverAuthenticationContract;

export const MULESOFT_AUTH_RESOLVER = {
  modes: ["Explicit Anypoint access token", "OAuth client credentials", "Username/password token exchange"],
  precedence: ["Explicit tool arguments", "ANYPOINT_* environment variables", "Explicit or default MuleSoft YAML configuration"],
  environment: [
    "MULESOFT_SEC_INSPECTOR_CONFIG", "ANYPOINT_CONFIG_FILE", "ANYPOINT_ACCESS_TOKEN", "ANYPOINT_TOKEN",
    "ANYPOINT_CLIENT_ID", "ANYPOINT_CLIENT_SECRET", "ANYPOINT_USERNAME", "ANYPOINT_PASSWORD",
    "ANYPOINT_ORGANIZATION_ID", "ANYPOINT_ORG_ID", "ANYPOINT_CONTROL_PLANE", "ANYPOINT_BASE_URL",
    "ANYPOINT_ENVIRONMENTS", "ANYPOINT_ENVIRONMENT_IDS", "ANYPOINT_TIMEOUT",
  ],
  configLocations: ["~/.mulesoft-sec-inspector/config.yaml", "Explicit path from config_file, ANYPOINT_CONFIG_FILE, or MULESOFT_SEC_INSPECTOR_CONFIG"],
  variants: ["US", "EU", "US government", "Explicit Anypoint control-plane URL", "Optional environment allowlist"],
  configFields: ["access_token", "client_id", "client_secret", "username", "password", "organization_id", "control_plane", "base_url", "environment_ids", "timeout_seconds"],
  refreshRequest: "POST /accounts/api/v2/oauth2/token with client_credentials, or POST /accounts/login with username and password.",
} as const satisfies ResolverAuthenticationContract;

export const GITHUB_AUTH_RESOLVER = {
  modes: ["Fine-grained or classic personal access token", "GitHub App installation token minted from an RS256 JWT"],
  precedence: ["Explicit tool arguments", "GITHUB_TOKEN then GH_TOKEN", "GitHub App environment or explicit arguments"],
  environment: [
    "GITHUB_TOKEN", "GH_TOKEN", "GITHUB_ORG", "GH_ORG", "GITHUB_API_URL", "GITHUB_API_BASE_URL",
    "GITHUB_GRAPHQL_URL", "GITHUB_ENTERPRISE", "GITHUB_APP_ID", "GITHUB_APP_PRIVATE_KEY",
    "GITHUB_APP_PRIVATE_KEY_PATH", "GITHUB_APP_INSTALLATION_ID", "GITHUB_LOOKBACK_DAYS",
  ],
  configLocations: ["GitHub App private key path supplied explicitly or through GITHUB_APP_PRIVATE_KEY_PATH"],
  variants: ["GitHub.com", "GitHub Enterprise Server REST /api/v3 and GraphQL /api/graphql origins"],
  configFields: [],
  refreshRequest: "POST /app/installations/{installation_id}/access_tokens using a ten-minute GitHub App JWT signed with RS256.",
} as const satisfies ResolverAuthenticationContract;

export const SNOWFLAKE_AUTH_RESOLVER = {
  modes: ["Key-pair JWT authentication", "OAuth bearer token", "Programmatic access token"],
  precedence: ["Explicit tool arguments", "SNOWFLAKE_* environment variables", "Selected connection in Snowflake connections.toml or config.toml"],
  environment: [
    "SNOWFLAKE_ACCOUNT", "SNOWFLAKE_USER", "SNOWFLAKE_PRIVATE_KEY_PATH", "SNOWFLAKE_PRIVATE_KEY_FILE",
    "SNOWFLAKE_PRIVATE_KEY", "SNOWFLAKE_PRIVATE_KEY_RAW", "SNOWFLAKE_PRIVATE_KEY_PASSPHRASE",
    "PRIVATE_KEY_PASSPHRASE", "SNOWFLAKE_TOKEN", "SNOWFLAKE_OAUTH_TOKEN", "SNOWFLAKE_ACCESS_TOKEN",
    "SNOWFLAKE_TOKEN_TYPE", "SNOWFLAKE_AUTHENTICATOR", "SNOWFLAKE_ROLE", "SNOWFLAKE_WAREHOUSE",
    "SNOWFLAKE_DATABASE", "SNOWFLAKE_SCHEMA", "SNOWFLAKE_BASE_URL", "SNOWFLAKE_HOST",
    "SNOWFLAKE_CONNECTION_NAME", "SNOWFLAKE_DEFAULT_CONNECTION_NAME", "SNOWFLAKE_HOME",
    "SNOWFLAKE_TIMEOUT", "SNOWFLAKE_STATEMENT_TIMEOUT", "SNOWFLAKE_POLL_INTERVAL_MS",
  ],
  configLocations: ["~/.snowflake/connections.toml", "~/.snowflake/config.toml", "SNOWFLAKE_HOME equivalents"],
  variants: ["Account identifier host derivation", "Explicit Snowflake SQL API host", "Optional role, warehouse, database, and schema"],
  configFields: ["account", "user", "private_key_path", "private_key", "private_key_passphrase", "token", "authenticator", "role", "warehouse", "database", "schema", "host"],
} as const satisfies ResolverAuthenticationContract;

export const PAGERDUTY_AUTH_RESOLVER = {
  modes: ["PagerDuty API token", "OAuth access token", "Scoped OAuth client-credentials token"],
  precedence: ["Explicit tool arguments", "PAGERDUTY_* then PD_API_KEY environment aliases", "Explicit or default PagerDuty JSON configuration"],
  environment: [
    "PAGERDUTY_CONFIG_FILE", "PAGERDUTY_API_TOKEN", "PAGERDUTY_API_KEY", "PAGERDUTY_TOKEN", "PD_API_KEY",
    "PAGERDUTY_ACCESS_TOKEN", "PAGERDUTY_OAUTH_TOKEN", "PAGERDUTY_CLIENT_ID", "PAGERDUTY_CLIENT_SECRET",
    "PAGERDUTY_SUBDOMAIN", "PAGERDUTY_ACCOUNT_SUBDOMAIN", "PAGERDUTY_USER_EMAIL", "PAGERDUTY_FROM_EMAIL",
    "PAGERDUTY_REGION", "PAGERDUTY_SERVICE_REGION", "PAGERDUTY_BASE_URL", "PAGERDUTY_API_BASE_URL",
    "PAGERDUTY_IDENTITY_TOKEN_URL", "PAGERDUTY_TIMEOUT",
  ],
  configLocations: ["~/.config/grclanker/pagerduty.json", "Explicit path from config_file or PAGERDUTY_CONFIG_FILE"],
  variants: ["US service region", "EU service region", "Scoped credential requiring account subdomain and From header"],
  configFields: ["api_token", "access_token", "client_id", "client_secret", "subdomain", "from_email", "region", "base_url", "timeout_seconds"],
  refreshRequest: "POST the PagerDuty identity token endpoint with the client_credentials grant for scoped OAuth credentials.",
} as const satisfies ResolverAuthenticationContract;

export const ANSIBLE_AUTH_RESOLVER = {
  modes: ["AAP OAuth2 bearer token", "AAP username/password Basic authentication"],
  precedence: ["Explicit tool arguments", "AAP_* environment variables"],
  environment: ["AAP_URL", "AAP_TOKEN", "AAP_USERNAME", "AAP_PASSWORD", "AAP_VERIFY_SSL", "AAP_TIMEOUT"],
  configLocations: [],
  variants: ["Automation Controller and Ansible Automation Platform Gateway API v2", "Per-client TLS verification setting"],
  configFields: [],
} as const satisfies ResolverAuthenticationContract;
