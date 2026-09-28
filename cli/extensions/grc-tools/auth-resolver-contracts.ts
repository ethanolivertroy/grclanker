export interface ResolverAuthenticationContract {
  modes: readonly string[];
  precedence: readonly string[];
  environment: readonly string[];
  configLocations: readonly string[];
  variants: readonly string[];
  configFields: readonly string[];
  refreshRequest?: string;
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
