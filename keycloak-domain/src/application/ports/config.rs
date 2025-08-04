use crate::domain::errors::{ConfigError, DomainResult};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Configuration port for accessing application configuration
#[async_trait]
pub trait ConfigurationPort: Send + Sync {
    /// Get Keycloak server configuration
    fn get_keycloak_config(&self) -> &KeycloakConfig;

    /// Get authentication configuration
    fn get_auth_config(&self) -> &AuthConfig;

    /// Get HTTP client configuration
    fn get_http_config(&self) -> &HttpConfig;

    /// Get logging configuration
    fn get_logging_config(&self) -> &LoggingConfig;

    /// Validate all configuration
    fn validate(&self) -> DomainResult<()>;

    /// Check if running in development mode
    fn is_development(&self) -> bool;

    /// Check if running in test mode
    fn is_test(&self) -> bool;
}

/// Keycloak server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeycloakConfig {
    pub url: String,
    pub admin_realm: String,
    pub admin_client_id: String,
    pub admin_username: String,
    pub admin_password: String,
    pub default_realm: Option<String>,
    pub verify_ssl: bool,
}

impl KeycloakConfig {
    pub fn validate(&self) -> DomainResult<()> {
        if self.url.is_empty() {
            return Err(ConfigError::MissingRequired {
                key: "KEYCLOAK_URL".to_string(),
            }
            .into());
        }

        if !self.url.starts_with("http://") && !self.url.starts_with("https://") {
            return Err(ConfigError::InvalidValue {
                key: "KEYCLOAK_URL".to_string(),
                message: "Must start with http:// or https://".to_string(),
            }
            .into());
        }

        if self.admin_username.is_empty() {
            return Err(ConfigError::MissingRequired {
                key: "KEYCLOAK_ADMIN_USERNAME".to_string(),
            }
            .into());
        }

        if self.admin_password.is_empty() {
            return Err(ConfigError::MissingRequired {
                key: "KEYCLOAK_ADMIN_PASSWORD".to_string(),
            }
            .into());
        }

        if self.admin_realm.is_empty() {
            return Err(ConfigError::MissingRequired {
                key: "KEYCLOAK_ADMIN_REALM".to_string(),
            }
            .into());
        }

        if self.admin_client_id.is_empty() {
            return Err(ConfigError::MissingRequired {
                key: "KEYCLOAK_ADMIN_CLIENT_ID".to_string(),
            }
            .into());
        }

        Ok(())
    }

    pub fn get_admin_url(&self) -> String {
        format!(
            "{}/admin/realms/{}",
            self.url.trim_end_matches('/'),
            self.admin_realm
        )
    }

    pub fn get_auth_url(&self) -> String {
        format!(
            "{}/realms/{}/protocol/openid-connect/token",
            self.url.trim_end_matches('/'),
            self.admin_realm
        )
    }

    pub fn get_realm_url(&self, realm: &str) -> String {
        format!("{}/admin/realms/{}", self.url.trim_end_matches('/'), realm)
    }
}

/// Authentication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    pub token_refresh_threshold_seconds: u64,
    pub token_cache_ttl_seconds: u64,
    pub max_token_refresh_attempts: u32,
    pub authentication_timeout_seconds: u64,
    pub require_ssl: bool,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            token_refresh_threshold_seconds: 300, // 5 minutes
            token_cache_ttl_seconds: 3600,        // 1 hour
            max_token_refresh_attempts: 3,
            authentication_timeout_seconds: 30,
            require_ssl: true,
        }
    }
}

impl AuthConfig {
    pub fn validate(&self) -> DomainResult<()> {
        if self.token_refresh_threshold_seconds == 0 {
            return Err(ConfigError::InvalidValue {
                key: "token_refresh_threshold_seconds".to_string(),
                message: "Must be greater than 0".to_string(),
            }
            .into());
        }

        if self.max_token_refresh_attempts == 0 {
            return Err(ConfigError::InvalidValue {
                key: "max_token_refresh_attempts".to_string(),
                message: "Must be greater than 0".to_string(),
            }
            .into());
        }

        Ok(())
    }

    pub fn get_refresh_threshold(&self) -> Duration {
        Duration::from_secs(self.token_refresh_threshold_seconds)
    }

    pub fn get_cache_ttl(&self) -> Duration {
        Duration::from_secs(self.token_cache_ttl_seconds)
    }

    pub fn get_auth_timeout(&self) -> Duration {
        Duration::from_secs(self.authentication_timeout_seconds)
    }
}

/// HTTP client configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpConfig {
    pub timeout_seconds: u64,
    pub connect_timeout_seconds: u64,
    pub max_retries: u32,
    pub retry_delay_ms: u64,
    pub max_connections: usize,
    pub keep_alive_timeout_seconds: u64,
    pub pool_idle_timeout_seconds: u64,
    pub user_agent: String,
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            timeout_seconds: 30,
            connect_timeout_seconds: 10,
            max_retries: 3,
            retry_delay_ms: 1000,
            max_connections: 100,
            keep_alive_timeout_seconds: 90,
            pool_idle_timeout_seconds: 30,
            user_agent: "keycloak-domain/0.1.0".to_string(),
        }
    }
}

impl HttpConfig {
    pub fn validate(&self) -> DomainResult<()> {
        if self.timeout_seconds == 0 {
            return Err(ConfigError::InvalidValue {
                key: "timeout_seconds".to_string(),
                message: "Must be greater than 0".to_string(),
            }
            .into());
        }

        if self.connect_timeout_seconds == 0 {
            return Err(ConfigError::InvalidValue {
                key: "connect_timeout_seconds".to_string(),
                message: "Must be greater than 0".to_string(),
            }
            .into());
        }

        if self.max_connections == 0 {
            return Err(ConfigError::InvalidValue {
                key: "max_connections".to_string(),
                message: "Must be greater than 0".to_string(),
            }
            .into());
        }

        Ok(())
    }

    pub fn get_timeout(&self) -> Duration {
        Duration::from_secs(self.timeout_seconds)
    }

    pub fn get_connect_timeout(&self) -> Duration {
        Duration::from_secs(self.connect_timeout_seconds)
    }

    pub fn get_retry_delay(&self) -> Duration {
        Duration::from_millis(self.retry_delay_ms)
    }

    pub fn get_keep_alive_timeout(&self) -> Duration {
        Duration::from_secs(self.keep_alive_timeout_seconds)
    }

    pub fn get_pool_idle_timeout(&self) -> Duration {
        Duration::from_secs(self.pool_idle_timeout_seconds)
    }
}

/// Logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    pub level: LogLevel,
    pub format: LogFormat,
    pub enable_json: bool,
    pub enable_colors: bool,
    pub log_requests: bool,
    pub log_responses: bool,
    pub sensitive_fields: Vec<String>,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: LogLevel::Info,
            format: LogFormat::Compact,
            enable_json: false,
            enable_colors: true,
            log_requests: true,
            log_responses: false,
            sensitive_fields: vec![
                "password".to_string(),
                "secret".to_string(),
                "token".to_string(),
                "authorization".to_string(),
                "cookie".to_string(),
            ],
        }
    }
}

/// Log level enumeration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl std::fmt::Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LogLevel::Trace => write!(f, "trace"),
            LogLevel::Debug => write!(f, "debug"),
            LogLevel::Info => write!(f, "info"),
            LogLevel::Warn => write!(f, "warn"),
            LogLevel::Error => write!(f, "error"),
        }
    }
}

/// Log format enumeration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum LogFormat {
    Compact,
    Pretty,
    Json,
    Full,
}

/// Environment-specific configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[derive(Default)]
pub enum Environment {
    #[default]
    Development,
    Test,
    Staging,
    Production,
}


impl std::fmt::Display for Environment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Environment::Development => write!(f, "development"),
            Environment::Test => write!(f, "test"),
            Environment::Staging => write!(f, "staging"),
            Environment::Production => write!(f, "production"),
        }
    }
}

/// Complete application configuration
#[derive(Debug, Clone)]
pub struct AppConfig {
    pub environment: Environment,
    pub keycloak: KeycloakConfig,
    pub auth: AuthConfig,
    pub http: HttpConfig,
    pub logging: LoggingConfig,
}

impl AppConfig {
    pub fn validate(&self) -> DomainResult<()> {
        self.keycloak.validate()?;
        self.auth.validate()?;
        self.http.validate()?;
        Ok(())
    }

    pub fn is_development(&self) -> bool {
        self.environment == Environment::Development
    }

    pub fn is_test(&self) -> bool {
        self.environment == Environment::Test
    }

    pub fn is_production(&self) -> bool {
        self.environment == Environment::Production
    }

    /// Load configuration from environment variables
    pub fn from_env() -> DomainResult<Self> {
        use std::env;

        let environment = env::var("ENVIRONMENT")
            .unwrap_or_else(|_| "development".to_string())
            .parse()
            .map_err(|_| ConfigError::InvalidValue {
                key: "ENVIRONMENT".to_string(),
                message: "Must be one of: development, test, staging, production".to_string(),
            })?;

        let keycloak = KeycloakConfig {
            url: env::var("KEYCLOAK_URL").map_err(|_| ConfigError::MissingRequired {
                key: "KEYCLOAK_URL".to_string(),
            })?,
            admin_realm: env::var("KEYCLOAK_ADMIN_REALM").unwrap_or_else(|_| "master".to_string()),
            admin_client_id: env::var("KEYCLOAK_ADMIN_CLIENT_ID")
                .unwrap_or_else(|_| "admin-cli".to_string()),
            admin_username: env::var("KEYCLOAK_ADMIN_USERNAME").map_err(|_| {
                ConfigError::MissingRequired {
                    key: "KEYCLOAK_ADMIN_USERNAME".to_string(),
                }
            })?,
            admin_password: env::var("KEYCLOAK_ADMIN_PASSWORD").map_err(|_| {
                ConfigError::MissingRequired {
                    key: "KEYCLOAK_ADMIN_PASSWORD".to_string(),
                }
            })?,
            default_realm: env::var("KEYCLOAK_DEFAULT_REALM").ok(),
            verify_ssl: env::var("KEYCLOAK_VERIFY_SSL")
                .unwrap_or_else(|_| "true".to_string())
                .parse()
                .unwrap_or(true),
        };

        let auth = AuthConfig {
            token_refresh_threshold_seconds: env::var("AUTH_TOKEN_REFRESH_THRESHOLD_SECONDS")
                .unwrap_or_else(|_| "300".to_string())
                .parse()
                .unwrap_or(300),
            token_cache_ttl_seconds: env::var("AUTH_TOKEN_CACHE_TTL_SECONDS")
                .unwrap_or_else(|_| "3600".to_string())
                .parse()
                .unwrap_or(3600),
            max_token_refresh_attempts: env::var("AUTH_MAX_TOKEN_REFRESH_ATTEMPTS")
                .unwrap_or_else(|_| "3".to_string())
                .parse()
                .unwrap_or(3),
            authentication_timeout_seconds: env::var("AUTH_TIMEOUT_SECONDS")
                .unwrap_or_else(|_| "30".to_string())
                .parse()
                .unwrap_or(30),
            require_ssl: env::var("AUTH_REQUIRE_SSL")
                .unwrap_or_else(|_| "true".to_string())
                .parse()
                .unwrap_or(true),
        };

        let http = HttpConfig {
            timeout_seconds: env::var("HTTP_TIMEOUT_SECONDS")
                .unwrap_or_else(|_| "30".to_string())
                .parse()
                .unwrap_or(30),
            connect_timeout_seconds: env::var("HTTP_CONNECT_TIMEOUT_SECONDS")
                .unwrap_or_else(|_| "10".to_string())
                .parse()
                .unwrap_or(10),
            max_retries: env::var("HTTP_MAX_RETRIES")
                .unwrap_or_else(|_| "3".to_string())
                .parse()
                .unwrap_or(3),
            retry_delay_ms: env::var("HTTP_RETRY_DELAY_MS")
                .unwrap_or_else(|_| "1000".to_string())
                .parse()
                .unwrap_or(1000),
            max_connections: env::var("HTTP_MAX_CONNECTIONS")
                .unwrap_or_else(|_| "100".to_string())
                .parse()
                .unwrap_or(100),
            keep_alive_timeout_seconds: env::var("HTTP_KEEP_ALIVE_TIMEOUT_SECONDS")
                .unwrap_or_else(|_| "90".to_string())
                .parse()
                .unwrap_or(90),
            pool_idle_timeout_seconds: env::var("HTTP_POOL_IDLE_TIMEOUT_SECONDS")
                .unwrap_or_else(|_| "30".to_string())
                .parse()
                .unwrap_or(30),
            user_agent: env::var("HTTP_USER_AGENT")
                .unwrap_or_else(|_| "keycloak-domain/0.1.0".to_string()),
        };

        let logging = LoggingConfig {
            level: env::var("LOG_LEVEL")
                .unwrap_or_else(|_| "info".to_string())
                .parse()
                .unwrap_or(LogLevel::Info),
            format: env::var("LOG_FORMAT")
                .unwrap_or_else(|_| "compact".to_string())
                .parse()
                .unwrap_or(LogFormat::Compact),
            enable_json: env::var("LOG_JSON")
                .unwrap_or_else(|_| "false".to_string())
                .parse()
                .unwrap_or(false),
            enable_colors: env::var("LOG_COLORS")
                .unwrap_or_else(|_| "true".to_string())
                .parse()
                .unwrap_or(true),
            log_requests: env::var("LOG_REQUESTS")
                .unwrap_or_else(|_| "true".to_string())
                .parse()
                .unwrap_or(true),
            log_responses: env::var("LOG_RESPONSES")
                .unwrap_or_else(|_| "false".to_string())
                .parse()
                .unwrap_or(false),
            sensitive_fields: env::var("LOG_SENSITIVE_FIELDS")
                .unwrap_or_else(|_| "password,secret,token,authorization,cookie".to_string())
                .split(',')
                .map(|s| s.trim().to_string())
                .collect(),
        };

        let config = AppConfig {
            environment,
            keycloak,
            auth,
            http,
            logging,
        };

        config.validate()?;
        Ok(config)
    }
}

/// String parsing implementations
impl std::str::FromStr for Environment {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "development" | "dev" => Ok(Environment::Development),
            "test" => Ok(Environment::Test),
            "staging" | "stage" => Ok(Environment::Staging),
            "production" | "prod" => Ok(Environment::Production),
            _ => Err(format!("Invalid environment: {s}")),
        }
    }
}

impl std::str::FromStr for LogLevel {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "trace" => Ok(LogLevel::Trace),
            "debug" => Ok(LogLevel::Debug),
            "info" => Ok(LogLevel::Info),
            "warn" => Ok(LogLevel::Warn),
            "error" => Ok(LogLevel::Error),
            _ => Err(format!("Invalid log level: {s}")),
        }
    }
}

impl std::str::FromStr for LogFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "compact" => Ok(LogFormat::Compact),
            "pretty" => Ok(LogFormat::Pretty),
            "json" => Ok(LogFormat::Json),
            "full" => Ok(LogFormat::Full),
            _ => Err(format!("Invalid log format: {s}")),
        }
    }
}
