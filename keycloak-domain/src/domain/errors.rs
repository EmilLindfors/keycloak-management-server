use thiserror::Error;

/// Domain-specific errors for Keycloak operations
#[derive(Error, Debug)]
pub enum DomainError {
    #[error("User not found: {user_id} in realm {realm}")]
    UserNotFound { user_id: String, realm: String },

    #[error("Realm not found: {realm}")]
    RealmNotFound { realm: String },

    #[error("Client not found: {client_id} in realm {realm}")]
    ClientNotFound { client_id: String, realm: String },

    #[error("Group not found: {group_id} in realm {realm}")]
    GroupNotFound { group_id: String, realm: String },

    #[error("Role not found: {role_name} in realm {realm}")]
    RoleNotFound { role_name: String, realm: String },

    #[error("Invalid username: {reason}")]
    InvalidUsername { reason: String },

    #[error("Invalid email address: {email}")]
    InvalidEmail { email: String },

    #[error("Invalid password: {reason}")]
    InvalidPassword { reason: String },

    #[error("User already exists: {username} in realm {realm}")]
    UserAlreadyExists { username: String, realm: String },

    #[error("Realm already exists: {realm}")]
    RealmAlreadyExists { realm: String },

    #[error("Client already exists: {client_id} in realm {realm}")]
    ClientAlreadyExists { client_id: String, realm: String },

    #[error("Authentication failed: {reason}")]
    AuthenticationFailed { reason: String },

    #[error("Authorization failed: user {user_id} lacks permission {permission}")]
    AuthorizationFailed { user_id: String, permission: String },

    #[error("Token expired at {expired_at}")]
    TokenExpired {
        expired_at: chrono::DateTime<chrono::Utc>,
    },

    #[error("Invalid token: {reason}")]
    InvalidToken { reason: String },

    #[error("Configuration error: {message}")]
    Configuration { message: String },

    #[error("Validation error: {field} - {message}")]
    Validation { field: String, message: String },

    #[error("External service error: {service} - {message}")]
    ExternalService { service: String, message: String },

    #[error("Serialization error: {message}")]
    Serialization { message: String },

    #[error("{entity_type} already exists: {identifier}")]
    AlreadyExists {
        entity_type: String,
        identifier: String,
    },

    #[error("Business rule violation: {rule} - {context}")]
    BusinessRule { rule: String, context: String },
}

/// Result type for domain operations
pub type DomainResult<T> = Result<T, DomainError>;

/// Authentication-specific errors
#[derive(Error, Debug)]
pub enum AuthError {
    #[error("Invalid credentials")]
    InvalidCredentials,

    #[error("Token acquisition failed: {reason}")]
    TokenAcquisitionFailed { reason: String },

    #[error("Token refresh failed: {reason}")]
    TokenRefreshFailed { reason: String },

    #[error("Token validation failed: {reason}")]
    TokenValidationFailed { reason: String },

    #[error("Insufficient permissions for action: {action}")]
    InsufficientPermissions { action: String },
}

impl From<AuthError> for DomainError {
    fn from(err: AuthError) -> Self {
        match err {
            AuthError::InvalidCredentials => DomainError::AuthenticationFailed {
                reason: "Invalid credentials".to_string(),
            },
            AuthError::TokenAcquisitionFailed { reason } => {
                DomainError::AuthenticationFailed { reason }
            }
            AuthError::TokenRefreshFailed { reason } => DomainError::InvalidToken { reason },
            AuthError::TokenValidationFailed { reason } => DomainError::InvalidToken { reason },
            AuthError::InsufficientPermissions { action } => DomainError::AuthorizationFailed {
                user_id: "unknown".to_string(),
                permission: action,
            },
        }
    }
}

/// Repository-specific errors
#[derive(Error, Debug)]
pub enum RepositoryError {
    #[error("Connection failed: {message}")]
    ConnectionFailed { message: String },

    #[error("Query failed: {query} - {message}")]
    QueryFailed { query: String, message: String },

    #[error("Serialization failed: {message}")]
    SerializationFailed { message: String },

    #[error("Network error: {message}")]
    NetworkError { message: String },

    #[error("Timeout after {seconds} seconds")]
    Timeout { seconds: u64 },
}

impl From<RepositoryError> for DomainError {
    fn from(err: RepositoryError) -> Self {
        match err {
            RepositoryError::ConnectionFailed { message } => DomainError::ExternalService {
                service: "Keycloak".to_string(),
                message,
            },
            RepositoryError::QueryFailed { message, .. } => DomainError::ExternalService {
                service: "Keycloak".to_string(),
                message,
            },
            RepositoryError::SerializationFailed { message } => {
                DomainError::Serialization { message }
            }
            RepositoryError::NetworkError { message } => DomainError::ExternalService {
                service: "Keycloak".to_string(),
                message,
            },
            RepositoryError::Timeout { seconds } => DomainError::ExternalService {
                service: "Keycloak".to_string(),
                message: format!("Request timed out after {seconds} seconds"),
            },
        }
    }
}

/// Configuration-specific errors
#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Missing required configuration: {key}")]
    MissingRequired { key: String },

    #[error("Invalid configuration value for {key}: {message}")]
    InvalidValue { key: String, message: String },

    #[error("Configuration file error: {message}")]
    FileError { message: String },
}

impl From<ConfigError> for DomainError {
    fn from(err: ConfigError) -> Self {
        match err {
            ConfigError::MissingRequired { key } => DomainError::Configuration {
                message: format!("Missing required configuration: {key}"),
            },
            ConfigError::InvalidValue { key, message } => DomainError::Configuration {
                message: format!("Invalid value for {key}: {message}"),
            },
            ConfigError::FileError { message } => DomainError::Configuration { message },
        }
    }
}
