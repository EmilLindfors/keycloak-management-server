use crate::domain::errors::AuthError;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Authentication token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthToken {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub token_type: String,
    pub scope: Option<String>,
}

impl AuthToken {
    pub fn new(
        access_token: String,
        expires_in: i64,
        refresh_token: Option<String>,
        token_type: Option<String>,
    ) -> Self {
        Self {
            access_token,
            refresh_token,
            expires_at: Utc::now() + chrono::Duration::seconds(expires_in),
            token_type: token_type.unwrap_or_else(|| "Bearer".to_string()),
            scope: None,
        }
    }

    pub fn is_expired(&self) -> bool {
        Utc::now() >= self.expires_at
    }

    pub fn is_expiring_soon(&self, seconds: i64) -> bool {
        Utc::now() + chrono::Duration::seconds(seconds) >= self.expires_at
    }

    pub fn time_until_expiry(&self) -> chrono::Duration {
        self.expires_at - Utc::now()
    }
}

/// Admin credentials for Keycloak authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminCredentials {
    pub username: String,
    pub password: String,
    pub realm: String,
    pub client_id: String,
    pub grant_type: String,
}

impl AdminCredentials {
    pub fn new(username: String, password: String, realm: String, client_id: String) -> Self {
        Self {
            username,
            password,
            realm,
            client_id,
            grant_type: "password".to_string(),
        }
    }

    pub fn service_account(client_id: String, client_secret: String, realm: String) -> Self {
        Self {
            username: client_id.clone(),
            password: client_secret,
            realm,
            client_id,
            grant_type: "client_credentials".to_string(),
        }
    }
}

/// Token management port
#[async_trait]
pub trait TokenManager: Send + Sync {
    /// Acquire a new token using credentials
    async fn acquire_token(&self, credentials: &AdminCredentials) -> Result<AuthToken, AuthError>;

    /// Refresh an existing token
    async fn refresh_token(&self, token: &AuthToken) -> Result<AuthToken, AuthError>;

    /// Validate a token (check if it's valid and not expired)
    async fn validate_token(&self, token: &AuthToken) -> Result<bool, AuthError>;

    /// Revoke a token (logout)
    async fn revoke_token(&self, token: &AuthToken) -> Result<(), AuthError>;

    /// Get token info/introspection
    async fn introspect_token(&self, token: &str) -> Result<TokenInfo, AuthError>;
}

/// Token introspection information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenInfo {
    pub active: bool,
    pub scope: Option<String>,
    pub client_id: Option<String>,
    pub username: Option<String>,
    pub token_type: Option<String>,
    pub exp: Option<i64>,
    pub iat: Option<i64>,
    pub sub: Option<String>,
    pub aud: Option<String>,
    pub iss: Option<String>,
    pub jti: Option<String>,
}

/// Authorization context for permission checks
#[derive(Debug, Clone)]
pub struct AuthorizationContext {
    pub user_id: Option<String>,
    pub realm: String,
    pub client_id: Option<String>,
    pub roles: Vec<String>,
    pub permissions: Vec<Permission>,
    pub token: Option<AuthToken>,
}

impl AuthorizationContext {
    pub fn new(realm: String) -> Self {
        Self {
            user_id: None,
            realm,
            client_id: None,
            roles: Vec::new(),
            permissions: Vec::new(),
            token: None,
        }
    }

    pub fn with_user(mut self, user_id: String) -> Self {
        self.user_id = Some(user_id);
        self
    }

    pub fn with_client(mut self, client_id: String) -> Self {
        self.client_id = Some(client_id);
        self
    }

    pub fn with_roles(mut self, roles: Vec<String>) -> Self {
        self.roles = roles;
        self
    }

    pub fn with_token(mut self, token: AuthToken) -> Self {
        self.token = Some(token);
        self
    }

    pub fn has_role(&self, role: &str) -> bool {
        self.roles.iter().any(|r| r == role)
    }

    pub fn has_any_role(&self, roles: &[String]) -> bool {
        roles.iter().any(|role| self.has_role(role))
    }

    pub fn has_permission(&self, resource: &str, action: &str) -> bool {
        self.permissions.iter().any(|p| p.matches(resource, action))
    }
}

/// Permission definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Permission {
    pub resource: String,
    pub action: String,
    pub effect: PermissionEffect,
}

impl Permission {
    pub fn allow(resource: String, action: String) -> Self {
        Self {
            resource,
            action,
            effect: PermissionEffect::Allow,
        }
    }

    pub fn deny(resource: String, action: String) -> Self {
        Self {
            resource,
            action,
            effect: PermissionEffect::Deny,
        }
    }

    pub fn matches(&self, resource: &str, action: &str) -> bool {
        (self.resource == "*" || self.resource == resource)
            && (self.action == "*" || self.action == action)
    }
}

/// Permission effect
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PermissionEffect {
    Allow,
    Deny,
}

/// Authorization service port
#[async_trait]
pub trait AuthorizationService: Send + Sync {
    /// Check if the context has permission to perform an action
    async fn check_permission(
        &self,
        context: &AuthorizationContext,
        resource: &str,
        action: &str,
    ) -> Result<bool, AuthError>;

    /// Get all permissions for a user in a realm
    async fn get_user_permissions(
        &self,
        realm: &str,
        user_id: &str,
    ) -> Result<Vec<Permission>, AuthError>;

    /// Check if user has a specific realm role
    async fn has_realm_role(
        &self,
        context: &AuthorizationContext,
        role: &str,
    ) -> Result<bool, AuthError>;

    /// Check if user has a specific client role
    async fn has_client_role(
        &self,
        context: &AuthorizationContext,
        client_id: &str,
        role: &str,
    ) -> Result<bool, AuthError>;

    /// Get effective roles for a user (including composite roles)
    async fn get_effective_roles(
        &self,
        realm: &str,
        user_id: &str,
    ) -> Result<Vec<String>, AuthError>;
}

/// Authentication provider port
#[async_trait]
pub trait AuthenticationProvider: Send + Sync {
    /// Authenticate admin user and return context
    async fn authenticate_admin(
        &self,
        credentials: &AdminCredentials,
    ) -> Result<AuthorizationContext, AuthError>;

    /// Authenticate service account and return context
    async fn authenticate_service_account(
        &self,
        client_id: &str,
        client_secret: &str,
        realm: &str,
    ) -> Result<AuthorizationContext, AuthError>;

    /// Validate and create context from existing token
    async fn create_context_from_token(
        &self,
        token: &str,
        realm: &str,
    ) -> Result<AuthorizationContext, AuthError>;

    /// Refresh authentication context
    async fn refresh_context(
        &self,
        context: &AuthorizationContext,
    ) -> Result<AuthorizationContext, AuthError>;
}

/// Action definitions for authorization
pub mod actions {
    pub const CREATE: &str = "create";
    pub const READ: &str = "read";
    pub const UPDATE: &str = "update";
    pub const DELETE: &str = "delete";
    pub const MANAGE: &str = "manage";
    pub const VIEW: &str = "view";
    pub const IMPERSONATE: &str = "impersonate";
    pub const MAP_ROLES: &str = "map_roles";
    pub const MANAGE_GROUP_MEMBERSHIP: &str = "manage_group_membership";
}

/// Resource definitions for authorization
pub mod resources {
    pub const USERS: &str = "users";
    pub const REALMS: &str = "realms";
    pub const CLIENTS: &str = "clients";
    pub const GROUPS: &str = "groups";
    pub const ROLES: &str = "roles";
    pub const IDENTITY_PROVIDERS: &str = "identity_providers";
    pub const EVENTS: &str = "events";
    pub const SESSIONS: &str = "sessions";
    pub const CLIENT_SCOPES: &str = "client_scopes";
}

/// Common authorization checks
impl AuthorizationContext {
    pub fn can_manage_users(&self) -> bool {
        self.has_permission(resources::USERS, actions::MANAGE)
            || (self.has_permission(resources::USERS, actions::CREATE)
                && self.has_permission(resources::USERS, actions::UPDATE)
                && self.has_permission(resources::USERS, actions::DELETE))
    }

    pub fn can_view_users(&self) -> bool {
        self.has_permission(resources::USERS, actions::VIEW)
            || self.has_permission(resources::USERS, actions::READ)
            || self.can_manage_users()
    }

    pub fn can_manage_realm(&self) -> bool {
        self.has_permission(resources::REALMS, actions::MANAGE)
            || self.has_role("realm-admin")
            || self.has_role("admin")
    }

    pub fn can_impersonate_users(&self) -> bool {
        self.has_permission(resources::USERS, actions::IMPERSONATE)
            || self.has_role("impersonation")
    }
}
