use crate::{
    application::ports::*,
    domain::errors::{DomainError, DomainResult},
};
use std::sync::Arc;
use tracing::{error, info, instrument, warn};

/// Authentication service implementing business use cases for authentication and authorization
pub struct AuthenticationService {
    token_manager: Arc<dyn TokenManager>,
    auth_provider: Arc<dyn AuthenticationProvider>,
    auth_service: Arc<dyn AuthorizationService>,
    event_publisher: Arc<dyn EventPublisher>,
}

impl AuthenticationService {
    pub fn new(
        token_manager: Arc<dyn TokenManager>,
        auth_provider: Arc<dyn AuthenticationProvider>,
        auth_service: Arc<dyn AuthorizationService>,
        event_publisher: Arc<dyn EventPublisher>,
    ) -> Self {
        Self {
            token_manager,
            auth_provider,
            auth_service,
            event_publisher,
        }
    }

    /// Authenticate admin user with username/password
    #[instrument(skip(self, credentials), fields(username = %credentials.username, realm = %credentials.realm))]
    pub async fn authenticate_admin(
        &self,
        credentials: &AdminCredentials,
    ) -> DomainResult<AuthorizationContext> {
        info!(
            "Authenticating admin user '{}' in realm '{}'",
            credentials.username, credentials.realm
        );

        // Attempt authentication
        match self.auth_provider.authenticate_admin(credentials).await {
            Ok(context) => {
                info!(
                    "Admin authentication successful for user '{}' in realm '{}'",
                    credentials.username, credentials.realm
                );

                // Publish success event
                let event = DomainEvent::admin_login_successful(
                    context
                        .user_id
                        .clone()
                        .unwrap_or_else(|| "unknown".to_string()),
                    credentials.username.clone(),
                    credentials.realm.clone(),
                );

                if let Err(e) = self.event_publisher.publish(event).await {
                    warn!("Failed to publish admin login successful event: {}", e);
                }

                Ok(context)
            }
            Err(auth_error) => {
                error!(
                    "Admin authentication failed for user '{}' in realm '{}': {}",
                    credentials.username, credentials.realm, auth_error
                );

                // Publish failure event
                let event = DomainEvent::new(
                    EventType::AdminLoginFailed,
                    "unknown".to_string(),
                    AggregateType::Session,
                    credentials.realm.clone(),
                    EventData::AdminLoginFailed {
                        username: credentials.username.clone(),
                        realm: credentials.realm.clone(),
                        reason: auth_error.to_string(),
                    },
                );

                if let Err(e) = self.event_publisher.publish(event).await {
                    warn!("Failed to publish admin login failed event: {}", e);
                }

                Err(DomainError::from(auth_error))
            }
        }
    }

    /// Authenticate service account with client credentials
    #[instrument(skip(self, client_secret), fields(client_id = %client_id, realm = %realm))]
    pub async fn authenticate_service_account(
        &self,
        client_id: &str,
        client_secret: &str,
        realm: &str,
    ) -> DomainResult<AuthorizationContext> {
        info!(
            "Authenticating service account '{}' in realm '{}'",
            client_id, realm
        );

        match self
            .auth_provider
            .authenticate_service_account(client_id, client_secret, realm)
            .await
        {
            Ok(context) => {
                info!(
                    "Service account authentication successful for client '{}' in realm '{}'",
                    client_id, realm
                );

                // Publish success event
                let event = DomainEvent::admin_login_successful(
                    context
                        .user_id
                        .clone()
                        .unwrap_or_else(|| client_id.to_string()),
                    client_id.to_string(),
                    realm.to_string(),
                );

                if let Err(e) = self.event_publisher.publish(event).await {
                    warn!(
                        "Failed to publish service account login successful event: {}",
                        e
                    );
                }

                Ok(context)
            }
            Err(auth_error) => {
                error!(
                    "Service account authentication failed for client '{}' in realm '{}': {}",
                    client_id, realm, auth_error
                );

                // Publish failure event
                let event = DomainEvent::new(
                    EventType::AdminLoginFailed,
                    client_id.to_string(),
                    AggregateType::Session,
                    realm.to_string(),
                    EventData::AdminLoginFailed {
                        username: client_id.to_string(),
                        realm: realm.to_string(),
                        reason: auth_error.to_string(),
                    },
                );

                if let Err(e) = self.event_publisher.publish(event).await {
                    warn!(
                        "Failed to publish service account login failed event: {}",
                        e
                    );
                }

                Err(DomainError::from(auth_error))
            }
        }
    }

    /// Create authorization context from an existing token
    #[instrument(skip(self, token), fields(realm = %realm))]
    pub async fn create_context_from_token(
        &self,
        token: &str,
        realm: &str,
    ) -> DomainResult<AuthorizationContext> {
        info!(
            "Creating authorization context from token for realm '{}'",
            realm
        );

        match self
            .auth_provider
            .create_context_from_token(token, realm)
            .await
        {
            Ok(context) => {
                info!(
                    "Successfully created authorization context from token for realm '{}'",
                    realm
                );
                Ok(context)
            }
            Err(auth_error) => {
                error!(
                    "Failed to create authorization context from token for realm '{}': {}",
                    realm, auth_error
                );
                Err(DomainError::from(auth_error))
            }
        }
    }

    /// Refresh an authentication context
    #[instrument(skip(self, context), fields(realm = %context.realm, user_id = ?context.user_id))]
    pub async fn refresh_context(
        &self,
        context: &AuthorizationContext,
    ) -> DomainResult<AuthorizationContext> {
        info!(
            "Refreshing authorization context for realm '{}'",
            context.realm
        );

        match self.auth_provider.refresh_context(context).await {
            Ok(refreshed_context) => {
                info!(
                    "Successfully refreshed authorization context for realm '{}'",
                    context.realm
                );

                // Publish token refresh event
                if let Some(ref user_id) = context.user_id {
                    let event = DomainEvent::new(
                        EventType::TokenRefreshed,
                        user_id.clone(),
                        AggregateType::Session,
                        context.realm.clone(),
                        EventData::TokenRefreshed {
                            username: user_id.clone(),
                            realm: context.realm.clone(),
                        },
                    );

                    if let Err(e) = self.event_publisher.publish(event).await {
                        warn!("Failed to publish token refreshed event: {}", e);
                    }
                }

                Ok(refreshed_context)
            }
            Err(auth_error) => {
                error!(
                    "Failed to refresh authorization context for realm '{}': {}",
                    context.realm, auth_error
                );
                Err(DomainError::from(auth_error))
            }
        }
    }

    /// Acquire a new token using credentials
    #[instrument(skip(self, credentials), fields(username = %credentials.username, realm = %credentials.realm))]
    pub async fn acquire_token(&self, credentials: &AdminCredentials) -> DomainResult<AuthToken> {
        info!(
            "Acquiring token for user '{}' in realm '{}'",
            credentials.username, credentials.realm
        );

        match self.token_manager.acquire_token(credentials).await {
            Ok(token) => {
                info!(
                    "Successfully acquired token for user '{}' in realm '{}', expires at {}",
                    credentials.username, credentials.realm, token.expires_at
                );
                Ok(token)
            }
            Err(auth_error) => {
                error!(
                    "Failed to acquire token for user '{}' in realm '{}': {}",
                    credentials.username, credentials.realm, auth_error
                );
                Err(DomainError::from(auth_error))
            }
        }
    }

    /// Refresh an existing token
    #[instrument(skip(self, token), fields(token_type = %token.token_type, expires_at = %token.expires_at))]
    pub async fn refresh_token(&self, token: &AuthToken) -> DomainResult<AuthToken> {
        info!("Refreshing token that expires at {}", token.expires_at);

        // Check if token can be refreshed
        if token.refresh_token.is_none() {
            return Err(DomainError::InvalidToken {
                reason: "Token does not have a refresh token".to_string(),
            });
        }

        match self.token_manager.refresh_token(token).await {
            Ok(new_token) => {
                info!(
                    "Successfully refreshed token, new expiry: {}",
                    new_token.expires_at
                );
                Ok(new_token)
            }
            Err(auth_error) => {
                error!("Failed to refresh token: {}", auth_error);
                Err(DomainError::from(auth_error))
            }
        }
    }

    /// Validate a token
    #[instrument(skip(self, token), fields(token_type = %token.token_type, expires_at = %token.expires_at))]
    pub async fn validate_token(&self, token: &AuthToken) -> DomainResult<bool> {
        // First check local expiry
        if token.is_expired() {
            info!("Token is expired locally (expired at {})", token.expires_at);
            return Ok(false);
        }

        match self.token_manager.validate_token(token).await {
            Ok(is_valid) => {
                info!("Token validation result: {}", is_valid);
                Ok(is_valid)
            }
            Err(auth_error) => {
                error!("Failed to validate token: {}", auth_error);
                Err(DomainError::from(auth_error))
            }
        }
    }

    /// Revoke a token (logout)
    #[instrument(skip(self, token), fields(token_type = %token.token_type))]
    pub async fn revoke_token(&self, token: &AuthToken) -> DomainResult<()> {
        info!("Revoking token");

        match self.token_manager.revoke_token(token).await {
            Ok(()) => {
                info!("Successfully revoked token");
                Ok(())
            }
            Err(auth_error) => {
                error!("Failed to revoke token: {}", auth_error);
                Err(DomainError::from(auth_error))
            }
        }
    }

    /// Get token information via introspection
    #[instrument(skip(self, token))]
    pub async fn introspect_token(&self, token: &str) -> DomainResult<TokenInfo> {
        info!("Introspecting token");

        match self.token_manager.introspect_token(token).await {
            Ok(token_info) => {
                info!(
                    "Token introspection successful, active: {}",
                    token_info.active
                );
                Ok(token_info)
            }
            Err(auth_error) => {
                error!("Failed to introspect token: {}", auth_error);
                Err(DomainError::from(auth_error))
            }
        }
    }

    /// Check if context has permission for a resource and action
    #[instrument(skip(self, context), fields(realm = %context.realm, user_id = ?context.user_id, resource = %resource, action = %action))]
    pub async fn check_permission(
        &self,
        context: &AuthorizationContext,
        resource: &str,
        action: &str,
    ) -> DomainResult<bool> {
        match self
            .auth_service
            .check_permission(context, resource, action)
            .await
        {
            Ok(has_permission) => {
                info!(
                    "Permission check result for {}:{} = {}",
                    resource, action, has_permission
                );
                Ok(has_permission)
            }
            Err(auth_error) => {
                error!(
                    "Failed to check permission for {}:{}: {}",
                    resource, action, auth_error
                );
                Err(DomainError::from(auth_error))
            }
        }
    }

    /// Get all permissions for a user in a realm
    #[instrument(skip(self), fields(realm = %realm, user_id = %user_id))]
    pub async fn get_user_permissions(
        &self,
        realm: &str,
        user_id: &str,
    ) -> DomainResult<Vec<Permission>> {
        info!(
            "Getting permissions for user '{}' in realm '{}'",
            user_id, realm
        );

        match self.auth_service.get_user_permissions(realm, user_id).await {
            Ok(permissions) => {
                info!(
                    "Found {} permissions for user '{}' in realm '{}'",
                    permissions.len(),
                    user_id,
                    realm
                );
                Ok(permissions)
            }
            Err(auth_error) => {
                error!(
                    "Failed to get permissions for user '{}' in realm '{}': {}",
                    user_id, realm, auth_error
                );
                Err(DomainError::from(auth_error))
            }
        }
    }

    /// Check if user has a specific realm role
    #[instrument(skip(self, context), fields(realm = %context.realm, user_id = ?context.user_id, role = %role))]
    pub async fn has_realm_role(
        &self,
        context: &AuthorizationContext,
        role: &str,
    ) -> DomainResult<bool> {
        match self.auth_service.has_realm_role(context, role).await {
            Ok(has_role) => {
                info!("Realm role check for '{}' = {}", role, has_role);
                Ok(has_role)
            }
            Err(auth_error) => {
                error!("Failed to check realm role '{}': {}", role, auth_error);
                Err(DomainError::from(auth_error))
            }
        }
    }

    /// Check if user has a specific client role
    #[instrument(skip(self, context), fields(realm = %context.realm, user_id = ?context.user_id, client_id = %client_id, role = %role))]
    pub async fn has_client_role(
        &self,
        context: &AuthorizationContext,
        client_id: &str,
        role: &str,
    ) -> DomainResult<bool> {
        match self
            .auth_service
            .has_client_role(context, client_id, role)
            .await
        {
            Ok(has_role) => {
                info!(
                    "Client role check for client '{}' role '{}' = {}",
                    client_id, role, has_role
                );
                Ok(has_role)
            }
            Err(auth_error) => {
                error!(
                    "Failed to check client role for client '{}' role '{}': {}",
                    client_id, role, auth_error
                );
                Err(DomainError::from(auth_error))
            }
        }
    }

    /// Get effective roles for a user (including composite roles)
    #[instrument(skip(self), fields(realm = %realm, user_id = %user_id))]
    pub async fn get_effective_roles(
        &self,
        realm: &str,
        user_id: &str,
    ) -> DomainResult<Vec<String>> {
        info!(
            "Getting effective roles for user '{}' in realm '{}'",
            user_id, realm
        );

        match self.auth_service.get_effective_roles(realm, user_id).await {
            Ok(roles) => {
                info!(
                    "Found {} effective roles for user '{}' in realm '{}'",
                    roles.len(),
                    user_id,
                    realm
                );
                Ok(roles)
            }
            Err(auth_error) => {
                error!(
                    "Failed to get effective roles for user '{}' in realm '{}': {}",
                    user_id, realm, auth_error
                );
                Err(DomainError::from(auth_error))
            }
        }
    }

    /// Check if a token needs refreshing (expires within threshold)
    pub fn should_refresh_token(&self, token: &AuthToken, threshold_seconds: i64) -> bool {
        token.is_expiring_soon(threshold_seconds)
    }

    /// Get time until token expiry
    pub fn time_until_token_expiry(&self, token: &AuthToken) -> chrono::Duration {
        token.time_until_expiry()
    }

    /// Create a basic authorization context for system operations
    pub fn create_system_context(&self, realm: &str) -> AuthorizationContext {
        AuthorizationContext::new(realm.to_string())
            .with_user("system".to_string())
            .with_roles(vec![
                "system".to_string(),
                "admin".to_string(),
                "realm-admin".to_string(),
            ])
    }

    /// Create an authorization context with elevated privileges for internal operations
    pub fn create_elevated_context(&self, realm: &str, user_id: &str) -> AuthorizationContext {
        AuthorizationContext::new(realm.to_string())
            .with_user(user_id.to_string())
            .with_roles(vec!["realm-admin".to_string(), "admin".to_string()])
    }

    /// Validate that a context is not expired
    pub async fn ensure_context_valid(&self, context: &AuthorizationContext) -> DomainResult<()> {
        if let Some(ref token) = context.token {
            if token.is_expired() {
                return Err(DomainError::TokenExpired {
                    expired_at: token.expires_at,
                });
            }

            // Optionally validate with the token manager
            if !self.validate_token(token).await? {
                return Err(DomainError::InvalidToken {
                    reason: "Token validation failed".to_string(),
                });
            }
        }
        Ok(())
    }
}
