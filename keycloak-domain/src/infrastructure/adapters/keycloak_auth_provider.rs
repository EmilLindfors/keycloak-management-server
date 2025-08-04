use async_trait::async_trait;
use keycloak::{KeycloakAdmin, KeycloakTokenSupplier};
use std::sync::Arc;

use crate::application::ports::auth::*;
use crate::application::ports::repository::KeycloakRepository;
use crate::domain::errors::*;

/// Keycloak authentication provider implementation
pub struct KeycloakAuthProvider<TS: KeycloakTokenSupplier> {
    token_manager: Arc<dyn TokenManager>,
    repository: Arc<dyn KeycloakRepository>,
    #[allow(dead_code)]
    keycloak_admin: Arc<KeycloakAdmin<TS>>,
}

impl<TS: KeycloakTokenSupplier + Send + Sync> KeycloakAuthProvider<TS> {
    pub fn new(
        token_manager: Arc<dyn TokenManager>,
        repository: Arc<dyn KeycloakRepository>,
        keycloak_admin: Arc<KeycloakAdmin<TS>>,
    ) -> Self {
        Self {
            token_manager,
            repository,
            keycloak_admin,
        }
    }
}

#[async_trait]
impl<TS: KeycloakTokenSupplier + Send + Sync> AuthenticationProvider for KeycloakAuthProvider<TS> {
    async fn authenticate_admin(
        &self,
        credentials: &AdminCredentials,
    ) -> Result<AuthorizationContext, AuthError> {
        // First acquire a token
        let token = self.token_manager.acquire_token(credentials).await?;

        // Get token info to extract user details
        let token_info = self.token_manager.introspect_token(&token.access_token).await?;

        if !token_info.active {
            return Err(AuthError::InvalidCredentials);
        }

        // Create authorization context
        let mut context = AuthorizationContext::new(credentials.realm.clone())
            .with_token(token);

        if let Some(username) = token_info.username {
            context = context.with_user(username);
        }

        if let Some(client_id) = token_info.client_id {
            context = context.with_client(client_id);
        }

        // Get user roles from Keycloak
        if let Some(ref user_id) = context.user_id {
            match self.get_user_roles(&credentials.realm, user_id).await {
                Ok(roles) => {
                    context = context.with_roles(roles);
                }
                Err(e) => {
                    tracing::warn!("Failed to get user roles: {}", e);
                    // Continue without roles for now
                }
            }
        }

        Ok(context)
    }

    async fn authenticate_service_account(
        &self,
        client_id: &str,
        client_secret: &str,
        realm: &str,
    ) -> Result<AuthorizationContext, AuthError> {
        let credentials = AdminCredentials::service_account(
            client_id.to_string(),
            client_secret.to_string(),
            realm.to_string(),
        );

        // Authenticate using service account credentials
        let token = self.token_manager.acquire_token(&credentials).await?;

        // Get token info
        let token_info = self.token_manager.introspect_token(&token.access_token).await?;

        if !token_info.active {
            return Err(AuthError::InvalidCredentials);
        }

        // Create context for service account
        let context = AuthorizationContext::new(realm.to_string())
            .with_client(client_id.to_string())
            .with_token(token)
            .with_roles(vec![
                "service-account".to_string(),
                format!("service-account-{}", client_id),
            ]);

        Ok(context)
    }

    async fn create_context_from_token(
        &self,
        token: &str,
        realm: &str,
    ) -> Result<AuthorizationContext, AuthError> {
        // Introspect the token to get user information
        let token_info = self.token_manager.introspect_token(token).await?;

        if !token_info.active {
            return Err(AuthError::TokenValidationFailed {
                reason: "Token is not active".to_string(),
            });
        }

        // Create basic auth token object
        let auth_token = AuthToken {
            access_token: token.to_string(),
            refresh_token: None,
            expires_at: token_info.exp.map(|exp| {
                chrono::DateTime::from_timestamp(exp, 0).unwrap_or_else(chrono::Utc::now)
            }).unwrap_or_else(|| chrono::Utc::now() + chrono::Duration::hours(1)),
            token_type: token_info.token_type.unwrap_or_else(|| "Bearer".to_string()),
            scope: token_info.scope,
        };

        let mut context = AuthorizationContext::new(realm.to_string())
            .with_token(auth_token);

        if let Some(username) = token_info.username {
            context = context.with_user(username);
        }

        if let Some(client_id) = token_info.client_id {
            context = context.with_client(client_id);
        }

        // Get user roles if we have a user
        if let Some(ref user_id) = context.user_id {
            match self.get_user_roles(realm, user_id).await {
                Ok(roles) => {
                    context = context.with_roles(roles);
                }
                Err(e) => {
                    tracing::warn!("Failed to get user roles for token context: {}", e);
                }
            }
        }

        Ok(context)
    }

    async fn refresh_context(
        &self,
        context: &AuthorizationContext,
    ) -> Result<AuthorizationContext, AuthError> {
        let token = context.token.as_ref().ok_or_else(|| {
            AuthError::TokenRefreshFailed {
                reason: "No token in context".to_string(),
            }
        })?;

        // Refresh the token
        let new_token = self.token_manager.refresh_token(token).await?;

        // Create new context with refreshed token
        let mut new_context = context.clone();
        new_context.token = Some(new_token);

        // Optionally refresh user roles
        if let Some(ref user_id) = new_context.user_id {
            match self.get_user_roles(&new_context.realm, user_id).await {
                Ok(roles) => {
                    new_context.roles = roles;
                }
                Err(e) => {
                    tracing::warn!("Failed to refresh user roles: {}", e);
                    // Keep existing roles
                }
            }
        }

        Ok(new_context)
    }
}

impl<TS: KeycloakTokenSupplier + Send + Sync> KeycloakAuthProvider<TS> {
    /// Helper method to get user roles from Keycloak
    async fn get_user_roles(&self, realm: &str, user_id: &str) -> Result<Vec<String>, AuthError> {
        match self.repository.get_user_role_mappings(realm, user_id).await {
            Ok(role_mapping) => {
                let mut roles = Vec::new();
                
                // Add realm roles
                roles.extend(role_mapping.realm_mappings.clone());
                
                // Add client roles
                for (client_id, client_roles) in role_mapping.client_mappings {
                    for role in client_roles {
                        roles.push(format!("{}:{}", client_id, role));
                    }
                }
                
                Ok(roles)
            }
            Err(e) => Err(AuthError::TokenValidationFailed {
                reason: format!("Failed to get user roles: {}", e),
            }),
        }
    }
}