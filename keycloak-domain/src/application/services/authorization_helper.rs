use crate::{
    application::ports::{auth::AuthorizationService, AuthorizationContext},
    domain::errors::{DomainError, DomainResult},
};
use async_trait::async_trait;
use std::sync::Arc;

/// Trait providing centralized authorization checking for all services
#[async_trait]
pub trait AuthorizationHelper {
    /// Get the authorization service instance
    fn auth_service(&self) -> &Arc<dyn AuthorizationService>;

    /// Check permissions and return AuthorizationFailed if denied
    async fn check_permission(&self, context: &AuthorizationContext, resource: &str, action: &str) -> DomainResult<()> {
        let has_permission = self.auth_service()
            .check_permission(context, resource, action)
            .await
            .map_err(|_e| DomainError::AuthorizationFailed {
                user_id: context.user_id.clone().unwrap_or_default(),
                permission: format!("{}:{}", resource, action),
            })?;
        
        if !has_permission {
            return Err(DomainError::AuthorizationFailed {
                user_id: context.user_id.clone().unwrap_or_default(),
                permission: format!("{}:{}", resource, action),
            });
        }
        
        Ok(())
    }
}