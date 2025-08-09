/// Macros for simplifying authorization checks in service methods
/// 
/// These macros work with the AuthorizationHelper trait to provide
/// even cleaner and more readable authorization code.

/// Check authorization for a single resource:action pair
/// 
/// # Example
/// ```rust
/// authorize!(self, context, "users", "view");
/// ```
#[macro_export]
macro_rules! authorize {
    ($self:ident, $context:ident, $resource:expr, $action:expr) => {
        $self.check_permission($context, $resource, $action).await?
    };
}

/// Check authorization using constants from the domain layer
/// 
/// # Example
/// ```rust
/// authorize_const!(self, context, resources::USERS, actions::VIEW);
/// ```
#[macro_export]
macro_rules! authorize_const {
    ($self:ident, $context:ident, $resource:expr, $action:expr) => {
        $self.check_permission($context, $resource, $action).await?
    };
}

/// Check authorization with a custom error message
/// 
/// # Example
/// ```rust
/// authorize_with_msg!(self, context, "users", "delete", "Cannot delete users");
/// ```
#[macro_export]
macro_rules! authorize_with_msg {
    ($self:ident, $context:ident, $resource:expr, $action:expr, $message:expr) => {
        match $self.check_permission($context, $resource, $action).await {
            Ok(()) => {},
            Err(mut err) => {
                if let crate::domain::errors::DomainError::AuthorizationFailed { ref mut permission, .. } = err {
                    *permission = format!("{}: {}", $message, permission);
                }
                return Err(err);
            }
        }
    };
}

/// Require specific permissions for the current method
/// 
/// This is designed to be used at the beginning of service methods
/// to clearly document and enforce required permissions.
/// 
/// # Example
/// ```rust
/// #[instrument(skip(self))]
/// pub async fn delete_user(&self, realm: &str, user_id: &str, context: &AuthorizationContext) -> DomainResult<()> {
///     require_permissions!(self, context, users:delete);
///     
///     // Rest of method implementation...
/// }
/// ```
#[macro_export]
macro_rules! require_permissions {
    ($self:ident, $context:ident, $resource:ident : $action:ident) => {
        $self.check_permission($context, 
            crate::domain::constants::resources::stringify!($resource).to_uppercase(),
            crate::domain::constants::actions::stringify!($action).to_uppercase()
        ).await?
    };
    
    ($self:ident, $context:ident, $resource:expr, $action:expr) => {
        $self.check_permission($context, $resource, $action).await?
    };
}

/// Check multiple permissions - all must pass
/// 
/// # Example
/// ```rust
/// authorize_all!(self, context, [
///     ("users", "view"),
///     ("groups", "view")
/// ]);
/// ```
#[macro_export]
macro_rules! authorize_all {
    ($self:ident, $context:ident, [$(($resource:expr, $action:expr)),* $(,)?]) => {
        $(
            $self.check_permission($context, $resource, $action).await?;
        )*
    };
}

/// Check permissions - any one can pass (OR logic)
/// 
/// # Example
/// ```rust
/// authorize_any!(self, context, [
///     ("users", "admin"),
///     ("users", "manage")
/// ], "Need either admin or manage permissions for users");
/// ```
#[macro_export]
macro_rules! authorize_any {
    ($self:ident, $context:ident, [$(($resource:expr, $action:expr)),* $(,)?], $error_msg:expr) => {
        {
            let mut all_failed = true;
            $(
                if $self.check_permission($context, $resource, $action).await.is_ok() {
                    all_failed = false;
                }
            )*
            if all_failed {
                return Err(crate::domain::errors::DomainError::AuthorizationFailed {
                    user_id: $context.user_id.clone().unwrap_or_default(),
                    permission: format!("{}", $error_msg),
                });
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::services::AuthorizationHelper;
    use crate::application::ports::{auth::AuthorizationContext, AuthorizationService};
    use crate::domain::errors::{DomainError, DomainResult};
    use async_trait::async_trait;
    use std::sync::Arc;

    struct TestService {
        auth_service: Arc<dyn AuthorizationService>,
    }

    #[async_trait]
    impl AuthorizationHelper for TestService {
        fn auth_service(&self) -> &Arc<dyn AuthorizationService> {
            &self.auth_service
        }
    }

    // Note: These would be integration tests that require a mock AuthorizationService
    // The tests would verify that the macros generate the correct authorization calls
}