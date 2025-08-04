use async_trait::async_trait;
use keycloak::{KeycloakAdmin, KeycloakTokenSupplier};
use std::sync::Arc;

use crate::application::ports::auth::*;
use crate::application::ports::repository::KeycloakRepository;
use crate::domain::errors::*;

/// Keycloak authorization service implementation
pub struct KeycloakAuthorizationService<TS: KeycloakTokenSupplier> {
    repository: Arc<dyn KeycloakRepository>,
    #[allow(dead_code)]
    keycloak_admin: Arc<KeycloakAdmin<TS>>,
}

impl<TS: KeycloakTokenSupplier + Send + Sync> KeycloakAuthorizationService<TS> {
    pub fn new(
        repository: Arc<dyn KeycloakRepository>,
        keycloak_admin: Arc<KeycloakAdmin<TS>>,
    ) -> Self {
        Self {
            repository,
            keycloak_admin,
        }
    }
}

#[async_trait]
impl<TS: KeycloakTokenSupplier + Send + Sync> AuthorizationService for KeycloakAuthorizationService<TS> {
    async fn check_permission(
        &self,
        context: &AuthorizationContext,
        resource: &str,
        action: &str,
    ) -> Result<bool, AuthError> {
        // First check local permissions in context
        if context.has_permission(resource, action) {
            return Ok(true);
        }

        // Check role-based permissions
        match (resource, action) {
            // User management permissions
            (resources::USERS, actions::MANAGE) => {
                Ok(context.has_role("realm-admin") 
                   || context.has_role("admin")
                   || context.has_role("manage-users"))
            }
            (resources::USERS, actions::VIEW) | (resources::USERS, actions::READ) => {
                Ok(context.has_role("realm-admin")
                   || context.has_role("admin")
                   || context.has_role("manage-users")
                   || context.has_role("view-users"))
            }
            (resources::USERS, actions::CREATE) => {
                Ok(context.has_role("realm-admin")
                   || context.has_role("admin")
                   || context.has_role("manage-users"))
            }
            (resources::USERS, actions::UPDATE) => {
                Ok(context.has_role("realm-admin")
                   || context.has_role("admin")
                   || context.has_role("manage-users"))
            }
            (resources::USERS, actions::DELETE) => {
                Ok(context.has_role("realm-admin")
                   || context.has_role("admin")
                   || context.has_role("manage-users"))
            }
            (resources::USERS, actions::IMPERSONATE) => {
                Ok(context.has_role("realm-admin")
                   || context.has_role("admin")
                   || context.has_role("impersonation"))
            }

            // Realm management permissions
            (resources::REALMS, actions::MANAGE) => {
                Ok(context.has_role("admin") || context.has_role("realm-admin"))
            }
            (resources::REALMS, actions::VIEW) | (resources::REALMS, actions::READ) => {
                Ok(context.has_role("admin") 
                   || context.has_role("realm-admin")
                   || context.has_role("view-realm"))
            }

            // Client management permissions
            (resources::CLIENTS, actions::MANAGE) => {
                Ok(context.has_role("realm-admin")
                   || context.has_role("admin")
                   || context.has_role("manage-clients"))
            }
            (resources::CLIENTS, actions::VIEW) | (resources::CLIENTS, actions::READ) => {
                Ok(context.has_role("realm-admin")
                   || context.has_role("admin")
                   || context.has_role("manage-clients")
                   || context.has_role("view-clients"))
            }

            // Group management permissions
            (resources::GROUPS, actions::MANAGE) => {
                Ok(context.has_role("realm-admin")
                   || context.has_role("admin")
                   || context.has_role("manage-users"))
            }
            (resources::GROUPS, actions::VIEW) | (resources::GROUPS, actions::READ) => {
                Ok(context.has_role("realm-admin")
                   || context.has_role("admin")
                   || context.has_role("manage-users")
                   || context.has_role("view-users"))
            }

            // Role management permissions
            (resources::ROLES, actions::MANAGE) => {
                Ok(context.has_role("realm-admin")
                   || context.has_role("admin")
                   || context.has_role("manage-realm"))
            }
            (resources::ROLES, actions::VIEW) | (resources::ROLES, actions::READ) => {
                Ok(context.has_role("realm-admin")
                   || context.has_role("admin")
                   || context.has_role("manage-realm")
                   || context.has_role("view-realm"))
            }

            // Events permissions
            (resources::EVENTS, actions::VIEW) | (resources::EVENTS, actions::READ) => {
                Ok(context.has_role("realm-admin")
                   || context.has_role("admin")
                   || context.has_role("view-events"))
            }

            // Default deny
            _ => Ok(false),
        }
    }

    async fn get_user_permissions(
        &self,
        realm: &str,
        user_id: &str,
    ) -> Result<Vec<Permission>, AuthError> {
        // Get user role mappings from Keycloak
        let role_mapping = self
            .repository
            .get_user_role_mappings(realm, user_id)
            .await
            .map_err(|_e| AuthError::InsufficientPermissions {
                action: format!("get permissions for user {}", user_id),
            })?;

        let mut permissions = Vec::new();

        // Convert realm roles to permissions
        for role in &role_mapping.realm_mappings {
            permissions.extend(self.role_to_permissions(role));
        }

        // Convert client roles to permissions
        for (client_id, client_roles) in &role_mapping.client_mappings {
            for role in client_roles {
                permissions.extend(self.client_role_to_permissions(client_id, role));
            }
        }

        Ok(permissions)
    }

    async fn has_realm_role(
        &self,
        context: &AuthorizationContext,
        role: &str,
    ) -> Result<bool, AuthError> {
        // Check local context first
        if context.has_role(role) {
            return Ok(true);
        }

        // If user ID is available, check with Keycloak
        if let Some(ref user_id) = context.user_id {
            let role_mapping = self
                .repository
                .get_user_role_mappings(&context.realm, user_id)
                .await
                .map_err(|_e| AuthError::InsufficientPermissions {
                    action: format!("check realm role {} for user {}", role, user_id),
                })?;

            Ok(role_mapping.realm_mappings.iter().any(|r| r == role))
        } else {
            Ok(false)
        }
    }

    async fn has_client_role(
        &self,
        context: &AuthorizationContext,
        client_id: &str,
        role: &str,
    ) -> Result<bool, AuthError> {
        // Check local context for client role
        let client_role = format!("{}:{}", client_id, role);
        if context.has_role(&client_role) {
            return Ok(true);
        }

        // If user ID is available, check with Keycloak
        if let Some(ref user_id) = context.user_id {
            let role_mapping = self
                .repository
                .get_user_role_mappings(&context.realm, user_id)
                .await
                .map_err(|_e| AuthError::InsufficientPermissions {
                    action: format!("check client role {}:{} for user {}", client_id, role, user_id),
                })?;

            if let Some(client_roles) = role_mapping.client_mappings.get(client_id) {
                Ok(client_roles.iter().any(|r| r == role))
            } else {
                Ok(false)
            }
        } else {
            Ok(false)
        }
    }

    async fn get_effective_roles(
        &self,
        realm: &str,
        user_id: &str,
    ) -> Result<Vec<String>, AuthError> {
        let role_mapping = self
            .repository
            .get_user_role_mappings(realm, user_id)
            .await
            .map_err(|_e| AuthError::InsufficientPermissions {
                action: format!("get effective roles for user {}", user_id),
            })?;

        let mut roles = Vec::new();

        // Add realm roles
        for role in &role_mapping.realm_mappings {
            roles.push(role.clone());
        }

        // Add client roles
        for (client_id, client_roles) in &role_mapping.client_mappings {
            for role in client_roles {
                roles.push(format!("{}:{}", client_id, role));
            }
        }

        Ok(roles)
    }
}

impl<TS: KeycloakTokenSupplier + Send + Sync> KeycloakAuthorizationService<TS> {
    /// Convert realm role to permissions
    fn role_to_permissions(&self, role: &str) -> Vec<Permission> {
        match role {
            "admin" => vec![
                Permission::allow(resources::USERS.to_string(), actions::MANAGE.to_string()),
                Permission::allow(resources::REALMS.to_string(), actions::MANAGE.to_string()),
                Permission::allow(resources::CLIENTS.to_string(), actions::MANAGE.to_string()),
                Permission::allow(resources::GROUPS.to_string(), actions::MANAGE.to_string()),
                Permission::allow(resources::ROLES.to_string(), actions::MANAGE.to_string()),
                Permission::allow(resources::EVENTS.to_string(), actions::VIEW.to_string()),
                Permission::allow(resources::SESSIONS.to_string(), actions::MANAGE.to_string()),
            ],
            "realm-admin" => vec![
                Permission::allow(resources::USERS.to_string(), actions::MANAGE.to_string()),
                Permission::allow(resources::CLIENTS.to_string(), actions::MANAGE.to_string()),
                Permission::allow(resources::GROUPS.to_string(), actions::MANAGE.to_string()),
                Permission::allow(resources::ROLES.to_string(), actions::MANAGE.to_string()),
                Permission::allow(resources::EVENTS.to_string(), actions::VIEW.to_string()),
                Permission::allow(resources::SESSIONS.to_string(), actions::MANAGE.to_string()),
            ],
            "manage-users" => vec![
                Permission::allow(resources::USERS.to_string(), actions::MANAGE.to_string()),
                Permission::allow(resources::GROUPS.to_string(), actions::MANAGE.to_string()),
            ],
            "view-users" => vec![
                Permission::allow(resources::USERS.to_string(), actions::VIEW.to_string()),
                Permission::allow(resources::GROUPS.to_string(), actions::VIEW.to_string()),
            ],
            "manage-clients" => vec![
                Permission::allow(resources::CLIENTS.to_string(), actions::MANAGE.to_string()),
            ],
            "view-clients" => vec![
                Permission::allow(resources::CLIENTS.to_string(), actions::VIEW.to_string()),
            ],
            "view-realm" => vec![
                Permission::allow(resources::REALMS.to_string(), actions::VIEW.to_string()),
            ],
            "view-events" => vec![
                Permission::allow(resources::EVENTS.to_string(), actions::VIEW.to_string()),
            ],
            "impersonation" => vec![
                Permission::allow(resources::USERS.to_string(), actions::IMPERSONATE.to_string()),
            ],
            _ => vec![], // Unknown roles have no permissions
        }
    }

    /// Convert client role to permissions
    fn client_role_to_permissions(&self, client_id: &str, role: &str) -> Vec<Permission> {
        // Client-specific role permissions
        match role {
            "admin" => vec![
                Permission::allow(format!("client:{}", client_id), actions::MANAGE.to_string()),
            ],
            "user" => vec![
                Permission::allow(format!("client:{}", client_id), actions::VIEW.to_string()),
            ],
            _ => vec![], // Unknown client roles have no permissions
        }
    }
}