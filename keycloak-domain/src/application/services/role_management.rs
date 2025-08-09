use crate::{
    application::ports::*,
    domain::{
        entities::*,
        errors::{DomainError, DomainResult},
    },
};
use std::sync::Arc;
use tracing::{info, instrument, warn};

/// Role management service implementing business use cases
pub struct RoleManagementService {
    repository: Arc<dyn KeycloakRepository>,
    event_publisher: Arc<dyn EventPublisher>,
    auth_service: Arc<dyn AuthorizationService>,
}

impl RoleManagementService {
    pub fn new(
        repository: Arc<dyn KeycloakRepository>,
        event_publisher: Arc<dyn EventPublisher>,
        auth_service: Arc<dyn AuthorizationService>,
    ) -> Self {
        Self {
            repository,
            event_publisher,
            auth_service,
        }
    }

    /// List roles in a realm with optional filtering
    #[instrument(skip(self), fields(realm = %realm))]
    pub async fn list_roles(
        &self,
        realm: &str,
        filter: &RoleFilter,
        context: &AuthorizationContext,
    ) -> DomainResult<Vec<Role>> {
        // Check permissions
        self.auth_service
            .check_permission(context, resources::ROLES, actions::VIEW)
            .await
            .map_err(|_e| DomainError::AuthorizationFailed {
                user_id: context.user_id.clone().unwrap_or_default(),
                permission: format!("{}:{}", resources::ROLES, actions::VIEW),
            })?;

        info!("Listing roles in realm '{}' with filter", realm);

        let roles = self.repository.list_realm_roles(realm, filter).await?;

        info!("Found {} roles in realm '{}'", roles.len(), realm);
        Ok(roles)
    }

    /// Get a specific role by name (since role by ID lookup is not available)
    #[instrument(skip(self), fields(realm = %realm, role_name = %role_name))]
    pub async fn get_role_by_name(
        &self,
        realm: &str,
        role_name: &str,
        context: &AuthorizationContext,
    ) -> DomainResult<Role> {
        // Check permissions
        self.auth_service
            .check_permission(context, resources::ROLES, actions::VIEW)
            .await
            .map_err(|_e| DomainError::AuthorizationFailed {
                user_id: context.user_id.clone().unwrap_or_default(),
                permission: format!("{}:{}", resources::ROLES, actions::VIEW),
            })?;

        info!("Getting role '{}' from realm '{}'", role_name, realm);

        let role = self.repository.find_realm_role_by_name(realm, role_name).await?;

        info!(
            "Found role '{}' ({})",
            role.name,
            role.id.as_ref().map(|id| id.as_str()).unwrap_or("unknown")
        );
        Ok(role)
    }

    /// Create a new role
    #[instrument(skip(self, request), fields(realm = %realm, role_name = %request.name))]
    pub async fn create_role(
        &self,
        realm: &str,
        request: &CreateRoleRequest,
        context: &AuthorizationContext,
    ) -> DomainResult<EntityId> {
        // Check permissions
        self.auth_service
            .check_permission(context, resources::ROLES, actions::CREATE)
            .await
            .map_err(|_e| DomainError::AuthorizationFailed {
                user_id: context.user_id.clone().unwrap_or_default(),
                permission: format!("{}:{}", resources::ROLES, actions::CREATE),
            })?;

        info!("Creating role '{}' in realm '{}'", request.name, realm);

        // Validate the request
        request.validate()?;

        // Check if role already exists by name
        if let Ok(_) = self.repository.find_realm_role_by_name(realm, &request.name).await {
            return Err(DomainError::AlreadyExists {
                entity_type: "role".to_string(),
                identifier: request.name.clone(),
            });
        }

        // Create the domain role
        let role = request.to_domain_role()?;

        // Save to repository
        let role_id = self.repository.create_realm_role(realm, &role).await?;

        // Publish domain event
        let event = DomainEvent::role_created(
            role_id.to_string(),
            realm.to_string(),
            request.name.clone(),
            request.description.clone(),
        )
        .with_metadata(
            EventMetadata::new()
                .with_user_id(context.user_id.clone().unwrap_or_default())
                .with_correlation_id(uuid::Uuid::new_v4().to_string()),
        );

        if let Err(e) = self.event_publisher.publish(event).await {
            warn!("Failed to publish role created event: {}", e);
        }

        info!(
            "Successfully created role '{}' with ID '{}'",
            request.name, role_id
        );
        Ok(role_id)
    }

    // TODO: These methods require role lookup by ID and role assignment operations that don't exist yet
    // in the repository trait. They should be implemented when the repository supports them.
    //
    // - update_role_by_id
    // - delete_role_by_id  
    // - assign_role_to_user
    // - remove_role_from_user

    /// Get user's roles
    #[instrument(skip(self), fields(realm = %realm, user_id = %user_id))]
    pub async fn get_user_roles(
        &self,
        realm: &str,
        user_id: &str,
        context: &AuthorizationContext,
    ) -> DomainResult<Vec<Role>> {
        // Check permissions
        self.auth_service
            .check_permission(context, resources::ROLES, actions::VIEW)
            .await
            .map_err(|_e| DomainError::AuthorizationFailed {
                user_id: context.user_id.clone().unwrap_or_default(),
                permission: format!("{}:{}", resources::ROLES, actions::VIEW),
            })?;

        info!("Getting roles for user '{}' in realm '{}'", user_id, realm);

        let role_mapping = self
            .repository
            .get_user_role_mappings(realm, user_id)
            .await?;

        // Convert role names to Role objects
        let mut all_roles = Vec::new();
        
        // Add realm roles
        for role_name in role_mapping.realm_mappings {
            if let Ok(role) = self.repository.find_realm_role_by_name(realm, &role_name).await {
                all_roles.push(role);
            }
        }
        
        // Add client roles (we'll skip client roles for now since they're more complex)
        // TODO: Implement client role lookup when needed

        info!("Found {} roles for user '{}'", all_roles.len(), user_id);
        Ok(all_roles)
    }

    /// Count total roles in realm
    #[instrument(skip(self), fields(realm = %realm))]
    pub async fn count_roles(
        &self,
        realm: &str,
        context: &AuthorizationContext,
    ) -> DomainResult<i64> {
        // Check permissions
        self.auth_service
            .check_permission(context, resources::ROLES, actions::VIEW)
            .await
            .map_err(|_e| DomainError::AuthorizationFailed {
                user_id: context.user_id.clone().unwrap_or_default(),
                permission: format!("{}:{}", resources::ROLES, actions::VIEW),
            })?;

        info!("Counting roles in realm '{}'", realm);

        // For now, use list_realm_roles and count them since count_roles doesn't exist
        let roles = self.repository.list_realm_roles(realm, &RoleFilter::default()).await?;
        let count = roles.len() as i64;

        info!("Found {} roles in realm '{}'", count, realm);
        Ok(count)
    }
}

/// Additional helper functions for DomainEvent
impl DomainEvent {
    pub fn role_created(
        role_id: String,
        realm: String,
        name: String,
        _description: Option<String>,
    ) -> Self {
        Self::new(
            EventType::RoleCreated,
            role_id,
            AggregateType::Role,
            realm.clone(),
            EventData::RoleCreated {
                role_name: name,
                client_role: false,
                container_id: realm,
            },
        )
    }

    pub fn role_updated(
        role_id: String,
        realm: String,
        name: String,
        changes: Vec<String>,
    ) -> Self {
        Self::new(
            EventType::RoleUpdated,
            role_id,
            AggregateType::Role,
            realm,
            EventData::RoleUpdated {
                role_name: name,
                changes,
            },
        )
    }

    pub fn role_deleted(
        role_id: String,
        realm: String,
        name: String,
    ) -> Self {
        Self::new(
            EventType::RoleDeleted,
            role_id,
            AggregateType::Role,
            realm,
            EventData::RoleDeleted {
                role_name: name,
                client_role: false,
            },
        )
    }

}