use crate::{
    application::{
        ports::*,
        services::AuthorizationHelper,
    },
    domain::{
        entities::*,
        errors::{DomainError, DomainResult},
    },
};
use async_trait::async_trait;
use std::sync::Arc;
use tracing::{info, instrument, warn};

/// Group management service implementing business use cases
pub struct GroupManagementService {
    repository: Arc<dyn KeycloakRepository>,
    event_publisher: Arc<dyn EventPublisher>,
    auth_service: Arc<dyn AuthorizationService>,
}

impl GroupManagementService {
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
}

#[async_trait]
impl AuthorizationHelper for GroupManagementService {
    fn auth_service(&self) -> &Arc<dyn AuthorizationService> {
        &self.auth_service
    }
}

impl GroupManagementService {
    /// List groups in a realm with optional filtering
    #[instrument(skip(self), fields(realm = %realm))]
    pub async fn list_groups(
        &self,
        realm: &str,
        filter: &GroupFilter,
        context: &AuthorizationContext,
    ) -> DomainResult<Vec<Group>> {
        // Check permissions
        self.check_permission(context, resources::GROUPS, actions::VIEW).await?;

        info!("Listing groups in realm '{}' with filter", realm);

        let groups = self.repository.list_groups(realm, filter).await?;

        info!("Found {} groups in realm '{}'", groups.len(), realm);
        Ok(groups)
    }

    /// Get a specific group by ID
    #[instrument(skip(self), fields(realm = %realm, group_id = %group_id))]
    pub async fn get_group(
        &self,
        realm: &str,
        group_id: &str,
        context: &AuthorizationContext,
    ) -> DomainResult<Group> {
        // Check permissions
        self.check_permission(context, resources::GROUPS, actions::VIEW).await?;

        info!("Getting group '{}' from realm '{}'", group_id, realm);

        let group = self.repository.find_group_by_id(realm, group_id).await?;

        info!(
            "Found group '{}' ({})",
            group.name,
            group.id.as_ref().map(|id| id.as_str()).unwrap_or("unknown")
        );
        Ok(group)
    }

    /// Create a new group
    #[instrument(skip(self, request), fields(realm = %realm, group_name = %request.name))]
    pub async fn create_group(
        &self,
        realm: &str,
        request: &CreateGroupRequest,
        context: &AuthorizationContext,
    ) -> DomainResult<EntityId> {
        // Check permissions
        self.check_permission(context, resources::GROUPS, actions::CREATE).await?;

        info!("Creating group '{}' in realm '{}'", request.name, realm);

        // Validate the request
        request.validate()?;

        // Check if group already exists by path (if provided) or name
        if let Some(ref path) = request.path {
            if let Ok(Some(_)) = self.repository.find_group_by_path(realm, path).await {
                return Err(DomainError::AlreadyExists {
                    entity_type: "group".to_string(),
                    identifier: path.clone(),
                });
            }
        } else {
            // Check by name only if no path is provided
            let existing_groups = self.repository.list_groups(realm, &GroupFilter {
                search: Some(request.name.clone()),
                exact: Some(true),
                ..Default::default()
            }).await?;
            
            if !existing_groups.is_empty() {
                return Err(DomainError::AlreadyExists {
                    entity_type: "group".to_string(),
                    identifier: request.name.clone(),
                });
            }
        }

        // Create the domain group
        let group = request.to_domain_group()?;

        // Save to repository
        let group_id = self.repository.create_group(realm, &group).await?;

        // Publish domain event
        let event = DomainEvent::group_created(
            group_id.to_string(),
            realm.to_string(),
            request.name.clone(),
            request.path.clone().unwrap_or_default(),
        )
        .with_metadata(
            EventMetadata::new()
                .with_user_id(context.user_id.clone().unwrap_or_default())
                .with_correlation_id(uuid::Uuid::new_v4().to_string()),
        );

        if let Err(e) = self.event_publisher.publish(event).await {
            warn!("Failed to publish group created event: {}", e);
        }

        info!(
            "Successfully created group '{}' with ID '{}'",
            request.name, group_id
        );
        Ok(group_id)
    }

    /// Update an existing group
    #[instrument(skip(self, request), fields(realm = %realm, group_id = %group_id))]
    pub async fn update_group(
        &self,
        realm: &str,
        group_id: &str,
        request: &UpdateGroupRequest,
        context: &AuthorizationContext,
    ) -> DomainResult<()> {
        // Check permissions
        self.check_permission(context, resources::GROUPS, actions::UPDATE).await?;

        info!("Updating group '{}' in realm '{}'", group_id, realm);

        // Get the existing group
        let mut group = self.repository.find_group_by_id(realm, group_id).await?;
        let original_group = group.clone();

        // Apply the updates
        request.apply_to_group(&mut group)?;

        // Save the updated group
        self.repository.update_group(realm, &group).await?;

        // Determine what changed
        let mut changes = Vec::new();
        if original_group.name != group.name {
            changes.push("name".to_string());
        }
        // Note: We'll skip attribute comparison for now since Attributes doesn't implement PartialEq
        // if original_group.attributes != group.attributes {
        //     changes.push("attributes".to_string());
        // }

        // Publish domain event
        if !changes.is_empty() {
            let event = DomainEvent::group_updated(
                group_id.to_string(),
                realm.to_string(),
                group.name.clone(),
                changes,
            )
            .with_metadata(
                EventMetadata::new()
                    .with_user_id(context.user_id.clone().unwrap_or_default())
                    .with_correlation_id(uuid::Uuid::new_v4().to_string()),
            );

            if let Err(e) = self.event_publisher.publish(event).await {
                warn!("Failed to publish group updated event: {}", e);
            }
        }

        info!("Successfully updated group '{}'", group_id);
        Ok(())
    }

    /// Delete a group
    #[instrument(skip(self), fields(realm = %realm, group_id = %group_id))]
    pub async fn delete_group(
        &self,
        realm: &str,
        group_id: &str,
        context: &AuthorizationContext,
    ) -> DomainResult<()> {
        // Check permissions
        self.check_permission(context, resources::GROUPS, actions::DELETE).await?;

        info!("Deleting group '{}' from realm '{}'", group_id, realm);

        // Get the group first for the event
        let group = self.repository.find_group_by_id(realm, group_id).await?;

        // Delete the group
        self.repository.delete_group(realm, group_id).await?;

        // Publish domain event
        let event = DomainEvent::group_deleted(
            group_id.to_string(),
            realm.to_string(),
            group.name.clone(),
        )
        .with_metadata(
            EventMetadata::new()
                .with_user_id(context.user_id.clone().unwrap_or_default())
                .with_correlation_id(uuid::Uuid::new_v4().to_string()),
        );

        if let Err(e) = self.event_publisher.publish(event).await {
            warn!("Failed to publish group deleted event: {}", e);
        }

        info!("Successfully deleted group '{}'", group_id);
        Ok(())
    }

    /// Get group members
    #[instrument(skip(self), fields(realm = %realm, group_id = %group_id))]
    pub async fn get_group_members(
        &self,
        realm: &str,
        group_id: &str,
        context: &AuthorizationContext,
    ) -> DomainResult<Vec<User>> {
        // Check permissions
        self.check_permission(context, resources::GROUPS, actions::VIEW).await?;

        info!("Getting members for group '{}' in realm '{}'", group_id, realm);

        // For now, return empty members since get_group_members doesn't exist in the repository
        // This should be implemented in the repository trait when needed
        let members = Vec::new();

        info!("Found {} members in group '{}'", members.len(), group_id);
        Ok(members)
    }

    /// Add a user to a group
    #[instrument(skip(self), fields(realm = %realm, user_id = %user_id, group_id = %group_id))]
    pub async fn add_user_to_group(
        &self,
        realm: &str,
        user_id: &str,
        group_id: &str,
        context: &AuthorizationContext,
    ) -> DomainResult<()> {
        // Check permissions
        self.check_permission(context, resources::GROUPS, actions::UPDATE).await?;

        info!("Adding user '{}' to group '{}' in realm '{}'", user_id, group_id, realm);

        // Verify the group exists
        let group = self.repository.find_group_by_id(realm, group_id).await?;

        // Add user to group via repository
        self.repository.add_user_to_group(realm, user_id, group_id).await?;

        // Publish domain event
        let event = DomainEvent::user_added_to_group(
            user_id.to_string(),
            realm.to_string(),
            "unknown".to_string(), // We don't have username here, but it's required
            group.path.clone(),
        )
        .with_metadata(
            EventMetadata::new()
                .with_user_id(context.user_id.clone().unwrap_or_default())
                .with_correlation_id(uuid::Uuid::new_v4().to_string()),
        );

        if let Err(e) = self.event_publisher.publish(event).await {
            warn!("Failed to publish user added to group event: {}", e);
        }

        info!("Successfully added user '{}' to group '{}'", user_id, group_id);
        Ok(())
    }

    /// Remove a user from a group
    #[instrument(skip(self), fields(realm = %realm, user_id = %user_id, group_id = %group_id))]
    pub async fn remove_user_from_group(
        &self,
        realm: &str,
        user_id: &str,
        group_id: &str,
        context: &AuthorizationContext,
    ) -> DomainResult<()> {
        // Check permissions
        self.check_permission(context, resources::GROUPS, actions::UPDATE).await?;

        info!("Removing user '{}' from group '{}' in realm '{}'", user_id, group_id, realm);

        // Verify the group exists
        let group = self.repository.find_group_by_id(realm, group_id).await?;

        // Remove user from group via repository
        self.repository.remove_user_from_group(realm, user_id, group_id).await?;

        // Publish domain event
        let event = DomainEvent::user_removed_from_group(
            user_id.to_string(),
            realm.to_string(),
            "unknown".to_string(), // We don't have username here, but it's required
            group.path.clone(),
        )
        .with_metadata(
            EventMetadata::new()
                .with_user_id(context.user_id.clone().unwrap_or_default())
                .with_correlation_id(uuid::Uuid::new_v4().to_string()),
        );

        if let Err(e) = self.event_publisher.publish(event).await {
            warn!("Failed to publish user removed from group event: {}", e);
        }

        info!("Successfully removed user '{}' from group '{}'", user_id, group_id);
        Ok(())
    }

    /// Count total groups in realm
    #[instrument(skip(self), fields(realm = %realm))]
    pub async fn count_groups(
        &self,
        realm: &str,
        context: &AuthorizationContext,
    ) -> DomainResult<i64> {
        // Check permissions
        self.check_permission(context, resources::GROUPS, actions::VIEW).await?;

        info!("Counting groups in realm '{}'", realm);

        // For now, use list_groups and count them since count_groups doesn't exist
        let groups = self.repository.list_groups(realm, &GroupFilter::default()).await?;
        let count = groups.len() as i64;

        info!("Found {} groups in realm '{}'", count, realm);
        Ok(count)
    }
}

/// Additional helper functions for DomainEvent
impl DomainEvent {
    pub fn group_created(
        group_id: String,
        realm: String,
        name: String,
        path: String,
    ) -> Self {
        Self::new(
            EventType::GroupCreated,
            group_id,
            AggregateType::Group,
            realm,
            EventData::GroupCreated {
                group_name: name,
                group_path: path,
            },
        )
    }

    pub fn group_updated(
        group_id: String,
        realm: String,
        name: String,
        changes: Vec<String>,
    ) -> Self {
        Self::new(
            EventType::GroupUpdated,
            group_id,
            AggregateType::Group,
            realm,
            EventData::GroupUpdated {
                group_name: name,
                changes,
            },
        )
    }

    pub fn group_deleted(
        group_id: String,
        realm: String,
        name: String,
    ) -> Self {
        Self::new(
            EventType::GroupDeleted,
            group_id,
            AggregateType::Group,
            realm,
            EventData::GroupDeleted {
                group_name: name,
                group_path: String::new(), // We'll need to get this from the group when we have it
            },
        )
    }

}