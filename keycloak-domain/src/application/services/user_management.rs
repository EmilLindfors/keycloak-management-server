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
use uuid::Uuid;

/// User management service implementing business use cases
pub struct UserManagementService {
    repository: Arc<dyn KeycloakRepository>,
    event_publisher: Arc<dyn EventPublisher>,
    auth_service: Arc<dyn AuthorizationService>,
}

impl UserManagementService {
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
impl AuthorizationHelper for UserManagementService {
    fn auth_service(&self) -> &Arc<dyn AuthorizationService> {
        &self.auth_service
    }
}

impl UserManagementService {
    /// List users in a realm with optional filtering
    #[instrument(skip(self), fields(realm = %realm))]
    pub async fn list_users(
        &self,
        realm: &str,
        filter: &UserFilter,
        context: &AuthorizationContext,
    ) -> DomainResult<Vec<User>> {
        // Check permissions
        self.check_permission(context, resources::USERS, actions::VIEW).await?;

        info!("Listing users in realm '{}' with filter", realm);

        let users = self.repository.list_users(realm, filter).await?;

        info!("Found {} users in realm '{}'", users.len(), realm);
        Ok(users)
    }

    /// Get a specific user by ID
    #[instrument(skip(self), fields(realm = %realm, user_id = %user_id))]
    pub async fn get_user(
        &self,
        realm: &str,
        user_id: &str,
        context: &AuthorizationContext,
    ) -> DomainResult<User> {
        // Check permissions
        self.check_permission(context, resources::USERS, actions::VIEW).await?;

        info!("Getting user '{}' from realm '{}'", user_id, realm);

        let user = self.repository.find_user_by_id(realm, user_id).await?;

        info!(
            "Found user '{}' ({})",
            user.username,
            user.id.as_ref().map(|id| id.as_str()).unwrap_or("unknown")
        );
        Ok(user)
    }

    /// Find user by username
    #[instrument(skip(self), fields(realm = %realm, username = %username))]
    pub async fn find_user_by_username(
        &self,
        realm: &str,
        username: &str,
        context: &AuthorizationContext,
    ) -> DomainResult<Option<User>> {
        // Check permissions
        self.check_permission(context, resources::USERS, actions::VIEW).await?;

        info!("Finding user '{}' in realm '{}'", username, realm);

        let user = self.repository.find_user_by_username(realm, username).await?;

        if let Some(ref found_user) = user {
            info!(
                "Found user '{}' ({})",
                found_user.username,
                found_user.id.as_ref().map(|id| id.as_str()).unwrap_or("unknown")
            );
        } else {
            info!("User '{}' not found in realm '{}'", username, realm);
        }
        
        Ok(user)
    }

    /// Create a new user
    #[instrument(skip(self, request), fields(realm = %realm, username = %request.username))]
    pub async fn create_user(
        &self,
        realm: &str,
        request: &CreateUserRequest,
        context: &AuthorizationContext,
    ) -> DomainResult<EntityId> {
        // Check permissions
        self.check_permission(context, resources::USERS, actions::CREATE).await?;

        info!("Creating user '{}' in realm '{}'", request.username, realm);

        // Validate the request
        request.validate()?;

        // Check if user already exists
        if let Ok(Some(_)) = self
            .repository
            .find_user_by_username(realm, &request.username)
            .await
        {
            return Err(DomainError::UserAlreadyExists {
                username: request.username.clone(),
                realm: realm.to_string(),
            });
        }

        // Check email uniqueness if provided
        if let Some(ref email) = request.email {
            if let Ok(Some(_)) = self.repository.find_user_by_email(realm, email).await {
                return Err(DomainError::Validation {
                    field: "email".to_string(),
                    message: format!("Email '{email}' is already in use"),
                });
            }
        }

        // Create the domain user
        let user = request.to_domain_user()?;

        // Save to repository
        let user_id = self.repository.create_user(realm, &user).await?;

        // Set temporary password if provided
        if let Some(ref password) = request.temporary_password {
            let credential = Credential::password(password.clone(), true);
            self.repository
                .set_user_password(realm, user_id.as_str(), &credential)
                .await?;
        }

        // Publish domain event
        let event = DomainEvent::user_created(
            user_id.to_string(),
            realm.to_string(),
            request.username.clone(),
            request.email.clone(),
            request.enabled.unwrap_or(true),
        )
        .with_metadata(
            EventMetadata::new()
                .with_user_id(context.user_id.clone().unwrap_or_default())
                .with_correlation_id(Uuid::new_v4().to_string()),
        );

        if let Err(e) = self.event_publisher.publish(event).await {
            warn!("Failed to publish user created event: {}", e);
        }

        info!(
            "Successfully created user '{}' with ID '{}'",
            request.username, user_id
        );
        Ok(user_id)
    }

    /// Update an existing user
    #[instrument(skip(self, request), fields(realm = %realm, user_id = %user_id))]
    pub async fn update_user(
        &self,
        realm: &str,
        user_id: &str,
        request: &UpdateUserRequest,
        context: &AuthorizationContext,
    ) -> DomainResult<()> {
        // Check permissions
        self.check_permission(context, resources::USERS, actions::UPDATE).await?;

        info!("Updating user '{}' in realm '{}'", user_id, realm);

        // Get the existing user
        let mut user = self.repository.find_user_by_id(realm, user_id).await?;
        let original_user = user.clone();

        // Apply the updates
        request.apply_to_user(&mut user)?;

        // Validate email uniqueness if changed
        if let Some(ref new_email) = request.email {
            if original_user.email.as_ref() != Some(new_email) {
                if let Ok(Some(existing_user)) =
                    self.repository.find_user_by_email(realm, new_email).await
                {
                    if existing_user.id != user.id {
                        return Err(DomainError::Validation {
                            field: "email".to_string(),
                            message: format!("Email '{new_email}' is already in use"),
                        });
                    }
                }
            }
        }

        // Save the updated user
        self.repository.update_user(realm, &user).await?;

        // Determine what changed
        let mut changes = Vec::new();
        if original_user.email != user.email {
            changes.push("email".to_string());
        }
        if original_user.first_name != user.first_name {
            changes.push("first_name".to_string());
        }
        if original_user.last_name != user.last_name {
            changes.push("last_name".to_string());
        }
        if original_user.enabled != user.enabled {
            changes.push("enabled".to_string());
        }

        // Publish domain event
        if !changes.is_empty() {
            let event = DomainEvent::user_updated(
                user_id.to_string(),
                realm.to_string(),
                user.username.clone(),
                changes,
            )
            .with_metadata(
                EventMetadata::new()
                    .with_user_id(context.user_id.clone().unwrap_or_default())
                    .with_correlation_id(Uuid::new_v4().to_string()),
            );

            if let Err(e) = self.event_publisher.publish(event).await {
                warn!("Failed to publish user updated event: {}", e);
            }
        }

        info!("Successfully updated user '{}'", user_id);
        Ok(())
    }

    /// Delete a user
    #[instrument(skip(self), fields(realm = %realm, user_id = %user_id))]
    pub async fn delete_user(
        &self,
        realm: &str,
        user_id: &str,
        context: &AuthorizationContext,
    ) -> DomainResult<()> {
        // Check permissions
        self.check_permission(context, resources::USERS, actions::DELETE).await?;

        info!("Deleting user '{}' from realm '{}'", user_id, realm);

        // Get the user first for the event
        let user = self.repository.find_user_by_id(realm, user_id).await?;

        // Delete the user
        self.repository.delete_user(realm, user_id).await?;

        // Publish domain event
        let event = DomainEvent::user_deleted(
            user_id.to_string(),
            realm.to_string(),
            user.username.clone(),
        )
        .with_metadata(
            EventMetadata::new()
                .with_user_id(context.user_id.clone().unwrap_or_default())
                .with_correlation_id(Uuid::new_v4().to_string()),
        );

        if let Err(e) = self.event_publisher.publish(event).await {
            warn!("Failed to publish user deleted event: {}", e);
        }

        info!("Successfully deleted user '{}'", user_id);
        Ok(())
    }

    /// Reset user password
    #[instrument(skip(self, password), fields(realm = %realm, user_id = %user_id, temporary = %temporary))]
    pub async fn reset_password(
        &self,
        realm: &str,
        user_id: &str,
        password: &str,
        temporary: bool,
        context: &AuthorizationContext,
    ) -> DomainResult<()> {
        // Check permissions
        self.check_permission(context, resources::USERS, actions::UPDATE).await?;

        info!(
            "Resetting password for user '{}' in realm '{}' (temporary: {})",
            user_id, realm, temporary
        );

        // Validate password
        if password.len() < 8 {
            return Err(DomainError::InvalidPassword {
                reason: "Password must be at least 8 characters long".to_string(),
            });
        }

        // Get the user for validation and event
        let user = self.repository.find_user_by_id(realm, user_id).await?;

        // Create credential
        let credential = Credential::password(password.to_string(), temporary);

        // Set the password
        self.repository
            .set_user_password(realm, user_id, &credential)
            .await?;

        // Publish domain event
        let event = DomainEvent::user_password_reset(
            user_id.to_string(),
            realm.to_string(),
            user.username.clone(),
            temporary,
        )
        .with_metadata(
            EventMetadata::new()
                .with_user_id(context.user_id.clone().unwrap_or_default())
                .with_correlation_id(Uuid::new_v4().to_string()),
        );

        if let Err(e) = self.event_publisher.publish(event).await {
            warn!("Failed to publish password reset event: {}", e);
        }

        info!("Successfully reset password for user '{}'", user_id);
        Ok(())
    }

    /// Add user to groups
    #[instrument(skip(self), fields(realm = %realm, user_id = %user_id, group_ids = ?group_ids))]
    pub async fn add_user_to_groups(
        &self,
        realm: &str,
        user_id: &str,
        group_ids: &[String],
        context: &AuthorizationContext,
    ) -> DomainResult<()> {
        // Check permissions
        self.check_permission(context, resources::USERS, actions::MANAGE_GROUP_MEMBERSHIP).await?;

        info!(
            "Adding user '{}' to groups {:?} in realm '{}'",
            user_id, group_ids, realm
        );

        // Verify user exists
        let user = self.repository.find_user_by_id(realm, user_id).await?;

        // Add user to each group
        for group_id in group_ids {
            // Verify group exists
            let group = self.repository.find_group_by_id(realm, group_id).await?;

            // Add user to group
            self.repository
                .add_user_to_group(realm, user_id, group_id)
                .await?;

            // Publish event for each group addition
            let event = DomainEvent::user_added_to_group(
                user_id.to_string(),
                realm.to_string(),
                user.username.clone(),
                group.path.clone(),
            )
            .with_metadata(
                EventMetadata::new()
                    .with_user_id(context.user_id.clone().unwrap_or_default())
                    .with_correlation_id(Uuid::new_v4().to_string()),
            );

            if let Err(e) = self.event_publisher.publish(event).await {
                warn!("Failed to publish user added to group event: {}", e);
            }
        }

        info!(
            "Successfully added user '{}' to {} groups",
            user_id,
            group_ids.len()
        );
        Ok(())
    }

    /// Remove user from group
    #[instrument(skip(self), fields(realm = %realm, user_id = %user_id, group_id = %group_id))]
    pub async fn remove_user_from_group(
        &self,
        realm: &str,
        user_id: &str,
        group_id: &str,
        context: &AuthorizationContext,
    ) -> DomainResult<()> {
        // Check permissions
        self.check_permission(context, resources::USERS, actions::MANAGE_GROUP_MEMBERSHIP).await?;

        info!(
            "Removing user '{}' from group '{}' in realm '{}'",
            user_id, group_id, realm
        );

        // Get user and group for event
        let user = self.repository.find_user_by_id(realm, user_id).await?;
        let group = self.repository.find_group_by_id(realm, group_id).await?;

        // Remove user from group
        self.repository
            .remove_user_from_group(realm, user_id, group_id)
            .await?;

        // Publish domain event
        let event = DomainEvent::user_removed_from_group(
            user_id.to_string(),
            realm.to_string(),
            user.username.clone(),
            group.path.clone(),
        )
        .with_metadata(
            EventMetadata::new()
                .with_user_id(context.user_id.clone().unwrap_or_default())
                .with_correlation_id(Uuid::new_v4().to_string()),
        );

        if let Err(e) = self.event_publisher.publish(event).await {
            warn!("Failed to publish user removed from group event: {}", e);
        }

        info!(
            "Successfully removed user '{}' from group '{}'",
            user_id, group_id
        );
        Ok(())
    }

    /// Get user groups
    #[instrument(skip(self), fields(realm = %realm, user_id = %user_id))]
    pub async fn get_user_groups(
        &self,
        realm: &str,
        user_id: &str,
        context: &AuthorizationContext,
    ) -> DomainResult<Vec<Group>> {
        // Check permissions
        self.check_permission(context, resources::USERS, actions::VIEW).await?;

        info!("Getting groups for user '{}' in realm '{}'", user_id, realm);

        let groups = self.repository.get_user_groups(realm, user_id).await?;

        info!("Found {} groups for user '{}'", groups.len(), user_id);
        Ok(groups)
    }

    /// Count total users in realm
    #[instrument(skip(self), fields(realm = %realm))]
    pub async fn count_users(
        &self,
        realm: &str,
        context: &AuthorizationContext,
    ) -> DomainResult<i64> {
        // Check permissions
        self.check_permission(context, resources::USERS, actions::VIEW).await?;

        info!("Counting users in realm '{}'", realm);

        let count = self.repository.count_users(realm).await?;

        info!("Found {} users in realm '{}'", count, realm);
        Ok(count)
    }
}

/// Additional helper functions for DomainEvent
impl DomainEvent {
    pub fn user_password_reset(
        user_id: String,
        realm: String,
        username: String,
        temporary: bool,
    ) -> Self {
        Self::new(
            EventType::UserPasswordReset,
            user_id,
            AggregateType::User,
            realm,
            EventData::UserPasswordReset {
                username,
                temporary,
            },
        )
    }

    pub fn user_added_to_group(
        user_id: String,
        realm: String,
        username: String,
        group_path: String,
    ) -> Self {
        Self::new(
            EventType::UserAddedToGroup,
            user_id,
            AggregateType::User,
            realm,
            EventData::UserAddedToGroup {
                username,
                group_path,
            },
        )
    }

    pub fn user_removed_from_group(
        user_id: String,
        realm: String,
        username: String,
        group_path: String,
    ) -> Self {
        Self::new(
            EventType::UserRemovedFromGroup,
            user_id,
            AggregateType::User,
            realm,
            EventData::UserRemovedFromGroup {
                username,
                group_path,
            },
        )
    }
}
