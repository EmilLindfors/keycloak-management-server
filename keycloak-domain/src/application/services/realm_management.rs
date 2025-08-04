use crate::{
    application::ports::*,
    domain::{
        entities::*,
        errors::{DomainError, DomainResult},
    },
};
use std::sync::Arc;
use tracing::{info, instrument, warn};

/// Realm management service implementing business use cases
pub struct RealmManagementService {
    repository: Arc<dyn KeycloakRepository>,
    event_publisher: Arc<dyn EventPublisher>,
    auth_service: Arc<dyn AuthorizationService>,
}

impl RealmManagementService {
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

    /// List all realms
    #[instrument(skip(self))]
    pub async fn list_realms(&self, context: &AuthorizationContext) -> DomainResult<Vec<Realm>> {
        // Check permissions
        self.auth_service
            .check_permission(context, resources::REALMS, actions::VIEW)
            .await
            .map_err(|_e| DomainError::AuthorizationFailed {
                user_id: context.user_id.clone().unwrap_or_default(),
                permission: format!("{}:{}", resources::REALMS, actions::VIEW),
            })?;

        info!("Listing all realms");

        let realms = self.repository.list_realms().await?;

        info!("Found {} realms", realms.len());
        Ok(realms)
    }

    /// Get a specific realm by name
    #[instrument(skip(self), fields(realm = %realm_name))]
    pub async fn get_realm(
        &self,
        realm_name: &str,
        context: &AuthorizationContext,
    ) -> DomainResult<Realm> {
        // Check permissions
        self.auth_service
            .check_permission(context, resources::REALMS, actions::VIEW)
            .await
            .map_err(|_e| DomainError::AuthorizationFailed {
                user_id: context.user_id.clone().unwrap_or_default(),
                permission: format!("{}:{}", resources::REALMS, actions::VIEW),
            })?;

        info!("Getting realm '{}'", realm_name);

        let realm = self.repository.find_realm_by_name(realm_name).await?;

        info!("Found realm '{}' (enabled: {})", realm.realm, realm.enabled);
        Ok(realm)
    }

    /// Create a new realm
    #[instrument(skip(self, request), fields(realm = %request.realm))]
    pub async fn create_realm(
        &self,
        request: &CreateRealmRequest,
        context: &AuthorizationContext,
    ) -> DomainResult<EntityId> {
        // Check permissions
        self.auth_service
            .check_permission(context, resources::REALMS, actions::CREATE)
            .await
            .map_err(|_e| DomainError::AuthorizationFailed {
                user_id: context.user_id.clone().unwrap_or_default(),
                permission: format!("{}:{}", resources::REALMS, actions::CREATE),
            })?;

        info!("Creating realm '{}'", request.realm);

        // Validate request
        request.validate()?;

        // Convert to domain entity
        let realm = request.to_domain_realm()?;

        // Check if realm already exists
        if (self.repository.find_realm_by_name(&realm.realm).await).is_ok() {
            return Err(DomainError::AlreadyExists {
                entity_type: "Realm".to_string(),
                identifier: realm.realm,
            });
        }

        // Create the realm
        let realm_id = self.repository.create_realm(&realm).await?;

        // Publish domain event
        let mut event =
            DomainEvent::realm_created(realm_id.to_string(), realm.realm.clone(), realm.enabled);

        if let Some(ref user_id) = context.user_id {
            event = event.with_metadata(EventMetadata::new().with_user_id(user_id.clone()));
        }

        if let Err(e) = self.event_publisher.publish(event).await {
            warn!("Failed to publish realm created event: {}", e);
        }

        info!("Created realm '{}' with ID '{}'", realm.realm, realm_id);
        Ok(realm_id)
    }

    /// Update an existing realm
    #[instrument(skip(self, request), fields(realm = %realm_name))]
    pub async fn update_realm(
        &self,
        realm_name: &str,
        request: &UpdateRealmRequest,
        context: &AuthorizationContext,
    ) -> DomainResult<()> {
        // Check permissions
        self.auth_service
            .check_permission(context, resources::REALMS, actions::UPDATE)
            .await
            .map_err(|_e| DomainError::AuthorizationFailed {
                user_id: context.user_id.clone().unwrap_or_default(),
                permission: format!("{}:{}", resources::REALMS, actions::UPDATE),
            })?;

        info!("Updating realm '{}'", realm_name);

        // Get current realm
        let mut realm = self.repository.find_realm_by_name(realm_name).await?;

        // Apply updates
        request.apply_to_realm(&mut realm)?;

        // Save updated realm
        self.repository.update_realm(&realm).await?;

        // Publish domain event
        let mut event = DomainEvent::realm_updated(
            realm
                .id
                .as_ref()
                .map(|id| id.to_string())
                .unwrap_or_else(|| "unknown".to_string()),
            realm.realm.clone(),
            vec!["realm_updated".to_string()],
        );

        if let Some(ref user_id) = context.user_id {
            event = event.with_metadata(EventMetadata::new().with_user_id(user_id.clone()));
        }

        if let Err(e) = self.event_publisher.publish(event).await {
            warn!("Failed to publish realm updated event: {}", e);
        }

        info!("Updated realm '{}'", realm_name);
        Ok(())
    }

    /// Delete a realm
    #[instrument(skip(self), fields(realm = %realm_name))]
    pub async fn delete_realm(
        &self,
        realm_name: &str,
        context: &AuthorizationContext,
    ) -> DomainResult<()> {
        // Check permissions
        self.auth_service
            .check_permission(context, resources::REALMS, actions::DELETE)
            .await
            .map_err(|_e| DomainError::AuthorizationFailed {
                user_id: context.user_id.clone().unwrap_or_default(),
                permission: format!("{}:{}", resources::REALMS, actions::DELETE),
            })?;

        info!("Deleting realm '{}'", realm_name);

        // Get current realm to check if it exists and get ID
        let realm = self.repository.find_realm_by_name(realm_name).await?;

        // Prevent deletion of master realm
        if realm.is_master_realm() {
            return Err(DomainError::BusinessRule {
                rule: "Master realm cannot be deleted".to_string(),
                context: format!("Attempted to delete realm '{realm_name}'"),
            });
        }

        // Delete the realm
        self.repository.delete_realm(realm_name).await?;

        // Publish domain event
        let mut event = DomainEvent::realm_deleted(
            realm
                .id
                .as_ref()
                .map(|id| id.to_string())
                .unwrap_or_else(|| "unknown".to_string()),
            realm.realm.clone(),
        );

        if let Some(ref user_id) = context.user_id {
            event = event.with_metadata(EventMetadata::new().with_user_id(user_id.clone()));
        }

        if let Err(e) = self.event_publisher.publish(event).await {
            warn!("Failed to publish realm deleted event: {}", e);
        }

        info!("Deleted realm '{}'", realm_name);
        Ok(())
    }

    /// Enable or disable a realm
    #[instrument(skip(self), fields(realm = %realm_name, enabled = %enabled))]
    pub async fn set_realm_enabled(
        &self,
        realm_name: &str,
        enabled: bool,
        context: &AuthorizationContext,
    ) -> DomainResult<()> {
        // Check permissions
        self.auth_service
            .check_permission(context, resources::REALMS, actions::UPDATE)
            .await
            .map_err(|_e| DomainError::AuthorizationFailed {
                user_id: context.user_id.clone().unwrap_or_default(),
                permission: format!("{}:{}", resources::REALMS, actions::UPDATE),
            })?;

        info!(
            "Setting realm '{}' enabled status to {}",
            realm_name, enabled
        );

        // Get current realm
        let mut realm = self.repository.find_realm_by_name(realm_name).await?;

        // Prevent disabling master realm
        if realm.is_master_realm() && !enabled {
            return Err(DomainError::BusinessRule {
                rule: "Master realm cannot be disabled".to_string(),
                context: format!("Attempted to disable realm '{realm_name}'"),
            });
        }

        // Update enabled status
        realm.set_enabled(enabled);

        // Save updated realm
        self.repository.update_realm(&realm).await?;

        // Publish domain event
        let mut event = if enabled {
            DomainEvent::realm_enabled(
                realm
                    .id
                    .as_ref()
                    .map(|id| id.to_string())
                    .unwrap_or_else(|| "unknown".to_string()),
                realm.realm.clone(),
            )
        } else {
            DomainEvent::realm_disabled(
                realm
                    .id
                    .as_ref()
                    .map(|id| id.to_string())
                    .unwrap_or_else(|| "unknown".to_string()),
                realm.realm.clone(),
            )
        };

        if let Some(ref user_id) = context.user_id {
            event = event.with_metadata(EventMetadata::new().with_user_id(user_id.clone()));
        }

        if let Err(e) = self.event_publisher.publish(event).await {
            warn!("Failed to publish realm enabled/disabled event: {}", e);
        }

        info!("Set realm '{}' enabled status to {}", realm_name, enabled);
        Ok(())
    }

    /// Configure realm security settings
    #[instrument(skip(self), fields(realm = %realm_name))]
    pub async fn configure_realm_security(
        &self,
        realm_name: &str,
        reset_password_allowed: Option<bool>,
        edit_username_allowed: Option<bool>,
        brute_force_protected: Option<bool>,
        password_policy: Option<String>,
        context: &AuthorizationContext,
    ) -> DomainResult<()> {
        // Check permissions
        self.auth_service
            .check_permission(context, resources::REALMS, actions::UPDATE)
            .await
            .map_err(|_e| DomainError::AuthorizationFailed {
                user_id: context.user_id.clone().unwrap_or_default(),
                permission: format!("{}:{}", resources::REALMS, actions::UPDATE),
            })?;

        info!("Configuring security settings for realm '{}'", realm_name);

        // Get current realm
        let mut realm = self.repository.find_realm_by_name(realm_name).await?;

        // Apply security configurations
        if let (Some(reset_password), Some(edit_username), Some(brute_force)) = (
            reset_password_allowed,
            edit_username_allowed,
            brute_force_protected,
        ) {
            realm.configure_security(reset_password, edit_username, brute_force);
        } else {
            // Apply individual settings
            if let Some(reset_password) = reset_password_allowed {
                realm.reset_password_allowed = reset_password;
            }
            if let Some(edit_username) = edit_username_allowed {
                realm.edit_username_allowed = edit_username;
            }
            if let Some(brute_force) = brute_force_protected {
                realm.brute_force_protected = brute_force;
            }
        }

        // Set password policy if provided
        if let Some(ref policy) = password_policy {
            realm.set_password_policy(Some(policy.clone()))?;
        }

        // Save updated realm
        self.repository.update_realm(&realm).await?;

        // Publish domain event
        let mut settings = Vec::new();
        if reset_password_allowed.is_some() {
            settings.push("reset_password".to_string());
        }
        if edit_username_allowed.is_some() {
            settings.push("edit_username".to_string());
        }
        if brute_force_protected.is_some() {
            settings.push("brute_force_protection".to_string());
        }
        if password_policy.is_some() {
            settings.push("password_policy".to_string());
        }

        let mut event = DomainEvent::realm_security_configured(
            realm
                .id
                .as_ref()
                .map(|id| id.to_string())
                .unwrap_or_else(|| "unknown".to_string()),
            realm.realm.clone(),
            settings,
        );

        if let Some(ref user_id) = context.user_id {
            event = event.with_metadata(EventMetadata::new().with_user_id(user_id.clone()));
        }

        if let Err(e) = self.event_publisher.publish(event).await {
            warn!("Failed to publish realm security configured event: {}", e);
        }

        info!("Configured security settings for realm '{}'", realm_name);
        Ok(())
    }

    /// Import realm configuration from a file or data
    #[instrument(skip(self, realm_data), fields(realm = %realm_data.realm))]
    pub async fn import_realm(
        &self,
        realm_data: &Realm,
        context: &AuthorizationContext,
    ) -> DomainResult<EntityId> {
        // Check permissions
        self.auth_service
            .check_permission(context, resources::REALMS, actions::CREATE)
            .await
            .map_err(|_e| DomainError::AuthorizationFailed {
                user_id: context.user_id.clone().unwrap_or_default(),
                permission: format!("{}:{}", resources::REALMS, actions::CREATE),
            })?;

        info!("Importing realm '{}'", realm_data.realm);

        // Validate realm name
        Realm::validate_realm_name(&realm_data.realm)?;

        // Check if realm already exists
        if (self.repository.find_realm_by_name(&realm_data.realm).await).is_ok() {
            return Err(DomainError::AlreadyExists {
                entity_type: "Realm".to_string(),
                identifier: realm_data.realm.clone(),
            });
        }

        // Import the realm
        let realm_id = self.repository.create_realm(realm_data).await?;

        // Publish domain event
        let mut event = DomainEvent::realm_imported(realm_id.to_string(), realm_data.realm.clone());

        if let Some(ref user_id) = context.user_id {
            event = event.with_metadata(EventMetadata::new().with_user_id(user_id.clone()));
        }

        if let Err(e) = self.event_publisher.publish(event).await {
            warn!("Failed to publish realm imported event: {}", e);
        }

        info!(
            "Imported realm '{}' with ID '{}'",
            realm_data.realm, realm_id
        );
        Ok(realm_id)
    }

    /// Export realm configuration
    #[instrument(skip(self), fields(realm = %realm_name))]
    pub async fn export_realm(
        &self,
        realm_name: &str,
        context: &AuthorizationContext,
    ) -> DomainResult<Realm> {
        // Check permissions
        self.auth_service
            .check_permission(context, resources::REALMS, actions::VIEW)
            .await
            .map_err(|_e| DomainError::AuthorizationFailed {
                user_id: context.user_id.clone().unwrap_or_default(),
                permission: format!("{}:{}", resources::REALMS, actions::VIEW),
            })?;

        info!("Exporting realm '{}'", realm_name);

        // Get realm data
        let realm = self.repository.find_realm_by_name(realm_name).await?;

        // Publish domain event
        let mut event = DomainEvent::realm_exported(
            realm
                .id
                .as_ref()
                .map(|id| id.to_string())
                .unwrap_or_else(|| "unknown".to_string()),
            realm.realm.clone(),
        );

        if let Some(ref user_id) = context.user_id {
            event = event.with_metadata(EventMetadata::new().with_user_id(user_id.clone()));
        }

        if let Err(e) = self.event_publisher.publish(event).await {
            warn!("Failed to publish realm exported event: {}", e);
        }

        info!("Exported realm '{}'", realm_name);
        Ok(realm)
    }
}
