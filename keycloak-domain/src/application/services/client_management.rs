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

/// Client management service implementing business use cases
pub struct ClientManagementService {
    repository: Arc<dyn KeycloakRepository>,
    event_publisher: Arc<dyn EventPublisher>,
    auth_service: Arc<dyn AuthorizationService>,
}

impl ClientManagementService {
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
impl AuthorizationHelper for ClientManagementService {
    fn auth_service(&self) -> &Arc<dyn AuthorizationService> {
        &self.auth_service
    }
}

impl ClientManagementService {
    /// List clients in a realm with optional filtering
    #[instrument(skip(self), fields(realm = %realm))]
    pub async fn list_clients(
        &self,
        realm: &str,
        filter: &ClientFilter,
        context: &AuthorizationContext,
    ) -> DomainResult<Vec<Client>> {
        // Check permissions
        self.check_permission(context, resources::CLIENTS, actions::VIEW).await?;

        info!("Listing clients in realm '{}' with filter", realm);

        let clients = self.repository.list_clients(realm, filter).await?;

        info!("Found {} clients in realm '{}'", clients.len(), realm);
        Ok(clients)
    }

    /// Get a specific client by ID
    #[instrument(skip(self), fields(realm = %realm, client_id = %client_id))]
    pub async fn get_client(
        &self,
        realm: &str,
        client_id: &str,
        context: &AuthorizationContext,
    ) -> DomainResult<Client> {
        // Check permissions
        self.check_permission(context, resources::CLIENTS, actions::VIEW).await?;

        info!("Getting client '{}' from realm '{}'", client_id, realm);

        let client = self.repository.find_client_by_id(realm, client_id).await?;

        info!(
            "Found client '{}' ({})",
            client.client_id,
            client.name.as_deref().unwrap_or("unnamed")
        );
        Ok(client)
    }

    /// Create a new client
    #[instrument(skip(self, request), fields(realm = %realm, client_id = %request.client_id))]
    pub async fn create_client(
        &self,
        realm: &str,
        request: &CreateClientRequest,
        context: &AuthorizationContext,
    ) -> DomainResult<EntityId> {
        // Check permissions
        self.check_permission(context, resources::CLIENTS, actions::CREATE).await?;

        info!(
            "Creating client '{}' in realm '{}'",
            request.client_id, realm
        );

        // Validate request
        request.validate()?;

        // Convert to domain entity
        let client = request.to_domain_client()?;

        // Check if client already exists
        if let Ok(Some(_)) = self
            .repository
            .find_client_by_client_id(realm, &client.client_id)
            .await
        {
            return Err(DomainError::AlreadyExists {
                entity_type: "Client".to_string(),
                identifier: client.client_id,
            });
        }

        // Create the client
        let client_id = self.repository.create_client(realm, &client).await?;

        // Publish domain event
        let mut event = DomainEvent::client_created(
            client_id.to_string(),
            realm.to_string(),
            client.client_id.clone(),
            client.public_client,
        );

        if let Some(ref user_id) = context.user_id {
            event = event.with_metadata(EventMetadata::new().with_user_id(user_id.clone()));
        }

        if let Err(e) = self.event_publisher.publish(event).await {
            warn!("Failed to publish client created event: {}", e);
        }

        info!(
            "Created client '{}' with ID '{}'",
            client.client_id, client_id
        );
        Ok(client_id)
    }

    /// Update an existing client
    #[instrument(skip(self, request), fields(realm = %realm, client_id = %client_id))]
    pub async fn update_client(
        &self,
        realm: &str,
        client_id: &str,
        request: &UpdateClientRequest,
        context: &AuthorizationContext,
    ) -> DomainResult<()> {
        // Check permissions
        self.check_permission(context, resources::CLIENTS, actions::UPDATE).await?;

        info!("Updating client '{}' in realm '{}'", client_id, realm);

        // Get current client
        let mut client = self.repository.find_client_by_id(realm, client_id).await?;

        // Apply updates
        request.apply_to_client(&mut client)?;

        // Save updated client
        self.repository.update_client(realm, &client).await?;

        // Publish domain event
        let mut event = DomainEvent::new(
            EventType::ClientUpdated,
            client
                .id
                .as_ref()
                .map(|id| id.to_string())
                .unwrap_or_else(|| "unknown".to_string()),
            AggregateType::Client,
            realm.to_string(),
            EventData::ClientUpdated {
                client_id: client.client_id.clone(),
                changes: vec!["client_updated".to_string()],
            },
        );

        if let Some(ref user_id) = context.user_id {
            event = event.with_metadata(EventMetadata::new().with_user_id(user_id.clone()));
        }

        if let Err(e) = self.event_publisher.publish(event).await {
            warn!("Failed to publish client updated event: {}", e);
        }

        info!("Updated client '{}' in realm '{}'", client_id, realm);
        Ok(())
    }

    /// Delete a client
    #[instrument(skip(self), fields(realm = %realm, client_id = %client_id))]
    pub async fn delete_client(
        &self,
        realm: &str,
        client_id: &str,
        context: &AuthorizationContext,
    ) -> DomainResult<()> {
        // Check permissions
        self.check_permission(context, resources::CLIENTS, actions::DELETE).await?;

        info!("Deleting client '{}' from realm '{}'", client_id, realm);

        // Get current client to check if it exists and get details
        let client = self.repository.find_client_by_id(realm, client_id).await?;

        // Delete the client
        self.repository.delete_client(realm, client_id).await?;

        // Publish domain event
        let mut event = DomainEvent::new(
            EventType::ClientDeleted,
            client
                .id
                .as_ref()
                .map(|id| id.to_string())
                .unwrap_or_else(|| "unknown".to_string()),
            AggregateType::Client,
            realm.to_string(),
            EventData::ClientDeleted {
                client_id: client.client_id.clone(),
            },
        );

        if let Some(ref user_id) = context.user_id {
            event = event.with_metadata(EventMetadata::new().with_user_id(user_id.clone()));
        }

        if let Err(e) = self.event_publisher.publish(event).await {
            warn!("Failed to publish client deleted event: {}", e);
        }

        info!("Deleted client '{}' from realm '{}'", client_id, realm);
        Ok(())
    }

    /// Get client secret
    #[instrument(skip(self), fields(realm = %realm, client_id = %client_id))]
    pub async fn get_client_secret(
        &self,
        realm: &str,
        client_id: &str,
        context: &AuthorizationContext,
    ) -> DomainResult<String> {
        // Check permissions
        self.check_permission(context, resources::CLIENTS, actions::VIEW).await?;

        info!(
            "Getting secret for client '{}' in realm '{}'",
            client_id, realm
        );

        let secret = self.repository.get_client_secret(realm, client_id).await?;

        info!(
            "Retrieved secret for client '{}' in realm '{}'",
            client_id, realm
        );
        Ok(secret)
    }

    /// Regenerate client secret
    #[instrument(skip(self), fields(realm = %realm, client_id = %client_id))]
    pub async fn regenerate_client_secret(
        &self,
        realm: &str,
        client_id: &str,
        context: &AuthorizationContext,
    ) -> DomainResult<String> {
        // Check permissions
        self.check_permission(context, resources::CLIENTS, actions::UPDATE).await?;

        info!(
            "Regenerating secret for client '{}' in realm '{}'",
            client_id, realm
        );

        // Get current client to validate it exists
        let client = self.repository.find_client_by_id(realm, client_id).await?;

        // Check if this is a public client
        if client.public_client {
            return Err(DomainError::BusinessRule {
                rule: "Public clients do not have secrets".to_string(),
                context: format!(
                    "Attempted to regenerate secret for public client '{client_id}'"
                ),
            });
        }

        // Regenerate the secret
        let new_secret = self
            .repository
            .regenerate_client_secret(realm, client_id)
            .await?;

        // Publish domain event
        let mut event = DomainEvent::new(
            EventType::ClientSecretRegenerated,
            client
                .id
                .as_ref()
                .map(|id| id.to_string())
                .unwrap_or_else(|| "unknown".to_string()),
            AggregateType::Client,
            realm.to_string(),
            EventData::ClientSecretRegenerated {
                client_id: client.client_id.clone(),
            },
        );

        if let Some(ref user_id) = context.user_id {
            event = event.with_metadata(EventMetadata::new().with_user_id(user_id.clone()));
        }

        if let Err(e) = self.event_publisher.publish(event).await {
            warn!("Failed to publish client secret regenerated event: {}", e);
        }

        info!(
            "Regenerated secret for client '{}' in realm '{}'",
            client_id, realm
        );
        Ok(new_secret)
    }

    /// Enable or disable a client
    #[instrument(skip(self), fields(realm = %realm, client_id = %client_id, enabled = %enabled))]
    pub async fn set_client_enabled(
        &self,
        realm: &str,
        client_id: &str,
        enabled: bool,
        context: &AuthorizationContext,
    ) -> DomainResult<()> {
        // Check permissions
        self.check_permission(context, resources::CLIENTS, actions::UPDATE).await?;

        info!(
            "Setting client '{}' enabled status to {} in realm '{}'",
            client_id, enabled, realm
        );

        // Get current client
        let mut client = self.repository.find_client_by_id(realm, client_id).await?;

        // Update enabled status
        client.enabled = enabled;
        client.timestamps.updated_timestamp = Some(chrono::Utc::now());

        // Save updated client
        self.repository.update_client(realm, &client).await?;

        // Publish domain event
        let mut event = DomainEvent::new(
            EventType::ClientUpdated,
            client
                .id
                .as_ref()
                .map(|id| id.to_string())
                .unwrap_or_else(|| "unknown".to_string()),
            AggregateType::Client,
            realm.to_string(),
            EventData::ClientUpdated {
                client_id: client.client_id.clone(),
                changes: vec![if enabled { "enabled" } else { "disabled" }.to_string()],
            },
        );

        if let Some(ref user_id) = context.user_id {
            event = event.with_metadata(EventMetadata::new().with_user_id(user_id.clone()));
        }

        if let Err(e) = self.event_publisher.publish(event).await {
            warn!("Failed to publish client enabled/disabled event: {}", e);
        }

        info!(
            "Set client '{}' enabled status to {} in realm '{}'",
            client_id, enabled, realm
        );
        Ok(())
    }
}
