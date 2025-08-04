use crate::config::Config;
use keycloak::{KeycloakAdmin, KeycloakAdminToken};
use keycloak_domain::{
    application::{
        ports::repository::KeycloakRepository,
        services::{
            user_management::UserManagementService,
            realm_management::RealmManagementService,
            client_management::ClientManagementService,
            group_management::GroupManagementService,
            role_management::RoleManagementService,
        },
    },
    infrastructure::adapters::keycloak_rest::KeycloakRestAdapter,
};
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Clone)]
pub struct AppState {
    pub config: Config,
    pub keycloak_admin: Arc<RwLock<KeycloakAdmin>>,
    pub reqwest_client: reqwest::Client,
    // Domain services
    pub repository: Arc<dyn KeycloakRepository>,
    pub user_service: UserManagementService<KeycloakRestAdapter<KeycloakAdminToken>>,
    pub realm_service: RealmManagementService<KeycloakRestAdapter<KeycloakAdminToken>>,
    pub client_service: ClientManagementService<KeycloakRestAdapter<KeycloakAdminToken>>,
    pub group_service: GroupManagementService<KeycloakRestAdapter<KeycloakAdminToken>>,
    pub role_service: RoleManagementService<KeycloakRestAdapter<KeycloakAdminToken>>,
}

impl AppState {
    pub async fn new(config: &Config) -> Result<Self, Box<dyn std::error::Error>> {
        let reqwest_client = reqwest::Client::new();
        
        let admin_token = KeycloakAdminToken::acquire_custom_realm(
            &config.keycloak_url,
            &config.keycloak_username,
            &config.keycloak_password,
            &config.keycloak_realm,
            &config.keycloak_client_id,
            "password",
            &reqwest_client,
        )
        .await?;

        let keycloak_admin = KeycloakAdmin::new(
            &config.keycloak_url,
            admin_token.clone(),
            reqwest_client.clone(),
        );

        // Create second admin instance for the repository
        let keycloak_admin_for_repository = KeycloakAdmin::new(
            &config.keycloak_url,
            admin_token.clone(),
            reqwest_client.clone(),
        );

        // Create domain layer components
        let repository = Arc::new(KeycloakRestAdapter::new(keycloak_admin_for_repository));
        
        // Create simple event publisher and authorization service implementations
        let (event_publisher, _event_receiver) = keycloak_domain::infrastructure::adapters::memory_event_publisher::MemoryEventPublisher::new();
        let event_publisher = Arc::new(event_publisher);
        
        // Create third admin instance for authorization service
        let keycloak_admin_for_auth = KeycloakAdmin::new(
            &config.keycloak_url,
            admin_token.clone(),
            reqwest_client.clone(),
        );
        
        let auth_service = Arc::new(keycloak_domain::infrastructure::adapters::keycloak_authorization_service::KeycloakAuthorizationService::new(
            repository.clone(),
            Arc::new(keycloak_admin_for_auth)
        ));
        
        let user_service = UserManagementService::new(repository.clone(), event_publisher.clone(), auth_service.clone());
        let realm_service = RealmManagementService::new(repository.clone(), event_publisher.clone(), auth_service.clone());
        let client_service = ClientManagementService::new(repository.clone(), event_publisher.clone(), auth_service.clone());
        let group_service = GroupManagementService::new(repository.clone(), event_publisher.clone(), auth_service.clone());
        let role_service = RoleManagementService::new(repository.clone(), event_publisher.clone(), auth_service.clone());

        Ok(Self {
            config: config.clone(),
            keycloak_admin: Arc::new(RwLock::new(keycloak_admin)),
            reqwest_client,
            repository,
            user_service,
            realm_service,
            client_service,
            group_service,
            role_service,
        })
    }

    pub async fn refresh_token(&self) -> Result<(), Box<dyn std::error::Error>> {
        let admin_token = KeycloakAdminToken::acquire_custom_realm(
            &self.config.keycloak_url,
            &self.config.keycloak_username,
            &self.config.keycloak_password,
            &self.config.keycloak_realm,
            &self.config.keycloak_client_id,
            "password",
            &self.reqwest_client,
        )
        .await?;

        let new_admin = KeycloakAdmin::new(
            &self.config.keycloak_url,
            admin_token,
            self.reqwest_client.clone(),
        );

        *self.keycloak_admin.write().await = new_admin;

        Ok(())
    }
}