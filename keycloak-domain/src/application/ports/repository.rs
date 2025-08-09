use crate::domain::{entities::*, errors::DomainResult};
use async_trait::async_trait;

/// Repository port for Keycloak operations
#[async_trait]
pub trait KeycloakRepository: Send + Sync {
    // User operations
    async fn find_user_by_id(&self, realm: &str, user_id: &str) -> DomainResult<User>;
    async fn find_user_by_username(
        &self,
        realm: &str,
        username: &str,
    ) -> DomainResult<Option<User>>;
    async fn find_user_by_email(&self, realm: &str, email: &str) -> DomainResult<Option<User>>;
    async fn list_users(&self, realm: &str, filter: &UserFilter) -> DomainResult<Vec<User>>;
    async fn create_user(&self, realm: &str, user: &User) -> DomainResult<EntityId>;
    async fn update_user(&self, realm: &str, user: &User) -> DomainResult<()>;
    async fn delete_user(&self, realm: &str, user_id: &str) -> DomainResult<()>;
    async fn count_users(&self, realm: &str) -> DomainResult<i64>;

    // User credential operations
    async fn set_user_password(
        &self,
        realm: &str,
        user_id: &str,
        credential: &Credential,
    ) -> DomainResult<()>;
    async fn get_user_credentials(
        &self,
        realm: &str,
        user_id: &str,
    ) -> DomainResult<Vec<Credential>>;
    async fn delete_user_credential(
        &self,
        realm: &str,
        user_id: &str,
        credential_id: &str,
    ) -> DomainResult<()>;

    // Realm operations
    async fn find_realm_by_name(&self, realm: &str) -> DomainResult<Realm>;
    async fn list_realms(&self) -> DomainResult<Vec<Realm>>;
    async fn list_realms_with_filter(&self, filter: &RealmFilter) -> DomainResult<Vec<Realm>>;
    async fn create_realm(&self, realm: &Realm) -> DomainResult<EntityId>;
    async fn update_realm(&self, realm: &Realm) -> DomainResult<()>;
    async fn delete_realm(&self, realm: &str) -> DomainResult<()>;

    // Client operations
    async fn find_client_by_id(&self, realm: &str, client_id: &str) -> DomainResult<Client>;
    async fn find_client_by_client_id(
        &self,
        realm: &str,
        client_id: &str,
    ) -> DomainResult<Option<Client>>;
    async fn list_clients(&self, realm: &str, filter: &ClientFilter) -> DomainResult<Vec<Client>>;
    async fn create_client(&self, realm: &str, client: &Client) -> DomainResult<EntityId>;
    async fn update_client(&self, realm: &str, client: &Client) -> DomainResult<()>;
    async fn delete_client(&self, realm: &str, client_id: &str) -> DomainResult<()>;

    // Client secret operations
    async fn get_client_secret(&self, realm: &str, client_id: &str) -> DomainResult<String>;
    async fn regenerate_client_secret(&self, realm: &str, client_id: &str) -> DomainResult<String>;

    // Group operations
    async fn find_group_by_id(&self, realm: &str, group_id: &str) -> DomainResult<Group>;
    async fn find_group_by_path(&self, realm: &str, path: &str) -> DomainResult<Option<Group>>;
    async fn list_groups(&self, realm: &str, filter: &GroupFilter) -> DomainResult<Vec<Group>>;
    async fn create_group(&self, realm: &str, group: &Group) -> DomainResult<EntityId>;
    async fn update_group(&self, realm: &str, group: &Group) -> DomainResult<()>;
    async fn delete_group(&self, realm: &str, group_id: &str) -> DomainResult<()>;

    // Role operations
    async fn find_realm_role_by_name(&self, realm: &str, role_name: &str) -> DomainResult<Role>;
    async fn find_client_role_by_name(
        &self,
        realm: &str,
        client_id: &str,
        role_name: &str,
    ) -> DomainResult<Role>;
    async fn list_realm_roles(&self, realm: &str, filter: &RoleFilter) -> DomainResult<Vec<Role>>;
    async fn list_client_roles(
        &self,
        realm: &str,
        client_id: &str,
        filter: &RoleFilter,
    ) -> DomainResult<Vec<Role>>;
    async fn create_realm_role(&self, realm: &str, role: &Role) -> DomainResult<EntityId>;
    async fn create_client_role(
        &self,
        realm: &str,
        client_id: &str,
        role: &Role,
    ) -> DomainResult<EntityId>;
    async fn update_realm_role(&self, realm: &str, role: &Role) -> DomainResult<()>;
    async fn update_client_role(
        &self,
        realm: &str,
        client_id: &str,
        role: &Role,
    ) -> DomainResult<()>;
    async fn delete_realm_role(&self, realm: &str, role_name: &str) -> DomainResult<()>;
    async fn delete_client_role(
        &self,
        realm: &str,
        client_id: &str,
        role_name: &str,
    ) -> DomainResult<()>;

    // Role mapping operations
    async fn get_user_role_mappings(&self, realm: &str, user_id: &str)
        -> DomainResult<RoleMapping>;
    async fn add_user_realm_roles(
        &self,
        realm: &str,
        user_id: &str,
        roles: &[String],
    ) -> DomainResult<()>;
    async fn remove_user_realm_roles(
        &self,
        realm: &str,
        user_id: &str,
        roles: &[String],
    ) -> DomainResult<()>;
    async fn add_user_client_roles(
        &self,
        realm: &str,
        user_id: &str,
        client_id: &str,
        roles: &[String],
    ) -> DomainResult<()>;
    async fn remove_user_client_roles(
        &self,
        realm: &str,
        user_id: &str,
        client_id: &str,
        roles: &[String],
    ) -> DomainResult<()>;

    async fn get_group_role_mappings(
        &self,
        realm: &str,
        group_id: &str,
    ) -> DomainResult<RoleMapping>;
    async fn add_group_realm_roles(
        &self,
        realm: &str,
        group_id: &str,
        roles: &[String],
    ) -> DomainResult<()>;
    async fn remove_group_realm_roles(
        &self,
        realm: &str,
        group_id: &str,
        roles: &[String],
    ) -> DomainResult<()>;
    async fn add_group_client_roles(
        &self,
        realm: &str,
        group_id: &str,
        client_id: &str,
        roles: &[String],
    ) -> DomainResult<()>;
    async fn remove_group_client_roles(
        &self,
        realm: &str,
        group_id: &str,
        client_id: &str,
        roles: &[String],
    ) -> DomainResult<()>;

    // User-Group operations
    async fn get_user_groups(&self, realm: &str, user_id: &str) -> DomainResult<Vec<Group>>;
    async fn add_user_to_group(
        &self,
        realm: &str,
        user_id: &str,
        group_id: &str,
    ) -> DomainResult<()>;
    async fn remove_user_from_group(
        &self,
        realm: &str,
        user_id: &str,
        group_id: &str,
    ) -> DomainResult<()>;

    // Session operations
    async fn get_user_sessions(&self, realm: &str, user_id: &str)
        -> DomainResult<Vec<UserSession>>;
    async fn logout_user(&self, realm: &str, user_id: &str) -> DomainResult<()>;
    async fn logout_all_sessions(&self, realm: &str) -> DomainResult<()>;
    async fn delete_session(&self, realm: &str, session_id: &str) -> DomainResult<()>;

    // Federated identity operations
    async fn get_user_federated_identities(
        &self,
        realm: &str,
        user_id: &str,
    ) -> DomainResult<Vec<FederatedIdentity>>;
    async fn add_user_federated_identity(
        &self,
        realm: &str,
        user_id: &str,
        provider: &str,
        identity: &FederatedIdentity,
    ) -> DomainResult<()>;
    async fn remove_user_federated_identity(
        &self,
        realm: &str,
        user_id: &str,
        provider: &str,
    ) -> DomainResult<()>;
}

/// Additional session-related types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserSession {
    pub id: EntityId,
    pub user_id: EntityId,
    pub username: String,
    pub ip_address: Option<String>,
    pub start: chrono::DateTime<chrono::Utc>,
    pub last_access: chrono::DateTime<chrono::Utc>,
    pub clients: std::collections::HashMap<String, String>,
}

/// Client scope operations
#[async_trait]
pub trait ClientScopeRepository: Send + Sync {
    async fn find_client_scope_by_id(
        &self,
        realm: &str,
        scope_id: &str,
    ) -> DomainResult<ClientScope>;
    async fn list_client_scopes(
        &self,
        realm: &str,
        filter: &QueryFilter,
    ) -> DomainResult<Vec<ClientScope>>;
    async fn create_client_scope(&self, realm: &str, scope: &ClientScope)
        -> DomainResult<EntityId>;
    async fn update_client_scope(&self, realm: &str, scope: &ClientScope) -> DomainResult<()>;
    async fn delete_client_scope(&self, realm: &str, scope_id: &str) -> DomainResult<()>;

    async fn get_client_default_scopes(
        &self,
        realm: &str,
        client_id: &str,
    ) -> DomainResult<Vec<ClientScope>>;
    async fn get_client_optional_scopes(
        &self,
        realm: &str,
        client_id: &str,
    ) -> DomainResult<Vec<ClientScope>>;
    async fn add_client_default_scope(
        &self,
        realm: &str,
        client_id: &str,
        scope_id: &str,
    ) -> DomainResult<()>;
    async fn remove_client_default_scope(
        &self,
        realm: &str,
        client_id: &str,
        scope_id: &str,
    ) -> DomainResult<()>;
    async fn add_client_optional_scope(
        &self,
        realm: &str,
        client_id: &str,
        scope_id: &str,
    ) -> DomainResult<()>;
    async fn remove_client_optional_scope(
        &self,
        realm: &str,
        client_id: &str,
        scope_id: &str,
    ) -> DomainResult<()>;
}

/// Client scope entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientScope {
    pub id: Option<EntityId>,
    pub name: String,
    pub description: Option<String>,
    pub protocol: String,
    pub attributes: Attributes,
    pub protocol_mappers: Vec<ProtocolMapper>,
}

/// Protocol mapper for client scopes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolMapper {
    pub id: Option<EntityId>,
    pub name: String,
    pub protocol: String,
    pub protocol_mapper: String,
    pub consent_required: bool,
    pub config: std::collections::HashMap<String, String>,
}

/// Events operations
#[async_trait]
pub trait EventRepository: Send + Sync {
    async fn list_events(&self, realm: &str, filter: &EventFilter) -> DomainResult<Vec<Event>>;
    async fn clear_events(&self, realm: &str) -> DomainResult<()>;
    async fn get_events_config(&self, realm: &str) -> DomainResult<EventConfig>;
    async fn update_events_config(&self, realm: &str, config: &EventConfig) -> DomainResult<()>;
}

/// Event entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub time: chrono::DateTime<chrono::Utc>,
    pub type_: String,
    pub realm_id: String,
    pub client_id: Option<String>,
    pub user_id: Option<String>,
    pub session_id: Option<String>,
    pub ip_address: Option<String>,
    pub error: Option<String>,
    pub details: std::collections::HashMap<String, String>,
}

/// Event configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventConfig {
    pub events_enabled: bool,
    pub events_listeners: Vec<String>,
    pub enabled_event_types: Vec<String>,
    pub admin_events_enabled: bool,
    pub admin_events_details_enabled: bool,
    pub events_expiration: Option<i64>,
}

/// Event filter
#[derive(Debug, Clone, Default)]
pub struct EventFilter {
    pub client: Option<String>,
    pub date_from: Option<chrono::DateTime<chrono::Utc>>,
    pub date_to: Option<chrono::DateTime<chrono::Utc>>,
    pub ip_address: Option<String>,
    pub user: Option<String>,
    pub type_: Option<String>,
    pub first: Option<i32>,
    pub max: Option<i32>,
}

/// Identity provider operations
#[async_trait]
pub trait IdentityProviderRepository: Send + Sync {
    async fn find_identity_provider_by_alias(
        &self,
        realm: &str,
        alias: &str,
    ) -> DomainResult<IdentityProvider>;
    async fn list_identity_providers(&self, realm: &str) -> DomainResult<Vec<IdentityProvider>>;
    async fn create_identity_provider(
        &self,
        realm: &str,
        provider: &IdentityProvider,
    ) -> DomainResult<String>;
    async fn update_identity_provider(
        &self,
        realm: &str,
        provider: &IdentityProvider,
    ) -> DomainResult<()>;
    async fn delete_identity_provider(&self, realm: &str, alias: &str) -> DomainResult<()>;
}

/// Identity provider entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityProvider {
    pub alias: String,
    pub display_name: Option<String>,
    pub provider_id: String,
    pub enabled: bool,
    pub store_token: bool,
    pub add_read_token_role_on_create: bool,
    pub authenticate_by_default: bool,
    pub link_only: bool,
    pub first_broker_login_flow_alias: String,
    pub post_broker_login_flow_alias: Option<String>,
    pub config: std::collections::HashMap<String, String>,
}

use serde::{Deserialize, Serialize};
