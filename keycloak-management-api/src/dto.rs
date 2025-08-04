use serde::{Deserialize, Serialize};
use keycloak_domain::domain::entities::*;
use std::collections::HashMap;

/// Response DTOs that mirror domain entities but optimized for API responses

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserDto {
    pub id: Option<String>,
    pub username: String,
    pub email: Option<String>,
    pub email_verified: bool,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub enabled: bool,
    pub attributes: HashMap<String, Vec<String>>,
    pub required_actions: Vec<String>,
    pub created_timestamp: Option<chrono::DateTime<chrono::Utc>>,
}

impl From<User> for UserDto {
    fn from(user: User) -> Self {
        Self {
            id: user.id.map(|id| id.to_string()),
            username: user.username,
            email: user.email,
            email_verified: user.email_verified,
            first_name: user.first_name,
            last_name: user.last_name,
            enabled: user.enabled,
            attributes: user.attributes.attributes,
            required_actions: user.required_actions.iter().map(|a| a.to_string()).collect(),
            created_timestamp: user.timestamps.created_timestamp,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub email: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub enabled: Option<bool>,
    pub password: Option<String>,
    pub temporary_password: Option<bool>,
    pub attributes: Option<HashMap<String, Vec<String>>>,
}

impl CreateUserRequest {
    pub fn to_domain(&self) -> Result<User, keycloak_domain::domain::errors::DomainError> {
        let mut user = User::new(self.username.clone())?;
        user.email = self.email.clone();
        user.first_name = self.first_name.clone();
        user.last_name = self.last_name.clone();
        user.enabled = self.enabled.unwrap_or(true);
        
        if let Some(attrs) = &self.attributes {
            for (key, values) in attrs {
                user.attributes.set_attribute(key.clone(), values.clone());
            }
        }
        
        Ok(user)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealmDto {
    pub id: Option<String>,
    pub realm: String,
    pub display_name: Option<String>,
    pub enabled: bool,
    pub ssl_required: String,
    pub registration_allowed: bool,
    pub login_with_email_allowed: bool,
    pub attributes: HashMap<String, Vec<String>>,
}

impl From<Realm> for RealmDto {
    fn from(realm: Realm) -> Self {
        Self {
            id: realm.id.map(|id| id.to_string()),
            realm: realm.realm,
            display_name: realm.display_name,
            enabled: realm.enabled,
            ssl_required: match realm.ssl_required {
                SslRequired::All => "all".to_string(),
                SslRequired::External => "external".to_string(),
                SslRequired::None => "none".to_string(),
            },
            registration_allowed: realm.registration_allowed,
            login_with_email_allowed: realm.login_with_email_allowed,
            attributes: realm.attributes.attributes,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateRealmRequest {
    pub realm: String,
    pub display_name: Option<String>,
    pub enabled: Option<bool>,
}

impl CreateRealmRequest {
    pub fn to_domain(&self) -> Result<Realm, keycloak_domain::domain::errors::DomainError> {
        let mut realm = Realm::new(self.realm.clone())?;
        realm.display_name = self.display_name.clone();
        realm.enabled = self.enabled.unwrap_or(true);
        Ok(realm)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientDto {
    pub id: Option<String>,
    pub client_id: String,
    pub name: Option<String>,
    pub enabled: bool,
    pub protocol: String,
    pub public_client: bool,
    pub bearer_only: bool,
    pub standard_flow_enabled: bool,
    pub implicit_flow_enabled: bool,
    pub direct_access_grants_enabled: bool,
    pub service_accounts_enabled: bool,
    pub redirect_uris: Vec<String>,
    pub web_origins: Vec<String>,
}

impl From<Client> for ClientDto {
    fn from(client: Client) -> Self {
        Self {
            id: client.id.map(|id| id.to_string()),
            client_id: client.client_id,
            name: client.name,
            enabled: client.enabled,
            protocol: client.protocol,
            public_client: client.public_client,
            bearer_only: client.bearer_only,
            standard_flow_enabled: client.standard_flow_enabled,
            implicit_flow_enabled: client.implicit_flow_enabled,
            direct_access_grants_enabled: client.direct_access_grants_enabled,
            service_accounts_enabled: client.service_accounts_enabled,
            redirect_uris: client.redirect_uris,
            web_origins: client.web_origins,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateClientRequest {
    pub client_id: String,
    pub name: Option<String>,
    pub enabled: Option<bool>,
    pub protocol: Option<String>,
    pub public_client: Option<bool>,
    pub redirect_uris: Option<Vec<String>>,
}

impl CreateClientRequest {
    pub fn to_domain(&self) -> Result<Client, keycloak_domain::domain::errors::DomainError> {
        let mut client = Client::new(self.client_id.clone())?;
        client.name = self.name.clone();
        client.enabled = self.enabled.unwrap_or(true);
        client.protocol = self.protocol.clone().unwrap_or_else(|| "openid-connect".to_string());
        client.public_client = self.public_client.unwrap_or(false);
        if let Some(uris) = &self.redirect_uris {
            client.redirect_uris = uris.clone();
        }
        Ok(client)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupDto {
    pub id: Option<String>,
    pub name: String,
    pub path: String,
    pub attributes: HashMap<String, Vec<String>>,
    pub realm_roles: Vec<String>,
    pub client_roles: HashMap<String, Vec<String>>,
    pub sub_groups: Vec<GroupDto>,
}

impl From<Group> for GroupDto {
    fn from(group: Group) -> Self {
        Self {
            id: group.id.map(|id| id.to_string()),
            name: group.name,
            path: group.path,
            attributes: group.attributes.attributes,
            realm_roles: group.realm_roles,
            client_roles: group.client_roles,
            sub_groups: group.sub_groups.into_iter().map(|g| g.into()).collect(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateGroupRequest {
    pub name: String,
    pub path: Option<String>,
}

impl CreateGroupRequest {
    pub fn to_domain(&self) -> Result<Group, keycloak_domain::domain::errors::DomainError> {
        Group::new(self.name.clone(), self.path.clone())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleDto {
    pub id: Option<String>,
    pub name: String,
    pub description: Option<String>,
    pub composite: bool,
    pub client_role: bool,
    pub container_id: String,
}

impl From<Role> for RoleDto {
    fn from(role: Role) -> Self {
        Self {
            id: role.id.map(|id| id.to_string()),
            name: role.name,
            description: role.description,
            composite: role.composite,
            client_role: role.client_role,
            container_id: role.container_id,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateRoleRequest {
    pub name: String,
    pub description: Option<String>,
}

impl CreateRoleRequest {
    pub fn to_domain(&self, realm: &str, client_id: Option<&str>) -> Result<Role, keycloak_domain::domain::errors::DomainError> {
        if let Some(client_id) = client_id {
            Role::new_client_role(self.name.clone(), client_id.to_string())
        } else {
            Role::new_realm_role(self.name.clone(), realm.to_string())
        }.map(|mut role| {
            role.description = self.description.clone();
            role
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub data: Option<T>,
    pub message: Option<String>,
}

impl<T> ApiResponse<T> {
    pub fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            message: None,
        }
    }

    pub fn success_with_message(data: T, message: String) -> Self {
        Self {
            success: true,
            data: Some(data),
            message: Some(message),
        }
    }

    pub fn error(message: String) -> Self {
        Self {
            success: false,
            data: None,
            message: Some(message),
        }
    }
}

// Query parameter structs
#[derive(Debug, Deserialize)]
pub struct UserQuery {
    pub search: Option<String>,
    pub username: Option<String>,
    pub email: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub enabled: Option<bool>,
    pub email_verified: Option<bool>,
    #[serde(rename = "firstResult")]
    pub first_result: Option<i32>,
    #[serde(rename = "maxResults")]
    pub max_results: Option<i32>,
}

impl UserQuery {
    pub fn to_domain_filter(&self) -> UserFilter {
        UserFilter {
            search: self.search.clone(),
            username: self.username.clone(),
            email: self.email.clone(),
            first_name: self.first_name.clone(),
            last_name: self.last_name.clone(),
            enabled: self.enabled,
            email_verified: self.email_verified,
            first: self.first_result,
            max: self.max_results,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct ClientQuery {
    pub client_id: Option<String>,
    pub enabled: Option<bool>,
    #[serde(rename = "firstResult")]
    pub first_result: Option<i32>,
    #[serde(rename = "maxResults")]
    pub max_results: Option<i32>,
}

impl ClientQuery {
    pub fn to_domain_filter(&self) -> ClientFilter {
        ClientFilter {
            client_id: self.client_id.clone(),
            enabled: self.enabled,
            protocol: None,
            public_client: None,
            bearer_only: None,
            search: None,
            first: self.first_result,
            max: self.max_results,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct GroupQuery {
    pub search: Option<String>,
    #[serde(rename = "firstResult")]
    pub first_result: Option<i32>,
    #[serde(rename = "maxResults")]
    pub max_results: Option<i32>,
}

impl GroupQuery {
    pub fn to_domain_filter(&self) -> GroupFilter {
        GroupFilter {
            search: self.search.clone(),
            exact: None,
            first: self.first_result,
            max: self.max_results,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct RoleQuery {
    pub search: Option<String>,
    #[serde(rename = "firstResult")]
    pub first_result: Option<i32>,
    #[serde(rename = "maxResults")]
    pub max_results: Option<i32>,
}

impl RoleQuery {
    pub fn to_domain_filter(&self) -> RoleFilter {
        RoleFilter {
            search: self.search.clone(),
            client_role: None,
            composite: None,
            first: self.first_result,
            max: self.max_results,
        }
    }
}