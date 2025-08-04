use super::common::*;
use crate::domain::errors::{DomainError, DomainResult};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Domain entity representing a Keycloak client
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Client {
    pub id: Option<EntityId>,
    pub client_id: String,
    pub name: Option<String>,
    pub description: Option<String>,
    pub enabled: bool,
    pub client_authenticator_type: String,
    pub secret: Option<String>,
    pub registration_access_token: Option<String>,
    pub default_scopes: Vec<String>,
    pub optional_scopes: Vec<String>,
    pub redirect_uris: Vec<String>,
    pub web_origins: Vec<String>,
    pub not_before: Option<DateTime<Utc>>,
    pub bearer_only: bool,
    pub consent_required: bool,
    pub standard_flow_enabled: bool,
    pub implicit_flow_enabled: bool,
    pub direct_access_grants_enabled: bool,
    pub service_accounts_enabled: bool,
    pub authorization_services_enabled: bool,
    pub public_client: bool,
    pub frontchannel_logout: bool,
    pub protocol: String,
    pub attributes: Attributes,
    pub authentication_flow_binding_overrides: HashMap<String, String>,
    pub full_scope_allowed: bool,
    pub node_re_registration_timeout: Option<i32>,
    pub timestamps: Timestamps,
}

impl Client {
    /// Create a new client with required fields
    pub fn new(client_id: String) -> DomainResult<Self> {
        Self::validate_client_id(&client_id)?;

        Ok(Self {
            id: None,
            client_id,
            name: None,
            description: None,
            enabled: true,
            client_authenticator_type: "client-secret".to_string(),
            secret: None,
            registration_access_token: None,
            default_scopes: Vec::new(),
            optional_scopes: Vec::new(),
            redirect_uris: Vec::new(),
            web_origins: Vec::new(),
            not_before: None,
            bearer_only: false,
            consent_required: false,
            standard_flow_enabled: true,
            implicit_flow_enabled: false,
            direct_access_grants_enabled: true,
            service_accounts_enabled: false,
            authorization_services_enabled: false,
            public_client: false,
            frontchannel_logout: false,
            protocol: "openid-connect".to_string(),
            attributes: Attributes::new(),
            authentication_flow_binding_overrides: HashMap::new(),
            full_scope_allowed: true,
            node_re_registration_timeout: None,
            timestamps: Timestamps::default(),
        })
    }

    /// Create a public client (SPA, mobile app)
    pub fn public_client(client_id: String) -> DomainResult<Self> {
        let mut client = Self::new(client_id)?;
        client.public_client = true;
        client.client_authenticator_type = "none".to_string();
        client.standard_flow_enabled = true;
        client.direct_access_grants_enabled = false;
        Ok(client)
    }

    /// Create a confidential client (server-side application)
    pub fn confidential_client(client_id: String) -> DomainResult<Self> {
        let mut client = Self::new(client_id)?;
        client.public_client = false;
        client.client_authenticator_type = "client-secret".to_string();
        client.standard_flow_enabled = true;
        client.direct_access_grants_enabled = true;
        Ok(client)
    }

    /// Create a service account client (machine-to-machine)
    pub fn service_account_client(client_id: String) -> DomainResult<Self> {
        let mut client = Self::new(client_id)?;
        client.public_client = false;
        client.service_accounts_enabled = true;
        client.standard_flow_enabled = false;
        client.implicit_flow_enabled = false;
        client.direct_access_grants_enabled = false;
        Ok(client)
    }

    /// Validate client ID according to business rules
    pub fn validate_client_id(client_id: &str) -> DomainResult<()> {
        if client_id.is_empty() {
            return Err(DomainError::Validation {
                field: "client_id".to_string(),
                message: "Client ID cannot be empty".to_string(),
            });
        }

        if client_id.len() < 2 {
            return Err(DomainError::Validation {
                field: "client_id".to_string(),
                message: "Client ID must be at least 2 characters long".to_string(),
            });
        }

        if client_id.len() > 255 {
            return Err(DomainError::Validation {
                field: "client_id".to_string(),
                message: "Client ID cannot exceed 255 characters".to_string(),
            });
        }

        Ok(())
    }

    /// Validate redirect URI
    pub fn validate_redirect_uri(uri: &str) -> DomainResult<()> {
        if uri.is_empty() {
            return Err(DomainError::Validation {
                field: "redirect_uri".to_string(),
                message: "Redirect URI cannot be empty".to_string(),
            });
        }

        // Basic URI validation
        if !uri.starts_with("http://") && !uri.starts_with("https://") && uri != "*" {
            return Err(DomainError::Validation {
                field: "redirect_uri".to_string(),
                message: "Redirect URI must start with http:// or https:// or be '*'".to_string(),
            });
        }

        Ok(())
    }

    /// Update client name and description
    pub fn update_info(&mut self, name: Option<String>, description: Option<String>) {
        self.name = name;
        self.description = description;
        self.timestamps.updated_timestamp = Some(Utc::now());
    }

    /// Enable or disable the client
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
        self.timestamps.updated_timestamp = Some(Utc::now());
    }

    /// Set client secret (for confidential clients)
    pub fn set_secret(&mut self, secret: Option<String>) -> DomainResult<()> {
        if self.public_client && secret.is_some() {
            return Err(DomainError::Validation {
                field: "secret".to_string(),
                message: "Public clients cannot have secrets".to_string(),
            });
        }

        self.secret = secret;
        self.timestamps.updated_timestamp = Some(Utc::now());
        Ok(())
    }

    /// Add a redirect URI
    pub fn add_redirect_uri(&mut self, uri: String) -> DomainResult<()> {
        Self::validate_redirect_uri(&uri)?;

        if !self.redirect_uris.contains(&uri) {
            self.redirect_uris.push(uri);
            self.timestamps.updated_timestamp = Some(Utc::now());
        }
        Ok(())
    }

    /// Remove a redirect URI
    pub fn remove_redirect_uri(&mut self, uri: &str) {
        let initial_len = self.redirect_uris.len();
        self.redirect_uris.retain(|u| u != uri);
        if self.redirect_uris.len() != initial_len {
            self.timestamps.updated_timestamp = Some(Utc::now());
        }
    }

    /// Add a web origin
    pub fn add_web_origin(&mut self, origin: String) {
        if !self.web_origins.contains(&origin) {
            self.web_origins.push(origin);
            self.timestamps.updated_timestamp = Some(Utc::now());
        }
    }

    /// Remove a web origin
    pub fn remove_web_origin(&mut self, origin: &str) {
        let initial_len = self.web_origins.len();
        self.web_origins.retain(|o| o != origin);
        if self.web_origins.len() != initial_len {
            self.timestamps.updated_timestamp = Some(Utc::now());
        }
    }

    /// Configure OAuth2 flows
    pub fn configure_flows(
        &mut self,
        standard_flow: bool,
        implicit_flow: bool,
        direct_access_grants: bool,
        service_accounts: bool,
    ) -> DomainResult<()> {
        if self.public_client && service_accounts {
            return Err(DomainError::Validation {
                field: "service_accounts_enabled".to_string(),
                message: "Public clients cannot enable service accounts".to_string(),
            });
        }

        self.standard_flow_enabled = standard_flow;
        self.implicit_flow_enabled = implicit_flow;
        self.direct_access_grants_enabled = direct_access_grants;
        self.service_accounts_enabled = service_accounts;
        self.timestamps.updated_timestamp = Some(Utc::now());
        Ok(())
    }

    /// Configure client scopes
    pub fn configure_scopes(&mut self, default_scopes: Vec<String>, optional_scopes: Vec<String>) {
        self.default_scopes = default_scopes;
        self.optional_scopes = optional_scopes;
        self.timestamps.updated_timestamp = Some(Utc::now());
    }

    /// Add a default scope
    pub fn add_default_scope(&mut self, scope: String) {
        if !self.default_scopes.contains(&scope) {
            self.default_scopes.push(scope);
            self.timestamps.updated_timestamp = Some(Utc::now());
        }
    }

    /// Remove a default scope
    pub fn remove_default_scope(&mut self, scope: &str) {
        let initial_len = self.default_scopes.len();
        self.default_scopes.retain(|s| s != scope);
        if self.default_scopes.len() != initial_len {
            self.timestamps.updated_timestamp = Some(Utc::now());
        }
    }

    /// Add an optional scope
    pub fn add_optional_scope(&mut self, scope: String) {
        if !self.optional_scopes.contains(&scope) {
            self.optional_scopes.push(scope);
            self.timestamps.updated_timestamp = Some(Utc::now());
        }
    }

    /// Remove an optional scope
    pub fn remove_optional_scope(&mut self, scope: &str) {
        let initial_len = self.optional_scopes.len();
        self.optional_scopes.retain(|s| s != scope);
        if self.optional_scopes.len() != initial_len {
            self.timestamps.updated_timestamp = Some(Utc::now());
        }
    }

    /// Check if client is a public client
    pub fn is_public(&self) -> bool {
        self.public_client
    }

    /// Check if client supports authorization services
    pub fn supports_authorization(&self) -> bool {
        self.authorization_services_enabled
    }

    /// Check if client supports service accounts
    pub fn supports_service_accounts(&self) -> bool {
        self.service_accounts_enabled
    }
}

/// Client authentication methods
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[derive(Default)]
pub enum ClientAuthenticatorType {
    #[serde(rename = "client-secret")]
    #[default]
    ClientSecret,
    #[serde(rename = "client-secret-jwt")]
    ClientSecretJwt,
    #[serde(rename = "private-key-jwt")]
    PrivateKeyJwt,
    #[serde(rename = "none")]
    None,
}


/// Request to create a new client
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateClientRequest {
    pub client_id: String,
    pub name: Option<String>,
    pub description: Option<String>,
    pub enabled: Option<bool>,
    pub client_protocol: Option<String>,
    pub public_client: Option<bool>,
    pub bearer_only: Option<bool>,
    pub standard_flow_enabled: Option<bool>,
    pub implicit_flow_enabled: Option<bool>,
    pub direct_access_grants_enabled: Option<bool>,
    pub service_accounts_enabled: Option<bool>,
    pub authorization_services_enabled: Option<bool>,
    pub redirect_uris: Option<Vec<String>>,
    pub web_origins: Option<Vec<String>>,
    pub attributes: Option<HashMap<String, Vec<String>>>,
}

impl CreateClientRequest {
    pub fn new(client_id: String) -> Self {
        Self {
            client_id,
            name: None,
            description: None,
            enabled: Some(true),
            client_protocol: Some("openid-connect".to_string()),
            public_client: Some(false),
            bearer_only: Some(false),
            standard_flow_enabled: Some(true),
            implicit_flow_enabled: Some(false),
            direct_access_grants_enabled: Some(true),
            service_accounts_enabled: Some(false),
            authorization_services_enabled: Some(false),
            redirect_uris: None,
            web_origins: None,
            attributes: None,
        }
    }

    pub fn public_client(mut self) -> Self {
        self.public_client = Some(true);
        self.direct_access_grants_enabled = Some(false);
        self
    }

    pub fn service_account(mut self) -> Self {
        self.public_client = Some(false);
        self.service_accounts_enabled = Some(true);
        self.standard_flow_enabled = Some(false);
        self.implicit_flow_enabled = Some(false);
        self.direct_access_grants_enabled = Some(false);
        self
    }

    pub fn with_redirect_uris(mut self, uris: Vec<String>) -> Self {
        self.redirect_uris = Some(uris);
        self
    }

    pub fn validate(&self) -> DomainResult<()> {
        Client::validate_client_id(&self.client_id)?;

        if let Some(ref uris) = self.redirect_uris {
            for uri in uris {
                Client::validate_redirect_uri(uri)?;
            }
        }

        Ok(())
    }

    pub fn to_domain_client(&self) -> DomainResult<Client> {
        self.validate()?;

        let mut client = if self.public_client.unwrap_or(false) {
            Client::public_client(self.client_id.clone())?
        } else if self.service_accounts_enabled.unwrap_or(false) {
            Client::service_account_client(self.client_id.clone())?
        } else {
            Client::confidential_client(self.client_id.clone())?
        };

        client.name = self.name.clone();
        client.description = self.description.clone();
        client.enabled = self.enabled.unwrap_or(true);

        if let Some(ref protocol) = self.client_protocol {
            client.protocol = protocol.clone();
        }

        if let Some(bearer_only) = self.bearer_only {
            client.bearer_only = bearer_only;
        }

        if let Some(standard_flow) = self.standard_flow_enabled {
            client.standard_flow_enabled = standard_flow;
        }

        if let Some(implicit_flow) = self.implicit_flow_enabled {
            client.implicit_flow_enabled = implicit_flow;
        }

        if let Some(direct_access) = self.direct_access_grants_enabled {
            client.direct_access_grants_enabled = direct_access;
        }

        if let Some(authorization) = self.authorization_services_enabled {
            client.authorization_services_enabled = authorization;
        }

        if let Some(ref uris) = self.redirect_uris {
            client.redirect_uris = uris.clone();
        }

        if let Some(ref origins) = self.web_origins {
            client.web_origins = origins.clone();
        }

        if let Some(ref attrs) = self.attributes {
            for (key, values) in attrs {
                client.attributes.set_attribute(key.clone(), values.clone());
            }
        }

        Ok(client)
    }
}

/// Request to update an existing client
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateClientRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub enabled: Option<bool>,
    pub standard_flow_enabled: Option<bool>,
    pub implicit_flow_enabled: Option<bool>,
    pub direct_access_grants_enabled: Option<bool>,
    pub service_accounts_enabled: Option<bool>,
    pub authorization_services_enabled: Option<bool>,
    pub redirect_uris: Option<Vec<String>>,
    pub web_origins: Option<Vec<String>>,
    pub attributes: Option<HashMap<String, Vec<String>>>,
}

impl UpdateClientRequest {
    pub fn apply_to_client(&self, client: &mut Client) -> DomainResult<()> {
        if let Some(ref name) = self.name {
            client.name = Some(name.clone());
        }

        if let Some(ref description) = self.description {
            client.description = Some(description.clone());
        }

        if let Some(enabled) = self.enabled {
            client.set_enabled(enabled);
        }

        if let Some(standard_flow) = self.standard_flow_enabled {
            client.standard_flow_enabled = standard_flow;
        }

        if let Some(implicit_flow) = self.implicit_flow_enabled {
            client.implicit_flow_enabled = implicit_flow;
        }

        if let Some(direct_access) = self.direct_access_grants_enabled {
            client.direct_access_grants_enabled = direct_access;
        }

        if let Some(service_accounts) = self.service_accounts_enabled {
            if client.public_client && service_accounts {
                return Err(DomainError::Validation {
                    field: "service_accounts_enabled".to_string(),
                    message: "Public clients cannot enable service accounts".to_string(),
                });
            }
            client.service_accounts_enabled = service_accounts;
        }

        if let Some(authorization) = self.authorization_services_enabled {
            client.authorization_services_enabled = authorization;
        }

        if let Some(ref uris) = self.redirect_uris {
            for uri in uris {
                Client::validate_redirect_uri(uri)?;
            }
            client.redirect_uris = uris.clone();
        }

        if let Some(ref origins) = self.web_origins {
            client.web_origins = origins.clone();
        }

        if let Some(ref attrs) = self.attributes {
            for (key, values) in attrs {
                client.attributes.set_attribute(key.clone(), values.clone());
            }
        }

        client.timestamps.updated_timestamp = Some(Utc::now());
        Ok(())
    }
}

/// Filter for querying clients
#[derive(Debug, Clone, Default)]
pub struct ClientFilter {
    pub client_id: Option<String>,
    pub search: Option<String>,
    pub enabled: Option<bool>,
    pub protocol: Option<String>,
    pub public_client: Option<bool>,
    pub bearer_only: Option<bool>,
    pub first: Option<i32>,
    pub max: Option<i32>,
}

impl ClientFilter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_client_id(mut self, client_id: String) -> Self {
        self.client_id = Some(client_id);
        self
    }

    pub fn with_search(mut self, search: String) -> Self {
        self.search = Some(search);
        self
    }

    pub fn with_enabled(mut self, enabled: bool) -> Self {
        self.enabled = Some(enabled);
        self
    }

    pub fn with_protocol(mut self, protocol: String) -> Self {
        self.protocol = Some(protocol);
        self
    }

    pub fn with_pagination(mut self, first: i32, max: i32) -> Self {
        self.first = Some(first);
        self.max = Some(max);
        self
    }
}
