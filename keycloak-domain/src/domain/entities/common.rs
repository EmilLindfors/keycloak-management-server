use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Unique identifier for entities
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EntityId(pub String);

impl EntityId {
    pub fn new() -> Self {
        Self(Uuid::new_v4().to_string())
    }

    pub fn from_string(id: String) -> Self {
        Self(id)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for EntityId {
    fn default() -> Self {
        Self::new()
    }
}

impl From<String> for EntityId {
    fn from(id: String) -> Self {
        Self(id)
    }
}

impl From<&str> for EntityId {
    fn from(id: &str) -> Self {
        Self(id.to_string())
    }
}

impl std::fmt::Display for EntityId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Timestamp information for entities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Timestamps {
    pub created_timestamp: Option<DateTime<Utc>>,
    pub updated_timestamp: Option<DateTime<Utc>>,
}

impl Default for Timestamps {
    fn default() -> Self {
        let now = Utc::now();
        Self {
            created_timestamp: Some(now),
            updated_timestamp: Some(now),
        }
    }
}

/// User attributes as key-value pairs
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Attributes {
    pub attributes: HashMap<String, Vec<String>>,
}

impl Attributes {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_attribute(&mut self, key: String, value: String) {
        self.attributes.entry(key).or_default().push(value);
    }

    pub fn set_attribute(&mut self, key: String, values: Vec<String>) {
        self.attributes.insert(key, values);
    }

    pub fn get_attribute(&self, key: &str) -> Option<&Vec<String>> {
        self.attributes.get(key)
    }

    pub fn get_single_attribute(&self, key: &str) -> Option<&String> {
        self.attributes.get(key)?.first()
    }

    pub fn remove_attribute(&mut self, key: &str) -> Option<Vec<String>> {
        self.attributes.remove(key)
    }
}

/// Credentials for authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credential {
    pub id: Option<EntityId>,
    pub type_: String,
    pub value: Option<String>,
    pub temporary: Option<bool>,
    pub created_date: Option<DateTime<Utc>>,
    pub user_label: Option<String>,
    pub secret_data: Option<String>,
    pub credential_data: Option<String>,
    pub priority: Option<i32>,
}

impl Credential {
    pub fn password(value: String, temporary: bool) -> Self {
        Self {
            id: None,
            type_: "password".to_string(),
            value: Some(value),
            temporary: Some(temporary),
            created_date: Some(Utc::now()),
            user_label: None,
            secret_data: None,
            credential_data: None,
            priority: None,
        }
    }

    pub fn is_password(&self) -> bool {
        self.type_ == "password"
    }

    pub fn is_temporary(&self) -> bool {
        self.temporary.unwrap_or(false)
    }
}

/// Required actions for users
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum RequiredAction {
    #[serde(rename = "VERIFY_EMAIL")]
    VerifyEmail,
    #[serde(rename = "UPDATE_PROFILE")]
    UpdateProfile,
    #[serde(rename = "CONFIGURE_TOTP")]
    ConfigureTotp,
    #[serde(rename = "UPDATE_PASSWORD")]
    UpdatePassword,
    #[serde(rename = "terms_and_conditions")]
    TermsAndConditions,
    Other(String),
}

impl std::fmt::Display for RequiredAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            RequiredAction::VerifyEmail => "VERIFY_EMAIL",
            RequiredAction::UpdateProfile => "UPDATE_PROFILE",
            RequiredAction::ConfigureTotp => "CONFIGURE_TOTP",
            RequiredAction::UpdatePassword => "UPDATE_PASSWORD",
            RequiredAction::TermsAndConditions => "terms_and_conditions",
            RequiredAction::Other(s) => s,
        };
        write!(f, "{s}")
    }
}

/// Federated identity for users
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederatedIdentity {
    pub identity_provider: String,
    pub user_id: String,
    pub user_name: String,
}

/// Access information for entities
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Access {
    pub manage_group_membership: Option<bool>,
    pub view: Option<bool>,
    pub map_roles: Option<bool>,
    pub impersonate: Option<bool>,
    pub manage: Option<bool>,
}

/// Email verification status
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EmailStatus {
    pub email_verified: bool,
    pub email: Option<String>,
}

impl EmailStatus {
    pub fn new(email: Option<String>, verified: bool) -> Self {
        Self {
            email,
            email_verified: verified,
        }
    }

    pub fn verified(email: String) -> Self {
        Self {
            email: Some(email),
            email_verified: true,
        }
    }

    pub fn unverified(email: String) -> Self {
        Self {
            email: Some(email),
            email_verified: false,
        }
    }
}

/// Filter criteria for entity queries
#[derive(Debug, Clone, Default)]
pub struct QueryFilter {
    pub search: Option<String>,
    pub first: Option<i32>,
    pub max: Option<i32>,
}

impl QueryFilter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_search(mut self, search: String) -> Self {
        self.search = Some(search);
        self
    }

    pub fn with_pagination(mut self, first: i32, max: i32) -> Self {
        self.first = Some(first);
        self.max = Some(max);
        self
    }
}
