use super::common::*;
use crate::domain::errors::{DomainError, DomainResult};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Domain entity representing a Keycloak user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: Option<EntityId>,
    pub username: String,
    pub email: Option<String>,
    pub email_verified: bool,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub enabled: bool,
    pub timestamps: Timestamps,
    pub attributes: Attributes,
    pub required_actions: Vec<RequiredAction>,
    pub federated_identities: Vec<FederatedIdentity>,
    pub access: Access,
}

impl User {
    /// Create a new user with required fields
    pub fn new(username: String) -> DomainResult<Self> {
        Self::validate_username(&username)?;

        Ok(Self {
            id: None,
            username,
            email: None,
            email_verified: false,
            first_name: None,
            last_name: None,
            enabled: true,
            timestamps: Timestamps::default(),
            attributes: Attributes::new(),
            required_actions: Vec::new(),
            federated_identities: Vec::new(),
            access: Access::default(),
        })
    }

    /// Create a new user with email
    pub fn with_email(username: String, email: String) -> DomainResult<Self> {
        Self::validate_username(&username)?;
        Self::validate_email(&email)?;

        let mut user = Self::new(username)?;
        user.email = Some(email);
        user.required_actions.push(RequiredAction::VerifyEmail);
        Ok(user)
    }

    /// Validate username according to business rules
    pub fn validate_username(username: &str) -> DomainResult<()> {
        if username.is_empty() {
            return Err(DomainError::InvalidUsername {
                reason: "Username cannot be empty".to_string(),
            });
        }

        if username.len() < 2 {
            return Err(DomainError::InvalidUsername {
                reason: "Username must be at least 2 characters long".to_string(),
            });
        }

        if username.len() > 100 {
            return Err(DomainError::InvalidUsername {
                reason: "Username cannot exceed 100 characters".to_string(),
            });
        }

        // Check for invalid characters
        if !username
            .chars()
            .all(|c| c.is_alphanumeric() || c == '_' || c == '-' || c == '.')
        {
            return Err(DomainError::InvalidUsername {
                reason: "Username can only contain alphanumeric characters, hyphens, underscores, and dots".to_string(),
            });
        }

        Ok(())
    }

    /// Validate email address
    pub fn validate_email(email: &str) -> DomainResult<()> {
        if email.is_empty() {
            return Err(DomainError::InvalidEmail {
                email: email.to_string(),
            });
        }

        // Basic email validation
        if !email.contains('@') || !email.contains('.') {
            return Err(DomainError::InvalidEmail {
                email: email.to_string(),
            });
        }

        let parts: Vec<&str> = email.split('@').collect();
        if parts.len() != 2 || parts[0].is_empty() || parts[1].is_empty() {
            return Err(DomainError::InvalidEmail {
                email: email.to_string(),
            });
        }

        Ok(())
    }

    /// Update user email with validation
    pub fn update_email(&mut self, email: Option<String>) -> DomainResult<()> {
        if let Some(ref email) = email {
            Self::validate_email(email)?;
            self.email_verified = false;
            if !self.required_actions.contains(&RequiredAction::VerifyEmail) {
                self.required_actions.push(RequiredAction::VerifyEmail);
            }
        }
        self.email = email;
        self.timestamps.updated_timestamp = Some(Utc::now());
        Ok(())
    }

    /// Mark email as verified
    pub fn verify_email(&mut self) -> DomainResult<()> {
        if self.email.is_none() {
            return Err(DomainError::Validation {
                field: "email".to_string(),
                message: "Cannot verify email when no email is set".to_string(),
            });
        }

        self.email_verified = true;
        self.required_actions
            .retain(|action| *action != RequiredAction::VerifyEmail);
        self.timestamps.updated_timestamp = Some(Utc::now());
        Ok(())
    }

    /// Update user profile
    pub fn update_profile(
        &mut self,
        first_name: Option<String>,
        last_name: Option<String>,
    ) -> DomainResult<()> {
        self.first_name = first_name;
        self.last_name = last_name;
        self.required_actions
            .retain(|action| *action != RequiredAction::UpdateProfile);
        self.timestamps.updated_timestamp = Some(Utc::now());
        Ok(())
    }

    /// Enable or disable the user
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
        self.timestamps.updated_timestamp = Some(Utc::now());
    }

    /// Add a required action
    pub fn add_required_action(&mut self, action: RequiredAction) {
        if !self.required_actions.contains(&action) {
            self.required_actions.push(action);
            self.timestamps.updated_timestamp = Some(Utc::now());
        }
    }

    /// Remove a required action
    pub fn remove_required_action(&mut self, action: &RequiredAction) {
        self.required_actions.retain(|a| a != action);
        self.timestamps.updated_timestamp = Some(Utc::now());
    }

    /// Add or update a user attribute
    pub fn set_attribute(&mut self, key: String, values: Vec<String>) {
        self.attributes.set_attribute(key, values);
        self.timestamps.updated_timestamp = Some(Utc::now());
    }

    /// Get a user attribute
    pub fn get_attribute(&self, key: &str) -> Option<&Vec<String>> {
        self.attributes.get_attribute(key)
    }

    /// Get a single user attribute value
    pub fn get_single_attribute(&self, key: &str) -> Option<&String> {
        self.attributes.get_single_attribute(key)
    }

    /// Remove a user attribute
    pub fn remove_attribute(&mut self, key: &str) -> Option<Vec<String>> {
        let result = self.attributes.remove_attribute(key);
        if result.is_some() {
            self.timestamps.updated_timestamp = Some(Utc::now());
        }
        result
    }

    /// Add a federated identity
    pub fn add_federated_identity(&mut self, identity: FederatedIdentity) {
        // Remove existing identity for the same provider
        self.federated_identities
            .retain(|id| id.identity_provider != identity.identity_provider);
        self.federated_identities.push(identity);
        self.timestamps.updated_timestamp = Some(Utc::now());
    }

    /// Remove a federated identity
    pub fn remove_federated_identity(&mut self, provider: &str) {
        let initial_len = self.federated_identities.len();
        self.federated_identities
            .retain(|id| id.identity_provider != provider);
        if self.federated_identities.len() != initial_len {
            self.timestamps.updated_timestamp = Some(Utc::now());
        }
    }

    /// Get full display name
    pub fn display_name(&self) -> String {
        match (&self.first_name, &self.last_name) {
            (Some(first), Some(last)) => format!("{first} {last}"),
            (Some(first), None) => first.clone(),
            (None, Some(last)) => last.clone(),
            (None, None) => self.username.clone(),
        }
    }

    /// Check if user is fully configured
    pub fn is_fully_configured(&self) -> bool {
        self.required_actions.is_empty()
    }

    /// Check if user needs email verification
    pub fn needs_email_verification(&self) -> bool {
        self.email.is_some() && !self.email_verified
    }
}

/// Request to create a new user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub email: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub enabled: Option<bool>,
    pub temporary_password: Option<String>,
    pub require_password_update: Option<bool>,
    pub attributes: Option<HashMap<String, Vec<String>>>,
}

impl CreateUserRequest {
    pub fn new(username: String) -> Self {
        Self {
            username,
            email: None,
            first_name: None,
            last_name: None,
            enabled: Some(true),
            temporary_password: None,
            require_password_update: None,
            attributes: None,
        }
    }

    pub fn with_email(mut self, email: String) -> Self {
        self.email = Some(email);
        self
    }

    pub fn with_name(mut self, first_name: String, last_name: String) -> Self {
        self.first_name = Some(first_name);
        self.last_name = Some(last_name);
        self
    }

    pub fn with_temporary_password(mut self, password: String) -> Self {
        self.temporary_password = Some(password);
        self.require_password_update = Some(true);
        self
    }

    pub fn validate(&self) -> DomainResult<()> {
        User::validate_username(&self.username)?;

        if let Some(ref email) = self.email {
            User::validate_email(email)?;
        }

        if let Some(ref password) = self.temporary_password {
            if password.len() < 8 {
                return Err(DomainError::InvalidPassword {
                    reason: "Password must be at least 8 characters long".to_string(),
                });
            }
        }

        Ok(())
    }

    pub fn to_domain_user(&self) -> DomainResult<User> {
        self.validate()?;

        let mut user = if let Some(ref email) = self.email {
            User::with_email(self.username.clone(), email.clone())?
        } else {
            User::new(self.username.clone())?
        };

        user.first_name = self.first_name.clone();
        user.last_name = self.last_name.clone();
        user.enabled = self.enabled.unwrap_or(true);

        if let Some(ref attrs) = self.attributes {
            for (key, values) in attrs {
                user.set_attribute(key.clone(), values.clone());
            }
        }

        if self.require_password_update.unwrap_or(false) {
            user.add_required_action(RequiredAction::UpdatePassword);
        }

        Ok(user)
    }
}

/// Request to update an existing user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateUserRequest {
    pub email: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub enabled: Option<bool>,
    pub attributes: Option<HashMap<String, Vec<String>>>,
}

impl UpdateUserRequest {
    pub fn apply_to_user(&self, user: &mut User) -> DomainResult<()> {
        if let Some(ref email) = self.email {
            user.update_email(Some(email.clone()))?;
        }

        if let Some(ref first_name) = self.first_name {
            user.first_name = Some(first_name.clone());
        }

        if let Some(ref last_name) = self.last_name {
            user.last_name = Some(last_name.clone());
        }

        if let Some(enabled) = self.enabled {
            user.set_enabled(enabled);
        }

        if let Some(ref attrs) = self.attributes {
            for (key, values) in attrs {
                user.set_attribute(key.clone(), values.clone());
            }
        }

        Ok(())
    }
}

/// Filter for querying users
#[derive(Debug, Clone, Default)]
pub struct UserFilter {
    pub search: Option<String>,
    pub email: Option<String>,
    pub username: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub enabled: Option<bool>,
    pub email_verified: Option<bool>,
    pub first: Option<i32>,
    pub max: Option<i32>,
}

impl UserFilter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_search(mut self, search: String) -> Self {
        self.search = Some(search);
        self
    }

    pub fn with_email(mut self, email: String) -> Self {
        self.email = Some(email);
        self
    }

    pub fn with_username(mut self, username: String) -> Self {
        self.username = Some(username);
        self
    }

    pub fn with_enabled(mut self, enabled: bool) -> Self {
        self.enabled = Some(enabled);
        self
    }

    pub fn with_pagination(mut self, first: i32, max: i32) -> Self {
        self.first = Some(first);
        self.max = Some(max);
        self
    }
}
