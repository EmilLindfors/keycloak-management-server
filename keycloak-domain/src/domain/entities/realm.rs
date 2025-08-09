use super::common::*;
use crate::domain::errors::{DomainError, DomainResult};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Domain entity representing a Keycloak realm
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Realm {
    pub id: Option<EntityId>,
    pub realm: String,
    pub display_name: Option<String>,
    pub display_name_html: Option<String>,
    pub enabled: bool,
    pub ssl_required: SslRequired,
    pub registration_allowed: bool,
    pub registration_email_as_username: bool,
    pub remember_me: bool,
    pub verify_email: bool,
    pub login_with_email_allowed: bool,
    pub duplicate_emails_allowed: bool,
    pub reset_password_allowed: bool,
    pub edit_username_allowed: bool,
    pub brute_force_protected: bool,
    pub permanent_lockout: bool,
    pub max_failure_wait_seconds: i32,
    pub minimum_quick_login_wait_seconds: i32,
    pub wait_increment_seconds: i32,
    pub quick_login_check_milli_seconds: i32,
    pub max_delta_time_seconds: i32,
    pub failure_factor: i32,
    pub default_roles: Vec<String>,
    pub required_credentials: Vec<String>,
    pub password_policy: Option<String>,
    pub otp_policy_type: Option<String>,
    pub otp_policy_algorithm: Option<String>,
    pub otp_policy_digits: Option<i32>,
    pub otp_policy_look_ahead_window: Option<i32>,
    pub otp_policy_period: Option<i32>,
    pub attributes: Attributes,
    pub timestamps: Timestamps,
}

impl Realm {
    /// Create a new realm with required fields
    pub fn new(realm: String) -> DomainResult<Self> {
        Self::validate_realm_name(&realm)?;

        Ok(Self {
            id: None,
            realm,
            display_name: None,
            display_name_html: None,
            enabled: true,
            ssl_required: SslRequired::External,
            registration_allowed: false,
            registration_email_as_username: false,
            remember_me: false,
            verify_email: false,
            login_with_email_allowed: true,
            duplicate_emails_allowed: false,
            reset_password_allowed: false,
            edit_username_allowed: false,
            brute_force_protected: false,
            permanent_lockout: false,
            max_failure_wait_seconds: 900,
            minimum_quick_login_wait_seconds: 60,
            wait_increment_seconds: 60,
            quick_login_check_milli_seconds: 1000,
            max_delta_time_seconds: 43200,
            failure_factor: 30,
            default_roles: vec![
                "offline_access".to_string(),
                "uma_authorization".to_string(),
            ],
            required_credentials: vec!["password".to_string()],
            password_policy: None,
            otp_policy_type: Some("totp".to_string()),
            otp_policy_algorithm: Some("HmacSHA1".to_string()),
            otp_policy_digits: Some(6),
            otp_policy_look_ahead_window: Some(1),
            otp_policy_period: Some(30),
            attributes: Attributes::new(),
            timestamps: Timestamps::default(),
        })
    }

    /// Validate realm name according to business rules
    pub fn validate_realm_name(realm: &str) -> DomainResult<()> {
        if realm.is_empty() {
            return Err(DomainError::Validation {
                field: "realm".to_string(),
                message: "Realm name cannot be empty".to_string(),
            });
        }

        if realm.len() < 2 {
            return Err(DomainError::Validation {
                field: "realm".to_string(),
                message: "Realm name must be at least 2 characters long".to_string(),
            });
        }

        if realm.len() > 36 {
            return Err(DomainError::Validation {
                field: "realm".to_string(),
                message: "Realm name cannot exceed 36 characters".to_string(),
            });
        }

        // Check for invalid characters
        if !realm
            .chars()
            .all(|c| c.is_alphanumeric() || c == '_' || c == '-')
        {
            return Err(DomainError::Validation {
                field: "realm".to_string(),
                message:
                    "Realm name can only contain alphanumeric characters, hyphens, and underscores"
                        .to_string(),
            });
        }

        // Reserved realm names
        let reserved = ["master", "admin", "security-admin-console"];
        if reserved.contains(&realm) {
            return Err(DomainError::Validation {
                field: "realm".to_string(),
                message: format!("Realm name '{realm}' is reserved"),
            });
        }

        Ok(())
    }

    /// Update realm display name
    pub fn update_display_name(&mut self, display_name: Option<String>) {
        self.display_name = display_name;
        self.timestamps.updated_timestamp = Some(Utc::now());
    }

    /// Enable or disable the realm
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
        self.timestamps.updated_timestamp = Some(Utc::now());
    }

    /// Update SSL requirements
    pub fn set_ssl_required(&mut self, ssl_required: SslRequired) {
        self.ssl_required = ssl_required;
        self.timestamps.updated_timestamp = Some(Utc::now());
    }

    /// Configure user registration
    pub fn configure_registration(&mut self, allowed: bool, email_as_username: bool) {
        self.registration_allowed = allowed;
        self.registration_email_as_username = email_as_username;
        self.timestamps.updated_timestamp = Some(Utc::now());
    }

    /// Configure email settings
    pub fn configure_email_settings(
        &mut self,
        verify_email: bool,
        login_with_email: bool,
        duplicate_emails: bool,
    ) {
        self.verify_email = verify_email;
        self.login_with_email_allowed = login_with_email;
        self.duplicate_emails_allowed = duplicate_emails;
        self.timestamps.updated_timestamp = Some(Utc::now());
    }

    /// Configure security settings
    pub fn configure_security(
        &mut self,
        reset_password: bool,
        edit_username: bool,
        brute_force_protection: bool,
    ) {
        self.reset_password_allowed = reset_password;
        self.edit_username_allowed = edit_username;
        self.brute_force_protected = brute_force_protection;
        self.timestamps.updated_timestamp = Some(Utc::now());
    }

    /// Set password policy
    pub fn set_password_policy(&mut self, policy: Option<String>) -> DomainResult<()> {
        if let Some(ref policy) = policy {
            // Basic validation of password policy format
            if policy.is_empty() {
                return Err(DomainError::Validation {
                    field: "password_policy".to_string(),
                    message: "Password policy cannot be empty".to_string(),
                });
            }
        }

        self.password_policy = policy;
        self.timestamps.updated_timestamp = Some(Utc::now());
        Ok(())
    }

    /// Configure OTP policy
    pub fn configure_otp_policy(
        &mut self,
        type_: Option<String>,
        algorithm: Option<String>,
        digits: Option<i32>,
        period: Option<i32>,
    ) -> DomainResult<()> {
        if let Some(digits) = digits {
            if !(4..=8).contains(&digits) {
                return Err(DomainError::Validation {
                    field: "otp_policy_digits".to_string(),
                    message: "OTP digits must be between 4 and 8".to_string(),
                });
            }
        }

        if let Some(period) = period {
            if !(1..=120).contains(&period) {
                return Err(DomainError::Validation {
                    field: "otp_policy_period".to_string(),
                    message: "OTP period must be between 1 and 120 seconds".to_string(),
                });
            }
        }

        self.otp_policy_type = type_;
        self.otp_policy_algorithm = algorithm;
        self.otp_policy_digits = digits;
        self.otp_policy_period = period;
        self.timestamps.updated_timestamp = Some(Utc::now());
        Ok(())
    }

    /// Add a default role
    pub fn add_default_role(&mut self, role: String) {
        if !self.default_roles.contains(&role) {
            self.default_roles.push(role);
            self.timestamps.updated_timestamp = Some(Utc::now());
        }
    }

    /// Remove a default role
    pub fn remove_default_role(&mut self, role: &str) {
        let initial_len = self.default_roles.len();
        self.default_roles.retain(|r| r != role);
        if self.default_roles.len() != initial_len {
            self.timestamps.updated_timestamp = Some(Utc::now());
        }
    }

    /// Check if realm is the master realm
    pub fn is_master_realm(&self) -> bool {
        self.realm == "master"
    }

    /// Check if realm allows user registration
    pub fn allows_registration(&self) -> bool {
        self.enabled && self.registration_allowed
    }
}

/// SSL requirement levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[derive(Default)]
pub enum SslRequired {
    #[serde(rename = "all")]
    All,
    #[serde(rename = "external")]
    #[default]
    External,
    #[serde(rename = "none")]
    None,
}


/// Request to create a new realm
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateRealmRequest {
    pub realm: String,
    pub display_name: Option<String>,
    pub enabled: Option<bool>,
    pub ssl_required: Option<SslRequired>,
    pub registration_allowed: Option<bool>,
    pub verify_email: Option<bool>,
    pub login_with_email_allowed: Option<bool>,
    pub reset_password_allowed: Option<bool>,
    pub attributes: Option<HashMap<String, Vec<String>>>,
}

impl CreateRealmRequest {
    pub fn new(realm: String) -> Self {
        Self {
            realm,
            display_name: None,
            enabled: Some(true),
            ssl_required: Some(SslRequired::External),
            registration_allowed: Some(false),
            verify_email: Some(false),
            login_with_email_allowed: Some(true),
            reset_password_allowed: Some(false),
            attributes: None,
        }
    }

    pub fn with_display_name(mut self, display_name: String) -> Self {
        self.display_name = Some(display_name);
        self
    }

    pub fn with_registration(mut self, allowed: bool) -> Self {
        self.registration_allowed = Some(allowed);
        self
    }

    pub fn validate(&self) -> DomainResult<()> {
        Realm::validate_realm_name(&self.realm)?;
        Ok(())
    }

    pub fn to_domain_realm(&self) -> DomainResult<Realm> {
        self.validate()?;

        let mut realm = Realm::new(self.realm.clone())?;

        if let Some(ref display_name) = self.display_name {
            realm.display_name = Some(display_name.clone());
        }

        if let Some(enabled) = self.enabled {
            realm.enabled = enabled;
        }

        if let Some(ssl_required) = self.ssl_required.clone() {
            realm.ssl_required = ssl_required;
        }

        if let Some(registration_allowed) = self.registration_allowed {
            realm.registration_allowed = registration_allowed;
        }

        if let Some(verify_email) = self.verify_email {
            realm.verify_email = verify_email;
        }

        if let Some(login_with_email) = self.login_with_email_allowed {
            realm.login_with_email_allowed = login_with_email;
        }

        if let Some(reset_password) = self.reset_password_allowed {
            realm.reset_password_allowed = reset_password;
        }

        if let Some(ref attrs) = self.attributes {
            for (key, values) in attrs {
                realm.attributes.set_attribute(key.clone(), values.clone());
            }
        }

        Ok(realm)
    }
}

/// Filter for realm queries
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RealmFilter {
    /// Return brief representation of realms (less detailed)
    pub brief_representation: Option<bool>,
}

impl RealmFilter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_brief_representation(mut self, brief: bool) -> Self {
        self.brief_representation = Some(brief);
        self
    }
}

/// Request to update an existing realm
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateRealmRequest {
    pub display_name: Option<String>,
    pub enabled: Option<bool>,
    pub ssl_required: Option<SslRequired>,
    pub registration_allowed: Option<bool>,
    pub verify_email: Option<bool>,
    pub login_with_email_allowed: Option<bool>,
    pub reset_password_allowed: Option<bool>,
    pub brute_force_protected: Option<bool>,
    pub password_policy: Option<String>,
    pub attributes: Option<HashMap<String, Vec<String>>>,
}

impl UpdateRealmRequest {
    pub fn apply_to_realm(&self, realm: &mut Realm) -> DomainResult<()> {
        if let Some(ref display_name) = self.display_name {
            realm.update_display_name(Some(display_name.clone()));
        }

        if let Some(enabled) = self.enabled {
            realm.set_enabled(enabled);
        }

        if let Some(ssl_required) = self.ssl_required.clone() {
            realm.set_ssl_required(ssl_required);
        }

        if let Some(registration_allowed) = self.registration_allowed {
            realm.registration_allowed = registration_allowed;
        }

        if let Some(verify_email) = self.verify_email {
            realm.verify_email = verify_email;
        }

        if let Some(login_with_email) = self.login_with_email_allowed {
            realm.login_with_email_allowed = login_with_email;
        }

        if let Some(reset_password) = self.reset_password_allowed {
            realm.reset_password_allowed = reset_password;
        }

        if let Some(brute_force_protected) = self.brute_force_protected {
            realm.brute_force_protected = brute_force_protected;
        }

        if let Some(ref password_policy) = self.password_policy {
            realm.set_password_policy(Some(password_policy.clone()))?;
        }

        if let Some(ref attrs) = self.attributes {
            for (key, values) in attrs {
                realm.attributes.set_attribute(key.clone(), values.clone());
            }
        }

        realm.timestamps.updated_timestamp = Some(Utc::now());
        Ok(())
    }
}
