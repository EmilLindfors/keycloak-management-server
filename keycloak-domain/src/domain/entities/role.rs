use super::common::*;
use crate::domain::errors::{DomainError, DomainResult};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Domain entity representing a Keycloak role
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Role {
    pub id: Option<EntityId>,
    pub name: String,
    pub description: Option<String>,
    pub composite: bool,
    pub client_role: bool,
    pub container_id: String, // Realm ID or Client ID
    pub attributes: Attributes,
    pub composites: Option<RoleComposites>,
    pub timestamps: Timestamps,
}

impl Role {
    /// Create a new realm role
    pub fn new_realm_role(name: String, realm_id: String) -> DomainResult<Self> {
        Self::validate_role_name(&name)?;

        Ok(Self {
            id: None,
            name,
            description: None,
            composite: false,
            client_role: false,
            container_id: realm_id,
            attributes: Attributes::new(),
            composites: None,
            timestamps: Timestamps::default(),
        })
    }

    /// Create a new client role
    pub fn new_client_role(name: String, client_id: String) -> DomainResult<Self> {
        Self::validate_role_name(&name)?;

        Ok(Self {
            id: None,
            name,
            description: None,
            composite: false,
            client_role: true,
            container_id: client_id,
            attributes: Attributes::new(),
            composites: None,
            timestamps: Timestamps::default(),
        })
    }

    /// Create a composite role
    pub fn new_composite_role(
        name: String,
        container_id: String,
        is_client_role: bool,
    ) -> DomainResult<Self> {
        Self::validate_role_name(&name)?;

        Ok(Self {
            id: None,
            name,
            description: None,
            composite: true,
            client_role: is_client_role,
            container_id,
            attributes: Attributes::new(),
            composites: Some(RoleComposites::default()),
            timestamps: Timestamps::default(),
        })
    }

    /// Validate role name according to business rules
    pub fn validate_role_name(name: &str) -> DomainResult<()> {
        if name.is_empty() {
            return Err(DomainError::Validation {
                field: "name".to_string(),
                message: "Role name cannot be empty".to_string(),
            });
        }

        if name.len() < 2 {
            return Err(DomainError::Validation {
                field: "name".to_string(),
                message: "Role name must be at least 2 characters long".to_string(),
            });
        }

        if name.len() > 255 {
            return Err(DomainError::Validation {
                field: "name".to_string(),
                message: "Role name cannot exceed 255 characters".to_string(),
            });
        }

        // Check for invalid characters
        if !name
            .chars()
            .all(|c| c.is_alphanumeric() || c == '_' || c == '-' || c == '.' || c == ':')
        {
            return Err(DomainError::Validation {
                field: "name".to_string(),
                message: "Role name can only contain alphanumeric characters, hyphens, underscores, dots, and colons".to_string(),
            });
        }

        Ok(())
    }

    /// Update role description
    pub fn update_description(&mut self, description: Option<String>) {
        self.description = description;
        self.timestamps.updated_timestamp = Some(Utc::now());
    }

    /// Make this role a composite role
    pub fn make_composite(&mut self) -> DomainResult<()> {
        if !self.composite {
            self.composite = true;
            self.composites = Some(RoleComposites::default());
            self.timestamps.updated_timestamp = Some(Utc::now());
        }
        Ok(())
    }

    /// Remove composite nature from this role
    pub fn remove_composite(&mut self) -> DomainResult<()> {
        if self.composite {
            // Check if there are any composite roles that would be orphaned
            if let Some(ref composites) = self.composites {
                if !composites.is_empty() {
                    return Err(DomainError::Validation {
                        field: "composite".to_string(),
                        message:
                            "Cannot remove composite nature while role has composite relationships"
                                .to_string(),
                    });
                }
            }

            self.composite = false;
            self.composites = None;
            self.timestamps.updated_timestamp = Some(Utc::now());
        }
        Ok(())
    }

    /// Add a realm role as a composite
    pub fn add_realm_composite(&mut self, role_name: String) -> DomainResult<()> {
        if !self.composite {
            self.make_composite()?;
        }

        if let Some(ref mut composites) = self.composites {
            composites.add_realm_role(role_name);
            self.timestamps.updated_timestamp = Some(Utc::now());
        }

        Ok(())
    }

    /// Add a client role as a composite
    pub fn add_client_composite(
        &mut self,
        client_id: String,
        role_name: String,
    ) -> DomainResult<()> {
        if !self.composite {
            self.make_composite()?;
        }

        if let Some(ref mut composites) = self.composites {
            composites.add_client_role(client_id, role_name);
            self.timestamps.updated_timestamp = Some(Utc::now());
        }

        Ok(())
    }

    /// Remove a realm role composite
    pub fn remove_realm_composite(&mut self, role_name: &str) {
        if let Some(ref mut composites) = self.composites {
            composites.remove_realm_role(role_name);
            self.timestamps.updated_timestamp = Some(Utc::now());
        }
    }

    /// Remove a client role composite
    pub fn remove_client_composite(&mut self, client_id: &str, role_name: &str) {
        if let Some(ref mut composites) = self.composites {
            composites.remove_client_role(client_id, role_name);
            self.timestamps.updated_timestamp = Some(Utc::now());
        }
    }

    /// Check if this role is a realm role
    pub fn is_realm_role(&self) -> bool {
        !self.client_role
    }

    /// Check if this role is a client role
    pub fn is_client_role(&self) -> bool {
        self.client_role
    }

    /// Check if this role is composite
    pub fn is_composite(&self) -> bool {
        self.composite
    }

    /// Get all composite roles
    pub fn get_all_composites(&self) -> Vec<String> {
        if let Some(ref composites) = self.composites {
            composites.get_all_roles()
        } else {
            Vec::new()
        }
    }

    /// Set an attribute
    pub fn set_attribute(&mut self, key: String, values: Vec<String>) {
        self.attributes.set_attribute(key, values);
        self.timestamps.updated_timestamp = Some(Utc::now());
    }

    /// Get an attribute
    pub fn get_attribute(&self, key: &str) -> Option<&Vec<String>> {
        self.attributes.get_attribute(key)
    }

    /// Remove an attribute
    pub fn remove_attribute(&mut self, key: &str) -> Option<Vec<String>> {
        let result = self.attributes.remove_attribute(key);
        if result.is_some() {
            self.timestamps.updated_timestamp = Some(Utc::now());
        }
        result
    }

    /// Get the role's full name including container
    pub fn get_full_name(&self) -> String {
        if self.client_role {
            format!("{}:{}", self.container_id, self.name)
        } else {
            self.name.clone()
        }
    }
}

/// Composite role relationships
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RoleComposites {
    pub realm: Vec<String>,
    pub client: HashMap<String, Vec<String>>,
}

impl RoleComposites {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a realm role to composites
    pub fn add_realm_role(&mut self, role_name: String) {
        if !self.realm.contains(&role_name) {
            self.realm.push(role_name);
        }
    }

    /// Remove a realm role from composites
    pub fn remove_realm_role(&mut self, role_name: &str) {
        self.realm.retain(|r| r != role_name);
    }

    /// Add a client role to composites
    pub fn add_client_role(&mut self, client_id: String, role_name: String) {
        let roles = self.client.entry(client_id).or_default();
        if !roles.contains(&role_name) {
            roles.push(role_name);
        }
    }

    /// Remove a client role from composites
    pub fn remove_client_role(&mut self, client_id: &str, role_name: &str) {
        if let Some(roles) = self.client.get_mut(client_id) {
            roles.retain(|r| r != role_name);
            if roles.is_empty() {
                self.client.remove(client_id);
            }
        }
    }

    /// Get all composite roles as a flat list
    pub fn get_all_roles(&self) -> Vec<String> {
        let mut all_roles = self.realm.clone();

        for (client_id, roles) in &self.client {
            for role in roles {
                all_roles.push(format!("{client_id}:{role}"));
            }
        }

        all_roles
    }

    /// Check if there are any composite roles
    pub fn is_empty(&self) -> bool {
        self.realm.is_empty() && self.client.is_empty()
    }

    /// Get count of all composite roles
    pub fn count(&self) -> usize {
        let client_count: usize = self.client.values().map(|roles| roles.len()).sum();
        self.realm.len() + client_count
    }
}

/// Request to create a new role
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateRoleRequest {
    pub name: String,
    pub description: Option<String>,
    pub composite: Option<bool>,
    pub client_role: Option<bool>,
    pub container_id: String,
    pub attributes: Option<HashMap<String, Vec<String>>>,
}

impl CreateRoleRequest {
    pub fn new_realm_role(name: String, realm_id: String) -> Self {
        Self {
            name,
            description: None,
            composite: Some(false),
            client_role: Some(false),
            container_id: realm_id,
            attributes: None,
        }
    }

    pub fn new_client_role(name: String, client_id: String) -> Self {
        Self {
            name,
            description: None,
            composite: Some(false),
            client_role: Some(true),
            container_id: client_id,
            attributes: None,
        }
    }

    pub fn with_description(mut self, description: String) -> Self {
        self.description = Some(description);
        self
    }

    pub fn as_composite(mut self) -> Self {
        self.composite = Some(true);
        self
    }

    pub fn validate(&self) -> DomainResult<()> {
        Role::validate_role_name(&self.name)?;
        Ok(())
    }

    pub fn to_domain_role(&self) -> DomainResult<Role> {
        self.validate()?;

        let is_client_role = self.client_role.unwrap_or(false);
        let is_composite = self.composite.unwrap_or(false);

        let mut role = if is_composite {
            Role::new_composite_role(self.name.clone(), self.container_id.clone(), is_client_role)?
        } else if is_client_role {
            Role::new_client_role(self.name.clone(), self.container_id.clone())?
        } else {
            Role::new_realm_role(self.name.clone(), self.container_id.clone())?
        };

        role.description = self.description.clone();

        if let Some(ref attrs) = self.attributes {
            for (key, values) in attrs {
                role.set_attribute(key.clone(), values.clone());
            }
        }

        Ok(role)
    }
}

/// Request to update an existing role
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateRoleRequest {
    pub description: Option<String>,
    pub composite: Option<bool>,
    pub attributes: Option<HashMap<String, Vec<String>>>,
}

impl UpdateRoleRequest {
    pub fn apply_to_role(&self, role: &mut Role) -> DomainResult<()> {
        if let Some(ref description) = self.description {
            role.update_description(Some(description.clone()));
        }

        if let Some(composite) = self.composite {
            if composite && !role.composite {
                role.make_composite()?;
            } else if !composite && role.composite {
                role.remove_composite()?;
            }
        }

        if let Some(ref attrs) = self.attributes {
            for (key, values) in attrs {
                role.set_attribute(key.clone(), values.clone());
            }
        }

        Ok(())
    }
}

/// Filter for querying roles
#[derive(Debug, Clone, Default)]
pub struct RoleFilter {
    pub search: Option<String>,
    pub client_role: Option<bool>,
    pub composite: Option<bool>,
    pub first: Option<i32>,
    pub max: Option<i32>,
}

impl RoleFilter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_search(mut self, search: String) -> Self {
        self.search = Some(search);
        self
    }

    pub fn realm_roles_only(mut self) -> Self {
        self.client_role = Some(false);
        self
    }

    pub fn client_roles_only(mut self) -> Self {
        self.client_role = Some(true);
        self
    }

    pub fn composite_roles_only(mut self) -> Self {
        self.composite = Some(true);
        self
    }

    pub fn with_pagination(mut self, first: i32, max: i32) -> Self {
        self.first = Some(first);
        self.max = Some(max);
        self
    }
}

/// Role mapping for users or groups
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleMapping {
    pub realm_mappings: Vec<String>,
    pub client_mappings: HashMap<String, Vec<String>>,
}

impl RoleMapping {
    pub fn new() -> Self {
        Self {
            realm_mappings: Vec::new(),
            client_mappings: HashMap::new(),
        }
    }

    /// Add a realm role mapping
    pub fn add_realm_role(&mut self, role_name: String) {
        if !self.realm_mappings.contains(&role_name) {
            self.realm_mappings.push(role_name);
        }
    }

    /// Remove a realm role mapping
    pub fn remove_realm_role(&mut self, role_name: &str) {
        self.realm_mappings.retain(|r| r != role_name);
    }

    /// Add a client role mapping
    pub fn add_client_role(&mut self, client_id: String, role_name: String) {
        let roles = self.client_mappings.entry(client_id).or_default();
        if !roles.contains(&role_name) {
            roles.push(role_name);
        }
    }

    /// Remove a client role mapping
    pub fn remove_client_role(&mut self, client_id: &str, role_name: &str) {
        if let Some(roles) = self.client_mappings.get_mut(client_id) {
            roles.retain(|r| r != role_name);
            if roles.is_empty() {
                self.client_mappings.remove(client_id);
            }
        }
    }

    /// Get all role mappings as a flat list
    pub fn get_all_roles(&self) -> Vec<String> {
        let mut all_roles = self.realm_mappings.clone();

        for (client_id, roles) in &self.client_mappings {
            for role in roles {
                all_roles.push(format!("{client_id}:{role}"));
            }
        }

        all_roles
    }

    /// Check if mapping is empty
    pub fn is_empty(&self) -> bool {
        self.realm_mappings.is_empty() && self.client_mappings.is_empty()
    }
}

impl Default for RoleMapping {
    fn default() -> Self {
        Self::new()
    }
}
