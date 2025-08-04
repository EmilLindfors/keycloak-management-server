use super::common::*;
use crate::domain::errors::{DomainError, DomainResult};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Domain entity representing a Keycloak group
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Group {
    pub id: Option<EntityId>,
    pub name: String,
    pub path: String,
    pub parent_id: Option<EntityId>,
    pub sub_groups: Vec<Group>,
    pub attributes: Attributes,
    pub realm_roles: Vec<String>,
    pub client_roles: HashMap<String, Vec<String>>,
    pub timestamps: Timestamps,
}

impl Group {
    /// Create a new group with required fields
    pub fn new(name: String, path: Option<String>) -> DomainResult<Self> {
        Self::validate_group_name(&name)?;

        let group_path = path.unwrap_or_else(|| format!("/{name}"));
        Self::validate_group_path(&group_path)?;

        Ok(Self {
            id: None,
            name,
            path: group_path,
            parent_id: None,
            sub_groups: Vec::new(),
            attributes: Attributes::new(),
            realm_roles: Vec::new(),
            client_roles: HashMap::new(),
            timestamps: Timestamps::default(),
        })
    }

    /// Create a subgroup under a parent
    pub fn new_subgroup(name: String, parent: &Group) -> DomainResult<Self> {
        Self::validate_group_name(&name)?;

        let path = format!("{}/{}", parent.path, name);
        Self::validate_group_path(&path)?;

        Ok(Self {
            id: None,
            name,
            path,
            parent_id: parent.id.clone(),
            sub_groups: Vec::new(),
            attributes: Attributes::new(),
            realm_roles: Vec::new(),
            client_roles: HashMap::new(),
            timestamps: Timestamps::default(),
        })
    }

    /// Validate group name according to business rules
    pub fn validate_group_name(name: &str) -> DomainResult<()> {
        if name.is_empty() {
            return Err(DomainError::Validation {
                field: "name".to_string(),
                message: "Group name cannot be empty".to_string(),
            });
        }

        if name.len() < 2 {
            return Err(DomainError::Validation {
                field: "name".to_string(),
                message: "Group name must be at least 2 characters long".to_string(),
            });
        }

        if name.len() > 255 {
            return Err(DomainError::Validation {
                field: "name".to_string(),
                message: "Group name cannot exceed 255 characters".to_string(),
            });
        }

        // Check for invalid characters in group names
        if name.contains('/') {
            return Err(DomainError::Validation {
                field: "name".to_string(),
                message: "Group name cannot contain forward slashes".to_string(),
            });
        }

        Ok(())
    }

    /// Validate group path
    pub fn validate_group_path(path: &str) -> DomainResult<()> {
        if path.is_empty() {
            return Err(DomainError::Validation {
                field: "path".to_string(),
                message: "Group path cannot be empty".to_string(),
            });
        }

        if !path.starts_with('/') {
            return Err(DomainError::Validation {
                field: "path".to_string(),
                message: "Group path must start with '/'".to_string(),
            });
        }

        if path.ends_with('/') && path != "/" {
            return Err(DomainError::Validation {
                field: "path".to_string(),
                message: "Group path cannot end with '/' except for root".to_string(),
            });
        }

        if path.contains("//") {
            return Err(DomainError::Validation {
                field: "path".to_string(),
                message: "Group path cannot contain consecutive slashes".to_string(),
            });
        }

        Ok(())
    }

    /// Update group name
    pub fn update_name(&mut self, name: String) -> DomainResult<()> {
        Self::validate_group_name(&name)?;

        // Update the path to reflect the new name
        if let Some(parent_path) = self.get_parent_path() {
            self.path = format!("{parent_path}/{name}");
        } else {
            self.path = format!("/{name}");
        }

        self.name = name;
        self.timestamps.updated_timestamp = Some(Utc::now());
        Ok(())
    }

    /// Get the parent path from the current path
    pub fn get_parent_path(&self) -> Option<String> {
        if self.path == "/" || !self.path.contains('/') {
            return None;
        }

        let parts: Vec<&str> = self.path.rsplitn(2, '/').collect();
        if parts.len() == 2 {
            let parent = parts[1];
            if parent.is_empty() {
                Some("/".to_string())
            } else {
                Some(parent.to_string())
            }
        } else {
            None
        }
    }

    /// Get the depth level of this group
    pub fn get_depth(&self) -> usize {
        if self.path == "/" {
            0
        } else {
            self.path.matches('/').count() - 1
        }
    }

    /// Check if this is a root group
    pub fn is_root_group(&self) -> bool {
        self.parent_id.is_none() && self.path.matches('/').count() == 1
    }

    /// Add a subgroup
    pub fn add_subgroup(&mut self, subgroup: Group) -> DomainResult<()> {
        // Verify the subgroup's path is valid for this parent
        let expected_path = format!("{}/{}", self.path, subgroup.name);
        if subgroup.path != expected_path {
            return Err(DomainError::Validation {
                field: "path".to_string(),
                message: format!(
                    "Subgroup path '{}' does not match expected path '{}'",
                    subgroup.path, expected_path
                ),
            });
        }

        // Check for duplicate names
        if self.sub_groups.iter().any(|g| g.name == subgroup.name) {
            return Err(DomainError::Validation {
                field: "name".to_string(),
                message: format!("Subgroup with name '{}' already exists", subgroup.name),
            });
        }

        self.sub_groups.push(subgroup);
        self.timestamps.updated_timestamp = Some(Utc::now());
        Ok(())
    }

    /// Remove a subgroup by name
    pub fn remove_subgroup(&mut self, name: &str) -> Option<Group> {
        let initial_len = self.sub_groups.len();
        let mut removed_group = None;

        self.sub_groups.retain(|g| {
            if g.name == name {
                removed_group = Some(g.clone());
                false
            } else {
                true
            }
        });

        if self.sub_groups.len() != initial_len {
            self.timestamps.updated_timestamp = Some(Utc::now());
        }

        removed_group
    }

    /// Find a subgroup by name
    pub fn find_subgroup(&self, name: &str) -> Option<&Group> {
        self.sub_groups.iter().find(|g| g.name == name)
    }

    /// Find a subgroup by path (recursive)
    pub fn find_subgroup_by_path(&self, path: &str) -> Option<&Group> {
        if self.path == path {
            return Some(self);
        }

        for subgroup in &self.sub_groups {
            if let Some(found) = subgroup.find_subgroup_by_path(path) {
                return Some(found);
            }
        }

        None
    }

    /// Add a realm role to the group
    pub fn add_realm_role(&mut self, role: String) {
        if !self.realm_roles.contains(&role) {
            self.realm_roles.push(role);
            self.timestamps.updated_timestamp = Some(Utc::now());
        }
    }

    /// Remove a realm role from the group
    pub fn remove_realm_role(&mut self, role: &str) {
        let initial_len = self.realm_roles.len();
        self.realm_roles.retain(|r| r != role);
        if self.realm_roles.len() != initial_len {
            self.timestamps.updated_timestamp = Some(Utc::now());
        }
    }

    /// Add a client role to the group
    pub fn add_client_role(&mut self, client_id: String, role: String) {
        let roles = self.client_roles.entry(client_id).or_default();
        if !roles.contains(&role) {
            roles.push(role);
            self.timestamps.updated_timestamp = Some(Utc::now());
        }
    }

    /// Remove a client role from the group
    pub fn remove_client_role(&mut self, client_id: &str, role: &str) {
        if let Some(roles) = self.client_roles.get_mut(client_id) {
            let initial_len = roles.len();
            roles.retain(|r| r != role);

            let is_empty = roles.is_empty();
            let roles_changed = roles.len() != initial_len;

            if is_empty {
                self.client_roles.remove(client_id);
            }

            if roles_changed {
                self.timestamps.updated_timestamp = Some(Utc::now());
            }
        }
    }

    /// Get all roles (realm and client roles combined)
    pub fn get_all_roles(&self) -> Vec<String> {
        let mut all_roles = self.realm_roles.clone();

        for (client_id, roles) in &self.client_roles {
            for role in roles {
                all_roles.push(format!("{client_id}:{role}"));
            }
        }

        all_roles
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
}

/// Request to create a new group
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateGroupRequest {
    pub name: String,
    pub path: Option<String>,
    pub parent_id: Option<String>,
    pub attributes: Option<HashMap<String, Vec<String>>>,
}

impl CreateGroupRequest {
    pub fn new(name: String) -> Self {
        Self {
            name,
            path: None,
            parent_id: None,
            attributes: None,
        }
    }

    pub fn with_parent(mut self, parent_id: String) -> Self {
        self.parent_id = Some(parent_id);
        self
    }

    pub fn with_path(mut self, path: String) -> Self {
        self.path = Some(path);
        self
    }

    pub fn validate(&self) -> DomainResult<()> {
        Group::validate_group_name(&self.name)?;

        if let Some(ref path) = self.path {
            Group::validate_group_path(path)?;
        }

        Ok(())
    }

    pub fn to_domain_group(&self) -> DomainResult<Group> {
        self.validate()?;

        let mut group = Group::new(self.name.clone(), self.path.clone())?;

        if let Some(ref parent_id) = self.parent_id {
            group.parent_id = Some(EntityId::from_string(parent_id.clone()));
        }

        if let Some(ref attrs) = self.attributes {
            for (key, values) in attrs {
                group.set_attribute(key.clone(), values.clone());
            }
        }

        Ok(group)
    }
}

/// Request to update an existing group
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateGroupRequest {
    pub name: Option<String>,
    pub attributes: Option<HashMap<String, Vec<String>>>,
}

impl UpdateGroupRequest {
    pub fn apply_to_group(&self, group: &mut Group) -> DomainResult<()> {
        if let Some(ref name) = self.name {
            group.update_name(name.clone())?;
        }

        if let Some(ref attrs) = self.attributes {
            for (key, values) in attrs {
                group.set_attribute(key.clone(), values.clone());
            }
        }

        Ok(())
    }
}

/// Filter for querying groups
#[derive(Debug, Clone, Default)]
pub struct GroupFilter {
    pub search: Option<String>,
    pub exact: Option<bool>,
    pub first: Option<i32>,
    pub max: Option<i32>,
}

impl GroupFilter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_search(mut self, search: String) -> Self {
        self.search = Some(search);
        self
    }

    pub fn with_exact_match(mut self, exact: bool) -> Self {
        self.exact = Some(exact);
        self
    }

    pub fn with_pagination(mut self, first: i32, max: i32) -> Self {
        self.first = Some(first);
        self.max = Some(max);
        self
    }
}
