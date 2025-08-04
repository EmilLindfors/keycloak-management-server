use async_trait::async_trait;
use keycloak::{KeycloakAdmin, KeycloakTokenSupplier};
use keycloak::types::*;
use std::sync::Arc;

use crate::application::ports::repository::*;
use crate::domain::{entities::*, errors::*};

/// Keycloak REST API adapter implementing the KeycloakRepository port
pub struct KeycloakRestAdapter<TS: KeycloakTokenSupplier> {
    admin: Arc<KeycloakAdmin<TS>>,
}

impl<TS: KeycloakTokenSupplier + std::marker::Sync + std::marker::Send> KeycloakRestAdapter<TS> {
    pub fn new(admin: KeycloakAdmin<TS>) -> Self {
        Self {
            admin: Arc::new(admin),
        }
    }
}

#[async_trait]
impl<TS: KeycloakTokenSupplier + Send + Sync> KeycloakRepository for KeycloakRestAdapter<TS> {
    // User operations
    async fn find_user_by_id(&self, realm: &str, user_id: &str) -> DomainResult<User> {
        let keycloak_user = self
            .admin
            .realm_users_with_user_id_get(realm, user_id, None)
            .await
            .map_err(|e| DomainError::ExternalService {
                service: "Keycloak".to_string(),
                message: format!("Failed to find user by ID: {}", e),
            })?;

        self.convert_user_from_keycloak(keycloak_user).await
    }

    async fn find_user_by_username(
        &self,
        realm: &str,
        username: &str,
    ) -> DomainResult<Option<User>> {
        let users = self
            .admin
            .realm_users_get(realm, None, None, None, None, None, None, None, None, None, None, None, None, None, Some(username.to_string()))
            .await
            .map_err(|e| DomainError::ExternalService {
                service: "Keycloak".to_string(),
                message: format!("Failed to find user by username: {}", e),
            })?;

        if let Some(keycloak_user) = users.into_iter().next() {
            Ok(Some(self.convert_user_from_keycloak(keycloak_user).await?))
        } else {
            Ok(None)
        }
    }

    async fn find_user_by_email(&self, realm: &str, email: &str) -> DomainResult<Option<User>> {
        let users = self
            .admin
            .realm_users_get(realm, None, Some(email.to_string()), None, None, None, None, None, None, None, None, None, None, None, None)
            .await
            .map_err(|e| DomainError::ExternalService {
                service: "Keycloak".to_string(),
                message: format!("Failed to find user by email: {}", e),
            })?;

        if let Some(keycloak_user) = users.into_iter().next() {
            Ok(Some(self.convert_user_from_keycloak(keycloak_user).await?))
        } else {
            Ok(None)
        }
    }

    async fn list_users(&self, realm: &str, filter: &UserFilter) -> DomainResult<Vec<User>> {
        let users = self
            .admin
            .realm_users_get(
                realm,
                None, // brief_representation
                None, // email
                None, // email_verified
                filter.enabled, // enabled
                None, // exact
                filter.first, // first
                None, // first_name
                None, // idp_alias
                None, // idp_user_id
                None, // last_name
                filter.max, // max
                None, // q
                filter.search.as_deref().map(|s| s.to_string()), // search
                None, // username
            )
            .await
            .map_err(|e| DomainError::ExternalService {
                service: "Keycloak".to_string(),
                message: format!("Failed to list users: {}", e),
            })?;

        let mut domain_users = Vec::new();
        for keycloak_user in users {
            domain_users.push(self.convert_user_from_keycloak(keycloak_user).await?);
        }
        Ok(domain_users)
    }

    async fn create_user(&self, realm: &str, user: &User) -> DomainResult<EntityId> {
        let keycloak_user = self.convert_user_to_keycloak(user).await?;
        
        self.admin
            .realm_users_post(realm, keycloak_user)
            .await
            .map_err(|e| DomainError::ExternalService {
                service: "Keycloak".to_string(),
                message: format!("Failed to create user: {}", e),
            })?;

        // Find the created user to get the ID
        self.find_user_by_username(realm, &user.username)
            .await?
            .ok_or_else(|| DomainError::ExternalService {
                service: "Keycloak".to_string(),
                message: "User created but could not retrieve ID".to_string(),
            })
            .map(|u| u.id.unwrap_or_else(|| EntityId::new()))
    }

    async fn update_user(&self, realm: &str, user: &User) -> DomainResult<()> {
        let user_id = user.id.as_ref().ok_or_else(|| DomainError::Validation {
            field: "id".to_string(),
            message: "User ID is required for updates".to_string(),
        })?;

        let keycloak_user = self.convert_user_to_keycloak(user).await?;
        
        self.admin
            .realm_users_with_user_id_put(realm, user_id.as_str(), keycloak_user)
            .await
            .map_err(|e| DomainError::ExternalService {
                service: "Keycloak".to_string(),
                message: format!("Failed to update user: {}", e),
            })?;

        Ok(())
    }

    async fn delete_user(&self, realm: &str, user_id: &str) -> DomainResult<()> {
        self.admin
            .realm_users_with_user_id_delete(realm, user_id)
            .await
            .map_err(|e| DomainError::ExternalService {
                service: "Keycloak".to_string(),
                message: format!("Failed to delete user: {}", e),
            })?;

        Ok(())
    }

    async fn count_users(&self, realm: &str) -> DomainResult<i64> {
        self.admin
            .realm_users_count_get(realm, None, None, None, None, None, None, None, None)
            .await
            .map_err(|e| DomainError::ExternalService {
                service: "Keycloak".to_string(),
                message: format!("Failed to count users: {}", e),
            })
            .map(|count| count as i64)
    }

    // User credential operations
    async fn set_user_password(
        &self,
        realm: &str,
        user_id: &str,
        credential: &Credential,
    ) -> DomainResult<()> {
        let keycloak_credential = self.convert_credential_to_keycloak(credential).await?;
        
        self.admin
            .realm_users_with_user_id_reset_password_put(realm, user_id, keycloak_credential)
            .await
            .map_err(|e| DomainError::ExternalService {
                service: "Keycloak".to_string(),
                message: format!("Failed to set user password: {}", e),
            })?;

        Ok(())
    }

    async fn get_user_credentials(
        &self,
        realm: &str,
        user_id: &str,
    ) -> DomainResult<Vec<Credential>> {
        let keycloak_credentials = self
            .admin
            .realm_users_with_user_id_credentials_get(realm, user_id)
            .await
            .map_err(|e| DomainError::ExternalService {
                service: "Keycloak".to_string(),
                message: format!("Failed to get user credentials: {}", e),
            })?;

        let mut credentials = Vec::new();
        for keycloak_credential in keycloak_credentials {
            credentials.push(self.convert_credential_from_keycloak(keycloak_credential).await?);
        }
        Ok(credentials)
    }

    async fn delete_user_credential(
        &self,
        realm: &str,
        user_id: &str,
        credential_id: &str,
    ) -> DomainResult<()> {
        self.admin
            .realm_users_with_user_id_credentials_with_credential_id_delete(realm, user_id, credential_id)
            .await
            .map_err(|e| DomainError::ExternalService {
                service: "Keycloak".to_string(),
                message: format!("Failed to delete user credential: {}", e),
            })?;

        Ok(())
    }

    // Additional methods for missing TODO functionality

    // Realm operations
    async fn find_realm_by_name(&self, realm: &str) -> DomainResult<Realm> {
        let keycloak_realm = self
            .admin
            .realm_get(realm)
            .await
            .map_err(|e| DomainError::ExternalService {
                service: "Keycloak".to_string(),
                message: format!("Failed to find realm by name: {}", e),
            })?;

        self.convert_realm_from_keycloak(keycloak_realm).await
    }

    async fn list_realms(&self) -> DomainResult<Vec<Realm>> {
        let keycloak_realms = self
            .admin
            .get(None)
            .await
            .map_err(|e| DomainError::ExternalService {
                service: "Keycloak".to_string(),
                message: format!("Failed to list realms: {}", e),
            })?;

        let mut domain_realms = Vec::new();
        for keycloak_realm in keycloak_realms {
            domain_realms.push(self.convert_realm_from_keycloak(keycloak_realm).await?);
        }
        Ok(domain_realms)
    }

    async fn create_realm(&self, realm: &Realm) -> DomainResult<EntityId> {
        let keycloak_realm = self.convert_realm_to_keycloak(realm).await?;
        
        self.admin
            .post(keycloak_realm)
            .await
            .map_err(|e| DomainError::ExternalService {
                service: "Keycloak".to_string(),
                message: format!("Failed to create realm: {}", e),
            })?;

        // Realm creation doesn't return an ID, so we return the realm name as ID
        Ok(EntityId::from_string(realm.realm.clone()))
    }

    async fn update_realm(&self, realm: &Realm) -> DomainResult<()> {
        let keycloak_realm = self.convert_realm_to_keycloak(realm).await?;
        
        self.admin
            .realm_put(&realm.realm, keycloak_realm)
            .await
            .map_err(|e| DomainError::ExternalService {
                service: "Keycloak".to_string(),
                message: format!("Failed to update realm: {}", e),
            })?;

        Ok(())
    }

    async fn delete_realm(&self, realm: &str) -> DomainResult<()> {
        self.admin
            .realm_delete(realm)
            .await
            .map_err(|e| DomainError::ExternalService {
                service: "Keycloak".to_string(),
                message: format!("Failed to delete realm: {}", e),
            })?;

        Ok(())
    }

    // Client operations
    async fn find_client_by_id(&self, realm: &str, client_id: &str) -> DomainResult<Client> {
        let clients = self
            .admin
            .realm_clients_get(realm, Some(client_id.to_string()), None, None, None, None, None)
            .await
            .map_err(|e| DomainError::ExternalService {
                service: "Keycloak".to_string(),
                message: format!("Failed to find client by ID: {}", e),
            })?;

        let keycloak_client = clients.first().ok_or_else(|| DomainError::ClientNotFound {
            client_id: client_id.to_string(),
            realm: realm.to_string(),
        })?;

        self.convert_client_from_keycloak(keycloak_client.clone()).await
    }

    async fn find_client_by_client_id(
        &self,
        realm: &str,
        client_id: &str,
    ) -> DomainResult<Option<Client>> {
        let clients = self
            .admin
            .realm_clients_get(realm, Some(client_id.to_string()), None, None, None, None, None)
            .await
            .map_err(|e| DomainError::ExternalService {
                service: "Keycloak".to_string(),
                message: format!("Failed to find client by client ID: {}", e),
            })?;

        if let Some(keycloak_client) = clients.into_iter().next() {
            Ok(Some(self.convert_client_from_keycloak(keycloak_client).await?))
        } else {
            Ok(None)
        }
    }

    async fn list_clients(&self, realm: &str, filter: &ClientFilter) -> DomainResult<Vec<Client>> {
        let clients = self
            .admin
            .realm_clients_get(
                realm,
                filter.client_id.clone(),
                filter.max,
                filter.first,
                None, // view_clients_only
                None, // q
                None, // scope
            )
            .await
            .map_err(|e| DomainError::ExternalService {
                service: "Keycloak".to_string(),
                message: format!("Failed to list clients: {}", e),
            })?;

        let mut domain_clients = Vec::new();
        for keycloak_client in clients {
            // Apply additional filtering that may not be supported by the API
            let client = self.convert_client_from_keycloak(keycloak_client).await?;
            
            let mut include = true;
            if let Some(enabled) = filter.enabled {
                if client.enabled != enabled {
                    include = false;
                }
            }
            if let Some(ref protocol) = filter.protocol {
                if client.protocol != *protocol {
                    include = false;
                }
            }
            if let Some(public_client) = filter.public_client {
                if client.public_client != public_client {
                    include = false;
                }
            }
            if let Some(bearer_only) = filter.bearer_only {
                if client.bearer_only != bearer_only {
                    include = false;
                }
            }

            if include {
                domain_clients.push(client);
            }
        }
        Ok(domain_clients)
    }

    async fn create_client(&self, realm: &str, client: &Client) -> DomainResult<EntityId> {
        let keycloak_client = self.convert_client_to_keycloak(client).await?;
        
        let response = self.admin
            .realm_clients_post(realm, keycloak_client)
            .await
            .map_err(|e| DomainError::ExternalService {
                service: "Keycloak".to_string(),
                message: format!("Failed to create client: {}", e),
            })?;

        // Extract client ID from the Location header or find by client_id
        let client_id = response
            .to_id()
            .ok_or_else(|| DomainError::ExternalService {
                service: "Keycloak".to_string(),
                message: "Failed to get client ID from response".to_string(),
            })?;

        Ok(EntityId::from_string(client_id.to_string()))
    }

    async fn update_client(&self, realm: &str, client: &Client) -> DomainResult<()> {
        let client_uuid = client.id.as_ref().ok_or_else(|| DomainError::Validation {
            field: "id".to_string(),
            message: "Client ID is required for updates".to_string(),
        })?;

        let keycloak_client = self.convert_client_to_keycloak(client).await?;
        
        self.admin
            .realm_clients_with_client_uuid_put(realm, client_uuid.as_str(), keycloak_client)
            .await
            .map_err(|e| DomainError::ExternalService {
                service: "Keycloak".to_string(),
                message: format!("Failed to update client: {}", e),
            })?;

        Ok(())
    }

    async fn delete_client(&self, realm: &str, client_id: &str) -> DomainResult<()> {
        self.admin
            .realm_clients_with_client_uuid_delete(realm, client_id)
            .await
            .map_err(|e| DomainError::ExternalService {
                service: "Keycloak".to_string(),
                message: format!("Failed to delete client: {}", e),
            })?;

        Ok(())
    }

    // Client secret operations
    async fn get_client_secret(&self, realm: &str, client_id: &str) -> DomainResult<String> {
        let credentials = self
            .admin
            .realm_clients_with_client_uuid_client_secret_get(realm, client_id)
            .await
            .map_err(|e| DomainError::ExternalService {
                service: "Keycloak".to_string(),
                message: format!("Failed to get client secret: {}", e),
            })?;

        credentials.value.ok_or_else(|| DomainError::ExternalService {
            service: "Keycloak".to_string(),
            message: "Client secret not found".to_string(),
        }).map(|s| s.to_string())
    }

    async fn regenerate_client_secret(&self, realm: &str, client_id: &str) -> DomainResult<String> {
        let credentials = self
            .admin
            .realm_clients_with_client_uuid_client_secret_post(realm, client_id)
            .await
            .map_err(|e| DomainError::ExternalService {
                service: "Keycloak".to_string(),
                message: format!("Failed to regenerate client secret: {}", e),
            })?;

        credentials.value.ok_or_else(|| DomainError::ExternalService {
            service: "Keycloak".to_string(),
            message: "Failed to get regenerated client secret".to_string(),
        }).map(|s| s.to_string())
    }

    // Group operations
    async fn find_group_by_id(&self, realm: &str, group_id: &str) -> DomainResult<Group> {
        let keycloak_group = self
            .admin
            .realm_groups_with_group_id_get(realm, group_id)
            .await
            .map_err(|e| DomainError::ExternalService {
                service: "Keycloak".to_string(),
                message: format!("Failed to find group by ID: {}", e),
            })?;

        self.convert_group_from_keycloak(keycloak_group).await
    }

    async fn find_group_by_path(&self, realm: &str, path: &str) -> DomainResult<Option<Group>> {
        // Get all groups and search for the path
        let groups = self
            .admin
            .realm_groups_get(realm, None, None, None, None, None, None, None, None)
            .await
            .map_err(|e| DomainError::ExternalService {
                service: "Keycloak".to_string(),
                message: format!("Failed to find group by path: {}", e),
            })?;

        // Search through groups and subgroups recursively
        for keycloak_group in groups {
            if let Some(group) = self.find_group_by_path_recursive(&keycloak_group, path).await? {
                return Ok(Some(group));
            }
        }

        Ok(None)
    }

    async fn list_groups(&self, realm: &str, filter: &GroupFilter) -> DomainResult<Vec<Group>> {
        let groups = self
            .admin
            .realm_groups_get(
                realm,
                None, // brief_representation
                None, // exact
                filter.first,
                filter.max,
                None, // populate_hierarchy
                filter.search.clone(),
                None, // q
                None, // populate_parents
            )
            .await
            .map_err(|e| DomainError::ExternalService {
                service: "Keycloak".to_string(),
                message: format!("Failed to list groups: {}", e),
            })?;

        let mut domain_groups = Vec::new();
        for keycloak_group in groups {
            let group = self.convert_group_from_keycloak(keycloak_group).await?;
            domain_groups.push(group);
        }
        Ok(domain_groups)
    }

    async fn create_group(&self, realm: &str, group: &Group) -> DomainResult<EntityId> {
        let keycloak_group = self.convert_group_to_keycloak(group).await?;
        
        let response = self.admin
            .realm_groups_post(realm, keycloak_group)
            .await
            .map_err(|e| DomainError::ExternalService {
                service: "Keycloak".to_string(),
                message: format!("Failed to create group: {}", e),
            })?;

        let group_id = response
            .to_id()
            .ok_or_else(|| DomainError::ExternalService {
                service: "Keycloak".to_string(),
                message: "Failed to get group ID from response".to_string(),
            })?;

        Ok(EntityId::from_string(group_id.to_string()))
    }

    async fn update_group(&self, realm: &str, group: &Group) -> DomainResult<()> {
        let group_id = group.id.as_ref().ok_or_else(|| DomainError::Validation {
            field: "id".to_string(),
            message: "Group ID is required for updates".to_string(),
        })?;

        let keycloak_group = self.convert_group_to_keycloak(group).await?;
        
        self.admin
            .realm_groups_with_group_id_put(realm, group_id.as_str(), keycloak_group)
            .await
            .map_err(|e| DomainError::ExternalService {
                service: "Keycloak".to_string(),
                message: format!("Failed to update group: {}", e),
            })?;

        Ok(())
    }

    async fn delete_group(&self, realm: &str, group_id: &str) -> DomainResult<()> {
        self.admin
            .realm_groups_with_group_id_delete(realm, group_id)
            .await
            .map_err(|e| DomainError::ExternalService {
                service: "Keycloak".to_string(),
                message: format!("Failed to delete group: {}", e),
            })?;

        Ok(())
    }

    // Role operations
    async fn find_realm_role_by_name(&self, realm: &str, role_name: &str) -> DomainResult<Role> {
        let keycloak_role = self
            .admin
            .realm_roles_with_role_name_get(realm, role_name)
            .await
            .map_err(|e| DomainError::ExternalService {
                service: "Keycloak".to_string(),
                message: format!("Failed to find realm role by name: {}", e),
            })?;

        self.convert_role_from_keycloak(keycloak_role).await
    }

    async fn find_client_role_by_name(
        &self,
        realm: &str,
        client_id: &str,
        role_name: &str,
    ) -> DomainResult<Role> {
        let keycloak_role = self
            .admin
            .realm_clients_with_client_uuid_roles_with_role_name_get(realm, client_id, role_name)
            .await
            .map_err(|e| DomainError::ExternalService {
                service: "Keycloak".to_string(),
                message: format!("Failed to find client role by name: {}", e),
            })?;

        self.convert_role_from_keycloak(keycloak_role).await
    }

    async fn list_realm_roles(&self, realm: &str, filter: &RoleFilter) -> DomainResult<Vec<Role>> {
        let keycloak_roles = self
            .admin
            .realm_roles_get(
                realm,
                None, // brief_representation
                filter.first,
                filter.max,
                filter.search.clone(),
            )
            .await
            .map_err(|e| DomainError::ExternalService {
                service: "Keycloak".to_string(),
                message: format!("Failed to list realm roles: {}", e),
            })?;

        let mut domain_roles = Vec::new();
        for keycloak_role in keycloak_roles {
            let role = self.convert_role_from_keycloak(keycloak_role).await?;
            
            // Apply additional filtering
            let mut include = true;
            if let Some(client_role) = filter.client_role {
                if role.client_role != client_role {
                    include = false;
                }
            }
            if let Some(composite) = filter.composite {
                if role.composite != composite {
                    include = false;
                }
            }

            if include {
                domain_roles.push(role);
            }
        }

        Ok(domain_roles)
    }

    async fn list_client_roles(
        &self,
        realm: &str,
        client_id: &str,
        filter: &RoleFilter,
    ) -> DomainResult<Vec<Role>> {
        let keycloak_roles = self
            .admin
            .realm_clients_with_client_uuid_roles_get(
                realm,
                client_id,
                None, // brief_representation
                filter.first,
                filter.max,
                filter.search.clone(),
            )
            .await
            .map_err(|e| DomainError::ExternalService {
                service: "Keycloak".to_string(),
                message: format!("Failed to list client roles: {}", e),
            })?;

        let mut domain_roles = Vec::new();
        for keycloak_role in keycloak_roles {
            let role = self.convert_role_from_keycloak(keycloak_role).await?;
            
            // Apply additional filtering
            let mut include = true;
            if let Some(client_role) = filter.client_role {
                if role.client_role != client_role {
                    include = false;
                }
            }
            if let Some(composite) = filter.composite {
                if role.composite != composite {
                    include = false;
                }
            }

            if include {
                domain_roles.push(role);
            }
        }

        Ok(domain_roles)
    }

    async fn create_realm_role(&self, realm: &str, role: &Role) -> DomainResult<EntityId> {
        let keycloak_role = self.convert_role_to_keycloak(role).await?;
        
        let response = self
            .admin
            .realm_roles_post(realm, keycloak_role)
            .await
            .map_err(|e| DomainError::ExternalService {
                service: "Keycloak".to_string(),
                message: format!("Failed to create realm role: {}", e),
            })?;

        // Extract role ID from the response or fetch by name
        if let Some(role_id) = response.to_id() {
            Ok(EntityId::from_string(role_id.to_string()))
        } else {
            // Fallback: fetch the created role by name to get its ID
            let created_role = self.find_realm_role_by_name(realm, &role.name).await?;
            created_role.id.ok_or_else(|| DomainError::ExternalService {
                service: "Keycloak".to_string(),
                message: "Failed to get role ID after creation".to_string(),
            })
        }
    }

    async fn create_client_role(
        &self,
        realm: &str,
        client_id: &str,
        role: &Role,
    ) -> DomainResult<EntityId> {
        let keycloak_role = self.convert_role_to_keycloak(role).await?;
        
        let response = self
            .admin
            .realm_clients_with_client_uuid_roles_post(realm, client_id, keycloak_role)
            .await
            .map_err(|e| DomainError::ExternalService {
                service: "Keycloak".to_string(),
                message: format!("Failed to create client role: {}", e),
            })?;

        // Extract role ID from the response or fetch by name
        if let Some(role_id) = response.to_id() {
            Ok(EntityId::from_string(role_id.to_string()))
        } else {
            // Fallback: fetch the created role by name to get its ID
            let created_role = self.find_client_role_by_name(realm, client_id, &role.name).await?;
            created_role.id.ok_or_else(|| DomainError::ExternalService {
                service: "Keycloak".to_string(),
                message: "Failed to get role ID after creation".to_string(),
            })
        }
    }

    async fn update_realm_role(&self, realm: &str, role: &Role) -> DomainResult<()> {
        let keycloak_role = self.convert_role_to_keycloak(role).await?;
        
        self.admin
            .realm_roles_with_role_name_put(realm, &role.name, keycloak_role)
            .await
            .map_err(|e| DomainError::ExternalService {
                service: "Keycloak".to_string(),
                message: format!("Failed to update realm role: {}", e),
            })?;

        Ok(())
    }

    async fn update_client_role(
        &self,
        realm: &str,
        client_id: &str,
        role: &Role,
    ) -> DomainResult<()> {
        let keycloak_role = self.convert_role_to_keycloak(role).await?;
        
        self.admin
            .realm_clients_with_client_uuid_roles_with_role_name_put(realm, client_id, &role.name, keycloak_role)
            .await
            .map_err(|e| DomainError::ExternalService {
                service: "Keycloak".to_string(),
                message: format!("Failed to update client role: {}", e),
            })?;

        Ok(())
    }

    async fn delete_realm_role(&self, realm: &str, role_name: &str) -> DomainResult<()> {
        self.admin
            .realm_roles_with_role_name_delete(realm, role_name)
            .await
            .map_err(|e| DomainError::ExternalService {
                service: "Keycloak".to_string(),
                message: format!("Failed to delete realm role: {}", e),
            })?;

        Ok(())
    }

    async fn delete_client_role(
        &self,
        realm: &str,
        client_id: &str,
        role_name: &str,
    ) -> DomainResult<()> {
        self.admin
            .realm_clients_with_client_uuid_roles_with_role_name_delete(realm, client_id, role_name)
            .await
            .map_err(|e| DomainError::ExternalService {
                service: "Keycloak".to_string(),
                message: format!("Failed to delete client role: {}", e),
            })?;

        Ok(())
    }

    // Role mapping operations
    async fn get_user_role_mappings(&self, realm: &str, user_id: &str)
        -> DomainResult<RoleMapping> {
        let mappings = self
            .admin
            .realm_users_with_user_id_role_mappings_get(realm, user_id)
            .await
            .map_err(|e| DomainError::ExternalService {
                service: "Keycloak".to_string(),
                message: format!("Failed to get user role mappings: {}", e),
            })?;

        let mut role_mapping = RoleMapping::new();

        // Add realm roles
        if let Some(realm_mappings) = mappings.realm_mappings {
            for role_rep in realm_mappings {
                if let Some(role_name) = role_rep.name {
                    role_mapping.add_realm_role(role_name.to_string());
                }
            }
        }

        // Add client roles
        if let Some(client_mappings) = mappings.client_mappings {
            for (client_id, client_role_mappings) in client_mappings.iter() {
                if let Some(mappings) = client_role_mappings.mappings.as_ref() {
                    for role_rep in mappings {
                        if let Some(role_name) = &role_rep.name {
                            role_mapping.add_client_role(client_id.to_string(), role_name.to_string());
                        }
                    }
                }
            }
        }

        Ok(role_mapping)
    }

    async fn add_user_realm_roles(
        &self,
        realm: &str,
        user_id: &str,
        roles: &[String],
    ) -> DomainResult<()> {
        let mut role_representations = Vec::new();
        
        // Convert role names to RoleRepresentation objects
        for role_name in roles {
            let role = self.find_realm_role_by_name(realm, role_name).await?;
            let keycloak_role = self.convert_role_to_keycloak(&role).await?;
            role_representations.push(keycloak_role);
        }

        self.admin
            .realm_users_with_user_id_role_mappings_realm_post(realm, user_id, role_representations)
            .await
            .map_err(|e| DomainError::ExternalService {
                service: "Keycloak".to_string(),
                message: format!("Failed to add user realm roles: {}", e),
            })?;

        Ok(())
    }

    async fn remove_user_realm_roles(
        &self,
        realm: &str,
        user_id: &str,
        roles: &[String],
    ) -> DomainResult<()> {
        let mut role_representations = Vec::new();
        
        // Convert role names to RoleRepresentation objects
        for role_name in roles {
            let role = self.find_realm_role_by_name(realm, role_name).await?;
            let keycloak_role = self.convert_role_to_keycloak(&role).await?;
            role_representations.push(keycloak_role);
        }

        self.admin
            .realm_users_with_user_id_role_mappings_realm_delete(realm, user_id, role_representations)
            .await
            .map_err(|e| DomainError::ExternalService {
                service: "Keycloak".to_string(),
                message: format!("Failed to remove user realm roles: {}", e),
            })?;

        Ok(())
    }

    async fn add_user_client_roles(
        &self,
        realm: &str,
        user_id: &str,
        client_id: &str,
        roles: &[String],
    ) -> DomainResult<()> {
        let mut role_representations = Vec::new();
        
        // Convert role names to RoleRepresentation objects
        for role_name in roles {
            let role = self.find_client_role_by_name(realm, client_id, role_name).await?;
            let keycloak_role = self.convert_role_to_keycloak(&role).await?;
            role_representations.push(keycloak_role);
        }

        self.admin
            .realm_users_with_user_id_role_mappings_clients_with_client_id_post(realm, user_id, client_id, role_representations)
            .await
            .map_err(|e| DomainError::ExternalService {
                service: "Keycloak".to_string(),
                message: format!("Failed to add user client roles: {}", e),
            })?;

        Ok(())
    }

    async fn remove_user_client_roles(
        &self,
        realm: &str,
        user_id: &str,
        client_id: &str,
        roles: &[String],
    ) -> DomainResult<()> {
        let mut role_representations = Vec::new();
        
        // Convert role names to RoleRepresentation objects
        for role_name in roles {
            let role = self.find_client_role_by_name(realm, client_id, role_name).await?;
            let keycloak_role = self.convert_role_to_keycloak(&role).await?;
            role_representations.push(keycloak_role);
        }

        self.admin
            .realm_users_with_user_id_role_mappings_clients_with_client_id_delete(realm, user_id, client_id, role_representations)
            .await
            .map_err(|e| DomainError::ExternalService {
                service: "Keycloak".to_string(),
                message: format!("Failed to remove user client roles: {}", e),
            })?;

        Ok(())
    }

    async fn get_group_role_mappings(
        &self,
        realm: &str,
        group_id: &str,
    ) -> DomainResult<RoleMapping> {
        let mappings = self
            .admin
            .realm_groups_with_group_id_role_mappings_get(realm, group_id)
            .await
            .map_err(|e| DomainError::ExternalService {
                service: "Keycloak".to_string(),
                message: format!("Failed to get group role mappings: {}", e),
            })?;

        let mut role_mapping = RoleMapping::new();

        // Add realm roles
        if let Some(realm_mappings) = mappings.realm_mappings {
            for role_rep in realm_mappings {
                if let Some(role_name) = role_rep.name {
                    role_mapping.add_realm_role(role_name.to_string());
                }
            }
        }

        // Add client roles
        if let Some(client_mappings) = mappings.client_mappings {
            for (client_id, client_role_mappings) in client_mappings.iter() {
                if let Some(mappings) = client_role_mappings.mappings.as_ref() {
                    for role_rep in mappings {
                        if let Some(role_name) = &role_rep.name {
                            role_mapping.add_client_role(client_id.to_string(), role_name.to_string());
                        }
                    }
                }
            }
        }

        Ok(role_mapping)
    }

    async fn add_group_realm_roles(
        &self,
        realm: &str,
        group_id: &str,
        roles: &[String],
    ) -> DomainResult<()> {
        let mut role_representations = Vec::new();
        
        for role_name in roles {
            let role = self.find_realm_role_by_name(realm, role_name).await?;
            let keycloak_role = self.convert_role_to_keycloak(&role).await?;
            role_representations.push(keycloak_role);
        }

        self.admin
            .realm_groups_with_group_id_role_mappings_realm_post(realm, group_id, role_representations)
            .await
            .map_err(|e| DomainError::ExternalService {
                service: "Keycloak".to_string(),
                message: format!("Failed to add group realm roles: {}", e),
            })?;

        Ok(())
    }

    async fn remove_group_realm_roles(
        &self,
        realm: &str,
        group_id: &str,
        roles: &[String],
    ) -> DomainResult<()> {
        let mut role_representations = Vec::new();
        
        for role_name in roles {
            let role = self.find_realm_role_by_name(realm, role_name).await?;
            let keycloak_role = self.convert_role_to_keycloak(&role).await?;
            role_representations.push(keycloak_role);
        }

        self.admin
            .realm_groups_with_group_id_role_mappings_realm_delete(realm, group_id, role_representations)
            .await
            .map_err(|e| DomainError::ExternalService {
                service: "Keycloak".to_string(),
                message: format!("Failed to remove group realm roles: {}", e),
            })?;

        Ok(())
    }

    async fn add_group_client_roles(
        &self,
        realm: &str,
        group_id: &str,
        client_id: &str,
        roles: &[String],
    ) -> DomainResult<()> {
        let mut role_representations = Vec::new();
        
        for role_name in roles {
            let role = self.find_client_role_by_name(realm, client_id, role_name).await?;
            let keycloak_role = self.convert_role_to_keycloak(&role).await?;
            role_representations.push(keycloak_role);
        }

        self.admin
            .realm_groups_with_group_id_role_mappings_clients_with_client_id_post(realm, group_id, client_id, role_representations)
            .await
            .map_err(|e| DomainError::ExternalService {
                service: "Keycloak".to_string(),
                message: format!("Failed to add group client roles: {}", e),
            })?;

        Ok(())
    }

    async fn remove_group_client_roles(
        &self,
        realm: &str,
        group_id: &str,
        client_id: &str,
        roles: &[String],
    ) -> DomainResult<()> {
        let mut role_representations = Vec::new();
        
        for role_name in roles {
            let role = self.find_client_role_by_name(realm, client_id, role_name).await?;
            let keycloak_role = self.convert_role_to_keycloak(&role).await?;
            role_representations.push(keycloak_role);
        }

        self.admin
            .realm_groups_with_group_id_role_mappings_clients_with_client_id_delete(realm, group_id, client_id, role_representations)
            .await
            .map_err(|e| DomainError::ExternalService {
                service: "Keycloak".to_string(),
                message: format!("Failed to remove group client roles: {}", e),
            })?;

        Ok(())
    }

    // User-Group operations
    async fn get_user_groups(&self, realm: &str, user_id: &str) -> DomainResult<Vec<Group>> {
        let keycloak_groups = self
            .admin
            .realm_users_with_user_id_groups_get(realm, user_id, None, None, None, None)
            .await
            .map_err(|e| DomainError::ExternalService {
                service: "Keycloak".to_string(),
                message: format!("Failed to get user groups: {}", e),
            })?;

        let mut groups = Vec::new();
        for keycloak_group in keycloak_groups {
            let group = self.convert_group_from_keycloak(keycloak_group).await?;
            groups.push(group);
        }

        Ok(groups)
    }

    async fn add_user_to_group(
        &self,
        realm: &str,
        user_id: &str,
        group_id: &str,
    ) -> DomainResult<()> {
        self.admin
            .realm_users_with_user_id_groups_with_group_id_put(realm, user_id, group_id)
            .await
            .map_err(|e| DomainError::ExternalService {
                service: "Keycloak".to_string(),
                message: format!("Failed to add user to group: {}", e),
            })?;

        Ok(())
    }

    async fn remove_user_from_group(
        &self,
        realm: &str,
        user_id: &str,
        group_id: &str,
    ) -> DomainResult<()> {
        self.admin
            .realm_users_with_user_id_groups_with_group_id_delete(realm, user_id, group_id)
            .await
            .map_err(|e| DomainError::ExternalService {
                service: "Keycloak".to_string(),
                message: format!("Failed to remove user from group: {}", e),
            })?;

        Ok(())
    }

    // Session operations
    async fn get_user_sessions(&self, realm: &str, user_id: &str)
        -> DomainResult<Vec<UserSession>> {
        let keycloak_sessions = self
            .admin
            .realm_users_with_user_id_sessions_get(realm, user_id)
            .await
            .map_err(|e| DomainError::ExternalService {
                service: "Keycloak".to_string(),
                message: format!("Failed to get user sessions: {}", e),
            })?;

        let mut sessions = Vec::new();
        for keycloak_session in keycloak_sessions {
            let session = self.convert_session_from_keycloak_with_realm(keycloak_session, realm).await?;
            sessions.push(session);
        }

        Ok(sessions)
    }

    async fn logout_user(&self, realm: &str, user_id: &str) -> DomainResult<()> {
        self.admin
            .realm_users_with_user_id_logout_post(realm, user_id)
            .await
            .map_err(|e| DomainError::ExternalService {
                service: "Keycloak".to_string(),
                message: format!("Failed to logout user: {}", e),
            })?;

        Ok(())
    }

    async fn logout_all_sessions(&self, realm: &str) -> DomainResult<()> {
        self.admin
            .realm_logout_all_post(realm)
            .await
            .map_err(|e| DomainError::ExternalService {
                service: "Keycloak".to_string(),
                message: format!("Failed to logout all sessions: {}", e),
            })?;

        Ok(())
    }

    async fn delete_session(&self, realm: &str, session_id: &str) -> DomainResult<()> {
        self.admin
            .realm_sessions_with_session_delete(realm, session_id, None)
            .await
            .map_err(|e| DomainError::ExternalService {
                service: "Keycloak".to_string(),
                message: format!("Failed to delete session: {}", e),
            })?;

        Ok(())
    }

    // Federated identity operations
    async fn get_user_federated_identities(
        &self,
        realm: &str,
        user_id: &str,
    ) -> DomainResult<Vec<FederatedIdentity>> {
        let keycloak_identities = self
            .admin
            .realm_users_with_user_id_federated_identity_get(realm, user_id)
            .await
            .map_err(|e| DomainError::ExternalService {
                service: "Keycloak".to_string(),
                message: format!("Failed to get user federated identities: {}", e),
            })?;

        let mut identities = Vec::new();
        for keycloak_identity in keycloak_identities {
            let identity = self.convert_federated_identity_from_keycloak(keycloak_identity).await?;
            identities.push(identity);
        }

        Ok(identities)
    }

    async fn add_user_federated_identity(
        &self,
        realm: &str,
        user_id: &str,
        provider: &str,
        identity: &FederatedIdentity,
    ) -> DomainResult<()> {
        let _keycloak_identity = self.convert_federated_identity_to_keycloak(identity).await?;
        
        self.admin
            .realm_users_with_user_id_federated_identity_with_provider_post(realm, user_id, provider)
            .await
            .map_err(|e| DomainError::ExternalService {
                service: "Keycloak".to_string(),
                message: format!("Failed to add user federated identity: {}", e),
            })?;

        Ok(())
    }

    async fn remove_user_federated_identity(
        &self,
        realm: &str,
        user_id: &str,
        provider: &str,
    ) -> DomainResult<()> {
        self.admin
            .realm_users_with_user_id_federated_identity_with_provider_delete(realm, user_id, provider)
            .await
            .map_err(|e| DomainError::ExternalService {
                service: "Keycloak".to_string(),
                message: format!("Failed to remove user federated identity: {}", e),
            })?;

        Ok(())
    }
}

impl<TS: KeycloakTokenSupplier + std::marker::Sync + std::marker::Send> KeycloakRestAdapter<TS> {
    // Conversion methods between domain entities and Keycloak types

    async fn convert_user_from_keycloak(&self, keycloak_user: UserRepresentation) -> DomainResult<User> {
        let id = keycloak_user.id.map(|id| EntityId::from_string(id.to_string()));
        let username = keycloak_user.username.ok_or_else(|| DomainError::Validation {
            field: "username".to_string(),
            message: "Username is required".to_string(),
        })?.to_string();

        let mut user = User::new(username)?;
        user.id = id;
        user.email = keycloak_user.email.map(|e| e.to_string());
        user.email_verified = keycloak_user.email_verified.unwrap_or(false);
        user.first_name = keycloak_user.first_name.map(|f| f.to_string());
        user.last_name = keycloak_user.last_name.map(|l| l.to_string());
        user.enabled = keycloak_user.enabled.unwrap_or(true);

        // Convert attributes
        if let Some(attrs) = keycloak_user.attributes {
            for (key, values) in attrs.iter() {
                user.attributes.set_attribute(key.to_string(), values.iter().map(|v| v.to_string()).collect());
            }
        }

        // Convert required actions
        if let Some(actions) = keycloak_user.required_actions {
            user.required_actions = actions.iter().map(|a| {
                match a.as_str() {
                    "VERIFY_EMAIL" => RequiredAction::VerifyEmail,
                    "UPDATE_PROFILE" => RequiredAction::UpdateProfile,
                    "CONFIGURE_TOTP" => RequiredAction::ConfigureTotp,
                    "UPDATE_PASSWORD" => RequiredAction::UpdatePassword,
                    "terms_and_conditions" => RequiredAction::TermsAndConditions,
                    other => RequiredAction::Other(other.to_string()),
                }
            }).collect();
        }

        // Convert timestamps
        if let Some(created) = keycloak_user.created_timestamp {
            user.timestamps.created_timestamp = Some(chrono::DateTime::from_timestamp_millis(created).unwrap_or_else(chrono::Utc::now));
        }

        Ok(user)
    }

    async fn convert_user_to_keycloak(&self, user: &User) -> DomainResult<UserRepresentation> {
        let mut keycloak_user = UserRepresentation::default();
        
        keycloak_user.id = user.id.as_ref().map(|id| id.to_string().into());
        keycloak_user.username = Some(user.username.clone().into());
        keycloak_user.email = user.email.as_ref().map(|e| e.clone().into());
        keycloak_user.email_verified = Some(user.email_verified);
        keycloak_user.first_name = user.first_name.as_ref().map(|f| f.clone().into());
        keycloak_user.last_name = user.last_name.as_ref().map(|l| l.clone().into());
        keycloak_user.enabled = Some(user.enabled);

        // Convert attributes
        if !user.attributes.attributes.is_empty() {
            let mut attrs = std::collections::HashMap::new();
            for (key, values) in &user.attributes.attributes {
                attrs.insert(key.clone(), values.iter().map(|v| v.clone().into()).collect());
            }
            keycloak_user.attributes = Some(attrs.into());
        }

        // Convert required actions
        if !user.required_actions.is_empty() {
            keycloak_user.required_actions = Some(
                user.required_actions.iter().map(|a| a.to_string().into()).collect()
            );
        }

        // Convert timestamps
        if let Some(created) = user.timestamps.created_timestamp {
            keycloak_user.created_timestamp = Some(created.timestamp_millis());
        }

        Ok(keycloak_user)
    }

    async fn convert_credential_from_keycloak(&self, keycloak_credential: CredentialRepresentation) -> DomainResult<Credential> {
        Ok(Credential {
            id: keycloak_credential.id.map(|id| EntityId::from_string(id.to_string())),
            type_: keycloak_credential.type_.map(|t| t.to_string()).unwrap_or_default(),
            value: keycloak_credential.value.map(|v| v.to_string()),
            temporary: keycloak_credential.temporary,
            created_date: keycloak_credential.created_date.and_then(|ts| 
                chrono::DateTime::from_timestamp_millis(ts)
            ),
            user_label: keycloak_credential.user_label.map(|l| l.to_string()),
            secret_data: keycloak_credential.secret_data.map(|s| s.to_string()),
            credential_data: keycloak_credential.credential_data.map(|c| c.to_string()),
            priority: keycloak_credential.priority,
        })
    }

    async fn convert_credential_to_keycloak(&self, credential: &Credential) -> DomainResult<CredentialRepresentation> {
        let mut keycloak_credential = CredentialRepresentation::default();
        
        keycloak_credential.id = credential.id.as_ref().map(|id| id.to_string().into());
        keycloak_credential.type_ = Some(credential.type_.clone().into());
        keycloak_credential.value = credential.value.as_ref().map(|v| v.clone().into());
        keycloak_credential.temporary = credential.temporary;
        keycloak_credential.created_date = credential.created_date.map(|dt| dt.timestamp_millis());
        keycloak_credential.user_label = credential.user_label.as_ref().map(|l| l.clone().into());
        keycloak_credential.secret_data = credential.secret_data.as_ref().map(|s| s.clone().into());
        keycloak_credential.credential_data = credential.credential_data.as_ref().map(|c| c.clone().into());
        keycloak_credential.priority = credential.priority;

        Ok(keycloak_credential)
    }

    async fn convert_realm_from_keycloak(&self, keycloak_realm: RealmRepresentation) -> DomainResult<Realm> {
        let realm_name = keycloak_realm.realm.ok_or_else(|| DomainError::Validation {
            field: "realm".to_string(),
            message: "Realm name is required".to_string(),
        })?.to_string();

        let mut realm = Realm::new(realm_name)?;
        realm.id = keycloak_realm.id.map(|id| EntityId::from_string(id.to_string()));
        realm.display_name = keycloak_realm.display_name.map(|d| d.to_string());
        realm.display_name_html = keycloak_realm.display_name_html.map(|d| d.to_string());
        realm.enabled = keycloak_realm.enabled.unwrap_or(true);
        
        // Convert SSL required
        if let Some(ssl) = keycloak_realm.ssl_required {
            realm.ssl_required = match ssl.as_str() {
                "all" => SslRequired::All,
                "external" => SslRequired::External,
                "none" => SslRequired::None,
                _ => SslRequired::External,
            };
        }

        realm.registration_allowed = keycloak_realm.registration_allowed.unwrap_or(false);
        realm.registration_email_as_username = keycloak_realm.registration_email_as_username.unwrap_or(false);
        realm.remember_me = keycloak_realm.remember_me.unwrap_or(false);
        realm.verify_email = keycloak_realm.verify_email.unwrap_or(false);
        realm.login_with_email_allowed = keycloak_realm.login_with_email_allowed.unwrap_or(true);
        realm.duplicate_emails_allowed = keycloak_realm.duplicate_emails_allowed.unwrap_or(false);
        realm.reset_password_allowed = keycloak_realm.reset_password_allowed.unwrap_or(false);
        realm.edit_username_allowed = keycloak_realm.edit_username_allowed.unwrap_or(false);
        realm.brute_force_protected = keycloak_realm.brute_force_protected.unwrap_or(false);
        realm.permanent_lockout = keycloak_realm.permanent_lockout.unwrap_or(false);

        // Convert numeric settings
        realm.max_failure_wait_seconds = keycloak_realm.max_failure_wait_seconds.unwrap_or(900);
        realm.minimum_quick_login_wait_seconds = keycloak_realm.minimum_quick_login_wait_seconds.unwrap_or(60);
        realm.wait_increment_seconds = keycloak_realm.wait_increment_seconds.unwrap_or(60);
        realm.quick_login_check_milli_seconds = keycloak_realm.quick_login_check_milli_seconds.unwrap_or(1000) as i32;
        realm.max_delta_time_seconds = keycloak_realm.max_delta_time_seconds.unwrap_or(43200);
        realm.failure_factor = keycloak_realm.failure_factor.unwrap_or(30);

        // Convert default roles from modern API structure
        if let Some(default_role) = keycloak_realm.default_role {
            if let Some(composites) = default_role.composites {
                if let Some(realm_roles) = composites.realm {
                    realm.default_roles = realm_roles.iter().map(|r| r.to_string()).collect();
                }
            }
        }
        
        // Convert authentication requirements from modern API structure
        if let Some(required_actions) = keycloak_realm.required_actions {
            realm.required_credentials = required_actions.iter()
                .filter_map(|action| action.alias.as_ref().map(|a| a.to_string()))
                .collect();
        } else {
            // Fallback to reasonable defaults for authentication
            realm.required_credentials = vec!["password".to_string()];
        }

        // Convert policy settings
        realm.password_policy = keycloak_realm.password_policy.map(|p| p.to_string());
        realm.otp_policy_type = keycloak_realm.otp_policy_type.map(|t| t.to_string());
        realm.otp_policy_algorithm = keycloak_realm.otp_policy_algorithm.map(|a| a.to_string());
        realm.otp_policy_digits = keycloak_realm.otp_policy_digits;
        realm.otp_policy_look_ahead_window = keycloak_realm.otp_policy_look_ahead_window;
        realm.otp_policy_period = keycloak_realm.otp_policy_period;

        // Convert attributes
        if let Some(attrs) = keycloak_realm.attributes {
            for (key, values) in attrs.iter() {
                realm.attributes.set_attribute(key.to_string(), vec![values.to_string()]);
            }
        }

        Ok(realm)
    }

    async fn convert_realm_to_keycloak(&self, realm: &Realm) -> DomainResult<RealmRepresentation> {
        let mut keycloak_realm = RealmRepresentation::default();
        
        keycloak_realm.id = realm.id.as_ref().map(|id| id.to_string().into());
        keycloak_realm.realm = Some(realm.realm.clone().into());
        keycloak_realm.display_name = realm.display_name.as_ref().map(|d| d.clone().into());
        keycloak_realm.display_name_html = realm.display_name_html.as_ref().map(|d| d.clone().into());
        keycloak_realm.enabled = Some(realm.enabled);
        
        // Convert SSL required
        keycloak_realm.ssl_required = Some(match realm.ssl_required {
            SslRequired::All => "all".to_string().into(),
            SslRequired::External => "external".to_string().into(),
            SslRequired::None => "none".to_string().into(),
        });

        keycloak_realm.registration_allowed = Some(realm.registration_allowed);
        keycloak_realm.registration_email_as_username = Some(realm.registration_email_as_username);
        keycloak_realm.remember_me = Some(realm.remember_me);
        keycloak_realm.verify_email = Some(realm.verify_email);
        keycloak_realm.login_with_email_allowed = Some(realm.login_with_email_allowed);
        keycloak_realm.duplicate_emails_allowed = Some(realm.duplicate_emails_allowed);
        keycloak_realm.reset_password_allowed = Some(realm.reset_password_allowed);
        keycloak_realm.edit_username_allowed = Some(realm.edit_username_allowed);
        keycloak_realm.brute_force_protected = Some(realm.brute_force_protected);
        keycloak_realm.permanent_lockout = Some(realm.permanent_lockout);

        // Convert numeric settings
        keycloak_realm.max_failure_wait_seconds = Some(realm.max_failure_wait_seconds);
        keycloak_realm.minimum_quick_login_wait_seconds = Some(realm.minimum_quick_login_wait_seconds);
        keycloak_realm.wait_increment_seconds = Some(realm.wait_increment_seconds);
        keycloak_realm.quick_login_check_milli_seconds = Some(realm.quick_login_check_milli_seconds as i64);
        keycloak_realm.max_delta_time_seconds = Some(realm.max_delta_time_seconds);
        keycloak_realm.failure_factor = Some(realm.failure_factor);

        // Convert default roles to modern API structure
        if !realm.default_roles.is_empty() {
            use keycloak::types::{RoleRepresentation, Composites};
            
            let mut default_role = RoleRepresentation::default();
            default_role.name = Some("default-roles-realm".into());
            default_role.composite = Some(true);
            
            let mut composites = Composites::default();
            composites.realm = Some(realm.default_roles.iter().map(|r| r.clone().into()).collect());
            default_role.composites = Some(composites);
            
            keycloak_realm.default_role = Some(default_role);
        }
        
        // Convert authentication requirements to modern API structure
        if !realm.required_credentials.is_empty() {
            use keycloak::types::RequiredActionProviderRepresentation;
            
            let required_actions: Vec<RequiredActionProviderRepresentation> = realm.required_credentials.iter()
                .map(|cred| {
                    let mut action = RequiredActionProviderRepresentation::default();
                    match cred.as_str() {
                        "password" => {
                            action.alias = Some("UPDATE_PASSWORD".into());
                            action.provider_id = Some("update_password".into());
                            action.enabled = Some(true);
                            action.default_action = Some(true);
                        },
                        "otp" => {
                            action.alias = Some("CONFIGURE_TOTP".into());
                            action.provider_id = Some("CONFIGURE_TOTP".into());
                            action.enabled = Some(true);
                            action.default_action = Some(false);
                        },
                        _ => {
                            action.alias = Some(cred.clone().into());
                            action.provider_id = Some(cred.clone().into());
                            action.enabled = Some(true);
                            action.default_action = Some(false);
                        }
                    }
                    action
                })
                .collect();
            
            keycloak_realm.required_actions = Some(required_actions.into());
        }

        // Convert policy settings
        keycloak_realm.password_policy = realm.password_policy.as_ref().map(|p| p.clone().into());
        keycloak_realm.otp_policy_type = realm.otp_policy_type.as_ref().map(|t| t.clone().into());
        keycloak_realm.otp_policy_algorithm = realm.otp_policy_algorithm.as_ref().map(|a| a.clone().into());
        keycloak_realm.otp_policy_digits = realm.otp_policy_digits;
        keycloak_realm.otp_policy_look_ahead_window = realm.otp_policy_look_ahead_window;
        keycloak_realm.otp_policy_period = realm.otp_policy_period;

        // Convert attributes
        if !realm.attributes.attributes.is_empty() {
            let mut attrs = std::collections::HashMap::new();
            for (key, values) in &realm.attributes.attributes {
                attrs.insert(key.clone(), values.iter().map(|v| v.clone()).collect());
            }
            keycloak_realm.attributes = Some(attrs.into());
        }

        Ok(keycloak_realm)
    }

    async fn convert_client_from_keycloak(&self, keycloak_client: ClientRepresentation) -> DomainResult<Client> {
        let client_id = keycloak_client.client_id.ok_or_else(|| DomainError::Validation {
            field: "client_id".to_string(),
            message: "Client ID is required".to_string(),
        })?.to_string();

        let mut client = Client::new(client_id)?;
        client.id = keycloak_client.id.map(|id| EntityId::from_string(id.to_string()));
        client.name = keycloak_client.name.map(|n| n.to_string());
        client.description = keycloak_client.description.map(|d| d.to_string());
        client.enabled = keycloak_client.enabled.unwrap_or(true);
        client.client_authenticator_type = keycloak_client.client_authenticator_type.map(|t| t.to_string()).unwrap_or_else(|| "client-secret".to_string());
        client.secret = keycloak_client.secret.map(|s| s.to_string());
        client.registration_access_token = keycloak_client.registration_access_token.map(|t| t.to_string());

        // Convert arrays
        if let Some(default_scopes) = keycloak_client.default_client_scopes {
            client.default_scopes = default_scopes.iter().map(|s| s.to_string()).collect();
        }
        if let Some(optional_scopes) = keycloak_client.optional_client_scopes {
            client.optional_scopes = optional_scopes.iter().map(|s| s.to_string()).collect();
        }
        if let Some(redirect_uris) = keycloak_client.redirect_uris {
            client.redirect_uris = redirect_uris.iter().map(|u| u.to_string()).collect();
        }
        if let Some(web_origins) = keycloak_client.web_origins {
            client.web_origins = web_origins.iter().map(|o| o.to_string()).collect();
        }

        // Convert timestamps
        client.not_before = keycloak_client.not_before.and_then(|ts| 
            chrono::DateTime::from_timestamp(ts as i64, 0)
        );

        // Convert boolean flags
        client.bearer_only = keycloak_client.bearer_only.unwrap_or(false);
        client.consent_required = keycloak_client.consent_required.unwrap_or(false);
        client.standard_flow_enabled = keycloak_client.standard_flow_enabled.unwrap_or(true);
        client.implicit_flow_enabled = keycloak_client.implicit_flow_enabled.unwrap_or(false);
        client.direct_access_grants_enabled = keycloak_client.direct_access_grants_enabled.unwrap_or(true);
        client.service_accounts_enabled = keycloak_client.service_accounts_enabled.unwrap_or(false);
        client.authorization_services_enabled = keycloak_client.authorization_services_enabled.unwrap_or(false);
        client.public_client = keycloak_client.public_client.unwrap_or(false);
        client.frontchannel_logout = keycloak_client.frontchannel_logout.unwrap_or(false);
        client.full_scope_allowed = keycloak_client.full_scope_allowed.unwrap_or(true);

        // Convert protocol and other fields
        client.protocol = keycloak_client.protocol.map(|p| p.to_string()).unwrap_or_else(|| "openid-connect".to_string());
        client.node_re_registration_timeout = keycloak_client.node_re_registration_timeout;

        // Convert attributes
        if let Some(attrs) = keycloak_client.attributes {
            for (key, values) in attrs.iter() {
                client.attributes.set_attribute(key.to_string(), vec![values.to_string()]);
            }
        }

        // Convert authentication flow binding overrides
        if let Some(bindings) = keycloak_client.authentication_flow_binding_overrides {
            client.authentication_flow_binding_overrides = bindings.iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();
        }

        Ok(client)
    }

    async fn convert_client_to_keycloak(&self, client: &Client) -> DomainResult<ClientRepresentation> {
        let mut keycloak_client = ClientRepresentation::default();
        
        keycloak_client.id = client.id.as_ref().map(|id| id.to_string().into());
        keycloak_client.client_id = Some(client.client_id.clone().into());
        keycloak_client.name = client.name.as_ref().map(|n| n.clone().into());
        keycloak_client.description = client.description.as_ref().map(|d| d.clone().into());
        keycloak_client.enabled = Some(client.enabled);
        keycloak_client.client_authenticator_type = Some(client.client_authenticator_type.clone().into());
        keycloak_client.secret = client.secret.as_ref().map(|s| s.clone().into());
        keycloak_client.registration_access_token = client.registration_access_token.as_ref().map(|t| t.clone().into());

        // Convert arrays
        if !client.default_scopes.is_empty() {
            keycloak_client.default_client_scopes = Some(client.default_scopes.iter().map(|s| s.clone().into()).collect());
        }
        if !client.optional_scopes.is_empty() {
            keycloak_client.optional_client_scopes = Some(client.optional_scopes.iter().map(|s| s.clone().into()).collect());
        }
        if !client.redirect_uris.is_empty() {
            keycloak_client.redirect_uris = Some(client.redirect_uris.iter().map(|u| u.clone().into()).collect());
        }
        if !client.web_origins.is_empty() {
            keycloak_client.web_origins = Some(client.web_origins.iter().map(|o| o.clone().into()).collect());
        }

        // Convert timestamps
        keycloak_client.not_before = client.not_before.map(|ts| ts.timestamp() as i32);

        // Convert boolean flags
        keycloak_client.bearer_only = Some(client.bearer_only);
        keycloak_client.consent_required = Some(client.consent_required);
        keycloak_client.standard_flow_enabled = Some(client.standard_flow_enabled);
        keycloak_client.implicit_flow_enabled = Some(client.implicit_flow_enabled);
        keycloak_client.direct_access_grants_enabled = Some(client.direct_access_grants_enabled);
        keycloak_client.service_accounts_enabled = Some(client.service_accounts_enabled);
        keycloak_client.authorization_services_enabled = Some(client.authorization_services_enabled);
        keycloak_client.public_client = Some(client.public_client);
        keycloak_client.frontchannel_logout = Some(client.frontchannel_logout);
        keycloak_client.full_scope_allowed = Some(client.full_scope_allowed);

        // Convert protocol and other fields
        keycloak_client.protocol = Some(client.protocol.clone().into());
        keycloak_client.node_re_registration_timeout = client.node_re_registration_timeout;

        // Convert attributes
        if !client.attributes.attributes.is_empty() {
            let mut attrs = std::collections::HashMap::new();
            for (key, values) in &client.attributes.attributes {
                attrs.insert(key.clone(), values.join(","));
            }
            keycloak_client.attributes = Some(attrs);
        }

        // Convert authentication flow binding overrides
        if !client.authentication_flow_binding_overrides.is_empty() {
            let bindings: std::collections::HashMap<_, _> = client.authentication_flow_binding_overrides.iter()
                .map(|(k, v)| (k.clone(), v.clone().into()))
                .collect();
            keycloak_client.authentication_flow_binding_overrides = Some(bindings.into());
        }

        Ok(keycloak_client)
    }

    fn find_group_by_path_recursive<'a>(&'a self, keycloak_group: &'a GroupRepresentation, path: &'a str) -> std::pin::Pin<Box<dyn std::future::Future<Output = DomainResult<Option<Group>>> + Send + 'a>> {
        Box::pin(async move {
            let group = self.convert_group_from_keycloak(keycloak_group.clone()).await?;
            
            if group.path == path {
                return Ok(Some(group));
            }

            // Search in subgroups
            if let Some(ref subgroups) = keycloak_group.sub_groups {
                for subgroup in subgroups {
                    if let Some(found) = self.find_group_by_path_recursive(subgroup, path).await? {
                        return Ok(Some(found));
                    }
                }
            }

            Ok(None)
        })
    }

    fn convert_group_from_keycloak(&self, keycloak_group: GroupRepresentation) -> std::pin::Pin<Box<dyn std::future::Future<Output = DomainResult<Group>> + Send + '_>> {
        Box::pin(async move {
            let name = keycloak_group.name.ok_or_else(|| DomainError::Validation {
                field: "name".to_string(),
                message: "Group name is required".to_string(),
            })?.to_string();

            let path = keycloak_group.path.ok_or_else(|| DomainError::Validation {
                field: "path".to_string(),
                message: "Group path is required".to_string(),
            })?.to_string();

            let mut group = Group::new(name, Some(path))?;
            group.id = keycloak_group.id.map(|id| EntityId::from_string(id.to_string()));

            // Convert attributes
            if let Some(attrs) = keycloak_group.attributes {
                for (key, values) in attrs.iter() {
                    group.attributes.set_attribute(key.to_string(), values.iter().map(|v| v.to_string()).collect());
                }
            }

            // Convert subgroups
            if let Some(subgroups) = keycloak_group.sub_groups {
                for keycloak_subgroup in subgroups {
                    let subgroup = self.convert_group_from_keycloak(keycloak_subgroup).await?;
                    group.sub_groups.push(subgroup);
                }
            }

            // Convert realm roles
            if let Some(realm_roles) = keycloak_group.realm_roles {
                group.realm_roles = realm_roles.iter().map(|r| r.to_string()).collect();
            }

            // Convert client roles
            if let Some(client_roles) = keycloak_group.client_roles {
                for (client, roles) in client_roles.iter() {
                    group.client_roles.insert(
                        client.to_string(),
                        roles.iter().map(|r| r.to_string()).collect(),
                    );
                }
            }

            Ok(group)
        })
    }

    fn convert_group_to_keycloak<'a>(&'a self, group: &'a Group) -> std::pin::Pin<Box<dyn std::future::Future<Output = DomainResult<GroupRepresentation>> + Send + 'a>> {
        Box::pin(async move {
            let mut keycloak_group = GroupRepresentation::default();
            
            keycloak_group.id = group.id.as_ref().map(|id| id.to_string().into());
            keycloak_group.name = Some(group.name.clone().into());
            keycloak_group.path = Some(group.path.clone().into());

            // Convert attributes
            if !group.attributes.attributes.is_empty() {
                let mut attrs = std::collections::HashMap::new();
                for (key, values) in &group.attributes.attributes {
                    attrs.insert(key.clone(), values.iter().map(|v| v.clone().into()).collect());
                }
                keycloak_group.attributes = Some(attrs.into());
            }

            // Convert subgroups
            if !group.sub_groups.is_empty() {
                let mut subgroups = Vec::new();
                for subgroup in &group.sub_groups {
                    subgroups.push(self.convert_group_to_keycloak(subgroup).await?);
                }
                keycloak_group.sub_groups = Some(subgroups);
            }

            // Convert realm roles
            if !group.realm_roles.is_empty() {
                keycloak_group.realm_roles = Some(group.realm_roles.iter().map(|r| r.clone().into()).collect());
            }

            // Convert client roles
            if !group.client_roles.is_empty() {
                let mut client_roles = std::collections::HashMap::new();
                for (client, roles) in &group.client_roles {
                    client_roles.insert(
                        client.clone(),
                        roles.iter().map(|r| r.clone().into()).collect(),
                    );
                }
                keycloak_group.client_roles = Some(client_roles.into());
            }

            Ok(keycloak_group)
        })
    }

    // Role conversion methods
    async fn convert_role_from_keycloak(&self, keycloak_role: RoleRepresentation) -> DomainResult<Role> {
        let name = keycloak_role.name.ok_or_else(|| DomainError::Validation {
            field: "name".to_string(),
            message: "Role name is required".to_string(),
        })?;

        let container_id = keycloak_role.container_id.unwrap_or_default();
        let client_role = keycloak_role.client_role.unwrap_or(false);

        let mut role = if client_role {
            Role::new_client_role(name.to_string(), container_id.to_string())?
        } else {
            Role::new_realm_role(name.to_string(), container_id.to_string())?
        };

        role.id = keycloak_role.id.map(|id| EntityId::from_string(id.to_string()));
        role.description = keycloak_role.description.map(|d| d.to_string());
        role.composite = keycloak_role.composite.unwrap_or(false);

        // Convert attributes
        if let Some(attrs) = keycloak_role.attributes {
            for (key, values) in attrs.iter() {
                if let Some(first_value) = values.first() {
                    role.attributes.set_attribute(key.to_string(), vec![first_value.clone()]);
                }
            }
        }

        // Handle composite relationships if role is composite
        if role.composite {
            role.composites = Some(RoleComposites::new());
            
            // Note: In a real implementation, you'd need to fetch the composite role relationships
            // from Keycloak's API separately, as they're not included in the basic role representation
        }

        Ok(role)
    }

    async fn convert_role_to_keycloak(&self, role: &Role) -> DomainResult<RoleRepresentation> {
        let mut keycloak_role = RoleRepresentation::default();
        
        keycloak_role.name = Some(role.name.clone().into());
        keycloak_role.description = role.description.clone().map(|d| d.into());
        keycloak_role.composite = Some(role.composite);
        keycloak_role.client_role = Some(role.client_role);
        keycloak_role.container_id = Some(role.container_id.clone().into());

        if let Some(ref id) = role.id {
            keycloak_role.id = Some(id.as_str().into());
        }

        // Convert attributes
        if !role.attributes.attributes.is_empty() {
            let mut attrs = std::collections::HashMap::new();
            for (key, values) in role.attributes.attributes.iter() {
                attrs.insert(key.clone().into(), values.clone().into());
            }
            keycloak_role.attributes = Some(attrs.into());
        }

        Ok(keycloak_role)
    }

    // Session conversion methods
    async fn convert_session_from_keycloak_with_realm(&self, keycloak_session: UserSessionRepresentation, _realm: &str) -> DomainResult<UserSession> {
        let session_id = keycloak_session.id.ok_or_else(|| DomainError::Validation {
            field: "id".to_string(),
            message: "Session ID is required".to_string(),
        })?;

        let user_id = keycloak_session.user_id.ok_or_else(|| DomainError::Validation {
            field: "user_id".to_string(),
            message: "User ID is required".to_string(),
        })?;

        let username = keycloak_session.username.unwrap_or_default().to_string();
        let ip_address = keycloak_session.ip_address.map(|ip| ip.to_string());

        // Convert timestamps
        let start = keycloak_session.start
            .and_then(|ts| chrono::DateTime::from_timestamp(ts as i64 / 1000, 0))
            .unwrap_or_else(chrono::Utc::now);
        
        let last_access = keycloak_session.last_access
            .and_then(|ts| chrono::DateTime::from_timestamp(ts as i64 / 1000, 0))
            .unwrap_or_else(chrono::Utc::now);

        // Convert clients
        let clients = if let Some(clients) = keycloak_session.clients {
            clients.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
        } else {
            std::collections::HashMap::new()
        };

        let session = UserSession {
            id: EntityId::from_string(session_id.to_string()),
            user_id: EntityId::from_string(user_id.to_string()),
            username,
            ip_address,
            start,
            last_access,
            clients,
        };

        Ok(session)
    }

    // Federated identity conversion methods
    async fn convert_federated_identity_from_keycloak(&self, keycloak_identity: FederatedIdentityRepresentation) -> DomainResult<FederatedIdentity> {
        let identity_provider = keycloak_identity.identity_provider.ok_or_else(|| DomainError::Validation {
            field: "identity_provider".to_string(),
            message: "Identity provider is required".to_string(),
        })?;

        let user_id = keycloak_identity.user_id.ok_or_else(|| DomainError::Validation {
            field: "user_id".to_string(),
            message: "User ID is required".to_string(),
        })?;

        let user_name = keycloak_identity.user_name.ok_or_else(|| DomainError::Validation {
            field: "user_name".to_string(),
            message: "User name is required".to_string(),
        })?;

        Ok(FederatedIdentity {
            identity_provider: identity_provider.to_string(),
            user_id: user_id.to_string(),
            user_name: user_name.to_string(),
        })
    }

    async fn convert_federated_identity_to_keycloak(&self, identity: &FederatedIdentity) -> DomainResult<FederatedIdentityRepresentation> {
        let mut keycloak_identity = FederatedIdentityRepresentation::default();
        
        keycloak_identity.identity_provider = Some(identity.identity_provider.clone().into());
        keycloak_identity.user_id = Some(identity.user_id.clone().into());
        keycloak_identity.user_name = Some(identity.user_name.clone().into());

        Ok(keycloak_identity)
    }
}

// Implementation of additional repository traits

#[async_trait]
impl<TS: KeycloakTokenSupplier + Send + Sync> ClientScopeRepository for KeycloakRestAdapter<TS> {
    async fn find_client_scope_by_id(
        &self,
        realm: &str,
        scope_id: &str,
    ) -> DomainResult<ClientScope> {
        let keycloak_scope = self
            .admin
            .realm_client_scopes_with_client_scope_id_get(realm, scope_id)
            .await
            .map_err(|e| DomainError::ExternalService {
                service: "Keycloak".to_string(),
                message: format!("Failed to find client scope by ID: {}", e),
            })?;

        self.convert_client_scope_from_keycloak(keycloak_scope).await
    }

    async fn list_client_scopes(
        &self,
        realm: &str,
        _filter: &QueryFilter,
    ) -> DomainResult<Vec<ClientScope>> {
        let keycloak_scopes = self
            .admin
            .realm_client_scopes_get(realm)
            .await
            .map_err(|e| DomainError::ExternalService {
                service: "Keycloak".to_string(),
                message: format!("Failed to list client scopes: {}", e),
            })?;

        let mut scopes = Vec::new();
        for keycloak_scope in keycloak_scopes {
            scopes.push(self.convert_client_scope_from_keycloak(keycloak_scope).await?);
        }
        Ok(scopes)
    }

    async fn create_client_scope(&self, realm: &str, scope: &ClientScope) -> DomainResult<EntityId> {
        let keycloak_scope = self.convert_client_scope_to_keycloak(scope).await?;
        
        let response = self
            .admin
            .realm_client_scopes_post(realm, keycloak_scope)
            .await
            .map_err(|e| DomainError::ExternalService {
                service: "Keycloak".to_string(),
                message: format!("Failed to create client scope: {}", e),
            })?;

        let scope_id = response
            .to_id()
            .ok_or_else(|| DomainError::ExternalService {
                service: "Keycloak".to_string(),
                message: "Failed to get scope ID from response".to_string(),
            })?;

        Ok(EntityId::from_string(scope_id.to_string()))
    }

    async fn update_client_scope(&self, realm: &str, scope: &ClientScope) -> DomainResult<()> {
        let scope_id = scope.id.as_ref().ok_or_else(|| DomainError::Validation {
            field: "id".to_string(),
            message: "Scope ID is required for updates".to_string(),
        })?;

        let keycloak_scope = self.convert_client_scope_to_keycloak(scope).await?;
        
        self.admin
            .realm_client_scopes_with_client_scope_id_put(realm, scope_id.as_str(), keycloak_scope)
            .await
            .map_err(|e| DomainError::ExternalService {
                service: "Keycloak".to_string(),
                message: format!("Failed to update client scope: {}", e),
            })?;

        Ok(())
    }

    async fn delete_client_scope(&self, realm: &str, scope_id: &str) -> DomainResult<()> {
        self.admin
            .realm_client_scopes_with_client_scope_id_delete(realm, scope_id)
            .await
            .map_err(|e| DomainError::ExternalService {
                service: "Keycloak".to_string(),
                message: format!("Failed to delete client scope: {}", e),
            })?;

        Ok(())
    }

    async fn get_client_default_scopes(
        &self,
        realm: &str,
        client_id: &str,
    ) -> DomainResult<Vec<ClientScope>> {
        let keycloak_scopes = self
            .admin
            .realm_clients_with_client_uuid_default_client_scopes_get(realm, client_id)
            .await
            .map_err(|e| DomainError::ExternalService {
                service: "Keycloak".to_string(),
                message: format!("Failed to get client default scopes: {}", e),
            })?;

        let mut scopes = Vec::new();
        for keycloak_scope in keycloak_scopes {
            scopes.push(self.convert_client_scope_from_keycloak(keycloak_scope).await?);
        }
        Ok(scopes)
    }

    async fn get_client_optional_scopes(
        &self,
        realm: &str,
        client_id: &str,
    ) -> DomainResult<Vec<ClientScope>> {
        let keycloak_scopes = self
            .admin
            .realm_clients_with_client_uuid_optional_client_scopes_get(realm, client_id)
            .await
            .map_err(|e| DomainError::ExternalService {
                service: "Keycloak".to_string(),
                message: format!("Failed to get client optional scopes: {}", e),
            })?;

        let mut scopes = Vec::new();
        for keycloak_scope in keycloak_scopes {
            scopes.push(self.convert_client_scope_from_keycloak(keycloak_scope).await?);
        }
        Ok(scopes)
    }

    async fn add_client_default_scope(
        &self,
        realm: &str,
        client_id: &str,
        scope_id: &str,
    ) -> DomainResult<()> {
        self.admin
            .realm_clients_with_client_uuid_default_client_scopes_with_client_scope_id_put(realm, client_id, scope_id)
            .await
            .map_err(|e| DomainError::ExternalService {
                service: "Keycloak".to_string(),
                message: format!("Failed to add client default scope: {}", e),
            })?;

        Ok(())
    }

    async fn remove_client_default_scope(
        &self,
        realm: &str,
        client_id: &str,
        scope_id: &str,
    ) -> DomainResult<()> {
        self.admin
            .realm_clients_with_client_uuid_default_client_scopes_with_client_scope_id_delete(realm, client_id, scope_id)
            .await
            .map_err(|e| DomainError::ExternalService {
                service: "Keycloak".to_string(),
                message: format!("Failed to remove client default scope: {}", e),
            })?;

        Ok(())
    }

    async fn add_client_optional_scope(
        &self,
        realm: &str,
        client_id: &str,
        scope_id: &str,
    ) -> DomainResult<()> {
        self.admin
            .realm_clients_with_client_uuid_optional_client_scopes_with_client_scope_id_put(realm, client_id, scope_id)
            .await
            .map_err(|e| DomainError::ExternalService {
                service: "Keycloak".to_string(),
                message: format!("Failed to add client optional scope: {}", e),
            })?;

        Ok(())
    }

    async fn remove_client_optional_scope(
        &self,
        realm: &str,
        client_id: &str,
        scope_id: &str,
    ) -> DomainResult<()> {
        self.admin
            .realm_clients_with_client_uuid_optional_client_scopes_with_client_scope_id_delete(realm, client_id, scope_id)
            .await
            .map_err(|e| DomainError::ExternalService {
                service: "Keycloak".to_string(),
                message: format!("Failed to remove client optional scope: {}", e),
            })?;

        Ok(())
    }
}

#[async_trait]
impl<TS: KeycloakTokenSupplier + Send + Sync> EventRepository for KeycloakRestAdapter<TS> {
    async fn list_events(&self, realm: &str, filter: &EventFilter) -> DomainResult<Vec<Event>> {
        let keycloak_events = self
            .admin
            .realm_events_get(
                realm,
                filter.client.clone(),
                filter.date_from.map(|d| d.to_rfc3339()),
                filter.date_to.map(|d| d.to_rfc3339()),
                filter.ip_address.clone(),
                filter.first,
                filter.type_.clone(),
                filter.max,
                None, // user parameter
                filter.user.clone(),
            )
            .await
            .map_err(|e| DomainError::ExternalService {
                service: "Keycloak".to_string(),
                message: format!("Failed to list events: {}", e),
            })?;

        let mut events = Vec::new();
        for keycloak_event in keycloak_events {
            events.push(self.convert_event_from_keycloak(keycloak_event).await?);
        }
        Ok(events)
    }

    async fn clear_events(&self, realm: &str) -> DomainResult<()> {
        self.admin
            .realm_events_delete(realm)
            .await
            .map_err(|e| DomainError::ExternalService {
                service: "Keycloak".to_string(),
                message: format!("Failed to clear events: {}", e),
            })?;

        Ok(())
    }

    async fn get_events_config(&self, realm: &str) -> DomainResult<EventConfig> {
        let keycloak_config = self
            .admin
            .realm_events_config_get(realm)
            .await
            .map_err(|e| DomainError::ExternalService {
                service: "Keycloak".to_string(),
                message: format!("Failed to get events config: {}", e),
            })?;

        self.convert_event_config_from_keycloak(keycloak_config).await
    }

    async fn update_events_config(&self, realm: &str, config: &EventConfig) -> DomainResult<()> {
        let keycloak_config = self.convert_event_config_to_keycloak(config).await?;
        
        self.admin
            .realm_events_config_put(realm, keycloak_config)
            .await
            .map_err(|e| DomainError::ExternalService {
                service: "Keycloak".to_string(),
                message: format!("Failed to update events config: {}", e),
            })?;

        Ok(())
    }
}

#[async_trait]
impl<TS: KeycloakTokenSupplier + Send + Sync> IdentityProviderRepository for KeycloakRestAdapter<TS> {
    async fn find_identity_provider_by_alias(
        &self,
        realm: &str,
        alias: &str,
    ) -> DomainResult<IdentityProvider> {
        let keycloak_provider = self
            .admin
            .realm_identity_provider_instances_with_alias_get(realm, alias)
            .await
            .map_err(|e| DomainError::ExternalService {
                service: "Keycloak".to_string(),
                message: format!("Failed to find identity provider by alias: {}", e),
            })?;

        self.convert_identity_provider_from_keycloak(keycloak_provider).await
    }

    async fn list_identity_providers(&self, realm: &str) -> DomainResult<Vec<IdentityProvider>> {
        let keycloak_providers = self
            .admin
            .realm_identity_provider_instances_get(realm, None, None, None, None, None)
            .await
            .map_err(|e| DomainError::ExternalService {
                service: "Keycloak".to_string(),
                message: format!("Failed to list identity providers: {}", e),
            })?;

        let mut providers = Vec::new();
        for keycloak_provider in keycloak_providers {
            providers.push(self.convert_identity_provider_from_keycloak(keycloak_provider).await?);
        }
        Ok(providers)
    }

    async fn create_identity_provider(
        &self,
        realm: &str,
        provider: &IdentityProvider,
    ) -> DomainResult<String> {
        let keycloak_provider = self.convert_identity_provider_to_keycloak(provider).await?;
        
        self.admin
            .realm_identity_provider_instances_post(realm, keycloak_provider)
            .await
            .map_err(|e| DomainError::ExternalService {
                service: "Keycloak".to_string(),
                message: format!("Failed to create identity provider: {}", e),
            })?;

        Ok(provider.alias.clone())
    }

    async fn update_identity_provider(
        &self,
        realm: &str,
        provider: &IdentityProvider,
    ) -> DomainResult<()> {
        let keycloak_provider = self.convert_identity_provider_to_keycloak(provider).await?;
        
        self.admin
            .realm_identity_provider_instances_with_alias_put(realm, &provider.alias, keycloak_provider)
            .await
            .map_err(|e| DomainError::ExternalService {
                service: "Keycloak".to_string(),
                message: format!("Failed to update identity provider: {}", e),
            })?;

        Ok(())
    }

    async fn delete_identity_provider(&self, realm: &str, alias: &str) -> DomainResult<()> {
        self.admin
            .realm_identity_provider_instances_with_alias_delete(realm, alias)
            .await
            .map_err(|e| DomainError::ExternalService {
                service: "Keycloak".to_string(),
                message: format!("Failed to delete identity provider: {}", e),
            })?;

        Ok(())
    }
}

// Conversion methods for new entities

impl<TS: KeycloakTokenSupplier + std::marker::Sync + std::marker::Send> KeycloakRestAdapter<TS> {
    async fn convert_client_scope_from_keycloak(&self, keycloak_scope: keycloak::types::ClientScopeRepresentation) -> DomainResult<ClientScope> {
        let name = keycloak_scope.name.ok_or_else(|| DomainError::Validation {
            field: "name".to_string(),
            message: "Client scope name is required".to_string(),
        })?.to_string();

        let mut scope = ClientScope {
            id: keycloak_scope.id.map(|id| EntityId::from_string(id.to_string())),
            name,
            description: keycloak_scope.description.map(|d| d.to_string()),
            protocol: keycloak_scope.protocol.map(|p| p.to_string()).unwrap_or_else(|| "openid-connect".to_string()),
            attributes: Attributes::new(),
            protocol_mappers: Vec::new(),
        };

        // Convert attributes
        if let Some(attrs) = keycloak_scope.attributes {
            for (key, values) in attrs.iter() {
                scope.attributes.set_attribute(key.to_string(), vec![values.to_string()]);
            }
        }

        // Convert protocol mappers
        if let Some(mappers) = keycloak_scope.protocol_mappers {
            for mapper in mappers {
                let protocol_mapper = ProtocolMapper {
                    id: mapper.id.map(|id| EntityId::from_string(id.to_string())),
                    name: mapper.name.map(|n| n.to_string()).unwrap_or_default(),
                    protocol: mapper.protocol.map(|p| p.to_string()).unwrap_or_default(),
                    protocol_mapper: mapper.protocol_mapper.map(|pm| pm.to_string()).unwrap_or_default(),
                    consent_required: mapper.consent_required.unwrap_or(false),
                    config: mapper.config.map(|c| 
                        c.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
                    ).unwrap_or_default(),
                };
                scope.protocol_mappers.push(protocol_mapper);
            }
        }

        Ok(scope)
    }

    async fn convert_client_scope_to_keycloak(&self, scope: &ClientScope) -> DomainResult<keycloak::types::ClientScopeRepresentation> {
        let mut keycloak_scope = keycloak::types::ClientScopeRepresentation::default();
        
        keycloak_scope.id = scope.id.as_ref().map(|id| id.to_string().into());
        keycloak_scope.name = Some(scope.name.clone().into());
        keycloak_scope.description = scope.description.as_ref().map(|d| d.clone().into());
        keycloak_scope.protocol = Some(scope.protocol.clone().into());

        // Convert attributes
        if !scope.attributes.attributes.is_empty() {
            let mut attrs = std::collections::HashMap::new();
            for (key, values) in &scope.attributes.attributes {
                attrs.insert(key.clone(), values.join(","));
            }
            keycloak_scope.attributes = Some(attrs);
        }

        // Convert protocol mappers
        if !scope.protocol_mappers.is_empty() {
            let mut mappers = Vec::new();
            for mapper in &scope.protocol_mappers {
                let mut keycloak_mapper = keycloak::types::ProtocolMapperRepresentation::default();
                keycloak_mapper.id = mapper.id.as_ref().map(|id| id.to_string().into());
                keycloak_mapper.name = Some(mapper.name.clone().into());
                keycloak_mapper.protocol = Some(mapper.protocol.clone().into());
                keycloak_mapper.protocol_mapper = Some(mapper.protocol_mapper.clone().into());
                keycloak_mapper.consent_required = Some(mapper.consent_required);
                
                if !mapper.config.is_empty() {
                    let config: std::collections::HashMap<_, _> = mapper.config.iter()
                        .map(|(k, v)| (k.clone().into(), v.clone().into()))
                        .collect();
                    keycloak_mapper.config = Some(config.into());
                }
                
                mappers.push(keycloak_mapper);
            }
            keycloak_scope.protocol_mappers = Some(mappers);
        }

        Ok(keycloak_scope)
    }

    async fn convert_event_from_keycloak(&self, keycloak_event: keycloak::types::EventRepresentation) -> DomainResult<Event> {
        let time = keycloak_event.time
            .and_then(|t| chrono::DateTime::from_timestamp_millis(t))
            .unwrap_or_else(chrono::Utc::now);

        let event = Event {
            time,
            type_: keycloak_event.type_.map(|t| t.to_string()).unwrap_or_default(),
            realm_id: keycloak_event.realm_id.map(|r| r.to_string()).unwrap_or_default(),
            client_id: keycloak_event.client_id.map(|c| c.to_string()),
            user_id: keycloak_event.user_id.map(|u| u.to_string()),
            session_id: keycloak_event.session_id.map(|s| s.to_string()),
            ip_address: keycloak_event.ip_address.map(|ip| ip.to_string()),
            error: keycloak_event.error.map(|e| e.to_string()),
            details: keycloak_event.details.map(|d| 
                d.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
            ).unwrap_or_default(),
        };

        Ok(event)
    }

    async fn convert_event_config_from_keycloak(&self, keycloak_config: keycloak::types::RealmEventsConfigRepresentation) -> DomainResult<EventConfig> {
        let config = EventConfig {
            events_enabled: keycloak_config.events_enabled.unwrap_or(false),
            events_listeners: keycloak_config.events_listeners.map(|l| 
                l.iter().map(|item| item.to_string()).collect()
            ).unwrap_or_default(),
            enabled_event_types: keycloak_config.enabled_event_types.map(|t| 
                t.iter().map(|item| item.to_string()).collect()
            ).unwrap_or_default(),
            admin_events_enabled: keycloak_config.admin_events_enabled.unwrap_or(false),
            admin_events_details_enabled: keycloak_config.admin_events_details_enabled.unwrap_or(false),
            events_expiration: keycloak_config.events_expiration,
        };

        Ok(config)
    }

    async fn convert_event_config_to_keycloak(&self, config: &EventConfig) -> DomainResult<keycloak::types::RealmEventsConfigRepresentation> {
        let mut keycloak_config = keycloak::types::RealmEventsConfigRepresentation::default();
        
        keycloak_config.events_enabled = Some(config.events_enabled);
        keycloak_config.admin_events_enabled = Some(config.admin_events_enabled);
        keycloak_config.admin_events_details_enabled = Some(config.admin_events_details_enabled);
        keycloak_config.events_expiration = config.events_expiration;

        if !config.events_listeners.is_empty() {
            keycloak_config.events_listeners = Some(
                config.events_listeners.iter().map(|l| l.clone().into()).collect()
            );
        }

        if !config.enabled_event_types.is_empty() {
            keycloak_config.enabled_event_types = Some(
                config.enabled_event_types.iter().map(|t| t.clone().into()).collect()
            );
        }

        Ok(keycloak_config)
    }

    async fn convert_identity_provider_from_keycloak(&self, keycloak_provider: keycloak::types::IdentityProviderRepresentation) -> DomainResult<IdentityProvider> {
        let alias = keycloak_provider.alias.ok_or_else(|| DomainError::Validation {
            field: "alias".to_string(),
            message: "Identity provider alias is required".to_string(),
        })?.to_string();

        let provider_id = keycloak_provider.provider_id.ok_or_else(|| DomainError::Validation {
            field: "provider_id".to_string(),
            message: "Identity provider ID is required".to_string(),
        })?.to_string();

        let provider = IdentityProvider {
            alias,
            display_name: keycloak_provider.display_name.map(|d| d.to_string()),
            provider_id,
            enabled: keycloak_provider.enabled.unwrap_or(true),
            store_token: keycloak_provider.store_token.unwrap_or(false),
            add_read_token_role_on_create: keycloak_provider.add_read_token_role_on_create.unwrap_or(false),
            authenticate_by_default: keycloak_provider.authenticate_by_default.unwrap_or(false),
            link_only: keycloak_provider.link_only.unwrap_or(false),
            first_broker_login_flow_alias: keycloak_provider.first_broker_login_flow_alias.map(|f| f.to_string()).unwrap_or_default(),
            post_broker_login_flow_alias: keycloak_provider.post_broker_login_flow_alias.map(|p| p.to_string()),
            config: keycloak_provider.config.map(|c| 
                c.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
            ).unwrap_or_default(),
        };

        Ok(provider)
    }

    async fn convert_identity_provider_to_keycloak(&self, provider: &IdentityProvider) -> DomainResult<keycloak::types::IdentityProviderRepresentation> {
        let mut keycloak_provider = keycloak::types::IdentityProviderRepresentation::default();
        
        keycloak_provider.alias = Some(provider.alias.clone().into());
        keycloak_provider.display_name = provider.display_name.as_ref().map(|d| d.clone().into());
        keycloak_provider.provider_id = Some(provider.provider_id.clone().into());
        keycloak_provider.enabled = Some(provider.enabled);
        keycloak_provider.store_token = Some(provider.store_token);
        keycloak_provider.add_read_token_role_on_create = Some(provider.add_read_token_role_on_create);
        keycloak_provider.authenticate_by_default = Some(provider.authenticate_by_default);
        keycloak_provider.link_only = Some(provider.link_only);
        keycloak_provider.first_broker_login_flow_alias = Some(provider.first_broker_login_flow_alias.clone().into());
        keycloak_provider.post_broker_login_flow_alias = provider.post_broker_login_flow_alias.as_ref().map(|p| p.clone().into());

        if !provider.config.is_empty() {
            let config: std::collections::HashMap<_, _> = provider.config.iter()
                .map(|(k, v)| (k.clone().into(), v.clone().into()))
                .collect();
            keycloak_provider.config = Some(config.into());
        }

        Ok(keycloak_provider)
    }
}
