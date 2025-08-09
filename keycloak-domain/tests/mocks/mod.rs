use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use keycloak_domain::{
    application::ports::{
        repository::{KeycloakRepository, UserSession},
        events::{EventPublisher, DomainEvent, EventError},
        auth::{AuthorizationService, AuthorizationContext, Permission},
    },
    domain::{
        entities::*,
        errors::{DomainError, DomainResult, AuthError},
    },
};

/// Mock repository implementation for testing
pub struct MockKeycloakRepository {
    pub users: Arc<Mutex<HashMap<String, Vec<User>>>>, // realm -> users
    pub realms: Arc<Mutex<Vec<Realm>>>,
    pub clients: Arc<Mutex<HashMap<String, Vec<Client>>>>, // realm -> clients
    pub groups: Arc<Mutex<HashMap<String, Vec<Group>>>>, // realm -> groups
    pub roles: Arc<Mutex<HashMap<String, Vec<Role>>>>, // realm -> roles
    pub user_counter: Arc<Mutex<u32>>,
    pub client_counter: Arc<Mutex<u32>>,
    pub group_counter: Arc<Mutex<u32>>,
    pub should_fail: Arc<Mutex<bool>>, // For testing error scenarios
}

impl MockKeycloakRepository {
    pub fn new() -> Self {
        let mut realms = Vec::new();
        // Add default test realm (avoiding "master" as it's reserved)
        realms.push(Realm::new("test-realm".to_string()).expect("Failed to create test realm"));
        
        // Add default test client
        let mut clients = HashMap::new();
        let mut test_client = Client::confidential_client("test-client".to_string())
            .expect("Failed to create test client");
        test_client.id = Some(EntityId::from("test-client-id"));
        clients.insert("test-realm".to_string(), vec![test_client]);
        
        Self {
            users: Arc::new(Mutex::new(HashMap::new())),
            realms: Arc::new(Mutex::new(realms)),
            clients: Arc::new(Mutex::new(clients)),
            groups: Arc::new(Mutex::new(HashMap::new())),
            roles: Arc::new(Mutex::new(HashMap::new())),
            user_counter: Arc::new(Mutex::new(0)),
            client_counter: Arc::new(Mutex::new(0)),
            group_counter: Arc::new(Mutex::new(0)),
            should_fail: Arc::new(Mutex::new(false)),
        }
    }
    
    pub fn set_should_fail(&self, should_fail: bool) {
        *self.should_fail.lock().unwrap() = should_fail;
    }
    
    fn check_should_fail(&self) -> DomainResult<()> {
        if *self.should_fail.lock().unwrap() {
            Err(DomainError::ExternalService {
                service: "mock-keycloak".to_string(),
                message: "Mock failure enabled".to_string(),
            })
        } else {
            Ok(())
        }
    }
    
    fn generate_user_id(&self) -> String {
        let mut counter = self.user_counter.lock().unwrap();
        *counter += 1;
        format!("user-{}", counter)
    }
    
    fn generate_client_id(&self) -> String {
        let mut counter = self.client_counter.lock().unwrap();
        *counter += 1;
        format!("client-{}", counter)
    }
    
    fn generate_group_id(&self) -> String {
        let mut counter = self.group_counter.lock().unwrap();
        *counter += 1;
        format!("group-{}", counter)
    }
}

#[async_trait]
impl KeycloakRepository for MockKeycloakRepository {
    // User operations
    async fn find_user_by_id(&self, realm: &str, user_id: &str) -> DomainResult<User> {
        self.check_should_fail()?;
        
        let users = self.users.lock().unwrap();
        if let Some(realm_users) = users.get(realm) {
            for user in realm_users {
                if user.id.as_ref().map(|id| id.as_str()) == Some(user_id) {
                    return Ok(user.clone());
                }
            }
        }
        
        Err(DomainError::UserNotFound {
            user_id: user_id.to_string(),
            realm: realm.to_string(),
        })
    }
    
    async fn find_user_by_username(&self, realm: &str, username: &str) -> DomainResult<Option<User>> {
        self.check_should_fail()?;
        
        let users = self.users.lock().unwrap();
        if let Some(realm_users) = users.get(realm) {
            for user in realm_users {
                if user.username == username {
                    return Ok(Some(user.clone()));
                }
            }
        }
        
        Ok(None)
    }
    
    async fn find_user_by_email(&self, realm: &str, email: &str) -> DomainResult<Option<User>> {
        self.check_should_fail()?;
        
        let users = self.users.lock().unwrap();
        if let Some(realm_users) = users.get(realm) {
            for user in realm_users {
                if user.email.as_ref() == Some(&email.to_string()) {
                    return Ok(Some(user.clone()));
                }
            }
        }
        
        Ok(None)
    }
    
    async fn list_users(&self, realm: &str, filter: &UserFilter) -> DomainResult<Vec<User>> {
        self.check_should_fail()?;
        
        let users = self.users.lock().unwrap();
        let realm_users = users.get(realm).cloned().unwrap_or_default();
        
        let mut filtered = realm_users;
        
        // Apply filters
        if let Some(username) = &filter.username {
            filtered.retain(|u| u.username.contains(username));
        }
        
        if let Some(email) = &filter.email {
            filtered.retain(|u| u.email.as_ref().map_or(false, |e| e.contains(email)));
        }
        
        if let Some(first_name) = &filter.first_name {
            filtered.retain(|u| u.first_name.as_ref().map_or(false, |f| f.contains(first_name)));
        }
        
        if let Some(last_name) = &filter.last_name {
            filtered.retain(|u| u.last_name.as_ref().map_or(false, |l| l.contains(last_name)));
        }
        
        if let Some(enabled) = filter.enabled {
            filtered.retain(|u| u.enabled == enabled);
        }
        
        // Apply pagination
        if let Some(first) = filter.first {
            if first > 0 {
                filtered = filtered.into_iter().skip(first as usize).collect();
            }
        }
        
        if let Some(max) = filter.max {
            filtered.truncate(max as usize);
        }
        
        Ok(filtered)
    }
    
    async fn create_user(&self, realm: &str, user: &User) -> DomainResult<EntityId> {
        self.check_should_fail()?;
        
        let user_id = self.generate_user_id();
        let mut new_user = user.clone();
        new_user.id = Some(EntityId::from(user_id.clone()));
        
        let mut users = self.users.lock().unwrap();
        users.entry(realm.to_string()).or_insert_with(Vec::new).push(new_user);
        
        Ok(EntityId::from(user_id))
    }
    
    async fn update_user(&self, realm: &str, user: &User) -> DomainResult<()> {
        self.check_should_fail()?;
        
        let user_id = user.id.as_ref().ok_or_else(|| DomainError::Validation {
            field: "id".to_string(),
            message: "User ID is required for update".to_string(),
        })?;
        
        let mut users = self.users.lock().unwrap();
        if let Some(realm_users) = users.get_mut(realm) {
            for existing_user in realm_users.iter_mut() {
                if existing_user.id.as_ref() == Some(user_id) {
                    *existing_user = user.clone();
                    return Ok(());
                }
            }
        }
        
        Err(DomainError::UserNotFound {
            user_id: user_id.to_string(),
            realm: realm.to_string(),
        })
    }
    
    async fn delete_user(&self, realm: &str, user_id: &str) -> DomainResult<()> {
        self.check_should_fail()?;
        
        let mut users = self.users.lock().unwrap();
        if let Some(realm_users) = users.get_mut(realm) {
            let initial_len = realm_users.len();
            realm_users.retain(|u| u.id.as_ref().map(|id| id.as_str()) != Some(user_id));
            
            if realm_users.len() < initial_len {
                Ok(())
            } else {
                Err(DomainError::UserNotFound {
                    user_id: user_id.to_string(),
                    realm: realm.to_string(),
                })
            }
        } else {
            Err(DomainError::RealmNotFound {
                realm: realm.to_string(),
            })
        }
    }
    
    async fn count_users(&self, realm: &str) -> DomainResult<i64> {
        self.check_should_fail()?;
        
        let users = self.users.lock().unwrap();
        let count = users.get(realm).map(|u| u.len()).unwrap_or(0);
        Ok(count as i64)
    }
    
    // User credential operations
    async fn set_user_password(&self, _realm: &str, _user_id: &str, _credential: &Credential) -> DomainResult<()> {
        self.check_should_fail()?;
        Ok(()) // Mock implementation - just succeed
    }
    
    async fn get_user_credentials(&self, _realm: &str, _user_id: &str) -> DomainResult<Vec<Credential>> {
        self.check_should_fail()?;
        Ok(vec![]) // Mock implementation - return empty list
    }
    
    async fn delete_user_credential(&self, _realm: &str, _user_id: &str, _credential_id: &str) -> DomainResult<()> {
        self.check_should_fail()?;
        Ok(()) // Mock implementation - just succeed
    }
    
    // Realm operations
    async fn find_realm_by_name(&self, realm: &str) -> DomainResult<Realm> {
        self.check_should_fail()?;
        
        let realms = self.realms.lock().unwrap();
        for r in realms.iter() {
            if r.realm == realm {
                return Ok(r.clone());
            }
        }
        
        Err(DomainError::RealmNotFound {
            realm: realm.to_string(),
        })
    }
    
    async fn list_realms(&self) -> DomainResult<Vec<Realm>> {
        self.check_should_fail()?;
        
        let realms = self.realms.lock().unwrap();
        Ok(realms.clone())
    }
    
    async fn create_realm(&self, realm: &Realm) -> DomainResult<EntityId> {
        self.check_should_fail()?;
        
        let mut realms = self.realms.lock().unwrap();
        
        // Check if realm already exists
        for existing in realms.iter() {
            if existing.realm == realm.realm {
                return Err(DomainError::RealmAlreadyExists {
                    realm: realm.realm.clone(),
                });
            }
        }
        
        realms.push(realm.clone());
        Ok(EntityId::from(realm.realm.clone()))
    }
    
    async fn update_realm(&self, realm: &Realm) -> DomainResult<()> {
        self.check_should_fail()?;
        
        let mut realms = self.realms.lock().unwrap();
        for existing in realms.iter_mut() {
            if existing.realm == realm.realm {
                *existing = realm.clone();
                return Ok(());
            }
        }
        
        Err(DomainError::RealmNotFound {
            realm: realm.realm.clone(),
        })
    }
    
    async fn delete_realm(&self, realm: &str) -> DomainResult<()> {
        self.check_should_fail()?;
        
        let mut realms = self.realms.lock().unwrap();
        let initial_len = realms.len();
        realms.retain(|r| r.realm != realm);
        
        if realms.len() < initial_len {
            Ok(())
        } else {
            Err(DomainError::RealmNotFound {
                realm: realm.to_string(),
            })
        }
    }
    
    // Client operations
    async fn find_client_by_id(&self, realm: &str, client_id: &str) -> DomainResult<Client> {
        self.check_should_fail()?;
        
        let clients = self.clients.lock().unwrap();
        if let Some(realm_clients) = clients.get(realm) {
            for client in realm_clients {
                if client.client_id == client_id {
                    return Ok(client.clone());
                }
            }
        }
        
        Err(DomainError::ClientNotFound {
            client_id: client_id.to_string(),
            realm: realm.to_string(),
        })
    }
    
    async fn find_client_by_client_id(&self, realm: &str, client_id: &str) -> DomainResult<Option<Client>> {
        self.check_should_fail()?;
        
        let clients = self.clients.lock().unwrap();
        if let Some(realm_clients) = clients.get(realm) {
            for client in realm_clients {
                if client.client_id == client_id {
                    return Ok(Some(client.clone()));
                }
            }
        }
        
        Ok(None)
    }
    
    async fn list_clients(&self, realm: &str, filter: &ClientFilter) -> DomainResult<Vec<Client>> {
        self.check_should_fail()?;
        
        let clients = self.clients.lock().unwrap();
        let mut realm_clients = clients.get(realm).cloned().unwrap_or_default();
        
        // Apply filters
        if let Some(client_id) = &filter.client_id {
            realm_clients.retain(|c| c.client_id.contains(client_id));
        }
        
        if let Some(search) = &filter.search {
            realm_clients.retain(|c| {
                c.client_id.contains(search) || 
                c.name.as_ref().map_or(false, |n| n.contains(search))
            });
        }
        
        // Apply pagination
        if let Some(first) = filter.first {
            if first > 0 {
                realm_clients = realm_clients.into_iter().skip(first as usize).collect();
            }
        }
        
        if let Some(max) = filter.max {
            realm_clients.truncate(max as usize);
        }
        
        Ok(realm_clients)
    }
    
    async fn create_client(&self, realm: &str, client: &Client) -> DomainResult<EntityId> {
        self.check_should_fail()?;
        
        let client_id = self.generate_client_id();
        let mut new_client = client.clone();
        new_client.id = Some(EntityId::from(client_id.clone()));
        
        let mut clients = self.clients.lock().unwrap();
        clients.entry(realm.to_string()).or_insert_with(Vec::new).push(new_client);
        
        Ok(EntityId::from(client_id))
    }
    
    async fn update_client(&self, realm: &str, client: &Client) -> DomainResult<()> {
        self.check_should_fail()?;
        
        let client_id = client.id.as_ref().ok_or_else(|| DomainError::Validation {
            field: "id".to_string(),
            message: "Client ID is required for update".to_string(),
        })?;
        
        let mut clients = self.clients.lock().unwrap();
        if let Some(realm_clients) = clients.get_mut(realm) {
            for existing_client in realm_clients.iter_mut() {
                if existing_client.id.as_ref() == Some(client_id) {
                    *existing_client = client.clone();
                    return Ok(());
                }
            }
        }
        
        Err(DomainError::ClientNotFound {
            client_id: client_id.to_string(),
            realm: realm.to_string(),
        })
    }
    
    async fn delete_client(&self, realm: &str, client_id: &str) -> DomainResult<()> {
        self.check_should_fail()?;
        
        let mut clients = self.clients.lock().unwrap();
        if let Some(realm_clients) = clients.get_mut(realm) {
            let initial_len = realm_clients.len();
            realm_clients.retain(|c| c.client_id != client_id);
            
            if realm_clients.len() < initial_len {
                Ok(())
            } else {
                Err(DomainError::ClientNotFound {
                    client_id: client_id.to_string(),
                    realm: realm.to_string(),
                })
            }
        } else {
            Err(DomainError::RealmNotFound {
                realm: realm.to_string(),
            })
        }
    }
    
    async fn get_client_secret(&self, _realm: &str, _client_id: &str) -> DomainResult<String> {
        self.check_should_fail()?;
        Ok("mock-client-secret".to_string())
    }
    
    async fn regenerate_client_secret(&self, _realm: &str, _client_id: &str) -> DomainResult<String> {
        self.check_should_fail()?;
        Ok("new-mock-client-secret".to_string())
    }
    
    // Additional methods would continue here for groups, roles, etc.
    // For brevity, I'll implement the essential ones and add placeholders for others
    
    async fn list_groups(&self, realm: &str, filter: &GroupFilter) -> DomainResult<Vec<Group>> {
        self.check_should_fail()?;
        
        let groups = self.groups.lock().unwrap();
        let mut realm_groups = groups.get(realm).cloned().unwrap_or_default();
        
        // Apply filters
        if let Some(ref search) = filter.search {
            if filter.exact.unwrap_or(false) {
                // Exact match
                realm_groups.retain(|g| g.name == *search);
            } else {
                // Partial match
                realm_groups.retain(|g| g.name.contains(search));
            }
        }
        
        // Apply pagination
        if let Some(first) = filter.first {
            if first > 0 {
                realm_groups = realm_groups.into_iter().skip(first as usize).collect();
            }
        }
        
        if let Some(max) = filter.max {
            realm_groups.truncate(max as usize);
        }
        
        Ok(realm_groups)
    }
    
    async fn create_group(&self, realm: &str, group: &Group) -> DomainResult<EntityId> {
        self.check_should_fail()?;
        
        let mut groups = self.groups.lock().unwrap();
        let realm_groups = groups.entry(realm.to_string()).or_insert_with(Vec::new);
        
        // Check for duplicate names at the same level
        if realm_groups.iter().any(|g| g.name == group.name && g.path == group.path) {
            return Err(DomainError::AlreadyExists {
                entity_type: "group".to_string(),
                identifier: group.name.clone(),
            });
        }
        
        let group_id = self.generate_group_id();
        let mut new_group = group.clone();
        new_group.id = Some(EntityId::from(group_id.clone()));
        
        realm_groups.push(new_group);
        
        Ok(EntityId::from(group_id))
    }
    
    // Placeholder implementations for other required methods
    async fn get_user_groups(&self, _realm: &str, _user_id: &str) -> DomainResult<Vec<Group>> {
        self.check_should_fail()?;
        Ok(vec![])
    }
    
    async fn add_user_to_group(&self, _realm: &str, _user_id: &str, _group_id: &str) -> DomainResult<()> {
        self.check_should_fail()?;
        Ok(())
    }
    
    async fn remove_user_from_group(&self, _realm: &str, _user_id: &str, _group_id: &str) -> DomainResult<()> {
        self.check_should_fail()?;
        Ok(())
    }
    
    async fn get_user_role_mappings(&self, _realm: &str, _user_id: &str) -> DomainResult<RoleMapping> {
        self.check_should_fail()?;
        Ok(RoleMapping {
            realm_mappings: vec![],
            client_mappings: std::collections::HashMap::new(),
        })
    }
    
    
    async fn list_realm_roles(&self, _realm: &str, _filter: &RoleFilter) -> DomainResult<Vec<Role>> {
        self.check_should_fail()?;
        
        let roles = self.roles.lock().unwrap();
        Ok(roles.get(_realm).cloned().unwrap_or_default())
    }
    
    async fn list_client_roles(&self, _realm: &str, _client_id: &str, _filter: &RoleFilter) -> DomainResult<Vec<Role>> {
        self.check_should_fail()?;
        Ok(vec![])
    }
    
    
    async fn delete_realm_role(&self, _realm: &str, _role_name: &str) -> DomainResult<()> {
        self.check_should_fail()?;
        Ok(())
    }
    
    async fn find_group_by_id(&self, realm: &str, group_id: &str) -> DomainResult<Group> {
        self.check_should_fail()?;
        
        let groups = self.groups.lock().unwrap();
        if let Some(realm_groups) = groups.get(realm) {
            for group in realm_groups {
                if group.id.as_ref().map(|id| id.as_str()) == Some(group_id) {
                    return Ok(group.clone());
                }
            }
        }
        
        Err(DomainError::GroupNotFound {
            group_id: group_id.to_string(),
            realm: realm.to_string(),
        })
    }
    
    async fn update_group(&self, realm: &str, group: &Group) -> DomainResult<()> {
        self.check_should_fail()?;
        
        let group_id = group.id.as_ref().ok_or_else(|| DomainError::Validation {
            field: "id".to_string(),
            message: "Group ID is required for update".to_string(),
        })?;
        
        let mut groups = self.groups.lock().unwrap();
        if let Some(realm_groups) = groups.get_mut(realm) {
            for existing_group in realm_groups.iter_mut() {
                if existing_group.id.as_ref() == Some(group_id) {
                    *existing_group = group.clone();
                    return Ok(());
                }
            }
        }
        
        Err(DomainError::GroupNotFound {
            group_id: group_id.to_string(),
            realm: realm.to_string(),
        })
    }
    
    async fn delete_group(&self, realm: &str, group_id: &str) -> DomainResult<()> {
        self.check_should_fail()?;
        
        let mut groups = self.groups.lock().unwrap();
        if let Some(realm_groups) = groups.get_mut(realm) {
            let initial_len = realm_groups.len();
            realm_groups.retain(|g| g.id.as_ref().map(|id| id.as_str()) != Some(group_id));
            
            if realm_groups.len() < initial_len {
                Ok(())
            } else {
                Err(DomainError::GroupNotFound {
                    group_id: group_id.to_string(),
                    realm: realm.to_string(),
                })
            }
        } else {
            Err(DomainError::RealmNotFound {
                realm: realm.to_string(),
            })
        }
    }

    // Missing methods from KeycloakRepository trait
    async fn list_realms_with_filter(&self, _filter: &RealmFilter) -> DomainResult<Vec<Realm>> {
        self.check_should_fail()?;
        let realms = self.realms.lock().unwrap();
        Ok(realms.clone())
    }

    async fn find_group_by_path(&self, realm: &str, path: &str) -> DomainResult<Option<Group>> {
        self.check_should_fail()?;
        
        let groups = self.groups.lock().unwrap();
        if let Some(realm_groups) = groups.get(realm) {
            for group in realm_groups {
                if group.path == path {
                    return Ok(Some(group.clone()));
                }
            }
        }
        
        Ok(None)
    }

    async fn find_realm_role_by_name(&self, _realm: &str, _role_name: &str) -> DomainResult<Role> {
        self.check_should_fail()?;
        Err(DomainError::RoleNotFound {
            role_name: _role_name.to_string(),
            realm: _realm.to_string(),
        })
    }

    async fn find_client_role_by_name(&self, _realm: &str, _client_id: &str, _role_name: &str) -> DomainResult<Role> {
        self.check_should_fail()?;
        Err(DomainError::RoleNotFound {
            role_name: _role_name.to_string(),
            realm: _realm.to_string(),
        })
    }

    async fn create_realm_role(&self, _realm: &str, _role: &Role) -> DomainResult<EntityId> {
        self.check_should_fail()?;
        Ok(EntityId::new())
    }

    async fn create_client_role(&self, _realm: &str, _client_id: &str, _role: &Role) -> DomainResult<EntityId> {
        self.check_should_fail()?;
        Ok(EntityId::new())
    }

    async fn update_realm_role(&self, _realm: &str, _role: &Role) -> DomainResult<()> {
        self.check_should_fail()?;
        Ok(())
    }

    async fn update_client_role(&self, _realm: &str, _client_id: &str, _role: &Role) -> DomainResult<()> {
        self.check_should_fail()?;
        Ok(())
    }

    async fn delete_client_role(&self, _realm: &str, _client_id: &str, _role_name: &str) -> DomainResult<()> {
        self.check_should_fail()?;
        Ok(())
    }

    async fn add_user_realm_roles(&self, _realm: &str, _user_id: &str, _roles: &[String]) -> DomainResult<()> {
        self.check_should_fail()?;
        Ok(())
    }

    async fn remove_user_realm_roles(&self, _realm: &str, _user_id: &str, _roles: &[String]) -> DomainResult<()> {
        self.check_should_fail()?;
        Ok(())
    }

    async fn add_user_client_roles(&self, _realm: &str, _user_id: &str, _client_id: &str, _roles: &[String]) -> DomainResult<()> {
        self.check_should_fail()?;
        Ok(())
    }

    async fn remove_user_client_roles(&self, _realm: &str, _user_id: &str, _client_id: &str, _roles: &[String]) -> DomainResult<()> {
        self.check_should_fail()?;
        Ok(())
    }

    async fn get_group_role_mappings(&self, _realm: &str, _group_id: &str) -> DomainResult<RoleMapping> {
        self.check_should_fail()?;
        Ok(RoleMapping {
            realm_mappings: vec![],
            client_mappings: std::collections::HashMap::new(),
        })
    }

    async fn add_group_realm_roles(&self, _realm: &str, _group_id: &str, _roles: &[String]) -> DomainResult<()> {
        self.check_should_fail()?;
        Ok(())
    }

    async fn remove_group_realm_roles(&self, _realm: &str, _group_id: &str, _roles: &[String]) -> DomainResult<()> {
        self.check_should_fail()?;
        Ok(())
    }

    async fn add_group_client_roles(&self, _realm: &str, _group_id: &str, _client_id: &str, _roles: &[String]) -> DomainResult<()> {
        self.check_should_fail()?;
        Ok(())
    }

    async fn remove_group_client_roles(&self, _realm: &str, _group_id: &str, _client_id: &str, _roles: &[String]) -> DomainResult<()> {
        self.check_should_fail()?;
        Ok(())
    }

    async fn get_user_sessions(&self, _realm: &str, _user_id: &str) -> DomainResult<Vec<UserSession>> {
        self.check_should_fail()?;
        Ok(vec![])
    }

    async fn logout_user(&self, _realm: &str, _user_id: &str) -> DomainResult<()> {
        self.check_should_fail()?;
        Ok(())
    }

    async fn logout_all_sessions(&self, _realm: &str) -> DomainResult<()> {
        self.check_should_fail()?;
        Ok(())
    }

    async fn delete_session(&self, _realm: &str, _session_id: &str) -> DomainResult<()> {
        self.check_should_fail()?;
        Ok(())
    }

    async fn get_user_federated_identities(&self, _realm: &str, _user_id: &str) -> DomainResult<Vec<FederatedIdentity>> {
        self.check_should_fail()?;
        Ok(vec![])
    }

    async fn add_user_federated_identity(&self, _realm: &str, _user_id: &str, _provider: &str, _identity: &FederatedIdentity) -> DomainResult<()> {
        self.check_should_fail()?;
        Ok(())
    }

    async fn remove_user_federated_identity(&self, _realm: &str, _user_id: &str, _provider: &str) -> DomainResult<()> {
        self.check_should_fail()?;
        Ok(())
    }
}

/// Mock event publisher for testing
pub struct MockEventPublisher {
    pub published_events: Arc<Mutex<Vec<DomainEvent>>>,
    pub should_fail: Arc<Mutex<bool>>,
}

impl MockEventPublisher {
    pub fn new() -> Self {
        Self {
            published_events: Arc::new(Mutex::new(Vec::new())),
            should_fail: Arc::new(Mutex::new(false)),
        }
    }
    
    pub fn set_should_fail(&self, should_fail: bool) {
        *self.should_fail.lock().unwrap() = should_fail;
    }
    
    pub fn get_published_events(&self) -> Vec<DomainEvent> {
        self.published_events.lock().unwrap().clone()
    }
    
    pub fn clear_events(&self) {
        self.published_events.lock().unwrap().clear();
    }
}

#[async_trait]
impl EventPublisher for MockEventPublisher {
    async fn publish(&self, event: DomainEvent) -> Result<(), EventError> {
        if *self.should_fail.lock().unwrap() {
            return Err(EventError::PublishFailed {
                message: "Mock failure enabled".to_string(),
            });
        }
        
        self.published_events.lock().unwrap().push(event);
        Ok(())
    }

    async fn publish_batch(&self, events: Vec<DomainEvent>) -> Result<(), EventError> {
        if *self.should_fail.lock().unwrap() {
            return Err(EventError::PublishFailed {
                message: "Mock failure enabled".to_string(),
            });
        }
        
        self.published_events.lock().unwrap().extend(events);
        Ok(())
    }

    async fn flush(&self) -> Result<(), EventError> {
        if *self.should_fail.lock().unwrap() {
            return Err(EventError::PublishFailed {
                message: "Mock failure enabled".to_string(),
            });
        }
        
        Ok(())
    }
}

/// Mock authorization service for testing
pub struct MockAuthorizationService {
    pub allowed_permissions: Arc<Mutex<Vec<String>>>,
    pub should_fail: Arc<Mutex<bool>>,
}

impl MockAuthorizationService {
    pub fn new() -> Self {
        Self {
            allowed_permissions: Arc::new(Mutex::new(Vec::new())),
            should_fail: Arc::new(Mutex::new(false)),
        }
    }
    
    pub fn allow_permission(&self, permission: &str) {
        self.allowed_permissions.lock().unwrap().push(permission.to_string());
    }
    
    pub fn allow_all_permissions(&self) {
        let mut perms = self.allowed_permissions.lock().unwrap();
        perms.clear();
        perms.push("*".to_string()); // Wildcard for all permissions
    }
    
    pub fn set_should_fail(&self, should_fail: bool) {
        *self.should_fail.lock().unwrap() = should_fail;
    }
}

#[async_trait]
impl AuthorizationService for MockAuthorizationService {
    async fn check_permission(
        &self,
        _context: &AuthorizationContext,
        resource: &str,
        action: &str,
    ) -> Result<bool, AuthError> {
        if *self.should_fail.lock().unwrap() {
            return Err(AuthError::InsufficientPermissions {
                action: format!("{}:{}", resource, action),
            });
        }
        
        let permissions = self.allowed_permissions.lock().unwrap();
        let required_permission = format!("{}:{}", resource, action);
        
        Ok(permissions.contains(&"*".to_string()) || permissions.contains(&required_permission))
    }
    
    async fn get_user_permissions(
        &self,
        _realm: &str,
        _user_id: &str,
    ) -> Result<Vec<Permission>, AuthError> {
        if *self.should_fail.lock().unwrap() {
            return Err(AuthError::TokenValidationFailed {
                reason: "Mock failure enabled".to_string(),
            });
        }
        
        Ok(vec![]) // Mock implementation
    }
    
    async fn has_realm_role(
        &self,
        _context: &AuthorizationContext,
        _role: &str,
    ) -> Result<bool, AuthError> {
        Ok(true) // Mock implementation
    }
    
    async fn has_client_role(
        &self,
        _context: &AuthorizationContext,
        _client_id: &str,
        _role: &str,
    ) -> Result<bool, AuthError> {
        Ok(true) // Mock implementation
    }
    
    async fn get_effective_roles(
        &self,
        _realm: &str,
        _user_id: &str,
    ) -> Result<Vec<String>, AuthError> {
        Ok(vec![]) // Mock implementation
    }
}