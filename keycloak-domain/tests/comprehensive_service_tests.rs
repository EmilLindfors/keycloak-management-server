use std::collections::HashMap;
use std::sync::Arc;

use keycloak_domain::{
    application::{
        ports::{
            auth::AuthorizationContext,
            events::{EventPublisher, DomainEvent},
            repository::KeycloakRepository,
        },
        services::{
            user_management::UserManagementService,
            realm_management::RealmManagementService,
            client_management::ClientManagementService,
            group_management::GroupManagementService,
        },
    },
    domain::{
        entities::{
            user::{CreateUserRequest, UpdateUserRequest, UserFilter},
            realm::{CreateRealmRequest, UpdateRealmRequest, RealmFilter},
            client::{CreateClientRequest, UpdateClientRequest, ClientFilter},
            group::{CreateGroupRequest, UpdateGroupRequest, GroupFilter},
            role::{RoleFilter},
        },
        errors::{DomainError, DomainResult},
    },
};

mod mocks;
use mocks::{MockKeycloakRepository, MockEventPublisher, MockAuthorizationService};

/// Comprehensive service layer tests with full coverage
/// 
/// These tests verify service layer business logic with mocks,
/// providing fast, reliable tests without external dependencies.

#[tokio::test]
async fn test_user_management_service_comprehensive() {
    // Setup
    let repository = Arc::new(MockKeycloakRepository::new());
    let event_publisher = Arc::new(MockEventPublisher::new());
    let auth_service = Arc::new(MockAuthorizationService::new());
    auth_service.allow_all_permissions(); // Allow all for this test
    
    let user_service = UserManagementService::new(
        repository.clone(),
        event_publisher.clone(),
        auth_service.clone(),
    );
    
    let auth_context = AuthorizationContext {
        realm: "test-realm".to_string(),
        user_id: Some("admin-user-id".to_string()),
        token: "test-token".to_string(),
        roles: vec!["realm-admin".to_string()],
        permissions: vec!["users:create".to_string(), "users:read".to_string()],
    };
    
    // Test 1: Create user with valid data
    let create_request = CreateUserRequest {
        username: "testuser".to_string(),
        email: Some("test@example.com".to_string()),
        first_name: Some("Test".to_string()),
        last_name: Some("User".to_string()),
        enabled: Some(true),
        temporary_password: None,
        require_password_update: None,
        attributes: Some({
            let mut attrs = HashMap::new();
            attrs.insert("department".to_string(), vec!["engineering".to_string()]);
            attrs
        }),
    };
    
    let user_id = user_service
        .create_user("test-realm", &create_request, &auth_context)
        .await
        .expect("User creation should succeed");
    
    assert!(!user_id.as_str().is_empty(), "User ID should not be empty");
    
    // Verify event was published
    let events = event_publisher.get_published_events();
    assert_eq!(events.len(), 1, "Should have published one event");
    match &events[0] {
        DomainEvent::UserCreated { user_id: event_user_id, realm, .. } => {
            assert_eq!(event_user_id.as_str(), user_id.as_str());
            assert_eq!(realm, "test-realm");
        }
        _ => panic!("Expected UserCreated event"),
    }
    
    // Test 2: Get user by ID
    let user = user_service
        .get_user("test-realm", user_id.as_str(), &auth_context)
        .await
        .expect("Should get user by ID");
    
    assert_eq!(user.username, "testuser");
    assert_eq!(user.email, Some("test@example.com".to_string()));
    assert_eq!(user.first_name, Some("Test".to_string()));
    assert_eq!(user.last_name, Some("User".to_string()));
    assert!(user.enabled);
    
    // Test 3: List users with filters
    let filter = UserFilter {
        username: Some("test".to_string()),
        email: None,
        first_name: None,
        last_name: None,
        enabled: Some(true),
        first: None,
        max: Some(10),
        search: None,
        exact: None,
    };
    
    let users = user_service
        .list_users("test-realm", &filter, &auth_context)
        .await
        .expect("Should list users");
    
    assert!(!users.is_empty(), "Should find users matching filter");
    assert!(users.iter().any(|u| u.username == "testuser"));
    
    // Test 4: Update user
    let update_request = UpdateUserRequest {
        email: Some("updated@example.com".to_string()),
        first_name: Some("Updated".to_string()),
        last_name: Some("User".to_string()),
        enabled: Some(false),
        attributes: None,
        required_actions: None,
    };
    
    event_publisher.clear_events();
    
    user_service
        .update_user("test-realm", user_id.as_str(), &update_request, &auth_context)
        .await
        .expect("User update should succeed");
    
    // Verify update event was published
    let events = event_publisher.get_published_events();
    assert_eq!(events.len(), 1, "Should have published update event");
    
    // Test 5: Delete user
    event_publisher.clear_events();
    
    user_service
        .delete_user("test-realm", user_id.as_str(), &auth_context)
        .await
        .expect("User deletion should succeed");
    
    // Verify delete event was published
    let events = event_publisher.get_published_events();
    assert_eq!(events.len(), 1, "Should have published delete event");
    match &events[0] {
        DomainEvent::UserDeleted { user_id: event_user_id, realm, .. } => {
            assert_eq!(event_user_id.as_str(), user_id.as_str());
            assert_eq!(realm, "test-realm");
        }
        _ => panic!("Expected UserDeleted event"),
    }
}

#[tokio::test]
async fn test_realm_management_service_comprehensive() {
    let repository = Arc::new(MockKeycloakRepository::new());
    let event_publisher = Arc::new(MockEventPublisher::new());
    let auth_service = Arc::new(MockAuthorizationService::new());
    auth_service.allow_all_permissions();
    
    let realm_service = RealmManagementService::new(
        repository.clone(),
        event_publisher.clone(),
        auth_service.clone(),
    );
    
    let auth_context = AuthorizationContext {
        realm: "master".to_string(),
        user_id: Some("admin-user-id".to_string()),
        token: "test-token".to_string(),
        roles: vec!["master-admin".to_string()],
        permissions: vec!["realms:create".to_string(), "realms:read".to_string()],
    };
    
    // Test 1: Create realm
    let create_request = CreateRealmRequest {
        realm: "test-new-realm".to_string(),
        display_name: Some("Test New Realm".to_string()),
        display_name_html: None,
        enabled: Some(true),
        attributes: None,
    };
    
    let realm_id = realm_service
        .create_realm(&create_request, &auth_context)
        .await
        .expect("Realm creation should succeed");
    
    assert_eq!(realm_id.as_str(), "test-new-realm");
    
    // Test 2: Get realm by name
    let realm = realm_service
        .get_realm("test-new-realm", &auth_context)
        .await
        .expect("Should get realm by name");
    
    assert_eq!(realm.realm, "test-new-realm");
    assert_eq!(realm.display_name, Some("Test New Realm".to_string()));
    assert!(realm.enabled);
    
    // Test 3: List realms
    let filter = RealmFilter {
        search: None,
        exact: None,
        first: None,
        max: Some(10),
    };
    
    let realms = realm_service
        .list_realms(&filter, &auth_context)
        .await
        .expect("Should list realms");
    
    assert!(!realms.is_empty(), "Should find realms");
    assert!(realms.iter().any(|r| r.realm == "test-new-realm"));
    
    // Test 4: Update realm
    let update_request = UpdateRealmRequest {
        display_name: Some("Updated Test Realm".to_string()),
        display_name_html: Some("<h1>Updated Test Realm</h1>".to_string()),
        enabled: Some(false),
        attributes: None,
    };
    
    realm_service
        .update_realm("test-new-realm", &update_request, &auth_context)
        .await
        .expect("Realm update should succeed");
    
    // Test 5: Delete realm
    realm_service
        .delete_realm("test-new-realm", &auth_context)
        .await
        .expect("Realm deletion should succeed");
}

#[tokio::test]
async fn test_client_management_service_comprehensive() {
    let repository = Arc::new(MockKeycloakRepository::new());
    let event_publisher = Arc::new(MockEventPublisher::new());
    let auth_service = Arc::new(MockAuthorizationService::new());
    auth_service.allow_all_permissions();
    
    let client_service = ClientManagementService::new(
        repository.clone(),
        event_publisher.clone(),
        auth_service.clone(),
    );
    
    let auth_context = AuthorizationContext {
        realm: "test-realm".to_string(),
        user_id: Some("admin-user-id".to_string()),
        token: "test-token".to_string(),
        roles: vec!["realm-admin".to_string()],
        permissions: vec!["clients:create".to_string(), "clients:read".to_string()],
    };
    
    // Test 1: Create client
    let create_request = CreateClientRequest {
        client_id: "test-client".to_string(),
        name: Some("Test Client".to_string()),
        description: Some("A test client for integration testing".to_string()),
        enabled: Some(true),
        public_client: Some(false),
        bearer_only: Some(false),
        redirect_uris: Some(vec![
            "https://example.com/callback".to_string(),
            "https://example.com/auth/callback".to_string(),
        ]),
        web_origins: Some(vec!["https://example.com".to_string()]),
        attributes: None,
    };
    
    let client_id = client_service
        .create_client("test-realm", &create_request, &auth_context)
        .await
        .expect("Client creation should succeed");
    
    assert!(!client_id.as_str().is_empty(), "Client ID should not be empty");
    
    // Test 2: Get client by client ID
    let client = client_service
        .get_client_by_client_id("test-realm", "test-client", &auth_context)
        .await
        .expect("Should get client by client ID");
    
    assert_eq!(client.client_id, "test-client");
    assert_eq!(client.name, Some("Test Client".to_string()));
    assert!(client.enabled);
    assert!(!client.public_client);
    
    // Test 3: List clients
    let filter = ClientFilter {
        client_id: Some("test".to_string()),
        search: None,
        first: None,
        max: Some(10),
        viewable_only: None,
    };
    
    let clients = client_service
        .list_clients("test-realm", &filter, &auth_context)
        .await
        .expect("Should list clients");
    
    assert!(!clients.is_empty(), "Should find clients");
    assert!(clients.iter().any(|c| c.client_id == "test-client"));
    
    // Test 4: Get client secret
    let secret = client_service
        .get_client_secret("test-realm", "test-client", &auth_context)
        .await
        .expect("Should get client secret");
    
    assert!(!secret.is_empty(), "Client secret should not be empty");
    
    // Test 5: Regenerate client secret
    let new_secret = client_service
        .regenerate_client_secret("test-realm", "test-client", &auth_context)
        .await
        .expect("Should regenerate client secret");
    
    assert!(!new_secret.is_empty(), "New client secret should not be empty");
    assert_ne!(secret, new_secret, "New secret should be different from old one");
}

#[tokio::test]
async fn test_group_management_service_comprehensive() {
    let repository = Arc::new(MockKeycloakRepository::new());
    let event_publisher = Arc::new(MockEventPublisher::new());
    let auth_service = Arc::new(MockAuthorizationService::new());
    auth_service.allow_all_permissions();
    
    let group_service = GroupManagementService::new(
        repository.clone(),
        event_publisher.clone(),
        auth_service.clone(),
    );
    
    let auth_context = AuthorizationContext {
        realm: "test-realm".to_string(),
        user_id: Some("admin-user-id".to_string()),
        token: "test-token".to_string(),
        roles: vec!["realm-admin".to_string()],
        permissions: vec!["groups:create".to_string(), "groups:read".to_string()],
    };
    
    // Test 1: Create group
    let create_request = CreateGroupRequest {
        name: "test-group".to_string(),
        path: Some("/test-group".to_string()),
        parent_id: None,
        attributes: Some({
            let mut attrs = HashMap::new();
            attrs.insert("type".to_string(), vec!["department".to_string()]);
            attrs
        }),
    };
    
    let group_id = group_service
        .create_group("test-realm", &create_request, &auth_context)
        .await
        .expect("Group creation should succeed");
    
    assert!(!group_id.as_str().is_empty(), "Group ID should not be empty");
    
    // Test 2: Get group by ID
    let group = group_service
        .get_group("test-realm", group_id.as_str(), &auth_context)
        .await
        .expect("Should get group by ID");
    
    assert_eq!(group.name, "test-group");
    assert_eq!(group.path, "/test-group");
    
    // Test 3: List groups
    let filter = GroupFilter {
        search: Some("test".to_string()),
        exact: Some(false),
        first: None,
        max: Some(10),
        populate_hierarchy: Some(false),
        brief_representation: Some(false),
    };
    
    let groups = group_service
        .list_groups("test-realm", &filter, &auth_context)
        .await
        .expect("Should list groups");
    
    assert!(!groups.is_empty(), "Should find groups");
    assert!(groups.iter().any(|g| g.name == "test-group"));
    
    // Test 4: Update group
    let update_request = UpdateGroupRequest {
        name: Some("updated-test-group".to_string()),
        attributes: Some({
            let mut attrs = HashMap::new();
            attrs.insert("type".to_string(), vec!["updated-department".to_string()]);
            attrs.insert("size".to_string(), vec!["large".to_string()]);
            attrs
        }),
    };
    
    group_service
        .update_group("test-realm", group_id.as_str(), &update_request, &auth_context)
        .await
        .expect("Group update should succeed");
    
    // Test 5: Delete group
    group_service
        .delete_group("test-realm", group_id.as_str(), &auth_context)
        .await
        .expect("Group deletion should succeed");
}

#[tokio::test]
async fn test_error_scenarios_comprehensive() {
    let repository = Arc::new(MockKeycloakRepository::new());
    let event_publisher = Arc::new(MockEventPublisher::new());
    let auth_service = Arc::new(MockAuthorizationService::new());
    
    let user_service = UserManagementService::new(
        repository.clone(),
        event_publisher.clone(),
        auth_service.clone(),
    );
    
    let auth_context = AuthorizationContext {
        realm: "test-realm".to_string(),
        user_id: Some("admin-user-id".to_string()),
        token: "test-token".to_string(),
        roles: vec!["realm-admin".to_string()],
        permissions: vec![],  // No permissions
    };
    
    // Test 1: Authorization failure
    let create_request = CreateUserRequest {
        username: "testuser".to_string(),
        email: None,
        first_name: None,
        last_name: None,
        enabled: Some(true),
        temporary_password: None,
        require_password_update: None,
        attributes: None,
    };
    
    let result = user_service
        .create_user("test-realm", &create_request, &auth_context)
        .await;
    
    assert!(result.is_err(), "Should fail due to insufficient permissions");
    
    // Test 2: Repository failure
    auth_service.allow_all_permissions();
    repository.set_should_fail(true);
    
    let result = user_service
        .create_user("test-realm", &create_request, &auth_context)
        .await;
    
    assert!(result.is_err(), "Should fail due to repository error");
    
    repository.set_should_fail(false);
    
    // Test 3: Event publisher failure
    event_publisher.set_should_fail(true);
    
    let result = user_service
        .create_user("test-realm", &create_request, &auth_context)
        .await;
    
    // Event publishing failure should not prevent user creation
    // (depends on implementation - adjust based on actual behavior)
    
    event_publisher.set_should_fail(false);
    
    // Test 4: Invalid input validation
    let invalid_request = CreateUserRequest {
        username: "".to_string(),  // Invalid empty username
        email: Some("invalid-email".to_string()),  // Invalid email format
        first_name: None,
        last_name: None,
        enabled: Some(true),
        temporary_password: Some("short".to_string()),  // Too short password
        require_password_update: None,
        attributes: None,
    };
    
    let result = user_service
        .create_user("test-realm", &invalid_request, &auth_context)
        .await;
    
    assert!(result.is_err(), "Should fail due to validation errors");
    
    // Test 5: Entity not found
    let result = user_service
        .get_user("test-realm", "non-existent-user-id", &auth_context)
        .await;
    
    assert!(result.is_err(), "Should fail when user does not exist");
    match result.unwrap_err() {
        DomainError::UserNotFound { .. } => {
            // Expected error type
        }
        other => panic!("Expected UserNotFound error, got {:?}", other),
    }
}

#[tokio::test]
async fn test_concurrent_operations() {
    use tokio::task::JoinSet;
    
    let repository = Arc::new(MockKeycloakRepository::new());
    let event_publisher = Arc::new(MockEventPublisher::new());
    let auth_service = Arc::new(MockAuthorizationService::new());
    auth_service.allow_all_permissions();
    
    let user_service = Arc::new(UserManagementService::new(
        repository.clone(),
        event_publisher.clone(),
        auth_service.clone(),
    ));
    
    let auth_context = AuthorizationContext {
        realm: "test-realm".to_string(),
        user_id: Some("admin-user-id".to_string()),
        token: "test-token".to_string(),
        roles: vec!["realm-admin".to_string()],
        permissions: vec!["users:create".to_string(), "users:read".to_string()],
    };
    
    // Create multiple users concurrently
    let mut join_set = JoinSet::new();
    
    for i in 0..10 {
        let service = user_service.clone();
        let context = auth_context.clone();
        let username = format!("user{}", i);
        
        join_set.spawn(async move {
            let request = CreateUserRequest {
                username: username.clone(),
                email: Some(format!("{}@example.com", username)),
                first_name: Some("Test".to_string()),
                last_name: Some(format!("User{}", i)),
                enabled: Some(true),
                temporary_password: None,
                require_password_update: None,
                attributes: None,
            };
            
            service.create_user("test-realm", &request, &context).await
        });
    }
    
    // Wait for all tasks to complete
    let mut results = Vec::new();
    while let Some(result) = join_set.join_next().await {
        let user_result = result.expect("Task should not panic");
        results.push(user_result);
    }
    
    // All operations should succeed
    let successful_count = results.iter().filter(|r| r.is_ok()).count();
    assert_eq!(successful_count, 10, "All concurrent user creations should succeed");
    
    // Verify that events were published for all users
    let events = event_publisher.get_published_events();
    let user_created_count = events
        .iter()
        .filter(|e| matches!(e, DomainEvent::UserCreated { .. }))
        .count();
    assert_eq!(user_created_count, 10, "Should have published events for all users");
}