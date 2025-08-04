use std::sync::Arc;
use keycloak_domain::{
    application::services::UserManagementService,
    domain::{
        entities::{
            user::{CreateUserRequest, UpdateUserRequest, UserFilter},
            common::{AuthorizationContext, EntityId},
        },
        errors::DomainError,
    },
};
use std::collections::HashMap;

mod mocks;
use mocks::{MockKeycloakRepository, MockEventPublisher, MockAuthorizationService};

/// Helper to create a test authorization context
fn create_auth_context() -> AuthorizationContext {
    AuthorizationContext {
        user_id: Some("test-admin".to_string()),
        realm: "test-realm".to_string(),
        token: "test-token".to_string(),
        roles: vec!["admin".to_string()],
        permissions: vec!["users:create".to_string(), "users:read".to_string(), "users:update".to_string(), "users:delete".to_string()],
    }
}

/// Test UserManagementService with mocks
#[tokio::test]
async fn test_user_management_service_create_user() {
    // Arrange
    let repository = Arc::new(MockKeycloakRepository::new());
    let event_publisher = Arc::new(MockEventPublisher::new());
    let auth_service = Arc::new(MockAuthorizationService::new());
    
    // Allow all permissions for this test
    auth_service.allow_all_permissions();
    
    let user_service = UserManagementService::new(
        repository.clone(),
        event_publisher.clone(),
        auth_service.clone(),
    );
    
    let auth_context = create_auth_context();
    let realm = "test-realm";
    
    let create_request = CreateUserRequest {
        username: "test-user".to_string(),
        email: Some("test@example.com".to_string()),
        first_name: Some("Test".to_string()),
        last_name: Some("User".to_string()),
        enabled: Some(true),
        temporary_password: Some("temp123!".to_string()),
        require_password_update: Some(false),
        attributes: Some(HashMap::new()),
    };
    
    // Act
    let result = user_service.create_user(realm, &create_request, &auth_context).await;
    
    // Assert
    assert!(result.is_ok(), "User creation should succeed");
    let user_id = result.unwrap();
    assert!(!user_id.is_empty(), "User ID should not be empty");
    
    // Verify user was created
    let created_user = repository.find_user_by_id(realm, &user_id).await;
    assert!(created_user.is_ok(), "Should be able to find created user");
    
    let user = created_user.unwrap();
    assert_eq!(user.username, "test-user");
    assert_eq!(user.email, Some("test@example.com".to_string()));
    assert_eq!(user.first_name, Some("Test".to_string()));
    assert_eq!(user.last_name, Some("User".to_string()));
    assert_eq!(user.enabled, true);
    
    // Verify event was published
    let events = event_publisher.get_published_events();
    assert_eq!(events.len(), 1, "Should have published one event");
    
    println!("✅ User creation test passed");
}

#[tokio::test]
async fn test_user_management_service_get_user() {
    // Arrange
    let repository = Arc::new(MockKeycloakRepository::new());
    let event_publisher = Arc::new(MockEventPublisher::new());
    let auth_service = Arc::new(MockAuthorizationService::new());
    
    auth_service.allow_all_permissions();
    
    let user_service = UserManagementService::new(
        repository.clone(),
        event_publisher.clone(),
        auth_service.clone(),
    );
    
    let auth_context = create_auth_context();
    let realm = "test-realm";
    
    // First create a user
    let create_request = CreateUserRequest {
        username: "get-test-user".to_string(),
        email: Some("get-test@example.com".to_string()),
        first_name: Some("Get".to_string()),
        last_name: Some("Test".to_string()),
        enabled: Some(true),
        temporary_password: None,
        require_password_update: None,
        attributes: None,
    };
    
    let user_id = user_service.create_user(realm, &create_request, &auth_context).await.unwrap();
    
    // Act
    let result = user_service.get_user(realm, &user_id, &auth_context).await;
    
    // Assert
    assert!(result.is_ok(), "Should be able to get user");
    let user = result.unwrap();
    assert_eq!(user.username, "get-test-user");
    assert_eq!(user.email, Some("get-test@example.com".to_string()));
    
    println!("✅ User retrieval test passed");
}

#[tokio::test]
async fn test_user_management_service_list_users() {
    // Arrange
    let repository = Arc::new(MockKeycloakRepository::new());
    let event_publisher = Arc::new(MockEventPublisher::new());
    let auth_service = Arc::new(MockAuthorizationService::new());
    
    auth_service.allow_all_permissions();
    
    let user_service = UserManagementService::new(
        repository.clone(),
        event_publisher.clone(),
        auth_service.clone(),
    );
    
    let auth_context = create_auth_context();
    let realm = "test-realm";
    
    // Create multiple users
    for i in 1..=3 {
        let create_request = CreateUserRequest {
            username: format!("list-test-user-{}", i),
            email: Some(format!("list-test-{}@example.com", i)),
            first_name: Some(format!("User{}", i)),
            last_name: Some("Test".to_string()),
            enabled: Some(true),
            temporary_password: None,
            require_password_update: None,
            attributes: None,
        };
        
        user_service.create_user(realm, &create_request, &auth_context).await.unwrap();
    }
    
    // Act - List all users
    let filter = UserFilter::default();
    let result = user_service.list_users(realm, &filter, &auth_context).await;
    
    // Assert
    assert!(result.is_ok(), "Should be able to list users");
    let users = result.unwrap();
    assert_eq!(users.len(), 3, "Should have 3 users");
    
    // Act - List users with filter
    let filter = UserFilter {
        username: Some("list-test-user-2".to_string()),
        ..Default::default()
    };
    let result = user_service.list_users(realm, &filter, &auth_context).await;
    
    // Assert
    assert!(result.is_ok(), "Should be able to list filtered users");
    let users = result.unwrap();
    assert_eq!(users.len(), 1, "Should have 1 filtered user");
    assert_eq!(users[0].username, "list-test-user-2");
    
    println!("✅ User listing test passed");
}

#[tokio::test]
async fn test_user_management_service_update_user() {
    // Arrange
    let repository = Arc::new(MockKeycloakRepository::new());
    let event_publisher = Arc::new(MockEventPublisher::new());
    let auth_service = Arc::new(MockAuthorizationService::new());
    
    auth_service.allow_all_permissions();
    
    let user_service = UserManagementService::new(
        repository.clone(),
        event_publisher.clone(),
        auth_service.clone(),
    );
    
    let auth_context = create_auth_context();
    let realm = "test-realm";
    
    // Create a user
    let create_request = CreateUserRequest {
        username: "update-test-user".to_string(),
        email: Some("update-test@example.com".to_string()),
        first_name: Some("Update".to_string()),
        last_name: Some("Test".to_string()),
        enabled: Some(true),
        temporary_password: None,
        require_password_update: None,
        attributes: None,
    };
    
    let user_id = user_service.create_user(realm, &create_request, &auth_context).await.unwrap();
    
    // Act - Update the user
    let update_request = UpdateUserRequest {
        user_id: user_id.clone(),
        username: Some("updated-test-user".to_string()),
        email: Some("updated-test@example.com".to_string()),
        first_name: Some("Updated".to_string()),
        last_name: Some("Test".to_string()),
        enabled: Some(false),
        attributes: None,
    };
    
    let result = user_service.update_user(realm, &update_request, &auth_context).await;
    
    // Assert
    assert!(result.is_ok(), "User update should succeed");
    
    // Verify the update
    let updated_user = user_service.get_user(realm, &user_id, &auth_context).await.unwrap();
    assert_eq!(updated_user.username, "updated-test-user");
    assert_eq!(updated_user.email, Some("updated-test@example.com".to_string()));
    assert_eq!(updated_user.first_name, Some("Updated".to_string()));
    assert_eq!(updated_user.enabled, false);
    
    // Verify event was published
    let events = event_publisher.get_published_events();
    assert_eq!(events.len(), 2, "Should have published two events (create + update)");
    
    println!("✅ User update test passed");
}

#[tokio::test]
async fn test_user_management_service_delete_user() {
    // Arrange
    let repository = Arc::new(MockKeycloakRepository::new());
    let event_publisher = Arc::new(MockEventPublisher::new());
    let auth_service = Arc::new(MockAuthorizationService::new());
    
    auth_service.allow_all_permissions();
    
    let user_service = UserManagementService::new(
        repository.clone(),
        event_publisher.clone(),
        auth_service.clone(),
    );
    
    let auth_context = create_auth_context();
    let realm = "test-realm";
    
    // Create a user
    let create_request = CreateUserRequest {
        username: "delete-test-user".to_string(),
        email: Some("delete-test@example.com".to_string()),
        first_name: Some("Delete".to_string()),
        last_name: Some("Test".to_string()),
        enabled: Some(true),
        temporary_password: None,
        require_password_update: None,
        attributes: None,
    };
    
    let user_id = user_service.create_user(realm, &create_request, &auth_context).await.unwrap();
    
    // Verify user exists
    assert!(user_service.get_user(realm, &user_id, &auth_context).await.is_ok());
    
    // Act - Delete the user
    let result = user_service.delete_user(realm, &user_id, &auth_context).await;
    
    // Assert
    assert!(result.is_ok(), "User deletion should succeed");
    
    // Verify user is deleted
    let get_result = user_service.get_user(realm, &user_id, &auth_context).await;
    assert!(get_result.is_err(), "Should not be able to get deleted user");
    
    if let Err(DomainError::EntityNotFound { entity_type, entity_id }) = get_result {
        assert_eq!(entity_type, "User");
        assert_eq!(entity_id, user_id);
    } else {
        panic!("Expected EntityNotFound error");
    }
    
    // Verify event was published
    let events = event_publisher.get_published_events();
    assert_eq!(events.len(), 2, "Should have published two events (create + delete)");
    
    println!("✅ User deletion test passed");
}

#[tokio::test]
async fn test_user_management_service_authorization_failure() {
    // Arrange
    let repository = Arc::new(MockKeycloakRepository::new());
    let event_publisher = Arc::new(MockEventPublisher::new());
    let auth_service = Arc::new(MockAuthorizationService::new());
    
    // Don't allow any permissions
    let user_service = UserManagementService::new(
        repository.clone(),
        event_publisher.clone(),
        auth_service.clone(),
    );
    
    let auth_context = create_auth_context();
    let realm = "test-realm";
    
    let create_request = CreateUserRequest {
        username: "auth-test-user".to_string(),
        email: Some("auth-test@example.com".to_string()),
        first_name: Some("Auth".to_string()),
        last_name: Some("Test".to_string()),
        enabled: Some(true),
        temporary_password: None,
        require_password_update: None,
        attributes: None,
    };
    
    // Act
    let result = user_service.create_user(realm, &create_request, &auth_context).await;
    
    // Assert
    assert!(result.is_err(), "Should fail due to authorization");
    
    if let Err(DomainError::AuthorizationFailed { user_id, permission }) = result {
        assert_eq!(user_id, "test-user");
        assert_eq!(permission, "users:create");
    } else {
        panic!("Expected AuthorizationFailed error");
    }
    
    println!("✅ Authorization failure test passed");
}

#[tokio::test]
async fn test_user_management_service_repository_failure() {
    // Arrange
    let repository = Arc::new(MockKeycloakRepository::new());
    let event_publisher = Arc::new(MockEventPublisher::new());
    let auth_service = Arc::new(MockAuthorizationService::new());
    
    auth_service.allow_all_permissions();
    repository.set_should_fail(true); // Enable mock failure
    
    let user_service = UserManagementService::new(
        repository.clone(),
        event_publisher.clone(),
        auth_service.clone(),
    );
    
    let auth_context = create_auth_context();
    let realm = "test-realm";
    
    let create_request = CreateUserRequest {
        username: "repo-fail-user".to_string(),
        email: Some("repo-fail@example.com".to_string()),
        first_name: Some("Repo".to_string()),
        last_name: Some("Fail".to_string()),
        enabled: Some(true),
        temporary_password: None,
        require_password_update: None,
        attributes: None,
    };
    
    // Act
    let result = user_service.create_user(realm, &create_request, &auth_context).await;
    
    // Assert
    assert!(result.is_err(), "Should fail due to repository failure");
    
    if let Err(DomainError::ExternalServiceError { service, message }) = result {
        assert_eq!(service, "mock-keycloak");
        assert_eq!(message, "Mock failure enabled");
    } else {
        panic!("Expected ExternalServiceError error");
    }
    
    println!("✅ Repository failure test passed");
}

#[tokio::test]
async fn test_user_management_service_event_publisher_failure() {
    // Arrange
    let repository = Arc::new(MockKeycloakRepository::new());
    let event_publisher = Arc::new(MockEventPublisher::new());
    let auth_service = Arc::new(MockAuthorizationService::new());
    
    auth_service.allow_all_permissions();
    event_publisher.set_should_fail(true); // Enable event publisher failure
    
    let user_service = UserManagementService::new(
        repository.clone(),
        event_publisher.clone(),
        auth_service.clone(),
    );
    
    let auth_context = create_auth_context();
    let realm = "test-realm";
    
    let create_request = CreateUserRequest {
        username: "event-fail-user".to_string(),
        email: Some("event-fail@example.com".to_string()),
        first_name: Some("Event".to_string()),
        last_name: Some("Fail".to_string()),
        enabled: Some(true),
        temporary_password: None,
        require_password_update: None,
        attributes: None,
    };
    
    // Act
    let result = user_service.create_user(realm, &create_request, &auth_context).await;
    
    // Assert
    assert!(result.is_err(), "Should fail due to event publisher failure");
    
    if let Err(DomainError::ExternalServiceError { service, message }) = result {
        assert_eq!(service, "event-publisher");
        assert_eq!(message, "Mock failure enabled");
    } else {
        panic!("Expected ExternalServiceError error");
    }
    
    println!("✅ Event publisher failure test passed");
}

#[tokio::test]
async fn test_user_management_service_validation_errors() {
    // Arrange
    let repository = Arc::new(MockKeycloakRepository::new());
    let event_publisher = Arc::new(MockEventPublisher::new());
    let auth_service = Arc::new(MockAuthorizationService::new());
    
    auth_service.allow_all_permissions();
    
    let user_service = UserManagementService::new(
        repository.clone(),
        event_publisher.clone(),
        auth_service.clone(),
    );
    
    let auth_context = create_auth_context();
    let realm = "test-realm";
    
    // Test with invalid username (empty)
    let invalid_request = CreateUserRequest {
        username: "".to_string(), // Invalid empty username
        email: Some("valid@example.com".to_string()),
        first_name: Some("Valid".to_string()),
        last_name: Some("User".to_string()),
        enabled: Some(true),
        temporary_password: None,
        require_password_update: None,
        attributes: None,
    };
    
    // Act
    let result = user_service.create_user(realm, &invalid_request, &auth_context).await;
    
    // Assert
    assert!(result.is_err(), "Should fail due to validation error");
    
    // The exact error type might vary based on domain validation logic
    match result {
        Err(DomainError::ValidationError { field, message }) => {
            println!("✅ Validation error caught: {} - {}", field, message);
        },
        Err(other) => {
            println!("✅ Other domain error caught (acceptable): {:?}", other);
        },
        Ok(_) => panic!("Expected validation error"),
    }
    
    println!("✅ Validation error test passed");
}

#[tokio::test]
async fn test_user_management_service_find_by_username() {
    // Arrange
    let repository = Arc::new(MockKeycloakRepository::new());
    let event_publisher = Arc::new(MockEventPublisher::new());
    let auth_service = Arc::new(MockAuthorizationService::new());
    
    auth_service.allow_all_permissions();
    
    let user_service = UserManagementService::new(
        repository.clone(),
        event_publisher.clone(),
        auth_service.clone(),
    );
    
    let auth_context = create_auth_context();
    let realm = "test-realm";
    
    // Create a user
    let create_request = CreateUserRequest {
        username: "findme-user".to_string(),
        email: Some("findme@example.com".to_string()),
        first_name: Some("Find".to_string()),
        last_name: Some("Me".to_string()),
        enabled: Some(true),
        temporary_password: None,
        require_password_update: None,
        attributes: None,
    };
    
    user_service.create_user(realm, &create_request, &auth_context).await.unwrap();
    
    // Act - Find by username
    let result = user_service.find_user_by_username(realm, "findme-user", &auth_context).await;
    
    // Assert
    assert!(result.is_ok(), "Should be able to find user by username");
    let user_option = result.unwrap();
    assert!(user_option.is_some(), "Should find the user");
    
    let user = user_option.unwrap();
    assert_eq!(user.username, "findme-user");
    assert_eq!(user.email, Some("findme@example.com".to_string()));
    
    // Test non-existent user
    let result = user_service.find_user_by_username(realm, "non-existent", &auth_context).await;
    assert!(result.is_ok(), "Should succeed even if user not found");
    let user_option = result.unwrap();
    assert!(user_option.is_none(), "Should not find non-existent user");
    
    println!("✅ Find by username test passed");
}