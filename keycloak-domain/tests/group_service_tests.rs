use std::sync::Arc;
use keycloak_domain::{
    application::{
        services::GroupManagementService,
        ports::{
            auth::AuthorizationContext,
            repository::KeycloakRepository,
        },
    },
    domain::{
        entities::{
            group::{CreateGroupRequest, UpdateGroupRequest, GroupFilter},
        },
        errors::DomainError,
    },
};
use std::collections::HashMap;

mod mocks;
use mocks::{MockKeycloakRepository, MockEventPublisher, MockAuthorizationService};

/// Helper to create a test authorization context
fn create_auth_context() -> AuthorizationContext {
    AuthorizationContext::new("test-realm".to_string())
        .with_user("test-admin".to_string())
        .with_roles(vec!["admin".to_string()])
}

/// Helper to create a valid CreateGroupRequest
fn create_valid_group_request(name: &str, path: Option<&str>) -> CreateGroupRequest {
    CreateGroupRequest {
        name: name.to_string(),
        path: path.map(|p| p.to_string()),
        parent_id: None,
        attributes: Some(HashMap::new()),
    }
}

/// Helper to create a root group request
fn create_root_group_request(name: &str) -> CreateGroupRequest {
    CreateGroupRequest {
        name: name.to_string(),
        path: Some(format!("/{}", name)),
        parent_id: None,
        attributes: Some({
            let mut attrs = HashMap::new();
            attrs.insert("description".to_string(), vec![format!("Root group {}", name)]);
            attrs
        }),
    }
}

/// Helper to create a subgroup request
fn create_subgroup_request(name: &str, parent_path: &str) -> CreateGroupRequest {
    CreateGroupRequest {
        name: name.to_string(),
        path: Some(format!("{}/{}", parent_path, name)),
        parent_id: None, // In real scenarios, this would be set to the parent's ID
        attributes: Some({
            let mut attrs = HashMap::new();
            attrs.insert("description".to_string(), vec![format!("Subgroup {}", name)]);
            attrs.insert("parent_path".to_string(), vec![parent_path.to_string()]);
            attrs
        }),
    }
}

/// Test GroupManagementService with mocks - Create Group
#[tokio::test]
async fn test_group_management_service_create_root_group() {
    // Arrange
    let repository = Arc::new(MockKeycloakRepository::new());
    let event_publisher = Arc::new(MockEventPublisher::new());
    let auth_service = Arc::new(MockAuthorizationService::new());
    
    // Allow all permissions for this test
    auth_service.allow_all_permissions();
    
    let group_service = GroupManagementService::new(
        repository.clone(),
        event_publisher.clone(),
        auth_service.clone(),
    );
    
    let auth_context = create_auth_context();
    let create_request = create_root_group_request("Engineering");
    
    // Act
    let result = group_service.create_group("test-realm", &create_request, &auth_context).await;
    
    // Assert
    assert!(result.is_ok(), "Root group creation should succeed");
    let group_id = result.unwrap();
    assert!(!group_id.as_str().is_empty(), "Group ID should not be empty");
    
    // Verify event was published
    let events = event_publisher.get_published_events();
    assert_eq!(events.len(), 1, "Should have published one event");
    
    println!("✅ Root group creation test passed");
}

#[tokio::test]
async fn test_group_management_service_create_subgroup() {
    // Arrange
    let repository = Arc::new(MockKeycloakRepository::new());
    let event_publisher = Arc::new(MockEventPublisher::new());
    let auth_service = Arc::new(MockAuthorizationService::new());
    
    auth_service.allow_all_permissions();
    
    let group_service = GroupManagementService::new(
        repository.clone(),
        event_publisher.clone(),
        auth_service.clone(),
    );
    
    let auth_context = create_auth_context();
    
    // First create a parent group
    let parent_request = create_root_group_request("Engineering");
    let _parent_id = group_service.create_group("test-realm", &parent_request, &auth_context).await.unwrap();
    
    // Now create a subgroup
    let subgroup_request = create_subgroup_request("Backend", "/Engineering");
    
    // Act
    let result = group_service.create_group("test-realm", &subgroup_request, &auth_context).await;
    
    // Assert
    assert!(result.is_ok(), "Subgroup creation should succeed");
    let subgroup_id = result.unwrap();
    assert!(!subgroup_id.as_str().is_empty(), "Subgroup ID should not be empty");
    
    // Verify events were published (parent + child)
    let events = event_publisher.get_published_events();
    assert_eq!(events.len(), 2, "Should have published two events");
    
    println!("✅ Subgroup creation test passed");
}

#[tokio::test]
async fn test_group_management_service_create_nested_hierarchy() {
    // Arrange
    let repository = Arc::new(MockKeycloakRepository::new());
    let event_publisher = Arc::new(MockEventPublisher::new());
    let auth_service = Arc::new(MockAuthorizationService::new());
    
    auth_service.allow_all_permissions();
    
    let group_service = GroupManagementService::new(
        repository.clone(),
        event_publisher.clone(),
        auth_service.clone(),
    );
    
    let auth_context = create_auth_context();
    
    // Create nested hierarchy: Engineering -> Backend -> Core
    let root_request = create_root_group_request("Engineering");
    let _root_id = group_service.create_group("test-realm", &root_request, &auth_context).await.unwrap();
    
    let backend_request = create_subgroup_request("Backend", "/Engineering");
    let _backend_id = group_service.create_group("test-realm", &backend_request, &auth_context).await.unwrap();
    
    let core_request = create_subgroup_request("Core", "/Engineering/Backend");
    
    // Act
    let result = group_service.create_group("test-realm", &core_request, &auth_context).await;
    
    // Assert
    assert!(result.is_ok(), "Nested group creation should succeed");
    let core_id = result.unwrap();
    assert!(!core_id.as_str().is_empty(), "Core group ID should not be empty");
    
    // Verify all events were published
    let events = event_publisher.get_published_events();
    assert_eq!(events.len(), 3, "Should have published three events");
    
    println!("✅ Nested group hierarchy creation test passed");
}

#[tokio::test]
async fn test_group_management_service_get_group() {
    // Arrange
    let repository = Arc::new(MockKeycloakRepository::new());
    let event_publisher = Arc::new(MockEventPublisher::new());
    let auth_service = Arc::new(MockAuthorizationService::new());
    
    auth_service.allow_all_permissions();
    
    let group_service = GroupManagementService::new(
        repository.clone(),
        event_publisher.clone(),
        auth_service.clone(),
    );
    
    let auth_context = create_auth_context();
    
    // First create a group
    let create_request = create_root_group_request("TestGroup");
    let group_id = group_service.create_group("test-realm", &create_request, &auth_context).await.unwrap();
    
    // Act
    let result = group_service.get_group("test-realm", group_id.as_str(), &auth_context).await;
    
    // Assert
    assert!(result.is_ok(), "Should be able to get group");
    let group = result.unwrap();
    assert_eq!(group.name, "TestGroup");
    
    println!("✅ Group retrieval test passed");
}

#[tokio::test]
async fn test_group_management_service_get_group_not_found() {
    // Arrange
    let repository = Arc::new(MockKeycloakRepository::new());
    let event_publisher = Arc::new(MockEventPublisher::new());
    let auth_service = Arc::new(MockAuthorizationService::new());
    
    auth_service.allow_all_permissions();
    
    let group_service = GroupManagementService::new(
        repository.clone(),
        event_publisher.clone(),
        auth_service.clone(),
    );
    
    let auth_context = create_auth_context();
    
    // Act
    let result = group_service.get_group("test-realm", "non-existent-group", &auth_context).await;
    
    // Assert
    assert!(result.is_err(), "Should fail when group doesn't exist");
    
    if let Err(DomainError::GroupNotFound { group_id, realm }) = result {
        assert_eq!(group_id, "non-existent-group");
        assert_eq!(realm, "test-realm");
    } else {
        panic!("Expected GroupNotFound error");
    }
    
    println!("✅ Group not found test passed");
}

#[tokio::test]
async fn test_group_management_service_list_groups() {
    // Arrange
    let repository = Arc::new(MockKeycloakRepository::new());
    let event_publisher = Arc::new(MockEventPublisher::new());
    let auth_service = Arc::new(MockAuthorizationService::new());
    
    auth_service.allow_all_permissions();
    
    let group_service = GroupManagementService::new(
        repository.clone(),
        event_publisher.clone(),
        auth_service.clone(),
    );
    
    let auth_context = create_auth_context();
    
    // Create multiple groups
    let _group1 = group_service.create_group("test-realm", &create_root_group_request("Group1"), &auth_context).await.unwrap();
    let _group2 = group_service.create_group("test-realm", &create_root_group_request("Group2"), &auth_context).await.unwrap();
    
    let filter = GroupFilter::new();
    
    // Act
    let result = group_service.list_groups("test-realm", &filter, &auth_context).await;
    
    // Assert
    assert!(result.is_ok(), "Should be able to list groups");
    let groups = result.unwrap();
    assert!(groups.len() >= 2, "Should have at least 2 groups");
    
    println!("✅ Group listing test passed");
}

#[tokio::test]
async fn test_group_management_service_update_group() {
    // Arrange
    let repository = Arc::new(MockKeycloakRepository::new());
    let event_publisher = Arc::new(MockEventPublisher::new());
    let auth_service = Arc::new(MockAuthorizationService::new());
    
    auth_service.allow_all_permissions();
    
    let group_service = GroupManagementService::new(
        repository.clone(),
        event_publisher.clone(),
        auth_service.clone(),
    );
    
    let auth_context = create_auth_context();
    
    // Create a group first
    let create_request = create_root_group_request("OriginalGroup");
    let group_id = group_service.create_group("test-realm", &create_request, &auth_context).await.unwrap();
    
    let mut update_attributes = HashMap::new();
    update_attributes.insert("description".to_string(), vec!["Updated description".to_string()]);
    update_attributes.insert("department".to_string(), vec!["Engineering".to_string()]);
    
    let update_request = UpdateGroupRequest {
        name: Some("UpdatedGroup".to_string()),
        attributes: Some(update_attributes),
    };
    
    // Act
    let result = group_service.update_group("test-realm", group_id.as_str(), &update_request, &auth_context).await;
    
    // Assert
    assert!(result.is_ok(), "Group update should succeed");
    
    // Verify the update
    let updated_group = group_service.get_group("test-realm", group_id.as_str(), &auth_context).await.unwrap();
    assert_eq!(updated_group.name, "UpdatedGroup");
    
    // Verify events were published (create + update)
    let events = event_publisher.get_published_events();
    assert_eq!(events.len(), 2, "Should have published two events");
    
    println!("✅ Group update test passed");
}

#[tokio::test]
async fn test_group_management_service_delete_group() {
    // Arrange
    let repository = Arc::new(MockKeycloakRepository::new());
    let event_publisher = Arc::new(MockEventPublisher::new());
    let auth_service = Arc::new(MockAuthorizationService::new());
    
    auth_service.allow_all_permissions();
    
    let group_service = GroupManagementService::new(
        repository.clone(),
        event_publisher.clone(),
        auth_service.clone(),
    );
    
    let auth_context = create_auth_context();
    
    // First create a group to delete
    let create_request = create_root_group_request("DeletableGroup");
    let group_id = group_service.create_group("test-realm", &create_request, &auth_context).await.unwrap();
    
    // Verify group exists
    assert!(group_service.get_group("test-realm", group_id.as_str(), &auth_context).await.is_ok());
    
    // Act - Delete the group
    let result = group_service.delete_group("test-realm", group_id.as_str(), &auth_context).await;
    
    // Assert
    assert!(result.is_ok(), "Group deletion should succeed");
    
    // Verify group is deleted
    let get_result = group_service.get_group("test-realm", group_id.as_str(), &auth_context).await;
    assert!(get_result.is_err(), "Should not be able to get deleted group");
    
    if let Err(DomainError::GroupNotFound { group_id: deleted_id, realm }) = get_result {
        assert_eq!(deleted_id, group_id.as_str());
        assert_eq!(realm, "test-realm");
    } else {
        panic!("Expected GroupNotFound error");
    }
    
    // Verify events were published (create + delete)
    let events = event_publisher.get_published_events();
    assert_eq!(events.len(), 2, "Should have published two events");
    
    println!("✅ Group deletion test passed");
}

#[tokio::test]
async fn test_group_management_service_add_user_to_group() {
    // Arrange
    let repository = Arc::new(MockKeycloakRepository::new());
    let event_publisher = Arc::new(MockEventPublisher::new());
    let auth_service = Arc::new(MockAuthorizationService::new());
    
    auth_service.allow_all_permissions();
    
    let group_service = GroupManagementService::new(
        repository.clone(),
        event_publisher.clone(),
        auth_service.clone(),
    );
    
    let auth_context = create_auth_context();
    
    // Create a group first
    let create_request = create_root_group_request("TestGroup");
    let group_id = group_service.create_group("test-realm", &create_request, &auth_context).await.unwrap();
    
    // Act
    let result = group_service.add_user_to_group("test-realm", "test-user-id", group_id.as_str(), &auth_context).await;
    
    // Assert
    assert!(result.is_ok(), "Adding user to group should succeed");
    
    // Verify events were published (group creation + user addition)
    let events = event_publisher.get_published_events();
    assert_eq!(events.len(), 2, "Should have published two events");
    
    println!("✅ Add user to group test passed");
}

#[tokio::test]
async fn test_group_management_service_remove_user_from_group() {
    // Arrange
    let repository = Arc::new(MockKeycloakRepository::new());
    let event_publisher = Arc::new(MockEventPublisher::new());
    let auth_service = Arc::new(MockAuthorizationService::new());
    
    auth_service.allow_all_permissions();
    
    let group_service = GroupManagementService::new(
        repository.clone(),
        event_publisher.clone(),
        auth_service.clone(),
    );
    
    let auth_context = create_auth_context();
    
    // Create a group and add a user
    let create_request = create_root_group_request("TestGroup");
    let group_id = group_service.create_group("test-realm", &create_request, &auth_context).await.unwrap();
    let _add_result = group_service.add_user_to_group("test-realm", "test-user-id", group_id.as_str(), &auth_context).await.unwrap();
    
    // Act
    let result = group_service.remove_user_from_group("test-realm", "test-user-id", group_id.as_str(), &auth_context).await;
    
    // Assert
    assert!(result.is_ok(), "Removing user from group should succeed");
    
    // Verify events were published (group creation + user addition + user removal)
    let events = event_publisher.get_published_events();
    assert_eq!(events.len(), 3, "Should have published three events");
    
    println!("✅ Remove user from group test passed");
}

#[tokio::test]
async fn test_group_management_service_authorization_failure() {
    // Arrange
    let repository = Arc::new(MockKeycloakRepository::new());
    let event_publisher = Arc::new(MockEventPublisher::new());
    let auth_service = Arc::new(MockAuthorizationService::new());
    
    // Set authorization to fail
    auth_service.set_should_fail(true);
    
    let group_service = GroupManagementService::new(
        repository.clone(),
        event_publisher.clone(),
        auth_service.clone(),
    );
    
    let auth_context = create_auth_context();
    let create_request = create_root_group_request("AuthTestGroup");
    
    // Act
    let result = group_service.create_group("test-realm", &create_request, &auth_context).await;
    
    // Assert
    assert!(result.is_err(), "Should fail due to authorization");
    
    if let Err(DomainError::AuthorizationFailed { user_id, permission }) = result {
        assert_eq!(user_id, "test-admin");
        assert_eq!(permission, "groups:create");
    } else {
        panic!("Expected AuthorizationFailed error");
    }
    
    println!("✅ Group authorization failure test passed");
}

#[tokio::test]
async fn test_group_management_service_repository_failure() {
    // Arrange
    let repository = Arc::new(MockKeycloakRepository::new());
    let event_publisher = Arc::new(MockEventPublisher::new());
    let auth_service = Arc::new(MockAuthorizationService::new());
    
    auth_service.allow_all_permissions();
    repository.set_should_fail(true); // Enable mock failure
    
    let group_service = GroupManagementService::new(
        repository.clone(),
        event_publisher.clone(),
        auth_service.clone(),
    );
    
    let auth_context = create_auth_context();
    let create_request = create_root_group_request("RepoFailGroup");
    
    // Act
    let result = group_service.create_group("test-realm", &create_request, &auth_context).await;
    
    // Assert
    assert!(result.is_err(), "Should fail due to repository failure");
    
    if let Err(DomainError::ExternalService { service, message }) = result {
        assert_eq!(service, "mock-keycloak");
        assert_eq!(message, "Mock failure enabled");
    } else {
        panic!("Expected ExternalService error");
    }
    
    println!("✅ Group repository failure test passed");
}

#[tokio::test]
async fn test_group_management_service_event_publisher_failure() {
    // Arrange
    let repository = Arc::new(MockKeycloakRepository::new());
    let event_publisher = Arc::new(MockEventPublisher::new());
    let auth_service = Arc::new(MockAuthorizationService::new());
    
    auth_service.allow_all_permissions();
    event_publisher.set_should_fail(true); // Enable event publisher failure
    
    let group_service = GroupManagementService::new(
        repository.clone(),
        event_publisher.clone(),
        auth_service.clone(),
    );
    
    let auth_context = create_auth_context();
    let create_request = create_root_group_request("EventFailGroup");
    
    // Act
    let result = group_service.create_group("test-realm", &create_request, &auth_context).await;
    
    // Assert - The operation should succeed even if event publishing fails
    assert!(result.is_ok(), "Main operation should succeed even if event publishing fails");
    
    let group_id = result.unwrap();
    assert!(!group_id.as_str().is_empty(), "Group ID should be returned");
    
    println!("✅ Group event publisher failure test passed (operation succeeds, event fails)");
}

#[tokio::test]
async fn test_group_management_service_validation_errors() {
    // Arrange
    let repository = Arc::new(MockKeycloakRepository::new());
    let event_publisher = Arc::new(MockEventPublisher::new());
    let auth_service = Arc::new(MockAuthorizationService::new());
    
    auth_service.allow_all_permissions();
    
    let group_service = GroupManagementService::new(
        repository.clone(),
        event_publisher.clone(),
        auth_service.clone(),
    );
    
    let auth_context = create_auth_context();
    
    // Test with invalid group name (empty)
    let invalid_request = CreateGroupRequest {
        name: "".to_string(), // Invalid empty group name
        path: Some("/empty".to_string()),
        parent_id: None,
        attributes: Some(HashMap::new()),
    };
    
    // Act
    let result = group_service.create_group("test-realm", &invalid_request, &auth_context).await;
    
    // Assert
    assert!(result.is_err(), "Should fail due to validation error");
    
    // The exact error type might vary based on domain validation logic
    match result {
        Err(DomainError::Validation { field, message }) => {
            println!("✅ Validation error caught: {} - {}", field, message);
        },
        Err(other) => {
            println!("✅ Other domain error caught (acceptable): {:?}", other);
        },
        Ok(_) => panic!("Expected validation error"),
    }
    
    println!("✅ Group validation error test passed");
}