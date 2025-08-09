use keycloak_domain::{
    application::{
        services::RoleManagementService,
        ports::auth::AuthorizationContext,
    },
    domain::{
        entities::role::{CreateRoleRequest, RoleFilter},
        errors::DomainError,
    },
};
use std::sync::Arc;

mod mocks;
use mocks::{MockKeycloakRepository, MockEventPublisher, MockAuthorizationService};

/// Helper to create a test authorization context
fn create_auth_context() -> AuthorizationContext {
    AuthorizationContext::new("test-realm".to_string())
        .with_user("test-admin".to_string())
        .with_client("admin-cli".to_string())
}

#[tokio::test]
async fn test_role_management_service_authorization_failure() {
    // Arrange
    let repository = Arc::new(MockKeycloakRepository::new());
    let event_publisher = Arc::new(MockEventPublisher::new());
    let auth_service = Arc::new(MockAuthorizationService::new());
    
    // Set authorization to fail
    auth_service.set_should_fail(true);
    
    let role_service = RoleManagementService::new(
        repository.clone(),
        event_publisher.clone(),
        auth_service.clone(),
    );
    
    let auth_context = create_auth_context();
    let filter = RoleFilter::default();
    
    // Act - Try to list roles (should fail due to authorization)
    let result = role_service.list_roles("test-realm", &filter, &auth_context).await;
    
    // Assert
    assert!(result.is_err(), "Should fail due to authorization");
    
    if let Err(DomainError::AuthorizationFailed { user_id, permission }) = result {
        assert_eq!(user_id, "test-admin");
        assert!(permission.contains("roles:view"));
        println!("✅ Authorization failure detected correctly for role listing");
    } else {
        panic!("Expected AuthorizationFailed error, got: {:?}", result);
    }

    // Test role creation authorization failure
    let create_request = CreateRoleRequest {
        name: "test-role".to_string(),
        description: Some("Test role".to_string()),
        composite: Some(false),
        client_role: Some(false),
        container_id: "test-realm".to_string(),
        attributes: None,
    };
    
    let create_result = role_service.create_role("test-realm", &create_request, &auth_context).await;
    
    assert!(create_result.is_err(), "Should fail due to authorization");
    
    if let Err(DomainError::AuthorizationFailed { user_id, permission }) = create_result {
        assert_eq!(user_id, "test-admin");
        assert!(permission.contains("roles:create"));
        println!("✅ Authorization failure detected correctly for role creation");
    } else {
        panic!("Expected AuthorizationFailed error for creation, got: {:?}", create_result);
    }
    
    println!("✅ Role authorization failure test passed");
}

#[tokio::test]
async fn test_role_management_service_successful_operations() {
    // Arrange
    let repository = Arc::new(MockKeycloakRepository::new());
    let event_publisher = Arc::new(MockEventPublisher::new());
    let auth_service = Arc::new(MockAuthorizationService::new());
    
    // Allow all permissions
    auth_service.allow_all_permissions();
    
    let role_service = RoleManagementService::new(
        repository.clone(),
        event_publisher.clone(),
        auth_service.clone(),
    );
    
    let auth_context = create_auth_context();
    let filter = RoleFilter::default();
    
    // Act - Try to list roles (should succeed)
    let result = role_service.list_roles("test-realm", &filter, &auth_context).await;
    
    // Assert
    assert!(result.is_ok(), "Should succeed with proper authorization");
    
    println!("✅ Role operations work correctly with proper authorization");
}