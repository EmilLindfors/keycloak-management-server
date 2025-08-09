use std::sync::Arc;
use keycloak_domain::{
    application::{
        services::ClientManagementService,
        ports::{
            auth::AuthorizationContext,
            repository::KeycloakRepository,
        },
    },
    domain::{
        entities::{
            client::{CreateClientRequest, UpdateClientRequest, ClientFilter},
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

/// Helper to create a valid CreateClientRequest
fn create_valid_client_request(client_id: &str) -> CreateClientRequest {
    let mut request = CreateClientRequest::new(client_id.to_string())
        .with_redirect_uris(vec![
            "https://example.com/callback".to_string(),
            "http://localhost:8080/callback".to_string(),
        ]);
    
    request.name = Some(format!("{} Client", client_id));
    request.description = Some(format!("Test client {}", client_id));
    request.enabled = Some(true);
    request.public_client = Some(false); // Confidential client by default
    request.standard_flow_enabled = Some(true);
    request.direct_access_grants_enabled = Some(true);
    
    request
}

/// Helper to create a public client request
fn create_public_client_request(client_id: &str) -> CreateClientRequest {
    let mut request = CreateClientRequest::new(client_id.to_string())
        .public_client()
        .with_redirect_uris(vec![
            "https://spa.example.com/*".to_string(),
            "http://localhost:3000/*".to_string(),
        ]);
    
    request.name = Some(format!("{} SPA", client_id));
    request.description = Some("Single Page Application".to_string());
    request.enabled = Some(true);
    request.standard_flow_enabled = Some(true);
    request.implicit_flow_enabled = Some(true);
    
    request
}

/// Helper to create a service account client request
fn create_service_account_request(client_id: &str) -> CreateClientRequest {
    let mut request = CreateClientRequest::new(client_id.to_string())
        .service_account();
    
    request.name = Some(format!("{} Service", client_id));
    request.description = Some("Service Account Client".to_string());
    request.enabled = Some(true);
    
    request
}

/// Test ClientManagementService with mocks - Create Client
#[tokio::test]
async fn test_client_management_service_create_client() {
    // Arrange
    let repository = Arc::new(MockKeycloakRepository::new());
    let event_publisher = Arc::new(MockEventPublisher::new());
    let auth_service = Arc::new(MockAuthorizationService::new());
    
    // Allow all permissions for this test
    auth_service.allow_all_permissions();
    
    let client_service = ClientManagementService::new(
        repository.clone(),
        event_publisher.clone(),
        auth_service.clone(),
    );
    
    let auth_context = create_auth_context();
    let create_request = create_valid_client_request("new-test-client");
    
    // Act
    let result = client_service.create_client("test-realm", &create_request, &auth_context).await;
    
    // Assert
    assert!(result.is_ok(), "Client creation should succeed");
    let client_id = result.unwrap();
    assert!(!client_id.as_str().is_empty(), "Client ID should not be empty");
    
    // Verify client was created
    let created_client = repository.find_client_by_client_id("test-realm", "new-test-client").await;
    assert!(created_client.is_ok(), "Should be able to find created client");
    
    if let Ok(Some(client)) = created_client {
        assert_eq!(client.client_id, "new-test-client");
        assert_eq!(client.name, Some("new-test-client Client".to_string()));
        assert_eq!(client.enabled, true);
        assert_eq!(client.public_client, false);
    }
    
    // Verify event was published
    let events = event_publisher.get_published_events();
    assert_eq!(events.len(), 1, "Should have published one event");
    
    println!("✅ Client creation test passed");
}

#[tokio::test]
async fn test_client_management_service_create_public_client() {
    // Arrange
    let repository = Arc::new(MockKeycloakRepository::new());
    let event_publisher = Arc::new(MockEventPublisher::new());
    let auth_service = Arc::new(MockAuthorizationService::new());
    
    auth_service.allow_all_permissions();
    
    let client_service = ClientManagementService::new(
        repository.clone(),
        event_publisher.clone(),
        auth_service.clone(),
    );
    
    let auth_context = create_auth_context();
    let create_request = create_public_client_request("spa-client");
    
    // Act
    let result = client_service.create_client("test-realm", &create_request, &auth_context).await;
    
    // Assert
    assert!(result.is_ok(), "Public client creation should succeed");
    
    // Verify client was created with correct settings
    let created_client = repository.find_client_by_client_id("test-realm", "spa-client").await;
    assert!(created_client.is_ok(), "Should be able to find created client");
    
    if let Ok(Some(client)) = created_client {
        assert_eq!(client.client_id, "spa-client");
        assert_eq!(client.public_client, true);
        assert_eq!(client.standard_flow_enabled, true);
        assert_eq!(client.implicit_flow_enabled, true);
        assert_eq!(client.direct_access_grants_enabled, false);
    }
    
    println!("✅ Public client creation test passed");
}

#[tokio::test]
async fn test_client_management_service_create_service_account() {
    // Arrange
    let repository = Arc::new(MockKeycloakRepository::new());
    let event_publisher = Arc::new(MockEventPublisher::new());
    let auth_service = Arc::new(MockAuthorizationService::new());
    
    auth_service.allow_all_permissions();
    
    let client_service = ClientManagementService::new(
        repository.clone(),
        event_publisher.clone(),
        auth_service.clone(),
    );
    
    let auth_context = create_auth_context();
    let create_request = create_service_account_request("service-client");
    
    // Act
    let result = client_service.create_client("test-realm", &create_request, &auth_context).await;
    
    // Assert
    assert!(result.is_ok(), "Service account client creation should succeed");
    
    // Verify client was created with correct settings
    let created_client = repository.find_client_by_client_id("test-realm", "service-client").await;
    assert!(created_client.is_ok(), "Should be able to find created client");
    
    if let Ok(Some(client)) = created_client {
        assert_eq!(client.client_id, "service-client");
        assert_eq!(client.public_client, false);
        assert_eq!(client.service_accounts_enabled, true);
        assert_eq!(client.standard_flow_enabled, false);
        assert_eq!(client.implicit_flow_enabled, false);
        assert_eq!(client.direct_access_grants_enabled, false);
    }
    
    println!("✅ Service account client creation test passed");
}

#[tokio::test]
async fn test_client_management_service_create_client_already_exists() {
    // Arrange
    let repository = Arc::new(MockKeycloakRepository::new());
    let event_publisher = Arc::new(MockEventPublisher::new());
    let auth_service = Arc::new(MockAuthorizationService::new());
    
    auth_service.allow_all_permissions();
    
    let client_service = ClientManagementService::new(
        repository.clone(),
        event_publisher.clone(),
        auth_service.clone(),
    );
    
    let auth_context = create_auth_context();
    
    // Create a client request that conflicts with the test-client already in mock
    let create_request = create_valid_client_request("test-client");
    
    // Act
    let result = client_service.create_client("test-realm", &create_request, &auth_context).await;
    
    // Assert
    assert!(result.is_err(), "Should fail when client already exists");
    
    if let Err(DomainError::AlreadyExists { entity_type, identifier }) = result {
        assert_eq!(entity_type, "Client");
        assert_eq!(identifier, "test-client");
    } else {
        panic!("Expected AlreadyExists error");
    }
    
    println!("✅ Client creation duplicate test passed");
}

#[tokio::test]
async fn test_client_management_service_get_client() {
    // Arrange
    let repository = Arc::new(MockKeycloakRepository::new());
    let event_publisher = Arc::new(MockEventPublisher::new());
    let auth_service = Arc::new(MockAuthorizationService::new());
    
    auth_service.allow_all_permissions();
    
    let client_service = ClientManagementService::new(
        repository.clone(),
        event_publisher.clone(),
        auth_service.clone(),
    );
    
    let auth_context = create_auth_context();
    
    // Act
    let result = client_service.get_client("test-realm", "test-client", &auth_context).await;
    
    // Assert
    assert!(result.is_ok(), "Should be able to get client");
    let client = result.unwrap();
    assert_eq!(client.client_id, "test-client");
    
    println!("✅ Client retrieval test passed");
}

#[tokio::test]
async fn test_client_management_service_get_client_not_found() {
    // Arrange
    let repository = Arc::new(MockKeycloakRepository::new());
    let event_publisher = Arc::new(MockEventPublisher::new());
    let auth_service = Arc::new(MockAuthorizationService::new());
    
    auth_service.allow_all_permissions();
    
    let client_service = ClientManagementService::new(
        repository.clone(),
        event_publisher.clone(),
        auth_service.clone(),
    );
    
    let auth_context = create_auth_context();
    
    // Act
    let result = client_service.get_client("test-realm", "non-existent-client", &auth_context).await;
    
    // Assert
    assert!(result.is_err(), "Should fail when client doesn't exist");
    
    if let Err(DomainError::ClientNotFound { client_id, realm }) = result {
        assert_eq!(client_id, "non-existent-client");
        assert_eq!(realm, "test-realm");
    } else {
        panic!("Expected ClientNotFound error");
    }
    
    println!("✅ Client not found test passed");
}

#[tokio::test]
async fn test_client_management_service_list_clients() {
    // Arrange
    let repository = Arc::new(MockKeycloakRepository::new());
    let event_publisher = Arc::new(MockEventPublisher::new());
    let auth_service = Arc::new(MockAuthorizationService::new());
    
    auth_service.allow_all_permissions();
    
    let client_service = ClientManagementService::new(
        repository.clone(),
        event_publisher.clone(),
        auth_service.clone(),
    );
    
    let auth_context = create_auth_context();
    let filter = ClientFilter::new();
    
    // Act
    let result = client_service.list_clients("test-realm", &filter, &auth_context).await;
    
    // Assert
    assert!(result.is_ok(), "Should be able to list clients");
    let clients = result.unwrap();
    assert!(!clients.is_empty(), "Should have at least one client");
    
    // The mock has a test-client by default
    let test_client = clients.iter().find(|c| c.client_id == "test-client");
    assert!(test_client.is_some(), "Should contain the test-client");
    
    println!("✅ Client listing test passed");
}

#[tokio::test]
async fn test_client_management_service_update_client() {
    // Arrange
    let repository = Arc::new(MockKeycloakRepository::new());
    let event_publisher = Arc::new(MockEventPublisher::new());
    let auth_service = Arc::new(MockAuthorizationService::new());
    
    auth_service.allow_all_permissions();
    
    let client_service = ClientManagementService::new(
        repository.clone(),
        event_publisher.clone(),
        auth_service.clone(),
    );
    
    let auth_context = create_auth_context();
    
    let update_request = UpdateClientRequest {
        name: Some("Updated Test Client".to_string()),
        description: Some("Updated description".to_string()),
        enabled: Some(false),
        redirect_uris: Some(vec!["https://updated.example.com/callback".to_string()]),
        web_origins: Some(vec!["https://updated.example.com".to_string()]),
        standard_flow_enabled: Some(false),
        implicit_flow_enabled: Some(true),
        direct_access_grants_enabled: Some(false),
        service_accounts_enabled: None,
        authorization_services_enabled: None,
        attributes: None,
    };
    
    // Act
    let result = client_service.update_client("test-realm", "test-client", &update_request, &auth_context).await;
    
    // Assert
    assert!(result.is_ok(), "Client update should succeed");
    
    // Verify the update
    let updated_client = client_service.get_client("test-realm", "test-client", &auth_context).await.unwrap();
    assert_eq!(updated_client.name, Some("Updated Test Client".to_string()));
    assert_eq!(updated_client.description, Some("Updated description".to_string()));
    assert_eq!(updated_client.enabled, false);
    
    // Verify event was published
    let events = event_publisher.get_published_events();
    assert_eq!(events.len(), 1, "Should have published one event");
    
    println!("✅ Client update test passed");
}

#[tokio::test]
async fn test_client_management_service_delete_client() {
    // Arrange
    let repository = Arc::new(MockKeycloakRepository::new());
    let event_publisher = Arc::new(MockEventPublisher::new());
    let auth_service = Arc::new(MockAuthorizationService::new());
    
    auth_service.allow_all_permissions();
    
    let client_service = ClientManagementService::new(
        repository.clone(),
        event_publisher.clone(),
        auth_service.clone(),
    );
    
    let auth_context = create_auth_context();
    
    // First create a client to delete
    let create_request = create_valid_client_request("deletable-client");
    let _client_id = client_service.create_client("test-realm", &create_request, &auth_context).await.unwrap();
    
    // Verify client exists
    assert!(client_service.get_client("test-realm", "deletable-client", &auth_context).await.is_ok());
    
    // Act - Delete the client
    let result = client_service.delete_client("test-realm", "deletable-client", &auth_context).await;
    
    // Assert
    assert!(result.is_ok(), "Client deletion should succeed");
    
    // Verify client is deleted
    let get_result = client_service.get_client("test-realm", "deletable-client", &auth_context).await;
    assert!(get_result.is_err(), "Should not be able to get deleted client");
    
    if let Err(DomainError::ClientNotFound { client_id, realm }) = get_result {
        assert_eq!(client_id, "deletable-client");
        assert_eq!(realm, "test-realm");
    } else {
        panic!("Expected ClientNotFound error");
    }
    
    // Verify events were published (create + delete)
    let events = event_publisher.get_published_events();
    assert_eq!(events.len(), 2, "Should have published two events");
    
    println!("✅ Client deletion test passed");
}

#[tokio::test]
async fn test_client_management_service_get_client_secret() {
    // Arrange
    let repository = Arc::new(MockKeycloakRepository::new());
    let event_publisher = Arc::new(MockEventPublisher::new());
    let auth_service = Arc::new(MockAuthorizationService::new());
    
    auth_service.allow_all_permissions();
    
    let client_service = ClientManagementService::new(
        repository.clone(),
        event_publisher.clone(),
        auth_service.clone(),
    );
    
    let auth_context = create_auth_context();
    
    // Act
    let result = client_service.get_client_secret("test-realm", "test-client", &auth_context).await;
    
    // Assert
    assert!(result.is_ok(), "Should be able to get client secret");
    let secret = result.unwrap();
    assert!(!secret.is_empty(), "Secret should not be empty");
    
    println!("✅ Client secret retrieval test passed");
}

#[tokio::test]
async fn test_client_management_service_regenerate_client_secret() {
    // Arrange
    let repository = Arc::new(MockKeycloakRepository::new());
    let event_publisher = Arc::new(MockEventPublisher::new());
    let auth_service = Arc::new(MockAuthorizationService::new());
    
    auth_service.allow_all_permissions();
    
    let client_service = ClientManagementService::new(
        repository.clone(),
        event_publisher.clone(),
        auth_service.clone(),
    );
    
    let auth_context = create_auth_context();
    
    // Act
    let result = client_service.regenerate_client_secret("test-realm", "test-client", &auth_context).await;
    
    // Assert
    assert!(result.is_ok(), "Should be able to regenerate client secret");
    let new_secret = result.unwrap();
    assert!(!new_secret.is_empty(), "New secret should not be empty");
    
    // Verify event was published
    let events = event_publisher.get_published_events();
    assert_eq!(events.len(), 1, "Should have published one event");
    
    println!("✅ Client secret regeneration test passed");
}

#[tokio::test]
async fn test_client_management_service_regenerate_public_client_secret_forbidden() {
    // Arrange
    let repository = Arc::new(MockKeycloakRepository::new());
    let event_publisher = Arc::new(MockEventPublisher::new());
    let auth_service = Arc::new(MockAuthorizationService::new());
    
    auth_service.allow_all_permissions();
    
    let client_service = ClientManagementService::new(
        repository.clone(),
        event_publisher.clone(),
        auth_service.clone(),
    );
    
    let auth_context = create_auth_context();
    
    // First create a public client
    let create_request = create_public_client_request("public-client");
    let _client_id = client_service.create_client("test-realm", &create_request, &auth_context).await.unwrap();
    
    // Act - Try to regenerate secret for public client
    let result = client_service.regenerate_client_secret("test-realm", "public-client", &auth_context).await;
    
    // Assert
    assert!(result.is_err(), "Should not be able to regenerate secret for public client");
    
    if let Err(DomainError::BusinessRule { rule, context }) = result {
        assert!(rule.contains("Public clients do not have secrets"));
        assert!(context.contains("public-client"));
    } else {
        panic!("Expected BusinessRule error for public client secret regeneration");
    }
    
    println!("✅ Public client secret regeneration prevention test passed");
}

#[tokio::test]
async fn test_client_management_service_set_client_enabled() {
    // Arrange
    let repository = Arc::new(MockKeycloakRepository::new());
    let event_publisher = Arc::new(MockEventPublisher::new());
    let auth_service = Arc::new(MockAuthorizationService::new());
    
    auth_service.allow_all_permissions();
    
    let client_service = ClientManagementService::new(
        repository.clone(),
        event_publisher.clone(),
        auth_service.clone(),
    );
    
    let auth_context = create_auth_context();
    
    // Act - Disable the client
    let result = client_service.set_client_enabled("test-realm", "test-client", false, &auth_context).await;
    
    // Assert
    assert!(result.is_ok(), "Should be able to disable client");
    
    // Verify client is disabled
    let client = client_service.get_client("test-realm", "test-client", &auth_context).await.unwrap();
    assert!(!client.enabled, "Client should be disabled");
    
    // Act - Re-enable the client
    let result = client_service.set_client_enabled("test-realm", "test-client", true, &auth_context).await;
    
    // Assert
    assert!(result.is_ok(), "Should be able to enable client");
    
    // Verify client is enabled
    let client = client_service.get_client("test-realm", "test-client", &auth_context).await.unwrap();
    assert!(client.enabled, "Client should be enabled");
    
    // Verify events were published (2 enable/disable events)
    let events = event_publisher.get_published_events();
    assert_eq!(events.len(), 2, "Should have published two events");
    
    println!("✅ Client enable/disable test passed");
}

#[tokio::test]
async fn test_client_management_service_authorization_failure() {
    // Arrange
    let repository = Arc::new(MockKeycloakRepository::new());
    let event_publisher = Arc::new(MockEventPublisher::new());
    let auth_service = Arc::new(MockAuthorizationService::new());
    
    // Set authorization to fail
    auth_service.set_should_fail(true);
    
    let client_service = ClientManagementService::new(
        repository.clone(),
        event_publisher.clone(),
        auth_service.clone(),
    );
    
    let auth_context = create_auth_context();
    let create_request = create_valid_client_request("auth-test-client");
    
    // Act
    let result = client_service.create_client("test-realm", &create_request, &auth_context).await;
    
    // Assert
    assert!(result.is_err(), "Should fail due to authorization");
    
    if let Err(DomainError::AuthorizationFailed { user_id, permission }) = result {
        assert_eq!(user_id, "test-admin");
        assert_eq!(permission, "clients:create");
    } else {
        panic!("Expected AuthorizationFailed error");
    }
    
    println!("✅ Client authorization failure test passed");
}

#[tokio::test]
async fn test_client_management_service_repository_failure() {
    // Arrange
    let repository = Arc::new(MockKeycloakRepository::new());
    let event_publisher = Arc::new(MockEventPublisher::new());
    let auth_service = Arc::new(MockAuthorizationService::new());
    
    auth_service.allow_all_permissions();
    repository.set_should_fail(true); // Enable mock failure
    
    let client_service = ClientManagementService::new(
        repository.clone(),
        event_publisher.clone(),
        auth_service.clone(),
    );
    
    let auth_context = create_auth_context();
    let create_request = create_valid_client_request("repo-fail-client");
    
    // Act
    let result = client_service.create_client("test-realm", &create_request, &auth_context).await;
    
    // Assert
    assert!(result.is_err(), "Should fail due to repository failure");
    
    if let Err(DomainError::ExternalService { service, message }) = result {
        assert_eq!(service, "mock-keycloak");
        assert_eq!(message, "Mock failure enabled");
    } else {
        panic!("Expected ExternalService error");
    }
    
    println!("✅ Client repository failure test passed");
}

#[tokio::test]
async fn test_client_management_service_event_publisher_failure() {
    // Arrange
    let repository = Arc::new(MockKeycloakRepository::new());
    let event_publisher = Arc::new(MockEventPublisher::new());
    let auth_service = Arc::new(MockAuthorizationService::new());
    
    auth_service.allow_all_permissions();
    event_publisher.set_should_fail(true); // Enable event publisher failure
    
    let client_service = ClientManagementService::new(
        repository.clone(),
        event_publisher.clone(),
        auth_service.clone(),
    );
    
    let auth_context = create_auth_context();
    let create_request = create_valid_client_request("event-fail-client");
    
    // Act
    let result = client_service.create_client("test-realm", &create_request, &auth_context).await;
    
    // Assert - The operation should succeed even if event publishing fails
    assert!(result.is_ok(), "Main operation should succeed even if event publishing fails");
    
    let client_id = result.unwrap();
    assert!(!client_id.as_str().is_empty(), "Client ID should be returned");
    
    // Verify that the client was actually created despite event publishing failure
    let created_client = repository.find_client_by_client_id("test-realm", "event-fail-client").await;
    assert!(created_client.is_ok(), "Client should be created in repository");
    
    println!("✅ Client event publisher failure test passed (operation succeeds, event fails)");
}

#[tokio::test]
async fn test_client_management_service_validation_errors() {
    // Arrange
    let repository = Arc::new(MockKeycloakRepository::new());
    let event_publisher = Arc::new(MockEventPublisher::new());
    let auth_service = Arc::new(MockAuthorizationService::new());
    
    auth_service.allow_all_permissions();
    
    let client_service = ClientManagementService::new(
        repository.clone(),
        event_publisher.clone(),
        auth_service.clone(),
    );
    
    let auth_context = create_auth_context();
    
    // Test with invalid client ID (empty)
    let invalid_request = CreateClientRequest {
        client_id: "".to_string(), // Invalid empty client ID
        name: Some("Valid Name".to_string()),
        description: Some("Valid description".to_string()),
        enabled: Some(true),
        client_protocol: Some("openid-connect".to_string()),
        public_client: Some(false),
        bearer_only: Some(false),
        standard_flow_enabled: Some(true),
        implicit_flow_enabled: Some(false),
        direct_access_grants_enabled: Some(true),
        service_accounts_enabled: Some(false),
        authorization_services_enabled: Some(false),
        redirect_uris: Some(vec!["https://example.com/callback".to_string()]),
        web_origins: Some(vec!["https://example.com".to_string()]),
        attributes: Some(HashMap::new()),
    };
    
    // Act
    let result = client_service.create_client("test-realm", &invalid_request, &auth_context).await;
    
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
    
    println!("✅ Client validation error test passed");
}