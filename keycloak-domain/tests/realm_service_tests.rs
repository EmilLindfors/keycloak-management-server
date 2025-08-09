use std::sync::Arc;
use keycloak_domain::{
    application::{
        services::RealmManagementService,
        ports::{
            auth::AuthorizationContext,
            repository::KeycloakRepository,
        },
    },
    domain::{
        entities::{
            realm::{CreateRealmRequest, UpdateRealmRequest, RealmFilter, SslRequired},
        },
        errors::DomainError,
    },
};
use std::collections::HashMap;

mod mocks;
use mocks::{MockKeycloakRepository, MockEventPublisher, MockAuthorizationService};

fn create_auth_context() -> AuthorizationContext {
    AuthorizationContext::new("test-realm".to_string())
        .with_user("test-admin".to_string())
        .with_roles(vec!["admin".to_string()])
}

fn create_test_create_realm_request(realm_name: &str) -> CreateRealmRequest {
    CreateRealmRequest {
        realm: realm_name.to_string(),
        display_name: Some(format!("{} Display", realm_name)),
        enabled: Some(true),
        ssl_required: Some(SslRequired::External),
        registration_allowed: Some(true),
        verify_email: Some(true),
        login_with_email_allowed: Some(true),
        reset_password_allowed: Some(true),
        attributes: None,
    }
}

// ================================================================================================
// REALM CRUD OPERATIONS TESTS - Basic functionality tests
// ================================================================================================

#[tokio::test]
async fn test_create_realm_comprehensive() {
    let repository = Arc::new(MockKeycloakRepository::new());
    let event_publisher = Arc::new(MockEventPublisher::new());
    let auth_service = Arc::new(MockAuthorizationService::new());
    auth_service.allow_all_permissions();
    
    let realm_service = RealmManagementService::new(
        repository.clone(),
        event_publisher.clone(),
        auth_service.clone(),
    );
    
    let auth_context = create_auth_context();
    let request = create_test_create_realm_request("comprehensive-test-realm");
    
    let realm_id = realm_service.create_realm(&request, &auth_context).await
        .expect("Realm creation should succeed");
    
    assert!(!realm_id.as_str().is_empty(), "Realm ID should not be empty");
    
    // Verify realm was created in repository
    let created_realm = repository.find_realm_by_name("comprehensive-test-realm").await
        .expect("Created realm should be findable");
    
    assert_eq!(created_realm.realm, "comprehensive-test-realm");
    assert_eq!(created_realm.display_name, Some("comprehensive-test-realm Display".to_string()));
    assert!(created_realm.enabled);
    assert!(created_realm.registration_allowed);
    assert!(created_realm.verify_email);
    
    // Verify domain event was published
    let events = event_publisher.get_published_events();
    assert_eq!(events.len(), 1, "Should have published exactly one event");
}

#[tokio::test]
async fn test_update_realm_settings() {
    let repository = Arc::new(MockKeycloakRepository::new());
    let event_publisher = Arc::new(MockEventPublisher::new());
    let auth_service = Arc::new(MockAuthorizationService::new());
    auth_service.allow_all_permissions();
    
    let realm_service = RealmManagementService::new(
        repository.clone(),
        event_publisher.clone(),
        auth_service.clone(),
    );
    
    let auth_context = create_auth_context();
    
    // Create initial realm
    let create_request = create_test_create_realm_request("update-test-realm");
    realm_service.create_realm(&create_request, &auth_context).await
        .expect("Realm creation should succeed");
    
    event_publisher.clear_events();
    
    // Update realm settings
    let update_request = UpdateRealmRequest {
        display_name: Some("Updated Display Name".to_string()),
        enabled: Some(false),
        ssl_required: Some(SslRequired::All),
        registration_allowed: Some(false),
        verify_email: Some(false),
        login_with_email_allowed: Some(false),
        reset_password_allowed: Some(false),
        brute_force_protected: Some(true),
        password_policy: Some("length(8)".to_string()),
        attributes: Some({
            let mut attrs = HashMap::new();
            attrs.insert("updated".to_string(), vec!["value".to_string()]);
            attrs
        }),
    };
    
    realm_service.update_realm("update-test-realm", &update_request, &auth_context).await
        .expect("Realm update should succeed");
    
    // Verify changes were applied
    let updated_realm = repository.find_realm_by_name("update-test-realm").await
        .expect("Updated realm should be findable");
    
    assert_eq!(updated_realm.display_name, Some("Updated Display Name".to_string()));
    assert!(!updated_realm.enabled);
    assert!(!updated_realm.registration_allowed);
    assert!(!updated_realm.verify_email);
    
    // Verify domain event was published
    let events = event_publisher.get_published_events();
    assert_eq!(events.len(), 1, "Should have published exactly one update event");
}

#[tokio::test]
async fn test_delete_realm_with_cleanup() {
    let repository = Arc::new(MockKeycloakRepository::new());
    let event_publisher = Arc::new(MockEventPublisher::new());
    let auth_service = Arc::new(MockAuthorizationService::new());
    auth_service.allow_all_permissions();
    
    let realm_service = RealmManagementService::new(
        repository.clone(),
        event_publisher.clone(),
        auth_service.clone(),
    );
    
    let auth_context = create_auth_context();
    
    // Create realm to delete
    let create_request = create_test_create_realm_request("delete-test-realm");
    let _realm_id = realm_service.create_realm(&create_request, &auth_context).await
        .expect("Realm creation should succeed");
    
    event_publisher.clear_events();
    
    // Delete the realm
    realm_service.delete_realm("delete-test-realm", &auth_context).await
        .expect("Realm deletion should succeed");
    
    // Verify realm was deleted from repository
    let result = repository.find_realm_by_name("delete-test-realm").await;
    match result {
        Err(DomainError::RealmNotFound { .. }) => {
            // Expected - realm should not be found
        }
        _ => panic!("Realm should have been deleted"),
    }
    
    // Verify domain event was published
    let events = event_publisher.get_published_events();
    assert_eq!(events.len(), 1, "Should have published exactly one delete event");
}

#[tokio::test]
async fn test_get_realm_by_name() {
    let repository = Arc::new(MockKeycloakRepository::new());
    let event_publisher = Arc::new(MockEventPublisher::new());
    let auth_service = Arc::new(MockAuthorizationService::new());
    auth_service.allow_all_permissions();
    
    let realm_service = RealmManagementService::new(
        repository.clone(),
        event_publisher.clone(),
        auth_service.clone(),
    );
    
    let auth_context = create_auth_context();
    
    // Create realm
    let create_request = create_test_create_realm_request("get-test-realm");
    realm_service.create_realm(&create_request, &auth_context).await
        .expect("Realm creation should succeed");
    
    // Get the realm
    let retrieved_realm = realm_service.get_realm("get-test-realm", &auth_context).await
        .expect("Realm retrieval should succeed");
    
    assert_eq!(retrieved_realm.realm, "get-test-realm");
    assert_eq!(retrieved_realm.display_name, Some("get-test-realm Display".to_string()));
    assert!(retrieved_realm.enabled);
    assert!(retrieved_realm.registration_allowed);
    
    // Test getting non-existent realm
    let result = realm_service.get_realm("non-existent-realm", &auth_context).await;
    match result {
        Err(DomainError::RealmNotFound { realm, .. }) => {
            assert_eq!(realm, "non-existent-realm");
        }
        _ => panic!("Expected RealmNotFound error"),
    }
}

#[tokio::test]
async fn test_list_realms_with_filters() {
    let repository = Arc::new(MockKeycloakRepository::new());
    let event_publisher = Arc::new(MockEventPublisher::new());
    let auth_service = Arc::new(MockAuthorizationService::new());
    auth_service.allow_all_permissions();
    
    let realm_service = RealmManagementService::new(
        repository.clone(),
        event_publisher.clone(),
        auth_service.clone(),
    );
    
    let auth_context = create_auth_context();
    
    // Create multiple realms
    for i in 1..=5 {
        let request = create_test_create_realm_request(&format!("list-test-realm-{}", i));
        realm_service.create_realm(&request, &auth_context).await
            .expect("Realm creation should succeed");
    }
    
    // Test list all realms (includes default test realm)
    let all_realms = realm_service.list_realms(&auth_context).await
        .expect("Realm listing should succeed");
    
    assert!(all_realms.len() >= 6, "Should have at least 6 realms (5 created + 1 default)");
    
    // Test list realms with filter
    let filter = RealmFilter { brief_representation: Some(true) };
    let filtered_realms = realm_service.list_realms_with_filter(&filter, &auth_context).await
        .expect("Filtered realm listing should succeed");
    
    assert!(!filtered_realms.is_empty(), "Filtered results should not be empty");
}

#[tokio::test]
async fn test_set_realm_enabled_disabled() {
    let repository = Arc::new(MockKeycloakRepository::new());
    let event_publisher = Arc::new(MockEventPublisher::new());
    let auth_service = Arc::new(MockAuthorizationService::new());
    auth_service.allow_all_permissions();
    
    let realm_service = RealmManagementService::new(
        repository.clone(),
        event_publisher.clone(),
        auth_service.clone(),
    );
    
    let auth_context = create_auth_context();
    
    // Create realm
    let create_request = create_test_create_realm_request("enable-disable-test-realm");
    realm_service.create_realm(&create_request, &auth_context).await
        .expect("Realm creation should succeed");
    
    event_publisher.clear_events();
    
    // Disable the realm
    realm_service.set_realm_enabled("enable-disable-test-realm", false, &auth_context).await
        .expect("Realm disabling should succeed");
    
    // Verify realm is disabled
    let realm = repository.find_realm_by_name("enable-disable-test-realm").await
        .expect("Realm should be findable");
    assert!(!realm.enabled, "Realm should be disabled");
    
    // Verify domain event was published
    let events = event_publisher.get_published_events();
    assert_eq!(events.len(), 1, "Should have published exactly one disable event");
    
    event_publisher.clear_events();
    
    // Re-enable the realm
    realm_service.set_realm_enabled("enable-disable-test-realm", true, &auth_context).await
        .expect("Realm enabling should succeed");
    
    // Verify realm is enabled
    let realm = repository.find_realm_by_name("enable-disable-test-realm").await
        .expect("Realm should be findable");
    assert!(realm.enabled, "Realm should be enabled");
    
    // Verify domain event was published
    let events = event_publisher.get_published_events();
    assert_eq!(events.len(), 1, "Should have published exactly one enable event");
}

#[tokio::test]
async fn test_realm_already_exists_error() {
    let repository = Arc::new(MockKeycloakRepository::new());
    let event_publisher = Arc::new(MockEventPublisher::new());
    let auth_service = Arc::new(MockAuthorizationService::new());
    auth_service.allow_all_permissions();
    
    let realm_service = RealmManagementService::new(
        repository.clone(),
        event_publisher.clone(),
        auth_service.clone(),
    );
    
    let auth_context = create_auth_context();
    
    // Create initial realm
    let create_request = create_test_create_realm_request("duplicate-test-realm");
    realm_service.create_realm(&create_request, &auth_context).await
        .expect("Initial realm creation should succeed");
    
    // Try to create realm with same name
    let duplicate_request = create_test_create_realm_request("duplicate-test-realm");
    let result = realm_service.create_realm(&duplicate_request, &auth_context).await;
    
    match result {
        Err(DomainError::AlreadyExists { entity_type, identifier }) => {
            assert_eq!(entity_type, "Realm");
            assert_eq!(identifier, "duplicate-test-realm");
        }
        _ => panic!("Expected AlreadyExists error"),
    }
}

#[tokio::test]
async fn test_configure_realm_security() {
    let repository = Arc::new(MockKeycloakRepository::new());
    let event_publisher = Arc::new(MockEventPublisher::new());
    let auth_service = Arc::new(MockAuthorizationService::new());
    auth_service.allow_all_permissions();
    
    let realm_service = RealmManagementService::new(
        repository.clone(),
        event_publisher.clone(),
        auth_service.clone(),
    );
    
    let auth_context = create_auth_context();
    
    // Create realm
    let create_request = create_test_create_realm_request("security-test-realm");
    realm_service.create_realm(&create_request, &auth_context).await
        .expect("Realm creation should succeed");
    
    event_publisher.clear_events();
    
    // Configure security settings
    realm_service.configure_realm_security(
        "security-test-realm",
        Some(false), // reset_password_allowed
        Some(false), // edit_username_allowed  
        Some(true),  // brute_force_protected
        Some("length(12) and digits(2)".to_string()),
        &auth_context,
    ).await.expect("Security configuration should succeed");
    
    // Verify security settings were applied
    let realm = repository.find_realm_by_name("security-test-realm").await
        .expect("Realm should be findable");
    
    assert!(!realm.reset_password_allowed, "Reset password should be disabled");
    assert!(!realm.edit_username_allowed, "Edit username should be disabled");
    assert!(realm.brute_force_protected, "Brute force protection should be enabled");
    assert!(realm.password_policy.is_some(), "Password policy should be set");
    
    // Verify domain event was published
    let events = event_publisher.get_published_events();
    assert_eq!(events.len(), 1, "Should have published exactly one security config event");
}

// ================================================================================================
// REALM BUSINESS RULES & VALIDATION TESTS
// ================================================================================================

#[tokio::test] 
async fn test_master_realm_protection() {
    let repository = Arc::new(MockKeycloakRepository::new());
    let event_publisher = Arc::new(MockEventPublisher::new());
    let auth_service = Arc::new(MockAuthorizationService::new());
    auth_service.allow_all_permissions();
    
    let realm_service = RealmManagementService::new(
        repository.clone(),
        event_publisher.clone(),
        auth_service.clone(),
    );
    
    let auth_context = create_auth_context();
    
    // Create a regular test realm first, then change its name to "master" in the mock
    // This avoids the validation that prevents creating realms named "master"
    let test_request = create_test_create_realm_request("master-test-temp");
    let _ = realm_service.create_realm(&test_request, &auth_context).await.unwrap();
    
    // Now change the realm name to "master" in the mock repository
    {
        let mut realms = repository.realms.lock().unwrap();
        if let Some(realm) = realms.first_mut() {
            realm.realm = "master".to_string();
        }
    }
    
    // Test master realm deletion protection
    let delete_result = realm_service.delete_realm("master", &auth_context).await;
    match delete_result {
        Err(DomainError::BusinessRule { rule, context }) => {
            assert!(rule.contains("Master realm cannot be deleted"));
            assert!(context.contains("master"));
        }
        _ => panic!("Expected BusinessRule error for master realm deletion"),
    }
    
    // Test master realm disable protection
    let disable_result = realm_service.set_realm_enabled("master", false, &auth_context).await;
    match disable_result {
        Err(DomainError::BusinessRule { rule, context }) => {
            assert!(rule.contains("Master realm cannot be disabled"));
            assert!(context.contains("master"));
        }
        _ => panic!("Expected BusinessRule error for master realm disabling"),
    }
}

#[tokio::test]
async fn test_realm_authorization_failures() {
    let repository = Arc::new(MockKeycloakRepository::new());
    let event_publisher = Arc::new(MockEventPublisher::new());
    let auth_service = Arc::new(MockAuthorizationService::new());
    // Don't allow any permissions
    
    let realm_service = RealmManagementService::new(
        repository.clone(),
        event_publisher.clone(),
        auth_service.clone(),
    );
    
    let auth_context = create_auth_context();
    let request = create_test_create_realm_request("auth-test-realm");
    
    // Test create realm authorization failure
    let result = realm_service.create_realm(&request, &auth_context).await;
    match result {
        Err(DomainError::AuthorizationFailed { user_id, permission }) => {
            assert!(!user_id.is_empty());
            assert!(permission.contains("create"));
        }
        Ok(_) => panic!("Expected AuthorizationFailed error for create, but got success"),
        Err(other) => panic!("Expected AuthorizationFailed error for create, got: {:?}", other),
    }
    
    // Test view realm authorization failure
    let result = realm_service.get_realm("test-realm", &auth_context).await;
    match result {
        Err(DomainError::AuthorizationFailed { permission, .. }) => {
            assert!(permission.contains("view"));
        }
        _ => panic!("Expected AuthorizationFailed error for view"),
    }
    
    // Test list realms authorization failure
    let result = realm_service.list_realms(&auth_context).await;
    match result {
        Err(DomainError::AuthorizationFailed { permission, .. }) => {
            assert!(permission.contains("view"));
        }
        _ => panic!("Expected AuthorizationFailed error for list"),
    }
}

#[tokio::test]
async fn test_realm_repository_failure_handling() {
    let repository = Arc::new(MockKeycloakRepository::new());
    let event_publisher = Arc::new(MockEventPublisher::new());
    let auth_service = Arc::new(MockAuthorizationService::new());
    auth_service.allow_all_permissions();
    
    let realm_service = RealmManagementService::new(
        repository.clone(),
        event_publisher.clone(),
        auth_service.clone(),
    );
    
    let auth_context = create_auth_context();
    
    // Enable repository failures
    repository.set_should_fail(true);
    
    // Test create realm with repository failure
    let request = create_test_create_realm_request("repo-fail-test-realm");
    let result = realm_service.create_realm(&request, &auth_context).await;
    
    match result {
        Err(DomainError::ExternalService { service, message }) => {
            assert_eq!(service, "mock-keycloak");
            assert!(message.contains("Mock failure enabled"));
        }
        _ => panic!("Expected ExternalService error"),
    }
    
    // Test get realm with repository failure
    let result = realm_service.get_realm("any-realm", &auth_context).await;
    match result {
        Err(DomainError::ExternalService { .. }) => {
            // Expected
        }
        _ => panic!("Expected ExternalService error for get"),
    }
    
    // Test list realms with repository failure
    let result = realm_service.list_realms(&auth_context).await;
    match result {
        Err(DomainError::ExternalService { .. }) => {
            // Expected
        }
        _ => panic!("Expected ExternalService error for list"),
    }
}

#[tokio::test]
async fn test_realm_event_publisher_failure() {
    let repository = Arc::new(MockKeycloakRepository::new());
    let event_publisher = Arc::new(MockEventPublisher::new());
    let auth_service = Arc::new(MockAuthorizationService::new());
    auth_service.allow_all_permissions();
    
    let realm_service = RealmManagementService::new(
        repository.clone(),
        event_publisher.clone(),
        auth_service.clone(),
    );
    
    let auth_context = create_auth_context();
    
    // Enable event publisher failures
    event_publisher.set_should_fail(true);
    
    // Test create realm with event publisher failure - operation should succeed
    let request = create_test_create_realm_request("event-fail-test-realm");
    let _realm_id = realm_service.create_realm(&request, &auth_context).await
        .expect("Realm creation should succeed despite event failure");
    
    // Verify realm was created despite event failure
    let created_realm = repository.find_realm_by_name("event-fail-test-realm").await
        .expect("Realm should have been created despite event failure");
    
    assert_eq!(created_realm.realm, "event-fail-test-realm");
    
    // Verify no events were published due to failure
    let events = event_publisher.get_published_events();
    assert!(events.is_empty(), "No events should be published due to failure");
}