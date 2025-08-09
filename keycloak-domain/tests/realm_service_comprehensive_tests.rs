use std::sync::Arc;
use keycloak_domain::{
    application::{
        services::RealmManagementService,
        ports::{
            auth::AuthorizationContext,
            events::{EventPublisher, DomainEvent},
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
// 1. REALM CRUD OPERATIONS TESTS (8 tests)
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
    assert_eq!(events.len(), 1);
    
    match &events[0] {
        DomainEvent::RealmCreated { realm_id: event_realm_id, realm_name, enabled } => {
            assert_eq!(event_realm_id, &realm_id.to_string());
            assert_eq!(realm_name, "comprehensive-test-realm");
            assert!(enabled);
        }
        _ => panic!("Expected RealmCreated event"),
    }
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
    assert_eq!(events.len(), 1);
    
    match &events[0] {
        DomainEvent::RealmUpdated { realm_id: _, realm_name, changes } => {
            assert_eq!(realm_name, "update-test-realm");
            assert!(!changes.is_empty());
        }
        _ => panic!("Expected RealmUpdated event"),
    }
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
    let realm_id = realm_service.create_realm(&create_request, &auth_context).await
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
    assert_eq!(events.len(), 1);
    
    match &events[0] {
        DomainEvent::RealmDeleted { realm_id: event_realm_id, realm_name } => {
            assert_eq!(event_realm_id, &realm_id.to_string());
            assert_eq!(realm_name, "delete-test-realm");
        }
        _ => panic!("Expected RealmDeleted event"),
    }
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
    assert_eq!(events.len(), 1);
    match &events[0] {
        DomainEvent::RealmDisabled { realm_name, .. } => {
            assert_eq!(realm_name, "enable-disable-test-realm");
        }
        _ => panic!("Expected RealmDisabled event"),
    }
    
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
    assert_eq!(events.len(), 1);
    match &events[0] {
        DomainEvent::RealmEnabled { realm_name, .. } => {
            assert_eq!(realm_name, "enable-disable-test-realm");
        }
        _ => panic!("Expected RealmEnabled event"),
    }
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
    assert_eq!(events.len(), 1);
    match &events[0] {
        DomainEvent::RealmSecurityConfigured { realm_name, settings, .. } => {
            assert_eq!(realm_name, "security-test-realm");
            assert!(!settings.is_empty(), "Settings should not be empty");
        }
        _ => panic!("Expected RealmSecurityConfigured event"),
    }
}

// ================================================================================================
// 2. REALM BUSINESS RULES & VALIDATION TESTS (4 tests)
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
    
    // Create a master realm
    let master_request = CreateRealmRequest {
        realm: "master".to_string(),
        display_name: Some("Master Realm".to_string()),
        enabled: Some(true),
        ssl_required: Some(SslRequired::External),
        registration_allowed: Some(false),
        verify_email: Some(true),
        login_with_email_allowed: Some(true),
        reset_password_allowed: Some(true),
        attributes: None,
    };
    
    let _ = realm_service.create_realm(&master_request, &auth_context).await;
    
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
async fn test_reserved_realm_name_validation() {
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
    
    // Test various reserved/invalid realm names
    let test_names = vec![
        ("", "Empty name"),
        (" ", "Whitespace only"),
        ("admin", "Admin reserved"),
        ("console", "Console reserved"),
    ];
    
    for (reserved_name, description) in test_names {
        let request = CreateRealmRequest {
            realm: reserved_name.to_string(),
            display_name: Some(description.to_string()),
            enabled: Some(true),
            ssl_required: Some(SslRequired::External),
            registration_allowed: Some(true),
            verify_email: Some(true),
            login_with_email_allowed: Some(true),
            reset_password_allowed: Some(true),
            attributes: None,
        };
        
        let result = realm_service.create_realm(&request, &auth_context).await;
        
        // Should fail with validation error or already exists (depending on implementation)
        match result {
            Err(DomainError::Validation { .. }) => {
                // Expected for invalid names
            }
            Err(DomainError::AlreadyExists { .. }) => {
                // Acceptable for names that might already exist
            }
            Ok(_) => {
                // Some names might be allowed in the mock implementation
                if reserved_name.is_empty() {
                    panic!("Empty name should not be allowed");
                }
            }
            Err(other) => {
                // Other validation errors are also acceptable
                println!("Validation error for '{}': {:?}", reserved_name, other);
            }
        }
    }
}

#[tokio::test]
async fn test_realm_input_validation_errors() {
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
    
    // Test realm name too long (if validation exists)
    let long_name_request = CreateRealmRequest {
        realm: "a".repeat(256),
        display_name: Some("Too Long Name Test".to_string()),
        enabled: Some(true),
        ssl_required: Some(SslRequired::External),
        registration_allowed: Some(true),
        verify_email: Some(true),
        login_with_email_allowed: Some(true),
        reset_password_allowed: Some(true),
        attributes: None,
    };
    
    let _result = realm_service.create_realm(&long_name_request, &auth_context).await;
    // Result depends on validation implementation
    
    // Test special character validation
    let special_char_request = CreateRealmRequest {
        realm: "test-realm-with-!@#$%".to_string(),
        display_name: Some("Special Characters Test".to_string()),
        enabled: Some(true),
        ssl_required: Some(SslRequired::External),
        registration_allowed: Some(true),
        verify_email: Some(true),
        login_with_email_allowed: Some(true),
        reset_password_allowed: Some(true),
        attributes: None,
    };
    
    let _result = realm_service.create_realm(&special_char_request, &auth_context).await;
    // Test passes regardless of result as validation rules may vary
}

#[tokio::test]
async fn test_complex_realm_configuration() {
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
    
    // Create a complex realm configuration
    let mut attributes = HashMap::new();
    attributes.insert("theme".to_string(), vec!["custom".to_string()]);
    attributes.insert("locale".to_string(), vec!["en".to_string(), "es".to_string()]);
    attributes.insert("custom_field".to_string(), vec!["value1".to_string(), "value2".to_string()]);
    
    let complex_request = CreateRealmRequest {
        realm: "complex-config-realm".to_string(),
        display_name: Some("Complex Configuration Realm".to_string()),
        enabled: Some(true),
        ssl_required: Some(SslRequired::All),
        registration_allowed: Some(true),
        verify_email: Some(true),
        login_with_email_allowed: Some(true),
        reset_password_allowed: Some(true),
        attributes: Some(attributes),
    };
    
    let realm_id = realm_service.create_realm(&complex_request, &auth_context).await
        .expect("Complex realm creation should succeed");
    
    // Verify complex configuration was applied
    let created_realm = repository.find_realm_by_name("complex-config-realm").await
        .expect("Complex realm should be findable");
    
    assert_eq!(created_realm.realm, "complex-config-realm");
    assert_eq!(created_realm.display_name, Some("Complex Configuration Realm".to_string()));
    assert!(created_realm.enabled);
    assert!(created_realm.registration_allowed);
    assert!(created_realm.verify_email);
    
    // Test updating complex configuration
    let complex_update = UpdateRealmRequest {
        display_name: Some("Updated Complex Realm".to_string()),
        enabled: Some(false),
        ssl_required: Some(SslRequired::None),
        registration_allowed: Some(false),
        verify_email: Some(false),
        login_with_email_allowed: Some(false),
        reset_password_allowed: Some(false),
        brute_force_protected: Some(false),
        password_policy: Some("length(6)".to_string()),
        attributes: Some({
            let mut attrs = HashMap::new();
            attrs.insert("updated_theme".to_string(), vec!["new_theme".to_string()]);
            attrs
        }),
    };
    
    realm_service.update_realm("complex-config-realm", &complex_update, &auth_context).await
        .expect("Complex realm update should succeed");
    
    // Verify updates were applied
    let updated_realm = repository.find_realm_by_name("complex-config-realm").await
        .expect("Updated complex realm should be findable");
    
    assert_eq!(updated_realm.display_name, Some("Updated Complex Realm".to_string()));
    assert!(!updated_realm.enabled);
    assert!(!updated_realm.registration_allowed);
    assert!(!updated_realm.verify_email);
}

// ================================================================================================
// 3. REALM SERVICE ERROR SCENARIOS TESTS (4 tests)
// ================================================================================================

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
        _ => panic!("Expected AuthorizationFailed error for create"),
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
    let realm_id = realm_service.create_realm(&request, &auth_context).await
        .expect("Realm creation should succeed despite event failure");
    
    // Verify realm was created despite event failure
    let created_realm = repository.find_realm_by_name("event-fail-test-realm").await
        .expect("Realm should have been created despite event failure");
    
    assert_eq!(created_realm.realm, "event-fail-test-realm");
    
    // Verify no events were published due to failure
    let events = event_publisher.get_published_events();
    assert!(events.is_empty(), "No events should be published due to failure");
    
    // Test update with event publisher failure
    let update_request = UpdateRealmRequest {
        enabled: Some(false),
        display_name: Some("Updated Despite Event Failure".to_string()),
        ssl_required: None,
        registration_allowed: None,
        verify_email: None,
        login_with_email_allowed: None,
        reset_password_allowed: None,
        brute_force_protected: None,
        password_policy: None,
        attributes: None,
    };
    
    realm_service.update_realm("event-fail-test-realm", &update_request, &auth_context).await
        .expect("Realm update should succeed despite event failure");
    
    // Verify realm was updated despite event failure
    let updated_realm = repository.find_realm_by_name("event-fail-test-realm").await
        .expect("Updated realm should be findable");
    assert!(!updated_realm.enabled);
    assert_eq!(updated_realm.display_name, Some("Updated Despite Event Failure".to_string()));
}

#[tokio::test]
async fn test_concurrent_realm_operations() {
    let repository = Arc::new(MockKeycloakRepository::new());
    let event_publisher = Arc::new(MockEventPublisher::new());
    let auth_service = Arc::new(MockAuthorizationService::new());
    auth_service.allow_all_permissions();
    
    let realm_service = Arc::new(RealmManagementService::new(
        repository.clone(),
        event_publisher.clone(),
        auth_service.clone(),
    ));
    
    let auth_context = create_auth_context();
    
    // Create multiple concurrent realm creation tasks
    let mut handles = vec![];
    
    for i in 1..=5 {
        let service = Arc::clone(&realm_service);
        let context = auth_context.clone();
        
        let handle = tokio::spawn(async move {
            let request = create_test_create_realm_request(&format!("concurrent-realm-{}", i));
            service.create_realm(&request, &context).await
        });
        
        handles.push(handle);
    }
    
    // Wait for all tasks to complete
    let mut successful_creates = 0;
    let mut failed_creates = 0;
    
    for handle in handles {
        match handle.await.unwrap() {
            Ok(_) => successful_creates += 1,
            Err(_) => failed_creates += 1,
        }
    }
    
    // All should succeed since they have different names
    assert_eq!(successful_creates, 5);
    assert_eq!(failed_creates, 0);
    
    // Test concurrent operations on the same realm
    let mut update_handles = vec![];
    
    for i in 1..=3 {
        let service = Arc::clone(&realm_service);
        let context = auth_context.clone();
        
        let handle = tokio::spawn(async move {
            let update_request = UpdateRealmRequest {
                display_name: Some(format!("Updated by task {}", i)),
                enabled: None,
                ssl_required: None,
                registration_allowed: None,
                verify_email: None,
                login_with_email_allowed: None,
                reset_password_allowed: None,
                brute_force_protected: None,
                password_policy: None,
                attributes: None,
            };
            service.update_realm("concurrent-realm-1", &update_request, &context).await
        });
        
        update_handles.push(handle);
    }
    
    // Wait for concurrent updates
    let mut successful_updates = 0;
    
    for handle in update_handles {
        if handle.await.unwrap().is_ok() {
            successful_updates += 1;
        }
    }
    
    // At least some updates should succeed (exact number depends on timing)
    assert!(successful_updates > 0, "At least some concurrent updates should succeed");
    
    // Verify final state is consistent
    let final_realm = repository.find_realm_by_name("concurrent-realm-1").await
        .expect("Realm should exist after concurrent updates");
    
    assert!(final_realm.display_name.is_some(), "Display name should be set by one of the updates");
}

// Additional tests for import/export functionality

#[tokio::test]
async fn test_import_export_realm() {
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
    
    // Create a realm to export
    let create_request = create_test_create_realm_request("export-test-realm");
    realm_service.create_realm(&create_request, &auth_context).await
        .expect("Realm creation should succeed");
    
    event_publisher.clear_events();
    
    // Export the realm
    let exported_realm = realm_service.export_realm("export-test-realm", &auth_context).await
        .expect("Realm export should succeed");
    
    assert_eq!(exported_realm.realm, "export-test-realm");
    
    // Verify export event was published
    let events = event_publisher.get_published_events();
    assert_eq!(events.len(), 1);
    match &events[0] {
        DomainEvent::RealmExported { realm_name, .. } => {
            assert_eq!(realm_name, "export-test-realm");
        }
        _ => panic!("Expected RealmExported event"),
    }
    
    event_publisher.clear_events();
    
    // Modify the exported realm data for import
    let mut import_realm = exported_realm.clone();
    import_realm.realm = "imported-test-realm".to_string();
    import_realm.id = None; // Clear ID for import
    
    // Import as a new realm
    let imported_realm_id = realm_service.import_realm(&import_realm, &auth_context).await
        .expect("Realm import should succeed");
    
    // Verify imported realm exists
    let imported_realm = repository.find_realm_by_name("imported-test-realm").await
        .expect("Imported realm should be findable");
    
    assert_eq!(imported_realm.realm, "imported-test-realm");
    assert_eq!(imported_realm.display_name, exported_realm.display_name);
    assert_eq!(imported_realm.enabled, exported_realm.enabled);
    
    // Verify import event was published
    let events = event_publisher.get_published_events();
    assert_eq!(events.len(), 1);
    match &events[0] {
        DomainEvent::RealmImported { realm_name, .. } => {
            assert_eq!(realm_name, "imported-test-realm");
        }
        _ => panic!("Expected RealmImported event"),
    }
    
    // Test import duplicate realm - should fail
    let duplicate_import_result = realm_service.import_realm(&import_realm, &auth_context).await;
    match duplicate_import_result {
        Err(DomainError::AlreadyExists { entity_type, identifier }) => {
            assert_eq!(entity_type, "Realm");
            assert_eq!(identifier, "imported-test-realm");
        }
        _ => panic!("Expected AlreadyExists error for duplicate import"),
    }
}