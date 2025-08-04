use keycloak_domain::{application::ports::*, domain::entities::*, infrastructure::adapters::*};

#[tokio::test]
async fn test_user_creation() {
    // Test creating a new user with validation
    let user_request = CreateUserRequest::new("testuser".to_string())
        .with_email("test@example.com".to_string())
        .with_name("Test".to_string(), "User".to_string());

    let result = user_request.validate();
    assert!(result.is_ok(), "User request validation should pass");

    let user = user_request.to_domain_user().unwrap();
    assert_eq!(user.username, "testuser");
    assert_eq!(user.email, Some("test@example.com".to_string()));
    assert_eq!(user.first_name, Some("Test".to_string()));
    assert_eq!(user.last_name, Some("User".to_string()));
    assert!(user.enabled);
}

#[tokio::test]
async fn test_realm_creation() {
    // Test creating a new realm with validation
    let realm_request = CreateRealmRequest::new("test-realm".to_string())
        .with_display_name("Test Realm".to_string())
        .with_registration(true);

    let result = realm_request.validate();
    assert!(result.is_ok(), "Realm request validation should pass");

    let realm = realm_request.to_domain_realm().unwrap();
    assert_eq!(realm.realm, "test-realm");
    assert_eq!(realm.display_name, Some("Test Realm".to_string()));
    assert!(realm.registration_allowed);
    assert!(realm.enabled);
}

#[tokio::test]
async fn test_client_creation() {
    // Test creating different types of clients
    let public_client = Client::public_client("spa-app".to_string()).unwrap();
    assert!(public_client.is_public());
    assert_eq!(public_client.client_authenticator_type, "none");

    let confidential_client = Client::confidential_client("backend-app".to_string()).unwrap();
    assert!(!confidential_client.is_public());
    assert_eq!(
        confidential_client.client_authenticator_type,
        "client-secret"
    );

    let service_account = Client::service_account_client("api-service".to_string()).unwrap();
    assert!(service_account.supports_service_accounts());
    assert!(!service_account.standard_flow_enabled);
}

#[tokio::test]
async fn test_group_hierarchy() {
    // Test group creation and hierarchy
    let parent_group = Group::new("parent".to_string(), None).unwrap();
    assert_eq!(parent_group.path, "/parent");
    assert!(parent_group.is_root_group());

    let child_group = Group::new_subgroup("child".to_string(), &parent_group).unwrap();
    assert_eq!(child_group.path, "/parent/child");
    assert!(!child_group.is_root_group());
    assert_eq!(child_group.get_depth(), 1);
}

#[tokio::test]
async fn test_role_composites() {
    // Test role creation and composite relationships
    let mut composite_role = Role::new_composite_role(
        "admin".to_string(),
        "test-realm".to_string(),
        false, // realm role
    )
    .unwrap();

    assert!(composite_role.is_composite());
    assert!(composite_role.is_realm_role());

    // Add composite roles
    composite_role
        .add_realm_composite("user".to_string())
        .unwrap();
    composite_role
        .add_client_composite("my-client".to_string(), "view".to_string())
        .unwrap();

    let all_composites = composite_role.get_all_composites();
    assert_eq!(all_composites.len(), 2);
    assert!(all_composites.contains(&"user".to_string()));
    assert!(all_composites.contains(&"my-client:view".to_string()));
}

#[tokio::test]
async fn test_user_validation() {
    // Test user validation rules
    let invalid_username = CreateUserRequest::new("a".to_string()); // too short
    assert!(invalid_username.validate().is_err());

    let invalid_email =
        CreateUserRequest::new("validuser".to_string()).with_email("invalid-email".to_string());
    assert!(invalid_email.validate().is_err());

    let valid_request =
        CreateUserRequest::new("validuser".to_string()).with_email("valid@example.com".to_string());
    assert!(valid_request.validate().is_ok());
}

#[tokio::test]
async fn test_event_publisher() {
    // Test the in-memory event publisher
    let (publisher, mut receiver) = MemoryEventPublisher::new();

    let event = DomainEvent::user_created(
        "user-123".to_string(),
        "test-realm".to_string(),
        "testuser".to_string(),
        Some("test@example.com".to_string()),
        true,
    );

    // Publish the event
    publisher.publish(event.clone()).await.unwrap();

    // Receive the event
    let received_event = receiver.recv().await.unwrap();
    assert_eq!(received_event.event_type, EventType::UserCreated);
    assert_eq!(received_event.aggregate_id, "user-123");
    assert_eq!(received_event.realm, "test-realm");
}

#[tokio::test]
async fn test_configuration_loading() {
    // Test configuration loading from environment
    // This test uses default values since we don't set environment variables
    unsafe {
        std::env::set_var("KEYCLOAK_URL", "http://localhost:8080");
        std::env::set_var("KEYCLOAK_ADMIN_USERNAME", "admin");
        std::env::set_var("KEYCLOAK_ADMIN_PASSWORD", "password");
    }

    let config_adapter = EnvConfigurationAdapter::new();
    assert!(
        config_adapter.is_ok(),
        "Configuration should load successfully"
    );

    let adapter = config_adapter.unwrap();
    assert_eq!(adapter.get_keycloak_config().url, "http://localhost:8080");
    assert_eq!(adapter.get_keycloak_config().admin_username, "admin");
    assert!(adapter.validate().is_ok());

    // Clean up
    unsafe {
        std::env::remove_var("KEYCLOAK_URL");
        std::env::remove_var("KEYCLOAK_ADMIN_USERNAME");
        std::env::remove_var("KEYCLOAK_ADMIN_PASSWORD");
    }
}
