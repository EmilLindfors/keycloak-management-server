use keycloak_domain::domain::{
    entities::{
        user::{User, CreateUserRequest, UpdateUserRequest},
        common::{RequiredAction, FederatedIdentity},
    },
    errors::DomainError,
};
use std::collections::HashMap;

/// Comprehensive tests for User domain entity
/// Tests all methods, validation, state transitions, and edge cases

#[test]
fn test_user_new_with_valid_username() {
    let result = User::new("testuser".to_string());
    assert!(result.is_ok());
    
    let user = result.unwrap();
    assert_eq!(user.username, "testuser");
    assert_eq!(user.email, None);
    assert!(!user.email_verified);
    assert_eq!(user.first_name, None);
    assert_eq!(user.last_name, None);
    assert!(user.enabled);
    assert!(user.required_actions.is_empty());
    assert!(user.federated_identities.is_empty());
}

#[test]
fn test_user_new_with_invalid_username() {
    // Empty username
    let result = User::new("".to_string());
    assert!(result.is_err());
    match result.unwrap_err() {
        DomainError::InvalidUsername { reason } => {
            assert!(reason.contains("empty"));
        }
        _ => panic!("Expected InvalidUsername error"),
    }
    
    // Too short username
    let result = User::new("a".to_string());
    assert!(result.is_err());
    
    // Too long username
    let long_username = "a".repeat(101);
    let result = User::new(long_username);
    assert!(result.is_err());
    
    // Invalid characters
    let result = User::new("user@domain.com".to_string());
    assert!(result.is_err());
}

#[test]
fn test_user_with_email() {
    let result = User::with_email("testuser".to_string(), "test@example.com".to_string());
    assert!(result.is_ok());
    
    let user = result.unwrap();
    assert_eq!(user.username, "testuser");
    assert_eq!(user.email, Some("test@example.com".to_string()));
    assert!(!user.email_verified);
    assert!(user.required_actions.contains(&RequiredAction::VerifyEmail));
}

#[test]
fn test_user_with_invalid_email() {
    let result = User::with_email("testuser".to_string(), "invalid-email".to_string());
    assert!(result.is_err());
    match result.unwrap_err() {
        DomainError::InvalidEmail { .. } => {
            // Expected error
        }
        _ => panic!("Expected InvalidEmail error"),
    }
}

#[test]
fn test_validate_username() {
    // Valid usernames
    assert!(User::validate_username("testuser").is_ok());
    assert!(User::validate_username("test_user").is_ok());
    assert!(User::validate_username("test-user").is_ok());
    assert!(User::validate_username("test.user").is_ok());
    assert!(User::validate_username("TestUser123").is_ok());
    
    // Invalid usernames
    assert!(User::validate_username("").is_err());
    assert!(User::validate_username("a").is_err());
    assert!(User::validate_username("user@domain").is_err());
    assert!(User::validate_username("user with spaces").is_err());
    assert!(User::validate_username("user#hash").is_err());
    assert!(User::validate_username(&"a".repeat(101)).is_err());
}

#[test]
fn test_validate_email() {
    // Valid emails
    assert!(User::validate_email("test@example.com").is_ok());
    assert!(User::validate_email("user.name@domain.co.uk").is_ok());
    assert!(User::validate_email("user+tag@example.org").is_ok());
    
    // Invalid emails
    assert!(User::validate_email("").is_err());
    assert!(User::validate_email("invalid-email").is_err());
    assert!(User::validate_email("@example.com").is_err());
    assert!(User::validate_email("user@").is_err());
    assert!(User::validate_email("user@domain").is_err());
}

#[test]
fn test_update_email() {
    let mut user = User::new("testuser".to_string()).unwrap();
    
    // Update with valid email
    let result = user.update_email(Some("new@example.com".to_string()));
    assert!(result.is_ok());
    assert_eq!(user.email, Some("new@example.com".to_string()));
    assert!(!user.email_verified);
    assert!(user.required_actions.contains(&RequiredAction::VerifyEmail));
    
    // Update with invalid email
    let result = user.update_email(Some("invalid-email".to_string()));
    assert!(result.is_err());
    
    // Remove email
    let result = user.update_email(None);
    assert!(result.is_ok());
    assert_eq!(user.email, None);
}

#[test]
fn test_verify_email() {
    let mut user = User::with_email("testuser".to_string(), "test@example.com".to_string()).unwrap();
    
    assert!(!user.email_verified);
    assert!(user.required_actions.contains(&RequiredAction::VerifyEmail));
    
    let result = user.verify_email();
    assert!(result.is_ok());
    assert!(user.email_verified);
    assert!(!user.required_actions.contains(&RequiredAction::VerifyEmail));
    
    // Try to verify email when no email is set
    let mut user_no_email = User::new("testuser".to_string()).unwrap();
    let result = user_no_email.verify_email();
    assert!(result.is_err());
}

#[test]
fn test_update_profile() {
    let mut user = User::new("testuser".to_string()).unwrap();
    user.add_required_action(RequiredAction::UpdateProfile);
    
    let result = user.update_profile(
        Some("John".to_string()),
        Some("Doe".to_string()),
    );
    assert!(result.is_ok());
    assert_eq!(user.first_name, Some("John".to_string()));
    assert_eq!(user.last_name, Some("Doe".to_string()));
    assert!(!user.required_actions.contains(&RequiredAction::UpdateProfile));
    
    // Update with None values
    let result = user.update_profile(None, None);
    assert!(result.is_ok());
    assert_eq!(user.first_name, None);
    assert_eq!(user.last_name, None);
}

#[test]
fn test_set_enabled() {
    let mut user = User::new("testuser".to_string()).unwrap();
    assert!(user.enabled);
    
    user.set_enabled(false);
    assert!(!user.enabled);
    
    user.set_enabled(true);
    assert!(user.enabled);
}

#[test]
fn test_required_actions() {
    let mut user = User::new("testuser".to_string()).unwrap();
    assert!(user.required_actions.is_empty());
    
    // Add required action
    user.add_required_action(RequiredAction::UpdatePassword);
    assert!(user.required_actions.contains(&RequiredAction::UpdatePassword));
    
    // Don't add duplicate
    user.add_required_action(RequiredAction::UpdatePassword);
    assert_eq!(user.required_actions.len(), 1);
    
    // Add another action
    user.add_required_action(RequiredAction::UpdateProfile);
    assert_eq!(user.required_actions.len(), 2);
    
    // Remove action
    user.remove_required_action(&RequiredAction::UpdatePassword);
    assert!(!user.required_actions.contains(&RequiredAction::UpdatePassword));
    assert!(user.required_actions.contains(&RequiredAction::UpdateProfile));
}

#[test]
fn test_attributes() {
    let mut user = User::new("testuser".to_string()).unwrap();
    
    // Set attribute
    user.set_attribute("department".to_string(), vec!["engineering".to_string()]);
    assert_eq!(user.get_attribute("department"), Some(&vec!["engineering".to_string()]));
    assert_eq!(user.get_single_attribute("department"), Some(&"engineering".to_string()));
    
    // Set multi-value attribute
    user.set_attribute("roles".to_string(), vec!["admin".to_string(), "user".to_string()]);
    assert_eq!(user.get_attribute("roles"), Some(&vec!["admin".to_string(), "user".to_string()]));
    assert_eq!(user.get_single_attribute("roles"), Some(&"admin".to_string()));
    
    // Remove attribute
    let removed = user.remove_attribute("department");
    assert_eq!(removed, Some(vec!["engineering".to_string()]));
    assert_eq!(user.get_attribute("department"), None);
    
    // Remove non-existent attribute
    let removed = user.remove_attribute("nonexistent");
    assert_eq!(removed, None);
}

#[test]
fn test_federated_identities() {
    let mut user = User::new("testuser".to_string()).unwrap();
    
    let identity1 = FederatedIdentity {
        identity_provider: "google".to_string(),
        user_id: "google-user-123".to_string(),
        user_name: "testuser@gmail.com".to_string(),
    };
    
    let identity2 = FederatedIdentity {
        identity_provider: "facebook".to_string(),
        user_id: "facebook-user-456".to_string(),
        user_name: "testuser".to_string(),
    };
    
    // Add federated identity
    user.add_federated_identity(identity1.clone());
    assert_eq!(user.federated_identities.len(), 1);
    assert_eq!(user.federated_identities[0].identity_provider, "google");
    
    // Add another identity
    user.add_federated_identity(identity2.clone());
    assert_eq!(user.federated_identities.len(), 2);
    
    // Replace existing identity
    let updated_identity = FederatedIdentity {
        identity_provider: "google".to_string(),
        user_id: "google-user-789".to_string(),
        user_name: "newtestuser@gmail.com".to_string(),
    };
    user.add_federated_identity(updated_identity);
    assert_eq!(user.federated_identities.len(), 2);
    let google_identity = user.federated_identities.iter()
        .find(|id| id.identity_provider == "google")
        .unwrap();
    assert_eq!(google_identity.user_id, "google-user-789");
    
    // Remove federated identity
    user.remove_federated_identity("google");
    assert_eq!(user.federated_identities.len(), 1);
    assert_eq!(user.federated_identities[0].identity_provider, "facebook");
    
    // Remove non-existent identity
    user.remove_federated_identity("github");
    assert_eq!(user.federated_identities.len(), 1);
}

#[test]
fn test_display_name() {
    // No first/last name
    let user = User::new("testuser".to_string()).unwrap();
    assert_eq!(user.display_name(), "testuser");
    
    // First name only
    let mut user = User::new("testuser".to_string()).unwrap();
    user.first_name = Some("John".to_string());
    assert_eq!(user.display_name(), "John");
    
    // Last name only
    let mut user = User::new("testuser".to_string()).unwrap();
    user.last_name = Some("Doe".to_string());
    assert_eq!(user.display_name(), "Doe");
    
    // Both names
    let mut user = User::new("testuser".to_string()).unwrap();
    user.first_name = Some("John".to_string());
    user.last_name = Some("Doe".to_string());
    assert_eq!(user.display_name(), "John Doe");
}

#[test]
fn test_is_fully_configured() {
    let mut user = User::new("testuser".to_string()).unwrap();
    assert!(user.is_fully_configured());
    
    user.add_required_action(RequiredAction::UpdatePassword);
    assert!(!user.is_fully_configured());
    
    user.remove_required_action(&RequiredAction::UpdatePassword);
    assert!(user.is_fully_configured());
}

#[test]
fn test_needs_email_verification() {
    // User without email
    let user = User::new("testuser".to_string()).unwrap();
    assert!(!user.needs_email_verification());
    
    // User with unverified email
    let user = User::with_email("testuser".to_string(), "test@example.com".to_string()).unwrap();
    assert!(user.needs_email_verification());
    
    // User with verified email
    let mut user = User::with_email("testuser".to_string(), "test@example.com".to_string()).unwrap();
    user.verify_email().unwrap();
    assert!(!user.needs_email_verification());
}

#[test]
fn test_create_user_request() {
    // Basic request
    let request = CreateUserRequest::new("testuser".to_string());
    assert_eq!(request.username, "testuser");
    assert_eq!(request.email, None);
    assert_eq!(request.enabled, Some(true));
    
    // Fluent API
    let request = CreateUserRequest::new("testuser".to_string())
        .with_email("test@example.com".to_string())
        .with_name("John".to_string(), "Doe".to_string())
        .with_temporary_password("temppass123".to_string());
    
    assert_eq!(request.username, "testuser");
    assert_eq!(request.email, Some("test@example.com".to_string()));
    assert_eq!(request.first_name, Some("John".to_string()));
    assert_eq!(request.last_name, Some("Doe".to_string()));
    assert_eq!(request.temporary_password, Some("temppass123".to_string()));
    assert_eq!(request.require_password_update, Some(true));
}

#[test]
fn test_create_user_request_validation() {
    // Valid request
    let request = CreateUserRequest::new("testuser".to_string())
        .with_email("test@example.com".to_string());
    assert!(request.validate().is_ok());
    
    // Invalid username
    let request = CreateUserRequest::new("".to_string());
    assert!(request.validate().is_err());
    
    // Invalid email
    let request = CreateUserRequest::new("testuser".to_string())
        .with_email("invalid-email".to_string());
    assert!(request.validate().is_err());
    
    // Invalid password (too short)
    let request = CreateUserRequest::new("testuser".to_string())
        .with_temporary_password("short".to_string());
    assert!(request.validate().is_err());
}

#[test]
fn test_create_user_request_to_domain_user() {
    let mut attributes = HashMap::new();
    attributes.insert("department".to_string(), vec!["engineering".to_string()]);
    
    let request = CreateUserRequest {
        username: "testuser".to_string(),
        email: Some("test@example.com".to_string()),
        first_name: Some("John".to_string()),
        last_name: Some("Doe".to_string()),
        enabled: Some(false),
        temporary_password: Some("temppass123".to_string()),
        require_password_update: Some(true),
        attributes: Some(attributes),
    };
    
    let result = request.to_domain_user();
    assert!(result.is_ok());
    
    let user = result.unwrap();
    assert_eq!(user.username, "testuser");
    assert_eq!(user.email, Some("test@example.com".to_string()));
    assert_eq!(user.first_name, Some("John".to_string()));
    assert_eq!(user.last_name, Some("Doe".to_string()));
    assert!(!user.enabled);
    assert!(user.required_actions.contains(&RequiredAction::VerifyEmail));
    assert!(user.required_actions.contains(&RequiredAction::UpdatePassword));
    assert_eq!(user.get_single_attribute("department"), Some(&"engineering".to_string()));
}

#[test]
fn test_update_user_request() {
    let mut attributes = HashMap::new();
    attributes.insert("department".to_string(), vec!["marketing".to_string()]);
    
    let request = UpdateUserRequest {
        email: Some("newemail@example.com".to_string()),
        first_name: Some("Jane".to_string()),
        last_name: Some("Smith".to_string()),
        enabled: Some(false),
        attributes: Some(attributes),
    };
    
    // Test that all fields are accessible
    assert_eq!(request.email, Some("newemail@example.com".to_string()));
    assert_eq!(request.first_name, Some("Jane".to_string()));
    assert_eq!(request.last_name, Some("Smith".to_string()));
    assert_eq!(request.enabled, Some(false));
    assert!(request.attributes.is_some());
}

#[test]
fn test_user_serialization() {
    let user = User::with_email("testuser".to_string(), "test@example.com".to_string()).unwrap();
    
    // Serialize to JSON
    let json = serde_json::to_string(&user);
    assert!(json.is_ok());
    
    // Deserialize from JSON
    let json_str = json.unwrap();
    let deserialized: Result<User, _> = serde_json::from_str(&json_str);
    assert!(deserialized.is_ok());
    
    let deserialized_user = deserialized.unwrap();
    assert_eq!(deserialized_user.username, user.username);
    assert_eq!(deserialized_user.email, user.email);
    assert_eq!(deserialized_user.enabled, user.enabled);
}